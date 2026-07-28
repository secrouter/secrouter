/**
 * MCP protocol-client tests. Run: npx tsx test/security/mcp-protocol.test.ts
 * Stubs global fetch — no network. Covers JSON + SSE response framing, request
 * shape, JSON-RPC + HTTP error mapping, and the timeout path.
 */

import { mcpInitialize, mcpListTools, mcpCallTool, rpc } from "../../src/security/mcp/protocol.js";
import { MCP_PROTOCOL_VERSION, type McpServerConfig } from "../../src/security/mcp/types.js";

let pass = 0;
let fail = 0;
function ok(name: string, cond: boolean, extra = "") {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.error(`  ✗ ${name} ${extra}`);
  }
}

const server: McpServerConfig = { name: "mock", url: "http://mcp.internal:9000/mcp", authorizedClassifications: ["CUI"] };
const origFetch = globalThis.fetch;
type Captured = { url: string; init: RequestInit; body: { id: number; method: string; params?: unknown } };
let captured: Captured[] = [];

/** Install a fetch stub that routes by JSON-RPC method to a canned response. */
function stub(route: (method: string, id: number) => { status?: number; contentType?: string; text?: string; obj?: unknown }) {
  captured = [];
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    captured.push({ url: String(url), init, body });
    const r = route(body.method, body.id);
    const status = r.status ?? 200;
    const contentType = r.contentType ?? "application/json";
    const text = r.text ?? JSON.stringify(r.obj ?? { jsonrpc: "2.0", id: body.id, result: {} });
    return new Response(status === 204 ? null : text, { status, headers: { "content-type": contentType } });
  }) as typeof fetch;
}
const restore = () => (globalThis.fetch = origFetch);

async function main() {
  console.log("MCP protocol client:");

  // 1. initialize — request framing + Accept/Authorization headers
  stub((method, id) => ({ obj: { jsonrpc: "2.0", id, result: { protocolVersion: MCP_PROTOCOL_VERSION, serverInfo: { name: "up" } } } }));
  const sess = await mcpInitialize({ ...server, authEnvKey: undefined }, "tok-123");
  const init = captured.find((c) => c.body.method === "initialize")!;
  ok("initialize sends the pinned protocolVersion", (init.body.params as { protocolVersion: string }).protocolVersion === MCP_PROTOCOL_VERSION);
  ok("initialize returns the negotiated session", sess.protocolVersion === MCP_PROTOCOL_VERSION);
  ok("Accept header offers both json and event-stream", /application\/json/.test(String((init.init.headers as Record<string, string>).Accept)) && /text\/event-stream/.test(String((init.init.headers as Record<string, string>).Accept)));
  ok("bearer token forwarded as Authorization", (init.init.headers as Record<string, string>).Authorization === "Bearer tok-123");
  ok("initialized notification sent after initialize", captured.some((c) => c.body.method === "notifications/initialized"));
  restore();

  // 2. tools/list — application/json response
  stub((method, id) => (method === "tools/list" ? { obj: { jsonrpc: "2.0", id, result: { tools: [{ name: "echo" }, { name: "add" }] } } } : {}));
  const tools = await mcpListTools(server);
  ok("tools/list parses a JSON response", tools.length === 2 && tools[0].name === "echo");
  ok("tools/list request method + params", captured[0].body.method === "tools/list");
  restore();

  // 3. tools/call — application/json response
  stub((method, id) => ({ obj: { jsonrpc: "2.0", id, result: { content: [{ type: "text", text: "hi" }] } } }));
  const call = await mcpCallTool(server, "echo", { text: "hi" });
  const callReq = captured[0].body.params as { name: string; arguments: unknown };
  ok("tools/call sends name + arguments", callReq.name === "echo" && JSON.stringify(callReq.arguments) === '{"text":"hi"}');
  ok("tools/call returns content", Array.isArray(call.content) && (call.content as unknown[]).length === 1);
  restore();

  // 4. SSE (text/event-stream) response framing
  stub((method, id) => ({
    contentType: "text/event-stream",
    text: `event: message\ndata: {"jsonrpc":"2.0","id":${id},"result":{"tools":[{"name":"sse-tool"}]}}\n\n`,
  }));
  const sseTools = await mcpListTools(server);
  ok("tools/list parses an SSE response and matches the id", sseTools.length === 1 && sseTools[0].name === "sse-tool");
  restore();

  // 5. JSON-RPC error → typed throw
  stub((method, id) => ({ obj: { jsonrpc: "2.0", id, error: { code: -32000, message: "boom" } } }));
  let threw = "";
  try {
    await mcpListTools(server);
  } catch (e) {
    threw = e instanceof Error ? e.name : "";
  }
  ok("upstream JSON-RPC error surfaces as UpstreamError", threw === "UpstreamError");
  restore();

  // 6. HTTP 500 → UpstreamError carrying the status
  stub(() => ({ status: 500, text: "server exploded" }));
  let status = -1;
  try {
    await mcpListTools(server);
  } catch (e) {
    status = (e as { status?: number }).status ?? -1;
  }
  ok("HTTP 500 → UpstreamError with status 500", status === 500);
  restore();

  // 7. timeout → TimeoutError (fetch honors the abort signal)
  globalThis.fetch = ((_url: string, init: RequestInit) =>
    new Promise((_res, reject) => {
      (init.signal as AbortSignal).addEventListener("abort", () => {
        const err = new Error("aborted");
        err.name = "AbortError";
        reject(err);
      });
    })) as typeof fetch;
  let timedOut = "";
  try {
    await rpc(server, "tools/list", {}, { timeoutMs: 20 });
  } catch (e) {
    timedOut = e instanceof Error ? e.name : "";
  }
  ok("aborted fetch → TimeoutError", timedOut === "TimeoutError");
  restore();

  console.log(`\nMCP protocol: ${pass} passed, ${fail} failed`);
  if (fail > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
