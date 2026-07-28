// Dependency-free mock MCP server for the SecRouter test stack (Phase D).
// Speaks JSON-RPC 2.0 over POST /mcp (streamable HTTP). Exposes three trivial
// tools — echo, add, now — so the smoke test can prove tools/list filtering and
// tools/call gating end-to-end. Responds application/json by default; ?stream=1
// emits the response as a single SSE frame so both client framings are covered.
import { createServer } from "node:http";

const PORT = process.env.PORT || 8080;
const PROTOCOL_VERSION = "2025-06-18";

const TOOLS = [
  { name: "echo", description: "Echo the given text back.", inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"] } },
  { name: "add", description: "Add two numbers.", inputSchema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } }, required: ["a", "b"] } },
  { name: "now", description: "Return the server's current time (ISO-8601).", inputSchema: { type: "object", properties: {} } },
];

function handle(rpc) {
  const { id, method, params } = rpc || {};
  const ok = (result) => ({ jsonrpc: "2.0", id, result });
  const text = (t) => ok({ content: [{ type: "text", text: String(t) }] });
  switch (method) {
    case "initialize":
      return ok({ protocolVersion: PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: { name: "mock-mcp", version: "1.0.0" } });
    case "notifications/initialized":
    case "ping":
      return id == null ? null : ok({});
    case "tools/list":
      return ok({ tools: TOOLS });
    case "tools/call": {
      const name = params?.name;
      const a = params?.arguments || {};
      if (name === "echo") return text(a.text ?? "");
      if (name === "add") return text(Number(a.a) + Number(a.b));
      if (name === "now") return text(new Date().toISOString());
      return ok({ content: [{ type: "text", text: `unknown tool: ${name}` }], isError: true });
    }
    default:
      return { jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${method}` } };
  }
}

createServer((req, res) => {
  if (req.method === "GET" && req.url.startsWith("/health")) {
    res.writeHead(200, { "content-type": "text/plain" });
    return res.end("ok");
  }
  if (req.method !== "POST") {
    res.writeHead(405);
    return res.end();
  }
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    let payload;
    try {
      payload = JSON.parse(body);
    } catch {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }));
    }
    const stream = new URL(req.url, "http://x").searchParams.get("stream") === "1";
    const out = Array.isArray(payload) ? payload.map(handle).filter(Boolean) : handle(payload);
    if (stream && !Array.isArray(payload) && out) {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
      res.write(`event: message\ndata: ${JSON.stringify(out)}\n\n`);
      return res.end();
    }
    res.writeHead(out ? 200 : 202, { "content-type": "application/json" });
    res.end(out ? JSON.stringify(out) : "");
  });
}).listen(PORT, () => console.log(`mock-mcp listening on :${PORT}`));
