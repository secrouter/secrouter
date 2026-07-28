/**
 * MCP streamable-HTTP client (Tier 1 Phase D) — zero dependencies.
 *
 * Speaks JSON-RPC 2.0 to an upstream MCP server over a single POST endpoint.
 * The server may answer with `application/json` (one response) or
 * `text/event-stream` (SSE frames); this client handles both. Only the three
 * calls the gateway needs are implemented: `initialize`, `tools/list`,
 * `tools/call`. No prompts / resources / sampling (out of scope, phase 1).
 *
 * Errors reuse the Phase C provider classes so timeout/upstream semantics stay
 * uniform across the codebase (TimeoutError, UpstreamError).
 */

import { TimeoutError, UpstreamError } from "../../provider.js";
import {
  MCP_PROTOCOL_VERSION,
  type JsonRpcId,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type McpServerConfig,
  type McpSession,
  type McpTool,
  type ToolCallResult,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 30_000;
let rpcSeq = 0;
function nextId(): number {
  rpcSeq = (rpcSeq + 1) & 0x7fffffff;
  return rpcSeq;
}

export type RpcOptions = {
  token?: string;
  sessionId?: string;
  timeoutMs?: number;
  /** Set false for the initialize call, which precedes protocol-version negotiation. */
  sendProtocolHeader?: boolean;
};

/** Parse the `data:` payloads out of an SSE text buffer into JSON-RPC messages. */
function parseSseMessages(buffer: string): JsonRpcResponse[] {
  const out: JsonRpcResponse[] = [];
  for (const frame of buffer.split(/\n\n/)) {
    const data = frame
      .split(/\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).trim())
      .join("\n");
    if (!data) continue;
    try {
      out.push(JSON.parse(data) as JsonRpcResponse);
    } catch {
      /* ignore keep-alives / non-JSON frames */
    }
  }
  return out;
}

/** Read an SSE stream until the response with id `wantId` arrives, then stop. */
async function readSseUntil(res: Response, wantId: JsonRpcId): Promise<JsonRpcResponse> {
  const reader = res.body?.getReader();
  if (!reader) throw new UpstreamError("MCP server returned no response body", res.status, "mcp");
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (value) buffer += decoder.decode(value, { stream: true });
      // Parse complete frames (everything up to the last frame delimiter).
      const lastBreak = buffer.lastIndexOf("\n\n");
      if (lastBreak >= 0) {
        const ready = buffer.slice(0, lastBreak);
        const match = parseSseMessages(ready).find((m) => m.id === wantId);
        if (match) return match;
      }
      if (done) break;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  const match = parseSseMessages(buffer).find((m) => m.id === wantId);
  if (match) return match;
  throw new UpstreamError("MCP server closed the stream without a matching response", res.status, "mcp");
}

/**
 * Send one JSON-RPC request and return the matching response (+ any session id
 * the server assigned). The core transport used by every typed call below.
 */
export async function rpc(
  server: McpServerConfig,
  method: string,
  params: unknown,
  opts: RpcOptions = {},
): Promise<{ response: JsonRpcResponse; sessionId?: string }> {
  const id = nextId();
  const body: JsonRpcRequest = { jsonrpc: "2.0", id, method, params };
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  };
  if (opts.token) headers["Authorization"] = `Bearer ${opts.token}`;
  if (opts.sessionId) headers["Mcp-Session-Id"] = opts.sessionId;
  if (opts.sendProtocolHeader !== false) headers["MCP-Protocol-Version"] = MCP_PROTOCOL_VERSION;

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(server.url, { method: "POST", headers, body: JSON.stringify(body), signal: ctrl.signal });
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new TimeoutError(`MCP ${method} to '${server.name}' timed out`);
    }
    throw new UpstreamError(`MCP ${method} to '${server.name}' failed: ${err instanceof Error ? err.message : String(err)}`, 0, server.name);
  } finally {
    clearTimeout(timer);
  }

  const sessionId = res.headers.get("mcp-session-id") ?? undefined;
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new UpstreamError(`MCP ${method} to '${server.name}' → HTTP ${res.status}: ${text.slice(0, 200)}`, res.status, server.name);
  }

  const ctype = res.headers.get("content-type") ?? "";
  let response: JsonRpcResponse;
  if (ctype.includes("text/event-stream")) {
    response = await readSseUntil(res, id);
  } else {
    const json = (await res.json().catch(() => null)) as JsonRpcResponse | JsonRpcResponse[] | null;
    if (json == null) throw new UpstreamError(`MCP ${method} to '${server.name}' returned an unparseable body`, res.status, server.name);
    response = Array.isArray(json) ? (json.find((m) => m.id === id) ?? json[0]) : json;
  }
  return { response, sessionId };
}

function resultOf(response: JsonRpcResponse, server: string, method: string): unknown {
  if (response.error) {
    throw new UpstreamError(`MCP ${method} on '${server}' → JSON-RPC error ${response.error.code}: ${response.error.message}`, 0, server);
  }
  return response.result;
}

/** Establish a session: initialize + the initialized notification (best-effort). */
export async function mcpInitialize(server: McpServerConfig, token?: string): Promise<McpSession> {
  const { response, sessionId } = await rpc(
    server,
    "initialize",
    {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "secrouter", version: "1.0.0" },
    },
    { token, sendProtocolHeader: false },
  );
  const result = resultOf(response, server.name, "initialize") as { protocolVersion?: string; serverInfo?: unknown };
  // Complete the lifecycle handshake (notification — no response expected).
  try {
    await rpc(server, "notifications/initialized", {}, { token, sessionId });
  } catch {
    /* best-effort: many servers don't require it, and stateless mocks 202 it */
  }
  return { protocolVersion: result?.protocolVersion ?? MCP_PROTOCOL_VERSION, sessionId, serverInfo: result?.serverInfo };
}

/** List the tools an upstream server advertises (un-namespaced). */
export async function mcpListTools(server: McpServerConfig, opts: RpcOptions = {}): Promise<McpTool[]> {
  const { response } = await rpc(server, "tools/list", {}, opts);
  const result = resultOf(response, server.name, "tools/list") as { tools?: McpTool[] };
  return Array.isArray(result?.tools) ? result.tools : [];
}

/** Invoke one tool on an upstream server. */
export async function mcpCallTool(
  server: McpServerConfig,
  tool: string,
  args: unknown,
  opts: RpcOptions = {},
): Promise<ToolCallResult> {
  const { response } = await rpc(server, "tools/call", { name: tool, arguments: args ?? {} }, opts);
  const result = resultOf(response, server.name, "tools/call") as ToolCallResult;
  return { content: result?.content ?? [], isError: result?.isError };
}
