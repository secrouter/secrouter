/**
 * MCP gateway types (Tier 1 Phase D).
 *
 * SecRouter brokers Model Context Protocol tool calls to in-boundary upstream
 * servers, applying the same deny-by-default allow-list, classification gate,
 * and metadata-only audit that govern chat. These are the wire + config types;
 * the protocol client is in `protocol.ts`, the gateway in `gateway.ts`.
 */

/** The MCP protocol version SecRouter implements + advertises. Pinned, not negotiated. */
export const MCP_PROTOCOL_VERSION = "2025-06-18";

// McpServerConfig is a config type; it lives with the other config types in
// ../types.ts (which stays runtime-import-free) and is re-exported here so the
// mcp/* modules have a single import surface.
export type { McpServerConfig } from "../types.js";

/** A tool as advertised by an upstream server (un-namespaced). */
export type McpTool = {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
};

/** A tool after SecRouter namespaces it `server/tool` for the client + policy. */
export type NamespacedTool = McpTool & {
  /** Registered server name. */
  server: string;
  /** Namespaced id: `${server}/${name}`. */
  id: string;
};

// ── JSON-RPC 2.0 ──
export type JsonRpcId = string | number | null;
export type JsonRpcRequest = {
  jsonrpc: "2.0";
  id?: JsonRpcId; // absent ⇒ notification
  method: string;
  params?: unknown;
};
export type JsonRpcError = { code: number; message: string; data?: unknown };
export type JsonRpcResponse = {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result?: unknown;
  error?: JsonRpcError;
};

/** JSON-RPC error codes SecRouter returns for governed-tool decisions. */
export const RPC = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  /** SecRouter policy/classification denial (server-defined range). */
  NOT_PERMITTED: -32001,
  /** Upstream server unreachable / errored. */
  UPSTREAM_ERROR: -32002,
} as const;

/** Result of one MCP session establishment. */
export type McpSession = {
  protocolVersion: string;
  sessionId?: string; // from the Mcp-Session-Id response header, when the server uses sessions
  serverInfo?: unknown;
};

/** The shape of a `tools/call` result (MCP content blocks). */
export type ToolCallResult = { content: unknown; isError?: boolean };

/** Metadata-only record of a proxied tool call — hashes, never argument contents. */
export type ToolCallOutcome = {
  ok: boolean;
  server: string;
  tool: string;
  latencyMs: number;
  bytesIn: number;
  bytesOut: number;
  /** SHA-256 of the JSON-serialized arguments — for correlation, NOT the arguments. */
  argsSha256: string;
  error?: string;
};
