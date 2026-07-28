/**
 * MCP gateway (Tier 1 Phase D) — the JSON-RPC dispatcher behind POST /mcp.
 *
 * Extends SecRouter's model to agentic tools: the client only ever *sees*
 * sanctioned tools (tools/list is filtered to its effective allow-list), and
 * every tools/call passes the same gate chain as a model request —
 * policy → classification → forward → metadata-only audit. Arguments are hashed
 * for correlation and NEVER recorded or logged in the clear (CUI-safe).
 *
 * Stateless (phase 1): each call is authenticated by the caller's OIDC bearer
 * and proxied directly to a stateless streamable-HTTP upstream. No session state,
 * no stdio spawning, tools only (no prompts/resources/sampling).
 */

import { createHash } from "node:crypto";
import { logger } from "../../logger.js";
import { metrics } from "../../metrics.js";
import { getAuditor } from "../index.js";
import { audit } from "../audit/audit.js";
import { authorizeTool, getEffectivePolicy } from "../policy/engine.js";
import type { Principal } from "../types.js";
import { getMcpServer, isMcpServerInBoundary, listMcpServers, mcpServerToken } from "./registry.js";
import { mcpCallTool, mcpListTools } from "./protocol.js";
import { MCP_PROTOCOL_VERSION, RPC, type JsonRpcRequest, type JsonRpcResponse, type NamespacedTool } from "./types.js";

export type McpContext = { principal: Principal; classification: string; requestId: string };

const ok = (id: JsonRpcRequest["id"], result: unknown): JsonRpcResponse => ({ jsonrpc: "2.0", id: id ?? null, result });
const err = (id: JsonRpcRequest["id"], code: number, message: string): JsonRpcResponse => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });

/** Dispatch one JSON-RPC request through the governed gateway. */
export async function handleMcpRpc(req: JsonRpcRequest, ctx: McpContext): Promise<JsonRpcResponse | null> {
  switch (req.method) {
    case "initialize":
      return ok(req.id, {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: "secrouter", version: "1.0.0" },
      });
    case "notifications/initialized":
    case "ping":
      // Notifications have no id and expect no response body.
      return req.id == null ? null : ok(req.id, {});
    case "tools/list":
      return ok(req.id, { tools: await listTools(ctx) });
    case "tools/call":
      return callTool(req, ctx);
    default:
      return err(req.id, RPC.METHOD_NOT_FOUND, `method '${req.method}' is not supported by the SecRouter MCP gateway`);
  }
}

/** Admin probe: list one server's tools (namespaced), unfiltered by policy. */
export async function probeMcpTools(name: string): Promise<{ ok: boolean; tools?: string[]; error?: string }> {
  const server = getMcpServer(name);
  if (!server) return { ok: false, error: `unknown MCP server '${name}'` };
  if (!isMcpServerInBoundary(server)) return { ok: false, error: `server '${name}' is out of boundary` };
  try {
    const tools = await mcpListTools(server, { token: mcpServerToken(server), timeoutMs: 5000 });
    return { ok: true, tools: tools.map((t) => `${name}/${t.name}`) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/** Aggregate + namespace + filter tools across all registered servers. */
async function listTools(ctx: McpContext): Promise<NamespacedTool[]> {
  const policy = getEffectivePolicy(ctx.principal);
  const out: NamespacedTool[] = [];
  for (const server of listMcpServers()) {
    if (!isMcpServerInBoundary(server)) {
      logger.warn(`MCP: skipping out-of-boundary server '${server.name}' (${server.url})`);
      continue;
    }
    try {
      const tools = await mcpListTools(server, { token: mcpServerToken(server) });
      for (const t of tools) {
        if (authorizeTool(policy, server.name, t.name).allow) {
          out.push({ ...t, server: server.name, id: `${server.name}/${t.name}` });
        }
      }
    } catch (e) {
      // One dead/denied upstream must not blank the whole list.
      logger.error(`MCP tools/list '${server.name}' failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return out;
}

/** Gate chain for a single tools/call: parse → policy → classification → forward → audit. */
async function callTool(req: JsonRpcRequest, ctx: McpContext): Promise<JsonRpcResponse> {
  const params = (req.params ?? {}) as { name?: string; arguments?: unknown };
  const name = typeof params.name === "string" ? params.name : "";
  const slash = name.indexOf("/");
  if (slash <= 0 || slash === name.length - 1) {
    return err(req.id, RPC.INVALID_PARAMS, "tool name must be namespaced 'server/tool'");
  }
  const serverName = name.slice(0, slash);
  const tool = name.slice(slash + 1);
  const emit = (a: ReturnType<typeof audit.toolDeny>) => getAuditor().emit(a);

  const server = getMcpServer(serverName);
  if (!server || !isMcpServerInBoundary(server)) {
    emit(audit.toolDeny(ctx.principal.id, ctx.requestId, serverName, tool, "unknown or out-of-boundary server"));
    metrics.toolDeniedTotal.inc({ reason: "unknown_server" });
    return err(req.id, RPC.INVALID_PARAMS, `unknown MCP server '${serverName}'`);
  }

  // 1. Policy — deny-by-default tool allow-list (AC 3.1.5).
  const az = authorizeTool(getEffectivePolicy(ctx.principal), serverName, tool);
  if (!az.allow) {
    emit(audit.toolDeny(ctx.principal.id, ctx.requestId, serverName, tool, az.reason));
    metrics.toolDeniedTotal.inc({ reason: "policy" });
    return err(req.id, RPC.NOT_PERMITTED, `tool '${name}' is not permitted: ${az.reason}`);
  }

  // 2. Classification gate — this server may only receive authorized classifications (AC 3.1.3 / SC 3.13.6).
  if (!server.authorizedClassifications.includes(ctx.classification)) {
    emit(audit.toolDeny(ctx.principal.id, ctx.requestId, serverName, tool, `classification_not_authorized:${ctx.classification}`));
    metrics.toolDeniedTotal.inc({ reason: "classification" });
    return err(req.id, RPC.NOT_PERMITTED, `server '${serverName}' is not authorized for classification '${ctx.classification}'`);
  }

  // 3. Forward + audit (metadata only: hash of args, byte counts, latency).
  const argsJson = JSON.stringify(params.arguments ?? {});
  const argsSha256 = createHash("sha256").update(argsJson).digest("hex");
  const t0 = Date.now();
  try {
    const result = await mcpCallTool(server, tool, params.arguments, { token: mcpServerToken(server) });
    const bytesOut = JSON.stringify(result.content ?? "").length;
    getAuditor().emit(
      audit.toolCall(ctx.principal.id, ctx.requestId, serverName, tool, {
        ok: !result.isError,
        latencyMs: Date.now() - t0,
        bytesIn: argsJson.length,
        bytesOut,
        argsSha256,
        error: result.isError ? "tool_reported_error" : undefined,
      }),
    );
    metrics.toolCallsTotal.inc({ server: serverName, tool, outcome: result.isError ? "error" : "ok" });
    return ok(req.id, { content: result.content, isError: result.isError });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    getAuditor().emit(
      audit.toolCall(ctx.principal.id, ctx.requestId, serverName, tool, {
        ok: false,
        latencyMs: Date.now() - t0,
        bytesIn: argsJson.length,
        bytesOut: 0,
        argsSha256,
        error: msg,
      }),
    );
    metrics.toolCallsTotal.inc({ server: serverName, tool, outcome: "error" });
    return err(req.id, RPC.UPSTREAM_ERROR, `tool call failed: ${msg}`);
  }
}
