/**
 * MCP server registry (Tier 1 Phase D).
 *
 * The set of upstream MCP servers SecRouter will broker, read from
 * `security.mcp.servers`. Change-controlled like providers/egress. Every server
 * URL is held to the same in-boundary discipline as the add-endpoint probe, so a
 * misconfigured public URL can never become a proxy target.
 */

import { getSecurityConfig } from "../../config.js";
import { isInBoundaryHost } from "../endpoints.js";
import type { McpServerConfig } from "./types.js";

/** All registered MCP servers (empty when the gateway is disabled/unset). */
export function listMcpServers(): McpServerConfig[] {
  return getSecurityConfig()?.mcp?.servers ?? [];
}

/** Look up one registered server by name. */
export function getMcpServer(name: string): McpServerConfig | undefined {
  return listMcpServers().find((s) => s.name === name);
}

/** Resolve a server's bearer token from its env var (never stored in config). */
export function mcpServerToken(s: McpServerConfig): string | undefined {
  return s.authEnvKey ? process.env[s.authEnvKey] : undefined;
}

/** SSRF guard: is this server's URL host in-boundary (or explicitly allow-listed)? */
export function isMcpServerInBoundary(s: McpServerConfig): boolean {
  try {
    return isInBoundaryHost(new URL(s.url).hostname);
  } catch {
    return false; // unparseable URL → not reachable
  }
}
