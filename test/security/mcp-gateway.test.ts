/**
 * MCP gateway tests. Run: npx tsx test/security/mcp-gateway.test.ts
 * In-process: loads a temp secured config + store, stubs the upstream MCP server
 * via fetch, and drives handleMcpRpc directly. Proves list-filtering, the
 * tools/call gate chain (policy → classification), and CUI-safe audit (a hash of
 * the arguments is recorded; the argument contents never are).
 */

import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig } from "../../src/config.js";
import { initSecurity, getStore } from "../../src/security/index.js";
import { handleMcpRpc } from "../../src/security/mcp/gateway.js";
import type { Principal } from "../../src/security/types.js";

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

const dir = mkdtempSync(join(tmpdir(), "secrouter-mcp-"));
const cfgPath = join(dir, "config.json");
writeFileSync(
  cfgPath,
  JSON.stringify({
    port: 18990,
    host: "127.0.0.1",
    providers: { local: { baseUrl: "http://x.internal:1/v1", api: "openai" } },
    tiers: { SIMPLE: { primary: "local/x", fallback: [] }, MEDIUM: { primary: "local/x", fallback: [] }, COMPLEX: { primary: "local/x", fallback: [] }, REASONING: { primary: "local/x", fallback: [] } },
    auth: { default: "profiles", profiles: { type: "profiles", profilesPath: join(dir, "auth.json") } },
    security: {
      enabled: true,
      storePath: join(dir, "store.db"),
      oidc: { issuer: "https://idp.test", audience: "secrouter", jwksUri: "http://127.0.0.1:1/jwks", requireMfa: false },
      classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI"] },
      egress: { allowlist: [{ provider: "local", allowedHost: "x.internal:1", authorizedClassifications: ["CUI"] }] },
      policy: { default: {}, groups: { analysts: { allowedTools: ["mock/echo", "mock/add"] } } },
      mcp: { enabled: true, servers: [{ name: "mock", url: "http://mock.internal:9000/mcp", authorizedClassifications: ["CUI"] }] },
      audit: { sink: "sqlite", failClosed: true },
    },
  }),
);
writeFileSync(join(dir, "auth.json"), JSON.stringify({ version: 1, profiles: {}, lastGood: {} }));

// Stub the upstream MCP server: advertises echo/add/secret; echoes calls back.
const SECRET_ARG = "TOP-SECRET-PAYLOAD-9f3a";
globalThis.fetch = (async (_url: string, init: RequestInit) => {
  const body = JSON.parse(String(init.body));
  const json = (result: unknown) => new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }), { headers: { "content-type": "application/json" } });
  if (body.method === "tools/list") return json({ tools: [{ name: "echo" }, { name: "add" }, { name: "secret" }] });
  if (body.method === "tools/call") return json({ content: [{ type: "text", text: `ran ${body.params?.name}` }] });
  return json({});
}) as typeof fetch;

const analyst: Principal = { id: "analyst-1", groups: ["analysts"] } as Principal;
const rpc = (method: string, params?: unknown) => ({ jsonrpc: "2.0" as const, id: 1, method, params });

async function main() {
  process.env.FREEROUTER_CONFIG = cfgPath;
  loadConfig();
  initSecurity(loadConfig().security);

  console.log("MCP gateway:");

  // 1. tools/list — filtered to the principal's allow-list (echo, add — NOT secret)
  const list = await handleMcpRpc(rpc("tools/list"), { principal: analyst, classification: "CUI", requestId: "r1" });
  const tools = ((list?.result as { tools: { id: string }[] })?.tools ?? []).map((t) => t.id).sort();
  ok("tools/list namespaces + filters to the allow-list", JSON.stringify(tools) === '["mock/add","mock/echo"]', JSON.stringify(tools));

  // 2. tools/call an allowed tool → forwarded, result returned
  const call = await handleMcpRpc(rpc("tools/call", { name: "mock/echo", arguments: { text: SECRET_ARG } }), { principal: analyst, classification: "CUI", requestId: "r2" });
  ok("tools/call allowed tool → result content", !call?.error && Array.isArray((call?.result as { content: unknown[] })?.content));

  // 3. tools/call a tool NOT in the allow-list → policy deny
  const denied = await handleMcpRpc(rpc("tools/call", { name: "mock/secret", arguments: {} }), { principal: analyst, classification: "CUI", requestId: "r3" });
  ok("tools/call unsanctioned tool → JSON-RPC deny (-32001)", denied?.error?.code === -32001, JSON.stringify(denied?.error));

  // 4. classification gate — allowed tool, but request classification the server isn't authorized for
  const wrongClass = await handleMcpRpc(rpc("tools/call", { name: "mock/echo", arguments: {} }), { principal: analyst, classification: "UNCLASSIFIED", requestId: "r4" });
  ok("tools/call blocked by classification gate → deny", wrongClass?.error?.code === -32001 && /classification/i.test(wrongClass?.error?.message ?? ""), JSON.stringify(wrongClass?.error));

  // 5. unknown method → method-not-found
  const bad = await handleMcpRpc(rpc("resources/list"), { principal: analyst, classification: "CUI", requestId: "r5" });
  ok("unsupported method → -32601", bad?.error?.code === -32601);

  // 6. audit is CUI-safe: a tool.call row exists with argsSha256, and the argument
  //    contents (SECRET_ARG) never appear anywhere in the persisted audit.
  const audit = getStore().queryAudit({ limit: 50 });
  const callRow = audit.find((e) => e.type === "tool.call" && (e.detail as { tool?: string })?.tool === "echo");
  const denyRow = audit.find((e) => e.type === "tool.deny");
  ok("tool.call audit row written with argsSha256", !!callRow && typeof (callRow!.detail as { argsSha256?: string }).argsSha256 === "string");
  ok("tool.deny audit row written", !!denyRow);
  ok("argument CONTENTS never appear in the audit (CUI-safe)", !JSON.stringify(audit).includes(SECRET_ARG));

  console.log(`\nMCP gateway: ${pass} passed, ${fail} failed`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
