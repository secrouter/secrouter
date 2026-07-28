/**
 * MCP tool-authorization tests. Run: npx tsx test/security/mcp-policy.test.ts
 * Covers authorizeTool (allow / wildcard / deny-wins / default-deny), the
 * group→user tool merge in resolvePolicy, and the registry SSRF + token helpers.
 */

import { resolvePolicy, authorizeTool } from "../../src/security/policy/engine.js";
import { isMcpServerInBoundary, mcpServerToken } from "../../src/security/mcp/registry.js";
import { validateSecurityConfig, type FreeRouterConfig } from "../../src/config.js";
import type { EffectivePolicy, Principal, SecurityConfig } from "../../src/security/types.js";

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

const sec = (policy: SecurityConfig["policy"]): SecurityConfig =>
  ({ enabled: true, classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI"] }, policy }) as SecurityConfig;
const principal = (groups: string[], id = "u1"): Principal => ({ id, groups }) as Principal;

console.log("authorizeTool (default-deny; deny wins; server/* wildcard):");
{
  const p = { allowedTools: ["docs/*", "calc/add"], deniedTools: ["docs/secret"] } as EffectivePolicy;
  ok("wildcard grants a server's tool", authorizeTool(p, "docs", "find").allow === true);
  ok("exact grant", authorizeTool(p, "calc", "add").allow === true);
  ok("tool not in allow-list → deny", authorizeTool(p, "calc", "sub").allow === false);
  ok("deny wins over a matching wildcard", authorizeTool(p, "docs", "secret").allow === false);
}
{
  const none = { allowedTools: null, deniedTools: [] } as EffectivePolicy;
  ok("default-deny: null allow-list → no tools", authorizeTool(none, "docs", "find").allow === false);
  ok("default-deny reason is explicit", authorizeTool(none, "docs", "find").reason === "no tools permitted for this principal");
}

console.log("\nresolvePolicy tool merge (additive groups, authoritative user, denies accumulate):");
{
  // no grant anywhere → default-deny (null)
  const p0 = resolvePolicy(principal([]), sec({ default: {} }));
  ok("no allowedTools anywhere → allowedTools is null (default-deny)", p0.allowedTools === null);

  // two groups union their tool grants
  const cfg = sec({
    default: {},
    groups: {
      analysts: { allowedTools: ["docs/*"], deniedTools: ["docs/secret"] },
      calc: { allowedTools: ["calc/add"] },
    },
    users: { u1: { allowedTools: ["only/this"] } },
  });
  const pBoth = resolvePolicy(principal(["analysts", "calc"], "u2"), cfg);
  ok("groups union their allowedTools", !!pBoth.allowedTools && pBoth.allowedTools.includes("docs/*") && pBoth.allowedTools.includes("calc/add"));
  ok("group deniedTools carried through", pBoth.deniedTools.includes("docs/secret"));

  // the per-user rule is authoritative for allowedTools (locks down)
  const pUser = resolvePolicy(principal(["analysts", "calc"], "u1"), cfg);
  ok("user allowedTools replaces the group union", JSON.stringify(pUser.allowedTools) === '["only/this"]');
  ok("user rule still inherits accumulated denies", pUser.deniedTools.includes("docs/secret"));
}

console.log("\nRegistry SSRF + token helpers:");
ok("in-boundary .internal host allowed", isMcpServerInBoundary({ name: "a", url: "http://mcp.internal:9000/mcp", authorizedClassifications: ["CUI"] }));
ok("RFC1918 host allowed", isMcpServerInBoundary({ name: "b", url: "http://10.1.2.3:9000/mcp", authorizedClassifications: ["CUI"] }));
ok("public FQDN rejected", !isMcpServerInBoundary({ name: "c", url: "https://api.public-cloud.com/mcp", authorizedClassifications: ["CUI"] }));
ok("unparseable URL rejected", !isMcpServerInBoundary({ name: "d", url: "not a url", authorizedClassifications: ["CUI"] }));
process.env.SECROUTER_MCP_TEST_TOK = "s3cret";
ok("token resolved from env", mcpServerToken({ name: "e", url: "http://x.internal/mcp", authorizedClassifications: ["CUI"], authEnvKey: "SECROUTER_MCP_TEST_TOK" }) === "s3cret");
ok("no authEnvKey → undefined token", mcpServerToken({ name: "f", url: "http://x.internal/mcp", authorizedClassifications: ["CUI"] }) === undefined);
delete process.env.SECROUTER_MCP_TEST_TOK;

console.log("\nFail-closed config validation (security.mcp):");
{
  const baseSec = {
    enabled: true,
    oidc: { issuer: "https://idp", audience: "secrouter" },
    egress: { allowlist: [{ provider: "p", allowedHost: "h", authorizedClassifications: ["CUI"] }] },
    classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI"] },
  };
  const mcpErrs = (mcp: unknown) =>
    validateSecurityConfig({ security: { ...baseSec, mcp } } as unknown as FreeRouterConfig).filter((e) => /mcp/i.test(e));
  ok("valid mcp config → no errors", mcpErrs({ enabled: true, servers: [{ name: "s", url: "http://x.internal/mcp", authorizedClassifications: ["CUI"] }] }).length === 0);
  ok("enabled + empty servers → error", mcpErrs({ enabled: true, servers: [] }).length > 0);
  ok("server missing name → error", mcpErrs({ enabled: true, servers: [{ url: "http://x.internal/mcp", authorizedClassifications: ["CUI"] }] }).some((e) => /name/.test(e)));
  ok("invalid url → error", mcpErrs({ enabled: true, servers: [{ name: "s", url: "not a url", authorizedClassifications: ["CUI"] }] }).some((e) => /url/i.test(e)));
  ok("classification outside the ladder → error", mcpErrs({ enabled: true, servers: [{ name: "s", url: "http://x.internal/mcp", authorizedClassifications: ["SECRET"] }] }).some((e) => /ladder/.test(e)));
  ok("disabled mcp → not validated", mcpErrs({ enabled: false, servers: [] }).length === 0);
}

console.log(`\nMCP policy: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
