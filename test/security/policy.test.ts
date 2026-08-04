/**
 * Policy + quota tests. Run: npx tsx test/security/policy.test.ts
 * Covers resolvePolicy merge, authorize (allow/deny/downgrade/explicit/maxTier),
 * and checkQuota window enforcement.
 */

import { resolvePolicy, authorize } from "../../src/security/policy/engine.js";
import { checkQuota } from "../../src/security/accounting/quota.js";
import { SqliteStore } from "../../src/security/store/sqlite.js";
import type { Principal, SecurityConfig } from "../../src/security/types.js";

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

const ROUTING = {
  tiers: {
    SIMPLE: { primary: "local/llama" },
    MEDIUM: { primary: "bedrock/claude-sonnet" },
    COMPLEX: { primary: "bedrock/claude-opus" },
    REASONING: { primary: "bedrock/claude-opus" },
  },
};

const SEC: SecurityConfig = {
  enabled: true,
  classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI", "CUI//SP-PRVCY"] },
  egress: { allowlist: [] },
  policy: {
    default: { allowedTiers: ["SIMPLE", "MEDIUM"], onViolation: "downgrade" },
    groups: {
      "power-users": { allowedTiers: ["COMPLEX", "REASONING"], maxTier: "COMPLEX" },
      admins: { admin: true },
      "opus-only-denied": { deniedModels: ["bedrock/claude-opus"] },
    },
    users: {
      "locked-user": { allowedTiers: ["SIMPLE"], onViolation: "deny" },
    },
  },
};

function principal(groups: string[], id = "u"): Principal {
  return { id, groups, roles: [], mfa: true, claims: {} };
}

console.log("Policy engine:");

// default user: COMPLEX not allowed → downgrade to MEDIUM
{
  const pol = resolvePolicy(principal([]), SEC);
  const d = authorize(pol, "bedrock/claude-opus", "COMPLEX", ROUTING);
  ok("default user COMPLEX → downgrade to MEDIUM", d.effect === "downgrade" && d.tier === "MEDIUM", JSON.stringify(d));
  const allow = authorize(pol, "bedrock/claude-sonnet", "MEDIUM", ROUTING);
  ok("default user MEDIUM → allow", allow.effect === "allow");
}

// power-user: COMPLEX allowed (group additive grant)
{
  const pol = resolvePolicy(principal(["power-users"]), SEC);
  ok("power-user gets COMPLEX tier", pol.allowedTiers.includes("COMPLEX"));
  const d = authorize(pol, "bedrock/claude-opus", "COMPLEX", ROUTING);
  ok("power-user COMPLEX → allow", d.effect === "allow", JSON.stringify(d));
  // maxTier=COMPLEX caps REASONING → downgrade to COMPLEX
  const r = authorize(pol, "bedrock/claude-opus", "REASONING", ROUTING);
  ok("power-user REASONING capped to COMPLEX (maxTier)", r.effect === "downgrade" && r.tier === "COMPLEX", JSON.stringify(r));
}

// locked user: onViolation deny → MEDIUM denied outright
{
  const pol = resolvePolicy(principal([], "locked-user"), SEC);
  const d = authorize(pol, "bedrock/claude-sonnet", "MEDIUM", ROUTING);
  ok("locked-user MEDIUM → deny (onViolation=deny)", d.effect === "deny", JSON.stringify(d));
}

// deniedModels: opus denied even at allowed tier
{
  const pol = resolvePolicy(principal(["power-users", "opus-only-denied"]), SEC);
  const d = authorize(pol, "bedrock/claude-opus", "COMPLEX", ROUTING);
  ok("denied model → not allow", d.effect !== "allow", JSON.stringify(d));
}

// admin bit
{
  ok("admin group → admin true", resolvePolicy(principal(["admins"]), SEC).admin === true);
  ok("non-admin → admin false", resolvePolicy(principal([]), SEC).admin === false);
}

// explicit passthrough gating
{
  const pol = resolvePolicy(principal(["power-users"]), SEC);
  ok("EXPLICIT permitted model → allow", authorize(pol, "bedrock/claude-opus", "EXPLICIT", ROUTING).effect === "allow");
  const denyPol = resolvePolicy(principal([], "locked-user"), {
    ...SEC,
    policy: { ...SEC.policy!, users: { "locked-user": { allowedModels: ["local/llama"], onViolation: "deny" } } },
  });
  ok("EXPLICIT non-allowed model → deny", authorize(denyPol, "bedrock/claude-opus", "EXPLICIT", ROUTING).effect === "deny");
}

// Service-account governance (security.oidc.serviceSubjects, Feature: OIDC
// service-account auth): a service principal is just another Principal.id to
// the policy engine — no MFA/role special-casing anywhere here. Confirms it
// can be assigned its own budget/tier/classification via the EXISTING
// policy.users[<sub>] mechanism, same as a human.
{
  const svc: Principal = { id: "svc-agent-1", groups: [], roles: ["service"], mfa: false, claims: {} };
  const secWithSvc: SecurityConfig = {
    ...SEC,
    policy: {
      ...SEC.policy!,
      users: {
        ...SEC.policy!.users,
        "svc-agent-1": { allowedTiers: ["SIMPLE"], maxClassification: "UNCLASSIFIED", onViolation: "deny" },
      },
    },
  };
  const pol = resolvePolicy(svc, secWithSvc);
  ok(
    "service principal picks up its own policy.users[sub] entry",
    JSON.stringify(pol.allowedTiers) === JSON.stringify(["SIMPLE"]) && pol.maxClassification === "UNCLASSIFIED",
    JSON.stringify(pol),
  );
  const d = authorize(pol, "bedrock/claude-sonnet", "MEDIUM", ROUTING);
  ok("service principal denied a tier outside its assigned policy", d.effect === "deny", JSON.stringify(d));
  const allow = authorize(pol, "local/llama", "SIMPLE", ROUTING);
  ok("service principal allowed within its assigned policy", allow.effect === "allow", JSON.stringify(allow));

  // No per-sub entry → falls back to the default/group floor like any principal.
  const svcNoOverride = resolvePolicy({ ...svc, id: "svc-agent-2" }, secWithSvc);
  ok(
    "a service sub with no policy.users entry gets the default floor (no implicit grant from roles)",
    JSON.stringify(svcNoOverride.allowedTiers) === JSON.stringify(SEC.policy!.default.allowedTiers),
    JSON.stringify(svcNoOverride),
  );
}

console.log("\nQuota:");
{
  const store = new SqliteStore(":memory:");
  store.init();
  const budgets = [{ window: "day" as const, maxCostUsd: 1.0 }, { window: "minute" as const, maxRequests: 2 }];

  ok("fresh principal under quota", checkQuota(store, "q", budgets).allowed === true);

  // spend $0.60 then $0.60 → over $1/day
  for (let i = 0; i < 2; i++) {
    store.recordUsage({
      ts: new Date().toISOString(), requestId: `r${i}`, principalId: "q", groups: "[]",
      provider: "bedrock", model: "claude-opus", tier: "COMPLEX",
      inputTokens: 1000, outputTokens: 1000, cacheReadTokens: 0, costUsd: 0.6, outcome: "ok",
    });
  }
  const over = checkQuota(store, "q", budgets);
  ok("daily cost cap exceeded → deny", !over.allowed && over.violation?.limitType === "costUsd", JSON.stringify(over));

  // rate limit: 2 requests already in the last minute → maxRequests:2 exceeded
  const rl = checkQuota(store, "q", [{ window: "minute", maxRequests: 2 }]);
  ok("rpm rate limit exceeded → deny", !rl.allowed && rl.violation?.limitType === "requests", JSON.stringify(rl));

  // a different principal is unaffected
  ok("isolation: other principal under quota", checkQuota(store, "other", budgets).allowed === true);
  store.close();
}

console.log(`\nPolicy/Quota: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
