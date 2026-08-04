/**
 * Egress / data-residency gate tests. Run: npx tsx test/security/egress.test.ts
 * Proves deny-by-default and the classification gate — the controls that stop
 * CUI from reaching an unauthorized or foreign-jurisdiction destination —
 * plus the SECROUTER_EGRESS_FILE explicit, deployer-authored loader
 * (config.ts applyEgressFileIntake): load/merge/dedupe, deny-by-default
 * unaffected by the merge, and fail-loud on a missing/malformed file.
 */

import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkEgress, allowedHostsOf } from "../../src/security/egress/allowlist.js";
import type { SecurityConfig } from "../../src/security/types.js";
import { loadConfig, getConfig, type FreeRouterConfig } from "../../src/config.js";

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

const SEC: SecurityConfig = {
  enabled: true,
  classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI", "CUI//SP-PRVCY"] },
  egress: {
    allowlist: [
      {
        provider: "bedrock",
        allowedHost: "bedrock-runtime.us-gov-west-1.amazonaws.com",
        authorizedClassifications: ["UNCLASSIFIED", "CUI", "CUI//SP-PRVCY"],
        authorization: "Bedrock GovCloud — FedRAMP High / IL4-5",
      },
      {
        provider: "local",
        allowedHost: "llm.internal.mil",
        authorizedClassifications: ["UNCLASSIFIED", "CUI", "CUI//SP-PRVCY"],
        authorization: "Self-hosted inside the boundary",
      },
    ],
  },
};

console.log("Egress gate:");

// Authorized destinations
ok(
  "Bedrock GovCloud + CUI → allow",
  checkEgress("bedrock", "bedrock-runtime.us-gov-west-1.amazonaws.com", "CUI", SEC).allowed === true,
);
ok("self-hosted + CUI → allow", checkEgress("local", "llm.internal.mil", "CUI", SEC).allowed === true);

// Deny-by-default: provider not in the allow-list (the Kimi/Moonshot case)
ok(
  "Kimi (unlisted PRC provider) → DENY",
  checkEgress("kimi-coding", "api.kimi.com", "CUI", SEC).allowed === false,
);
ok(
  "commercial anthropic (unlisted) → DENY",
  checkEgress("anthropic", "api.anthropic.com", "CUI", SEC).allowed === false,
);

// Host mismatch for a listed provider → deny (defends against config drift / SSRF)
ok(
  "Bedrock listed but wrong host → DENY",
  checkEgress("bedrock", "bedrock-runtime.us-east-1.amazonaws.com", "CUI", SEC).allowed === false,
);

// Classification gate: destination not authorized for the data class
const SEC2: SecurityConfig = {
  ...SEC,
  egress: {
    allowlist: [
      {
        provider: "commercial",
        allowedHost: "api.example.com",
        authorizedClassifications: ["UNCLASSIFIED"],
      },
    ],
  },
};
ok(
  "UNCLASS-only destination + CUI request → DENY",
  checkEgress("commercial", "api.example.com", "CUI", SEC2).allowed === false,
);
ok(
  "UNCLASS-only destination + UNCLASSIFIED request → allow",
  checkEgress("commercial", "api.example.com", "UNCLASSIFIED", SEC2).allowed === true,
);

// Multi-host per provider (pooled/load-balanced providers, config.endpointsOf):
// one rule's allowedHost can be an array covering every endpoint host.
const SEC3: SecurityConfig = {
  ...SEC,
  egress: {
    allowlist: [
      {
        provider: "secllm",
        allowedHost: ["gpu1.internal.mil:8000", "gpu2.internal.mil:8000", "gpu3.internal.mil:8000"],
        authorizedClassifications: ["CUI"],
        authorization: "Self-hosted GPU pool inside the boundary",
      },
    ],
  },
};
console.log("\nMulti-host egress (pooled provider, one rule, array allowedHost):");
ok("pool host 1 + CUI → allow", checkEgress("secllm", "gpu1.internal.mil:8000", "CUI", SEC3).allowed === true);
ok("pool host 2 + CUI → allow", checkEgress("secllm", "gpu2.internal.mil:8000", "CUI", SEC3).allowed === true);
ok("pool host 3 + CUI → allow", checkEgress("secllm", "gpu3.internal.mil:8000", "CUI", SEC3).allowed === true);
ok(
  "a host NOT in the pool array → DENY (adding a baseUrl doesn't silently authorize egress)",
  checkEgress("secllm", "gpu4-unlisted.internal.mil:8000", "CUI", SEC3).allowed === false,
);
ok(
  "classification gate still applies per-host in the array",
  checkEgress("secllm", "gpu1.internal.mil:8000", "TOP_SECRET", SEC3).allowed === false,
);
// Backward compat: a plain string allowedHost (today's shape) still works exactly as before.
ok(
  "single-string allowedHost (unchanged shape) still allows its one host",
  checkEgress("bedrock", "bedrock-runtime.us-gov-west-1.amazonaws.com", "CUI", SEC).allowed === true,
);

console.log("\nallowedHostsOf() normalization:");
ok("string -> one-element list", JSON.stringify(allowedHostsOf({ allowedHost: "h1" })) === '["h1"]');
ok(
  "array -> unchanged (same order)",
  JSON.stringify(allowedHostsOf({ allowedHost: ["h1", "h2"] })) === '["h1","h2"]',
);

console.log("\nSECROUTER_EGRESS_FILE loader (explicit, deployer-authored egress rules):");
{
  const dir = mkdtempSync(join(tmpdir(), "secrouter-egress-file-"));
  const authPath = join(dir, "auth.json");
  writeFileSync(authPath, JSON.stringify({ version: 1, profiles: {}, lastGood: {} }));
  const cfgPath = join(dir, "config.json");
  writeFileSync(
    cfgPath,
    JSON.stringify({
      port: 1,
      host: "127.0.0.1",
      providers: { bedrock: { api: "openai", baseUrl: "https://bedrock-runtime.us-gov-west-1.amazonaws.com/openai/v1" } },
      tiers: {
        SIMPLE: { primary: "bedrock/x", fallback: [] },
        MEDIUM: { primary: "bedrock/x", fallback: [] },
        COMPLEX: { primary: "bedrock/x", fallback: [] },
        REASONING: { primary: "bedrock/x", fallback: [] },
      },
      auth: { default: "profiles", profiles: { type: "profiles", profilesPath: authPath } },
      security: {
        enabled: true,
        oidc: { issuer: "https://idp.example.mil", audience: "secrouter" },
        classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI"] },
        egress: { allowlist: [{ provider: "bedrock", allowedHost: "bedrock-runtime.us-gov-west-1.amazonaws.com", authorizedClassifications: ["CUI"] }] },
      },
    }),
  );

  const rulesPath = join(dir, "egress-rules.json");
  const loadWith = (file?: string): FreeRouterConfig => {
    process.env.FREEROUTER_CONFIG = cfgPath;
    if (file) process.env.SECROUTER_EGRESS_FILE = file;
    else delete process.env.SECROUTER_EGRESS_FILE;
    delete process.env.SECROUTER_SECLLM_ENDPOINTS;
    loadConfig();
    return getConfig();
  };

  // (a) Load + merge: file rules are ADDED to the config-file's own allowlist
  // (created from an existing security.egress block here; a wholly absent
  // security/security.egress block is exercised in scenario (a2) below).
  writeFileSync(
    rulesPath,
    JSON.stringify([
      { provider: "secllm", allowedHost: ["gpu1.internal:8000", "gpu2.internal:8000"], authorizedClassifications: ["CUI"], authorization: "Deployer-generated" },
    ]),
  );
  const cfg = loadWith(rulesPath);
  const rules = cfg.security?.egress?.allowlist ?? [];
  ok("config-file's own 'bedrock' rule is preserved", rules.some((r) => r.provider === "bedrock"));
  ok(
    "file-loaded 'secllm' rule is merged in",
    JSON.stringify(rules.find((r) => r.provider === "secllm")?.allowedHost) === '["gpu1.internal:8000","gpu2.internal:8000"]',
    JSON.stringify(rules),
  );
  ok("exactly 2 rules total (additive, not a replace)", rules.length === 2, JSON.stringify(rules));

  // (b) Non-listed host still DENIED under security.enabled — deny-by-default
  // survives the merge; the file only ever ADDS specific authorizations.
  ok("pool host from the file -> allow", checkEgress("secllm", "gpu1.internal:8000", "CUI", cfg.security!).allowed === true);
  ok(
    "a host NOT in the file (or the config) -> DENY",
    checkEgress("secllm", "not-listed.internal:8000", "CUI", cfg.security!).allowed === false,
  );
  ok("an unrelated unlisted provider -> DENY", checkEgress("rogue", "anything:1", "CUI", cfg.security!).allowed === false);

  // (c) Dedupe: reloading the SAME file must not duplicate the rule it already added.
  const cfg2 = loadWith(rulesPath);
  const rules2 = cfg2.security?.egress?.allowlist ?? [];
  ok("reloading the same file again is idempotent (still exactly 2 rules)", rules2.length === 2, JSON.stringify(rules2));

  // (d) Dedupe against a rule the config file ALREADY has: a file entry for
  // 'bedrock' with the SAME host as the config's own rule must not duplicate.
  writeFileSync(
    rulesPath,
    JSON.stringify([
      { provider: "bedrock", allowedHost: "bedrock-runtime.us-gov-west-1.amazonaws.com", authorizedClassifications: ["CUI"] },
      { provider: "secllm", allowedHost: ["gpu1.internal:8000", "gpu2.internal:8000"], authorizedClassifications: ["CUI"] },
    ]),
  );
  const cfg3 = loadWith(rulesPath);
  const rules3 = cfg3.security?.egress?.allowlist ?? [];
  ok(
    "a file rule matching an existing config-file rule (same provider+host) is deduped, not duplicated",
    rules3.filter((r) => r.provider === "bedrock").length === 1,
    JSON.stringify(rules3),
  );
  ok("still exactly 2 rules total", rules3.length === 2, JSON.stringify(rules3));

  // (a2) Structure created from scratch: a config with NO security/egress
  // block at all still gets one from the file.
  const bareCfgPath = join(dir, "config-bare.json");
  writeFileSync(
    bareCfgPath,
    JSON.stringify({
      port: 1,
      host: "127.0.0.1",
      auth: { default: "profiles", profiles: { type: "profiles", profilesPath: authPath } },
    }),
  );
  process.env.FREEROUTER_CONFIG = bareCfgPath;
  process.env.SECROUTER_EGRESS_FILE = rulesPath;
  loadConfig();
  const bareCfg = getConfig();
  ok(
    "security.egress.allowlist is created from scratch when absent entirely",
    (bareCfg.security?.egress?.allowlist ?? []).length === 2,
    JSON.stringify(bareCfg.security),
  );

  // (e) Missing file -> FAILS LOUD (throws), does not silently continue.
  process.env.FREEROUTER_CONFIG = cfgPath;
  process.env.SECROUTER_EGRESS_FILE = join(dir, "does-not-exist.json");
  let threwMissing = false;
  try {
    loadConfig();
  } catch {
    threwMissing = true;
  }
  ok("missing SECROUTER_EGRESS_FILE -> loadConfig() throws (fail loud, no silent fallback)", threwMissing);

  // (f) Malformed JSON -> also fails loud.
  const badPath = join(dir, "bad.json");
  writeFileSync(badPath, "{ not valid json");
  process.env.SECROUTER_EGRESS_FILE = badPath;
  let threwBadJson = false;
  try {
    loadConfig();
  } catch {
    threwBadJson = true;
  }
  ok("malformed JSON SECROUTER_EGRESS_FILE -> loadConfig() throws", threwBadJson);

  // (g) Not an array -> also fails loud.
  const notArrayPath = join(dir, "not-array.json");
  writeFileSync(notArrayPath, JSON.stringify({ provider: "secllm" }));
  process.env.SECROUTER_EGRESS_FILE = notArrayPath;
  let threwNotArray = false;
  try {
    loadConfig();
  } catch {
    threwNotArray = true;
  }
  ok("non-array SECROUTER_EGRESS_FILE contents -> loadConfig() throws", threwNotArray);

  // (h) A rule missing a required field -> also fails loud.
  const missingFieldPath = join(dir, "missing-field.json");
  writeFileSync(missingFieldPath, JSON.stringify([{ provider: "secllm" }]));
  process.env.SECROUTER_EGRESS_FILE = missingFieldPath;
  let threwMissingField = false;
  try {
    loadConfig();
  } catch {
    threwMissingField = true;
  }
  ok("a rule missing allowedHost/authorizedClassifications -> loadConfig() throws", threwMissingField);

  // Unset entirely -> pure no-op, no throw, config loads clean.
  delete process.env.SECROUTER_EGRESS_FILE;
  let threwUnset = false;
  try {
    loadConfig();
  } catch {
    threwUnset = true;
  }
  ok("SECROUTER_EGRESS_FILE unset -> no-op, loadConfig() does not throw", !threwUnset);

  delete process.env.FREEROUTER_CONFIG;
  delete process.env.SECROUTER_EGRESS_FILE;
}

console.log(`\nEgress: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
