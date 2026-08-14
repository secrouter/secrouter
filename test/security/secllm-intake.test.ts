/**
 * SECROUTER_SECLLM_ENDPOINTS turnkey intake tests. Run:
 *   npx tsx test/security/secllm-intake.test.ts
 *
 * Covers: provider + tier + provider-auth auto-registration from the env var
 * (ROUTING + PROVIDER AUTH ONLY — see config.ts applySecllmEndpointsIntake),
 * non-destructive no-op when the operator has taken explicit ownership
 * (provider OR tier routing, each checked independently), demotion/dedup of
 * the prior primary into fallback, a regression guard proving the intake
 * NEVER touches `security.egress` (egress is explicit — SECROUTER_EGRESS_FILE
 * is covered in egress.test.ts), and a regression guard against the env-var
 * intake ever leaking a mutation into the shared DEFAULT_CONFIG module state
 * (which would poison later, unrelated loadConfig() calls in the same
 * process).
 */

import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, getConfig, validateSecurityConfig, parseSecllmModels, type FreeRouterConfig } from "../../src/config.js";
import { checkEgress } from "../../src/security/egress/allowlist.js";

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

function tempConfigPath(partial: Record<string, unknown>): string {
  const dir = mkdtempSync(join(tmpdir(), "secrouter-secllm-intake-"));
  const authPath = join(dir, "auth.json");
  writeFileSync(authPath, JSON.stringify({ version: 1, profiles: {}, lastGood: {} }));
  const cfgPath = join(dir, "config.json");
  writeFileSync(
    cfgPath,
    JSON.stringify({
      port: 1,
      host: "127.0.0.1",
      auth: { default: "profiles", profiles: { type: "profiles", profilesPath: authPath } },
      ...partial,
    }),
  );
  return cfgPath;
}

/**
 * Load with a clean env-var slate for SECROUTER_CONFIG / SECROUTER_SECLLM_ENDPOINTS.
 * Also clears SECROUTER_EGRESS_FILE (a different intake, covered in
 * egress.test.ts) so it can never leak in from another test file sharing
 * this process.
 */
function loadWith(opts: { configPath?: string; secllmEndpoints?: string; secllmModels?: string }): FreeRouterConfig {
  if (opts.configPath) process.env.SECROUTER_CONFIG = opts.configPath;
  else delete process.env.SECROUTER_CONFIG;
  if (opts.secllmEndpoints !== undefined) process.env.SECROUTER_SECLLM_ENDPOINTS = opts.secllmEndpoints;
  else delete process.env.SECROUTER_SECLLM_ENDPOINTS;
  if (opts.secllmModels !== undefined) process.env.SECROUTER_SECLLM_MODELS = opts.secllmModels;
  else delete process.env.SECROUTER_SECLLM_MODELS;
  delete process.env.SECROUTER_EGRESS_FILE;
  loadConfig();
  return getConfig();
}

console.log("No SECROUTER_SECLLM_ENDPOINTS set — built-in defaults untouched:");
{
  const cfg = loadWith({});
  ok("no secllm provider", cfg.providers.secllm === undefined);
  ok("SIMPLE tier is still the built-in bedrock default", cfg.tiers.SIMPLE.primary === "bedrock/openai.gpt-oss-20b-1:0");
}

console.log("\nSECROUTER_SECLLM_ENDPOINTS set, no config file (pure defaults + env turnkey):");
{
  const cfg = loadWith({ secllmEndpoints: " http://gpu1.internal:8000/v1 , http://gpu2.internal:8000/v1 ,, " });
  ok(
    "provider 'secllm' registered with the parsed, trimmed, de-blanked URL array",
    JSON.stringify(cfg.providers.secllm?.baseUrl) === '["http://gpu1.internal:8000/v1","http://gpu2.internal:8000/v1"]',
    JSON.stringify(cfg.providers.secllm),
  );
  ok("provider api = openai", cfg.providers.secllm?.api === "openai");
  ok(
    "provider auth = env SECROUTER_SECLLM_TOKEN (Part 3 wiring)",
    JSON.stringify(cfg.providers.secllm?.auth) === '{"type":"env","key":"SECROUTER_SECLLM_TOKEN"}',
    JSON.stringify(cfg.providers.secllm?.auth),
  );

  ok("SIMPLE -> secllm/fast", cfg.tiers.SIMPLE.primary === "secllm/fast");
  ok("MEDIUM -> secllm/balanced", cfg.tiers.MEDIUM.primary === "secllm/balanced");
  ok("COMPLEX -> secllm/large", cfg.tiers.COMPLEX.primary === "secllm/large");
  ok("REASONING -> secllm/reasoning", cfg.tiers.REASONING.primary === "secllm/reasoning");

  // SIMPLE's default fallback was already ["bedrock/openai.gpt-oss-120b-1:0"];
  // the prior primary ("bedrock/openai.gpt-oss-20b-1:0") is demoted to the
  // FRONT of fallback, the pre-existing fallback entries follow, deduped.
  ok(
    "SIMPLE: prior primary demoted to front of fallback, old fallback preserved after it",
    JSON.stringify(cfg.tiers.SIMPLE.fallback) === '["bedrock/openai.gpt-oss-20b-1:0","bedrock/openai.gpt-oss-120b-1:0"]',
    JSON.stringify(cfg.tiers.SIMPLE.fallback),
  );
  ok(
    "MEDIUM: prior primary (bedrock 120b) demoted into a previously-empty fallback",
    JSON.stringify(cfg.tiers.MEDIUM.fallback) === '["bedrock/openai.gpt-oss-120b-1:0"]',
  );

  // agenticTiers gets the same turnkey treatment.
  ok("agenticTiers.SIMPLE -> secllm/fast too", cfg.agenticTiers?.SIMPLE.primary === "secllm/fast");
  ok(
    "agenticTiers.SIMPLE fallback demoted the same way",
    JSON.stringify(cfg.agenticTiers?.SIMPLE.fallback) === '["bedrock/openai.gpt-oss-20b-1:0","bedrock/openai.gpt-oss-120b-1:0"]',
  );

  // ROUTING + AUTH ONLY: no egress side effect whatsoever — DEFAULT_CONFIG
  // never had a `security` block, and this intake must not create one just
  // to stash an egress rule (that was the old, now-removed, behavior).
  ok("no security block was created (routing + auth only, never egress)", cfg.security === undefined);
}

console.log("\nSECROUTER_SECLLM_ENDPOINTS set, WITH a config file that has its own tiers (no secllm):");
{
  const cfgPath = tempConfigPath({
    providers: { local: { api: "openai", baseUrl: "http://llm.internal:8000/v1" } },
    tiers: {
      SIMPLE: { primary: "local/llama-small", fallback: [] },
      MEDIUM: { primary: "local/llama-big", fallback: ["local/llama-small"] },
      COMPLEX: { primary: "local/llama-big", fallback: [] },
      REASONING: { primary: "local/llama-big", fallback: [] },
    },
    security: {
      enabled: true,
      oidc: { issuer: "https://idp.example.mil", audience: "secrouter" },
      classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI", "CUI//SP-PRVCY"] },
      egress: { allowlist: [{ provider: "local", allowedHost: "llm.internal:8000", authorizedClassifications: ["CUI"] }] },
    },
  });
  const cfg = loadWith({ configPath: cfgPath, secllmEndpoints: "http://pool-a:8000/v1,http://pool-b:8000/v1" });
  ok("secllm provider added alongside the operator's 'local' provider", !!cfg.providers.secllm && !!cfg.providers.local);
  ok(
    "secllm provider auth wired to SECROUTER_SECLLM_TOKEN",
    JSON.stringify(cfg.providers.secllm?.auth) === '{"type":"env","key":"SECROUTER_SECLLM_TOKEN"}',
  );
  ok("MEDIUM -> secllm/balanced", cfg.tiers.MEDIUM.primary === "secllm/balanced");
  ok(
    "MEDIUM: prior primary demoted, pre-existing fallback entry deduped (not doubled)",
    JSON.stringify(cfg.tiers.MEDIUM.fallback) === '["local/llama-big","local/llama-small"]',
    JSON.stringify(cfg.tiers.MEDIUM.fallback),
  );

  // The pre-existing 'local' egress rule is untouched, and — the whole point
  // of Part 1 — NO 'secllm' egress rule was added. The pool is turnkey-ROUTED
  // to but not yet AUTHORIZED: a real request would be egress-denied until an
  // operator adds a rule or SECROUTER_EGRESS_FILE (see egress.test.ts).
  const rules = cfg.security?.egress?.allowlist ?? [];
  ok("pre-existing 'local' egress rule is untouched (not overwritten/duplicated)", rules.filter((r) => r.provider === "local").length === 1);
  ok("no 'secllm' egress rule was added — egress is never inferred by this intake", !rules.some((r) => r.provider === "secllm"), JSON.stringify(rules));
  ok(
    "a request to the turnkey-routed pool is still egress-DENIED (deny-by-default, unaffected by routing)",
    checkEgress("secllm", "pool-a:8000", "CUI", cfg.security!).allowed === false,
  );
}

console.log("\nNon-destructive: explicit `providers.secllm` in config => strict no-op (provider AND tiers):");
{
  const cfgPath = tempConfigPath({
    providers: {
      secllm: { api: "openai", baseUrl: "http://operator-chosen-secllm:9000/v1" },
    },
    tiers: {
      SIMPLE: { primary: "secllm/my-own-model", fallback: [] },
      MEDIUM: { primary: "secllm/my-own-model", fallback: [] },
      COMPLEX: { primary: "secllm/my-own-model", fallback: [] },
      REASONING: { primary: "secllm/my-own-model", fallback: [] },
    },
  });
  const cfg = loadWith({ configPath: cfgPath, secllmEndpoints: "http://should-be-ignored:8000/v1" });
  ok(
    "operator's secllm baseUrl is untouched (env urls NOT applied)",
    cfg.providers.secllm?.baseUrl === "http://operator-chosen-secllm:9000/v1",
    JSON.stringify(cfg.providers.secllm),
  );
  ok("operator's secllm auth is untouched (no auth block force-added)", cfg.providers.secllm?.auth === undefined);
  ok("operator's tier routing is untouched (not turnkey-rewritten)", cfg.tiers.SIMPLE.primary === "secllm/my-own-model");
  ok("no security block was created at all", cfg.security === undefined);
}

console.log("\nNon-destructive: no secllm provider, but a tier already routes to secllm/* => strict no-op:");
{
  const cfgPath = tempConfigPath({
    providers: { local: { api: "openai", baseUrl: "http://llm.internal:8000/v1" } },
    tiers: {
      SIMPLE: { primary: "local/llama-small", fallback: [] },
      MEDIUM: { primary: "local/llama-big", fallback: [] },
      COMPLEX: { primary: "local/llama-big", fallback: [] },
      // Only the FALLBACK references secllm/* — still counts as "routes to secllm/*".
      REASONING: { primary: "local/llama-big", fallback: ["secllm/some-custom-reasoning-model"] },
    },
  });
  const cfg = loadWith({ configPath: cfgPath, secllmEndpoints: "http://should-be-ignored:8000/v1" });
  ok("no secllm provider was added (whole-config no-op, not just that tier)", cfg.providers.secllm === undefined);
  ok("unrelated SIMPLE tier is ALSO left untouched", cfg.tiers.SIMPLE.primary === "local/llama-small");
}

console.log("\nRegression guard: intake never leaks a mutation into shared DEFAULT_CONFIG state:");
{
  // 1) Turnkey-inject against pure defaults (no file).
  const withEnv = loadWith({ secllmEndpoints: "http://gpuA:8000/v1" });
  ok("sanity: secllm present while the env var is set", withEnv.providers.secllm !== undefined);

  // 2) Unset the env var and reload against pure defaults again — if intake
  // had mutated DEFAULT_CONFIG's own nested objects in place (rather than
  // cloning before writing), this would still show a leftover 'secllm'
  // provider / rewritten tiers even with the env var gone.
  const withoutEnv = loadWith({});
  ok("secllm provider is GONE once the env var is unset", withoutEnv.providers.secllm === undefined);
  ok(
    "tiers are back to the pristine built-in defaults (DEFAULT_CONFIG was not poisoned)",
    withoutEnv.tiers.SIMPLE.primary === "bedrock/openai.gpt-oss-20b-1:0" &&
      JSON.stringify(withoutEnv.tiers.SIMPLE.fallback) === '["bedrock/openai.gpt-oss-120b-1:0"]',
    JSON.stringify(withoutEnv.tiers.SIMPLE),
  );
  ok("security block is gone too (DEFAULT_CONFIG never had one — nothing leaked)", withoutEnv.security === undefined);

  // 3) The sharper variant of the same hazard: a config FILE that OMITS
  // `providers`/`tiers`/`agenticTiers` entirely (relies on defaults for all
  // three) takes a DIFFERENT code path through loadConfig() — deepMerge()
  // rather than structuredClone(DEFAULT_CONFIG) — which shallow-copies
  // top-level keys the file doesn't touch, i.e. `merged.tiers` can end up the
  // SAME object reference as DEFAULT_CONFIG.tiers. Writing through that
  // reference without cloning first would poison the module-level default for
  // every later, unrelated loadConfig() call in this process.
  const bareFilePath = tempConfigPath({}); // no providers/tiers/agenticTiers/security keys at all
  const withBareFile = loadWith({ configPath: bareFilePath, secllmEndpoints: "http://gpuZ:8000/v1" });
  ok(
    "intake still applies when providers/tiers come straight from defaults via a file with no such keys",
    withBareFile.providers.secllm !== undefined && withBareFile.tiers.SIMPLE.primary === "secllm/fast",
  );
  const cleanAgain = loadWith({}); // fresh defaults, env var gone, no file
  ok("DEFAULT_CONFIG.providers still not poisoned after the omitted-keys-file path", cleanAgain.providers.secllm === undefined);
  ok(
    "DEFAULT_CONFIG.tiers still not poisoned after the omitted-keys-file path",
    cleanAgain.tiers.SIMPLE.primary === "bedrock/openai.gpt-oss-20b-1:0",
    JSON.stringify(cleanAgain.tiers.SIMPLE),
  );
  ok("DEFAULT_CONFIG.security still not poisoned either", cleanAgain.security === undefined);
}

console.log("\nIdempotency: repeated loadConfig() calls with the same env + file produce a stable result:");
{
  const cfgPath = tempConfigPath({
    providers: { local: { api: "openai", baseUrl: "http://llm.internal:8000/v1" } },
    tiers: {
      SIMPLE: { primary: "local/llama-small", fallback: [] },
      MEDIUM: { primary: "local/llama-big", fallback: [] },
      COMPLEX: { primary: "local/llama-big", fallback: [] },
      REASONING: { primary: "local/llama-big", fallback: [] },
    },
  });
  const first = loadWith({ configPath: cfgPath, secllmEndpoints: "http://gpu1:8000/v1,http://gpu2:8000/v1" });
  const second = loadWith({ configPath: cfgPath, secllmEndpoints: "http://gpu1:8000/v1,http://gpu2:8000/v1" });
  ok("second loadConfig() reproduces the identical provider config", JSON.stringify(first.providers.secllm) === JSON.stringify(second.providers.secllm));
  ok(
    "second loadConfig() reproduces identical tiers (no accumulating/duplicating fallback)",
    JSON.stringify(first.tiers) === JSON.stringify(second.tiers),
    JSON.stringify(second.tiers.SIMPLE),
  );
}

console.log("\nComposes with security.enabled: true (turnkey routes + auths, but egress stays deny-by-default):");
{
  // A realistic secured deploy: OIDC + a non-empty egress allow-list for its
  // EXISTING provider ("bedrock") — no rule for 'secllm' in the file at all.
  // Part 1: the turnkey intake registers the provider/tiers/auth regardless,
  // but 'secllm' traffic stays egress-denied until an operator (or
  // SECROUTER_EGRESS_FILE — see egress.test.ts) explicitly authorizes it.
  const cfgPath = tempConfigPath({
    providers: { bedrock: { api: "openai", baseUrl: "https://bedrock-runtime.us-gov-west-1.amazonaws.com/openai/v1" } },
    tiers: {
      SIMPLE: { primary: "bedrock/x", fallback: [] },
      MEDIUM: { primary: "bedrock/x", fallback: [] },
      COMPLEX: { primary: "bedrock/x", fallback: [] },
      REASONING: { primary: "bedrock/x", fallback: [] },
    },
    security: {
      enabled: true,
      oidc: { issuer: "https://idp.example.mil", audience: "secrouter" },
      classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI"] },
      egress: {
        allowlist: [
          { provider: "bedrock", allowedHost: "bedrock-runtime.us-gov-west-1.amazonaws.com", authorizedClassifications: ["CUI"] },
        ],
      },
    },
  });
  const cfg = loadWith({ configPath: cfgPath, secllmEndpoints: "http://gpu1:8000/v1,http://gpu2:8000/v1" });
  ok("secllm provider registered even with security.enabled: true", cfg.providers.secllm !== undefined);
  ok(
    "secllm provider auth wired to SECROUTER_SECLLM_TOKEN even under security.enabled: true",
    JSON.stringify(cfg.providers.secllm?.auth) === '{"type":"env","key":"SECROUTER_SECLLM_TOKEN"}',
  );
  ok(
    "tiers turnkey-routed to secllm, prior primary (bedrock/x) demoted to fallback",
    cfg.tiers.SIMPLE.primary === "secllm/fast" && JSON.stringify(cfg.tiers.SIMPLE.fallback) === '["bedrock/x"]',
  );
  const errors = validateSecurityConfig(cfg);
  ok(
    "validateSecurityConfig has NO errors — the server boots (the bedrock rule alone keeps the allow-list non-empty)",
    errors.length === 0,
    JSON.stringify(errors),
  );
  ok(
    "the pre-existing 'bedrock' rule is untouched",
    cfg.security?.egress?.allowlist.some((r) => r.provider === "bedrock" && r.allowedHost === "bedrock-runtime.us-gov-west-1.amazonaws.com"),
  );
  ok("still no 'secllm' egress rule anywhere", !cfg.security?.egress?.allowlist.some((r) => r.provider === "secllm"), JSON.stringify(cfg.security?.egress?.allowlist));
  // The core Part 1 guarantee, proven against the real deny-by-default gate:
  // routing to secllm/fast works, but the pool itself is NOT reachable yet.
  ok(
    "a real request to the turnkey pool is egress-DENIED — routing != authorization",
    checkEgress("secllm", "gpu1:8000", "CUI", cfg.security!).allowed === false,
  );
  // Full-server, authenticated-traffic proof that adding an explicit
  // SECROUTER_EGRESS_FILE (or a hand-authored rule) then makes the SAME
  // turnkey pool reachable — both endpoints, real round-robin, provider auth
  // on both the forward AND the /v1/models poll — lives in e2e.test.ts.
}

console.log("\nRegression guard: turnkey intake never touches security.egress (Part 1 removed egress synthesis entirely):");
{
  const cfgPath = tempConfigPath({
    security: {
      enabled: true,
      oidc: { issuer: "https://idp.example.mil", audience: "secrouter" },
      classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI"] },
      egress: {
        allowlist: [
          { provider: "bedrock", allowedHost: "bedrock-runtime.us-gov-west-1.amazonaws.com", authorizedClassifications: ["CUI"] },
          { provider: "secllm", allowedHost: "operator-picked-host:9000", authorizedClassifications: ["CUI"], authorization: "Hand-authored by the operator" },
        ],
      },
    },
  });
  const before = JSON.parse(JSON.stringify(loadWith({ configPath: cfgPath }).security?.egress));
  const after = loadWith({ configPath: cfgPath, secllmEndpoints: "http://gpu1:8000/v1,http://gpu2:8000/v1" });
  ok("provider + tiers WERE still turnkey-registered (that gate is independent of egress)", after.providers.secllm !== undefined && after.tiers.SIMPLE.primary === "secllm/fast");
  ok(
    "security.egress is BYTE-FOR-BYTE identical whether or not the turnkey intake ran",
    JSON.stringify(after.security?.egress) === JSON.stringify(before),
    JSON.stringify({ before, after: after.security?.egress }),
  );
}

console.log("\nparseSecllmModels: parses tag=id pairs, skips junk (never throws):");
{
  const m = parseSecllmModels(" balanced = lmstudio/gemma-26b , fast=llama-3b ,, bogus=x , large , reasoning= ");
  ok("balanced parsed + trimmed", m.balanced === "lmstudio/gemma-26b", JSON.stringify(m));
  ok("fast parsed + trimmed", m.fast === "llama-3b");
  ok("unknown tag 'bogus' skipped", !("bogus" in m));
  ok("malformed 'large' (no '=') skipped", !("large" in m));
  ok("empty id 'reasoning=' skipped", !("reasoning" in m));
  ok("blank entries between commas ignored", Object.keys(m).length === 2);
  ok("undefined → empty map", Object.keys(parseSecllmModels(undefined)).length === 0);
  ok("case-insensitive tag key", parseSecllmModels("BALANCED=z").balanced === "z");
  ok("id may itself contain '=' (only the first splits)", parseSecllmModels("fast=a=b").fast === "a=b");
}

console.log("\nSECROUTER_SECLLM_MODELS remaps tags to real backend ids (balanced → the 26B tool-caller):");
{
  const cfg = loadWith({
    secllmEndpoints: "http://mlx-a:8082/v1",
    secllmModels: "fast=mlx-community/Llama-3.2-3B-Instruct-4bit,balanced=lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit",
  });
  ok("provider still registered (endpoints drive the provider; models only relabel tiers)", cfg.providers.secllm !== undefined);
  ok(
    "MEDIUM (the 'balanced' tag) → secllm/<gemma id>",
    cfg.tiers.MEDIUM.primary === "secllm/lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit",
    cfg.tiers.MEDIUM.primary,
  );
  ok(
    "SIMPLE (the 'fast' tag) → secllm/<llama id>",
    cfg.tiers.SIMPLE.primary === "secllm/mlx-community/Llama-3.2-3B-Instruct-4bit",
    cfg.tiers.SIMPLE.primary,
  );
  ok("COMPLEX (the 'large' tag, unspecified) keeps the literal default", cfg.tiers.COMPLEX.primary === "secllm/large");
  ok("REASONING (unspecified) keeps the literal default", cfg.tiers.REASONING.primary === "secllm/reasoning");
  ok(
    "agenticTiers.MEDIUM is remapped identically (agentic path uses the same catalog)",
    cfg.agenticTiers?.MEDIUM.primary === "secllm/lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit",
  );
  ok(
    "fallback demotion is unaffected by the remap — prior MEDIUM primary (bedrock 120b) still demoted",
    JSON.stringify(cfg.tiers.MEDIUM.fallback) === '["bedrock/openai.gpt-oss-120b-1:0"]',
    JSON.stringify(cfg.tiers.MEDIUM.fallback),
  );
  ok(
    "cfg.secllmModelAliases exposes the tag→id map (so an explicit secllm/<tag> resolves at forward time)",
    JSON.stringify(cfg.secllmModelAliases) ===
      JSON.stringify({ fast: "mlx-community/Llama-3.2-3B-Instruct-4bit", balanced: "lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit" }),
    JSON.stringify(cfg.secllmModelAliases),
  );
}

console.log("\nSECROUTER_SECLLM_MODELS with NO endpoints ⇒ strict no-op (the intake needs endpoints to run):");
{
  const cfg = loadWith({ secllmModels: "balanced=lmstudio/gemma-26b" });
  ok("no secllm provider (endpoints unset ⇒ intake never runs)", cfg.providers.secllm === undefined);
  ok("tiers stay at the built-in bedrock defaults", cfg.tiers.MEDIUM.primary === "bedrock/openai.gpt-oss-120b-1:0");
}

console.log("\nNon-destructive: an explicit providers.secllm ⇒ SECROUTER_SECLLM_MODELS is ignored too (operator owns routing):");
{
  const cfgPath = tempConfigPath({
    providers: { secllm: { api: "openai", baseUrl: "http://operator:9000/v1" } },
    tiers: {
      SIMPLE: { primary: "secllm/my-own", fallback: [] },
      MEDIUM: { primary: "secllm/my-own", fallback: [] },
      COMPLEX: { primary: "secllm/my-own", fallback: [] },
      REASONING: { primary: "secllm/my-own", fallback: [] },
    },
  });
  const cfg = loadWith({ configPath: cfgPath, secllmEndpoints: "http://ignored:8000/v1", secllmModels: "balanced=should-be-ignored" });
  ok("operator's MEDIUM primary untouched (remap did not apply)", cfg.tiers.MEDIUM.primary === "secllm/my-own");
}

delete process.env.SECROUTER_CONFIG;
delete process.env.SECROUTER_SECLLM_ENDPOINTS;
delete process.env.SECROUTER_SECLLM_MODELS;

console.log(`\nSecLLM intake: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
