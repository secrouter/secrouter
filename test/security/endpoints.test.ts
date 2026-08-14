/**
 * Add-endpoint tooling tests. Run: npx tsx test/security/endpoints.test.ts
 * Covers the in-boundary probe guard (SSRF), the config-merge logic, validation,
 * and the atomic validated config-file writer (backup + reject-invalid).
 */

import { writeFileSync, readFileSync, existsSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  isInBoundaryHost,
  probeEndpoint,
  applyEndpointToConfig,
  previewEndpoint,
  type EndpointSpec,
} from "../../src/security/endpoints.js";
import { loadConfig, writeConfigFile, getConfigPath, type FreeRouterConfig } from "../../src/config.js";

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

const spec: EndpointSpec = {
  provider: { name: "onprem", api: "openai", baseUrl: "http://vllm.internal:8000/v1" },
  egress: { authorizedClassifications: ["CUI"] }, // allowedHost omitted → derived from baseUrl
  models: [{ id: "onprem/llama", name: "llama", inputPrice: 0, outputPrice: 2 }],
  tiers: { SIMPLE: { primary: "onprem/llama" } },
};

console.log("In-boundary probe guard:");
ok("localhost → allow", isInBoundaryHost("localhost"));
ok("10.0.0.5 (RFC1918) → allow", isInBoundaryHost("10.0.0.5"));
ok("192.168.1.10 (RFC1918) → allow", isInBoundaryHost("192.168.1.10"));
ok("single-label service name → allow", isInBoundaryHost("vllm"));
ok(".internal suffix → allow", isInBoundaryHost("llm.internal"));
ok("public FQDN → DENY", !isInBoundaryHost("api.openai.com"));
ok("public IP 8.8.8.8 → DENY", !isInBoundaryHost("8.8.8.8"));
process.env.SECROUTER_PROBE_ALLOW_HOSTS = "api.openai.com";
ok("env allow-list overrides → allow", isInBoundaryHost("api.openai.com"));
delete process.env.SECROUTER_PROBE_ALLOW_HOSTS;

console.log("\nConfig merge:");
const cfg = { providers: {}, tiers: {}, security: { enabled: true, egress: { allowlist: [] } } } as unknown as FreeRouterConfig;
applyEndpointToConfig(cfg, spec);
ok("provider added", cfg.providers.onprem?.baseUrl === "http://vllm.internal:8000/v1" && cfg.providers.onprem?.api === "openai");
ok("egress host derived from baseUrl (host:port)", cfg.security!.egress!.allowlist[0]?.allowedHost === "vllm.internal:8000");
ok("egress classifications carried", JSON.stringify(cfg.security!.egress!.allowlist[0]?.authorizedClassifications) === '["CUI"]');
ok("model catalog entry added with pricing", cfg.models?.[0]?.id === "onprem/llama" && cfg.models?.[0]?.outputPrice === 2);
ok("tier primary assigned", cfg.tiers.SIMPLE?.primary === "onprem/llama");
// idempotent: re-apply with a new host replaces the rule (no duplicate)
applyEndpointToConfig(cfg, { ...spec, provider: { ...spec.provider, baseUrl: "http://vllm.internal:9000/v1" } });
ok("re-apply replaces egress rule (no dup)", cfg.security!.egress!.allowlist.filter((r) => r.provider === "onprem").length === 1);

// embeddings: kind flows into the catalog and embeddingsDefault into the config
const ecfg = { providers: {}, tiers: {}, security: { enabled: true, egress: { allowlist: [] } } } as unknown as FreeRouterConfig;
applyEndpointToConfig(ecfg, {
  provider: { name: "vec", api: "openai", baseUrl: "http://vec.internal:8000/v1" },
  egress: { authorizedClassifications: ["CUI"] },
  models: [{ id: "vec/text-embed", kind: "embedding", inputPrice: 0 }],
  embeddingsDefault: "vec/text-embed",
});
ok("embedding model kind persisted", ecfg.models?.[0]?.kind === "embedding");
ok("embeddings default set in config", ecfg.embeddings?.default === "vec/text-embed");

// azure: api-version + auth mode flow into the provider config
const azcfg = { providers: {}, tiers: {}, security: { enabled: true, egress: { allowlist: [] } } } as unknown as FreeRouterConfig;
applyEndpointToConfig(azcfg, {
  provider: { name: "azure", api: "azure", baseUrl: "https://r.openai.azure.us", apiVersion: "2025-01-01", azureAuth: "entra", authEnvKey: "AZ_KEY" },
  egress: { authorizedClassifications: ["CUI"] },
  models: [{ id: "azure/gpt-4o", inputPrice: 2.5, outputPrice: 10 }],
});
ok("azure provider api persisted", azcfg.providers.azure?.api === "azure");
ok("azure apiVersion + azureAuth persisted", azcfg.providers.azure?.apiVersion === "2025-01-01" && azcfg.providers.azure?.azureAuth === "entra");

console.log("\nProbe model-list discovery:");
{
  const calls: string[] = [];
  const orig = globalThis.fetch;
  globalThis.fetch = (async (u: unknown) => {
    calls.push(String(u));
    if (String(u).endsWith("/v1/models")) {
      return new Response(JSON.stringify({ object: "list", data: [{ id: "m-a" }, { id: "m-b" }] }), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  try {
    const r = await probeEndpoint({ baseUrl: "http://vllm.internal:8000", api: "openai" });
    ok("tries /models first", calls.some((c) => c.endsWith(":8000/models")));
    ok("falls back to /v1/models and lists the endpoint's models", r.ok === true && (r.models ?? []).join(",") === "m-a,m-b");
  } finally {
    globalThis.fetch = orig;
  }
  const blocked = await probeEndpoint({ baseUrl: "https://api.openai.com/v1", api: "openai" });
  ok("public host blocked before any fetch (SSRF guard)", blocked.ok === false && /in-boundary/.test(blocked.error ?? ""));
}

console.log("\nProbe auth header (Part 3: the /v1/models health-check poll must send resolved provider auth):");
{
  // server.ts's runHealthChecks() calls probeEndpoint() with authEnvKey
  // derived from the provider's `auth: {type:"env", key}` — this is the exact
  // call shape it uses. A token-protected SecLLM would 401 an unauthenticated
  // poll (breaking model-awareness / breaker liveness) without this.
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const orig = globalThis.fetch;
  globalThis.fetch = (async (u: unknown, init?: RequestInit) => {
    calls.push({ url: String(u), headers: (init?.headers as Record<string, string>) ?? {} });
    return new Response(JSON.stringify({ object: "list", data: [{ id: "m-a" }] }), { status: 200 });
  }) as typeof fetch;
  try {
    process.env.SECROUTER_SECLLM_TOKEN = "poll-secret-token";
    await probeEndpoint({ baseUrl: "http://vllm.internal:9000", api: "openai", authEnvKey: "SECROUTER_SECLLM_TOKEN" });
    ok(
      "authEnvKey resolved -> the /models poll carries Authorization: Bearer <token>",
      calls.some((c) => c.headers["Authorization"] === "Bearer poll-secret-token"),
      JSON.stringify(calls.map((c) => c.headers)),
    );

    calls.length = 0;
    delete process.env.SECROUTER_SECLLM_TOKEN;
    await probeEndpoint({ baseUrl: "http://vllm.internal:9000", api: "openai", authEnvKey: "SECROUTER_SECLLM_TOKEN" });
    ok(
      "authEnvKey set but the env var is unset -> no Authorization header on the poll (open SecLLM, back-compat)",
      calls.length > 0 && calls.every((c) => !("Authorization" in c.headers)),
      JSON.stringify(calls.map((c) => c.headers)),
    );
  } finally {
    globalThis.fetch = orig;
  }
}

console.log("\nConfig file writer (atomic, validated, backed up):");
const tmp = join(tmpdir(), `secrouter-endpoints-${process.pid}-${Date.now()}.json`);
const base = {
  port: 18800,
  host: "127.0.0.1",
  providers: { local: { api: "openai", baseUrl: "http://llm.internal:8000/v1" } },
  tiers: { SIMPLE: { primary: "local/x", fallback: [] } },
  auth: { default: "profiles" },
  security: {
    enabled: true,
    oidc: { issuer: "https://idp.internal", audience: "secrouter" },
    egress: { allowlist: [{ provider: "local", allowedHost: "llm.internal:8000", authorizedClassifications: ["CUI"] }] },
    classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI"] },
  },
};
const cleanup = () => [tmp, `${tmp}.bak`, `${tmp}.tmp`].forEach((p) => existsSync(p) && unlinkSync(p));
try {
  writeFileSync(tmp, JSON.stringify(base, null, 2));
  process.env.SECROUTER_CONFIG = tmp;
  loadConfig();
  ok("loader picked up the temp config path", getConfigPath() === tmp);

  // preview validates against the loaded (security-enabled) config
  ok("preview of a valid endpoint → valid", previewEndpoint(spec).valid === true);
  ok(
    "preview with no classifications → invalid",
    previewEndpoint({ ...spec, egress: { authorizedClassifications: [] } }).valid === false,
  );

  // apply writes the file
  const out = writeConfigFile((c) => applyEndpointToConfig(c, spec));
  ok("writeConfigFile returns the path", out.path === tmp);
  const written = JSON.parse(readFileSync(tmp, "utf-8"));
  ok("provider persisted to file", !!written.providers.onprem);
  ok("model catalog persisted to file", written.models?.some((m: { id: string }) => m.id === "onprem/llama"));
  ok("backup written", existsSync(`${tmp}.bak`));
  ok("no leftover .tmp", !existsSync(`${tmp}.tmp`));

  // an invalid mutation is rejected and the file is left untouched
  let threw = false;
  try {
    writeConfigFile((c) => {
      c.security!.egress!.allowlist.push({ provider: "bad", allowedHost: "h", authorizedClassifications: [] });
    });
  } catch {
    threw = true;
  }
  ok("invalid mutation rejected (fail-closed)", threw);
  const after = JSON.parse(readFileSync(tmp, "utf-8"));
  ok("file unchanged after rejected write", !after.security.egress.allowlist.some((r: { provider: string }) => r.provider === "bad"));
} finally {
  delete process.env.SECROUTER_CONFIG;
  cleanup();
}

console.log(`\nEndpoints: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
