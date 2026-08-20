/**
 * Azure AI Foundry + Bedrock-OpenAI provider tests.
 * Run: npx tsx test/security/azure.test.ts
 *
 * Stubs fetch and drives forwardRequest to assert the wire shape:
 *  - Azure builds /openai/deployments/{model}/chat/completions?api-version=… and
 *    authenticates with the api-key header (key mode) or an Entra bearer (entra mode).
 *  - Bedrock's OpenAI-compatible endpoint routes through the standard OpenAI path
 *    (…/openai/v1/chat/completions) with Authorization: Bearer.
 *  - Entra tokens are fetched via client-credentials and cached.
 *  - Config validation is fail-closed for azure/entra misconfig.
 */

import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ServerResponse } from "node:http";
import { loadConfig, validateSecurityConfig, type FreeRouterConfig } from "../../src/config.js";
import { forwardRequest, type ChatRequest } from "../../src/provider.js";
import { getEntraToken, clearEntraCache } from "../../src/security/transport/azureEntra.js";

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

// ── stub fetch: capture outbound requests; answer token + chat endpoints ──
type Call = { url: string; headers: Record<string, string>; body: string };
const calls: Call[] = [];
let entraFetches = 0;
const origFetch = globalThis.fetch;
globalThis.fetch = (async (url: string, init: RequestInit) => {
  const u = String(url);
  calls.push({ url: u, headers: (init.headers as Record<string, string>) ?? {}, body: String(init.body ?? "") });
  if (u.includes("login.microsoftonline")) {
    entraFetches++;
    return new Response(JSON.stringify({ access_token: "ENTRA-TOKEN-123", expires_in: 3600 }), { headers: { "content-type": "application/json" } });
  }
  return new Response(
    JSON.stringify({ model: "m", choices: [{ message: { role: "assistant", content: "hi" }, finish_reason: "stop" }], usage: { prompt_tokens: 5, completion_tokens: 3 } }),
    { headers: { "content-type": "application/json" } },
  );
}) as typeof fetch;

function fakeRes(): ServerResponse {
  const r = { statusCode: 0, headers: {} as Record<string, unknown>, body: "", headersSent: false } as unknown as Record<string, unknown>;
  r.setHeader = (k: string, v: unknown) => ((r.headers as Record<string, unknown>)[k] = v);
  r.writeHead = (s: number, h?: Record<string, unknown>) => (Object.assign(r.headers as object, h ?? {}), (r.statusCode = s), r.headersSent = true, r);
  r.write = (c: string) => ((r.body = (r.body as string) + c), true);
  r.end = (c?: string) => (c ? (r.body = (r.body as string) + c) : undefined);
  return r as unknown as ServerResponse;
}

const chat: ChatRequest = { messages: [{ role: "user", content: "hi" }] } as ChatRequest;
const last = () => calls[calls.length - 1];

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "secrouter-azure-"));
  const cfgPath = join(dir, "config.json");
  writeFileSync(
    cfgPath,
    JSON.stringify({
      port: 1, host: "127.0.0.1",
      providers: {
        azurekey: { api: "azure", baseUrl: "https://res.openai.azure.us", apiVersion: "2024-10-21", azureAuth: "api-key", auth: { type: "env", key: "AZ_KEY" } },
        azureentra: { api: "azure", baseUrl: "https://res.openai.azure.us", apiVersion: "2025-01-01", azureAuth: "entra", entra: { tenantId: "tid", clientId: "cid", clientSecretEnv: "AZ_SECRET", authority: "https://login.microsoftonline.us", scope: "https://cognitiveservices.azure.us/.default" } },
        bedrock: { api: "openai", baseUrl: "https://bedrock-runtime.us-gov-west-1.amazonaws.com/openai/v1", auth: { type: "env", key: "BR_KEY" } },
        // Same shape the SECROUTER_SECLLM_ENDPOINTS turnkey intake registers
        // (config.ts applySecllmEndpointsIntake) — proves the generic
        // env-auth path (not a secllm-specific special case) both sends the
        // header when the token resolves and omits it when it doesn't.
        secllm: { api: "openai", baseUrl: "http://127.0.0.1:1/v1", auth: { type: "env", key: "SECROUTER_SECLLM_TOKEN" } },
      },
      tiers: { SIMPLE: { primary: "azurekey/gpt-4o", fallback: [] }, MEDIUM: { primary: "azurekey/gpt-4o", fallback: [] }, COMPLEX: { primary: "azurekey/gpt-4o", fallback: [] }, REASONING: { primary: "azurekey/gpt-4o", fallback: [] } },
      auth: { default: "profiles", profiles: { type: "profiles", profilesPath: join(dir, "auth.json") } },
    }),
  );
  writeFileSync(join(dir, "auth.json"), JSON.stringify({ version: 1, profiles: {}, lastGood: {} }));
  process.env.FREEROUTER_CONFIG = cfgPath;
  process.env.AZ_KEY = "azure-secret-key";
  process.env.BR_KEY = "bedrock-api-key";
  process.env.AZ_SECRET = "entra-client-secret";
  loadConfig();

  console.log("Azure + Bedrock-OpenAI forwarding:");

  await forwardRequest(chat, "azurekey/gpt-4o", "SIMPLE", fakeRes(), false);
  ok("azure URL = /openai/deployments/{model}/chat/completions?api-version", last().url === "https://res.openai.azure.us/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21", last().url);
  ok("azure api-key mode → api-key header (not Authorization)", last().headers["api-key"] === "azure-secret-key" && !last().headers["Authorization"]);

  await forwardRequest(chat, "bedrock/openai.gpt-oss-120b-1:0", "MEDIUM", fakeRes(), false);
  ok("bedrock-openai routes via the OpenAI path to /openai/v1/chat/completions", last().url === "https://bedrock-runtime.us-gov-west-1.amazonaws.com/openai/v1/chat/completions", last().url);
  ok("bedrock-openai uses Authorization: Bearer <api key>", last().headers["Authorization"] === "Bearer bedrock-api-key");

  console.log("\nSecLLM provider auth (Part 3: token from SECROUTER_SECLLM_TOKEN, same generic env-auth path):");
  process.env.SECROUTER_SECLLM_TOKEN = "secllm-secret-token";
  await forwardRequest(chat, "secllm/Llama-3.2-3B-Instruct", "SIMPLE", fakeRes(), false);
  ok("SECROUTER_SECLLM_TOKEN set -> Authorization: Bearer <token> sent on forward", last().headers["Authorization"] === "Bearer secllm-secret-token", JSON.stringify(last().headers));

  delete process.env.SECROUTER_SECLLM_TOKEN;
  await forwardRequest(chat, "secllm/Llama-3.2-3B-Instruct", "SIMPLE", fakeRes(), false);
  ok(
    "SECROUTER_SECLLM_TOKEN unset -> no Authorization header at all (open SecLLM, back-compat)",
    !("Authorization" in last().headers),
    JSON.stringify(last().headers),
  );

  clearEntraCache();
  entraFetches = 0;
  await forwardRequest(chat, "azureentra/gpt-4o", "SIMPLE", fakeRes(), false);
  ok("azure entra mode → Authorization: Bearer <entra token>", last().headers["Authorization"] === "Bearer ENTRA-TOKEN-123");
  ok("azure entra hit the tenant token endpoint", calls.some((c) => c.url === "https://login.microsoftonline.us/tid/oauth2/v2.0/token"));
  ok("azure entra uses api-version from provider config", last().url.endsWith("api-version=2025-01-01"));

  await forwardRequest(chat, "azureentra/gpt-4o", "SIMPLE", fakeRes(), false);
  ok("entra token is cached (no second token fetch)", entraFetches === 1);

  console.log("\nEntra token helper:");
  clearEntraCache();
  const t = await getEntraToken("p", { tenantId: "t", clientId: "c", clientSecretEnv: "AZ_SECRET" });
  ok("getEntraToken returns the access_token", t === "ENTRA-TOKEN-123");
  let threw = false;
  try {
    await getEntraToken("p2", { tenantId: "t", clientId: "c", clientSecretEnv: "MISSING_ENV_VAR" });
  } catch {
    threw = true;
  }
  ok("missing client-secret env → throws", threw);

  console.log("\nFail-closed azure config validation:");
  const base = { providers: {} as Record<string, unknown>, tiers: {}, security: { enabled: false } };
  const errs = (providers: Record<string, unknown>) => validateSecurityConfig({ ...base, providers } as unknown as FreeRouterConfig).filter((e) => /azure|provider/i.test(e));
  ok("valid azure (api-key) → no errors", errs({ a: { api: "azure", baseUrl: "https://r.openai.azure.us", azureAuth: "api-key" } }).length === 0);
  ok("azure missing baseUrl → error", errs({ a: { api: "azure", azureAuth: "api-key" } }).some((e) => /baseUrl/.test(e)));
  ok("azure entra without entra block → error", errs({ a: { api: "azure", baseUrl: "https://r.openai.azure.us", azureAuth: "entra" } }).some((e) => /entra/.test(e)));

  console.log(`\nAzure: ${pass} passed, ${fail} failed`);
  globalThis.fetch = origFetch;
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
