/**
 * Endpoint management API test (models/available, endpoint/remove,
 * endpoint/egress). Run: npx tsx test/security/endpoint-mgmt.test.ts
 *
 * Mirrors test/security/admin.test.ts's live-server harness (real HTTP against
 * a spawned secrouter process) since these three routes exercise the actual
 * probe (real fetch against a fake local model server) and the real
 * validated/atomic config-file writer — not just the pure config-merge helpers
 * already covered by endpoints.test.ts.
 *
 * Covers:
 *  - GET  /admin/api/models/available: lists models for a reachable provider,
 *    marks an unreachable one (with an error), and folds in circuit health.
 *  - POST /admin/api/endpoint/remove: drops provider + egress rule + tier refs,
 *    the written file still validates, and an unknown provider is 404.
 *  - POST /admin/api/endpoint/egress: updates an existing rule in place; 404 for
 *    an unknown provider or one with no existing rule; 400 for empty
 *    authorizedClassifications.
 */

import { createServer, type Server } from "node:http";
import { spawn, type ChildProcess } from "node:child_process";
import { writeFileSync, readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { validateSecurityConfig, type FreeRouterConfig } from "../../src/config.js";

const ISS = "https://idp.test/realms/dod";
const AUD = "secrouter";
const PORT = 19200 + Math.floor(Math.random() * 99); // distinct range from admin.test.ts, avoids collisions
const BASE = `http://127.0.0.1:${PORT}`;
const CWD = new URL("../..", import.meta.url).pathname;

let pass = 0, fail = 0;
const ok = (n: string, c: boolean, x = "") => { if (c) (pass++, console.log(`  ✓ ${n}`)); else (fail++, console.error(`  ✗ ${n} ${x}`)); };

async function waitHealth(ms = 15000) {
  const start = Date.now();
  while (Date.now() - start < ms) {
    try { if ((await fetch(`${BASE}/health`)).ok) return; } catch { /* wait */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("router not healthy");
}

/** Start an HTTP server on an OS-assigned port and return {server, port}. */
async function listenEphemeral(handler: (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => void) {
  const server = createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { server, port: (server.address() as { port: number }).port };
}

async function main() {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey); jwk.kid = "k1"; jwk.alg = "RS256"; jwk.use = "sig";
  const oidc: Server = createServer((_req, res) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ keys: [jwk] })); });
  await new Promise<void>((r) => oidc.listen(0, "127.0.0.1", r));
  const oidcPort = (oidc.address() as { port: number }).port;

  // A fake reachable OpenAI-compatible model server for the "ok" provider.
  const { server: okServer, port: okPort } = await listenEphemeral((req, res) => {
    if (req.url === "/v1/models") {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ object: "list", data: [{ id: "model-b" }] }));
    } else {
      res.writeHead(404).end();
    }
  });

  // A port nobody is listening on, for the "flaky" (unreachable) provider —
  // bind then immediately close so it's guaranteed free for the test's duration.
  const { server: closer, port: flakyPort } = await listenEphemeral((_req, res) => res.end());
  await new Promise<void>((r) => closer.close(() => r()));
  const barePort = flakyPort; // reused: "bare" is never actually dialed in these tests

  const dir = mkdtempSync(join(tmpdir(), "secrouter-endpoint-mgmt-"));
  const cfgPath = join(dir, "config.json");
  writeFileSync(cfgPath, JSON.stringify({
    port: PORT, host: "127.0.0.1",
    providers: {
      ok: { baseUrl: `http://127.0.0.1:${okPort}/v1`, api: "openai" },
      flaky: { baseUrl: `http://127.0.0.1:${flakyPort}/v1`, api: "openai" },
      bare: { baseUrl: `http://127.0.0.1:${barePort}/v1`, api: "openai" }, // no egress rule
    },
    tiers: {
      SIMPLE: { primary: "flaky/model-a", fallback: ["ok/model-b"] },
      MEDIUM: { primary: "ok/model-b", fallback: [] },
      COMPLEX: { primary: "ok/model-b", fallback: [] },
      REASONING: { primary: "ok/model-b", fallback: [] },
    },
    auth: { default: "profiles", profiles: { type: "profiles", profilesPath: join(dir, "noauth.json") } },
    security: {
      enabled: true, storePath: join(dir, "store.db"),
      oidc: { issuer: ISS, audience: AUD, jwksUri: `http://127.0.0.1:${oidcPort}/jwks`, groupsClaim: "groups", clientId: "secrouter-admin-console" },
      classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI"] },
      egress: {
        allowlist: [
          { provider: "ok", allowedHost: `127.0.0.1:${okPort}`, authorizedClassifications: ["CUI"] },
          { provider: "flaky", allowedHost: `127.0.0.1:${flakyPort}`, authorizedClassifications: ["CUI"] },
        ],
      },
      policy: { default: {}, groups: { admins: { admin: true } } },
    },
  }));

  const mint = (groups: string[], sub: string) => new SignJWT({ groups })
    .setProtectedHeader({ alg: "RS256", kid: "k1" }).setIssuer(ISS).setAudience(AUD).setSubject(sub)
    .setIssuedAt().setExpirationTime(Math.floor(Date.now() / 1000) + 600).sign(privateKey);
  const adminTok = await mint(["admins"], "admin-1");
  const H = (t: string) => ({ Authorization: `Bearer ${t}` });
  const HJ = (t: string) => ({ ...H(t), "Content-Type": "application/json" });

  let log = "";
  const child: ChildProcess = spawn("npx", ["tsx", "src/server.ts"], { cwd: CWD, env: { ...process.env, FREEROUTER_CONFIG: cfgPath, SECROUTER_PORT: String(PORT) } });
  child.stdout?.on("data", (d) => (log += d)); child.stderr?.on("data", (d) => (log += d));

  try {
    await waitHealth();

    console.log("GET /admin/api/models/available:");
    ok("no token → 401", (await fetch(`${BASE}/admin/api/models/available`)).status === 401);
    const avRes = await fetch(`${BASE}/admin/api/models/available`, { headers: H(adminTok) });
    const av = await avRes.json() as Array<{ provider: string; reachable: boolean; models: { id: string; owned_by: string }[]; error: string | null; health: { state: string; healthIntervalSec: number } }>;
    // 4, not 3: the loader always merges in the built-in default "bedrock" provider
    // (config.ts DEFAULT_CONFIG) alongside the 3 explicitly configured here.
    ok("200 with one entry per configured provider (incl. the built-in default)", avRes.status === 200 && Array.isArray(av) && av.length === 4);
    const okEntry = av.find((e) => e.provider === "ok");
    const flakyEntry = av.find((e) => e.provider === "flaky");
    ok("reachable provider: reachable=true, models listed + provider-prefixed",
      okEntry?.reachable === true && okEntry.models.some((m) => m.id === "ok/model-b" && m.owned_by === "ok"),
      JSON.stringify(okEntry));
    ok("reachable provider: error=null", okEntry?.error === null);
    ok("unreachable provider: reachable=false + non-null error", flakyEntry?.reachable === false && !!flakyEntry?.error, JSON.stringify(flakyEntry));
    ok("health state folded in (closed, no traffic yet) + healthIntervalSec present",
      okEntry?.health?.state === "closed" && typeof okEntry?.health?.healthIntervalSec === "number");

    console.log("\nPOST /admin/api/endpoint/remove:");
    ok("no token → 401", (await fetch(`${BASE}/admin/api/endpoint/remove`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).status === 401);
    const missing = await fetch(`${BASE}/admin/api/endpoint/remove`, { method: "POST", headers: HJ(adminTok), body: JSON.stringify({ provider: "doesnotexist" }) });
    ok("unknown provider → 404", missing.status === 404);

    const rm = await fetch(`${BASE}/admin/api/endpoint/remove`, { method: "POST", headers: HJ(adminTok), body: JSON.stringify({ provider: "flaky" }) });
    const rmJson = await rm.json();
    ok("remove ok provider → 200 removed", rm.status === 200 && rmJson.status === "removed" && rmJson.provider === "flaky");
    ok("response reports egress dropped", rmJson.removedEgress === true);
    ok("response reports cleared tier (SIMPLE primary referenced flaky/model-a)", Array.isArray(rmJson.clearedTiers) && rmJson.clearedTiers.includes("SIMPLE"));

    const afterRemove = JSON.parse(readFileSync(cfgPath, "utf-8")) as FreeRouterConfig;
    ok("provider deleted from written config", afterRemove.providers.flaky === undefined);
    ok("egress rule dropped from written config", !afterRemove.security!.egress!.allowlist.some((r) => r.provider === "flaky"));
    ok("tier primary blanked (was flaky/model-a)", afterRemove.tiers.SIMPLE.primary === "");
    ok("tier fallback referencing the surviving provider untouched", JSON.stringify(afterRemove.tiers.SIMPLE.fallback) === '["ok/model-b"]');
    ok("surviving provider + its egress rule untouched", !!afterRemove.providers.ok && afterRemove.security!.egress!.allowlist.some((r) => r.provider === "ok"));
    ok("written config still validates", validateSecurityConfig(afterRemove).length === 0, JSON.stringify(validateSecurityConfig(afterRemove)));

    console.log("\nPOST /admin/api/endpoint/egress:");
    ok("no token → 401", (await fetch(`${BASE}/admin/api/endpoint/egress`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).status === 401);
    const eUnknown = await fetch(`${BASE}/admin/api/endpoint/egress`, { method: "POST", headers: HJ(adminTok), body: JSON.stringify({ provider: "ghost", allowedHost: "h", authorizedClassifications: ["CUI"] }) });
    ok("unknown provider → 404", eUnknown.status === 404);
    const eNoRule = await fetch(`${BASE}/admin/api/endpoint/egress`, { method: "POST", headers: HJ(adminTok), body: JSON.stringify({ provider: "bare", allowedHost: "h", authorizedClassifications: ["CUI"] }) });
    ok("provider exists but has no existing rule → 404", eNoRule.status === 404);
    const eEmpty = await fetch(`${BASE}/admin/api/endpoint/egress`, { method: "POST", headers: HJ(adminTok), body: JSON.stringify({ provider: "ok", allowedHost: "h", authorizedClassifications: [] }) });
    ok("empty authorizedClassifications → 400", eEmpty.status === 400);

    const eOk = await fetch(`${BASE}/admin/api/endpoint/egress`, {
      method: "POST", headers: HJ(adminTok),
      body: JSON.stringify({ provider: "ok", allowedHost: `127.0.0.1:${okPort}`, authorizedClassifications: ["UNCLASSIFIED", "CUI"] }),
    });
    const eOkJson = await eOk.json();
    ok("valid edit → 200 updated with the new rule", eOk.status === 200 && eOkJson.status === "updated" && JSON.stringify(eOkJson.egress.authorizedClassifications) === '["UNCLASSIFIED","CUI"]');

    const afterEgress = JSON.parse(readFileSync(cfgPath, "utf-8")) as FreeRouterConfig;
    const okRule = afterEgress.security!.egress!.allowlist.find((r) => r.provider === "ok");
    ok("egress rule updated in place (no duplicate, no new entry)", afterEgress.security!.egress!.allowlist.filter((r) => r.provider === "ok").length === 1);
    ok("egress rule reflects the new classifications", JSON.stringify(okRule?.authorizedClassifications) === '["UNCLASSIFIED","CUI"]');
    ok("written config still validates", validateSecurityConfig(afterEgress).length === 0, JSON.stringify(validateSecurityConfig(afterEgress)));
  } finally {
    child.kill("SIGKILL"); oidc.close(); okServer.close();
  }

  console.log(`\nEndpoint mgmt: ${pass} passed, ${fail} failed`);
  if (fail > 0) console.error("\n--- server log ---\n" + log.split("\n").slice(-40).join("\n"));
  process.exit(fail > 0 ? 1 : 0); // force-exit (see e2e.test.ts note)
}

main().catch((e) => { console.error(e); process.exit(1); });
