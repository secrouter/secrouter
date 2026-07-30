/**
 * Admin console API test. Run: npx tsx test/security/admin.test.ts
 *
 * Proves: public shell + OIDC params, admin gating of /admin/api, and that a
 * DB override written through the API takes effect on LIVE authorization
 * (grant a group admin → a member who was 403 becomes 200 → delete → 403 again).
 */

import { createServer, type Server } from "node:http";
import { spawn, type ChildProcess } from "node:child_process";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, exportJWK, SignJWT } from "jose";

const ISS = "https://idp.test/realms/dod";
const AUD = "secrouter";
const PORT = 19000 + Math.floor(Math.random() * 99); // randomized to avoid re-run port collisions
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

async function main() {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey); jwk.kid = "k1"; jwk.alg = "RS256"; jwk.use = "sig";
  const oidc: Server = createServer((_req, res) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ keys: [jwk] })); });
  await new Promise<void>((r) => oidc.listen(0, "127.0.0.1", r));
  const oidcPort = (oidc.address() as { port: number }).port;

  const dir = mkdtempSync(join(tmpdir(), "secrouter-admin-"));
  const cfgPath = join(dir, "config.json");
  const tier = { primary: "local/x", fallback: [] as string[] };
  writeFileSync(cfgPath, JSON.stringify({
    port: PORT, host: "127.0.0.1",
    providers: { local: { baseUrl: "https://llm.internal/v1", api: "openai" } },
    tiers: { SIMPLE: tier, MEDIUM: tier, COMPLEX: tier, REASONING: tier },
    auth: { default: "profiles", profiles: { type: "profiles", profilesPath: join(dir, "noauth.json") } },
    security: {
      enabled: true, storePath: join(dir, "store.db"),
      oidc: { issuer: ISS, audience: AUD, jwksUri: `http://127.0.0.1:${oidcPort}/jwks`, groupsClaim: "groups", clientId: "secrouter-admin-console" },
      classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI"] },
      egress: { allowlist: [{ provider: "local", allowedHost: "llm.internal", authorizedClassifications: ["CUI"] }] },
      policy: { default: { allowedTiers: ["SIMPLE", "MEDIUM"] }, groups: { admins: { admin: true } } },
    },
  }));

  const mint = (groups: string[], sub: string) => new SignJWT({ groups })
    .setProtectedHeader({ alg: "RS256", kid: "k1" }).setIssuer(ISS).setAudience(AUD).setSubject(sub)
    .setIssuedAt().setExpirationTime(Math.floor(Date.now() / 1000) + 600).sign(privateKey);
  const adminTok = await mint(["admins"], "admin-1");
  const newTok = await mint(["newadmins"], "new-1");
  const H = (t: string) => ({ Authorization: `Bearer ${t}` });

  let log = "";
  const child: ChildProcess = spawn("npx", ["tsx", "src/server.ts"], { cwd: CWD, env: { ...process.env, FREEROUTER_CONFIG: cfgPath, SECROUTER_PORT: String(PORT) } });
  child.stdout?.on("data", (d) => (log += d)); child.stderr?.on("data", (d) => (log += d));

  try {
    await waitHealth();
    console.log("Admin console API:");

    // Public shell + OIDC params
    const shell = await fetch(`${BASE}/admin`);
    ok("GET /admin → 200 HTML (public)", shell.status === 200 && (shell.headers.get("content-type") || "").includes("text/html"));
    const oc = await (await fetch(`${BASE}/admin/oidc`)).json();
    ok("GET /admin/oidc → enabled + clientId (public)", oc.enabled === true && oc.clientId === "secrouter-admin-console");

    // Admin gating
    ok("/admin/api/config no token → 401", (await fetch(`${BASE}/admin/api/config`)).status === 401);
    ok("/admin/api/config non-admin → 403", (await fetch(`${BASE}/admin/api/config`, { headers: H(newTok) })).status === 403);
    const cfgRes = await fetch(`${BASE}/admin/api/config`, { headers: H(adminTok) });
    const cfg = await cfgRes.json();
    ok("/admin/api/config admin → 200 with policy + knownModels", cfgRes.status === 200 && !!cfg.policy && Array.isArray(cfg.knownModels));

    // Override takes effect on LIVE authz
    ok("newadmins initially 403", (await fetch(`${BASE}/admin/api/config`, { headers: H(newTok) })).status === 403);
    const put = await fetch(`${BASE}/admin/api/policy/group/newadmins`, { method: "PUT", headers: { ...H(adminTok), "Content-Type": "application/json" }, body: JSON.stringify({ admin: true }) });
    ok("admin grants newadmins admin via override → 200", put.status === 200);
    ok("newadmins now 200 (override took effect live)", (await fetch(`${BASE}/admin/api/config`, { headers: H(newTok) })).status === 200);

    // Override is reflected + provenance recorded
    const cfg2 = await (await fetch(`${BASE}/admin/api/config`, { headers: H(adminTok) })).json();
    ok("config reflects the override", cfg2.policy?.groups?.newadmins?.admin === true);
    ok("override provenance recorded", (cfg2.overrides || []).some((o: { scope: string; name: string }) => o.scope === "policy.group" && o.name === "newadmins"));

    // Tier mapping edit
    const tput = await fetch(`${BASE}/admin/api/tier/MEDIUM`, { method: "PUT", headers: { ...H(adminTok), "Content-Type": "application/json" }, body: JSON.stringify({ primary: "local/llama-3.3-70b-instruct", fallback: [] }) });
    const cfg3 = await (await fetch(`${BASE}/admin/api/config`, { headers: H(adminTok) })).json();
    ok("tier override saved + reflected", tput.status === 200 && cfg3.tiers?.MEDIUM?.primary === "local/llama-3.3-70b-instruct");

    // Delete reverts
    await fetch(`${BASE}/admin/api/policy/group/newadmins`, { method: "DELETE", headers: H(adminTok) });
    ok("after delete, newadmins 403 again", (await fetch(`${BASE}/admin/api/config`, { headers: H(newTok) })).status === 403);

    // CMMC evidence: audit-chain verify + one-shot evidence bundle (admin-gated)
    ok("/admin/api/audit/verify non-admin → 403", (await fetch(`${BASE}/admin/api/audit/verify`, { headers: H(newTok) })).status === 403);
    const ver = await fetch(`${BASE}/admin/api/audit/verify`, { headers: H(adminTok) });
    const verJson = await ver.json();
    ok("/admin/api/audit/verify admin → chain intact", ver.status === 200 && verJson.ok === true && typeof verJson.checked === "number");

    ok("/admin/api/evidence non-admin → 403", (await fetch(`${BASE}/admin/api/evidence`, { headers: H(newTok) })).status === 403);
    const ev = await fetch(`${BASE}/admin/api/evidence`, { headers: H(adminTok) });
    const evJson = await ev.json();
    ok("/admin/api/evidence admin → bundle with config + auditChain + controls + usage",
      ev.status === 200 && !!evJson.config && !!evJson.auditChain && !!evJson.controls && !!evJson.health && !!evJson.usage && evJson.auditChain.ok === true);
    ok("evidence bundle is a download (Content-Disposition)", (ev.headers.get("content-disposition") || "").includes("secrouter-evidence-"));
    ok("evidence control map covers AU-3.3.8 tamper-evidence", JSON.stringify(evJson.controls).includes("AU-3.3.8"));

    // /metrics is off unless security.metrics.enabled (this config omits it)
    ok("/metrics disabled → 404", (await fetch(`${BASE}/metrics`)).status === 404);
  } finally {
    child.kill("SIGKILL"); oidc.close();
  }

  console.log(`\nAdmin: ${pass} passed, ${fail} failed`);
  if (fail > 0) console.error("\n--- server log ---\n" + log.split("\n").slice(-25).join("\n"));
  process.exit(fail > 0 ? 1 : 0); // force-exit (see e2e.test.ts note)
}

main().catch((e) => { console.error(e); process.exit(1); });
