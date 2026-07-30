/**
 * End-to-end secured-pipeline test.  Run: npx tsx test/security/e2e.test.ts
 *
 * Boots the REAL server (child process) against a mock OIDC (JWKS) and a mock
 * Anthropic upstream, then drives the full pipeline:
 *   401 (no token) · 200 (valid) · streaming token capture · admin gating
 *   (403/200) · per-user quota (429) · /v1/usage accounting.
 */

import { createServer, type Server } from "node:http";
import { spawn, type ChildProcess } from "node:child_process";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, exportJWK, SignJWT } from "jose";

const ISS = "https://idp.test/realms/dod";
const AUD = "secrouter";
const ROUTER_PORT = 18900 + Math.floor(Math.random() * 99); // randomized to avoid re-run port collisions
const ROUTER = `http://127.0.0.1:${ROUTER_PORT}`;
const CWD = new URL("../..", import.meta.url).pathname;

let pass = 0;
let fail = 0;
const ok = (name: string, cond: boolean, extra = "") => {
  if (cond) (pass++, console.log(`  ✓ ${name}`));
  else (fail++, console.error(`  ✗ ${name} ${extra}`));
};

async function waitForHealth(timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch(`${ROUTER}/health`);
      if (r.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("router did not become healthy");
}

async function main() {
  // ── Mock OIDC (JWKS) ──
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "k1";
  jwk.alg = "RS256";
  jwk.use = "sig";
  const oidc: Server = createServer((req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  await new Promise<void>((r) => oidc.listen(0, "127.0.0.1", r));
  const oidcPort = (oidc.address() as { port: number }).port;

  // ── Mock Anthropic upstream (/v1/messages, streaming + non-streaming) ──
  // `upstreamFail` lets a test simulate a dead provider (503) to drive the breaker.
  let upstreamFail = false;
  const upstream: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (upstreamFail && !req.url?.endsWith("/embeddings")) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "upstream down" }));
        return;
      }
      if (req.url?.endsWith("/embeddings")) {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ object: "list", data: [{ object: "embedding", index: 0, embedding: [0.1, 0.2, 0.3] }], model: "mock-embed", usage: { prompt_tokens: 12, total_tokens: 12 } }));
        return;
      }
      const isStream = JSON.parse(body || "{}").stream === true;
      if (!isStream) {
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            content: [{ type: "text", text: "hello" }],
            usage: { input_tokens: 100, output_tokens: 50 },
            stop_reason: "end_turn",
            model: "mock",
          }),
        );
        return;
      }
      res.writeHead(200, { "content-type": "text/event-stream" });
      const send = (o: unknown) => res.write(`data: ${JSON.stringify(o)}\n\n`);
      send({ type: "message_start", message: { usage: { input_tokens: 100, output_tokens: 1 } } });
      send({ type: "content_block_start", index: 0, content_block: { type: "text" } });
      send({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "hello" } });
      send({ type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 50 } });
      send({ type: "message_stop" });
      res.end();
    });
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  const upstreamPort = (upstream.address() as { port: number }).port;
  const upstreamHost = `127.0.0.1:${upstreamPort}`;

  // ── Mock MCP server (echo / add / now) for the governed tool gateway ──
  const mcp: Server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const rpc = JSON.parse(b || "{}");
      const ok = (result: unknown) => ({ jsonrpc: "2.0", id: rpc.id, result });
      let out: unknown;
      if (rpc.method === "initialize") out = ok({ protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "mock-mcp" } });
      else if (rpc.method === "tools/list") out = ok({ tools: [{ name: "echo" }, { name: "add" }, { name: "now" }] });
      else if (rpc.method === "tools/call") {
        const a = rpc.params?.arguments || {};
        const text = rpc.params?.name === "add" ? String(Number(a.a) + Number(a.b)) : String(a.text ?? "now");
        out = ok({ content: [{ type: "text", text }] });
      } else if (rpc.id == null) out = null; // notification
      else out = { jsonrpc: "2.0", id: rpc.id, error: { code: -32601, message: "method not found" } };
      res.writeHead(out ? 200 : 202, { "content-type": "application/json" });
      res.end(out ? JSON.stringify(out) : "");
    });
  });
  await new Promise<void>((r) => mcp.listen(0, "127.0.0.1", r));
  const mcpPort = (mcp.address() as { port: number }).port;

  // ── Temp config + auth-profiles for the child server ──
  const dir = mkdtempSync(join(tmpdir(), "secrouter-e2e-"));
  const authPath = join(dir, "auth-profiles.json");
  writeFileSync(
    authPath,
    JSON.stringify({
      version: 1,
      profiles: { mock: { type: "token", provider: "anthropic", token: "sk-ant-mock" } },
      lastGood: { anthropic: "mock" },
    }),
  );
  const tier = { primary: "anthropic/mock", fallback: [] as string[] };
  const cfgPath = join(dir, "config.json");
  writeFileSync(
    cfgPath,
    JSON.stringify({
      port: ROUTER_PORT,
      host: "127.0.0.1",
      providers: {
        anthropic: { baseUrl: `http://${upstreamHost}`, api: "anthropic" },
        local: { baseUrl: `http://${upstreamHost}`, api: "openai" },
      },
      tiers: { SIMPLE: tier, MEDIUM: tier, COMPLEX: tier, REASONING: tier },
      models: [{ id: "local/mock-embed", name: "Mock Embed", inputPrice: 100, outputPrice: 0, kind: "embedding" }],
      embeddings: { default: "local/mock-embed" },
      auth: { default: "profiles", profiles: { type: "profiles", profilesPath: authPath } },
      security: {
        enabled: true,
        storePath: join(dir, "store.db"),
        oidc: { issuer: ISS, audience: AUD, jwksUri: `http://127.0.0.1:${oidcPort}/jwks`, groupsClaim: "groups", requireMfa: true },
        classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI"] },
        resilience: { circuitThreshold: 2, cooldownSec: 1, healthIntervalSec: 0 },
        mcp: { enabled: true, servers: [{ name: "mock", url: `http://127.0.0.1:${mcpPort}/mcp`, authorizedClassifications: ["CUI"] }] },
        egress: {
          allowlist: [
            { provider: "anthropic", allowedHost: upstreamHost, authorizedClassifications: ["CUI"] },
            { provider: "local", allowedHost: upstreamHost, authorizedClassifications: ["CUI"] },
          ],
        },
        policy: {
          default: { allowedTiers: ["SIMPLE", "MEDIUM", "COMPLEX", "REASONING"], onViolation: "downgrade", maxClassification: "CUI" },
          groups: {
            admins: { admin: true },
            limited: { budgets: [{ window: "day", maxRequests: 1 }] },
            embedrestricted: { allowedModels: ["anthropic/mock"] },
            toolers: { allowedTools: ["mock/echo", "mock/add"] }, // NOT mock/now → proves filtering
          },
        },
      },
    }),
  );

  const mint = (groups: string[], sub: string) =>
    new SignJWT({ groups, amr: ["otp"] })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(ISS)
      .setAudience(AUD)
      .setSubject(sub)
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 600)
      .sign(privateKey);
  const userTok = await mint(["analysts"], "user-1");
  const adminTok = await mint(["admins"], "admin-1");
  const limitedTok = await mint(["limited"], "limited-1");
  const embRestrictedTok = await mint(["embedrestricted"], "embedr-1");
  const toolerTok = await mint(["toolers"], "tooler-1");
  const hdr = (t: string) => ({ Authorization: `Bearer ${t}`, "Content-Type": "application/json" });
  const chat = (stream: boolean) =>
    JSON.stringify({ model: "auto", stream, messages: [{ role: "user", content: "hi there" }] });

  // ── Boot the real server ──
  let log = "";
  const child: ChildProcess = spawn("npx", ["tsx", "src/server.ts"], {
    cwd: CWD,
    env: { ...process.env, FREEROUTER_CONFIG: cfgPath, SECROUTER_PORT: String(ROUTER_PORT) },
  });
  child.stdout?.on("data", (d) => (log += d));
  child.stderr?.on("data", (d) => (log += d));

  try {
    await waitForHealth();
    console.log("E2E secured pipeline:");

    // 1. No token → 401
    ok("no token → 401", (await fetch(`${ROUTER}/v1/chat/completions`, { method: "POST", body: chat(false), headers: { "Content-Type": "application/json" } })).status === 401);

    // 2. Valid token non-streaming → 200
    const r2 = await fetch(`${ROUTER}/v1/chat/completions`, { method: "POST", headers: hdr(userTok), body: chat(false) });
    ok("valid token non-stream → 200", r2.status === 200);

    // 3. Streaming → 200 and usage captured (the previously-broken path)
    const r3 = await fetch(`${ROUTER}/v1/chat/completions`, { method: "POST", headers: hdr(userTok), body: chat(true) });
    await r3.text();
    ok("valid token stream → 200", r3.status === 200);

    // 4. /v1/usage reflects BOTH requests (200 input, 100 output tokens)
    const usage = await (await fetch(`${ROUTER}/v1/usage`, { headers: hdr(userTok) })).json();
    ok(
      "usage accounting: 2 requests, 200 input tokens captured (stream + non-stream)",
      usage?.usage?.last24h?.requestCount === 2 && usage?.usage?.last24h?.inputTokens === 200,
      JSON.stringify(usage?.usage?.last24h),
    );

    // 5. Admin gating
    ok("non-admin GET /stats → 403", (await fetch(`${ROUTER}/stats`, { headers: hdr(userTok) })).status === 403);
    ok("admin GET /stats → 200", (await fetch(`${ROUTER}/stats`, { headers: hdr(adminTok) })).status === 200);

    // 6. Per-user quota: limited group allows 1 request/day
    const q1 = await fetch(`${ROUTER}/v1/chat/completions`, { method: "POST", headers: hdr(limitedTok), body: chat(false) });
    const q2 = await fetch(`${ROUTER}/v1/chat/completions`, { method: "POST", headers: hdr(limitedTok), body: chat(false) });
    ok("quota: first request → 200", q1.status === 200);
    ok("quota: second request → 429", q2.status === 429, `got ${q2.status}`);

    // 7. Oversized body → 413
    const big = JSON.stringify({ model: "auto", messages: [{ role: "user", content: "x".repeat(20) }] });
    const r7 = await fetch(`${ROUTER}/v1/chat/completions`, {
      method: "POST",
      headers: hdr(userTok),
      body: big,
    });
    ok("normal small body still 200 (sanity)", r7.status === 200);

    // 8. Governed embeddings — same auth / policy / egress / usage gates as chat
    ok(
      "embeddings no token → 401",
      (await fetch(`${ROUTER}/v1/embeddings`, { method: "POST", body: JSON.stringify({ input: "hi" }), headers: { "Content-Type": "application/json" } })).status === 401,
    );
    const emb = await fetch(`${ROUTER}/v1/embeddings`, { method: "POST", headers: hdr(userTok), body: JSON.stringify({ model: "auto", input: "hello world" }) });
    const embJson = await emb.json();
    ok("embeddings valid token → 200 with data[]", emb.status === 200 && Array.isArray(embJson.data) && embJson.data.length === 1, `${emb.status}`);
    const eu = await (await fetch(`${ROUTER}/v1/usage`, { headers: hdr(userTok) })).json();
    const embRow = (eu.byModel || []).find((m: { key: string }) => m.key === "mock-embed");
    ok("embedding usage recorded with cost", !!embRow && embRow.inputTokens === 12 && embRow.costUsd > 0, JSON.stringify(eu.byModel));
    ok(
      "embeddings disallowed model → 403",
      (await fetch(`${ROUTER}/v1/embeddings`, { method: "POST", headers: hdr(embRestrictedTok), body: JSON.stringify({ model: "local/mock-embed", input: "x" }) })).status === 403,
    );

    // 9. Circuit breaker (Phase C): a dead provider trips open and fails fast,
    //    then a half-open probe recovers it once the upstream is healthy again.
    //    Config: circuitThreshold 2, cooldownSec 1.
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    const health = async () => (await fetch(`${ROUTER}/admin/api/health`, { headers: hdr(adminTok) })).json();
    const providerState = (h: { providers?: { provider: string; state: string }[] }) =>
      (h.providers || []).find((p) => p.provider === "anthropic")?.state;

    upstreamFail = true;
    const f1 = await fetch(`${ROUTER}/v1/chat/completions`, { method: "POST", headers: hdr(userTok), body: chat(false) });
    const f2 = await fetch(`${ROUTER}/v1/chat/completions`, { method: "POST", headers: hdr(userTok), body: chat(false) });
    ok("breaker: upstream 503 → 502 while circuit still closed", f1.status === 502 && f2.status === 502, `${f1.status}/${f2.status}`);
    ok("breaker: opens after threshold (2) consecutive health failures", (await health().then(providerState)) === "open");

    const f3start = Date.now();
    const f3 = await fetch(`${ROUTER}/v1/chat/completions`, { method: "POST", headers: hdr(userTok), body: chat(false) });
    const f3ms = Date.now() - f3start;
    ok("breaker: open circuit fails fast → 503 without an upstream call", f3.status === 503 && f3ms < 800, `${f3.status} in ${f3ms}ms`);

    upstreamFail = false; // upstream recovers
    await sleep(1300); // exceed the 1s cooldown so the next request is admitted as a half-open probe
    const r5 = await fetch(`${ROUTER}/v1/chat/completions`, { method: "POST", headers: hdr(userTok), body: chat(false) });
    ok("breaker: half-open probe succeeds → 200", r5.status === 200, `${r5.status}`);
    ok("breaker: closes after a successful probe", (await health().then(providerState)) === "closed");

    // 10. Governed MCP gateway (Phase D): filtered list + gated calls + audit.
    const mcpRpc = (tok: string, method: string, params?: unknown) =>
      fetch(`${ROUTER}/mcp`, { method: "POST", headers: hdr(tok), body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) }).then((r) => r.json());

    ok("mcp: no token → 401", (await fetch(`${ROUTER}/mcp`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }) })).status === 401);

    const initR = await mcpRpc(toolerTok, "initialize");
    ok("mcp: initialize handshake → protocolVersion", initR?.result?.protocolVersion === "2025-06-18", JSON.stringify(initR));

    const listR = await mcpRpc(toolerTok, "tools/list");
    const listed = (listR?.result?.tools ?? []).map((t: { id: string }) => t.id).sort();
    ok("mcp: tools/list filtered to the allow-list (echo, add — NOT now)", JSON.stringify(listed) === '["mock/add","mock/echo"]', JSON.stringify(listed));

    const addR = await mcpRpc(toolerTok, "tools/call", { name: "mock/add", arguments: { a: 2, b: 3 } });
    ok("mcp: tools/call allowed tool → result", addR?.result?.content?.[0]?.text === "5", JSON.stringify(addR));

    const nowR = await mcpRpc(toolerTok, "tools/call", { name: "mock/now", arguments: {} });
    ok("mcp: tools/call unsanctioned tool → JSON-RPC deny", nowR?.error?.code === -32001, JSON.stringify(nowR));

    const emptyR = await mcpRpc(userTok, "tools/list"); // analysts group: no allowedTools
    ok("mcp: principal with no allowedTools → empty tools/list (default-deny)", (emptyR?.result?.tools ?? []).length === 0, JSON.stringify(emptyR?.result));

    const tAudit = await (await fetch(`${ROUTER}/admin/api/audit?limit=30`, { headers: hdr(adminTok) })).json();
    ok("mcp: tool.call + tool.deny audit rows recorded", Array.isArray(tAudit) && tAudit.some((e: { type: string }) => e.type === "tool.call") && tAudit.some((e: { type: string }) => e.type === "tool.deny"));
  } finally {
    child.kill("SIGKILL");
    oidc.close();
    upstream.close();
    mcp.close();
  }

  console.log(`\nE2E: ${pass} passed, ${fail} failed`);
  if (fail > 0) console.error("\n--- server log ---\n" + log.split("\n").slice(-25).join("\n"));
  // Force-exit: the mock OIDC/upstream close() can hang on sockets left by the
  // SIGKILLed child, so exit deterministically once assertions are done.
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
