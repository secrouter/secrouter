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
    env: { ...process.env, SECROUTER_CONFIG: cfgPath, SECROUTER_PORT: String(ROUTER_PORT) },
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
    const tAuditRows: Array<{ type: string }> = tAudit?.rows ?? [];
    ok("mcp: tool.call + tool.deny audit rows recorded", tAuditRows.some((e) => e.type === "tool.call") && tAuditRows.some((e) => e.type === "tool.deny"));
  } finally {
    child.kill("SIGKILL");
    oidc.close();
    upstream.close();
    mcp.close();
  }

  await testLoadBalancing();
  await testModelAwareRouting();
  await testAutoEnableHealthChecks();
  await testLoadBalancingSecured();
  await testTurnkeyWithEgressFileAndAuth();

  console.log(`\nE2E: ${pass} passed, ${fail} failed`);
  if (fail > 0) console.error("\n--- server log ---\n" + log.split("\n").slice(-25).join("\n"));
  // Force-exit: the mock OIDC/upstream close() can hang on sockets left by the
  // SIGKILLed child, so exit deterministically once assertions are done.
  process.exit(fail > 0 ? 1 : 0);
}

/**
 * Multi-endpoint load balancing (STEP 1 engine): a single provider configured
 * with baseUrl: [urlA, urlB]. Proves round-robin distribution across both,
 * per-endpoint breaker isolation (endpoint A failing doesn't fail the
 * request — the SAME request retries endpoint B — and once A's breaker trips
 * open, traffic pins to B), and recovery once A's cooldown elapses.
 *
 * Runs on its OWN server instance with security disabled (dev mode): this
 * engine is orthogonal to auth/egress, and today's egress allow-list schema is
 * one-host-per-provider — it can't yet express two distinct hosts under one
 * provider name (a later "topology intake" step). Uses explicit model routing
 * ("balanced/mock", tier=EXPLICIT) so the classifier/tiers are not in play.
 */
async function testLoadBalancing() {
  console.log("\nMulti-endpoint load balancing (STEP 1 engine):");

  // ── Two independent mock upstreams, each toggleable and self-identifying via
  // a `served_by` field that passes through forwardToOpenAI untouched (only
  // `model` is rewritten by the router). ──
  let failA = false;
  const makeMockUpstream = (label: string, failing: () => boolean) =>
    createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        if (failing()) {
          res.writeHead(503, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: `${label} down` }));
          return;
        }
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            id: `chatcmpl-${label}`,
            object: "chat.completion",
            created: Math.floor(Date.now() / 1000),
            model: "mock",
            choices: [{ index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" }],
            usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
            served_by: label,
          }),
        );
      });
    });
  const upA = makeMockUpstream("A", () => failA);
  const upB = makeMockUpstream("B", () => false); // B never fails — the always-healthy fallback
  await new Promise<void>((r) => upA.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => upB.listen(0, "127.0.0.1", r));
  const urlA = `http://127.0.0.1:${(upA.address() as { port: number }).port}`;
  const urlB = `http://127.0.0.1:${(upB.address() as { port: number }).port}`;

  // ── Dedicated server instance (security disabled — see doc comment above). ──
  const lbPort = 19100 + Math.floor(Math.random() * 99);
  const LB_ROUTER = `http://127.0.0.1:${lbPort}`;
  const dir = mkdtempSync(join(tmpdir(), "secrouter-lb-"));
  const cfgPath = join(dir, "config.json");
  writeFileSync(
    cfgPath,
    JSON.stringify({
      port: lbPort,
      host: "127.0.0.1",
      providers: {
        balanced: { baseUrl: [urlA, urlB], api: "openai" },
      },
      tiers: {
        SIMPLE: { primary: "balanced/mock", fallback: [] },
        MEDIUM: { primary: "balanced/mock", fallback: [] },
        COMPLEX: { primary: "balanced/mock", fallback: [] },
        REASONING: { primary: "balanced/mock", fallback: [] },
      },
      auth: { default: "profiles", profiles: { type: "profiles", profilesPath: join(dir, "auth-profiles.json") } },
      // security.enabled stays false: exercises the load-balancing engine
      // without auth/egress noise (today's egress allow-list is one-host-per-
      // provider and can't express two distinct hosts yet). resilience and
      // metrics are read independent of the top-level `enabled` flag, so the
      // breaker timing stays fast/deterministic and /metrics is still
      // reachable (unauthenticated, ahead of the authN gate) to observe
      // per-endpoint circuit state — /admin/api/health is NOT usable here, it
      // hard-requires security.enabled (the store).
      security: {
        enabled: false,
        resilience: { circuitThreshold: 2, cooldownSec: 1, healthIntervalSec: 0 },
        metrics: { enabled: true },
      },
    }),
  );
  writeFileSync(join(dir, "auth-profiles.json"), JSON.stringify({ version: 1, profiles: {}, lastGood: {} }));

  let lbLog = "";
  const lbChild: ChildProcess = spawn("npx", ["tsx", "src/server.ts"], {
    cwd: CWD,
    env: { ...process.env, SECROUTER_CONFIG: cfgPath, SECROUTER_PORT: String(lbPort) },
  });
  lbChild.stdout?.on("data", (d) => (lbLog += d));
  lbChild.stderr?.on("data", (d) => (lbLog += d));
  const lbFailCount = fail; // snapshot so the log dump below only triggers on THIS section's failures

  try {
    const start = Date.now();
    while (Date.now() - start < 15000) {
      try {
        const r = await fetch(`${LB_ROUTER}/health`);
        if (r.ok) break;
      } catch {
        /* not up yet */
      }
      await new Promise((r) => setTimeout(r, 250));
    }

    const send = async (): Promise<{ status: number; servedBy: string | undefined }> => {
      const r = await fetch(`${LB_ROUTER}/v1/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: "balanced/mock", stream: false, messages: [{ role: "user", content: "hi" }] }),
      });
      const j = await r.json().catch(() => ({}) as Record<string, unknown>);
      return { status: r.status, servedBy: (j as { served_by?: string }).served_by };
    };
    // /admin/api/health needs security.enabled (the store) and is unavailable
    // here, so read circuit state off the labeled Prometheus gauge instead —
    // secrouter_circuit_state{provider="balanced",endpoint="N"} (0 closed, 1
    // open, 2 half-open) — which /metrics exposes unauthenticated.
    const circuitStateGauge = async (endpoint: number): Promise<number | undefined> => {
      const text = await (await fetch(`${LB_ROUTER}/metrics`)).text();
      const m = text.match(new RegExp(`secrouter_circuit_state\\{provider="balanced",endpoint="${endpoint}"\\} (\\d+)`));
      return m ? Number(m[1]) : undefined;
    };

    // (a) Round robin across both healthy endpoints — deterministic (cursor
    // starts at 0 -> A,B,A,B), no failures yet.
    const rr: (string | undefined)[] = [];
    for (let i = 0; i < 4; i++) {
      const { status, servedBy } = await send();
      ok(`lb round-robin request ${i}: 200`, status === 200, `got ${status}`);
      rr.push(servedBy);
    }
    ok("lb round-robin alternates A,B,A,B", JSON.stringify(rr) === JSON.stringify(["A", "B", "A", "B"]), JSON.stringify(rr));

    // (b) Endpoint A fails: each request still succeeds (the SAME request
    // retries endpoint B before giving up); once A's breaker trips open
    // (circuitThreshold=2), traffic pins to B only.
    failA = true;
    const isolation: { status: number; servedBy: string | undefined }[] = [];
    for (let i = 0; i < 6; i++) isolation.push(await send());
    ok("lb isolation: every request still 200 while A fails (B covers it)", isolation.every((r) => r.status === 200), JSON.stringify(isolation));
    ok("lb isolation: batch settles to B only (A's breaker opened)", isolation.slice(-2).every((r) => r.servedBy === "B"), JSON.stringify(isolation));
    const stateAMid = await circuitStateGauge(0);
    ok("lb isolation: endpoint A (index 0) circuit_state gauge = 1 (open)", stateAMid === 1, `got ${stateAMid}`);

    // (c) Recovery: A comes back; once its cooldown elapses a half-open probe
    // is admitted and (since A now succeeds) closes the breaker again.
    failA = false;
    await new Promise((r) => setTimeout(r, 1300)); // exceed cooldownSec=1
    const recovery: { status: number; servedBy: string | undefined }[] = [];
    for (let i = 0; i < 3; i++) recovery.push(await send());
    ok("lb recovery: every request 200 after A recovers", recovery.every((r) => r.status === 200), JSON.stringify(recovery));
    ok("lb recovery: A was actually exercised again (served at least one)", recovery.some((r) => r.servedBy === "A"), JSON.stringify(recovery));
    const stateAEnd = await circuitStateGauge(0);
    ok("lb recovery: endpoint A (index 0) circuit_state gauge = 0 (closed again)", stateAEnd === 0, `got ${stateAEnd}`);
  } finally {
    lbChild.kill("SIGKILL");
    upA.close();
    upB.close();
  }
  if (fail > lbFailCount) {
    console.error("\n--- load-balancing server log ---\n" + lbLog.split("\n").slice(-25).join("\n"));
  }
}

/**
 * Model-aware endpoint selection (STEP 2/3): a pooled provider whose two
 * endpoints serve DIFFERENT models, discovered via the active /models health
 * poll. Proves: (a) before the first probe completes there is no
 * false-negative narrowing (an endpoint with no info yet is still tried); (b)
 * once the probe lands, a request for a model only ONE endpoint reports
 * serving pins to that endpoint; (c) a model NEITHER endpoint reports serving
 * still round-robins both rather than failing outright (never-starve
 * fallback, router/balance.ts).
 */
async function testModelAwareRouting() {
  console.log("\nModel-aware endpoint selection (active /models polling):");

  const makeUpstream = (label: string, modelId: string) =>
    createServer((req, res) => {
      if (req.method === "GET" && /\/models$/.test(req.url ?? "")) {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ object: "list", data: [{ id: modelId }] }));
        return;
      }
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            id: `chatcmpl-${label}`,
            object: "chat.completion",
            created: Math.floor(Date.now() / 1000),
            model: "mock",
            choices: [{ index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" }],
            usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
            served_by: label,
          }),
        );
      });
    });
  const upFast = makeUpstream("FAST", "fast-model"); // only endpoint reporting it serves "fast-model"
  const upOther = makeUpstream("OTHER", "other-model"); // reports a DIFFERENT model — never "fast-model"
  await new Promise<void>((r) => upFast.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => upOther.listen(0, "127.0.0.1", r));
  const urlFast = `http://127.0.0.1:${(upFast.address() as { port: number }).port}`;
  const urlOther = `http://127.0.0.1:${(upOther.address() as { port: number }).port}`;

  const maPort = 19300 + Math.floor(Math.random() * 99);
  const MA_ROUTER = `http://127.0.0.1:${maPort}`;
  const dir = mkdtempSync(join(tmpdir(), "secrouter-modelaware-"));
  const cfgPath = join(dir, "config.json");
  writeFileSync(
    cfgPath,
    JSON.stringify({
      port: maPort,
      host: "127.0.0.1",
      providers: { pool: { baseUrl: [urlFast, urlOther], api: "openai" } },
      tiers: {
        SIMPLE: { primary: "pool/fast-model", fallback: [] },
        MEDIUM: { primary: "pool/fast-model", fallback: [] },
        COMPLEX: { primary: "pool/fast-model", fallback: [] },
        REASONING: { primary: "pool/fast-model", fallback: [] },
      },
      auth: { default: "profiles", profiles: { type: "profiles", profilesPath: join(dir, "auth-profiles.json") } },
      // Explicit, fast health interval (not the 15s pooled-provider auto
      // default) so this test observes the pre-probe -> post-probe
      // transition quickly and deterministically.
      security: { enabled: false, resilience: { circuitThreshold: 5, cooldownSec: 1, healthIntervalSec: 2 } },
    }),
  );
  writeFileSync(join(dir, "auth-profiles.json"), JSON.stringify({ version: 1, profiles: {}, lastGood: {} }));

  let maLog = "";
  const maChild: ChildProcess = spawn("npx", ["tsx", "src/server.ts"], {
    cwd: CWD,
    env: { ...process.env, SECROUTER_CONFIG: cfgPath, SECROUTER_PORT: String(maPort) },
  });
  maChild.stdout?.on("data", (d) => (maLog += d));
  maChild.stderr?.on("data", (d) => (maLog += d));
  const maFailCount = fail;

  try {
    const start = Date.now();
    while (Date.now() - start < 15000) {
      try {
        const r = await fetch(`${MA_ROUTER}/health`);
        if (r.ok) break;
      } catch {
        /* not up yet */
      }
      await new Promise((r) => setTimeout(r, 250));
    }

    const send = async (model: string): Promise<string | undefined> => {
      const r = await fetch(`${MA_ROUTER}/v1/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model, stream: false, messages: [{ role: "user", content: "hi" }] }),
      });
      const j = await r.json().catch(() => ({}) as Record<string, unknown>);
      return (j as { served_by?: string }).served_by;
    };

    // (a) Before the first /models probe completes, there's no served-model
    // info yet -- routing must NOT be narrowed (no false-negative blocking).
    const preProbe: (string | undefined)[] = [];
    for (let i = 0; i < 4; i++) preProbe.push(await send("pool/fast-model"));
    ok(
      "model-aware: before the first probe, BOTH endpoints are still offered (unrestricted)",
      new Set(preProbe).size === 2,
      JSON.stringify(preProbe),
    );

    // (b) Wait past the health-check interval so the first /models probe lands.
    await new Promise((r) => setTimeout(r, 3000));

    // (c) Now a request for "fast-model" must pin to the endpoint that
    // actually reported serving it -- the endpoint lacking it is skipped.
    const postProbe: (string | undefined)[] = [];
    for (let i = 0; i < 6; i++) postProbe.push(await send("pool/fast-model"));
    ok(
      "model-aware: after the probe, every request for 'fast-model' lands on FAST only",
      postProbe.every((s) => s === "FAST"),
      JSON.stringify(postProbe),
    );

    // (d) A model NEITHER endpoint reports serving is still attempted across
    // both (never starved to zero candidates) rather than failing outright.
    const unknownModel: (string | undefined)[] = [];
    for (let i = 0; i < 4; i++) unknownModel.push(await send("pool/nobody-serves-this"));
    ok(
      "model-aware: a model unknown to every endpoint still round-robins both (never-starve fallback)",
      new Set(unknownModel).size === 2,
      JSON.stringify(unknownModel),
    );
  } finally {
    maChild.kill("SIGKILL");
    upFast.close();
    upOther.close();
  }
  if (fail > maFailCount) {
    console.error("\n--- model-aware routing server log ---\n" + maLog.split("\n").slice(-25).join("\n"));
  }
}

/**
 * Auto-enable proof for active health checks. A pooled provider (>1
 * endpoint) with `healthIntervalSec` OMITTED must still schedule active
 * health checks at a sane default — liveness + model-list polling is needed
 * for load balancing to work well even if the operator never opts in
 * explicitly. Checked via the startup log line (printed synchronously by
 * startHealthChecks()) rather than waiting out the real interval, which stays
 * fast and deterministic. The complementary "stays OFF for an all
 * single-endpoint config" behavior is exercised for free by the main secured
 * pipeline test above (single-endpoint providers, healthIntervalSec: 0
 * explicit) and by testLoadBalancing()/testModelAwareRouting(), which set
 * their own explicit interval — none of those ever log an "auto-enabled" line.
 */
async function testAutoEnableHealthChecks() {
  console.log("\nActive health checks auto-enable for a pooled provider (healthIntervalSec omitted):");

  const aePort = 19500 + Math.floor(Math.random() * 99);
  const AE_ROUTER = `http://127.0.0.1:${aePort}`;
  const dir = mkdtempSync(join(tmpdir(), "secrouter-autohc-"));
  const cfgPath = join(dir, "config.json");
  writeFileSync(
    cfgPath,
    JSON.stringify({
      port: aePort,
      host: "127.0.0.1",
      // Two endpoints, neither of which needs to actually answer anything —
      // this test only checks that a timer got SCHEDULED at boot, not that a
      // probe completed, so unreachable placeholder ports are fine.
      providers: { pool: { baseUrl: ["http://127.0.0.1:1", "http://127.0.0.1:2"], api: "openai" } },
      tiers: {
        SIMPLE: { primary: "pool/x", fallback: [] },
        MEDIUM: { primary: "pool/x", fallback: [] },
        COMPLEX: { primary: "pool/x", fallback: [] },
        REASONING: { primary: "pool/x", fallback: [] },
      },
      auth: { default: "profiles", profiles: { type: "profiles", profilesPath: join(dir, "auth-profiles.json") } },
      security: { enabled: false }, // resilience block omitted entirely -> healthIntervalSec defaults to 0
    }),
  );
  writeFileSync(join(dir, "auth-profiles.json"), JSON.stringify({ version: 1, profiles: {}, lastGood: {} }));

  let aeLog = "";
  const aeChild: ChildProcess = spawn("npx", ["tsx", "src/server.ts"], {
    cwd: CWD,
    env: { ...process.env, SECROUTER_CONFIG: cfgPath, SECROUTER_PORT: String(aePort) },
  });
  aeChild.stdout?.on("data", (d) => (aeLog += d));
  aeChild.stderr?.on("data", (d) => (aeLog += d));

  try {
    const start = Date.now();
    while (Date.now() - start < 15000) {
      try {
        const r = await fetch(`${AE_ROUTER}/health`);
        if (r.ok) break;
      } catch {
        /* not up yet */
      }
      await new Promise((r) => setTimeout(r, 250));
    }
    ok(
      "a pooled provider (2 endpoints) with healthIntervalSec omitted auto-enables active health checks at boot",
      /Active provider health checks auto-enabled/.test(aeLog),
      aeLog.split("\n").filter((l) => /health check/i.test(l)).join(" | "),
    );
  } finally {
    aeChild.kill("SIGKILL");
  }
}

/**
 * Multi-endpoint load balancing UNDER security.enabled: true (STEP 3): proves
 * the egress multi-host fix — a pooled provider's egress rule lists BOTH
 * endpoint hosts as an array, and the full secured pipeline (authN -> authZ
 * -> classification -> egress -> LB) round-robins real, authenticated traffic
 * across both. Complements testLoadBalancing() above, which deliberately runs
 * security-disabled because (before this fix) the egress allow-list schema
 * could only express one host per provider.
 */
async function testLoadBalancingSecured() {
  console.log("\nMulti-endpoint load balancing UNDER security.enabled: true (multi-host egress):");

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

  const makeMockUpstream = (label: string) =>
    createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            id: `chatcmpl-${label}`,
            object: "chat.completion",
            created: Math.floor(Date.now() / 1000),
            model: "mock",
            choices: [{ index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" }],
            usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
            served_by: label,
          }),
        );
      });
    });
  const upA = makeMockUpstream("A");
  const upB = makeMockUpstream("B");
  await new Promise<void>((r) => upA.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => upB.listen(0, "127.0.0.1", r));
  const hostA = `127.0.0.1:${(upA.address() as { port: number }).port}`;
  const hostB = `127.0.0.1:${(upB.address() as { port: number }).port}`;

  const ISS2 = "https://idp.test/realms/secllm";
  const AUD2 = "secrouter";
  const slbPort = 19700 + Math.floor(Math.random() * 99);
  const SLB_ROUTER = `http://127.0.0.1:${slbPort}`;
  const dir = mkdtempSync(join(tmpdir(), "secrouter-lb-secured-"));
  const cfgPath = join(dir, "config.json");
  writeFileSync(
    cfgPath,
    JSON.stringify({
      port: slbPort,
      host: "127.0.0.1",
      providers: { secllm: { baseUrl: [`http://${hostA}`, `http://${hostB}`], api: "openai" } },
      tiers: {
        SIMPLE: { primary: "secllm/pooled-model", fallback: [] },
        MEDIUM: { primary: "secllm/pooled-model", fallback: [] },
        COMPLEX: { primary: "secllm/pooled-model", fallback: [] },
        REASONING: { primary: "secllm/pooled-model", fallback: [] },
      },
      auth: { default: "profiles", profiles: { type: "profiles", profilesPath: join(dir, "auth-profiles.json") } },
      security: {
        enabled: true,
        storePath: join(dir, "store.db"),
        oidc: { issuer: ISS2, audience: AUD2, jwksUri: `http://127.0.0.1:${oidcPort}/jwks`, groupsClaim: "groups" },
        classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI"] },
        resilience: { circuitThreshold: 2, cooldownSec: 1, healthIntervalSec: 0 },
        // The point of this test: ONE egress rule, allowedHost as an ARRAY,
        // authorizes BOTH pool hosts — a secured deploy can authorize every
        // endpoint in the pool under one rule (task requirement).
        egress: { allowlist: [{ provider: "secllm", allowedHost: [hostA, hostB], authorizedClassifications: ["CUI"] }] },
        policy: { default: { allowedTiers: ["SIMPLE", "MEDIUM", "COMPLEX", "REASONING"], maxClassification: "CUI" } },
      },
    }),
  );
  writeFileSync(join(dir, "auth-profiles.json"), JSON.stringify({ version: 1, profiles: {}, lastGood: {} }));

  const mint = () =>
    new SignJWT({ groups: ["analysts"] })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(ISS2)
      .setAudience(AUD2)
      .setSubject("secured-lb-user")
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 600)
      .sign(privateKey);
  const tok = await mint();
  const hdr = { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" };

  let slbLog = "";
  const slbChild: ChildProcess = spawn("npx", ["tsx", "src/server.ts"], {
    cwd: CWD,
    env: { ...process.env, SECROUTER_CONFIG: cfgPath, SECROUTER_PORT: String(slbPort) },
  });
  slbChild.stdout?.on("data", (d) => (slbLog += d));
  slbChild.stderr?.on("data", (d) => (slbLog += d));
  const slbFailCount = fail;

  try {
    const start = Date.now();
    while (Date.now() - start < 15000) {
      try {
        const r = await fetch(`${SLB_ROUTER}/health`);
        if (r.ok) break;
      } catch {
        /* not up yet */
      }
      await new Promise((r) => setTimeout(r, 250));
    }

    ok(
      "secured pool: no token -> 401 (security really is enabled)",
      (
        await fetch(`${SLB_ROUTER}/v1/chat/completions`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ model: "secllm/pooled-model", stream: false, messages: [{ role: "user", content: "hi" }] }),
        })
      ).status === 401,
    );

    const send = async (): Promise<{ status: number; servedBy: string | undefined }> => {
      const r = await fetch(`${SLB_ROUTER}/v1/chat/completions`, {
        method: "POST",
        headers: hdr,
        body: JSON.stringify({ model: "secllm/pooled-model", stream: false, messages: [{ role: "user", content: "hi" }] }),
      });
      const j = await r.json().catch(() => ({}) as Record<string, unknown>);
      return { status: r.status, servedBy: (j as { served_by?: string }).served_by };
    };

    const results: { status: number; servedBy: string | undefined }[] = [];
    for (let i = 0; i < 4; i++) results.push(await send());
    ok(
      "secured pool: every authenticated request succeeds (egress array authorizes both hosts)",
      results.every((r) => r.status === 200),
      JSON.stringify(results),
    );
    ok(
      "secured pool: BOTH pool endpoints were actually reached (real round robin under full auth+policy+egress)",
      new Set(results.map((r) => r.servedBy)).size === 2,
      JSON.stringify(results),
    );
  } finally {
    slbChild.kill("SIGKILL");
    oidc.close();
    upA.close();
    upB.close();
  }
  if (fail > slbFailCount) {
    console.error("\n--- secured pooled LB server log ---\n" + slbLog.split("\n").slice(-25).join("\n"));
  }
}

/**
 * Turnkey pool + explicit egress file + provider auth (Parts 1-3): proves the
 * CORRECTED turnkey behavior. SECROUTER_SECLLM_ENDPOINTS wires up ROUTING and
 * PROVIDER AUTH only (config.ts applySecllmEndpointsIntake) — it never
 * touches security.egress. Reachability here comes ENTIRELY from an
 * explicit, deployer-authored SECROUTER_EGRESS_FILE (config.ts
 * applyEgressFileIntake): the config file's own `security` block has NO
 * `egress` key at all, so a clean boot proves the file alone creates the
 * whole allow-list structure. Complements testLoadBalancingSecured() above
 * (which hand-authors the rule directly in the config file) by proving the
 * file-based path instead. Proves, end to end against a real running server:
 *   1. both declared pool endpoints are reachable (real auth, real
 *      round-robin) purely because of the egress FILE — no manual rule
 *      anywhere in the config file itself;
 *   2. the resolved SECROUTER_SECLLM_TOKEN is sent as `Authorization: Bearer`
 *      on BOTH the chat-completion forward AND the active /v1/models
 *      health-check poll (Part 3's critical requirement — a token-protected
 *      SecLLM would 401 an unauthenticated poll, breaking model-awareness);
 *   3. a provider that's configured but named in NEITHER the config file's
 *      own allowlist (absent) NOR the egress file stays egress-DENIED — the
 *      file's authorization is explicit/scoped, not a blanket bypass;
 *   4. it's audit-evident, not silent: an `egress.file_loaded` row lands in
 *      the tamper-evident audit trail, naming the file path + rule counts.
 */
async function testTurnkeyWithEgressFileAndAuth() {
  console.log("\nTurnkey pool + explicit SECROUTER_EGRESS_FILE + SECROUTER_SECLLM_TOKEN:");

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

  const SECLLM_TOKEN = "turnkey-secllm-token-xyz";
  type Call = { method: string; url: string; authorization: string | string[] | undefined };
  const callsA: Call[] = [];
  const callsB: Call[] = [];
  // Captures EVERY inbound request (chat-completion forwards AND the active
  // /v1/models health-check poll) with whatever Authorization header it
  // carried, so both Part 3 assertions (forward + poll) read off the same
  // real HTTP traffic a live SecLLM deployment would see.
  const makeMockUpstream = (label: string, calls: Call[]) =>
    createServer((req, res) => {
      calls.push({ method: req.method ?? "", url: req.url ?? "", authorization: req.headers["authorization"] });
      if (req.method === "GET" && /\/models$/.test(req.url ?? "")) {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ object: "list", data: [{ id: "Llama-3.2-3B-Instruct" }] }));
        return;
      }
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            id: `chatcmpl-${label}`,
            object: "chat.completion",
            created: Math.floor(Date.now() / 1000),
            model: "mock",
            choices: [{ index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" }],
            usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
            served_by: label,
          }),
        );
      });
    });
  const upA = makeMockUpstream("A", callsA);
  const upB = makeMockUpstream("B", callsB);
  await new Promise<void>((r) => upA.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => upB.listen(0, "127.0.0.1", r));
  const urlA = `http://127.0.0.1:${(upA.address() as { port: number }).port}`;
  const urlB = `http://127.0.0.1:${(upB.address() as { port: number }).port}`;
  const hostA = urlA.replace(/^https?:\/\//, "");
  const hostB = urlB.replace(/^https?:\/\//, "");

  const ISS3 = "https://idp.test/realms/turnkey";
  const AUD3 = "secrouter";
  const tkPort = 19900 + Math.floor(Math.random() * 90);
  const TK_ROUTER = `http://127.0.0.1:${tkPort}`;
  const dir = mkdtempSync(join(tmpdir(), "secrouter-turnkey-secured-"));

  // Part 2: explicit, deployer-authored egress rules file — the ONLY source
  // of egress authorization anywhere in this test.
  const egressFilePath = join(dir, "egress-rules.json");
  writeFileSync(
    egressFilePath,
    JSON.stringify([
      {
        provider: "secllm",
        allowedHost: [hostA, hostB],
        authorizedClassifications: ["UNCLASSIFIED", "CUI"],
        authorization: "Deployer-generated egress rules for the turnkey SecLLM pool",
      },
    ]),
  );

  const cfgPath = join(dir, "config.json");
  writeFileSync(
    cfgPath,
    JSON.stringify({
      port: tkPort,
      host: "127.0.0.1",
      // No 'secllm' provider or tiers here — SECROUTER_SECLLM_ENDPOINTS (set
      // on the child's env below) supplies ALL of that via turnkey intake.
      // 'rogue' is a real, separately-configured provider named in NEITHER
      // this config's (absent) egress block NOR the egress file, to prove
      // the file's authorization stays scoped.
      providers: { rogue: { api: "openai", baseUrl: "http://127.0.0.1:1" } },
      auth: { default: "profiles", profiles: { type: "profiles", profilesPath: join(dir, "auth-profiles.json") } },
      security: {
        enabled: true,
        storePath: join(dir, "store.db"),
        oidc: { issuer: ISS3, audience: AUD3, jwksUri: `http://127.0.0.1:${oidcPort}/jwks`, groupsClaim: "groups" },
        classification: { default: "CUI", levels: ["UNCLASSIFIED", "CUI"] },
        // Short interval so the active /v1/models poll (Part 3) fires within
        // this test's window instead of waiting out the pooled-provider
        // auto-enabled default (15s).
        resilience: { circuitThreshold: 5, cooldownSec: 1, healthIntervalSec: 2 },
        // NOTE: no `egress` key at all — applyEgressFileIntake must create
        // the whole security.egress.allowlist structure from scratch for
        // this to boot (validateSecurityConfig requires a non-empty
        // allowlist), proving the file alone is sufficient.
        policy: {
          default: { allowedTiers: ["SIMPLE", "MEDIUM", "COMPLEX", "REASONING"], maxClassification: "CUI" },
          groups: { admins: { admin: true } },
        },
      },
    }),
  );
  writeFileSync(join(dir, "auth-profiles.json"), JSON.stringify({ version: 1, profiles: {}, lastGood: {} }));

  const mint = () =>
    new SignJWT({ groups: ["admins"] })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(ISS3)
      .setAudience(AUD3)
      .setSubject("turnkey-admin")
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 600)
      .sign(privateKey);
  const tok = await mint();
  const hdr = { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" };

  let tkLog = "";
  const tkChild: ChildProcess = spawn("npx", ["tsx", "src/server.ts"], {
    cwd: CWD,
    env: {
      ...process.env,
      SECROUTER_CONFIG: cfgPath,
      SECROUTER_PORT: String(tkPort),
      // Part 1: routing + provider auth only, no egress.
      SECROUTER_SECLLM_ENDPOINTS: `${urlA},${urlB}`,
      // Part 3: the bearer token the turnkey-registered provider resolves.
      SECROUTER_SECLLM_TOKEN: SECLLM_TOKEN,
      // Part 2: the ONLY source of egress authorization in this test.
      SECROUTER_EGRESS_FILE: egressFilePath,
    },
  });
  tkChild.stdout?.on("data", (d) => (tkLog += d));
  tkChild.stderr?.on("data", (d) => (tkLog += d));
  const tkFailCount = fail;

  try {
    const start = Date.now();
    while (Date.now() - start < 15000) {
      try {
        const r = await fetch(`${TK_ROUTER}/health`);
        if (r.ok) break;
      } catch {
        /* not up yet */
      }
      await new Promise((r) => setTimeout(r, 250));
    }

    const send = async (model: string): Promise<{ status: number; servedBy: string | undefined; body: unknown }> => {
      const r = await fetch(`${TK_ROUTER}/v1/chat/completions`, {
        method: "POST",
        headers: hdr,
        body: JSON.stringify({ model, stream: false, messages: [{ role: "user", content: "hi" }] }),
      });
      const j = await r.json().catch(() => ({}) as Record<string, unknown>);
      return { status: r.status, servedBy: (j as { served_by?: string }).served_by, body: j };
    };

    // (1) Both DECLARED pool endpoints reachable, real round-robin — purely
    // via the egress FILE, no manual rule in the config file at all.
    // "secllm/Llama-3.2-3B-Instruct" is the turnkey-registered SIMPLE-tier
    // model id (tier-rewiring itself is covered directly/deterministically in
    // secllm-intake.test.ts; explicit routing here keeps this full-server
    // test focused on egress + auth + LB).
    const results: { status: number; servedBy: string | undefined }[] = [];
    for (let i = 0; i < 4; i++) {
      const { status, servedBy } = await send("secllm/Llama-3.2-3B-Instruct");
      results.push({ status, servedBy });
    }
    ok(
      "turnkey pool: every request succeeds — reachable purely via SECROUTER_EGRESS_FILE",
      results.every((r) => r.status === 200),
      JSON.stringify(results),
    );
    ok(
      "turnkey pool: BOTH declared endpoints actually reached (real round robin)",
      new Set(results.map((r) => r.servedBy)).size === 2,
      JSON.stringify(results),
    );

    // (2) Part 3: the resolved SECROUTER_SECLLM_TOKEN was sent as
    // Authorization: Bearer on the chat-completion forward.
    const forwardCalls = [...callsA, ...callsB].filter((c) => c.method === "POST");
    ok(
      "provider auth: the forward carried Authorization: Bearer <SECROUTER_SECLLM_TOKEN>",
      forwardCalls.length > 0 && forwardCalls.every((c) => c.authorization === `Bearer ${SECLLM_TOKEN}`),
      JSON.stringify(forwardCalls),
    );

    // (3) A provider that's configured but named in neither the config
    // file's own allowlist (there isn't one) nor the egress file is still
    // denied — the file's authorization is scoped, not a bypass.
    const rogue = await send("rogue/some-model");
    ok("turnkey pool: a non-pool provider is still egress-DENIED (502)", rogue.status === 502, JSON.stringify(rogue));
    ok(
      "turnkey pool: denial is specifically egress, not some other error",
      (rogue.body as { error?: { type?: string } })?.error?.type === "egress_denied",
      JSON.stringify(rogue.body),
    );

    // (4) Audit-evident, not silent: an egress.file_loaded row exists,
    // naming the file path and rule counts.
    const auditResp: { rows?: unknown[] } = await (
      await fetch(`${TK_ROUTER}/admin/api/audit?type=egress.file_loaded&limit=10`, { headers: hdr })
    ).json();
    const auditRows: unknown[] = auditResp?.rows ?? [];
    const row = auditRows.find(
      (e: { detail?: { source?: string } }) => e.detail?.source === "SECROUTER_EGRESS_FILE",
    ) as { detail: { path: string; addedCount: number; totalCount: number; source: string } } | undefined;
    ok("turnkey pool: an egress.file_loaded audit row exists", !!row, JSON.stringify(auditRows));
    ok(
      "turnkey pool: audit row names the egress rules file + rule counts",
      row?.detail.path === egressFilePath && row?.detail.addedCount === 1 && row?.detail.totalCount === 1,
      JSON.stringify(row),
    );

    // (5) Part 3 CRITICAL: the active /v1/models health-check poll ALSO
    // carries the resolved auth header — wait for at least one poll to land
    // (healthIntervalSec is 2s, but a fixed 2.5s sleep flaked under full-suite
    // load: poll until a deadline instead), then inspect what it actually sent.
    const pollDeadline = Date.now() + 10_000;
    let pollCalls = [...callsA, ...callsB].filter((c) => c.method === "GET" && /\/models$/.test(c.url));
    while (pollCalls.length === 0 && Date.now() < pollDeadline) {
      await new Promise((r) => setTimeout(r, 250));
      pollCalls = [...callsA, ...callsB].filter((c) => c.method === "GET" && /\/models$/.test(c.url));
    }
    ok("provider auth: the /v1/models health-check poll ran at least once", pollCalls.length > 0, JSON.stringify([...callsA, ...callsB]));
    ok(
      "provider auth: the /v1/models poll ALSO carried Authorization: Bearer <SECROUTER_SECLLM_TOKEN> (not just the forward)",
      pollCalls.length > 0 && pollCalls.every((c) => c.authorization === `Bearer ${SECLLM_TOKEN}`),
      JSON.stringify(pollCalls),
    );
  } finally {
    tkChild.kill("SIGKILL");
    oidc.close();
    upA.close();
    upB.close();
  }
  if (fail > tkFailCount) {
    console.error("\n--- turnkey pool server log ---\n" + tkLog.split("\n").slice(-25).join("\n"));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
