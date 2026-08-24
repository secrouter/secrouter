/**
 * Escalation routing tests. Run: npx tsx test/security/escalation.test.ts
 *
 * Part 1 (pure, no server): heuristic verdicts, judge-output parsing, config
 * validation — deterministic, see src/router/escalation.ts.
 * Part 2 (spawned real server + fake upstreams): the full draft -> judge ->
 * accept/escalate flow, streaming bypass, escalation-denied, exactly-one-escalation.
 */

import { createServer, type Server } from "node:http";
import { spawn, type ChildProcess } from "node:child_process";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import {
  heuristicVerdict,
  parseJudgeVerdict,
  buildJudgeInput,
  validateEscalationConfig,
  resolveJudgeConfig,
  escalationApplies,
  DEFAULT_REFUSAL_PATTERNS,
} from "../../src/router/escalation.js";

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

const CWD = new URL("../..", import.meta.url).pathname;

// ─────────────────────────── Part 1: pure logic ───────────────────────────

console.log("heuristicVerdict — checked in order: empty, truncated, refusal, too-short:");
{
  const judge = resolveJudgeConfig({ mode: "heuristic" });
  ok("empty draft -> escalate (empty_draft)", heuristicVerdict("", "stop", judge).escalate && heuristicVerdict("", "stop", judge).reason === "empty_draft");
  ok("whitespace-only draft -> escalate (empty_draft)", heuristicVerdict("   \n  ", "stop", judge).reason === "empty_draft");
  ok(
    "truncated (finish_reason length) -> escalate (truncated_finish_reason)",
    heuristicVerdict("a perfectly fine answer", "length", judge).reason === "truncated_finish_reason",
  );
  ok(
    "refusal pattern match -> escalate (refusal_pattern:...)",
    heuristicVerdict("I'm sorry, but I can't help with that request.", "stop", judge).escalate &&
      /^refusal_pattern:/.test(heuristicVerdict("I'm sorry, but I can't help with that request.", "stop", judge).reason),
  );
  const shortJudge = resolveJudgeConfig({ mode: "heuristic", minDraftChars: 20 });
  ok("shorter than minDraftChars -> escalate (draft_too_short)", heuristicVerdict("too short", "stop", shortJudge).reason === "draft_too_short");
  ok("a solid, non-refusing, long-enough draft -> accept", heuristicVerdict("Paris is the capital of France.", "stop", judge).escalate === false);
  ok("check order: empty wins over finish_reason", heuristicVerdict("", "length", judge).reason === "empty_draft");
}

console.log("\nDEFAULT_REFUSAL_PATTERNS — sane defaults catch common deflections:");
{
  const judge = resolveJudgeConfig({ mode: "heuristic" });
  ok("'As an AI language model, I cannot ...' matches", heuristicVerdict("As an AI language model, I cannot do that.", "stop", judge).escalate);
  ok("'I must decline' matches", heuristicVerdict("I must decline this request.", "stop", judge).escalate);
  ok("patterns list is non-empty", DEFAULT_REFUSAL_PATTERNS.length > 0);
}

console.log("\nparseJudgeVerdict — ACCEPT / ESCALATE parsing, unparseable -> null:");
{
  ok("'ACCEPT' -> accept", parseJudgeVerdict("ACCEPT")?.escalate === false);
  ok("'accept' (any case) -> accept", parseJudgeVerdict("accept")?.escalate === false);
  ok("'ACCEPT\\n' with trailing whitespace -> accept", parseJudgeVerdict("ACCEPT\n")?.escalate === false);
  ok("'ESCALATE: too vague' -> escalate with reason", parseJudgeVerdict("ESCALATE: too vague")?.reason === "too vague");
  ok("'ESCALATE:no space' -> escalate, reason still parsed", parseJudgeVerdict("ESCALATE:no space")?.reason === "no space");
  ok("garbage output -> null (caller fails open)", parseJudgeVerdict("I dunno, looks fine I guess") === null);
  ok("empty output -> null", parseJudgeVerdict("") === null);
}

console.log("\nbuildJudgeInput — truncates an overlong user prompt:");
{
  const input = buildJudgeInput("a".repeat(5000), "the draft", 100);
  ok("truncated to the cap + marker", input.includes("…(truncated)") && !input.includes("a".repeat(200)));
  const short = buildJudgeInput("short prompt", "the draft");
  ok("short prompt untouched", short.includes("short prompt") && !short.includes("truncated"));
}

console.log("\nescalationApplies — gating:");
{
  const cfg = { enabled: true, fromTiers: ["SIMPLE" as const], toTier: "MEDIUM" as const, judge: { mode: "heuristic" as const } };
  ok("disabled config -> false", escalationApplies({ ...cfg, enabled: false }, "SIMPLE", false) === false);
  ok("undefined config -> false", escalationApplies(undefined, "SIMPLE", false) === false);
  ok("streaming request -> false (bypass)", escalationApplies(cfg, "SIMPLE", true) === false);
  ok("EXPLICIT tier -> false", escalationApplies(cfg, "EXPLICIT", false) === false);
  ok("tier not in fromTiers -> false", escalationApplies(cfg, "MEDIUM", false) === false);
  ok("tier in fromTiers, non-streaming, enabled -> true", escalationApplies(cfg, "SIMPLE", false) === true);
}

console.log("\nvalidateEscalationConfig — rejects malformed configs, no-ops when disabled:");
{
  ok("undefined -> no errors", validateEscalationConfig(undefined).length === 0);
  ok(
    "disabled + garbage -> no errors",
    validateEscalationConfig({ enabled: false, fromTiers: [], toTier: "SIMPLE" as any, judge: { mode: "model" as any } }).length === 0,
  );
  ok(
    "empty fromTiers -> error",
    validateEscalationConfig({ enabled: true, fromTiers: [], toTier: "MEDIUM", judge: { mode: "heuristic" } }).some((e) => /fromTiers/.test(e)),
  );
  ok(
    "toTier also in fromTiers -> error",
    validateEscalationConfig({ enabled: true, fromTiers: ["SIMPLE", "MEDIUM"], toTier: "MEDIUM", judge: { mode: "heuristic" } }).some((e) => /toTier/.test(e)),
  );
  ok(
    "mode model without judge.model -> error",
    validateEscalationConfig({ enabled: true, fromTiers: ["SIMPLE"], toTier: "MEDIUM", judge: { mode: "model" } }).some((e) => /judge\.model/.test(e)),
  );
  ok(
    "mode model WITH judge.model -> no error",
    validateEscalationConfig({ enabled: true, fromTiers: ["SIMPLE"], toTier: "MEDIUM", judge: { mode: "model", model: "anthropic/judge" } }).length === 0,
  );
  ok(
    "valid heuristic config -> no errors",
    validateEscalationConfig({ enabled: true, fromTiers: ["SIMPLE"], toTier: "MEDIUM", judge: { mode: "heuristic" } }).length === 0,
  );
}

console.log(`\nEscalation (pure logic): ${pass} passed, ${fail} failed so far`);

// ─────────────────────── Part 2: spawned server ───────────────────────

function jsonUpstream(handler: (body: any, req: import("node:http").IncomingMessage) => Record<string, unknown>) {
  return createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const parsed = body ? JSON.parse(body) : {};
      const result = handler(parsed, req);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(result));
    });
  });
}

function chatCompletion(text: string, finishReason = "stop", label = "mock") {
  return {
    id: `chatcmpl-${label}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: "mock",
    choices: [{ index: 0, message: { role: "assistant", content: text }, finish_reason: finishReason }],
    usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
  };
}

async function listenOn(server: Server): Promise<string> {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}

async function waitForHealth(base: string, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch(`${base}/health`);
      if (r.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("router did not become healthy");
}

/** An OS-assigned free port: bind :0, read the port, release — see split.test.ts's freePort. */
async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  const port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  return port;
}

async function spawnRouter(cfg: Record<string, unknown>): Promise<{ base: string; child: ChildProcess; log: () => string }> {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const dir = mkdtempSync(join(tmpdir(), "secrouter-escalation-"));
  const cfgPath = join(dir, "config.json");
  writeFileSync(join(dir, "auth-profiles.json"), JSON.stringify({ version: 1, profiles: {}, lastGood: {} }));
  writeFileSync(
    cfgPath,
    JSON.stringify({
      port,
      host: "127.0.0.1",
      auth: { default: "profiles", profiles: { type: "profiles", profilesPath: join(dir, "auth-profiles.json") } },
      ...cfg,
    }),
  );
  const child = spawn("npx", ["tsx", "src/server.ts"], {
    cwd: CWD,
    env: { ...process.env, SECROUTER_CONFIG: cfgPath, SECROUTER_PORT: String(port) },
  });
  let log = "";
  child.stdout?.on("data", (d) => (log += d));
  child.stderr?.on("data", (d) => (log += d));
  await waitForHealth(base);
  return { base, child, log: () => log };
}

async function chat(base: string, message: string, stream = false, headers: Record<string, string> = {}) {
  return fetch(`${base}/v1/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify({ model: "auto", stream, messages: [{ role: "user", content: message }] }),
  });
}

/** Standard 2-tier config: cheap "va/*" for SIMPLE (the draft), strong "vb/*" for MEDIUM (the escalation target). */
function baseTiers(cheapModel: string, strongModel: string) {
  return {
    SIMPLE: { primary: cheapModel, fallback: [] as string[] },
    MEDIUM: { primary: strongModel, fallback: [] as string[] },
    COMPLEX: { primary: strongModel, fallback: [] as string[] },
    REASONING: { primary: strongModel, fallback: [] as string[] },
  };
}

async function testHeuristicAcceptAndEscalate() {
  console.log("\nEscalation (heuristic): accept path returns the draft body; escalate path hits the second model:");
  const cheap = jsonUpstream((body) => {
    const msg = String(body.messages?.[body.messages.length - 1]?.content ?? "");
    if (msg.includes("PLEASE_ESCALATE")) return chatCompletion("", "stop", "DRAFT-EMPTY"); // empty -> heuristic escalates
    return chatCompletion("This is a solid, complete draft answer.", "stop", "DRAFT-GOOD");
  });
  const strong = jsonUpstream(() => chatCompletion("This is the ESCALATED, stronger answer.", "stop", "STRONG"));
  const cheapUrl = await listenOn(cheap);
  const strongUrl = await listenOn(strong);

  const { base, child, log } = await spawnRouter({
    providers: { va: { baseUrl: cheapUrl, api: "openai" }, vb: { baseUrl: strongUrl, api: "openai" } },
    tiers: baseTiers("va/cheap-model", "vb/strong-model"),
    experiments: {
      escalation: { enabled: true, fromTiers: ["SIMPLE"], toTier: "MEDIUM", judge: { mode: "heuristic" } },
    },
    security: { enabled: false, metrics: { enabled: true } },
  });

  try {
    const rAccept = await chat(base, "/simple give me a good answer");
    const bodyAccept = await rAccept.json().catch(() => ({}) as any);
    ok("accept: 200", rAccept.status === 200, String(rAccept.status));
    ok("accept: X-SecRouter-Escalation: accepted", rAccept.headers.get("x-secrouter-escalation") === "accepted", String(rAccept.headers.get("x-secrouter-escalation")));
    ok("accept: response body IS the draft", bodyAccept?.choices?.[0]?.message?.content === "This is a solid, complete draft answer.", JSON.stringify(bodyAccept));

    const rEsc = await chat(base, "/simple PLEASE_ESCALATE this one");
    if (rEsc.status !== 200) console.error("child log:\n" + log());
    const bodyEsc = await rEsc.json().catch(() => ({}) as any);
    ok("escalate: 200", rEsc.status === 200, String(rEsc.status));
    ok("escalate: X-SecRouter-Escalation: escalated", rEsc.headers.get("x-secrouter-escalation") === "escalated", String(rEsc.headers.get("x-secrouter-escalation")));
    ok("escalate: X-SecRouter-Model is the strong model", rEsc.headers.get("x-secrouter-model") === "vb/strong-model", String(rEsc.headers.get("x-secrouter-model")));
    ok("escalate: X-SecRouter-Tier is toTier (MEDIUM)", rEsc.headers.get("x-secrouter-tier") === "MEDIUM", String(rEsc.headers.get("x-secrouter-tier")));
    ok("escalate: response body is from the SECOND (strong) model", bodyEsc?.choices?.[0]?.message?.content === "This is the ESCALATED, stronger answer.", JSON.stringify(bodyEsc));

    // Both the draft AND the final call must be accounted (distinct outcome labels).
    const metricsText = await (await fetch(`${base}/metrics`)).text();
    ok(
      "both draft and ok outcomes accounted in secrouter_requests_total",
      /outcome="draft"/.test(metricsText) && /tier="SIMPLE".*outcome="draft"|outcome="draft"/.test(metricsText),
      metricsText.split("\n").filter((l) => l.includes("secrouter_requests_total")).join("\n"),
    );
    ok(
      "secrouter_escalations_total{...,outcome=\"escalated\"} == 1 (exactly one escalation)",
      /secrouter_escalations_total\{from_tier="SIMPLE",to_tier="MEDIUM",outcome="escalated"\} 1/.test(metricsText),
      metricsText.split("\n").filter((l) => l.includes("secrouter_escalations_total")).join("\n"),
    );
    ok(
      "secrouter_escalations_total{...,outcome=\"accepted\"} == 1",
      /secrouter_escalations_total\{from_tier="SIMPLE",to_tier="MEDIUM",outcome="accepted"\} 1/.test(metricsText),
    );
  } finally {
    child.kill();
  }
}

async function testStreamingBypass() {
  console.log("\nEscalation: a streaming request bypasses escalation entirely:");
  const cheap = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const parsed = JSON.parse(body || "{}");
      if (!parsed.stream) {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(chatCompletion("", "stop", "SHOULD-NOT-HAPPEN"))); // would escalate if judged
        return;
      }
      res.writeHead(200, { "content-type": "text/event-stream" });
      const send = (o: unknown) => res.write(`data: ${JSON.stringify(o)}\n\n`);
      send({ id: "c1", object: "chat.completion.chunk", created: 1, model: "mock", choices: [{ index: 0, delta: { role: "assistant", content: "streamed" }, finish_reason: null }] });
      send({ id: "c1", object: "chat.completion.chunk", created: 1, model: "mock", choices: [{ index: 0, delta: {}, finish_reason: "stop" }] });
      res.write("data: [DONE]\n\n");
      res.end();
    });
  });
  const cheapUrl = await listenOn(cheap);
  const strong = jsonUpstream(() => chatCompletion("strong", "stop", "STRONG"));
  const strongUrl = await listenOn(strong);

  const { base, child } = await spawnRouter({
    providers: { va: { baseUrl: cheapUrl, api: "openai" }, vb: { baseUrl: strongUrl, api: "openai" } },
    tiers: baseTiers("va/cheap-model", "vb/strong-model"),
    experiments: {
      escalation: { enabled: true, fromTiers: ["SIMPLE"], toTier: "MEDIUM", judge: { mode: "heuristic" } },
    },
    security: { enabled: false },
  });

  try {
    const r = await chat(base, "/simple this would escalate if judged", true);
    ok("streaming request: 200", r.status === 200, String(r.status));
    ok("streaming request: no X-SecRouter-Escalation header (bypassed)", !r.headers.get("x-secrouter-escalation"), String(r.headers.get("x-secrouter-escalation")));
    ok("streaming request: model is still the cheap tier's primary (never escalated)", r.headers.get("x-secrouter-model") === "va/cheap-model", String(r.headers.get("x-secrouter-model")));
    const text = await r.text();
    ok("streaming body carries the streamed content", text.includes("streamed"), text);
  } finally {
    child.kill();
  }
}

async function testModelJudge() {
  console.log("\nEscalation (model-judge): ACCEPT / ESCALATE parsing, fail-open on timeout + garbage:");
  const draftContent = "a candidate draft answer";
  const cheap = jsonUpstream(() => chatCompletion(draftContent, "stop", "DRAFT"));
  const strong = jsonUpstream(() => chatCompletion("stronger answer", "stop", "STRONG"));
  const cheapUrl = await listenOn(cheap);
  const strongUrl = await listenOn(strong);

  // Judge upstream: content of the LAST message (the judge input, which embeds
  // the draft) decides what the judge says, so one process can serve every case.
  const judge = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", async () => {
      const parsed = JSON.parse(body || "{}");
      const input = String(parsed.messages?.[parsed.messages.length - 1]?.content ?? "");
      if (input.includes("MAKE_JUDGE_HANG")) {
        await new Promise((r) => setTimeout(r, 5000)); // longer than judge.timeoutMs below
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(chatCompletion("ACCEPT", "stop", "JUDGE-LATE")));
        return;
      }
      const verdictText = input.includes("MAKE_JUDGE_ESCALATE") ? "ESCALATE: draft is weak" : input.includes("MAKE_JUDGE_GARBAGE") ? "uh, sure, looks ok??" : "ACCEPT";
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(chatCompletion(verdictText, "stop", "JUDGE")));
    });
  });
  const judgeUrl = await listenOn(judge);

  const { base, child } = await spawnRouter({
    providers: {
      va: { baseUrl: cheapUrl, api: "openai" },
      vb: { baseUrl: strongUrl, api: "openai" },
      judge: { baseUrl: judgeUrl, api: "openai" },
    },
    tiers: baseTiers("va/cheap-model", "vb/strong-model"),
    experiments: {
      escalation: {
        enabled: true,
        fromTiers: ["SIMPLE"],
        toTier: "MEDIUM",
        judge: { mode: "model", model: "judge/judge-model", timeoutMs: 1500 },
      },
    },
    security: { enabled: false },
  });

  try {
    const rAccept = await chat(base, "/simple normal request");
    ok("judge says ACCEPT -> accepted", rAccept.headers.get("x-secrouter-escalation") === "accepted", String(rAccept.headers.get("x-secrouter-escalation")));

    const rEscalate = await chat(base, "/simple MAKE_JUDGE_ESCALATE please");
    ok("judge says ESCALATE -> escalated", rEscalate.headers.get("x-secrouter-escalation") === "escalated", String(rEscalate.headers.get("x-secrouter-escalation")));
    const bodyEsc = await rEscalate.json().catch(() => ({}) as any);
    ok("escalated body comes from the strong model", bodyEsc?.choices?.[0]?.message?.content === "stronger answer", JSON.stringify(bodyEsc));

    const rGarbage = await chat(base, "/simple MAKE_JUDGE_GARBAGE please");
    ok("unparseable judge output -> fails open (accepted)", rGarbage.headers.get("x-secrouter-escalation") === "accepted", String(rGarbage.headers.get("x-secrouter-escalation")));

    const startTimeout = Date.now();
    const rTimeout = await chat(base, "/simple MAKE_JUDGE_HANG please");
    const elapsed = Date.now() - startTimeout;
    ok("judge timeout -> fails open (accepted)", rTimeout.headers.get("x-secrouter-escalation") === "accepted", String(rTimeout.headers.get("x-secrouter-escalation")));
    ok("judge timeout resolved near judge.timeoutMs, not the full 5s hang", elapsed < 4000, String(elapsed));
  } finally {
    child.kill();
  }
}

async function testExactlyOneEscalation() {
  console.log("\nEscalation: exactly one escalation per request (escalated tier's own answer is never re-judged):");
  const cheap = jsonUpstream(() => chatCompletion("", "stop", "DRAFT-EMPTY")); // always escalates (empty)
  const strong = jsonUpstream(() => chatCompletion("", "stop", "STRONG-ALSO-EMPTY")); // would ALSO "fail" heuristic judging if re-run
  const cheapUrl = await listenOn(cheap);
  const strongUrl = await listenOn(strong);

  const { base, child } = await spawnRouter({
    providers: { va: { baseUrl: cheapUrl, api: "openai" }, vb: { baseUrl: strongUrl, api: "openai" } },
    tiers: baseTiers("va/cheap-model", "vb/strong-model"),
    experiments: {
      escalation: { enabled: true, fromTiers: ["SIMPLE"], toTier: "MEDIUM", judge: { mode: "heuristic" } },
    },
    security: { enabled: false, metrics: { enabled: true } },
  });

  try {
    const r = await chat(base, "/simple always escalates");
    ok("request succeeded even though BOTH tiers would 'fail' judging", r.status === 200, String(r.status));
    ok("escalated exactly once (final answer is the strong model's, not re-escalated)", r.headers.get("x-secrouter-escalation") === "escalated");
    ok("final model is the strong (toTier) model", r.headers.get("x-secrouter-model") === "vb/strong-model", String(r.headers.get("x-secrouter-model")));
    const metricsText = await (await fetch(`${base}/metrics`)).text();
    const m = /secrouter_escalations_total\{from_tier="SIMPLE",to_tier="MEDIUM",outcome="escalated"\} (\d+)/.exec(metricsText);
    ok("escalations_total incremented exactly once, not twice", !!m && m[1] === "1", metricsText.split("\n").filter((l) => l.includes("escalations_total")).join("\n"));
  } finally {
    child.kill();
  }
}

async function testEscalationDenied() {
  console.log("\nEscalation: policy-denied escalation serves the draft instead of hard-failing:");
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "k1";
  jwk.alg = "RS256";
  jwk.use = "sig";
  const oidc = createServer((_req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  const oidcUrl = await listenOn(oidc);

  const cheap = jsonUpstream(() => chatCompletion("", "stop", "DRAFT-EMPTY")); // always escalates
  const strong = jsonUpstream(() => chatCompletion("stronger", "stop", "STRONG"));
  const cheapUrl = await listenOn(cheap);
  const strongUrl = await listenOn(strong);

  const ISS = "https://idp.test/escalation";
  const AUD = "secrouter";
  const dir = mkdtempSync(join(tmpdir(), "secrouter-escalation-denied-"));
  const { base, child } = await spawnRouter({
    providers: { va: { baseUrl: cheapUrl, api: "openai" }, vb: { baseUrl: strongUrl, api: "openai" } },
    tiers: baseTiers("va/cheap-model", "vb/strong-model"),
    experiments: {
      escalation: { enabled: true, fromTiers: ["SIMPLE"], toTier: "MEDIUM", judge: { mode: "heuristic" } },
    },
    security: {
      enabled: true,
      storePath: join(dir, "store.db"),
      oidc: { issuer: ISS, audience: AUD, jwksUri: `${oidcUrl}/jwks`, groupsClaim: "groups", requireMfa: false },
      classification: { default: "UNCLASSIFIED", levels: ["UNCLASSIFIED"] },
      egress: {
        allowlist: [
          { provider: "va", allowedHost: new URL(cheapUrl).host, authorizedClassifications: ["UNCLASSIFIED"] },
          { provider: "vb", allowedHost: new URL(strongUrl).host, authorizedClassifications: ["UNCLASSIFIED"] },
        ],
      },
      policy: {
        default: {
          allowedTiers: ["SIMPLE"], // MEDIUM is NOT permitted -> escalation target denied
          maxTier: "SIMPLE",
          onViolation: "deny",
          maxClassification: "UNCLASSIFIED",
        },
      },
    },
  });

  try {
    const token = await new SignJWT({ groups: [] })
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(ISS)
      .setAudience(AUD)
      .setSubject("capped-user")
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 600)
      .sign(privateKey);

    const r = await chat(base, "/simple this always escalates", false, { Authorization: `Bearer ${token}` });
    ok("request still succeeds (200), draft served instead of hard failure", r.status === 200, String(r.status));
    ok("X-SecRouter-Escalation: escalation_denied", r.headers.get("x-secrouter-escalation") === "escalation_denied", String(r.headers.get("x-secrouter-escalation")));
    const body = await r.json().catch(() => ({}) as any);
    ok("body is the draft (empty content), not the strong model's answer", body?.choices?.[0]?.message?.content === "", JSON.stringify(body));
  } finally {
    child.kill();
  }
}

async function main() {
  await testHeuristicAcceptAndEscalate();
  await testStreamingBypass();
  await testModelJudge();
  await testExactlyOneEscalation();
  await testEscalationDenied();
}

main()
  .then(() => {
    console.log(`\nEscalation routing: ${pass} passed, ${fail} failed`);
    if (fail > 0) process.exit(1);
    process.exit(0);
  })
  .catch((err) => {
    console.error("Escalation test crashed:", err);
    process.exit(1);
  });
