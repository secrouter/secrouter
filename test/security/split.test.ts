/**
 * Split (A/B) routing tests. Run: npx tsx test/security/split.test.ts
 *
 * Part 1 (pure, no server): weighted-assignment math and config validation —
 * fully deterministic given an injected RNG, see src/router/split.ts.
 * Part 2 (spawned real server + fake upstreams): header/reasoning wiring,
 * disabled/EXPLICIT/absent-tier no-ops, and the health-aware-steer-away
 * contamination marker (secrouter_split_steered_total).
 */

import { createServer, type Server } from "node:http";
import { spawn, type ChildProcess } from "node:child_process";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pickWeightedVariant, applySplit, validateSplitConfig } from "../../src/router/split.js";

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

console.log("pickWeightedVariant — boundary rng values map to the right variant:");
{
  const variants = [
    { model: "a/x", weight: 1 },
    { model: "b/y", weight: 3 },
  ]; // total=4; a occupies [0,1), b occupies [1,4) in raw r-space, i.e. rng in [0, 0.25) -> a
  ok("rng=0 -> first variant (a)", pickWeightedVariant(variants, () => 0).model === "a/x");
  ok("rng just under 0.25 -> still a", pickWeightedVariant(variants, () => 0.24).model === "a/x");
  ok("rng=0.25 exactly -> b (boundary)", pickWeightedVariant(variants, () => 0.25).model === "b/y");
  ok("rng close to 1 -> b", pickWeightedVariant(variants, () => 0.999999).model === "b/y");
}

console.log("\npickWeightedVariant — distribution matches weights within tolerance over many draws:");
{
  const variants = [
    { model: "a/x", weight: 1 },
    { model: "b/y", weight: 4 },
  ]; // expect ~20% a, ~80% b
  const N = 20_000;
  let seed = 42;
  const rng = () => {
    // simple deterministic LCG so the test is reproducible
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed / 0x7fffffff;
  };
  let countA = 0;
  for (let i = 0; i < N; i++) {
    if (pickWeightedVariant(variants, rng).model === "a/x") countA++;
  }
  const frac = countA / N;
  ok(`~20% assigned to the weight-1 variant (got ${(frac * 100).toFixed(1)}%)`, frac > 0.17 && frac < 0.23, String(frac));
}

console.log("\napplySplit — no-ops:");
{
  ok("no experiments config -> null", applySplit(undefined, "SIMPLE", () => 0) === null);
  ok(
    "split disabled -> null",
    applySplit({ split: { enabled: false, name: "x", tiers: { SIMPLE: { variants: [{ model: "a/x", weight: 1 }, { model: "b/y", weight: 1 }] } } } }, "SIMPLE", () => 0) === null,
  );
  ok(
    "tier === EXPLICIT -> null even if configured",
    applySplit({ split: { enabled: true, name: "x", tiers: { SIMPLE: { variants: [{ model: "a/x", weight: 1 }, { model: "b/y", weight: 1 }] } } } }, "EXPLICIT", () => 0) === null,
  );
  ok(
    "tier absent from split.tiers -> null",
    applySplit({ split: { enabled: true, name: "x", tiers: { MEDIUM: { variants: [{ model: "a/x", weight: 1 }, { model: "b/y", weight: 1 }] } } } }, "SIMPLE", () => 0) === null,
  );
}

console.log("\napplySplit — a valid, enabled, matching tier assigns a variant:");
{
  const cfg = { split: { enabled: true, name: "exp1", tiers: { SIMPLE: { variants: [{ model: "a/x", weight: 1 }, { model: "b/y", weight: 1 }] } } } };
  const assigned = applySplit(cfg, "SIMPLE", () => 0);
  ok("assignment carries the experiment name", assigned?.name === "exp1", JSON.stringify(assigned));
  ok("assignment carries a configured model", assigned?.model === "a/x", JSON.stringify(assigned));
}

console.log("\nvalidateSplitConfig — rejects malformed configs, no-ops when disabled:");
{
  ok("undefined -> no errors", validateSplitConfig(undefined).length === 0);
  ok("disabled + garbage -> no errors (short-circuits)", validateSplitConfig({ enabled: false, name: "", tiers: {} }).length === 0);
  ok(
    "enabled without name -> error",
    validateSplitConfig({ enabled: true, name: "", tiers: { SIMPLE: { variants: [{ model: "a/x", weight: 1 }, { model: "b/y", weight: 1 }] } } }).some((e) => /name/.test(e)),
  );
  ok(
    "enabled with zero tiers -> error",
    validateSplitConfig({ enabled: true, name: "x", tiers: {} }).some((e) => /at least one tier/.test(e)),
  );
  ok(
    "only 1 variant -> error",
    validateSplitConfig({ enabled: true, name: "x", tiers: { SIMPLE: { variants: [{ model: "a/x", weight: 1 }] } } }).some((e) => /at least 2 variants/.test(e)),
  );
  ok(
    "zero weight -> error",
    validateSplitConfig({ enabled: true, name: "x", tiers: { SIMPLE: { variants: [{ model: "a/x", weight: 0 }, { model: "b/y", weight: 1 }] } } }).some((e) => /weight/.test(e)),
  );
  ok(
    "negative weight -> error",
    validateSplitConfig({ enabled: true, name: "x", tiers: { SIMPLE: { variants: [{ model: "a/x", weight: -1 }, { model: "b/y", weight: 1 }] } } }).some((e) => /weight/.test(e)),
  );
  ok(
    "malformed model id (no provider prefix) -> error",
    validateSplitConfig({ enabled: true, name: "x", tiers: { SIMPLE: { variants: [{ model: "no-slash-here", weight: 1 }, { model: "b/y", weight: 1 }] } } }).some((e) => /provider\/model/.test(e)),
  );
  ok(
    "valid enabled config -> no errors",
    validateSplitConfig({ enabled: true, name: "x", tiers: { SIMPLE: { variants: [{ model: "a/x", weight: 1 }, { model: "b/y", weight: 2 }] } } }).length === 0,
  );
}

console.log(`\nSplit (pure logic): ${pass} passed, ${fail} failed so far`);

// ─────────────────────── Part 2: spawned server ───────────────────────

function makeEchoUpstream(label: string) {
  return createServer((req, res) => {
    if (req.method === "GET" && /\/models$/.test(req.url ?? "")) {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ object: "list", data: [{ id: label }] }));
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
          choices: [{ index: 0, message: { role: "assistant", content: `hi from ${label}` }, finish_reason: "stop" }],
          usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
        }),
      );
    });
  });
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

/** An OS-assigned free port: bind :0, read the port, release. Far less collision-prone than a
 * fixed random range — a range pick collided with e2e's 19500-19599 servers under the full suite. */
async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  const port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  return port;
}

async function spawnRouter(cfg: Record<string, unknown>): Promise<{ base: string; child: ChildProcess; dir: string }> {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const dir = mkdtempSync(join(tmpdir(), "secrouter-split-"));
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
  (child as any)._log = () => log;
  await waitForHealth(base);
  return { base, child, dir };
}

async function chat(base: string, message: string, stream = false) {
  return fetch(`${base}/v1/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: "auto", stream, messages: [{ role: "user", content: message }] }),
  });
}

async function testHeaderAndReasoning() {
  console.log("\nSplit: header + reasoning set when a variant is assigned (both variants resolve to the same upstream):");
  const up = makeEchoUpstream("VARIANT");
  const upUrl = await listenOn(up);

  const { base, child } = await spawnRouter({
    providers: {
      va: { baseUrl: upUrl, api: "openai" },
      vb: { baseUrl: upUrl, api: "openai" },
    },
    tiers: {
      SIMPLE: { primary: "va/model-a", fallback: [] },
      MEDIUM: { primary: "va/model-a", fallback: [] },
      COMPLEX: { primary: "va/model-a", fallback: [] },
      REASONING: { primary: "va/model-a", fallback: [] },
    },
    experiments: {
      split: {
        enabled: true,
        name: "exp-header",
        tiers: { SIMPLE: { variants: [{ model: "va/model-a", weight: 1 }, { model: "vb/model-b", weight: 1 }] } },
      },
    },
    security: { enabled: false },
  });

  try {
    const r = await chat(base, "/simple hello there");
    ok("request succeeded", r.status === 200, String(r.status));
    const splitHeader = r.headers.get("x-secrouter-split") ?? "";
    ok("X-SecRouter-Split header present", /^exp-header=/.test(splitHeader), splitHeader);
    const model = r.headers.get("x-secrouter-model") ?? "";
    ok("assigned model is one of the two variants", model === "va/model-a" || model === "vb/model-b", model);
    const reasoning = r.headers.get("x-secrouter-reasoning") ?? "";
    ok("reasoning names the split experiment", reasoning.includes("split:exp-header="), reasoning);
  } finally {
    child.kill();
  }
}

async function testNoOps() {
  console.log("\nSplit: no-ops (absent tier entry, EXPLICIT model, disabled):");
  const up = makeEchoUpstream("PLAIN");
  const upUrl = await listenOn(up);

  const { base, child } = await spawnRouter({
    providers: { va: { baseUrl: upUrl, api: "openai" }, vb: { baseUrl: upUrl, api: "openai" } },
    tiers: {
      SIMPLE: { primary: "va/simple-primary", fallback: [] },
      MEDIUM: { primary: "va/medium-primary", fallback: [] },
      COMPLEX: { primary: "va/medium-primary", fallback: [] },
      REASONING: { primary: "va/medium-primary", fallback: [] },
    },
    experiments: {
      split: {
        enabled: true,
        name: "exp-medium-only",
        tiers: { MEDIUM: { variants: [{ model: "va/medium-primary", weight: 1 }, { model: "vb/medium-b", weight: 1 }] } },
      },
    },
    security: { enabled: false },
  });

  try {
    const rSimple = await chat(base, "/simple no split for me");
    ok("SIMPLE (no split entry for this tier) -> no split header", !rSimple.headers.get("x-secrouter-split"), String(rSimple.headers.get("x-secrouter-split")));
    ok("SIMPLE -> model is the plain configured primary", rSimple.headers.get("x-secrouter-model") === "va/simple-primary", String(rSimple.headers.get("x-secrouter-model")));

    const rMedium = await chat(base, "/medium this one has a split entry");
    ok("MEDIUM (has a split entry) -> split header present", !!rMedium.headers.get("x-secrouter-split"), String(rMedium.headers.get("x-secrouter-split")));

    const rExplicit = await chat(base, "hello");
    // override the model field directly to force EXPLICIT
    const rExplicit2 = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: "va/medium-primary", stream: false, messages: [{ role: "user", content: "hi" }] }),
    });
    ok(
      "explicit model request (tier=EXPLICIT) -> no split header even though MEDIUM has a split entry",
      !rExplicit2.headers.get("x-secrouter-split"),
      String(rExplicit2.headers.get("x-secrouter-split")),
    );
    void rExplicit;
  } finally {
    child.kill();
  }
}

/** Chat-only upstream with NO /models handler — never registers as "live" via the active health probe. */
function makeChatOnlyUpstream(label: string) {
  return createServer((req, res) => {
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
          choices: [{ index: 0, message: { role: "assistant", content: `hi from ${label}` }, finish_reason: "stop" }],
          usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
        }),
      );
    });
  });
}

async function testSteerAway() {
  console.log("\nSplit: health-aware steer-away increments split_steered_total (and split_assigned_total still counted):");
  // NO /models handler on the split variants' own upstreams — they must never
  // register as "live" themselves, or "onlylive" wouldn't be the SOLE live model.
  const upA = makeChatOnlyUpstream("VA");
  const upB = makeChatOnlyUpstream("VB");
  // The sole "live" model globally, from an unrelated provider — health-aware
  // steering collapses ANY non-EXPLICIT routed model onto it when it's the only
  // thing reported live anywhere (see router/health.ts "sole live model" rule),
  // regardless of which split variant was randomly assigned.
  const upLive = createServer((req, res) => {
    if (req.method === "GET" && /\/models$/.test(req.url ?? "")) {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ object: "list", data: [{ id: "steer-target" }] }));
      return;
    }
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          id: "chatcmpl-LIVE",
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: "mock",
          choices: [{ index: 0, message: { role: "assistant", content: "hi from live" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
        }),
      );
    });
  });

  const urlA = await listenOn(upA);
  const urlB = await listenOn(upB);
  const urlLive = await listenOn(upLive);

  const { base, child } = await spawnRouter({
    providers: {
      va: { baseUrl: urlA, api: "openai" },
      vb: { baseUrl: urlB, api: "openai" },
      onlylive: { baseUrl: urlLive, api: "openai" },
    },
    tiers: {
      SIMPLE: { primary: "va/steer-model-a", fallback: [] },
      MEDIUM: { primary: "va/steer-model-a", fallback: [] },
      COMPLEX: { primary: "va/steer-model-a", fallback: [] },
      REASONING: { primary: "va/steer-model-a", fallback: [] },
    },
    experiments: {
      split: {
        enabled: true,
        name: "exp-steer",
        tiers: { SIMPLE: { variants: [{ model: "va/steer-model-a", weight: 1 }, { model: "vb/steer-model-b", weight: 1 }] } },
      },
    },
    security: { enabled: false, resilience: { circuitThreshold: 5, cooldownSec: 1, healthIntervalSec: 2 }, metrics: { enabled: true } },
  });

  try {
    // Wait past the health-check interval so the active /models probe of
    // 'onlylive' lands and it becomes the sole known-live model. Generous
    // margin over the 2s interval to avoid flakiness under load.
    await new Promise((r) => setTimeout(r, 5000));

    const r = await chat(base, "/simple steer me please");
    if (r.status !== 200) console.error("DEBUG child log:\n" + (child as any)._log());
    ok("request succeeded", r.status === 200, String(r.status) + " body=" + (await r.text().catch(() => "")));
    ok(
      "steered onto the sole live model regardless of which split variant was assigned",
      r.headers.get("x-secrouter-model") === "onlylive/steer-target",
      String(r.headers.get("x-secrouter-model")),
    );

    const metricsRes = await fetch(`${base}/metrics`);
    const metricsText = await metricsRes.text();
    ok("secrouter_split_assigned_total appears (a variant was assigned before the steer)", /secrouter_split_assigned_total\{[^}]*tier="SIMPLE"/.test(metricsText), metricsText.slice(0, 400));
    const steerMatch = /secrouter_split_steered_total\{tier="SIMPLE"\} (\d+)/.exec(metricsText);
    ok("secrouter_split_steered_total{tier=SIMPLE} == 1", !!steerMatch && steerMatch[1] === "1", metricsText.slice(0, 800));
  } finally {
    child.kill();
  }
}

async function main() {
  await testHeaderAndReasoning();
  await testNoOps();
  await testSteerAway();
}

main()
  .then(() => {
    console.log(`\nSplit routing: ${pass} passed, ${fail} failed`);
    if (fail > 0) process.exit(1);
    process.exit(0);
  })
  .catch((err) => {
    console.error("Split test crashed:", err);
    process.exit(1);
  });
