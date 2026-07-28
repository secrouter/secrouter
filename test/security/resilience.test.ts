/**
 * Circuit-breaker unit tests. Run: npx tsx test/security/resilience.test.ts
 * Pure state machine driven by an injected clock — deterministic, no timers.
 */

import { CircuitBreaker, isHealthFailure, resolveResilience, CIRCUIT_STATE_CODE } from "../../src/security/resilience.js";

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

// Injectable clock so cooldown math is deterministic.
let clock = 1_000_000;
const now = () => clock;
const cfg = { circuitThreshold: 3, cooldownSec: 30, healthIntervalSec: 0 };

console.log("Circuit breaker state machine:");
{
  const b = new CircuitBreaker(cfg, now);
  // Below threshold stays closed, no transition.
  ok("failure 1 of 3 → still closed, no transition", b.recordFailure("p") === null && b.getState("p") === "closed");
  ok("failure 2 of 3 → still closed", b.recordFailure("p") === null && b.getState("p") === "closed");
  const tr = b.recordFailure("p"); // 3rd → open
  ok("failure 3 of 3 → trips open with a transition", tr?.to === "open" && tr?.from === "closed" && tr?.consecutiveFailures === 3);
  ok("open provider is not admitted within cooldown", b.admit("p").ok === false);
}

console.log("\nCooldown → half-open → recovery:");
{
  clock = 2_000_000;
  const b = new CircuitBreaker(cfg, now);
  b.recordFailure("p");
  b.recordFailure("p");
  b.recordFailure("p"); // open at clock=2_000_000
  ok("still open just before cooldown elapses", ((clock = 2_000_000 + 29_999), b.admit("p").ok === false));
  clock = 2_000_000 + 30_000; // exactly cooldownSec later
  const g = b.admit("p");
  ok("cooldown elapsed → admitted as half-open with transition", g.ok === true && g.transition?.to === "half-open");
  ok("state is now half-open", b.getState("p") === "half-open");
  const cl = b.recordSuccess("p", 42);
  ok("half-open success → closes with transition", cl?.to === "closed" && b.getState("p") === "closed");
  ok("latency recorded on success", b.snapshot().find((h) => h.provider === "p")?.lastLatencyMs === 42);
}

console.log("\nFailed half-open probe re-opens:");
{
  clock = 3_000_000;
  const b = new CircuitBreaker(cfg, now);
  b.recordFailure("p");
  b.recordFailure("p");
  b.recordFailure("p"); // open
  clock += 30_000;
  b.admit("p"); // → half-open
  const re = b.recordFailure("p"); // probe fails → re-open
  ok("failed probe re-opens with transition", re?.to === "open" && b.getState("p") === "open");
  ok("cooldown re-armed from the failed probe", ((clock += 1), b.admit("p").ok === false));
}

console.log("\nSuccess resets the failure streak (closed):");
{
  const b = new CircuitBreaker(cfg, now);
  b.recordFailure("p");
  b.recordFailure("p");
  ok("2 failures then success → no transition, streak reset", b.recordSuccess("p") === null);
  ok("a subsequent single failure does not open (streak was reset)", b.recordFailure("p") === null && b.getState("p") === "closed");
}

console.log("\nPer-provider isolation:");
{
  const b = new CircuitBreaker(cfg, now);
  b.recordFailure("a");
  b.recordFailure("a");
  b.recordFailure("a"); // a opens
  ok("provider a open, provider b untouched (closed + admitted)", b.getState("a") === "open" && b.getState("b") === "closed" && b.admit("b").ok);
}

console.log("\nSnapshot shape:");
{
  const b = new CircuitBreaker(cfg, now);
  b.recordSuccess("p", 10);
  b.recordFailure("p");
  const h = b.snapshot().find((x) => x.provider === "p")!;
  ok("snapshot has public fields", h.state === "closed" && h.totalSuccesses === 1 && h.totalFailures === 1);
  ok("snapshot does NOT leak the internal openedAtMs field", !("openedAtMs" in h));
}

console.log("\nHealth-failure classification (breaker counts provider health only):");
ok("EgressDeniedError → not a health failure", isHealthFailure({ name: "EgressDeniedError" }) === false);
ok("TimeoutError → health failure", isHealthFailure({ name: "TimeoutError" }) === true);
ok("UpstreamError 500 → health failure", isHealthFailure({ name: "UpstreamError", status: 500 }) === true);
ok("UpstreamError 503 → health failure", isHealthFailure({ name: "UpstreamError", status: 503 }) === true);
ok("UpstreamError 404 → client error, NOT health", isHealthFailure({ name: "UpstreamError", status: 404 }) === false);
ok("UpstreamError 400 → client error, NOT health", isHealthFailure({ name: "UpstreamError", status: 400 }) === false);
ok("UpstreamError without status → health failure", isHealthFailure({ name: "UpstreamError" }) === true);
ok("generic connect error → health failure", isHealthFailure(new Error("fetch failed")) === true);
ok("non-object throw → health failure", isHealthFailure("boom") === true);

console.log("\nConfig defaults + encoding:");
{
  const r = resolveResilience({ circuitThreshold: 7 });
  ok("resolveResilience keeps overrides, fills defaults", r.circuitThreshold === 7 && r.cooldownSec === 30 && r.healthIntervalSec === 0);
  ok("resolveResilience() with no partial → all defaults", resolveResilience().circuitThreshold === 5);
  ok("state codes: closed=0, open=1, half-open=2", CIRCUIT_STATE_CODE.closed === 0 && CIRCUIT_STATE_CODE.open === 1 && CIRCUIT_STATE_CODE["half-open"] === 2);
}

console.log(`\nResilience: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
