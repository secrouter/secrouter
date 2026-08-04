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

console.log("\nPer-endpoint isolation (multi-endpoint load balancing):");
{
  const b = new CircuitBreaker(cfg, now);
  // endpoint 0 of provider "m" trips open; endpoint 1 must be untouched.
  b.recordFailure("m", 0);
  b.recordFailure("m", 0);
  const tr0 = b.recordFailure("m", 0); // 3rd failure on endpoint 0 -> open
  ok("endpoint 0 opens with a transition carrying endpoint:0", tr0?.to === "open" && tr0?.endpoint === 0);
  ok("endpoint 0 is open and not admitted", b.getState("m", 0) === "open" && b.admit("m", 0).ok === false);
  ok("endpoint 1 of the SAME provider is untouched (closed, admitted)", b.getState("m", 1) === "closed" && b.admit("m", 1).ok === true);

  // Recovery is per-endpoint too: closing endpoint 1 (never opened) via success
  // must not affect endpoint 0's open state.
  const s1 = b.recordSuccess("m", 5, 1);
  ok("recordSuccess on endpoint 1 (already closed) -> no transition", s1 === null);
  ok("endpoint 0 still open after endpoint 1 activity", b.getState("m", 0) === "open");

  // Default endpoint (omitted arg) is exactly endpoint 0 — same key, same state.
  ok("omitting endpoint == endpoint 0 (same underlying state)", b.getState("m") === b.getState("m", 0) && b.admit("m").ok === false);

  // Two DIFFERENT providers each addressed by endpoint never collide.
  const b2 = new CircuitBreaker(cfg, now);
  b2.recordFailure("x", 0);
  b2.recordFailure("x", 0);
  b2.recordFailure("x", 0); // x#0 opens
  ok("provider x endpoint 0 open", b2.getState("x", 0) === "open");
  ok("provider x endpoint 1 unaffected", b2.getState("x", 1) === "closed");
  ok("a different provider y endpoint 0 unaffected", b2.getState("y", 0) === "closed");

  // snapshot() surfaces one row per (provider, endpoint) with the endpoint field,
  // and does NOT leak the internal composite key.
  const snap = b.snapshot();
  const e0 = snap.find((h) => h.provider === "m" && h.endpoint === 0);
  const e1 = snap.find((h) => h.provider === "m" && h.endpoint === 1);
  ok("snapshot has a distinct row for endpoint 0 (open)", e0?.state === "open");
  ok("snapshot has a distinct row for endpoint 1 (closed)", e1?.state === "closed");
}

console.log("\nCooldown/half-open promotion is scoped to the failing endpoint:");
{
  clock = 4_000_000;
  const b = new CircuitBreaker(cfg, now);
  b.recordFailure("p", 2);
  b.recordFailure("p", 2);
  b.recordFailure("p", 2); // p#2 opens at clock=4_000_000
  ok("p#2 open, p#0 (default) still closed and admitted", b.getState("p", 2) === "open" && b.admit("p").ok === true);
  clock += 30_000; // cooldown elapses for p#2 only
  const g = b.admit("p", 2);
  ok("p#2 promoted to half-open after its own cooldown", g.ok === true && g.transition?.to === "half-open" && g.transition?.endpoint === 2);
  const cl = b.recordSuccess("p", 7, 2);
  ok("p#2 half-open probe succeeds -> closed", cl?.to === "closed" && cl?.endpoint === 2 && b.getState("p", 2) === "closed");
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
