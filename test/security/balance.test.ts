/**
 * Load-balancing selector unit tests. Run: npx tsx test/security/balance.test.ts
 * Pure function driven by a real CircuitBreaker with an injected clock — no
 * server, no network, fully deterministic.
 */

import { selectEndpoints, type CursorState } from "../../src/router/balance.js";
import { CircuitBreaker, type Transition } from "../../src/security/resilience.js";

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

let clock = 1_000_000;
const now = () => clock;
const cfg = { circuitThreshold: 2, cooldownSec: 30, healthIntervalSec: 0 };

console.log("Single-endpoint provider (today's shape) is unaffected:");
{
  const breaker = new CircuitBreaker(cfg, now);
  const cursor: CursorState = {};
  ok("1 healthy endpoint -> [0]", JSON.stringify(selectEndpoints("solo", 1, breaker, cursor)) === "[0]");
  ok("repeated calls still return [0] (nothing else to rotate to)", JSON.stringify(selectEndpoints("solo", 1, breaker, cursor)) === "[0]");
  breaker.recordFailure("solo", 0);
  breaker.recordFailure("solo", 0); // opens at threshold 2
  ok("its only endpoint open -> []", JSON.stringify(selectEndpoints("solo", 1, breaker, cursor)) === "[]");
}

console.log("\nRound robin across healthy endpoints:");
{
  const breaker = new CircuitBreaker(cfg, now);
  const cursor: CursorState = {};
  const firsts = [0, 1, 2, 0, 1, 2, 0].map(() => selectEndpoints("rr", 3, breaker, cursor)[0]);
  ok("first-pick cycles 0,1,2,0,1,2,0", JSON.stringify(firsts) === JSON.stringify([0, 1, 2, 0, 1, 2, 0]), JSON.stringify(firsts));
  ok(
    "cursorState shape: a plain { [provider]: number } map",
    typeof cursor === "object" && typeof cursor.rr === "number" && Object.keys(cursor).length === 1,
    JSON.stringify(cursor),
  );
}

console.log("\nEach call returns the FULL ordering (for in-request fallback), not just one pick:");
{
  const breaker = new CircuitBreaker(cfg, now);
  const cursor: CursorState = {};
  const order = selectEndpoints("full", 3, breaker, cursor);
  ok("all 3 healthy endpoints present, rotated (not dropped)", order.length === 3 && new Set(order).size === 3, JSON.stringify(order));
}

console.log("\nBreaker-aware: an open endpoint is dropped, survivors still round-robin:");
{
  const breaker = new CircuitBreaker(cfg, now);
  const cursor: CursorState = {};
  breaker.recordFailure("mix", 1);
  breaker.recordFailure("mix", 1); // endpoint 1 opens
  const order = selectEndpoints("mix", 3, breaker, cursor);
  ok("endpoint 1 (open) excluded from the order", !order.includes(1), JSON.stringify(order));
  ok("endpoints 0 and 2 both present", order.includes(0) && order.includes(2), JSON.stringify(order));
}

console.log("\nAll endpoints open -> empty order (caller treats as circuit_open):");
{
  const breaker = new CircuitBreaker(cfg, now);
  const cursor: CursorState = {};
  for (const idx of [0, 1]) {
    breaker.recordFailure("dead", idx);
    breaker.recordFailure("dead", idx);
  }
  ok("both endpoints open -> []", JSON.stringify(selectEndpoints("dead", 2, breaker, cursor)) === "[]");
}

console.log("\nRecovery: a single failing endpoint is skipped, traffic pins to the healthy one:");
{
  clock = 2_000_000;
  const breaker = new CircuitBreaker(cfg, now);
  const cursor: CursorState = {};
  breaker.recordFailure("pin", 0);
  breaker.recordFailure("pin", 0); // endpoint 0 opens
  for (let i = 0; i < 4; i++) {
    const order = selectEndpoints("pin", 2, breaker, cursor);
    ok(`request ${i}: only endpoint 1 offered while 0 is open`, JSON.stringify(order) === "[1]", JSON.stringify(order));
  }
  // Cooldown elapses -> endpoint 0 is promoted to half-open and reoffered.
  clock += 30_000;
  const recovered = selectEndpoints("pin", 2, breaker, cursor);
  ok("after cooldown, endpoint 0 (half-open) is offered again", recovered.includes(0), JSON.stringify(recovered));
}

console.log("\nModel-aware `serves` hook narrows candidates, but never to zero:");
{
  const breaker = new CircuitBreaker(cfg, now);
  const cursor: CursorState = {};
  const onlyServesTwo = selectEndpoints("hook", 3, breaker, cursor, { serves: (idx) => idx === 2 });
  ok("narrows to the serving endpoint only", JSON.stringify(onlyServesTwo) === "[2]", JSON.stringify(onlyServesTwo));

  const cursor2: CursorState = {};
  const servesNone = selectEndpoints("hook2", 3, breaker, cursor2, { serves: () => false });
  ok("serves() excluding everything falls back to ALL admitted (never starves the request)", servesNone.length === 3, JSON.stringify(servesNone));
}

console.log("\nonTransition hook surfaces admission-time transitions (e.g. open -> half-open on cooldown):");
{
  clock = 3_000_000;
  const breaker = new CircuitBreaker(cfg, now);
  const cursor: CursorState = {};
  breaker.recordFailure("probe", 0);
  breaker.recordFailure("probe", 0); // opens
  clock += 30_000; // cooldown elapses
  const seen: Transition[] = [];
  const order = selectEndpoints("probe", 1, breaker, cursor, { onTransition: (t) => seen.push(t) });
  ok("endpoint re-admitted as half-open", order.length === 1);
  ok("onTransition fired exactly once, for the open->half-open promotion", seen.length === 1 && seen[0].from === "open" && seen[0].to === "half-open" && seen[0].endpoint === 0, JSON.stringify(seen));
}

console.log("\nInvalid endpoint counts are handled defensively:");
{
  const breaker = new CircuitBreaker(cfg, now);
  const cursor: CursorState = {};
  ok("endpointCount 0 -> []", JSON.stringify(selectEndpoints("none", 0, breaker, cursor)) === "[]");
  ok("negative endpointCount -> []", JSON.stringify(selectEndpoints("neg", -1, breaker, cursor)) === "[]");
}

console.log(`\nBalance: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
