/**
 * Provider load balancing — round-robin across a provider's endpoints
 * (config.endpointsOf), aware of the per-endpoint circuit breaker
 * (security/resilience.ts), with a hook for model-awareness that a later step
 * wires up (active /v1/models polling — NOT built here).
 *
 * Pure: the only state this module mutates is (a) the breaker, via its own
 * documented admit() side effect (the timed open -> half-open promotion), and
 * (b) the caller-owned `cursorState` object passed in on every call. No
 * timers, no module-level globals — a caller can run several independent
 * balancers (e.g. in tests) by simply passing separate CursorState objects.
 */

import type { CircuitBreaker, Transition } from "../security/resilience.js";

/**
 * Per-provider round-robin position. The caller owns one instance for the
 * process lifetime (e.g. a single module-level `{}` in server.ts) and passes
 * it into every selectEndpoints() call; this module only ever reads/writes
 * the `[provider]` key it was called with. Shape: `{ [provider]: number }`,
 * where the number is the next endpoint index (0..endpointCount-1) to start
 * from — NOT a request count or timestamp.
 */
export type CursorState = Record<string, number>;

export type SelectEndpointsOpts = {
  /**
   * Model-aware hook (wired by a later step): restrict candidates to the
   * endpoints known to serve the requested model. Applied AFTER breaker
   * admission. If it would leave zero candidates, ALL admitted indices are
   * used instead — an endpoint of unconfirmed model support is still
   * preferable to failing the request outright.
   */
  serves?: (endpoint: number) => boolean;
  /**
   * Called synchronously for every circuit transition observed while admitting
   * candidates (most notably an open endpoint promoted to half-open on
   * cooldown expiry), so the caller can meter/audit it. Without this hook that
   * transition would otherwise go unreported: the caller's own follow-up
   * `breaker.admit(provider, idx)` immediately before forwarding (recommended,
   * to catch state changes from concurrent requests) will typically observe
   * the endpoint already in its post-transition state and report `transition:
   * null` for it.
   */
  onTransition?: (transition: Transition) => void;
};

/**
 * Choose an ordered list of endpoint indices (0-based, < endpointCount) to try
 * for `provider`. Breaker-aware: an endpoint whose circuit is open is dropped
 * (via `breaker.admit`, which also performs the timed open -> half-open
 * promotion, so recovery probes still happen on schedule even though this
 * function itself never blocks or sleeps). If every endpoint is currently
 * open, returns `[]` — the caller's existing "circuit open, fail fast to the
 * next authorized model" handling applies unchanged.
 *
 * The survivors are rotated to round-robin traffic: consecutive calls for the
 * same provider start at a different endpoint, tracked via
 * `cursorState[provider]`. A provider with exactly one endpoint (today's only
 * shape, and the default when a config still uses a plain string `baseUrl`)
 * always gets back `[0]` (once admitted) — behaviorally identical to today.
 */
export function selectEndpoints(
  provider: string,
  endpointCount: number,
  breaker: Pick<CircuitBreaker, "admit">,
  cursorState: CursorState,
  opts?: SelectEndpointsOpts,
): number[] {
  if (!Number.isInteger(endpointCount) || endpointCount <= 0) return [];

  // 1. Breaker-aware admission: drop any endpoint whose circuit is open.
  const admitted: number[] = [];
  for (let i = 0; i < endpointCount; i++) {
    const gate = breaker.admit(provider, i);
    if (gate.transition) opts?.onTransition?.(gate.transition);
    if (gate.ok) admitted.push(i);
  }
  if (admitted.length === 0) return [];

  // 2. Model-aware narrowing (hook for a later step) — never let it starve
  // the request down to zero candidates.
  let candidates = admitted;
  if (opts?.serves) {
    const served = admitted.filter((idx) => opts.serves!(idx));
    if (served.length > 0) candidates = served;
  }

  // 3. Round-robin: rotate `candidates` to start at the shared cursor
  // position, then advance the cursor for next time. The cursor tracks a slot
  // in the full [0, endpointCount) space (not just the admitted subset) so a
  // transiently-open endpoint doesn't permanently skew the rotation once it
  // rejoins the healthy set.
  const cursor = (((cursorState[provider] ?? 0) % endpointCount) + endpointCount) % endpointCount;
  const splitAt = candidates.findIndex((idx) => idx >= cursor);
  const ordered = splitAt <= 0 ? candidates : [...candidates.slice(splitAt), ...candidates.slice(0, splitAt)];
  cursorState[provider] = (cursor + 1) % endpointCount;
  return ordered;
}
