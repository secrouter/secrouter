/**
 * Provider circuit breaker — availability hardening (SC 3.13.x).
 *
 * The chat fallback loop already retries the next authorized model on
 * timeout / 5xx / connect failure, but with **no cross-request memory**: every
 * request pays a dead provider's full timeout before failing over, forever. The
 * breaker adds that memory. After `circuitThreshold` consecutive *health*
 * failures a provider trips **open**; while open the fallback selector SKIPS it
 * (fail-fast to the next authorized model). After `cooldownSec` the breaker goes
 * **half-open** and admits one probe request — success **closes** it, failure
 * re-arms the cooldown.
 *
 * This module is pure state: it imports nothing from the rest of the app and
 * takes an injectable clock, so it is deterministic under test. Side effects
 * (metrics, audit) live at the call site, driven by the `Transition` values the
 * record/admit methods return.
 */

export type CircuitState = "closed" | "open" | "half-open";

/** Public, serialisable health of one provider (returned by snapshot()). */
export type ProviderHealth = {
  provider: string;
  state: CircuitState;
  consecutiveFailures: number;
  totalFailures: number;
  totalSuccesses: number;
  lastLatencyMs?: number;
  lastFailure?: string; // ISO-8601
  lastSuccess?: string; // ISO-8601
  openedAt?: string; // ISO-8601, when it last tripped open
};

/** Emitted whenever a provider changes state, so the caller can meter + audit it. */
export type Transition = {
  provider: string;
  from: CircuitState;
  to: CircuitState;
  consecutiveFailures: number;
};

export type ResilienceConfig = {
  /** Consecutive health failures before a provider trips open. */
  circuitThreshold: number;
  /** Seconds a provider stays open before a half-open probe is admitted. */
  cooldownSec: number;
  /** Active health-check interval in seconds; 0 = passive only (default). */
  healthIntervalSec: number;
};

export const DEFAULT_RESILIENCE: ResilienceConfig = {
  circuitThreshold: 5,
  cooldownSec: 30,
  healthIntervalSec: 0,
};

/** Merge a partial config (from security.resilience) onto the conservative defaults. */
export function resolveResilience(partial?: Partial<ResilienceConfig>): ResilienceConfig {
  return {
    circuitThreshold: partial?.circuitThreshold ?? DEFAULT_RESILIENCE.circuitThreshold,
    cooldownSec: partial?.cooldownSec ?? DEFAULT_RESILIENCE.cooldownSec,
    healthIntervalSec: partial?.healthIntervalSec ?? DEFAULT_RESILIENCE.healthIntervalSec,
  };
}

/**
 * Does a thrown error indicate the *provider* is unhealthy (should count toward
 * the breaker), vs. a policy / client issue that says nothing about
 * availability? Timeouts and connect failures count; upstream 5xx counts; egress
 * denials and 4xx client errors do not. Structural (duck-typed by `name` /
 * `status`) so this module stays dependency-free.
 */
export function isHealthFailure(err: unknown): boolean {
  if (!err || typeof err !== "object") return true; // unknown throw → assume connect failure
  const name = (err as { name?: string }).name;
  if (name === "EgressDeniedError") return false; // deny-by-default policy block, not health
  if (name === "TimeoutError") return true; // upstream too slow
  if (name === "UpstreamError") {
    const status = (err as { status?: number }).status;
    return status == null || status >= 500; // 5xx / connect = health; 4xx = client error
  }
  return true; // generic Error (ECONNREFUSED, "fetch failed", "No response body") → health failure
}

type Now = () => number;
type InternalHealth = ProviderHealth & { openedAtMs?: number };

export class CircuitBreaker {
  private readonly providers = new Map<string, InternalHealth>();

  constructor(
    private cfg: ResilienceConfig = DEFAULT_RESILIENCE,
    private readonly now: Now = () => Date.now(),
  ) {}

  /** Swap the tuning (e.g. after a config reload). Existing state is preserved. */
  setConfig(cfg: ResilienceConfig): void {
    this.cfg = cfg;
  }

  config(): ResilienceConfig {
    return this.cfg;
  }

  private get(provider: string): InternalHealth {
    let h = this.providers.get(provider);
    if (!h) {
      h = { provider, state: "closed", consecutiveFailures: 0, totalFailures: 0, totalSuccesses: 0 };
      this.providers.set(provider, h);
    }
    return h;
  }

  /**
   * May this provider be selected for the next attempt? A closed / half-open
   * provider is always admitted. An open provider is skipped until its cooldown
   * elapses, at which point it is promoted to half-open and the single probe is
   * admitted (the returned Transition records that promotion).
   */
  admit(provider: string): { ok: boolean; transition: Transition | null } {
    const h = this.get(provider);
    if (h.state !== "open") return { ok: true, transition: null };
    if (this.now() - (h.openedAtMs ?? 0) >= this.cfg.cooldownSec * 1000) {
      h.state = "half-open";
      return { ok: true, transition: { provider, from: "open", to: "half-open", consecutiveFailures: h.consecutiveFailures } };
    }
    return { ok: false, transition: null };
  }

  /** Record a successful forward. Closes a half-open/open provider; resets the streak. */
  recordSuccess(provider: string, latencyMs?: number): Transition | null {
    const h = this.get(provider);
    const from = h.state;
    h.consecutiveFailures = 0;
    h.totalSuccesses++;
    h.lastSuccess = new Date(this.now()).toISOString();
    if (latencyMs != null) h.lastLatencyMs = latencyMs;
    if (from !== "closed") {
      h.state = "closed";
      h.openedAtMs = undefined;
      h.openedAt = undefined;
      return { provider, from, to: "closed", consecutiveFailures: 0 };
    }
    return null;
  }

  /** Record a health failure. Trips open at the threshold, or re-arms a failed probe. */
  recordFailure(provider: string): Transition | null {
    const h = this.get(provider);
    const from = h.state;
    h.consecutiveFailures++;
    h.totalFailures++;
    h.lastFailure = new Date(this.now()).toISOString();
    // A closed provider trips once it crosses the threshold; a failed half-open
    // probe re-opens immediately (re-arming the cooldown). Both are transitions.
    if (from === "half-open" || (from === "closed" && h.consecutiveFailures >= this.cfg.circuitThreshold)) {
      h.state = "open";
      h.openedAtMs = this.now();
      h.openedAt = new Date(this.now()).toISOString();
      return { provider, from, to: "open", consecutiveFailures: h.consecutiveFailures };
    }
    return null;
  }

  getState(provider: string): CircuitState {
    return this.get(provider).state;
  }

  /** Serialisable per-provider health for GET /admin/api/health. */
  snapshot(): ProviderHealth[] {
    return [...this.providers.values()].map(({ openedAtMs: _omit, ...pub }) => pub);
  }

  /** Test/ops helper — forget all provider state. */
  reset(): void {
    this.providers.clear();
  }
}

/** Numeric encoding for the secrouter_circuit_state gauge. */
export const CIRCUIT_STATE_CODE: Record<CircuitState, number> = {
  closed: 0,
  open: 1,
  "half-open": 2,
};
