/**
 * Health-aware model resolution — collapse an auto-routed model onto what's actually LIVE.
 *
 * SecRouter classifies a request to a tier → model, but that model may not be loaded on any
 * backend: a single-GPU SecLLM commonly serves ONE model at a time, so the tier's configured
 * primary (say a cloud model) can be entirely absent from the local deployment. Without this,
 * the request forwards to a model nothing serves and 502s.
 *
 * Given the set of models SecRouter currently believes are live (learned from the active
 * `/v1/models` health probe — see server.ts liveModels), steer a non-pinned request to a live
 * model instead. The headline case: when exactly ONE model is live, every non-pinned request
 * lands on it. GATED requests — an explicit model id, or a policy pin/downgrade — are resolved
 * by the caller before this runs and must never be passed in here.
 *
 * PURE: no I/O, no globals. The caller owns liveness discovery, config lookup, and audit.
 */

/**
 * Decide whether to steer `routedModel` onto a live model.
 *
 * @param routedModel   the model the classifier / mode-override chose (fully-qualified `provider/model`)
 * @param fallbackChain the tier's `[primary, ...fallback]`, in preference order — the configured
 *                      intent to honor first when more than one model is live
 * @param liveModels    fully-qualified ids currently believed live; EMPTY means "unknown" (no
 *                      active health data yet), NOT "nothing is live"
 * @returns the model to use plus a short reason when it changed, or `null` to leave routing as-is
 *          (routed model already live, liveness unknown, or no safe live candidate to prefer).
 */
export function healthAwareModel(
  routedModel: string,
  fallbackChain: readonly string[],
  liveModels: ReadonlySet<string>,
): { model: string; reason: string } | null {
  // No liveness signal ⇒ behave exactly as before (route as classified, let the forward loop's
  // breaker discover a dead backend). This keeps the feature purely additive.
  if (liveModels.size === 0) return null;

  // Already live ⇒ nothing to do (covers "one model live and the classifier picked it").
  if (liveModels.has(routedModel)) return null;

  // Prefer a live model from THIS tier's own chain first, honoring the operator's configured
  // order (primary before fallbacks) rather than jumping to an unrelated tier's model.
  for (const candidate of fallbackChain) {
    if (candidate !== routedModel && liveModels.has(candidate)) {
      return { model: candidate, reason: `health: ${routedModel} not live → tier fallback ${candidate}` };
    }
  }

  // Nothing in this tier's chain is live, but if exactly one model is live ANYWHERE, every
  // non-gated request collapses onto it — the single-live-model deployment the user asked for.
  if (liveModels.size === 1) {
    const only = liveModels.values().next().value as string;
    return { model: only, reason: `health: sole live model → ${only}` };
  }

  // Several models are live but none belong to this tier's chain: don't guess across tiers.
  // Leave the decision alone — the forward loop's model-aware endpoint narrowing still applies.
  return null;
}

/**
 * Is `url` a loopback (local-host) endpoint? Such an endpoint is safe to actively health-check
 * even in an air-gapped deployment — polling it isn't egress — which is how SecRouter learns the
 * local live-model set. An unparseable URL is treated as remote (conservative: never auto-probed).
 */
export function isLoopbackUrl(url: string): boolean {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  const h = host.replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  return h === "localhost" || h === "::1" || h === "0.0.0.0" || h.startsWith("127.") || h.endsWith(".localhost");
}

/**
 * In AUTO mode (no explicit `security.resilience.healthIntervalSec`), should a provider's
 * endpoints be actively health-probed? True for:
 *   - a **pool** (>1 endpoint) — multi-endpoint load balancing needs per-replica liveness;
 *   - any **loopback** endpoint — a local backend; polling localhost isn't egress; or
 *   - the self-hosted **SecLLM turnkey-intake pool** (`name === "secllm"` && `secllmIntakeActive`,
 *     i.e. `SECROUTER_SECLLM_ENDPOINTS` is set) — the deployment's own inference tier, inside the
 *     accreditation boundary and already egress-authorized, and the pool health-aware routing needs
 *     liveness for. SecDeploy addresses it by FQDN even single-host, so the loopback signal alone
 *     wouldn't catch a single-instance pool.
 * A single **remote third-party** endpoint stays passive (returns false) unless the operator opts in
 * explicitly — preserving the air-gap "no background egress unless asked" default. PURE.
 */
export function autoProbeProvider(
  name: string,
  endpoints: readonly string[],
  secllmIntakeActive: boolean,
): boolean {
  if (name === "secllm" && secllmIntakeActive) return true;
  return endpoints.length > 1 || endpoints.some(isLoopbackUrl);
}

/**
 * Pure core of server.ts's `liveModels()`: fold the per-endpoint served-model sets (keyed
 * `provider#idx`, as populated by the /v1/models health probe) into the set of fully-qualified
 * `provider/model` ids that are live — excluding any endpoint whose circuit is currently open.
 * A bare model id may itself contain "/" (e.g. `llama-3.3-70b`), so the provider is taken as the
 * key prefix before the LAST "#", matching how the forward loop splits `provider/model`.
 */
export function computeLiveModels(
  served: ReadonlyMap<string, ReadonlySet<string>>,
  openEndpointKeys: ReadonlySet<string>,
): Set<string> {
  const live = new Set<string>();
  for (const [key, models] of served) {
    if (openEndpointKeys.has(key)) continue;
    const provider = key.slice(0, key.lastIndexOf("#"));
    for (const m of models) live.add(`${provider}/${m}`);
  }
  return live;
}
