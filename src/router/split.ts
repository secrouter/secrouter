/**
 * Split (A/B) routing — weighted-random model assignment per tier, for
 * benchmarking a candidate model against the configured primary (or several
 * candidates against each other) on real traffic.
 *
 * Pure and deterministic given an injected RNG — no I/O, no server coupling —
 * so the weighted-assignment math and config validation are unit-testable
 * without spinning up a server. server.ts wires this in BEFORE the
 * health-aware steer and BEFORE policy authorize() (see handleChatCompletions):
 * both of those still run afterward and may override the assignment — policy
 * always wins, and a health-steer-away is tracked separately (split_steered_total)
 * rather than silently miscounted as a clean sample.
 */

import type { ExperimentsConfig, SplitConfig, SplitVariant, Tier } from "./types.js";

export type SplitAssignment = {
  /** The experiment name (SplitConfig.name), echoed in headers/audit/reasoning. */
  name: string;
  /** The chosen model ("provider/model"). */
  model: string;
};

const MODEL_ID_RE = /^[^/\s]+\/[^/\s]+$/;

/**
 * Validate a split config. Returns human-readable errors; empty = valid.
 * Rules: enabled requires a non-empty `name` and at least one tier entry;
 * each tier entry needs >= 2 variants; every weight must be > 0; every model
 * id must be "provider/model" form.
 */
export function validateSplitConfig(cfg: SplitConfig | undefined): string[] {
  const errors: string[] = [];
  if (!cfg || !cfg.enabled) return errors;

  if (!cfg.name || !cfg.name.trim()) {
    errors.push("experiments.split.name is required when experiments.split.enabled is true");
  }
  const tierEntries = Object.entries(cfg.tiers ?? {});
  if (tierEntries.length === 0) {
    errors.push("experiments.split.tiers must have at least one tier entry when enabled");
  }
  for (const [tier, tierCfg] of tierEntries) {
    if (!tierCfg) continue;
    const variants = tierCfg.variants ?? [];
    if (variants.length < 2) {
      errors.push(`experiments.split.tiers.${tier} must have at least 2 variants (got ${variants.length})`);
    }
    for (const [i, v] of variants.entries()) {
      if (!v.model || !MODEL_ID_RE.test(v.model)) {
        errors.push(`experiments.split.tiers.${tier}.variants[${i}].model must be "provider/model" form (got ${JSON.stringify(v.model)})`);
      }
      if (!(v.weight > 0)) {
        errors.push(`experiments.split.tiers.${tier}.variants[${i}].weight must be > 0 (got ${v.weight})`);
      }
    }
  }
  return errors;
}

/**
 * Weighted-random pick among variants. Weights need not sum to 1 or 100 —
 * each variant's probability is weight / sum(weights). `rng` must return a
 * value in [0, 1); default Math.random, but ALWAYS inject a fake for tests —
 * assignment distribution must be deterministically verifiable.
 */
export function pickWeightedVariant(variants: SplitVariant[], rng: () => number = Math.random): SplitVariant {
  if (variants.length === 0) throw new Error("pickWeightedVariant: no variants");
  const total = variants.reduce((s, v) => s + v.weight, 0);
  if (!(total > 0)) throw new Error("pickWeightedVariant: total weight must be > 0");
  let r = rng() * total;
  for (const v of variants) {
    r -= v.weight;
    if (r < 0) return v;
  }
  return variants[variants.length - 1]; // floating-point fallback
}

/**
 * Apply split routing for the given tier, if applicable. Returns null (no-op)
 * when: no experiments config, split disabled, tier is "EXPLICIT" (an explicit
 * model request is a gate — never overridden here, same rule the health-aware
 * steer follows), or this tier has no split entry.
 */
export function applySplit(
  experiments: ExperimentsConfig | undefined,
  tier: string,
  rng: () => number = Math.random,
): SplitAssignment | null {
  const split = experiments?.split;
  if (!split || !split.enabled) return null;
  if (tier === "EXPLICIT") return null;
  const tierCfg = split.tiers[tier as Tier];
  if (!tierCfg || !tierCfg.variants || tierCfg.variants.length < 2) return null;
  const chosen = pickWeightedVariant(tierCfg.variants, rng);
  return { name: split.name, model: chosen.model };
}
