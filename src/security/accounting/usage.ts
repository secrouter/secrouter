/**
 * Usage accounting helpers — cost computation and ledger-record construction.
 *
 * Cost is derived from the pricing map in models.ts (USD per 1M tokens), with
 * Anthropic-style prompt-cache adjustments (cache read ≈ 0.1×, cache write ≈
 * 1.25× the input price). Providers that don't report cache tokens simply have
 * zero in those fields.
 */

import type { Principal, UsageRecord, UsageResult } from "../types.js";

type Pricing = Map<string, { inputPrice: number; outputPrice: number }>;

const CACHE_READ_MULT = 0.1;
const CACHE_WRITE_MULT = 1.25;

/** Pricing-map key for a usage result ("provider/model"). */
export function pricingKey(u: UsageResult): string {
  return `${u.provider}/${u.model}`;
}

/** Compute USD cost for a usage result. Returns 0 (and is safe) if unpriced. */
export function computeCost(u: UsageResult, pricing: Pricing): number {
  const p = pricing.get(pricingKey(u));
  if (!p) return 0;
  const inCost =
    (u.inputTokens * p.inputPrice +
      u.cacheReadTokens * p.inputPrice * CACHE_READ_MULT +
      u.cacheWriteTokens * p.inputPrice * CACHE_WRITE_MULT) /
    1_000_000;
  const outCost = (u.outputTokens * p.outputPrice) / 1_000_000;
  return inCost + outCost;
}

/** A zero-usage result (used when an upstream omits usage, or on failure). */
export function zeroUsage(provider: string, model: string): UsageResult {
  return { provider, model, inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };
}

/** Build a ledger record for a completed request. */
export function toUsageRecord(
  principal: Principal,
  requestId: string,
  tier: string,
  usage: UsageResult,
  costUsd: number,
  outcome: string,
): UsageRecord {
  return {
    ts: new Date().toISOString(),
    requestId,
    principalId: principal.id,
    groups: JSON.stringify(principal.groups),
    provider: usage.provider,
    model: usage.model,
    tier,
    inputTokens: usage.inputTokens,
    outputTokens: usage.outputTokens,
    cacheReadTokens: usage.cacheReadTokens,
    costUsd,
    outcome,
  };
}
