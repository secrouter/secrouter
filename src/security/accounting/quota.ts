/**
 * Quota / rate enforcement (cost containment).
 *
 * Budgets are evaluated over rolling windows against the usage ledger. A budget
 * with window="minute" + maxRequests is a request rate limit (rpm); + maxTotalTokens
 * is a token rate limit (tpm); window="day"/"month" + maxCostUsd is a spend cap.
 *
 * Pre-flight (this module) blocks the request that would START after a window is
 * already exhausted. The crossing request may slightly exceed; subsequent ones
 * are denied. Controls: AC 3.1.2; supports 800-172 DoS protection.
 */

import type { Budget, BudgetWindow, Store } from "../types.js";

const WINDOW_MS: Record<BudgetWindow, number> = {
  minute: 60_000,
  hour: 3_600_000,
  day: 86_400_000,
  month: 30 * 86_400_000,
};

export type QuotaViolation = {
  window: BudgetWindow;
  limitType: "requests" | "inputTokens" | "outputTokens" | "totalTokens" | "costUsd";
  limit: number;
  current: number;
};

export type QuotaResult = { allowed: boolean; violation?: QuotaViolation };

/**
 * Check all budgets for a principal. nowMs is injectable for testing.
 */
export function checkQuota(
  store: Store,
  principalId: string,
  budgets: Budget[],
  nowMs: number = Date.now(),
): QuotaResult {
  for (const b of budgets) {
    const sinceIso = new Date(nowMs - WINDOW_MS[b.window]).toISOString();
    const agg = store.aggregateUsage(principalId, sinceIso);

    if (b.maxRequests != null && agg.requestCount >= b.maxRequests) {
      return v(b.window, "requests", b.maxRequests, agg.requestCount);
    }
    if (b.maxInputTokens != null && agg.inputTokens >= b.maxInputTokens) {
      return v(b.window, "inputTokens", b.maxInputTokens, agg.inputTokens);
    }
    if (b.maxOutputTokens != null && agg.outputTokens >= b.maxOutputTokens) {
      return v(b.window, "outputTokens", b.maxOutputTokens, agg.outputTokens);
    }
    if (b.maxTotalTokens != null && agg.totalTokens >= b.maxTotalTokens) {
      return v(b.window, "totalTokens", b.maxTotalTokens, agg.totalTokens);
    }
    if (b.maxCostUsd != null && agg.costUsd >= b.maxCostUsd) {
      return v(b.window, "costUsd", b.maxCostUsd, agg.costUsd);
    }
  }
  return { allowed: true };
}

function v(
  window: BudgetWindow,
  limitType: QuotaViolation["limitType"],
  limit: number,
  current: number,
): QuotaResult {
  return { allowed: false, violation: { window, limitType, limit, current } };
}
