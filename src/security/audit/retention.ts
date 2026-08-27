/**
 * SecRouter Audit Retention — daily prune job (AU 3.3.1).
 *
 * `security.audit.retentionDays` (default 0/unset = keep forever, today's
 * unchanged behavior). When set > 0, a daily background job deletes audit_log
 * rows older than the retention window.
 *
 * Deleting old rows naively would break verifyAuditChain: the oldest
 * surviving row's prev_hash would point at a hash that no longer exists. So
 * pruning ALWAYS records a self-attesting `audit.pruned` event — through the
 * normal Auditor, so fail-closed/syslog-forward semantics apply — BEFORE it
 * deletes anything. If recording that event fails, the deletion is skipped
 * this cycle rather than silently losing the custody trail; the next cycle
 * retries. See store/sqlite.ts (`auditPruneCandidates`, `deleteAuditThrough`,
 * `verifyAuditChain`) for how the resulting anchor is trusted on verify.
 *
 * Deliberately free of singleton lookups (getStore()/getAuditor()/config) so
 * it's directly unit-testable; server.ts's timer wrapper supplies those.
 */

import { logger } from "../../logger.js";
import type { Store } from "../types.js";
import type { Auditor } from "./audit.js";
import { audit } from "./audit.js";

/** retentionDays <= 0 (or unset) means "keep forever" — the default. */
export function retentionEnabled(retentionDays: number | undefined): retentionDays is number {
  return typeof retentionDays === "number" && retentionDays > 0;
}

export type AuditPruneResult =
  | { pruned: false; reason: "disabled" | "nothing-to-prune" }
  | { pruned: false; reason: "audit-emit-failed" | "delete-failed"; error: string }
  | { pruned: true; deleted: number; throughId: number; anchorHash: string };

/**
 * Run one prune cycle against `store`/`auditor`. Pure function of its
 * arguments (including `now`, for deterministic tests) — see module doc.
 */
export function runAuditPrune(
  store: Store,
  auditor: Auditor,
  retentionDays: number | undefined,
  now: Date = new Date(),
): AuditPruneResult {
  if (!retentionEnabled(retentionDays)) return { pruned: false, reason: "disabled" };

  const cutoffIso = new Date(now.getTime() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
  const candidates = store.auditPruneCandidates(cutoffIso);
  if (!candidates) return { pruned: false, reason: "nothing-to-prune" };

  try {
    // Fail-closed by construction: if this throws (AuditFailureError under
    // failClosed), we return before deleting anything — no row is ever
    // removed without a durable, recorded custody-trail event.
    auditor.emit(audit.pruned(candidates.count, candidates.throughId, candidates.anchorHash));
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    logger.error(`audit prune: refusing to delete — custody-trail event failed: ${error}`);
    return { pruned: false, reason: "audit-emit-failed", error };
  }

  try {
    const deleted = store.deleteAuditThrough(candidates.throughId);
    logger.info(
      `🗑 Audit retention: pruned ${deleted} row(s) older than ${retentionDays}d (through id ${candidates.throughId})`,
    );
    return { pruned: true, deleted, throughId: candidates.throughId, anchorHash: candidates.anchorHash };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    logger.error(`audit prune: delete failed after the prune event was recorded: ${error}`);
    return { pruned: false, reason: "delete-failed", error };
  }
}
