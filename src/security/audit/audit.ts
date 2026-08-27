/**
 * SecRouter Audit — structured, tamper-evident accountability log.
 *
 * Controls: AU 3.3.1 (create records), 3.3.2 (trace to user), 3.3.4 (alert on
 * audit failure), 3.3.7 (time-synced UTC timestamps), 3.3.8 (protect audit info
 * via hash chain), plus 800-172 SIEM forwarding.
 *
 * CUI-SAFE: only metadata is recorded (token counts, model ids, decisions,
 * hashes). Prompt/response content is NEVER passed to the auditor.
 */

import { logger } from "../../logger.js";
import type { Store, AuditInput, StoredAuditEvent } from "../types.js";

/** Raised when a fail-closed audit sink cannot persist an event. */
export class AuditFailureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditFailureError";
  }
}

export type AuditOptions = {
  /** Reject the request if the audit write fails (AU 3.3.4). Default true. */
  failClosed?: boolean;
  /** Optional secondary sink (syslog/SIEM); wired in Phase 5. */
  forward?: (e: StoredAuditEvent) => void;
};

export class Auditor {
  constructor(
    private readonly store: Store,
    private readonly opts: AuditOptions = {},
  ) {}

  /**
   * Persist an audit event. On failure: always logs; throws only when
   * failClosed (default), so the caller can refuse the request.
   */
  emit(e: AuditInput): void {
    let stored: StoredAuditEvent;
    try {
      stored = this.store.appendAudit(e);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`⚠ AUDIT WRITE FAILED [${e.type}]: ${msg}`);
      if (this.opts.failClosed !== false) {
        throw new AuditFailureError(`Audit sink unavailable: ${msg}`);
      }
      return;
    }
    if (this.opts.forward) {
      try {
        this.opts.forward(stored);
      } catch (err) {
        // Forwarding is best-effort; the authoritative record is already persisted.
        logger.warn(`Audit forward failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }
}

// ─── Convenience event builders (keep server.ts call sites readable) ───

export const audit = {
  authSuccess: (principalId: string, sourceIp: string, detail?: Record<string, unknown>): AuditInput => ({
    type: "auth.success",
    principalId,
    sourceIp,
    outcome: "allow",
    detail,
  }),
  authFailure: (sourceIp: string, reason: string, detail?: Record<string, unknown>): AuditInput => ({
    type: "auth.failure",
    sourceIp,
    outcome: "deny",
    detail: { reason, ...detail },
  }),
  authzDeny: (
    principalId: string,
    requestId: string,
    model: string,
    reason: string,
  ): AuditInput => ({
    type: "authz.deny",
    principalId,
    requestId,
    model,
    outcome: "deny",
    detail: { reason },
  }),
  authzDowngrade: (
    principalId: string,
    requestId: string,
    fromModel: string,
    toModel: string,
    reason: string,
  ): AuditInput => ({
    type: "authz.downgrade",
    principalId,
    requestId,
    model: toModel,
    outcome: "downgrade",
    detail: { fromModel, toModel, reason },
  }),
  egressDeny: (principalId: string, requestId: string, provider: string, reason: string): AuditInput => ({
    type: "egress.deny",
    principalId,
    requestId,
    outcome: "deny",
    detail: { provider, reason },
  }),
  usage: (
    principalId: string,
    requestId: string,
    model: string,
    tier: string,
    detail: Record<string, unknown>,
  ): AuditInput => ({
    type: "usage",
    principalId,
    requestId,
    model,
    tier,
    outcome: "ok",
    detail,
  }),
  adminAction: (principalId: string, action: string, detail?: Record<string, unknown>): AuditInput => ({
    type: "admin.action",
    principalId,
    outcome: "ok",
    detail: { action, ...detail },
  }),
  quotaExceeded: (
    principalId: string,
    requestId: string,
    detail: Record<string, unknown>,
  ): AuditInput => ({
    type: "quota.exceeded",
    principalId,
    requestId,
    outcome: "deny",
    detail,
  }),
  /**
   * SECROUTER_EGRESS_FILE load (config.ts applyEgressFileIntake) — an
   * explicit, deployer-authored egress-rule file was read and merged into
   * `security.egress.allowlist`. Made audit-evident rather than a silent
   * config-assembly side effect. Emitted on every (re)load where the env var
   * is set and the file loads successfully (even if every rule in it was
   * already present / deduped) — each (re)load is its own auditable event.
   */
  egressFileLoaded: (path: string, addedCount: number, totalCount: number): AuditInput => ({
    type: "egress.file_loaded",
    outcome: "authorized",
    detail: { path, addedCount, totalCount, source: "SECROUTER_EGRESS_FILE" },
  }),
  /** Provider circuit-breaker transition — an auditable availability/ops change (SC/AU). */
  providerCircuit: (
    provider: string,
    to: string,
    from: string,
    consecutiveFailures: number,
    endpoint = 0,
  ): AuditInput => ({
    type: "provider.circuit",
    outcome: to === "closed" ? "recovered" : to === "open" ? "open" : "probe",
    detail: { provider, endpoint, state: to, from, consecutiveFailures },
  }),
  /**
   * A proxied MCP tool call (Phase D). Metadata ONLY — a SHA-256 of the arguments
   * for correlation, byte counts, latency; NEVER the argument or result contents.
   */
  toolCall: (
    principalId: string,
    requestId: string,
    server: string,
    tool: string,
    d: { ok: boolean; latencyMs: number; bytesIn: number; bytesOut: number; argsSha256: string; error?: string },
  ): AuditInput => ({
    type: "tool.call",
    principalId,
    requestId,
    model: `${server}/${tool}`,
    outcome: d.ok ? "ok" : "error",
    detail: {
      server,
      tool,
      latencyMs: d.latencyMs,
      bytesIn: d.bytesIn,
      bytesOut: d.bytesOut,
      argsSha256: d.argsSha256,
      ...(d.error ? { error: d.error } : {}),
    },
  }),
  /**
   * Audit retention prune (AU 3.3.1, `security.audit.retentionDays`). Emitted
   * BEFORE the corresponding rows are deleted, so the chain itself attests the
   * prune: `throughId` is the highest row id being removed, `anchorHash` is
   * that row's own hash — i.e. the prev_hash the next surviving row already
   * carries. verifyAuditChain (store/sqlite.ts) looks for exactly this event
   * to trust a non-GENESIS chain start. Metadata only — no row content.
   */
  pruned: (deleted: number, throughId: number, anchorHash: string): AuditInput => ({
    type: "audit.pruned",
    outcome: "ok",
    detail: { deleted, throughId, anchorHash },
  }),
  /** An MCP tool call refused by policy or the classification gate (Phase D). */
  toolDeny: (
    principalId: string,
    requestId: string,
    server: string,
    tool: string,
    reason: string,
  ): AuditInput => ({
    type: "tool.deny",
    principalId,
    requestId,
    model: `${server}/${tool}`,
    outcome: "deny",
    detail: { server, tool, reason },
  }),
};
