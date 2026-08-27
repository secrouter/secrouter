/**
 * SecRouter Store — node:sqlite implementation.
 *
 * Backs the usage ledger, quota aggregation, the tamper-evident audit log,
 * and the JWT replay (jti) cache. Synchronous API (DatabaseSync), WAL mode.
 *
 * The Store interface (security/types.ts) is the seam: swap this for a
 * Postgres implementation for multi-instance HA without touching callers.
 */

import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import type {
  Store,
  UsageRecord,
  UsageAggregate,
  UsageBreakdownRow,
  AuditInput,
  StoredAuditEvent,
  AuditFilter,
  ConfigOverride,
  OverrideScope,
} from "../types.js";

const SCHEMA_VERSION = 1;
const SEP = String.fromCharCode(0x1f); // ASCII Unit Separator — unambiguous field boundary
const GENESIS = "GENESIS";

/** Resolve ~ in a path. */
function resolvePath(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

export class SqliteStore implements Store {
  private db: DatabaseSync;
  private readonly path: string;

  constructor(path?: string) {
    this.path =
      path && path !== ":memory:"
        ? resolvePath(path)
        : path ?? join(homedir(), ".config", "secrouter", "secrouter.db");
    if (this.path !== ":memory:") {
      mkdirSync(dirname(this.path), { recursive: true });
    }
    this.db = new DatabaseSync(this.path);
  }

  init(): void {
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA foreign_keys = ON;");
    this.db.exec("PRAGMA busy_timeout = 5000;");
    this.migrate();
  }

  close(): void {
    this.db.close();
  }

  private migrate(): void {
    const row = this.db.prepare("PRAGMA user_version").get() as { user_version: number };
    if (row.user_version >= SCHEMA_VERSION) return;

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS usage_ledger (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        ts            TEXT NOT NULL,
        request_id    TEXT NOT NULL,
        principal_id  TEXT NOT NULL,
        groups        TEXT NOT NULL DEFAULT '[]',
        provider      TEXT NOT NULL,
        model         TEXT NOT NULL,
        tier          TEXT NOT NULL,
        input_tokens  INTEGER NOT NULL DEFAULT 0,
        output_tokens INTEGER NOT NULL DEFAULT 0,
        cache_read_tokens INTEGER NOT NULL DEFAULT 0,
        cost_usd      REAL NOT NULL DEFAULT 0,
        outcome       TEXT NOT NULL DEFAULT 'ok'
      );
      CREATE INDEX IF NOT EXISTS idx_usage_principal_ts ON usage_ledger(principal_id, ts);
      CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage_ledger(ts);

      CREATE TABLE IF NOT EXISTS audit_log (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        ts            TEXT NOT NULL,
        type          TEXT NOT NULL,
        request_id    TEXT,
        principal_id  TEXT,
        source_ip     TEXT,
        model         TEXT,
        tier          TEXT,
        outcome       TEXT,
        detail        TEXT NOT NULL DEFAULT '{}',
        prev_hash     TEXT NOT NULL,
        hash          TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_principal ON audit_log(principal_id);
      CREATE INDEX IF NOT EXISTS idx_audit_type_ts ON audit_log(type, ts);

      CREATE TABLE IF NOT EXISTS jti_seen (
        jti     TEXT PRIMARY KEY,
        exp     INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_jti_exp ON jti_seen(exp);

      CREATE TABLE IF NOT EXISTS config_overrides (
        scope      TEXT NOT NULL,
        name       TEXT NOT NULL,
        value      TEXT NOT NULL,
        updated_by TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (scope, name)
      );
    `);
    this.db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
  }

  /** Run fn inside an IMMEDIATE transaction (cross-process safe under WAL). */
  private tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const out = fn();
      this.db.exec("COMMIT");
      return out;
    } catch (err) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        /* ignore rollback failure */
      }
      throw err;
    }
  }

  // ─── Usage ledger ───

  recordUsage(r: UsageRecord): void {
    this.db
      .prepare(
        `INSERT INTO usage_ledger
           (ts, request_id, principal_id, groups, provider, model, tier,
            input_tokens, output_tokens, cache_read_tokens, cost_usd, outcome)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      )
      .run(
        r.ts,
        r.requestId,
        r.principalId,
        r.groups,
        r.provider,
        r.model,
        r.tier,
        r.inputTokens,
        r.outputTokens,
        r.cacheReadTokens,
        r.costUsd,
        r.outcome,
      );
  }

  aggregateUsage(principalId: string, sinceIso: string): UsageAggregate {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS requestCount,
                COALESCE(SUM(input_tokens),0)  AS inputTokens,
                COALESCE(SUM(output_tokens),0) AS outputTokens,
                COALESCE(SUM(cost_usd),0)      AS costUsd
           FROM usage_ledger
          WHERE principal_id = ? AND ts >= ?`,
      )
      .get(principalId, sinceIso) as {
      requestCount: number;
      inputTokens: number;
      outputTokens: number;
      costUsd: number;
    };
    return {
      requestCount: row.requestCount,
      inputTokens: row.inputTokens,
      outputTokens: row.outputTokens,
      totalTokens: row.inputTokens + row.outputTokens,
      costUsd: row.costUsd,
    };
  }

  usageBreakdown(opts: {
    principalId?: string;
    sinceIso: string;
    groupBy: "model" | "principal" | "day";
  }): UsageBreakdownRow[] {
    const keyExpr =
      opts.groupBy === "model"
        ? "model"
        : opts.groupBy === "principal"
          ? "principal_id"
          : "substr(ts,1,10)";
    const where = opts.principalId ? "WHERE principal_id = ? AND ts >= ?" : "WHERE ts >= ?";
    const params = opts.principalId ? [opts.principalId, opts.sinceIso] : [opts.sinceIso];
    const rows = this.db
      .prepare(
        `SELECT ${keyExpr} AS key,
                COUNT(*) AS requestCount,
                COALESCE(SUM(input_tokens),0)  AS inputTokens,
                COALESCE(SUM(output_tokens),0) AS outputTokens,
                COALESCE(SUM(cost_usd),0)      AS costUsd
           FROM usage_ledger
           ${where}
          GROUP BY key
          ORDER BY costUsd DESC`,
      )
      .all(...params) as UsageBreakdownRow[];
    return rows;
  }

  // ─── Audit log (append-only, hash-chained) ───

  appendAudit(e: AuditInput): StoredAuditEvent {
    const ts = new Date().toISOString();
    const detailStr = JSON.stringify(e.detail ?? {});
    return this.tx(() => {
      const prevHash = this.lastAuditHash() ?? GENESIS;
      const hash = SqliteStore.chainHash(prevHash, ts, e, detailStr);
      const info = this.db
        .prepare(
          `INSERT INTO audit_log
             (ts, type, request_id, principal_id, source_ip, model, tier, outcome, detail, prev_hash, hash)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        )
        .run(
          ts,
          e.type,
          e.requestId ?? null,
          e.principalId ?? null,
          e.sourceIp ?? null,
          e.model ?? null,
          e.tier ?? null,
          e.outcome ?? null,
          detailStr,
          prevHash,
          hash,
        );
      return {
        ...e,
        id: Number(info.lastInsertRowid),
        ts,
        prevHash,
        hash,
      };
    });
  }

  /** Deterministic chain hash over the row's stored fields. */
  private static chainHash(prevHash: string, ts: string, e: AuditInput, detailStr: string): string {
    const payload = [
      prevHash,
      ts,
      e.type,
      e.requestId ?? "",
      e.principalId ?? "",
      e.sourceIp ?? "",
      e.model ?? "",
      e.tier ?? "",
      e.outcome ?? "",
      detailStr,
    ].join(SEP);
    return createHash("sha256").update(payload).digest("hex");
  }

  lastAuditHash(): string | null {
    const row = this.db.prepare("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").get() as
      | { hash: string }
      | undefined;
    return row?.hash ?? null;
  }

  verifyAuditChain(): { ok: boolean; brokenAtId?: number; checked: number } {
    const rows = this.db
      .prepare(
        `SELECT id, ts, type, request_id, principal_id, source_ip, model, tier, outcome, detail, prev_hash, hash
           FROM audit_log ORDER BY id ASC`,
      )
      .all() as Array<{
      id: number;
      ts: string;
      type: string;
      request_id: string | null;
      principal_id: string | null;
      source_ip: string | null;
      model: string | null;
      tier: string | null;
      outcome: string | null;
      detail: string;
      prev_hash: string;
      hash: string;
    }>;

    if (rows.length === 0) return { ok: true, checked: 0 };

    const first = rows[0];
    let prev: string;
    if (first.id === 1) {
      // Nothing was ever pruned — the classic genesis check.
      prev = GENESIS;
    } else {
      // Rows before `first` are gone (retention prune — see auditPruneCandidates /
      // deleteAuditThrough). We trust `first.prev_hash` as the new chain anchor ONLY
      // if a surviving `audit.pruned` event self-attests it: it must name the exact
      // row id that used to precede `first` (throughId) and record that row's hash
      // (anchorHash) — which is exactly `first.prev_hash`. That attesting event is
      // itself just another row in `rows` below, so ITS prevHash/hash are checked for
      // tamper in the same walk as everything else; nothing here is exempt from
      // verification, only the requirement that the very first surviving row must
      // chain back to GENESIS is relaxed, and only when a matching prune event backs
      // it up. No matching event ⇒ an untrusted gap ⇒ reported as broken.
      const anchorEvent = rows.find((r) => {
        if (r.type !== "audit.pruned") return false;
        try {
          const detail = JSON.parse(r.detail) as { throughId?: unknown; anchorHash?: unknown };
          return detail.throughId === first.id - 1 && detail.anchorHash === first.prev_hash;
        } catch {
          return false;
        }
      });
      if (!anchorEvent) return { ok: false, brokenAtId: first.id, checked: 0 };
      prev = first.prev_hash;
    }

    let checked = 0;
    for (const row of rows) {
      if (row.prev_hash !== prev) return { ok: false, brokenAtId: row.id, checked };
      const expected = SqliteStore.chainHash(
        row.prev_hash,
        row.ts,
        {
          type: row.type,
          requestId: row.request_id ?? undefined,
          principalId: row.principal_id ?? undefined,
          sourceIp: row.source_ip ?? undefined,
          model: row.model ?? undefined,
          tier: row.tier ?? undefined,
          outcome: row.outcome ?? undefined,
        },
        row.detail,
      );
      if (expected !== row.hash) return { ok: false, brokenAtId: row.id, checked };
      prev = row.hash;
      checked++;
    }
    return { ok: true, checked };
  }

  // ─── Audit retention (AU 3.3.1) ───
  //
  // Deleting old rows naively would break verifyAuditChain: the oldest surviving
  // row's prev_hash would point at a hash that no longer exists. The fix is a
  // self-attesting custody trail rather than a second anchors table: the caller
  // (see server.ts's prune job) queries auditPruneCandidates, emits an
  // `audit.pruned` event THROUGH THE NORMAL AUDITOR recording {deleted, throughId,
  // anchorHash} — so that event is itself chained and fail-closed like any other —
  // and only THEN calls deleteAuditThrough. verifyAuditChain (above) trusts the
  // resulting gap only when it finds that exact attesting event among the
  // survivors.

  /** Read-only prune lookup: rows with ts < cutoffIso. Null when nothing qualifies. */
  auditPruneCandidates(cutoffIso: string): { count: number; throughId: number; anchorHash: string } | null {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS count, MAX(id) AS throughId
           FROM audit_log WHERE ts < ?`,
      )
      .get(cutoffIso) as { count: number; throughId: number | null };
    if (!row.count || row.throughId == null) return null;
    const anchor = this.db.prepare("SELECT hash FROM audit_log WHERE id = ?").get(row.throughId) as
      | { hash: string }
      | undefined;
    if (!anchor) return null; // shouldn't happen — throughId came from this same table
    return { count: row.count, throughId: row.throughId, anchorHash: anchor.hash };
  }

  /** Delete rows with id <= throughId. Returns the number of rows actually removed. */
  deleteAuditThrough(throughId: number): number {
    const info = this.db.prepare("DELETE FROM audit_log WHERE id <= ?").run(throughId);
    return Number(info.changes);
  }

  /** Shared WHERE builder for queryAudit/countAudit — same filter semantics, one source of truth. */
  private auditWhere(filter: AuditFilter): { where: string; params: string[] } {
    const clauses: string[] = [];
    const params: string[] = [];
    if (filter.principalId) {
      clauses.push("principal_id = ?");
      params.push(filter.principalId);
    }
    if (filter.type) {
      clauses.push("type = ?");
      params.push(filter.type);
    }
    if (filter.outcome) {
      clauses.push("outcome = ?");
      params.push(filter.outcome);
    }
    if (filter.sinceIso) {
      clauses.push("ts >= ?");
      params.push(filter.sinceIso);
    }
    if (filter.search) {
      // Free-text substring across the human-meaningful columns + the JSON detail blob.
      const like = `%${filter.search}%`;
      clauses.push(
        "(principal_id LIKE ? OR model LIKE ? OR type LIKE ? OR request_id LIKE ? OR source_ip LIKE ? OR detail LIKE ?)",
      );
      params.push(like, like, like, like, like, like);
    }
    return { where: clauses.length ? `WHERE ${clauses.join(" AND ")}` : "", params };
  }

  // Sort key → real column. Whitelist: the value is interpolated into SQL, so it must never
  // come straight from the caller. Unknown keys fall back to chronological (id) order.
  private static readonly AUDIT_SORT: Record<string, string> = {
    ts: "ts",
    type: "type",
    principal: "principal_id",
    model: "model",
    tier: "tier",
    outcome: "outcome",
  };

  countAudit(filter: AuditFilter): number {
    const { where, params } = this.auditWhere(filter);
    const row = this.db.prepare(`SELECT COUNT(*) AS n FROM audit_log ${where}`).get(...params) as {
      n: number;
    };
    return row.n;
  }

  queryAudit(filter: AuditFilter): StoredAuditEvent[] {
    const { where, params } = this.auditWhere(filter);
    const sortCol = SqliteStore.AUDIT_SORT[filter.sort ?? "ts"] ?? "ts";
    const dir = filter.dir === "asc" ? "ASC" : "DESC";
    const limit = Math.min(Math.max(filter.limit ?? 100, 1), 1000);
    const offset = Math.max(filter.offset ?? 0, 0);
    // id is the tiebreaker (and the effective sort when sortCol==="ts", since ts is monotonic
    // with insertion) so paging is stable across identical sort-key values.
    const rows = this.db
      .prepare(
        `SELECT id, ts, type, request_id, principal_id, source_ip, model, tier, outcome, detail, prev_hash, hash
           FROM audit_log ${where} ORDER BY ${sortCol} ${dir}, id ${dir} LIMIT ${limit} OFFSET ${offset}`,
      )
      .all(...params) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      id: r.id as number,
      ts: r.ts as string,
      type: r.type as string,
      requestId: (r.request_id as string) ?? undefined,
      principalId: (r.principal_id as string) ?? undefined,
      sourceIp: (r.source_ip as string) ?? undefined,
      model: (r.model as string) ?? undefined,
      tier: (r.tier as string) ?? undefined,
      outcome: (r.outcome as string) ?? undefined,
      detail: JSON.parse((r.detail as string) ?? "{}"),
      prevHash: r.prev_hash as string,
      hash: r.hash as string,
    }));
  }

  // ─── Replay cache (IA 3.5.4) ───

  // ─── Admin config overrides ───

  listOverrides(): ConfigOverride[] {
    const rows = this.db
      .prepare("SELECT scope, name, value, updated_by, updated_at FROM config_overrides ORDER BY scope, name")
      .all() as Array<{ scope: string; name: string; value: string; updated_by: string; updated_at: string }>;
    return rows.map((r) => ({
      scope: r.scope as OverrideScope,
      name: r.name,
      value: JSON.parse(r.value),
      updatedBy: r.updated_by,
      updatedAt: r.updated_at,
    }));
  }

  putOverride(o: ConfigOverride): void {
    this.db
      .prepare(
        `INSERT INTO config_overrides (scope, name, value, updated_by, updated_at)
         VALUES (?,?,?,?,?)
         ON CONFLICT(scope, name) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=excluded.updated_at`,
      )
      .run(o.scope, o.name, JSON.stringify(o.value), o.updatedBy, o.updatedAt);
  }

  deleteOverride(scope: OverrideScope, name: string): void {
    this.db.prepare("DELETE FROM config_overrides WHERE scope=? AND name=?").run(scope, name);
  }

  recordJtiIfNew(jti: string, expEpochSec: number): boolean {
    try {
      this.db.prepare("INSERT INTO jti_seen (jti, exp) VALUES (?, ?)").run(jti, expEpochSec);
      return true;
    } catch {
      // PRIMARY KEY conflict → already seen → replay
      return false;
    }
  }

  purgeExpiredJti(nowEpochSec: number): void {
    this.db.prepare("DELETE FROM jti_seen WHERE exp < ?").run(nowEpochSec);
  }
}
