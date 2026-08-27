/**
 * Audit retention (AU 3.3.1, `security.audit.retentionDays`) tests.
 * Run: npx tsx test/security/audit-retention.test.ts
 *
 * Covers: auditPruneCandidates/deleteAuditThrough only touch pre-cutoff rows;
 * verifyAuditChain in the classic genesis case AND the post-prune anchor case
 * (both single and repeated prunes); the prune event itself is recorded with
 * the right custody-trail fields; retentionDays<=0/unset never prunes; tamper
 * among surviving rows (including the anchor row) is still caught after a
 * prune; a gap with no attesting event is reported broken; and config
 * validation of security.audit.retentionDays.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { SqliteStore } from "../../src/security/store/sqlite.js";
import { Auditor } from "../../src/security/audit/audit.js";
import { runAuditPrune, retentionEnabled } from "../../src/security/audit/retention.js";
import { validateSecurityConfig, type FreeRouterConfig } from "../../src/config.js";
import type { SecurityConfig } from "../../src/security/types.js";

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

/** Busy-wait a few ms so successive appendAudit calls get distinct, strictly-increasing ts values. */
function tick(ms = 3): void {
  const t = Date.now() + ms;
  while (Date.now() < t) {
    /* spin */
  }
}

// ── 1. auditPruneCandidates / deleteAuditThrough: only pre-cutoff rows move ──
{
  const store = new SqliteStore(":memory:");
  store.init();

  const a = store.appendAudit({ type: "old.a", outcome: "ok" });
  const b = store.appendAudit({ type: "old.b", outcome: "ok" });
  tick();
  const cutoffIso = new Date().toISOString();
  tick();
  const c = store.appendAudit({ type: "new.c", outcome: "ok" });
  const d = store.appendAudit({ type: "new.d", outcome: "ok" });

  const candidates = store.auditPruneCandidates(cutoffIso);
  ok("candidates found", candidates !== null);
  ok("candidate count == 2 (a, b)", candidates?.count === 2);
  ok("candidate throughId == b.id", candidates?.throughId === b.id);
  ok("candidate anchorHash == b.hash", candidates?.anchorHash === b.hash);

  const deleted = store.deleteAuditThrough(candidates!.throughId);
  ok("deleteAuditThrough removed exactly 2 rows", deleted === 2);
  ok("countAudit == 2 after delete", store.countAudit({}) === 2);
  const remaining = store.queryAudit({ sort: "ts", dir: "asc" });
  ok(
    "only c and d survive, in order",
    remaining.length === 2 && remaining[0].id === c.id && remaining[1].id === d.id,
  );
  ok("nothing older than cutoff remains", !remaining.some((r) => r.type.startsWith("old.")));

  // No candidates once nothing is older than a cutoff in the past.
  const none = store.auditPruneCandidates(new Date(0).toISOString());
  ok("no candidates before the epoch", none === null);

  store.close();
}

// ── 2. verifyAuditChain: classic genesis case (nothing ever pruned) ──
{
  const store = new SqliteStore(":memory:");
  store.init();
  store.appendAudit({ type: "auth.success", principalId: "austin", outcome: "allow" });
  store.appendAudit({ type: "usage", principalId: "austin", outcome: "ok" });
  store.appendAudit({ type: "admin.action", principalId: "austin", outcome: "ok" });
  const r = store.verifyAuditChain();
  ok("fresh chain (no prune) verifies ok", r.ok === true && r.checked === 3);
  store.close();
}

// ── 3. Full runAuditPrune pipeline + post-prune anchor verification ──
{
  const store = new SqliteStore(":memory:");
  store.init();
  const auditor = new Auditor(store, { failClosed: true });

  store.appendAudit({ type: "old.1", outcome: "ok" });
  store.appendAudit({ type: "old.2", outcome: "ok" });
  store.appendAudit({ type: "old.3", outcome: "ok" });
  tick();
  const boundaryIso = new Date().toISOString();
  tick();
  store.appendAudit({ type: "new.1", outcome: "ok" });
  store.appendAudit({ type: "new.2", outcome: "ok" });

  // now := boundary + 1 day; retentionDays := 1  ⇒  cutoff := now - 1d == boundaryIso exactly.
  const retentionDays = 1;
  const now = new Date(new Date(boundaryIso).getTime() + retentionDays * 24 * 60 * 60 * 1000);

  const result = runAuditPrune(store, auditor, retentionDays, now);
  ok("runAuditPrune reports pruned:true", result.pruned === true);
  ok("runAuditPrune deleted 3 rows", result.pruned === true && result.deleted === 3);

  ok("audit_log no longer starts at id 1 (a prune happened)", store.queryAudit({ sort: "ts", dir: "asc" })[0].id !== 1);

  const chain = store.verifyAuditChain();
  ok("chain verifies after a single prune (anchor trusted)", chain.ok === true, JSON.stringify(chain));
  // Survivors: new.1, new.2, and the audit.pruned event itself.
  ok("checked == 3 surviving rows", chain.checked === 3, String(chain.checked));

  // ── 4. The prune event itself is recorded with the right custody-trail fields ──
  const prunedEvents = store.queryAudit({ type: "audit.pruned" });
  ok("exactly one audit.pruned event recorded", prunedEvents.length === 1);
  const pe = prunedEvents[0];
  ok(
    "audit.pruned detail matches the deleted range",
    pe.detail.deleted === 3 &&
      result.pruned === true &&
      pe.detail.throughId === result.throughId &&
      pe.detail.anchorHash === result.anchorHash,
    JSON.stringify(pe.detail),
  );
  ok("audit.pruned outcome is ok (not itself a denial)", pe.outcome === "ok");

  // ── Repeated prune: age out everything including the first prune event ──
  tick();
  const boundary2 = new Date().toISOString();
  tick();
  store.appendAudit({ type: "new.3", outcome: "ok" });
  const now2 = new Date(new Date(boundary2).getTime() + 1 * 24 * 60 * 60 * 1000);
  const result2 = runAuditPrune(store, auditor, 1, now2);
  ok("second prune also succeeds", result2.pruned === true);
  const chain2 = store.verifyAuditChain();
  ok("chain still verifies after a second, cascading prune", chain2.ok === true, JSON.stringify(chain2));
  ok(
    "second prune's own event is now the anchor for a fresh, non-genesis start",
    store.queryAudit({ sort: "ts", dir: "asc" })[0].id !== 1,
  );

  store.close();
}

// ── 5. retentionDays <= 0 / unset never prunes ──
{
  const store = new SqliteStore(":memory:");
  store.init();
  const auditor = new Auditor(store, { failClosed: true });
  store.appendAudit({ type: "old.1", outcome: "ok" });
  store.appendAudit({ type: "old.2", outcome: "ok" });

  const farFuture = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

  ok("retentionEnabled(0) is false", retentionEnabled(0) === false);
  ok("retentionEnabled(undefined) is false", retentionEnabled(undefined) === false);
  ok("retentionEnabled(-1) is false", retentionEnabled(-1) === false);
  ok("retentionEnabled(30) is true", retentionEnabled(30) === true);

  const r0 = runAuditPrune(store, auditor, 0, farFuture);
  ok("runAuditPrune(retentionDays=0) is a no-op", r0.pruned === false && r0.reason === "disabled");
  const rUndef = runAuditPrune(store, auditor, undefined, farFuture);
  ok("runAuditPrune(retentionDays=undefined) is a no-op", rUndef.pruned === false && rUndef.reason === "disabled");

  ok("no rows deleted, no audit.pruned event, even a year later", store.countAudit({}) === 2);
  ok("no audit.pruned event recorded", store.queryAudit({ type: "audit.pruned" }).length === 0);
  store.close();
}

// ── 6. Untrusted gap: manual/naive deletion (bypassing the prune mechanism) is caught ──
{
  const store = new SqliteStore(":memory:");
  store.init();
  store.appendAudit({ type: "old.1", outcome: "ok" });
  const b = store.appendAudit({ type: "old.2", outcome: "ok" });
  store.appendAudit({ type: "new.1", outcome: "ok" });

  // Delete straight through the store method WITHOUT emitting an audit.pruned
  // event first — simulates an operator (or attacker) poking at the DB
  // directly rather than going through the custody-trail-preserving path.
  store.deleteAuditThrough(b.id);

  const chain = store.verifyAuditChain();
  ok("naive deletion with no attesting event is reported broken, not silently trusted", chain.ok === false);
  store.close();
}

// ── 7. Tamper among surviving rows (including the anchor/prune-event row) is still caught ──
{
  const dir = mkdtempSync(join(tmpdir(), "secrouter-audit-retention-"));
  const dbPath = join(dir, "store.db");
  try {
    const store = new SqliteStore(dbPath);
    store.init();
    const auditor = new Auditor(store, { failClosed: true });

    store.appendAudit({ type: "old.1", outcome: "ok" });
    store.appendAudit({ type: "old.2", outcome: "ok" });
    tick();
    const boundaryIso = new Date().toISOString();
    tick();
    store.appendAudit({ type: "new.1", outcome: "ok" });
    const survivor = store.appendAudit({ type: "new.2", outcome: "ok", detail: { note: "untouched" } });

    const now = new Date(new Date(boundaryIso).getTime() + 24 * 60 * 60 * 1000);
    const result = runAuditPrune(store, auditor, 1, now);
    ok("setup: prune succeeded", result.pruned === true);
    ok("setup: chain verifies pre-tamper", store.verifyAuditChain().ok === true);

    // Reach past the Store abstraction (as an external tamperer would) and
    // rewrite a surviving, non-anchor row's outcome without recomputing the
    // hash chain from that point forward.
    const raw = new DatabaseSync(dbPath);
    raw.prepare("UPDATE audit_log SET outcome = 'TAMPERED' WHERE id = ?").run(survivor.id);
    raw.close();

    const tampered = store.verifyAuditChain();
    ok(
      "tamper on a surviving row is detected after a prune",
      tampered.ok === false && tampered.brokenAtId === survivor.id,
      JSON.stringify(tampered),
    );

    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ── 8. Config validation: security.audit.retentionDays ──
{
  const baseSec: SecurityConfig = {
    enabled: true,
    oidc: { issuer: "https://idp", audience: "secrouter" },
    egress: { allowlist: [{ provider: "p", allowedHost: "h", authorizedClassifications: ["CUI"] }] },
  };
  const retentionErrs = (retentionDays: unknown) =>
    validateSecurityConfig({
      security: { ...baseSec, audit: { retentionDays: retentionDays as number } },
    } as unknown as FreeRouterConfig).filter((e) => /retentionDays/.test(e));

  ok("retentionDays absent → no error", validateSecurityConfig({ security: baseSec } as unknown as FreeRouterConfig).filter((e) => /retentionDays/.test(e)).length === 0);
  ok("retentionDays 0 (default, keep forever) → no error", retentionErrs(0).length === 0);
  ok("retentionDays 30 → no error", retentionErrs(30).length === 0);
  ok("retentionDays negative → error", retentionErrs(-1).length > 0);
  ok("retentionDays non-integer → error", retentionErrs(1.5).length > 0);
  ok("retentionDays non-numeric → error", retentionErrs("30" as unknown as number).length > 0);
}

console.log(`\nAudit retention: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
