/**
 * Access-log store query tests. Run: npx tsx test/security/audit-query.test.ts
 * Covers queryAudit filtering (type/outcome/principal/search/since), whitelisted
 * column sort + direction, limit/offset paging, and countAudit (filter-consistent total).
 */

import { SqliteStore } from "../../src/security/store/sqlite.js";

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

{
  const store = new SqliteStore(":memory:");
  store.init();

  // Seed a varied audit trail. appendAudit stamps ts = now for each, in insertion order.
  store.appendAudit({ type: "auth.success", principalId: "austin", outcome: "allow", detail: { traceId: "t-a1" } });
  store.appendAudit({ type: "usage", principalId: "austin", model: "claude-opus", tier: "COMPLEX", outcome: "ok", detail: { inputTokens: 10 } });
  store.appendAudit({ type: "authz.deny", principalId: "bob", model: "gpt-4o", outcome: "deny", detail: { reason: "over quota" } });
  store.appendAudit({ type: "egress.deny", principalId: "bob", outcome: "deny", detail: { classification: "CUI" } });
  store.appendAudit({ type: "usage", principalId: "carol", model: "claude-sonnet", tier: "MEDIUM", outcome: "ok", detail: {} });

  // ── Baseline: newest-first, full set ──
  const all = store.queryAudit({});
  ok("returns all 5, newest first", all.length === 5 && all[0].type === "usage" && all[0].principalId === "carol");
  ok("countAudit({}) === 5", store.countAudit({}) === 5);

  // ── Filters ──
  ok("filter type=usage → 2", store.queryAudit({ type: "usage" }).length === 2 && store.countAudit({ type: "usage" }) === 2);
  ok("filter outcome=deny → 2", store.queryAudit({ outcome: "deny" }).length === 2);
  ok("filter principal=bob → 2", store.queryAudit({ principalId: "bob" }).length === 2);
  ok("filters compose (bob + deny) → 2", store.countAudit({ principalId: "bob", outcome: "deny" }) === 2);

  // ── Free-text search: hits columns AND the JSON detail blob ──
  ok("search 'claude' (model) → 2", store.queryAudit({ search: "claude" }).length === 2);
  ok("search 'over quota' (detail) → 1", store.queryAudit({ search: "over quota" }).length === 1);
  ok("search 'gpt' → 1 bob row", store.queryAudit({ search: "gpt" })[0]?.principalId === "bob");
  ok("search miss → 0", store.countAudit({ search: "zzz-nope" }) === 0);

  // ── Sort whitelist + direction ──
  const byPrincAsc = store.queryAudit({ sort: "principal", dir: "asc" });
  ok("sort principal asc → austin first", byPrincAsc[0].principalId === "austin");
  ok("sort principal desc → carol first", store.queryAudit({ sort: "principal", dir: "desc" })[0].principalId === "carol");
  // Unknown sort key falls back to chronological (id) order, never an injected column.
  ok("bogus sort key → safe chronological fallback", store.queryAudit({ sort: "id; DROP TABLE audit_log" as never }).length === 5);
  ok("audit_log survived injection attempt", store.countAudit({}) === 5);

  // ── Paging: limit + offset walk the ordered set without overlap ──
  const p1 = store.queryAudit({ limit: 2, offset: 0 });
  const p2 = store.queryAudit({ limit: 2, offset: 2 });
  ok("page 1 = 2 rows", p1.length === 2);
  ok("page 2 = 2 rows, disjoint from page 1", p2.length === 2 && p2[0].id !== p1[0].id && p2[0].id !== p1[1].id);
  ok("offset past end → 0 rows, total still 5", store.queryAudit({ limit: 2, offset: 10 }).length === 0 && store.countAudit({}) === 5);

  store.close();
}

console.log(`\nAudit query: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
