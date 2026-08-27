# Usage guide

How to use a running SecRouter: the API, model routing, the admin console,
the audit trail, and the routing-experiments features. For config field
reference see [`configuration.md`](configuration.md); for the pitch and
quick start see the [README](../README.md).

## `/v1` endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `POST /v1/chat/completions` (alias `/chat/completions`) | user | Route & forward (OpenAI-compatible). |
| `POST /v1/embeddings` (alias `/embeddings`) | user | Governed embeddings (OpenAI-compatible). Uses `embeddings.default` when `model` is `"auto"`/omitted. |
| `POST /mcp` | user | Governed MCP tool gateway (deny-by-default tool allow-list). 404s unless `security.mcp.enabled`. |
| `GET /v1/models` (alias `/models`) | user | List configured models. |
| `GET /v1/usage` | user | Your own token/cost usage: last-24h and last-30d aggregates, budgets, per-model breakdown. |
| `GET /health` | open | Liveness probe. |
| `GET /metrics` | config-gated | Prometheus metrics; enable via `security.metrics.enabled`. |

Every routed response carries:

- `X-Request-Id` — correlates to the audit trail.
- `X-SecRouter-Model` — the model actually used (after any steering/downgrade/escalation).
- `X-SecRouter-Tier` — the resolved tier (or `EXPLICIT` for a pinned model).
- `X-SecRouter-Reasoning` — a truncated (200-char) trace of how the model was chosen (classifier signals, mode override, split assignment, health steer, policy downgrade — whichever applied).
- `X-SecRouter-Split` — present only when a split (A/B) experiment assigned this request; `"<experiment-name>=<model>"`.
- `X-SecRouter-Escalation` — present only when escalation routing applies to this request; `accepted` \| `escalated` \| `escalation_denied`.

## Model selection: `model: "auto"` and mode overrides

Send `model: "auto"` (or `"secrouter/auto"`) and SecRouter's weighted
classifier scores the prompt (length, code/math complexity, reasoning
markers, domain specificity, multi-step/agentic patterns, …) and picks the
cheapest capable tier → model. Sending a concrete `model` instead is a
**passthrough/gate**: it's forwarded as-is, tagged tier `EXPLICIT`, and is
never re-steered by health-aware routing, split experiments, or escalation
(a per-user policy can still deny or downgrade it).

Override the classifier inline — the matched prefix is stripped before the
prompt is forwarded:

```
/simple  What's 2+2?
/max     Analyze this distributed system for race conditions
[complex] Refactor this module to use dependency injection
deep mode: Why does this recursive CTE produce duplicates?
```

| Aliases | Tier |
|---|---|
| `simple`, `basic`, `cheap` | SIMPLE |
| `medium`, `balanced` | MEDIUM |
| `complex`, `advanced` | COMPLEX |
| `max`, `reasoning`, `think`, `deep` | REASONING |

A mode override honors the tier's *configured* primary/fallback chain, same
as the classifier path — it just skips scoring.

### Health-aware steering

Independent of the above: when SecRouter has learned (by polling each
OpenAI-compatible provider's `/v1/models`) that the classifier's chosen model
isn't actually loaded anywhere, it steers a **non-gated** request to a model
that is live rather than forwarding to one that would `502`. See the
README's "Health-aware routing" section for the full auto-enable rules
(pooled providers, loopback endpoints, the SecLLM turnkey pool). This runs
*after* split-routing assignment and *before* per-user policy authorization.

## Admin console (`/admin`)

A dependency-free web UI, OIDC PKCE login, four tabs:

| Tab | Contents |
|---|---|
| **Monitor** | Compliance/control self-assessment, provider health (circuit-breaker state per endpoint), MCP status, and org usage — stacked, read-only. |
| **Policies** | Per-group/per-user policy editing (allowed tiers/models, budgets, classification ceiling, admin flag) — writes go through the audited overrides layer, applied live. |
| **Models** | Tier→model routing (model-driven — reflects what's actually reachable via `/admin/api/models/available`), and the add/remove-endpoint wizard (probe → preview → apply → reload/restart) with per-provider egress editing. |
| **Access Log** | The hash-chained audit trail — searchable (free text), filterable (type/outcome/principal/since), sortable, paginated/scrollable. Backed by `GET /admin/api/audit`. |

Admin-gated API surface (all under `/admin/api/*` except where noted; a
principal needs `policy.admin: true` — see [Policy](configuration.md#policy)):

| Endpoint | Description |
|---|---|
| `GET /admin/usage` | Org-wide usage breakdown. Query: `groupBy` (`principal`\|`model`\|`day`, default `principal`), `days` (1–365, default 30), `principal`. |
| `GET /admin/api/config` | Effective policy + tiers + model catalog (providers/egress read-only view). |
| `GET /admin/api/health` | Per-`(provider, endpoint)` circuit-breaker state. |
| `GET /admin/api/audit` | The access log. Query: `type`, `outcome`, `principal`, `search`, `since`, `sort` (`ts`\|`type`\|`principal`\|`model`\|`tier`\|`outcome`), `dir` (`asc`\|`desc`), `limit` (1–1000, default 100), `offset`. Returns `{ rows, total }`. |
| `GET /admin/api/audit/verify` | Verify the hash-chained audit integrity — see [Audit trail](#audit-trail-and-evidence). |
| `GET /admin/api/evidence` | One-click compliance evidence bundle — see [Audit trail](#audit-trail-and-evidence). |
| `GET /admin/api/models/available` | Probe every configured provider's `/v1/models` (read-only; same reach+list logic as endpoint/probe). |
| `POST /admin/api/endpoint/probe` \| `/preview` \| `/apply` \| `/remove` \| `/egress` | The endpoint-management wizard: reach a candidate URL and list its models, validate a proposed change, write it into the config file (atomic, validated, `.bak` backup — does not itself reload), remove an endpoint, or edit its egress rule. |
| `POST /admin/api/mcp/probe` | Probe a registered MCP server's tools. |
| `POST /admin/api/reload` / `POST /admin/api/restart` | Reload config (audited as `config.reload`) / restart the process. |
| `PUT`/`DELETE /admin/api/policy/group/<name>`, `/policy/user/<id>`, `/tier/<name>` | Admin-console override mutations (DB-backed overlay). |
| `GET /stats` · `GET /config` · `POST /reload` · `POST /reload-config` | Ops endpoints (not under `/admin/api`, but still admin-gated). |

## Audit trail and evidence

Every auth, authorization, routing, usage, and admin event is written to a
**hash-chained**, metadata-only (CUI-safe — never prompt/response content)
audit log. Each row's `hash` covers its own fields plus the previous row's
`hash`, so any row's removal or alteration breaks every later verification.

- `GET /admin/api/audit/verify` recomputes the chain and returns `{ ok,
  brokenAtId?, checked, ts }`.
- `GET /admin/api/evidence` bundles the sanitized config baseline, FIPS/TLS
  posture, the last 200 audit rows, 30-day usage by principal, and a live
  per-control self-assessment (`AC-3.1.x`, `AU-3.3.x`, `IA-3.5.x`,
  `SC-3.13.x`, `CM-3.4.x` — see `buildControlSelfAssessment` in
  `src/server.ts`) — downloaded as `secrouter-evidence-<date>.json`.

### Audit retention

`security.audit.retentionDays` (default `0` = keep forever) enables a daily
background job (`src/security/audit/retention.ts`, wired up in
`src/server.ts`'s `startAuditPrune`) that deletes `audit_log` rows older
than the retention window. Because naively deleting old rows would break
`verifyAuditChain` (the oldest surviving row's `prevHash` would point at a
hash that no longer exists), every prune cycle **first** emits a
self-attesting `audit.pruned` event (`{ deletedCount, throughId, anchorHash
}`) through the normal auditor — subject to the same `security.audit.failClosed`
semantics as any other audit write — and only deletes rows once that event is
durably recorded. If the event write fails, the cycle skips deletion entirely
and retries the next day; nothing is ever removed without a recorded custody
trail. `verifyAuditChain` trusts `audit.pruned`'s `anchorHash` as the new
chain root when it's present, so `AU-3.3.8` (tamper-evidence) holds across
pruning. `GET /admin/api/evidence`'s control self-assessment reports the
configured `retentionDays` and status (`"pruned after Nd"` or `"retained
indefinitely"`) under `AU-3.3.1`.

## Routing experiments

Two independent, off-by-default features under `experiments` in
`secrouter.config.json` — see [`configuration.md`](configuration.md#routing-experiments)
for full field reference. Both are validated fail-loud at startup/reload:
an invalid block refuses to (re)load rather than silently misrouting live
traffic.

### Running a split (A/B) experiment

1. Pick a tier and 2+ candidate models, e.g. benchmark a new model against
   the incumbent tier primary:

   ```json
   {
     "experiments": {
       "split": {
         "enabled": true,
         "name": "sonnet-vs-candidate",
         "tiers": {
           "MEDIUM": {
             "variants": [
               { "model": "azure/gpt-4o", "weight": 90 },
               { "model": "bedrock/openai.gpt-oss-120b-1:0", "weight": 10 }
             ]
           }
         }
       }
     }
   }
   ```

2. Reload/restart. Every non-`EXPLICIT` request that resolves to `MEDIUM`
   now gets weighted-randomly assigned one of the two variants (90%/10%
   here — weights don't need to sum to 100).
3. Read the assignment back from the `X-SecRouter-Split` response header
   (`sonnet-vs-candidate=azure/gpt-4o`), the `Access Log`/audit
   `route.decision` events, or the `secrouter_split_assigned_total{tier,model}`
   Prometheus counter.
4. **Watch for contamination**: if health-aware steering subsequently moves
   a request off its assigned variant (e.g. because that variant isn't
   actually live), it's counted separately in
   `secrouter_split_steered_total{tier}` rather than silently attributed to
   the variant — exclude those samples from analysis.
5. A per-user policy denial/downgrade still overrides the split assignment
   (policy always wins); split runs before both the health-aware steer and
   policy `authorize()`.

### Running escalation routing

1. Pick the cheap tier(s) to draft on, the tier to escalate to, and a judge:

   ```json
   {
     "experiments": {
       "escalation": {
         "enabled": true,
         "fromTiers": ["SIMPLE"],
         "toTier": "MEDIUM",
         "judge": { "mode": "heuristic", "timeoutMs": 10000, "minDraftChars": 1 }
       }
     }
   }
   ```

2. For a matching, **non-streaming** request: SecRouter drafts a response on
   `fromTiers`' resolved chain, then judges it.
   - `judge.mode: "heuristic"` escalates on an empty draft, a truncated
     (`finishReason: "length"`) draft, a match against `refusalPatterns`
     (a built-in generic list by default), or a draft shorter than
     `minDraftChars` — checked in that order.
   - `judge.mode: "model"` sends the prompt+draft to `judge.model` with a
     fixed rubric prompt and expects exactly `ACCEPT` or `ESCALATE: <reason>`;
     a timeout or call error, or unparseable output, **fails open** (accepts
     the draft) rather than escalating.
3. **Accept**: the draft is served as-is. `X-SecRouter-Escalation: accepted`,
   `X-SecRouter-Model` names the draft model. Draft usage is billed to the
   caller either way.
4. **Escalate**: `toTier`'s primary is re-authorized under the same
   principal's policy and the *original* request is forwarded fresh to
   `toTier`'s chain through the normal path. `X-SecRouter-Escalation:
   escalated`, `X-SecRouter-Tier` becomes `toTier`. If `toTier` has no
   configured model, or policy denies it, SecRouter serves the draft instead
   (`X-SecRouter-Escalation: escalation_denied`) rather than failing the
   request.
5. Escalation never fires on `stream: true` requests (a draft must be judged
   before anything reaches the client) or on an `EXPLICIT` (pinned-model)
   request.
6. Observability: `secrouter_escalations_total{from_tier,to_tier,outcome}`
   and `secrouter_escalation_judge_duration_seconds{mode}`; every draft,
   accept, escalate, and denial is also an audited event.

Split and escalation can be configured together: split resolves which model
the tier's chain starts with, and escalation then drafts on that chain
before deciding whether to escalate.
