# SecRouter Roadmap — Potential Features

> Living document. Sourced from a competitive-gap analysis vs. Bifrost
> (maximhq/bifrost) and other AI gateways, filtered through SecRouter's positioning:
> **security, compliance, and cost governance for regulated/defense environments** —
> not raw throughput or provider breadth. The committed near-term work lives in
> [`plans/2026-06-27-tier1-implementation-plan.md`](plans/2026-06-27-tier1-implementation-plan.md)
> (metrics, embeddings, provider health/circuit breaker, governed MCP gateway).

Ordering within each tier is by expected value to the target buyer.

---

## Tier 2 — valuable, moderate effort

### 1. In-boundary guardrail hook (PII / prompt-injection screening)
Optional, **off-by-default** pre-forward hook that calls an *in-boundary* guardrail
service — AWS Bedrock Guardrails (GovCloud), Azure Content Safety (Azure Gov), or a
self-hosted PII/prompt-injection scanner — before a request leaves SecRouter.
- **Why**: lets us truthfully claim prompt-injection/PII protection without SecRouter
  itself inspecting or storing content. SecRouter stays metadata-only; the guardrail
  runs inside the customer's enclave and returns allow/deny/redact.
- **Design notes**: a single `security.guardrail` block (endpoint, classification
  authorization, fail-open vs. fail-closed per policy); decision (not content) is
  audited; latency budget documented. Interface first, one reference integration
  (Bedrock Guardrails) second.
- **Risks**: latency; guardrail availability becomes a dependency when fail-closed.
- **Effort**: M.

### 2. High availability — Postgres store + stateless multi-node
Swap-in Postgres behind the existing `Store` interface (it was designed for this) so
multiple stateless SecRouter replicas share the ledger/audit/overrides behind a load
balancer.
- **Why**: single-node SQLite is the current scale/HA ceiling for enterprise deploys;
  Bifrost markets cluster mode.
- **Design notes**: `store: { driver: "sqlite" | "postgres", url }`; the hash-chained
  audit needs a serialized append path (single-writer advisory lock or per-node chains
  with a chain id — decide during design). Quota checks move to atomic SQL.
- **Risks**: audit-chain semantics across writers is the hard part; don't ship without
  a verifier that understands the chosen topology.
- **Effort**: M–L.

### 3. Per-provider key pools & load balancing
Multiple credentials per provider (rotate/spread) and multiple base URLs per provider
(round-robin across on-prem vLLM replicas), with breaker-aware selection.
- **Why**: rate-limit headroom on commercial endpoints; horizontal scale for
  self-hosted clusters; graceful key rotation (add new, drain old — audited).
- **Design notes**: `auth` and `baseUrl` accept arrays; selection is weighted +
  health-aware (builds on the Tier 1 circuit breaker). Key identity (never the secret)
  appears in audit/usage for attribution.
- **Effort**: M.

### 4. Additional CUI-authorized providers: Azure OpenAI (Azure Government), Vertex (Assured Workloads)
Not breadth for its own sake — these are the other FedRAMP/IL-authorized egress
targets alongside Bedrock GovCloud, and they expand who can deploy SecRouter.
- **Design notes**: Azure OpenAI is OpenAI-shaped (api-key header + deployment URLs —
  small adapter on the existing `openai` path). Vertex needs OAuth2 service-account
  signing (a `sigv4.ts`-style module). Each ships with a hardened-config egress
  example and pricing catalog entries.
- **Effort**: S (Azure Gov) + M (Vertex).

---

## Tier 3 — worth considering, with caveats

### 5. Semantic caching (⚠ handle with care)
Cache responses keyed by embedding similarity to cut cost/latency on repeated
questions. Squarely "contain spend" — **but it stores prompt/response content**, which
collides with SecRouter's CUI-safe, metadata-only posture.
- **Only acceptable as**: in-boundary vector store, opt-in per policy, classification-
  aware (cache partitioned by classification, never cross-classification hits),
  encrypted at rest, TTL'd, and cache hits audited like any routing decision.
- **Recommendation**: defer until a customer asks with a concrete enclave design;
  ship the guardrail hook first (same "content leaves the router" muscle).
- **Effort**: L (done safely).

### 6. Multi-format inbound API (Anthropic Messages, Google GenAI)
Accept Anthropic- and GenAI-shaped requests, not just OpenAI-shaped — so Claude
Code / Anthropic SDKs / Vertex SDKs point at SecRouter unmodified while still being
governed and routed (e.g., to Bedrock GovCloud).
- **Why**: client-compatibility friction is a real adoption blocker; Bifrost leads
  with "drop-in for every SDK."
- **Design notes**: thin translation layers at the edge (`/v1/messages` →
  internal request shape); the governance pipeline is format-agnostic already.
- **Effort**: M (Anthropic first — highest demand).

### 7. Plugin / middleware hooks
A small, documented hook interface (pre-auth, post-authz, pre-forward, post-usage) so
customers add custom policy or exporters without forking.
- **Why**: Bifrost's plugin ecosystem is a selling point; ours would be narrower but
  compliance-flavored (custom classifiers, org-specific audit sinks).
- **Caveat**: every hook is arbitrary code inside the trust boundary — require
  explicit config registration, document the supply-chain implications (CM/SI), and
  keep the core zero-dep.
- **Effort**: M.

### 8. OTLP span export
Full OpenTelemetry span export (OTLP/HTTP JSON, hand-rolled) to an in-boundary
collector — completes the trace story beyond the Tier 1 `traceparent` propagation.
- **Effort**: S–M.

### 9. Anomaly detection, beyond thresholds
Today: per-request token-threshold anomaly events. Potential: per-principal baselines
(rolling usage profiles) with deviation alerts to SIEM — strengthens the 800-172
story (3.14.6e / 3.14.7e).
- **Caveat**: keep it explainable (z-scores, not ML) so it's assessor-friendly.
- **Effort**: M.

---

## Explicitly not pursuing (and why)

| Capability (Bifrost) | Why not |
|---|---|
| 1000+ models / 23+ provider breadth | The deny-by-default egress boundary **is the product**. Breadth is an anti-feature for CUI; we add providers only when they're authorization-relevant (see Tier 2 #4). |
| Raw throughput (µs-overhead, 5k RPS) | Different runtime class (Go vs. Node) and not the buying criterion in this market. If overhead ever matters, measure the classifier and optimize — don't rewrite. |
| Hosted/SaaS control plane | Self-hosted/air-gap is the trust story. |
| Brokered *external* guardrail SaaS | Content must not leave the boundary; only in-boundary guardrails (Tier 2 #1). |

---

*Update this file when items graduate to a dated plan in `docs/plans/` or ship.*
