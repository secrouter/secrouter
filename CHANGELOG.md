# Changelog

## [Unreleased]

### Routing experiments
- **Split (A/B) routing.** For a request that resolves to a tier listed in `experiments.split.tiers`,
  weighted-random-pick one of several candidate models instead of always using the tier's configured
  primary — for benchmarking a candidate model against the incumbent (or several candidates against
  each other) on real traffic. Each assignment is echoed in the `X-SecRouter-Split` response header,
  the routing reasoning, and the `secrouter_split_assigned_total` metric; if health-aware steering
  later moves the request off its assigned variant, that's counted separately in
  `secrouter_split_steered_total` so analysis can exclude the contaminated sample. Runs before the
  health-aware steer and before per-user policy `authorize()` — both still run afterward and may
  override the assignment (policy always wins).
- **Escalation routing.** Draft a response on a cheap `fromTiers` model, judge it (heuristically —
  empty/truncated/refusal-matched/too-short — or via a model judge against a fixed rubric prompt), and
  escalate *once* to `toTier` if the draft looks weak. Non-streaming only (the draft must be judged
  before anything reaches the client, which is impossible once tokens are already streaming out). A
  judge timeout, call error, or unparseable output fails **open** (accepts the draft) rather than
  escalating; a `toTier` with no configured model, or one policy denies, also falls back to serving
  the draft instead of hard-failing the request. Reported via `X-SecRouter-Escalation`
  (`accepted`/`escalated`/`escalation_denied`), `secrouter_escalations_total`, and
  `secrouter_escalation_judge_duration_seconds`.
- Both features are off by default (`experiments.split.enabled` / `experiments.escalation.enabled`)
  and validated fail-loud at config load/reload — an invalid `experiments` block refuses to (re)load
  rather than silently misrouting live traffic. See `docs/usage.md#routing-experiments`.

### Security & compliance
- **Audit retention (AU 3.3.1) — `security.audit.retentionDays`.** A daily background job prunes
  `audit_log` rows older than the configured window (default `0` = keep forever, unchanged). Pruning
  always records a self-attesting `audit.pruned` event (deleted count, `throughId`, `anchorHash`)
  through the normal auditor *before* deleting anything, so `verifyAuditChain`'s tamper-evidence
  guarantee (AU 3.3.8) holds across pruning; if that custody-trail write fails, the cycle skips
  deletion entirely and retries the next day rather than losing the trail. Surfaced in
  `GET /admin/api/evidence`'s control self-assessment.
- **OIDC service-account tokens — `security.oidc.serviceSubjects`.** Exempts named non-interactive
  `sub`s from `requireMfa`/`requiredAcr` for machine clients (client-credentials grant) that can
  never produce an MFA assertion; every other check (signature, issuer, audience, exp/nbf, algorithm,
  jti replay) still applies in full.
- **On-behalf-of delegation for a governed UI — `security.oidc.delegatingSubjects`.** A trusted
  front-end service (e.g. a governed chat UI) authenticates with its own service-account token and
  forwards the signed-in end-user's identity via a header (default `x-sec-acting-user` /
  `x-sec-acting-groups`); SecRouter replaces the principal with that end-user for policy, budgets,
  quotas, and the usage ledger, while recording the delegating service as `delegatedBy` in the
  `auth.success` audit for a complete actor → subject chain.

### Admin console
- **Endpoint management, model-driven tiers, and provider health.** `GET /admin/api/models/available`
  live-probes every configured provider; the Models tab now drives tier→model assignment off what's
  actually reachable/serving, and an add/remove-endpoint wizard (probe → preview → apply/remove/
  edit-egress, atomic validated writes, audited) replaces hand-editing the config file for local/
  on-prem endpoints.
- **Dedicated Access Log tab.** The audit trail moved out from under Monitor into its own top-level
  tab — searchable (free text), filterable (type/outcome/principal/since), sortable, and
  independently paginated/scrollable — backed by `GET /admin/api/audit`'s `{ rows, total }` response.

### Routing
- **Multi-endpoint / load-balanced providers.** Any provider's `baseUrl` now accepts an array of
  URLs, round-robinned with per-endpoint circuit breaking and model-aware selection (an endpoint is
  only offered a model its own `/v1/models` confirms serving) across replicas of the same backend
  (e.g. a self-hosted GPU pool). `security.egress.allowlist[].allowedHost` accepts the same
  string-or-array shape so one rule authorizes every pool host. Includes the turnkey
  `SECROUTER_SECLLM_ENDPOINTS`/`SECROUTER_SECLLM_TOKEN` intake (routing + provider auth only — never
  egress) and `SECROUTER_EGRESS_FILE` for deployer-generated, additively-merged egress rules
  (audit-evident via `egress.file_loaded`, fails loud on a missing/malformed file).
- **Real-model-name tier binding for the SecLLM turnkey pool.** `SECROUTER_SECLLM_ENDPOINTS` now
  binds SIMPLE/MEDIUM/COMPLEX/REASONING directly to the real SecLLM model name each defaults to
  (`Llama-3.2-3B-Instruct` / `gemma-4-26B-A4B-it` / `Llama-3.3-70B-Instruct` / `gpt-oss-20b`) rather
  than catalog tags (`fast`/`balanced`/`large`/`reasoning`) — a clean break, since SecLLM now serves
  models by real name rather than tag. `SECROUTER_SECLLM_MODELS` is re-keyed to match: comma-separated
  `tier=modelId` pairs (`simple=`/`medium=`/`complex=`/`reasoning=`) instead of `tag=modelId`.
- **Custom-catalog tier remap — `SECROUTER_SECLLM_MODELS`.** A pool serving a custom OpenAI-compatible
  catalog (e.g. an MLX/vLLM server whose ids are `org/model`) can override any tier's bound model id
  via `SECROUTER_SECLLM_MODELS` without hand-authoring `providers.secllm` + the tier mappings.
  Backward-compatible (unset = the default real names), applies only alongside
  `SECROUTER_SECLLM_ENDPOINTS`, and skips unknown tiers/malformed entries with a warning.
- **Health-aware routing.** SecRouter now steers a non-gated request onto a model that is actually
  **live** — learned by polling each OpenAI-compatible provider's `/v1/models` — instead of
  forwarding to a tier's configured model that isn't loaded on any backend (which would `502`).
  **When exactly one model is live, every non-gated request goes to it**; when several are live it
  prefers a live model from the request's own tier chain. Explicit-model requests (`model` ≠ `auto`)
  and policy-pinned/downgraded requests are gates and are never re-steered. Active liveness polling
  auto-enables for a **loopback** endpoint (a local SecLLM), for pooled providers, and for the
  self-hosted **SecLLM turnkey pool** (`SECROUTER_SECLLM_ENDPOINTS`) even when addressed by FQDN —
  so it's turnkey for a provisioned suite. Polling those isn't egress (they're inside the boundary);
  a single remote third-party endpoint is still opt-in via `security.resilience.healthIntervalSec`.

### Changed
- **Config file renamed** `freerouter.config.json` → `secrouter.config.json` (and env var
  `FREEROUTER_CONFIG` → `SECROUTER_CONFIG`, `~/.config/freerouter` → `~/.config/secrouter`), aligning
  the on-disk name with the product. Legacy names/paths are still honored so existing deploys keep
  working through the migration — no forced cutover.

### Fixed
- **OpenAI-path tool-calling.** `forwardToOpenAI` built the upstream request body with only
  `model`/`messages`/`stream`/`max_tokens`/`temperature`/`top_p` — it silently dropped **`tools`**,
  **`tool_choice`**, and **`stop`**. Every OpenAI-compatible backend (MLX, vLLM, Ollama, TGI,
  Bedrock-openai, Azure) therefore never received tool definitions, so the model could not emit a
  structured `tool_call` and agentic clients (e.g. pi) saw it narrate the tool in prose instead. The
  Anthropic path already forwarded tools; the OpenAI path now does too. Body construction is factored
  into `buildOpenAIRequestBody` with a regression test on the forwarded-field allow-list.

## [1.0.0] — SecRouter

First public release of **SecRouter** — a self-hosted, OpenAI-compatible AI gateway
that puts governance and cost control in front of your LLMs. Apache 2.0.

### Security & governance
- **OIDC/SSO authentication** on every route (deny-by-default); MFA enforced via `amr`/`acr`.
- **Per-user/group access policy** — allowed tiers/models per group, per-account lockdown below the org default.
- **Deny-by-default egress + data-residency gate** — only authorized destinations and data classifications are reachable.
- **Tamper-evident, hash-chained audit** — CUI-safe (metadata only), optional syslog/SIEM forwarding, one-call chain verification.
- **One-click compliance evidence bundle** — config baseline, FIPS/TLS posture, and a live control self-assessment for assessors.
- **FIPS fail-closed startup + cipher policy.** Mapped to NIST SP 800-171 R2 + 800-172 (CMMC Level 3).

### Cost control
- **Per-user token & cost tracking** on both streaming and non-streaming calls, persisted in `node:sqlite`.
- **Budgets & rate limits** — daily/monthly spend caps and request/token limits, enforced atomically (over budget → `429`).
- **Smart routing** — a 14-dimension weighted classifier routes each request to the cheapest capable tier, with inline mode overrides (`/simple`, `/medium`, `/complex`, `/max`).

### Providers
- **OpenAI frontier models on AWS Bedrock GovCloud** (`gpt-oss-120b`, `gpt-oss-20b`) — the default posture (FedRAMP High / IL4-5).
- **Azure OpenAI (AI Foundry)** — `api-key` or Microsoft Entra auth; painless one-line switching between Bedrock and Azure.
- **Self-hosted / any OpenAI-compatible endpoint** inside your boundary.

### Operate & prove
- **Admin console** (`/admin`) — dependency-free OIDC-PKCE UI: per-user/model/day usage & cost, policy & tier→model routing (audited, applied live), an add-endpoint wizard, provider health, audit review, and evidence export.
- **Observability** — Prometheus `/metrics` (auth, routing, tokens, cost, circuit state) and W3C `traceparent` propagation.
- **Provider health & failover** — per-provider circuit breaker with automatic in-tier failover.
- **Governed embeddings & tool-calling** — `POST /v1/embeddings` and an OpenAI-compatible MCP tool gateway (`POST /mcp`, deny-by-default tool allow-list) under the same auth, policy, egress, and audit controls.

### Credits
Derived from an MIT-licensed upstream routing engine; attribution is preserved in [NOTICE](NOTICE). The payment layer was removed and the security & governance control plane added.
