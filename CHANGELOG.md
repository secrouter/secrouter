# Changelog

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
