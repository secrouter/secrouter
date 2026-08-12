# Changelog

## [Unreleased]

### Fixed
- **OpenAI-path tool-calling.** `forwardToOpenAI` built the upstream request body with only
  `model`/`messages`/`stream`/`max_tokens`/`temperature`/`top_p` — it silently dropped **`tools`**,
  **`tool_choice`**, and **`stop`**. Every OpenAI-compatible backend (MLX, vLLM, Ollama, TGI,
  Bedrock-openai, Azure) therefore never received tool definitions, so the model could not emit a
  structured `tool_call` and agentic clients (e.g. pi) saw it narrate the tool in prose instead. The
  Anthropic path already forwarded tools; the OpenAI path now does too. Body construction is factored
  into `buildOpenAIRequestBody` with a regression test on the forwarded-field allow-list.

### Routing
- **Custom-catalog tier remap — `SECROUTER_SECLLM_MODELS`.** The turnkey SecLLM intake
  (`SECROUTER_SECLLM_ENDPOINTS`) routes SIMPLE/MEDIUM/COMPLEX/REASONING to the default tags
  `secllm/fast|balanced|large|reasoning`, which only exist in SecLLM's own catalog. A pool serving a
  **custom** OpenAI-compatible catalog (e.g. an MLX/vLLM server whose ids are `org/model`) can now
  remap each tag to its real backend model id via `SECROUTER_SECLLM_MODELS` (`tag=modelId,…`) — e.g.
  `balanced=lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit` points the MEDIUM tier at the 26B
  tool-caller — without hand-authoring `providers.secllm` + the tier mappings. The mapping applies
  to **both** the classifier's tiers **and** an explicit `secllm/<tag>` request: `model:
  "secllm/balanced"` resolves to the mapped id at forward time, so a client that pins its model by
  tag (e.g. an agent) gets the mapped model instead of a 404 on the literal tag. Backward-compatible
  (unset = the literal tags), applies only alongside `SECROUTER_SECLLM_ENDPOINTS`, and skips
  unknown/malformed entries with a warning.
- **Health-aware routing.** SecRouter now steers a non-gated request onto a model that is actually
  **live** — learned by polling each OpenAI-compatible provider's `/v1/models` — instead of
  forwarding to a tier's configured model that isn't loaded on any backend (which would `502`).
  **When exactly one model is live, every non-gated request goes to it**; when several are live it
  prefers a live model from the request's own tier chain. Explicit-model requests (`model` ≠ `auto`)
  and policy-pinned/downgraded requests are gates and are never re-steered. Active liveness polling
  now auto-enables for a **loopback** endpoint (a local SecLLM), for pooled providers, and for the
  self-hosted **SecLLM turnkey pool** (`SECROUTER_SECLLM_ENDPOINTS`) even when SecDeploy addresses it
  by FQDN — so it's turnkey for a provisioned suite. Polling those isn't egress (they're inside the
  boundary); a single remote third-party endpoint is still opt-in via
  `security.resilience.healthIntervalSec`.

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
