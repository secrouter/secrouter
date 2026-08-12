# SecRouter — Secure, Self-Hosted AI Gateway

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/secrouter/secrouter_web/main/assets/logo-dark.png" />
    <img src="https://raw.githubusercontent.com/secrouter/secrouter_web/main/assets/logo.png" alt="SecRouter — Secure AI API Router" width="525" />
  </picture>
</p>

**Put every AI request under your control.** SecRouter is a self-hosted gateway that sits in front of your LLMs and adds the two things enterprises actually need before they can say yes to AI: **governance** (who can use which model, with a full audit trail and data that never leaves the boundary) and **cost control** (per-user token & dollar tracking, budgets, and smart routing to the cheapest capable model).

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CMMC](https://img.shields.io/badge/CMMC-Level%203%20ready-4f6a2e)](docs/compliance/cmmc-control-matrix.md)
[![OpenAI-compatible](https://img.shields.io/badge/API-OpenAI--compatible-444)](#endpoints)

---

## Why SecRouter

Teams are adopting AI faster than security and finance can govern it. Two problems show up immediately:

| For security & IT | For finance & ops |
|---|---|
| **Shadow AI** — ungoverned tools, prompts leaving the boundary, no audit, no access control | **Opaque spend** — no per-user visibility, every "hello" hitting your most expensive model, surprise bills |

SecRouter closes both gaps in one drop-in, OpenAI-compatible gateway you host yourself — **no middleman, no markup, your keys**.

### 🔒 Secure AI use
- **SSO / OIDC authentication** — every request carries a validated JWT from your IdP (Keycloak, Okta, Entra, Ping). LDAP/AD groups arrive as claims; MFA (`amr`/`acr`) is enforced. **Deny-by-default** on every route but `/health`.
- **Per-user access policy** — control which tiers and models each group/user may reach; lock down individual accounts below the org default.
- **Deny-by-default egress + data-residency gate** — only authorized destinations are reachable (e.g. **OpenAI frontier models (gpt-oss) on AWS Bedrock GovCloud** — FedRAMP High / IL4-5 — **Azure OpenAI**, or self-hosted models inside your boundary). A classification gate refuses to send data to anywhere it isn't cleared for.
- **Tamper-evident audit** — structured, **hash-chained**, CUI-safe (metadata-only) log of every auth, authorization, routing, and usage event, with optional syslog/SIEM forwarding.
- **Built for regulated environments** — mapped to **NIST SP 800-171 R2 + 800-172 (CMMC Level 3)**; FIPS fail-closed startup; FIPS cipher policy.

### 💸 Contain AI spend
- **Per-user token & cost tracking** — captured on **both** streaming and non-streaming calls, persisted in `node:sqlite`, attributed by user, model, and day.
- **Budgets & rate limits** — daily/monthly spend caps and request/token rate limits, enforced atomically. Over budget → `429`.
- **Smart routing** — a weighted classifier scores each request and routes to the cheapest model that can handle it.
- **Live cost visibility** — `GET /v1/usage` (self) and `GET /admin/usage` (admin), plus a web console.

### 🖥️ Admin console (`/admin`)
A dependency-free web UI (OIDC PKCE login) to **monitor** per-user/model/day usage & cost, **configure** group/user policies and tier→model routing (audited, applied live), **add local / on-prem model endpoints** with a guided wizard (test → discover models → price → set egress → validate → write the config file → reload/restart), **review** the audit trail, watch **provider health**, and export **compliance evidence**. [Light & dark themes.](#)

### 🔭 Operate & prove
- **Painless provider switching** — OpenAI-on-Bedrock (GovCloud) and Azure OpenAI both speak the OpenAI API, so moving a tier between clouds is a one-line target change. Credentials are handled per-provider: Bedrock API key / SigV4, Azure `api-key` **or** Microsoft Entra.
- **Observability** — Prometheus `/metrics` (auth, routing, tokens, cost, circuit state) and W3C `traceparent` propagation across the pipeline.
- **Provider health & failover** — a per-**endpoint** circuit breaker trips on upstream faults and fails over within the tier; live state on the console.
- **Multi-endpoint load balancing** — give a provider several base URLs (`baseUrl: [...]`) to round-robin, breaker-isolated and model-aware, across replicas of the same backend (e.g. a self-hosted GPU pool); see [Configuration](#configuration).
- **Governed embeddings & tool-calling** — `POST /v1/embeddings` and an OpenAI-compatible **MCP** tool gateway (`POST /mcp`, deny-by-default tool allow-list) run under the same auth, policy, egress, and audit controls.
- **Assessor-ready evidence** — verify the hash-chained audit in one call; export a one-click evidence bundle (config baseline, FIPS/TLS posture, control self-assessment).

> **Backward compatible.** Security is gated by `security.enabled` — off by default, so out of the box SecRouter behaves like a plain dev router (with a loud warning). Turn it on for any real deployment.

## How it works

```
                    ┌──────────────── hash-chained audit ────────────────┐
                    │                                                     │
client ──TLS──▶ [1] AuthN ──▶ [2] AuthZ ──▶ classifier ──▶ [3] egress gate ──▶ authorized model
   (SSO/JWT)      OIDC         policy +          route          deny-by-default    (OpenAI on Bedrock
                              quota check                        + data residency    / Azure / self-hosted)
                                    │                                  │
                                    └────── usage & cost ◀── token accounting
```

## Quick start (dev)

```bash
git clone https://github.com/secrouter/secrouter.git
cd secrouter
npm install
npm run build            # → dist/server.js
npm start                # http://localhost:18800  (security disabled — dev only)
```

```bash
# OpenAI-compatible
curl http://localhost:18800/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"auto","messages":[{"role":"user","content":"Hello!"}]}'
```

## Secured test deployment

A one-command, fully-secured stack (router + mock IdP + mock model) so you can exercise auth, policy, quotas, egress control, and the admin console without a real IdP or cloud:

```bash
cd deploy
docker compose -f docker-compose.test.yml up --build
./smoke-test.sh                       # 401 → 200, chat, usage, admin-gating
open http://localhost:18800/admin     # sign in (pick a test persona) → console
```

See [`deploy/README.md`](deploy/README.md) for the runbook and the path to production.

## Production

Start from the hardened reference config and the hardening guide:

- [`freerouter.config.hardened.example.json`](freerouter.config.hardened.example.json) — full CMMC L3 config (OIDC, per-user policy/quotas, **OpenAI-on-Bedrock GovCloud + Azure OpenAI + self-hosted** egress allow-list, FIPS, audit).
- [Deployment hardening guide](docs/compliance/deployment-hardening.md) · [CMMC control matrix](docs/compliance/cmmc-control-matrix.md).

```bash
npm run test:security      # OIDC, policy/quota, egress, SigV4, metrics, resilience, Azure, MCP
npm run test:integration   # full secured pipeline + admin API (e2e)
```

## Configuration

Config is loaded from, in order: `FREEROUTER_CONFIG` env var → `./freerouter.config.json` → `~/.config/freerouter/config.json`. The `security` block is validated at startup and **fails closed** — the server refuses to boot in an unsafe configuration.

```jsonc
{
  "providers": {
    // OpenAI frontier models on AWS Bedrock GovCloud (OpenAI-compatible endpoint)
    "bedrock": { "api": "openai", "region": "us-gov-west-1",
                 "baseUrl": "https://bedrock-runtime.us-gov-west-1.amazonaws.com/openai/v1" },
    // Azure AI Foundry (OpenAI) — api-key or Microsoft Entra; switch a tier by changing its target
    "azure":   { "api": "azure", "baseUrl": "https://my-aoai.openai.azure.com", "azureAuth": "entra" },
    "local":   { "api": "openai", "baseUrl": "https://llm.internal.example.mil/v1" },
    // Pooled provider: an array of base URLs round-robins across replicas of the
    // SAME backend (e.g. a self-hosted GPU cluster), breaker-isolated per endpoint
    // and model-aware (an endpoint is only offered a model its /v1/models lists).
    "secllm":  { "api": "openai", "baseUrl": ["https://gpu1.internal.example.mil/v1", "https://gpu2.internal.example.mil/v1"] }
  },
  "tiers": {
    "SIMPLE":    { "primary": "bedrock/openai.gpt-oss-20b-1:0",  "fallback": ["local/llama-3.3-70b-instruct"] },
    "MEDIUM":    { "primary": "bedrock/openai.gpt-oss-120b-1:0", "fallback": ["azure/gpt-4o"] },
    "COMPLEX":   { "primary": "bedrock/openai.gpt-oss-120b-1:0", "fallback": ["azure/gpt-4o"] },
    "REASONING": { "primary": "bedrock/openai.gpt-oss-120b-1:0", "fallback": ["azure/o4-mini"] }
  },
  "security": {
    "enabled": true,
    "oidc":   { "issuer": "https://idp.example.mil/realms/cui", "audience": "secrouter", "requireMfa": true },
    "egress": { "allowlist": [
      { "provider": "bedrock", "allowedHost": "bedrock-runtime.us-gov-west-1.amazonaws.com", "authorizedClassifications": ["CUI"] },
      { "provider": "azure",   "allowedHost": "my-aoai.openai.azure.com",                    "authorizedClassifications": ["CUI"] },
      // One rule, both pool hosts — allowedHost accepts an array so a pooled
      // provider's endpoints are ALL authorized (checkEgress matches any of them);
      // a host you add to `secllm.baseUrl` later but forget to list here still denies.
      { "provider": "secllm", "allowedHost": ["gpu1.internal.example.mil", "gpu2.internal.example.mil"], "authorizedClassifications": ["CUI"] }
    ] },
    "policy": { "default": { "allowedTiers": ["SIMPLE","MEDIUM"], "budgets": [{ "window": "day", "maxCostUsd": 25 }] } }
  }
}
```

**Multi-endpoint / load-balanced providers.** Any provider's `baseUrl` accepts a
single string (default) or an array of URLs. An array round-robins traffic
across the endpoints, with per-endpoint circuit breaking (one replica going
down doesn't take the others with it) and model-aware routing (an endpoint is
only offered a model that its own `GET /v1/models` reports serving — an
endpoint of unconfirmed support is still preferred over failing the request
outright). `security.egress.allowlist[].allowedHost` accepts the same
string-or-array shape, so ALL of a pool's hosts can be authorized under one
rule; a host that's reachable but not listed there is still denied. See
`GET /admin/api/health` / the console's Provider health panel for live,
per-endpoint circuit state.

**Turnkey SecLLM pool — `SECROUTER_SECLLM_ENDPOINTS`.** Set this env var to a
comma-separated list of base URLs (e.g.
`SECROUTER_SECLLM_ENDPOINTS=https://gpu1.internal:8000/v1,https://gpu2.internal:8000/v1`)
and SecRouter auto-registers a pooled `secllm` provider — with bearer-token
auth resolved from `SECROUTER_SECLLM_TOKEN` (the same env-based provider
`auth` every other provider uses; unset = no `Authorization` header sent, for
an open/unauthenticated SecLLM) — and turnkey-routes SIMPLE/MEDIUM/COMPLEX/
REASONING (in both `tiers` and `agenticTiers`) to SecLLM's default-catalog
friendly model ids — `secllm/fast`, `secllm/balanced`, `secllm/large`,
`secllm/reasoning` respectively — demoting whatever was previously each
tier's primary into that tier's fallback instead of discarding it. This intake is purely additive
and a strict no-op the moment you take explicit ownership — either by
defining your own `secllm` provider or routing any tier to `secllm/*`
yourself. **It only ever wires up routing + credentials — never a network
path**; see egress below.

**Custom catalog — `SECROUTER_SECLLM_MODELS`.** The tags above
(`fast`/`balanced`/`large`/`reasoning`) are SecLLM's *default* catalog names,
forwarded verbatim as the upstream model id. A pool serving a **different**
catalog — e.g. an OpenAI-compatible MLX or vLLM server whose ids are
`org/model` — would 404 those tags. Set `SECROUTER_SECLLM_MODELS` to a
comma-separated list of `tag=modelId` pairs to remap any tag to the real id
that pool serves, e.g.:

```
SECROUTER_SECLLM_MODELS=fast=mlx-community/Llama-3.2-3B-Instruct-4bit,balanced=lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit
```

routes the **`balanced`** tag (the MEDIUM tier) to the 26B tool-caller and
`fast` (SIMPLE) to the 3B; unspecified tags keep their literal default.
Unknown tags and malformed pairs are skipped with a warning. This is the
turnkey alternative to hand-authoring `providers.secllm` + the tier mappings
for a custom catalog, and applies only when `SECROUTER_SECLLM_ENDPOINTS` is
also set.

**Egress stays explicit — `SECROUTER_EGRESS_FILE`.** The turnkey intake above
never touches `security.egress`: under `security.enabled: true`, the
turnkey-routed pool stays egress-**denied** (deny-by-default, unchanged)
until you authorize it yourself, exactly like any other provider — either a
hand-authored `secllm` rule in `security.egress.allowlist` (see
[Configuration](#configuration) above), or — for deployment tooling that
generates the enclave's authorized hosts as a file rather than hand-editing
the main config — point `SECROUTER_EGRESS_FILE` at a JSON file containing an
**array** of `security.egress.allowlist` entries (exact same shape):

```jsonc
// egress-rules.json
[
  {
    "provider": "secllm",
    "allowedHost": ["gpu1.internal:8000", "gpu2.internal:8000"],
    "authorizedClassifications": ["UNCLASSIFIED", "CUI"],
    "authorization": "Deployer-generated — internal enclave inference pool"
  }
]
```

```bash
SECROUTER_EGRESS_FILE=/etc/secrouter/egress-rules.json
```

Loaded on every config (re)load and **merged additively** into
`security.egress.allowlist` — creating `security`/`security.egress` from
scratch if either is absent, never removing or overwriting a rule already
there, deduped by (provider, host) so reloading the same file twice never
duplicates entries. It's audit-evident, not silent: every successful load
writes an `egress.file_loaded` event to the tamper-evident audit trail (`GET
/admin/api/audit`) — file path and rule counts included — and a matching line
is always logged, even when security is disabled. A missing, unreadable, or
malformed file is a **hard startup/reload failure** (fail loud — this is a
security control, never a silent fallback), so a typo'd path can't quietly
leave you with less egress authorization than you think you have. The pool
being simply unreachable (down, network partition — the per-endpoint breaker
trips) still gracefully falls back to the demoted prior primary rather than
hard-failing.

## Endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `POST /v1/chat/completions` | user | Route & forward (OpenAI-compatible) |
| `POST /v1/embeddings` | user | Governed embeddings (OpenAI-compatible) |
| `POST /mcp` | user | Governed MCP tool gateway — deny-by-default tool allow-list |
| `GET /v1/models` | user | List configured models |
| `GET /v1/usage` | user | Your own token/cost usage |
| `GET /health` | open | Liveness probe |
| `GET /metrics` | config | Prometheus metrics (enable via `security.metrics`) |
| `GET /admin` | open shell | Admin web console (OIDC PKCE login) |
| `GET /admin/usage` · `/admin/api/*` | admin | Org usage + policy/model config |
| `GET /admin/api/health` | admin | Provider health / circuit-breaker state |
| `GET /admin/api/audit/verify` | admin | Verify hash-chained audit integrity |
| `GET /admin/api/evidence` | admin | One-click compliance evidence bundle |
| `GET /stats` · `/config` · `POST /reload` · `/reload-config` | admin | Ops |

## Smart routing & overrides

The classifier scores each message (length, reasoning depth, code/math complexity, domain specificity, …) and picks the cheapest capable tier. Override it inline when you know better — the prefix is stripped before forwarding:

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

### Health-aware routing

The classifier maps a request to a tier → model, but that model may not be **loaded** on any
backend — a single-GPU [SecLLM](https://github.com/secrouter/secllm) commonly serves one model at a
time, so a tier's configured primary can be entirely absent from the local deployment. SecRouter
learns what's actually live by polling each OpenAI-compatible provider's `/v1/models`, and steers a
**non-gated** request to a live model instead of forwarding to one that would `502`. The headline
case: **when exactly one model is live, every non-gated request goes to it.** When several are live,
it prefers a live model from the request's own tier chain (in configured order) and otherwise leaves
the decision alone. This is purely additive — with no liveness data yet, routing is unchanged.

A request is **gated** (never re-steered) when the caller pins a concrete `model` (anything but
`auto`), or when a per-user policy denies/downgrades to a specific model — those decisions win.

Liveness comes from the same active `/v1/models` probe that powers multi-endpoint load balancing.
It **auto-enables** for (a) a pooled provider (>1 endpoint), (b) any **loopback** endpoint (a local
SecLLM at `127.0.0.1`), and (c) the self-hosted **SecLLM turnkey pool** (`SECROUTER_SECLLM_ENDPOINTS`)
even when SecDeploy addresses it by FQDN — that pool is the deployment's own inference tier, inside
the boundary and already egress-authorized, so keeping liveness on it is exactly what's wanted. A
single **remote third-party** endpoint stays passive by default (no background egress); set
`security.resilience.healthIntervalSec` to actively probe it too. Steer decisions are logged and
carried in the `X-SecRouter-Reasoning` header.

## Project structure

```
src/
  server.ts            HTTP server, routing, admin API, auth middleware
  provider.ts          Multi-provider forwarding (OpenAI · Azure OpenAI · OpenAI-on-Bedrock; SigV4 / api-key / Entra) + usage capture
  config.ts            External config + effective-config overlay (file + DB overrides)
  models.ts            Model catalog + pricing
  admin-ui.ts          Admin console SPA (served at /admin)
  metrics.ts           Prometheus registry (served at /metrics)
  router/              Weighted classifier + tier mappings + multi-endpoint load balancing (balance.ts) + health-aware model steering (health.ts)
  security/            ← the security layer
    identity/          OIDC/JWT verification
    policy/            Per-user/group authorization
    accounting/        Token usage, cost, quota
    egress/            Deny-by-default allow-list + classification gate
    audit/             Hash-chained audit + syslog/SIEM
    store/             node:sqlite (ledger, audit, overrides)
    transport/         TLS/FIPS + AWS SigV4 + Azure Entra
    resilience.ts      per-endpoint circuit breaker
    mcp/               governed MCP tool gateway (deny-by-default tools)
docs/compliance/       CMMC control matrix + hardening guide
deploy/                Dockerfile, compose test stack, mocks, runbook
test/security/         Unit + integration tests
```

## License

[Apache 2.0](LICENSE) — Copyright 2026 Austin Probe. The routing engine descends from BlockRunAI/ClawRouter (MIT); that upstream attribution is preserved in [NOTICE](NOTICE). The x402 payment layer was removed and the security & governance control plane added.
