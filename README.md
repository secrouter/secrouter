# SecRouter — Secure, Self-Hosted AI Gateway

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/spaceProbe/secrouter_web/main/assets/logo-dark.png" />
    <img src="https://raw.githubusercontent.com/spaceProbe/secrouter_web/main/assets/logo.png" alt="SecRouter — Secure AI API Router" width="525" />
  </picture>
</p>

**Put every AI request under your control.** SecRouter is a self-hosted gateway that sits in front of your LLMs and adds the two things enterprises actually need before they can say yes to AI: **governance** (who can use which model, with a full audit trail and data that never leaves the boundary) and **cost control** (per-user token & dollar tracking, budgets, and smart routing to the cheapest capable model).

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
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
- **Deny-by-default egress + data-residency gate** — only authorized destinations are reachable (e.g. **Claude on AWS Bedrock GovCloud** — FedRAMP High / IL4-5 — or self-hosted models inside your boundary). A classification gate refuses to send data to anywhere it isn't cleared for.
- **Tamper-evident audit** — structured, **hash-chained**, CUI-safe (metadata-only) log of every auth, authorization, routing, and usage event, with optional syslog/SIEM forwarding.
- **Built for regulated environments** — mapped to **NIST SP 800-171 R2 + 800-172 (CMMC Level 3)**; FIPS fail-closed startup; FIPS cipher policy.

### 💸 Contain AI spend
- **Per-user token & cost tracking** — captured on **both** streaming and non-streaming calls, persisted in `node:sqlite`, attributed by user, model, and day.
- **Budgets & rate limits** — daily/monthly spend caps and request/token rate limits, enforced atomically. Over budget → `429`.
- **Smart routing** — a weighted classifier scores each request and routes to the cheapest model that can handle it.
- **Live cost visibility** — `GET /v1/usage` (self) and `GET /admin/usage` (admin), plus a web console.

### 🖥️ Admin console (`/admin`)
A dependency-free web UI (OIDC PKCE login) to **monitor** per-user/model/day usage & cost, **configure** group/user policies and tier→model routing (audited, applied live), **add local / on-prem model endpoints** with a guided wizard (test → discover models → price → set egress → validate → write the config file → reload/restart), and **review** the audit trail. [Light & dark themes.](#)

> **Backward compatible.** Security is gated by `security.enabled` — off by default, so out of the box SecRouter behaves like a plain dev router (with a loud warning). Turn it on for any real deployment.

## How it works

```
                    ┌──────────────── hash-chained audit ────────────────┐
                    │                                                     │
client ──TLS──▶ [1] AuthN ──▶ [2] AuthZ ──▶ classifier ──▶ [3] egress gate ──▶ authorized model
   (SSO/JWT)      OIDC         policy +          route          deny-by-default     (Bedrock GovCloud
                              quota check                        + data residency    or self-hosted)
                                    │                                  │
                                    └────── usage & cost ◀── token accounting
```

## Quick start (dev)

```bash
git clone https://github.com/spaceProbe/secrouter.git
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

- [`freerouter.config.hardened.example.json`](freerouter.config.hardened.example.json) — full CMMC L3 config (OIDC, per-user policy/quotas, Bedrock GovCloud + self-hosted egress allow-list, FIPS, audit).
- [Deployment hardening guide](docs/compliance/deployment-hardening.md) · [CMMC control matrix](docs/compliance/cmmc-control-matrix.md).

```bash
npm run test:security      # 36 assertions: OIDC, policy/quota, egress, SigV4
npm run test:integration   # full secured pipeline + admin API (e2e)
```

## Configuration

Config is loaded from, in order: `FREEROUTER_CONFIG` env var → `./freerouter.config.json` → `~/.config/freerouter/config.json`. The `security` block is validated at startup and **fails closed** — the server refuses to boot in an unsafe configuration.

```jsonc
{
  "providers": {
    "bedrock": { "api": "bedrock", "region": "us-gov-west-1", "baseUrl": "https://bedrock-runtime.us-gov-west-1.amazonaws.com" },
    "local":   { "api": "openai", "baseUrl": "https://llm.internal.example.mil/v1" }
  },
  "tiers": {
    "SIMPLE":    { "primary": "local/llama-3.3-70b-instruct" },
    "MEDIUM":    { "primary": "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0" },
    "COMPLEX":   { "primary": "bedrock/anthropic.claude-opus-4-20250514-v1:0" }
  },
  "security": {
    "enabled": true,
    "oidc":   { "issuer": "https://idp.example.mil/realms/cui", "audience": "secrouter", "requireMfa": true },
    "egress": { "allowlist": [ { "provider": "bedrock", "allowedHost": "bedrock-runtime.us-gov-west-1.amazonaws.com", "authorizedClassifications": ["CUI"] } ] },
    "policy": { "default": { "allowedTiers": ["SIMPLE","MEDIUM"], "budgets": [{ "window": "day", "maxCostUsd": 25 }] } }
  }
}
```

## Endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `POST /v1/chat/completions` | user | Route & forward (OpenAI-compatible) |
| `GET /v1/models` | user | List configured models |
| `GET /v1/usage` | user | Your own token/cost usage |
| `GET /health` | open | Liveness probe |
| `GET /admin` | open shell | Admin web console (OIDC PKCE login) |
| `GET /admin/usage` · `/admin/api/*` | admin | Org usage + policy/model config |
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

## Project structure

```
src/
  server.ts            HTTP server, routing, admin API, auth middleware
  provider.ts          Multi-provider forwarding (Anthropic, OpenAI, Bedrock SigV4) + usage capture
  config.ts            External config + effective-config overlay (file + DB overrides)
  models.ts            Model catalog + pricing
  admin-ui.ts          Admin console SPA (served at /admin)
  router/              Weighted classifier + tier mappings
  security/            ← the security layer
    identity/          OIDC/JWT verification
    policy/            Per-user/group authorization
    accounting/        Token usage, cost, quota
    egress/            Deny-by-default allow-list + classification gate
    audit/             Hash-chained audit + syslog/SIEM
    store/             node:sqlite (ledger, audit, overrides)
    transport/         TLS/FIPS + AWS SigV4
docs/compliance/       CMMC control matrix + hardening guide
deploy/                Dockerfile, compose test stack, mocks, runbook
test/security/         Unit + integration tests
```

## License

[MIT](LICENSE). Routing engine descends from BlockRunAI/ClawRouter (MIT); the x402 payment layer was removed and the security/governance layer added.
