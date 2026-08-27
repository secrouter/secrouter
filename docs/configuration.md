# Configuration reference

This is the field-by-field reference for `secrouter.config.json`. For a
worked, CMMC-hardened example see
[`secrouter.config.hardened.example.json`](../secrouter.config.hardened.example.json);
for the pitch and quick start see the [README](../README.md).

Everything here is verified against `src/config.ts` (`FreeRouterConfig`,
`DEFAULT_CONFIG`, `validateSecurityConfig`), `src/router/types.ts`
(`RoutingConfig`, `ExperimentsConfig`), `src/router/config.ts`, and
`src/security/types.ts` (`SecurityConfig`).

## File location and loading

Config is loaded once at startup (and on `POST /reload-config`) from the
first of, in order:

1. `SECROUTER_CONFIG` env var (legacy `FREEROUTER_CONFIG` still honored)
2. `./secrouter.config.json` (cwd) — legacy `./freerouter.config.json` also accepted
3. `~/.config/secrouter/config.json` — legacy `~/.config/freerouter/config.json` also accepted
4. Built-in defaults (security disabled, pointed at OpenAI-on-Bedrock GovCloud)

The loaded file is **deep-merged over the built-in defaults** (`DEFAULT_CONFIG`
in `src/config.ts`) — arrays are replaced wholesale, not concatenated; objects
merge key-by-key. Two turnkey intakes then run against the merged baseline
(see [Turnkey env vars](#turnkey-env-vars) below), and finally the admin
console's DB-backed overrides are overlaid to produce the **effective**
config every request sees. `GET /config` and `GET /admin/api/config` return
the sanitized effective config (secrets redacted); the admin "add endpoint"
tooling and `PUT /admin/api/tier/<name>` etc. write to the on-disk file
directly (validated, atomic, `.bak` backup) rather than only the DB overlay.

A `security.enabled: true` config is validated at startup/reload by
`validateSecurityConfig`; a failing config **refuses to start** (fail-closed)
rather than run a CUI gateway unsafely, and a failing `/reload-config`
restores the previously-running config rather than hot-swapping into a
broken one.

## Top-level keys

| Key | Type | Default | Notes |
|---|---|---|---|
| `port` | `number` | `18800` | Overridable by `SECROUTER_PORT`. |
| `host` | `string` | `"127.0.0.1"` | Overridable by `SECROUTER_HOST`. |
| `providers` | `Record<string, ProviderConfigEntry>` | one `bedrock` entry (OpenAI-on-Bedrock GovCloud) | See [Providers](#providers). |
| `tiers` | `Record<Tier, TierMapping>` | SIMPLE/MEDIUM/COMPLEX/REASONING → the default `bedrock` models | See [Tiers](#tiers-and-models). |
| `agenticTiers` | `Record<Tier, TierMapping>` (optional) | mirrors `tiers` | Used when the classifier detects an agentic task; see `overrides.agenticMode`. |
| `models` | `ModelCatalogEntry[]` (optional) | — | Per-model pricing/metadata overlay on the hardcoded `models.ts` registry (config wins by id). See [Model catalog entries](#model-catalog-entries). |
| `embeddings` | `{ default?: string }` (optional) | — | Default model for `POST /v1/embeddings` when the client sends `model: "auto"` or omits it. |
| `experiments` | `ExperimentsConfig` (optional) | — | Split (A/B) and escalation routing. See [Routing experiments](#routing-experiments). |
| `tierBoundaries` | `{ simpleMedium, mediumComplex, complexReasoning }` (optional) | classifier's coded defaults | Overrides the classifier's score-to-tier cut points. |
| `thinking` | `ThinkingConfig` (optional) | `{ adaptive: [], enabled: { models: [], budget: 4096 } }` | `adaptive`: model-id substrings that get adaptive thinking; `enabled`: exact models with a fixed thinking-token budget. |
| `auth` | `{ default: string; [strategy]: unknown }` | `{ default: "profiles", profiles: {...} }` | Upstream **provider credential** resolution strategy (see `AuthConfig`) — unrelated to end-user OIDC auth, which lives under `security.oidc`. |
| `scoring` | `Record<string, unknown>` (optional) | — | Reserved; the classifier's actual scoring weights/keywords live in `router/config.ts`'s `DEFAULT_ROUTING_CONFIG.scoring` and are not overridden from this top-level key today. |
| `security` | `SecurityConfig` (optional) | disabled | The governance/hardening block. See [Security config](#security-config). |

## Providers

`providers.<name>` is a `ProviderConfigEntry`:

| Field | Type | Notes |
|---|---|---|
| `baseUrl` | `string \| string[]` | A single endpoint (default), or an array for round-robin, breaker-isolated, model-aware load balancing across replicas of the *same* backend. Normalize with `endpointsOf()`. |
| `api` | `"anthropic" \| "openai" \| "bedrock" \| "azure"` | Wire protocol. Mapped to an internal type by `toInternalApiType()`. |
| `headers` | `Record<string, string>` (optional) | Extra headers sent to this provider. |
| `auth` | `AuthConfig` (optional) | See below. |
| `region` | `string` (optional) | AWS region, for `api: "bedrock"` (e.g. `"us-gov-west-1"`). |
| `apiVersion` | `string` (optional) | Azure OpenAI REST api-version, for `api: "azure"`. Default `"2024-10-21"`. |
| `azureAuth` | `"api-key" \| "entra"` (optional) | Azure credential mode. Default `"api-key"`. |
| `entra` | `{ tenantId, clientId, clientSecretEnv, authority?, scope? }` (optional) | Required (tenantId/clientId/clientSecretEnv) when `azureAuth: "entra"`; validated at startup. `clientSecretEnv` names an env var — the secret itself is never stored in config. `authority`/`scope` default to commercial Azure; use the `.us` variants for Azure Government. |

`auth` (`AuthConfig`) resolves the provider's own upstream credential:

| Field | Meaning |
|---|---|
| `type: "env"` | `key` names the env var holding the credential. |
| `type: "profiles"` | `profilesPath` (default `~/.config/secrouter/upstream-auth.json`) — a JSON file of named credential profiles. |
| `type: "file"` | `filePath` holds the raw credential. |
| `type: "keychain"` | `service`/`account` — OS keychain lookup. |

## Tiers and models

`tiers` and `agenticTiers` map each classification tier (`SIMPLE` \|
`MEDIUM` \| `COMPLEX` \| `REASONING`) to a `TierMapping`:

```json
{ "primary": "provider/model-id", "fallback": ["provider/model-id", "..."] }
```

The router tries `primary`, then each `fallback` in order, on upstream
failure. Overriding `tiers`/`agenticTiers` in the config file replaces the
*whole* map for that key (`getRoutingConfig()` does a whole-block override,
not a per-tier merge).

### Model catalog entries

`models[]` entries overlay the hardcoded pricing/metadata registry
(`src/models.ts`) by `id` — config wins:

| Field | Type | Notes |
|---|---|---|
| `id` | `string` | `"provider/model-id"`. |
| `name` | `string` (optional) | Display name. |
| `inputPrice` / `outputPrice` | `number` (optional) | `$` per 1M tokens; default `0` (self-hosted compute has no per-token cost). |
| `contextWindow` / `maxOutput` | `number` (optional) | |
| `reasoning` / `vision` / `agentic` | `boolean` (optional) | Capability flags. |
| `kind` | `"chat" \| "embedding"` (optional, default `"chat"`) | The router never routes chat traffic to an `"embedding"` model. |
| `classification` | `string` (optional) | Informational only — the **egress allow-list** is what actually authorizes a destination for a classification, not this field. |

## Routing experiments

`experiments` (`ExperimentsConfig`) holds two independently-enabled
features. Both are **off by default** and validated **fail-loud** at
startup/reload by `router/config.ts`'s `validateExperimentsConfig` (called
alongside `validateSecurityConfig`) — an invalid block refuses to (re)load
rather than silently misrouting traffic. See
[`usage.md`](usage.md#routing-experiments) for how to actually run these.

### `experiments.split` — A/B routing

```json
{
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
```

| Field | Notes |
|---|---|
| `enabled` | Master switch for this feature. |
| `name` | Required when enabled. Echoed in the `X-SecRouter-Split` header, routing reasoning, and the `secrouter_split_assigned_total` metric. |
| `tiers.<TIER>.variants` | ≥ 2 entries required per tier listed. Each variant: `{ model: "provider/model", weight: number }` — `model` must match `provider/model` shape; `weight` must be `> 0`. Weights need not sum to 1 or 100; probability is `weight / sum(weights)`. |

Only tiers listed under `tiers` are split; an explicit-model request
(`tier === "EXPLICIT"`) is never split.

### `experiments.escalation` — draft/judge/escalate routing

```json
{
  "enabled": true,
  "fromTiers": ["SIMPLE"],
  "toTier": "MEDIUM",
  "judge": {
    "mode": "heuristic",
    "timeoutMs": 10000,
    "minDraftChars": 1
  }
}
```

| Field | Notes |
|---|---|
| `enabled` | Master switch. |
| `fromTiers` | Non-empty list of tiers eligible to be drafted-then-judged. |
| `toTier` | Escalation target; must **not** also appear in `fromTiers`. |
| `judge.mode` | `"heuristic"` (no extra LLM call — checks empty draft, `finishReason === "length"`, a refusal-pattern match, or too-short) or `"model"` (an LLM judge call; requires `judge.model`). |
| `judge.model` | Required when `mode: "model"`. `"provider/model"` form. Operator config only — never principal-selectable. |
| `judge.timeoutMs` | Default `10000`. Must be `> 0`. Judge timeout or error **fails open** (accepts the draft). |
| `judge.minDraftChars` | Default `1`. Must be `>= 0`. |
| `judge.refusalPatterns` | Optional array of regex source strings (case-insensitive) tested against heuristic-mode draft text; defaults to a built-in generic refusal/deflection list (`DEFAULT_REFUSAL_PATTERNS` in `router/escalation.ts`). |

Escalation only applies to **non-streaming** requests — the draft must be
judged before anything reaches the client, which is impossible once tokens
are already streaming out (`stream: true` bypasses escalation entirely).

## Security config

`security` (`SecurityConfig`, `src/security/types.ts`) is undefined/absent
by default — the router runs as a plain, unauthenticated dev proxy (with a
startup warning). Setting `security.enabled: true` turns on deny-by-default
auth and triggers the full `validateSecurityConfig` fail-closed check.

| Key | Type | Notes |
|---|---|---|
| `enabled` | `boolean` | Master switch. |
| `requireFips` | `boolean` (optional) | Require FIPS-validated crypto at startup; fails closed if unavailable. |
| `storePath` | `string` (optional) | SQLite file for accounting + audit. Default `~/.config/secrouter/secrouter.db`. |
| `cors` | `{ allowedOrigins: string[] }` (optional) | Empty/omitted = deny all cross-origin (default). |
| `oidc` | `OidcConfig` (optional) | See [OIDC](#oidc). Required when `enabled: true`. |
| `policy` | `{ default: PolicyRule; groups?; users? }` (optional) | See [Policy](#policy). |
| `audit` | `{ sink?, failClosed?, syslog?, retentionDays? }` (optional) | See [Audit](#audit). |
| `metrics` | `{ enabled: boolean; bearerEnvKey?: string }` (optional) | Prometheus `/metrics`. Off unless `enabled: true`; scrapers can't do OIDC, so guard with a static bearer or network placement. |
| `resilience` | `{ circuitThreshold?, cooldownSec?, healthIntervalSec? }` (optional) | Per-endpoint circuit breaker. Defaults: threshold `5`, cooldown `30`s, `healthIntervalSec: 0` (passive only). |
| `mcp` | `{ enabled: boolean; servers: McpServerConfig[] }` (optional) | Governed MCP tool gateway; see the README's MCP mention. `enabled: true` requires a non-empty `servers` list, each with `name`, a valid `url`, and non-empty `authorizedClassifications`. |
| `egress` | `{ allowlist: EgressRule[]; failClosed?: boolean }` (optional) | Deny-by-default upstream allow-list. Required non-empty when `enabled: true`. `failClosed` defaults `true`. |
| `tls` | `{ mode: "frontend" \| "native"; certPath?; keyPath?; minVersion?; ciphers? }` (optional) | `"frontend"` (recommended) = TLS terminated by a FIPS-validated proxy in front of SecRouter; `"native"` = SecRouter terminates TLS itself via `node:https` and requires `certPath`+`keyPath`. |
| `classification` | `{ default: string; levels: string[] }` (optional) | Ordered low→high classification ladder used by the egress gate and per-user `maxClassification`. `default` must be one of `levels`. |

### OIDC

| Field | Notes |
|---|---|
| `issuer` / `audience` | Required. Must match the token's `iss`/`aud`. |
| `jwksUri` | Optional; discovered from `${issuer}/.well-known/openid-configuration` if omitted. |
| `algorithms` | Default `["RS256","ES256"]`. `none` and any `HS*` (symmetric) algorithm are always rejected — validated at startup. |
| `groupsClaim` / `rolesClaim` | Dotted paths into the token, e.g. `"realm_access.roles"`. |
| `clockToleranceSec` | Clock skew tolerance for `exp`/`nbf`/`iat`. |
| `requireMfa` | Require `amr`/`acr` evidence of MFA. |
| `mfaAmrValues` | Default `["mfa","otp","hwk","swk","pop"]`. |
| `requiredAcr` | Minimum acceptable `acr` value. |
| `serviceSubjects` | Exact `sub` claims exempted from `requireMfa`/`requiredAcr` (non-interactive service clients). Array of non-empty strings; validated at startup. |
| `delegatingSubjects` | Exact `sub`s (normally also in `serviceSubjects`) trusted for on-behalf-of delegation — see `actingUserHeader` below. Array of non-empty strings; validated at startup. |
| `actingUserHeader` | Default `x-sec-acting-user`. Header a delegator forwards the acting end-user's id/email in. |
| `actingGroupsHeader` | Default `x-sec-acting-groups`. Comma/space-separated acting-user groups. |
| `trackJti` | Default off. Enforces single-use per `jti` — only turn on if your IdP issues one-time tokens. |
| `jwksCacheTtlSec` | Default `600`. |
| `clientId` / `scopes` | Public client id / OAuth scopes for the admin console's browser PKCE login. Default scopes `"openid profile email"`. |

### Policy

`policy.default` is the floor applied to every principal; `policy.groups`
(keyed by group name, matched against the principal's groups) and
`policy.users` (keyed by principal `sub`) layer on top. Each is a
`PolicyRule`:

| Field | Notes |
|---|---|
| `allowedTiers` | If set, only these tiers may be used. |
| `maxTier` | Hard ceiling tier. |
| `allowedModels` | If set, only these `provider/model` ids are permitted. |
| `deniedModels` | Applied after `allowedModels`. |
| `allowedTools` / `deniedTools` | MCP tools, namespaced `server/tool` (`server/*` wildcard). Default-deny: absent `allowedTools` ⇒ no tools. |
| `onViolation` | `"deny"` or `"downgrade"` when a routed model isn't permitted. |
| `budgets` | `Budget[]` — see below. |
| `maxClassification` | Highest data classification this principal may submit. |
| `admin` | Grants access to `/admin/*`, `/config`, `/reload*`. |

A `Budget` is `{ window: "minute"|"hour"|"day"|"month", maxRequests?,
maxInputTokens?, maxOutputTokens?, maxTotalTokens?, maxCostUsd? }` — a rolling
window cap enforced atomically; exceeding it returns `429`.

### Audit

| Field | Notes |
|---|---|
| `sink` | `"sqlite"` (default) or `"both"` to also forward to syslog/SIEM. |
| `failClosed` | Default `true` — fail the request if the audit write itself fails (AU 3.3.4). |
| `syslog` | `{ host, port, protocol?: "udp"\|"tcp", format?: "cef"\|"json" }`. |
| `retentionDays` | Days to retain `audit_log` rows before a daily background job prunes them (AU 3.3.1). **Default `0` = keep forever** (unchanged behavior). Must be a non-negative integer; validated at startup. See [Audit retention](usage.md#audit-retention) in the usage guide for how pruning preserves tamper-evidence. |

## Turnkey env vars

These auto-configure a self-hosted SecLLM inference pool without hand-editing
`providers`/`tiers`. All are strictly additive/no-op the moment you take
explicit ownership (define `providers.secllm` yourself, or route any tier to
`secllm/*`).

| Env var | Effect |
|---|---|
| `SECROUTER_SECLLM_ENDPOINTS` | Comma-separated base URLs. Auto-registers a pooled `secllm` provider (`baseUrl: string[]`) and turnkey-routes SIMPLE/MEDIUM/COMPLEX/REASONING (in both `tiers` and `agenticTiers`) to `secllm/<real-model-name>` (see `SECLLM_TIER_MODELS` in `config.ts`: SIMPLE→`Llama-3.2-3B-Instruct`, MEDIUM→`gemma-4-26B-A4B-it`, COMPLEX→`Llama-3.3-70B-Instruct`, REASONING→`gpt-oss-20b`), demoting whatever was previously primary into that tier's fallback. Routing + provider auth only — **never** touches `security.egress`. |
| `SECROUTER_SECLLM_TOKEN` | Bearer token for the turnkey `secllm` provider (resolved the same way any other provider's `auth: {type:"env"}` is). Unset = no `Authorization` header (open/unauthenticated SecLLM). |
| `SECROUTER_SECLLM_MODELS` | Comma-separated `tier=modelId` pairs (tier case-insensitive: `simple`/`medium`/`complex`/`reasoning`) overriding which real model id a tier binds to, for a pool serving a different catalog. Unknown tiers/malformed pairs are skipped with a warning. Only applies alongside `SECROUTER_SECLLM_ENDPOINTS`. |
| `SECROUTER_EGRESS_FILE` | Path to a JSON file containing an **array** of `EgressRule` objects (same shape as `security.egress.allowlist[]`). Loaded on every config (re)load and merged **additively** into `security.egress.allowlist` (dedup'd by provider+host, never removing an existing rule). A missing/unreadable/malformed file is a **hard startup/reload failure**. Every successful load emits an `egress.file_loaded` audit event. |
| `SECROUTER_PROBE_ALLOW_HOSTS` | Comma-separated hosts/suffixes the admin console's "add endpoint" probe (SSRF-guarded) is allowed to reach beyond its built-in in-boundary heuristics (loopback, single-label service names, `.internal`/`.local`/`.lan`/`.corp`/`.mil`/`.gov`/etc., RFC1918 ranges). |

## Other env vars

| Env var | Default | Notes |
|---|---|---|
| `SECROUTER_CONFIG` (or legacy `FREEROUTER_CONFIG`) | — | Explicit config file path; takes priority over the cwd/home search. |
| `SECROUTER_PORT` | `18800` (or config `port`) | Overrides the listen port. |
| `SECROUTER_HOST` | `127.0.0.1` (or config `host`) | Overrides the listen host. |
| `SECROUTER_MAX_BODY_BYTES` | `10485760` (10 MiB) | Max request body size accepted. |
| `SECROUTER_ANOMALY_TOKENS` | `300000` | Per-request token count above which an `anomaly` audit event is emitted. |
