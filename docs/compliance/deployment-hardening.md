# SecRouter — CMMC Deployment Hardening Guide

How to deploy SecRouter so it processes CUI within a CMMC Level 3 boundary. Pair with [cmmc-control-matrix.md](cmmc-control-matrix.md).

## Reference architecture

```
 CAC/PIV or SSO              FIPS-validated front end                 SecRouter                 Authorized upstreams
 ───────────────►  mTLS / OIDC login  ──►  TLS term + reverse proxy ──►  :18800 (localhost) ──►  Bedrock GovCloud (FedRAMP High/IL4-5)
   user / client          (Apache+SSSD,        passes Bearer JWT          OIDC verify, policy,    Self-hosted vLLM/TGI (in boundary)
                          oauth2-proxy,        + X-Forwarded-For          quotas, egress gate,        ▲
                          or API gateway)                                 hash-chained audit          └ deny-by-default; nothing else reachable
```

**Trust boundary choice (FIPS, SC 3.13.11):**
- **Recommended — `tls.mode: "frontend"`.** A FIPS‑validated proxy terminates TLS (and mTLS/CAC). SecRouter binds `127.0.0.1` and is *not* the crypto boundary. Simplest path to a clean assessment.
- **Alternative — `tls.mode: "native"`.** SecRouter terminates TLS via `node:https`. Only compliant when Node links a **CMVP‑validated OpenSSL FIPS provider** (`--force-fips` / `openssl.cnf fips=yes`); set `certPath`/`keyPath`. `assertFips()` fails the boot otherwise.

## 1. Prerequisites

- Node ≥ 24 (uses built‑in `node:sqlite`); for native FIPS, a FIPS‑linked Node build.
- An enterprise **OIDC IdP** (Keycloak/Okta/Entra/Ping) federated to your LDAP/AD, configured to:
  - issue tokens with `aud: secrouter`, an MFA indicator (`amr`/`acr`), and a `groups` claim mirroring AD groups;
  - enforce MFA/CAC at login.
- A FedRAMP/IL path to models: **AWS GovCloud Bedrock** credentials (IAM role preferred) and/or a **self‑hosted** OpenAI‑compatible model inside the boundary.

## 2. Configure

```bash
cp freerouter.config.hardened.example.json /etc/secrouter/config.json
# replace every <PLACEHOLDER>; set issuer/jwksUri/audience, egress hosts, policy groups, SIEM host
export FREEROUTER_CONFIG=/etc/secrouter/config.json
```

Key blocks (see the example file): `oidc`, `policy` (tiers/models/budgets per group + per‑user lockdown), `egress.allowlist` (deny‑by‑default; **only** GovCloud/local hosts), `classification`, `audit` (SIEM), `tls`, `requireFips`.

The server **fail‑closes**: invalid security config or `requireFips` without FIPS → it refuses to start.

## 3. Credentials (never in config or logs)

- **Bedrock GovCloud:** standard AWS env / instance profile — `AWS_REGION` (or `providers.bedrock.region`), `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`. Prefer an IAM role over static keys.
- **Self‑hosted model:** `providers.local.auth = {type:"env", key:"LOCAL_LLM_API_KEY"}`; set that env var.

## 4. systemd unit (least privilege)

`/etc/systemd/system/secrouter.service`:

```ini
[Unit]
Description=SecRouter LLM gateway
After=network-online.target

[Service]
ExecStart=/usr/bin/node /opt/secrouter/dist/server.js
Environment=FREEROUTER_CONFIG=/etc/secrouter/config.json
EnvironmentFile=/etc/secrouter/secrets.env        # AWS_*, LOCAL_LLM_API_KEY (chmod 600)
User=secrouter
Group=secrouter
# Hardening (CM 3.4.6/3.4.7)
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/secrouter
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6
SystemCallFilter=@system-service
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`install -d -o secrouter -g secrouter -m 700 /var/lib/secrouter` — holds `secrouter.db` (audit + ledger). **Encrypt this volume at rest** (MP/SC).

## 5. Container (rootless, read‑only)

```dockerfile
FROM node:24-slim
WORKDIR /opt/secrouter
COPY package*.json ./
RUN npm ci --omit=dev
COPY dist ./dist
USER 10001:10001
ENTRYPOINT ["node","dist/server.js"]
```

Run read‑only with a writable volume for the DB:
```bash
podman run --read-only -v secrouter-data:/var/lib/secrouter:Z \
  --cap-drop=ALL --security-opt no-new-privileges \
  -e FREEROUTER_CONFIG=/etc/secrouter/config.json secrouter:latest
```

## 6. Reverse proxy (TLS + identity)

Terminate TLS/mTLS at a FIPS‑validated front end; forward to `127.0.0.1:18800`, passing the Bearer JWT and `X-Forwarded-For` (SecRouter trusts XFF only when `tls.mode="frontend"`). With CAC/PIV, terminate the client cert at the proxy and exchange it for an OIDC token (token‑broker pattern), or have the proxy assert identity into a JWT your IdP signs.

## 7. Client integration (CLI / SDK)

Machine clients use the OIDC **client‑credentials** grant (no separate API key system):

```jsonc
// client config (OpenAI-compatible)
{
  "providers": { "secrouter": { "baseUrl": "https://secrouter.example.mil", "api": "openai-completions",
    "headers": { "Authorization": "Bearer ${SECROUTER_TOKEN}" }, "models": [{ "id": "auto" }] } },
  "agents": { "defaults": { "model": "secrouter/auto" } }
}
```

Obtain `SECROUTER_TOKEN` from the IdP token endpoint and refresh before `exp`. Optional: send `X-Data-Classification: CUI` (capped by the caller's clearance).

## 7a. Admin console (`GET /admin`)

A web UI for usage monitoring and live policy/model configuration, served by the router itself behind the same boundary. The page shell and `GET /admin/oidc` are public; all data and mutation endpoints (`/admin/api/*`) require the **admin** role.

- **Browser auth (OIDC PKCE):** register a **public** OIDC client in your IdP for the console — `clientId` = `security.oidc.clientId`, **redirect URI** = the console URL (e.g. `https://secrouter.example.mil/admin`), grant type Authorization Code + PKCE, scopes `openid profile email groups`. No client secret. Admins reach `/admin` through the same FIPS/SSO front end as the API.
- **Authorization:** a console user must resolve to a policy with `admin: true` (e.g. membership in `secrouter-admins`).
- **What's editable:** group/user policies (tiers, models, budgets, classification, admin) and tier→model routing. Edits are written to the **audited DB overrides** layer (`config_overrides`) and applied live (`override.put`/`override.delete` audit events). Providers and the **egress allow-list are read-only** in the UI — they stay file-managed for change control. The file config remains the baseline; overrides layer on top and are re-validated (fail-closed) before taking effect.

## 8. Operate

- **Usage / cost:** `GET /v1/usage` (self), `GET /admin/usage?groupBy=principal|model|day&days=N` (admin).
- **Audit integrity:** periodically assert `Store.verifyAuditChain().ok`; alert on any `brokenAtId`.
- **SIEM:** set `audit.sink:"both"` + `audit.syslog`; alert on `auth.failure`, `authz.deny`, `egress.deny`, `quota.exceeded`, `anomaly`.
- **Config changes:** edit config → `POST /reload-config` (admin; re‑validates, fail‑closed) or restart.
- **Incident response:** DFARS 252.204‑7012 requires 72‑hour reporting; preserve `secrouter.db` + SIEM for ≥90 days.

## 9. Pre‑assessment checklist

- [ ] `security.enabled: true`, `requireFips: true`, FIPS front end or FIPS Node verified
- [ ] Egress allow‑list contains **only** GovCloud/in‑boundary hosts; **no** commercial `api.anthropic.com`, **no** Kimi/Moonshot
- [ ] OIDC enforces MFA; `requireMfa: true`; `trackJti: true`
- [ ] CORS `allowedOrigins` empty or explicit; admin endpoints role‑gated
- [ ] `storePath` on an encrypted volume; SIEM forwarding live; NTP synced
- [ ] `npm run test:security` and `e2e.test.ts` pass on the built artifact
- [ ] Bedrock GovCloud authorized model list re‑verified in the console
