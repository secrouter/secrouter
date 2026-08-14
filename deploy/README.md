# SecRouter — Test Deployment

A self-contained, **secured** test stack: the real SecRouter (OIDC auth, per-user
policy/quotas, egress control, audit) wired to a **mock IdP** and a **mock model**,
so you can exercise the whole thing without a real IdP or AWS GovCloud.

> ⚠️ **Test only — not for CUI.** FIPS is off, TLS is left to an (absent) front
> end, and the upstreams are mocks. For production start from
> [`../secrouter.config.hardened.example.json`](../secrouter.config.hardened.example.json)
> and the [deployment hardening guide](../docs/compliance/deployment-hardening.md).

## What's in the stack

| Service | Role | Port |
|---|---|---|
| `secrouter` | the gateway, secured (`secrouter.config.test.json`) | `18800` |
| `mock-oidc` | issues real RS256 JWTs; discovery + JWKS + **PKCE** + `/mint` | `8081` |
| `mock-llm` | OpenAI-compatible echo with token usage | (internal) |

## Quick start (Docker)

```bash
cd deploy
docker compose -f docker-compose.test.yml up --build
# in another shell:
./smoke-test.sh
```

Expected smoke output: `401` without a token, `200` with one, a chat reply from
the mock model, usage recorded, and `admin=200 / basic=403` on the admin API.

Then open the console at **http://localhost:18800/admin** → "Sign in with SSO" →
pick a persona (**Admin**, **Power user**, or **Basic user**) on the mock IdP page.
The PKCE flow completes and drops you into the console as that identity.

## Adding a model endpoint from the console

As **Admin**, open the **Models** tab → *Add a local / on-prem endpoint*. Point it
at the mock model (`http://mock-llm:8080/v1`), **Test endpoint** to discover its
models, pick one (price it or leave `0`), choose a classification, then
**Validate → Apply → Reload**. The change is written to the live config file and
the new provider routes immediately.

This works because the stack now keeps the live config on the **writable**
`secrouter-data` volume (seeded once from `secrouter.config.test.json`), and the
`secrouter` service has `restart: unless-stopped` so the **Restart** button comes
back. A read-only single-file mount would block the writer; `docker compose down -v`
(or `docker volume rm secrouter-test_secrouter-data`) resets to the template.

## Getting a token by hand

```bash
./get-token.sh admin        # or: power | basic
curl -H "Authorization: Bearer $(./get-token.sh admin)" http://localhost:18800/v1/usage
```

## Personas (mock IdP)

| Persona | groups | Can do |
|---|---|---|
| `admin` | `secrouter-admins` | everything + the admin console |
| `power` | `secrouter-power-users` | all tiers (incl. COMPLEX/REASONING) |
| `basic` | *(none)* | default policy only (SIMPLE/MEDIUM) |

## Run the image standalone (no compose)

```bash
docker build -t secrouter:test ..
docker run --rm -p 18800:18800 \
  -e SECROUTER_CONFIG=/etc/secrouter/config.json -e SECROUTER_HOST=0.0.0.0 \
  -e LOCAL_LLM_API_KEY=test-key \
  -v "$PWD/secrouter.config.test.json:/etc/secrouter/config.json:ro" \
  -v secrouter-data:/var/lib/secrouter \
  secrouter:test
```
(You still need the mock IdP/model reachable, or point the config at real ones.)

## Run without Docker (Node)

```bash
cd .. && npm ci && npm run build            # -> dist/server.js
# terminal 1: PORT=9081 EXTERNAL_ISSUER=http://localhost:9081 node deploy/mock-oidc/server.mjs
# terminal 2: PORT=9082 node deploy/mock-llm/server.mjs
# terminal 3: SECROUTER_CONFIG=<a localhost-wired config> SECROUTER_PORT=9080 \
#             LOCAL_LLM_API_KEY=test node dist/server.js
```
(Use localhost URLs for `oidc.issuer`/`jwksUri`, the `local` provider `baseUrl`,
and the egress `allowedHost`.)

## Non-container (systemd)

Build, drop `dist/` at `/opt/secrouter`, install [`secrouter.service`](secrouter.service)
to `/etc/systemd/system/`, put the config at `/etc/secrouter/config.json` and
secrets in `/etc/secrouter/secrets.env`, then `systemctl enable --now secrouter`.

## Promoting to a real deployment

1. Swap the config for a copy of `secrouter.config.hardened.example.json`.
2. Point `oidc` at your enterprise IdP; register the console as a public PKCE
   client (redirect URI = `https://<host>/admin`). Keep `trackJti` **off**
   (standard access tokens are multi-use).
3. Replace the `local` provider + egress allow-list with **Bedrock GovCloud**
   (and/or in-boundary self-hosted models); supply `AWS_*` credentials.
4. Set `requireFips: true` and terminate TLS at a FIPS-validated front end
   (`tls.mode: "frontend"`).
5. Point `audit.sink` at your SIEM; put `storePath` on an encrypted volume.
6. (Optional) enable `security.metrics` for Prometheus at `GET /metrics` — set
   `bearerEnvKey` (scrapers can't do OIDC) and scrape from inside the enclave.
7. Run `npm run test:security` + `npm run test:integration` on the built artifact.
