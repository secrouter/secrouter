# SecRouter — CMMC Level 3 Control Matrix

Maps the SecRouter LLM gateway to **NIST SP 800-171 Rev 2** (CMMC L2, 110 reqs) plus selected **NIST SP 800-172** enhancements (CMMC L3). This is *application-layer* evidence for your System Security Plan (SSP) — it covers what the software enforces, not the surrounding enclave (see [Shared Responsibility](#shared-responsibility)).

> **Regulatory note (verify at assessment time):** CMMC 32 CFR Part 170 effective 2024‑12‑16; DFARS 48 CFR rule effective 2025‑11‑10; L2/L3 assessed against **800‑171 Rev 2** (Rev 3 transition is later rulemaking). Claude is CUI‑authorized **only via Amazon Bedrock in AWS GovCloud (US)** (FedRAMP High / IL4‑5).

Status legend: ✅ enforced in code · ⚙️ configurable · 🤝 shared (needs enclave/process).

## 3.1 Access Control (AC)

| Control | Requirement | Implementation | Evidence |
|---|---|---|---|
| 3.1.1 / 3.1.2 | Limit system access to authorized users / transactions | Deny‑by‑default OIDC auth on every route except `/health`; admin routes gated by role | `src/server.ts` (`handleRequest`, `requireAdmin`), `src/security/identity/` |
| 3.1.3 | **Control the flow of CUI** | Egress allow‑list + per‑request data‑classification gate; deny‑by‑default at the network choke point | `src/security/egress/allowlist.ts`, `src/provider.ts` (`forwardRequest`) |
| 3.1.5 | Least privilege | Per‑group/per‑user policy: allowed tiers, model allow‑list, `maxTier`, per‑user lockdown below the org default | `src/security/policy/engine.ts` (`resolvePolicy`, `authorize`) |
| 3.1.10 / 3.1.11 | Session lock / termination | Short‑lived JWTs; `exp`/`nbf` enforced with bounded clock skew; expired tokens rejected | `src/security/identity/oidc.ts` |
| 3.1.12 / 3.1.13 | Control & encrypt remote access | TLS for all transport (front‑end mTLS/CAC or native FIPS TLS); CORS deny‑by‑default | `src/security/transport/tls.ts`, `applyCors` |
| **3.1.3e** (172) | Enhanced CUI flow enforcement | Classification‑labeled destinations; a request above the principal's clearance is denied before egress | `engine.ts` clearance check, `egress/allowlist.ts` |

## 3.3 Audit & Accountability (AU)

| Control | Requirement | Implementation | Evidence |
|---|---|---|---|
| 3.3.1 | Create & retain audit records | Structured events for auth, authz, routing, egress, usage, admin, quota, anomaly, errors | `src/security/audit/audit.ts`, `store/sqlite.ts` |
| 3.3.2 | Trace actions to individual users | Every event carries `principalId` (OIDC `sub`), `requestId`, `sourceIp` | `audit.ts` event builders |
| 3.3.4 | Alert on audit failure | Fail‑closed auditor: request rejected if the audit write fails | `Auditor.emit` (`failClosed`) |
| 3.3.5 | Correlate audit review | Per‑request UUID correlates routing → usage; `/admin/usage` rollups | `server.ts` (`X-Request-Id`), `handleUsageAdmin` |
| 3.3.7 | Authoritative, time‑synced timestamps | UTC ISO‑8601 on every record (host NTP — 🤝) | `store/sqlite.ts` `appendAudit` |
| 3.3.8 | **Protect audit information** | SHA‑256 **hash chain** (tamper‑evident); `verifyAuditChain()` detects any mutation | `store/sqlite.ts` (`chainHash`, `verifyAuditChain`) |
| 3.3.9 | Limit audit management to a subset | Audit/stats/config endpoints require admin role | `requireAdmin` |
| **3.3.x e** (172) | SIEM / SOC integration | Optional syslog/CEF forwarding of every event | `src/security/audit/syslog.ts` |
| — | **CUI‑safe logging** | Audit records metadata only (token counts, model ids, decisions, hashes) — never prompt/response content | `audit.ts` header contract |

## 3.5 Identification & Authentication (IA)

| Control | Requirement | Implementation | Evidence |
|---|---|---|---|
| 3.5.1 / 3.5.2 | Identify & authenticate users | OIDC JWT validation (signature via JWKS, `iss`/`aud`/`exp`/`nbf`) | `src/security/identity/oidc.ts` |
| 3.5.3 | **Multifactor authentication** | Token must evidence MFA via `amr`/`acr`; rejected otherwise (MFA performed at IdP) | `oidc.ts` MFA assertion |
| 3.5.4 | Replay‑resistant authentication | Short‑lived signed tokens over TLS + audience binding (verified `exp`/`nbf`/`aud`/sig). Optional single‑use `jti` cache for one‑time‑token schemes only; DPoP is the future sender‑constrained option. | `oidc.ts`, `store/sqlite.ts` |
| 3.5.7 / 3.5.10 | Password complexity / cryptographically‑protected secrets | No passwords in SecRouter (delegated to IdP); no secrets logged; `/config` redacts | `config.ts` (`getSanitizedConfig`) |
| — | Alg‑confusion defense | `none`/HMAC algorithms rejected at config‑validation and verification time | `config.ts` `validateSecurityConfig`, `oidc.ts` |

## 3.13 System & Communications Protection (SC)

| Control | Requirement | Implementation | Evidence |
|---|---|---|---|
| 3.13.1 / 3.13.5 | Boundary protection / subnet separation | App binds localhost behind a front‑end; egress confined to allow‑listed hosts | 🤝 enclave + `egress/allowlist.ts` |
| 3.13.6 | **Deny network traffic by default** | Egress allow‑list is deny‑by‑default; unlisted provider/host blocked | `egress/allowlist.ts` |
| 3.13.8 | Encrypt CUI in transit | TLS for inbound (front‑end/native) and HTTPS to GovCloud/local upstreams | `transport/tls.ts`, provider fetch |
| 3.13.11 | **FIPS‑validated cryptography** | `assertFips()` fail‑closed when `requireFips`; FIPS cipher policy; jose/SigV4 use node:crypto (inherits validated OpenSSL) | `transport/tls.ts`, `transport/sigv4.ts` |
| 3.13.15 | Session authenticity | Signed JWTs; per‑request id; TLS session integrity | `oidc.ts`, `transport/tls.ts` |

## 3.14 System & Information Integrity (SI)

| Control | Requirement | Implementation | Evidence |
|---|---|---|---|
| 3.14.1 | Flaw remediation | Minimal vetted deps (`jose`, `node:sqlite`); pinned versions; `npm audit`/SBOM in CI (🤝) | `package.json` |
| 3.14.6 | Monitor for attacks / unauthorized use | Body‑size + structural input validation; non‑leaking errors; anomaly events on outsized requests | `server.ts` (`validateChatRequest`, `readBody`), `recordUsageAndAudit` |
| **3.14.6e** (172) | Threat‑aware automated monitoring | Per‑request anomaly detection → audit/SIEM; per‑user rate limits | `server.ts` anomaly hook, `accounting/quota.ts` |

## 3.4 Configuration Management (CM)

| Control | Requirement | Implementation | Evidence |
|---|---|---|---|
| 3.4.1 / 3.4.2 | Baseline config / enforce settings | Versioned `freerouter.config.hardened.example.json`; startup validation refuses unsafe boot | `config.ts` `validateSecurityConfig` |
| 3.4.6 | Least functionality | `/health` minimized; stats/config/reload admin‑only; reload re‑validates (no unsafe hot‑swap) | `server.ts` (`handleHealth`, `handleReloadConfig`) |
| 3.4.7 | Disable nonessential services | Only the documented endpoints exist; Kimi/Moonshot (PRC) removed from all defaults | `server.ts`, `config.ts`, `models.ts` |
| 3.4.x | Change control on policy edits | Admin-console edits go through an audited DB-overrides layer, re-validated (fail-closed) and applied over the file baseline; every change is an audit event (`override.put`/`override.delete`). Providers + egress stay file-managed. | `src/security/overrides.ts`, `server.ts` `/admin/api/*` |

## Shared Responsibility

SecRouter enforces the application layer. The accreditation boundary must also provide:

- **Enclave / network** (3.13.1/3.1.x): run in AWS GovCloud IL4‑5 or an air‑gapped enclave; host‑based firewall; segmentation.
- **FIPS module** (3.13.11): a Node build linked to a CMVP‑validated OpenSSL FIPS provider, **or** a FIPS‑validated TLS front end (recommended) — then set `tls.mode="frontend"`.
- **IdP** (3.5.3): enterprise OIDC IdP (Keycloak/Okta/Entra/Ping) backed by your LDAP/AD, enforcing MFA/CAC and emitting `amr`/`acr`/`groups`.
- **NTP** (3.3.7), **log retention/review** (3.3.x), **SIEM** (point `audit.syslog` at it), **vuln mgmt / SBOM** (3.14.1), **incident response** (DFARS 7012 72‑hr reporting), **media protection** (encrypt `storePath` volume at rest).

## Verification

```bash
npm run build && npm run test:security        # 36 unit assertions across auth/authz/quota/egress/sigv4
npx tsx test/security/e2e.test.ts             # full secured pipeline (401/200/quota/streaming-usage/admin)
npx tsx test/security/admin.test.ts           # admin API: gating + DB overrides take effect live
```

Audit integrity can be re‑verified at any time via `Store.verifyAuditChain()` (any tampered row is reported by id).
