---
name: secrouter
description: Self-hosted secure AI gateway. Routes every request to the cheapest capable model across your approved providers (OpenAI on AWS Bedrock GovCloud, Azure OpenAI, self-hosted) — OIDC-authenticated, policy-governed, cost-tracked, and audited. OpenAI-compatible.
homepage: https://github.com/secrouter/secrouter
metadata: { "openclaw": { "emoji": "🛡️", "requires": { "config": ["providers", "security"] } } }
---

# SecRouter

A self-hosted, OpenAI-compatible gateway that puts every AI request under your control:
**governance** (who may use which model, deny-by-default egress, hash-chained audit, data that
never leaves your boundary) and **cost control** (per-user token & dollar tracking, budgets, and
smart routing to the cheapest capable model). Built for regulated environments — mapped to
NIST SP 800-171 R2 + 800-172 (CMMC Level 3).

## Install

You host it. Run the container image or build from source, then point any OpenAI client at it:

```bash
git clone https://github.com/secrouter/secrouter.git
cd secrouter && npm install && npm run build && npm start
# → http://localhost:18800   (turn on the security block for any real deployment)
```

## Use

```bash
# OpenAI-compatible — "auto" lets the classifier pick the cheapest capable model
curl http://localhost:18800/v1/chat/completions \
  -H "Authorization: Bearer $SECROUTER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"auto","messages":[{"role":"user","content":"Hello!"}]}'
```

Override the tier inline when you know better — the prefix is stripped before forwarding:

```
/simple  What's 2+2?
/max     Analyze this distributed system for race conditions
```

| Aliases | Tier |
|---|---|
| `simple`, `basic`, `cheap` | SIMPLE |
| `medium`, `balanced` | MEDIUM |
| `complex`, `advanced` | COMPLEX |
| `max`, `reasoning`, `think`, `deep` | REASONING |

## How routing works

SecRouter classifies each request into a tier and routes to the cheapest capable model in that
tier, failing over to the next model on upstream faults:

- **SIMPLE** — factual lookups, greetings, translations → `bedrock/openai.gpt-oss-20b`
- **MEDIUM** — summaries, explanations, extraction → `bedrock/openai.gpt-oss-120b`
- **COMPLEX** — code generation, multi-step analysis → `bedrock/openai.gpt-oss-120b`
- **REASONING** — proofs, formal logic, multi-step math → `bedrock/openai.gpt-oss-120b` (or `azure/o4-mini`)

Rules resolve most requests in <1 ms; only ambiguous queries hit the classifier. Every tier target
is configurable, and moving a tier between **OpenAI-on-Bedrock (GovCloud)** and **Azure OpenAI** is
a one-line change — both speak the OpenAI API.

## Providers

Deny-by-default — only approved destinations are reachable:

- **AWS Bedrock GovCloud** — OpenAI frontier models (`gpt-oss-120b`, `gpt-oss-20b`); FedRAMP High / IL4-5.
- **Azure OpenAI (AI Foundry)** — `gpt-4o`, `gpt-4o-mini`, `o4-mini`; `api-key` or Microsoft Entra auth.
- **Self-hosted** — any OpenAI-compatible endpoint inside your boundary.

## What you get

- **OIDC/SSO auth** on every route (deny-by-default), MFA enforced.
- **Per-user policy & budgets** — allowed tiers/models per group; daily/monthly cost caps (over budget → `429`).
- **Hash-chained audit** — tamper-evident, CUI-safe (metadata only); one-call integrity verify + one-click evidence bundle for assessors.
- **Governed embeddings & tool-calling** — `POST /v1/embeddings` and a `POST /mcp` tool gateway under the same auth, policy, egress, and audit controls.
- **Observability** — Prometheus `/metrics`, per-user cost visibility, and a dependency-free admin console at `/admin`.

## Example output

```
[SecRouter] bedrock/openai.gpt-oss-20b (SIMPLE, rules, confidence=0.92)
            user=alice@example.mil · tokens=412 · cost=$0.0006 · audited
```

## License

Apache 2.0. Source: https://github.com/secrouter/secrouter
