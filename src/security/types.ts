/**
 * SecRouter Security — shared types
 *
 * Pure type declarations with ZERO runtime imports, so any module
 * (including config.ts) can import these without creating a require cycle.
 *
 * Threaded through the request lifecycle:
 *   AuthN (identity) -> AuthZ (policy) -> classifier -> egress gate -> upstream
 *                                   \-> accounting (usage/ledger/quota)
 *   audit wraps the whole pipeline.
 */

// ─── Identity (Feature 1) ───

/** An authenticated caller, derived from a validated OIDC token. */
export type Principal = {
  /** Stable unique id — the OIDC `sub` claim. */
  id: string;
  email?: string;
  displayName?: string;
  /** Group memberships (reflecting LDAP/AD groups surfaced as token claims). */
  groups: string[];
  /** Roles, if the IdP issues a separate roles claim. */
  roles: string[];
  /** Whether the token evidences multi-factor authentication (IA 3.5.3). */
  mfa: boolean;
  /** Epoch seconds the IdP asserts authentication occurred (`auth_time`). */
  authTime?: number;
  /** Token id (`jti`) for replay tracking (IA 3.5.4). */
  jti?: string;
  /** Raw validated claims (metadata only — never logged as CUI). */
  claims: Record<string, unknown>;
};

/** Pluggable authentication mechanism. Returns null when no credential is present. */
export interface IdentityProvider {
  readonly name: string;
  authenticate(headers: Record<string, string | string[] | undefined>): Promise<Principal | null>;
}

export type OidcConfig = {
  /** Token issuer; must match the `iss` claim exactly. */
  issuer: string;
  /** Expected audience; the `aud` claim must contain this. */
  audience: string;
  /** JWKS URL. If omitted, discovered from `${issuer}/.well-known/openid-configuration`. */
  jwksUri?: string;
  /** Allowed signature algorithms. `none` and HMAC are always rejected. */
  algorithms?: string[]; // default ["RS256","ES256"]
  /** Dotted path to the groups claim, e.g. "groups" or "realm_access.roles". */
  groupsClaim?: string;
  /** Dotted path to the roles claim. */
  rolesClaim?: string;
  /** Clock skew tolerance in seconds for exp/nbf/iat checks. */
  clockToleranceSec?: number;
  /** Require the token to evidence MFA (via `amr`/`acr`). */
  requireMfa?: boolean;
  /** `amr` values that count as MFA (default ["mfa","otp","hwk","swk","pop"]). */
  mfaAmrValues?: string[];
  /** Minimum acceptable `acr` value, if your IdP uses acr levels. */
  requiredAcr?: string;
  /**
   * Enforce SINGLE-USE per `jti` (replay cache). Default off. WARNING: standard
   * OIDC access tokens are multi-use bearer tokens — enabling this rejects the
   * second request that reuses a token, so only turn it on if your IdP issues
   * one-time tokens. Replay resistance for normal bearer tokens comes from short
   * TTL + TLS + signature (IA 3.5.4); DPoP/sender-constrained tokens are the
   * stronger future option.
   */
  trackJti?: boolean;
  /** JWKS cache TTL in seconds (default 600). */
  jwksCacheTtlSec?: number;
  /** Public client id for the admin console's browser PKCE login flow. */
  clientId?: string;
  /** OAuth scopes the admin console requests (default "openid profile email"). */
  scopes?: string;
};

// ─── Policy / authorization (Feature 2) ───

export type Tier = "SIMPLE" | "MEDIUM" | "COMPLEX" | "REASONING";

export type BudgetWindow = "minute" | "hour" | "day" | "month";

/**
 * A spend/rate limit over a rolling time window. Unifies quotas and rate
 * limiting: an rpm cap is `{window:"minute", maxRequests}`; a tpm cap is
 * `{window:"minute", maxTotalTokens}`; a daily cost cap is
 * `{window:"day", maxCostUsd}`.
 */
export type Budget = {
  window: BudgetWindow;
  maxRequests?: number;
  maxInputTokens?: number;
  maxOutputTokens?: number;
  maxTotalTokens?: number;
  maxCostUsd?: number;
};

/** Policy as authored in config (per group or per user). All fields optional. */
export type PolicyRule = {
  /** If set, only these tiers may be used. */
  allowedTiers?: Tier[];
  /** Hard ceiling tier (a request routed above it is capped). */
  maxTier?: Tier;
  /** If set, ONLY these provider/model ids are permitted (allow-list). */
  allowedModels?: string[];
  /** Explicitly denied provider/model ids (applied after allowedModels). */
  deniedModels?: string[];
  /**
   * MCP tools this principal may use, namespaced `server/tool` (with a `server/*`
   * wildcard). Phase D. DEFAULT-DENY: absent ⇒ no tools (stricter than models).
   */
  allowedTools?: string[];
  /** Explicitly denied tools (applied after allowedTools; deny wins). */
  deniedTools?: string[];
  /** What to do when a routed model is not permitted. */
  onViolation?: "deny" | "downgrade";
  budgets?: Budget[];
  /** Highest data classification this principal may submit. */
  maxClassification?: string;
  /** Grants access to admin endpoints (/config, /reload*, /admin/*). */
  admin?: boolean;
};

/** Fully resolved policy for a principal (defaults applied, groups merged). */
export type EffectivePolicy = {
  allowedTiers: Tier[];
  maxTier: Tier | null;
  allowedModels: string[] | null; // null = no allow-list restriction
  deniedModels: string[];
  allowedTools: string[] | null; // null = NO tools (default-deny, Phase D)
  deniedTools: string[];
  onViolation: "deny" | "downgrade";
  budgets: Budget[];
  maxClassification: string;
  admin: boolean;
  /** Names of the group policies that contributed (for audit). */
  sources: string[];
};

export type AuthzDecision = {
  effect: "allow" | "downgrade" | "deny";
  model: string;
  tier: string;
  reason: string;
};

// ─── Accounting (Feature 2) ───

/** Token usage extracted from an upstream response (streaming or not). */
export type UsageResult = {
  provider: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
};

/** A single ledger row (one per completed request). */
export type UsageRecord = {
  ts: string; // ISO-8601 UTC
  requestId: string;
  principalId: string;
  groups: string; // JSON array string
  provider: string;
  model: string;
  tier: string;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  costUsd: number;
  outcome: string; // ok | error | timeout
};

export type UsageAggregate = {
  requestCount: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  costUsd: number;
};

export type UsageBreakdownRow = {
  key: string; // model id, principal id, or day, depending on groupBy
  requestCount: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
};

// ─── Egress / data residency (Feature 3) ───

/** One upstream allow-list entry. Deny-by-default: only listed providers reach the network. */
export type EgressRule = {
  provider: string;
  /**
   * Exact host(s) this provider is permitted to reach. A single host (today's
   * default), or an array to authorize every endpoint host of a pooled
   * provider (see `config.ProviderConfigEntry.baseUrl: string[]` /
   * `config.endpointsOf`) under one rule — e.g. a multi-replica on-prem
   * vLLM/SecLLM cluster. `checkEgress` matches ANY host in the list. This
   * type never derives `allowedHost` from a provider's `baseUrl` on its own —
   * egress authorization is a human compliance decision (which hosts, for
   * which classifications) and must stay explicit: hand-authored directly in
   * `security.egress.allowlist`, or merged in from an operator-supplied
   * `SECROUTER_EGRESS_FILE` (config.ts applyEgressFileIntake) — never
   * inferred from provider/routing config.
   */
  allowedHost: string | string[];
  /** Data classifications this destination is authorized to receive. */
  authorizedClassifications: string[];
  /** FedRAMP/IL note for the audit trail (e.g. "Bedrock GovCloud — FedRAMP High / IL4-5"). */
  authorization?: string;
};

export type EgressDecision = {
  allowed: boolean;
  reason: string;
  rule?: EgressRule;
};

/**
 * A registered upstream MCP server (Phase D). Same shape philosophy as an egress
 * rule: a named destination with the classifications it is authorized to receive.
 * `url` must resolve to an in-boundary host (SSRF discipline).
 */
export type McpServerConfig = {
  name: string;
  /** Streamable-HTTP MCP endpoint, e.g. http://mcp.internal:9000/mcp */
  url: string;
  /** Classifications this server may receive (deny-by-default gate). */
  authorizedClassifications: string[];
  /** Optional bearer token, resolved from this env var at call time; never stored. */
  authEnvKey?: string;
  /** Human-readable authorization note (mirrors EgressRule.authorization). */
  authorization?: string;
};

// ─── Audit (Feature 3) ───

export type AuditInput = {
  type: string; // auth.success | auth.failure | authz.deny | authz.downgrade | route.decision | egress.deny | egress.file_loaded | usage | admin.action | config.reload | provider.circuit | tool.call | tool.deny | error | anomaly
  requestId?: string;
  principalId?: string;
  sourceIp?: string;
  model?: string;
  tier?: string;
  outcome?: string;
  /** Metadata ONLY — token counts, decisions, hashes. NEVER prompt/CUI content. */
  detail?: Record<string, unknown>;
};

export type StoredAuditEvent = AuditInput & {
  id: number;
  ts: string;
  prevHash: string;
  hash: string;
};

export type AuditFilter = {
  principalId?: string;
  type?: string;
  sinceIso?: string;
  limit?: number;
};

// ─── Admin config overrides (DB-backed, layered over the file config) ───

export type OverrideScope = "policy.group" | "policy.user" | "tier" | "provider";

export type ConfigOverride = {
  scope: OverrideScope;
  /** Group name, user id (sub), tier name, or provider name. */
  name: string;
  /** JSON value: a PolicyRule, TierMapping, or ProviderConfigEntry. */
  value: unknown;
  updatedBy: string;
  updatedAt: string;
};

/** Structural view of the app config that the overrides overlay mutates. */
export type FreeRouterConfigLike = {
  security?: {
    enabled: boolean;
    policy?: { default: unknown; groups?: Record<string, unknown>; users?: Record<string, unknown> };
    [k: string]: unknown;
  };
  tiers?: Record<string, unknown>;
  providers?: Record<string, unknown>;
  [k: string]: unknown;
};

// ─── Persistence ───

export interface Store {
  init(): void;
  close(): void;

  // Admin config overrides
  listOverrides(): ConfigOverride[];
  putOverride(o: ConfigOverride): void;
  deleteOverride(scope: OverrideScope, name: string): void;

  // Usage ledger
  recordUsage(r: UsageRecord): void;
  aggregateUsage(principalId: string, sinceIso: string): UsageAggregate;
  usageBreakdown(opts: {
    principalId?: string;
    sinceIso: string;
    groupBy: "model" | "principal" | "day";
  }): UsageBreakdownRow[];

  // Audit (append-only, hash-chained)
  appendAudit(e: AuditInput): StoredAuditEvent;
  lastAuditHash(): string | null;
  verifyAuditChain(): { ok: boolean; brokenAtId?: number; checked: number };
  queryAudit(filter: AuditFilter): StoredAuditEvent[];

  // Replay cache (IA 3.5.4)
  recordJtiIfNew(jti: string, expEpochSec: number): boolean; // true = new, false = replay
  purgeExpiredJti(nowEpochSec: number): void;
}

// ─── Top-level security config block (lives under FreeRouterConfig.security) ───

export type SecurityConfig = {
  /** Master switch. When true, the router enforces auth deny-by-default. */
  enabled: boolean;
  /** Require FIPS-validated crypto at startup; fail closed if unavailable. */
  requireFips?: boolean;
  /** SQLite file path for accounting + audit (default ~/.config/secrouter/secrouter.db). */
  storePath?: string;
  /** CORS allow-list. Empty/omitted = deny all cross-origin (default). */
  cors?: { allowedOrigins: string[] };
  oidc?: OidcConfig;
  policy?: {
    /** Applied to every principal as the floor. */
    default: PolicyRule;
    /** Keyed by group name (matched against principal.groups). */
    groups?: Record<string, PolicyRule>;
    /** Keyed by principal id (sub) for per-user overrides. */
    users?: Record<string, PolicyRule>;
  };
  audit?: {
    /** "sqlite" (default) or "both" to also forward to syslog/SIEM. */
    sink?: "sqlite" | "both";
    /** Fail the request if the audit write fails (AU 3.3.4). Default true. */
    failClosed?: boolean;
    syslog?: { host: string; port: number; protocol?: "udp" | "tcp"; format?: "cef" | "json" };
  };
  /** Prometheus /metrics endpoint. Off unless enabled; guard with a static bearer or network placement. */
  metrics?: { enabled: boolean; bearerEnvKey?: string };
  /**
   * Provider circuit breaker (availability hardening, SC 3.13.x). All optional;
   * conservative defaults (threshold 5, cooldown 30s, no active health checks).
   */
  resilience?: {
    /** Consecutive upstream health failures before a provider trips open. */
    circuitThreshold?: number;
    /** Seconds a provider stays open before a half-open probe is admitted. */
    cooldownSec?: number;
    /** Active health-check interval in seconds; 0 = passive only (default). */
    healthIntervalSec?: number;
  };
  /**
   * Governed MCP / tool-calling gateway (Phase D, AC 3.1.3/3.1.5). Off unless
   * `enabled: true`. Servers are the in-boundary upstreams SecRouter brokers;
   * tools are gated per-principal via policy.allowedTools/deniedTools.
   */
  mcp?: {
    enabled: boolean;
    servers: McpServerConfig[];
  };
  egress?: {
    /** Deny-by-default upstream allow-list. */
    allowlist: EgressRule[];
    /** Block (vs warn) when a destination is not authorized. Default true. */
    failClosed?: boolean;
  };
  tls?: {
    /** "frontend" = TLS terminated by a FIPS-validated proxy (recommended); "native" = node:https. */
    mode: "frontend" | "native";
    certPath?: string;
    keyPath?: string;
    minVersion?: "TLSv1.2" | "TLSv1.3";
    ciphers?: string;
  };
  classification?: {
    /** Default classification assumed for an inbound request. */
    default: string;
    /** Ordered low→high. Used to compare maxClassification gates. */
    levels: string[];
  };
};
