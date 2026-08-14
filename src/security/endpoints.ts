/**
 * Admin "add endpoint" tooling — register a local / on-prem model endpoint from
 * the console, writing the change to the auditable config FILE (not ephemeral DB
 * overrides). Three steps, all driven by admin-gated, audited routes in
 * server.ts:
 *
 *   1. probe    — reach the candidate endpoint, verify its API, list its models.
 *   2. preview  — merge the proposed change into a config clone and validate it
 *                 (no write).
 *   3. apply    — validate + persist to the config file via writeConfigFile().
 *
 * Egress stays explicit: an endpoint is only reachable once its allow-list rule
 * (host + authorized classifications) is written and validated, so the
 * deny-by-default CUI boundary is preserved.
 */

import {
  getConfig,
  writeConfigFile,
  validateSecurityConfig,
  endpointsOf,
  type FreeRouterConfig,
  type ProviderConfigEntry,
  type ModelCatalogEntry,
  type TierMapping,
} from "../config.js";
import { allowedHostsOf } from "./egress/allowlist.js";
import type { EgressRule } from "./types.js";

/** Thrown when a remove/egress-edit targets a provider that isn't configured
 * (or, for egress edits, has no existing allow-list rule to edit). Distinct
 * from a validation failure so callers (server.ts) can map it to 404 instead
 * of 422. */
export class ProviderNotFoundError extends Error {
  constructor(provider: string, reason: string) {
    super(`provider '${provider}' ${reason}`);
    this.name = "ProviderNotFoundError";
  }
}

export type ApiType = "openai" | "anthropic" | "bedrock" | "azure";

/** Probe input. A typed `authToken` is used for the probe only and never stored. */
export type ProbeRequest = {
  baseUrl: string;
  api?: ApiType;
  authEnvKey?: string;
  authToken?: string;
};

export type ProbeResult = {
  ok: boolean;
  latencyMs?: number;
  models?: string[];
  /** Which model-list URL actually answered (helps the operator confirm the path). */
  url?: string;
  error?: string;
};

/** The full endpoint registration the wizard assembles and submits. */
export type EndpointSpec = {
  provider: { name: string; api: ApiType; baseUrl: string; authEnvKey?: string; region?: string; apiVersion?: string; azureAuth?: "api-key" | "entra" };
  egress: { allowedHost?: string; authorizedClassifications: string[]; authorization?: string };
  models: ModelCatalogEntry[];
  /** Optional tier → {primary,fallback} assignments to route to the new models. */
  tiers?: Record<string, { primary?: string; fallback?: string[] }>;
  /** Optionally set this (embedding) model id as cfg.embeddings.default. */
  embeddingsDefault?: string;
};

const trimSlash = (s: string) => s.replace(/\/+$/, "");

/** Hostnames already trusted because they're in the current providers/egress config. */
function configuredHosts(): Set<string> {
  const set = new Set<string>();
  const cfg = getConfig();
  for (const p of Object.values(cfg.providers ?? {})) {
    for (const url of endpointsOf(p)) {
      try {
        set.add(new URL(url).hostname.toLowerCase());
      } catch {
        /* ignore malformed baseUrl */
      }
    }
  }
  for (const r of cfg.security?.egress?.allowlist ?? []) {
    for (const h of allowedHostsOf(r)) set.add(h.split(":")[0].toLowerCase());
  }
  return set;
}

/**
 * SSRF guard: the probe makes the server fetch an operator-supplied URL, so by
 * default we only allow in-boundary / on-prem destinations (this feature is for
 * local/on-prem endpoints). Public FQDNs are blocked unless explicitly allowed
 * via SECROUTER_PROBE_ALLOW_HOSTS (comma-separated hosts or suffixes) or already
 * present in the config.
 */
export function isInBoundaryHost(host: string): boolean {
  const h = host.toLowerCase();
  const allow = (process.env.SECROUTER_PROBE_ALLOW_HOSTS ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (allow.some((a) => h === a || h.endsWith(`.${a}`) || h.endsWith(a))) return true;
  if (configuredHosts().has(h)) return true;
  if (h === "localhost" || h === "::1") return true;
  if (!h.includes(".")) return true; // single-label service name (docker/k8s/internal)
  if (/\.(internal|local|lan|corp|intranet|home|test|example|svc|cluster)$/.test(h)) return true;
  if (/\.(mil|gov)$/.test(h)) return true; // in-enclave by convention for this product
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a === 10 || a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
    return false; // other public IPv4
  }
  if (h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80")) return true; // IPv6 ULA/link-local
  return false; // public FQDN — blocked by default
}

function extractModelIds(body: unknown): string[] {
  const pick = (m: unknown): string | undefined =>
    typeof m === "string" ? m : ((m as { id?: string; name?: string })?.id ?? (m as { name?: string })?.name);
  const b = body as { data?: unknown[]; models?: unknown[] } | unknown[];
  if (Array.isArray((b as { data?: unknown[] })?.data)) return (b as { data: unknown[] }).data.map(pick).filter(Boolean) as string[];
  if (Array.isArray((b as { models?: unknown[] })?.models)) return (b as { models: unknown[] }).models.map(pick).filter(Boolean) as string[];
  if (Array.isArray(b)) return (b as unknown[]).map(pick).filter(Boolean) as string[];
  return [];
}

/** Reach the endpoint, confirm the API responds, and list its models. */
export async function probeEndpoint(req: ProbeRequest): Promise<ProbeResult> {
  let host: string;
  try {
    host = new URL(req.baseUrl).hostname;
  } catch {
    return { ok: false, error: "invalid baseUrl" };
  }
  if (!isInBoundaryHost(host)) {
    return {
      ok: false,
      error: `host '${host}' is outside the in-boundary probe allow-list — set SECROUTER_PROBE_ALLOW_HOSTS or add the endpoint to the config file directly`,
    };
  }
  const api: ApiType = req.api ?? "openai";
  const token = req.authToken || (req.authEnvKey ? process.env[req.authEnvKey] : undefined);
  const headers: Record<string, string> = { Accept: "application/json" };
  if (api === "anthropic") {
    if (token) headers["x-api-key"] = token;
    headers["anthropic-version"] = "2023-06-01";
  } else if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  // Try the conventional model-list paths so discovery works whether or not the
  // base URL already includes the version segment (people often omit `/v1`).
  const base = trimSlash(req.baseUrl);
  const candidates = [`${base}/models`];
  if (!/\/v\d+$/.test(base)) candidates.push(`${base}/v1/models`);

  const started = Date.now();
  let reachableButEmpty: ProbeResult | null = null;
  let lastErr = "no model-list endpoint responded";
  for (const url of candidates) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 6000);
    try {
      const r = await fetch(url, { headers, signal: ctrl.signal });
      if (!r.ok) {
        lastErr = `GET ${url} → HTTP ${r.status}`;
        continue;
      }
      const body = await r.json().catch(() => null);
      const models = extractModelIds(body);
      if (models.length) return { ok: true, latencyMs: Date.now() - started, models, url };
      // 200 but nothing we recognise as a model list — remember and keep trying.
      reachableButEmpty = { ok: true, latencyMs: Date.now() - started, models: [], url };
      lastErr = `GET ${url} → 200 but no model list found`;
    } catch (err) {
      lastErr =
        err instanceof Error && err.name === "AbortError"
          ? `GET ${url} → timed out after 6s`
          : `GET ${url} → ${err instanceof Error ? err.message : String(err)}`;
    } finally {
      clearTimeout(timer);
    }
  }
  return reachableButEmpty ?? { ok: false, error: lastErr };
}

/** Merge an endpoint registration into a config object (used by preview + apply). */
export function applyEndpointToConfig(cfg: FreeRouterConfig, spec: EndpointSpec): void {
  if (!spec?.provider?.name || !spec.provider.baseUrl) throw new Error("provider name and baseUrl are required");

  // 1. Provider
  cfg.providers ??= {};
  const prov: ProviderConfigEntry = { baseUrl: spec.provider.baseUrl, api: spec.provider.api };
  if (spec.provider.region) prov.region = spec.provider.region;
  if (spec.provider.apiVersion) prov.apiVersion = spec.provider.apiVersion;
  if (spec.provider.azureAuth) prov.azureAuth = spec.provider.azureAuth;
  if (spec.provider.authEnvKey) prov.auth = { type: "env", key: spec.provider.authEnvKey };
  cfg.providers[spec.provider.name] = prov;

  // 2. Egress allow-list rule (host:port, matching the runtime egress check)
  cfg.security ??= { enabled: false };
  cfg.security.egress ??= { allowlist: [] };
  const allowedHost = (spec.egress.allowedHost && spec.egress.allowedHost.trim()) || new URL(spec.provider.baseUrl).host;
  const rule: EgressRule = {
    provider: spec.provider.name,
    allowedHost,
    authorizedClassifications: spec.egress.authorizedClassifications ?? [],
  };
  if (spec.egress.authorization) rule.authorization = spec.egress.authorization;
  const list = cfg.security.egress.allowlist;
  const idx = list.findIndex((r) => r.provider === spec.provider.name);
  if (idx >= 0) list[idx] = rule;
  else list.push(rule);

  // 3. Model catalog (pricing/metadata for cost tracking)
  if (spec.models?.length) {
    cfg.models ??= [];
    for (const m of spec.models) {
      if (!m?.id) continue;
      const i = cfg.models.findIndex((x) => x.id === m.id);
      if (i >= 0) cfg.models[i] = m;
      else cfg.models.push(m);
    }
  }

  // 3b. Embeddings default (for POST /v1/embeddings with "auto"/none)
  if (spec.embeddingsDefault) {
    cfg.embeddings ??= {};
    cfg.embeddings.default = spec.embeddingsDefault;
  }

  // 4. Optional tier assignments
  if (spec.tiers) {
    cfg.tiers ??= {};
    for (const [t, mapping] of Object.entries(spec.tiers)) {
      const cur = cfg.tiers[t] ?? { primary: "", fallback: [] };
      cfg.tiers[t] = {
        primary: mapping.primary ?? cur.primary,
        fallback: mapping.fallback ?? cur.fallback ?? [],
      };
    }
  }
}

/** Validate-only: merge the spec into a config clone and report errors. No write. */
export function previewEndpoint(spec: EndpointSpec): {
  valid: boolean;
  errors: string[];
  summary: { provider: string; api: string; baseUrl: string; egress: EgressRule; modelIds: string[]; tiers: string[] };
} {
  const clone = structuredClone(getConfig());
  applyEndpointToConfig(clone, spec);
  const errors = validateSecurityConfig(clone);
  const rule = clone.security!.egress!.allowlist.find((r) => r.provider === spec.provider.name)!;
  return {
    valid: errors.length === 0,
    errors,
    summary: {
      provider: spec.provider.name,
      api: spec.provider.api,
      baseUrl: spec.provider.baseUrl,
      egress: rule,
      modelIds: (spec.models ?? []).map((m) => m.id),
      tiers: Object.keys(spec.tiers ?? {}),
    },
  };
}

/** Persist the endpoint registration to the config file (validated, atomic, backed up). */
export function applyEndpoint(spec: EndpointSpec): { path: string } {
  return writeConfigFile((cfg) => applyEndpointToConfig(cfg, spec));
}

// ─── Remove endpoint ───

export type RemovalSummary = {
  /** Egress allow-list rule for this provider was dropped. */
  removedEgress: boolean;
  /** Tier names (in `tiers`, and `agentic:`-prefixed for `agenticTiers`) whose
   * primary was blanked or fallback list was pruned because it referenced
   * `${provider}/...`. */
  clearedTiers: string[];
};

/**
 * Remove a provider's registration in place: delete providers.<name>, drop its
 * egress allow-list rule, and blank/prune any tier primary/fallback that
 * referenced one of its models (`${provider}/...`) so the config stays
 * structurally consistent (tiers themselves aren't shape-validated by
 * validateSecurityConfig, but leaving a dangling reference would silently
 * route to a provider that no longer exists). Throws ProviderNotFoundError if
 * the provider isn't configured.
 */
export function removeEndpointFromConfig(cfg: FreeRouterConfig, provider: string): RemovalSummary {
  if (!cfg.providers?.[provider]) {
    throw new ProviderNotFoundError(provider, "not found");
  }
  delete cfg.providers[provider];

  let removedEgress = false;
  if (cfg.security?.egress?.allowlist) {
    const before = cfg.security.egress.allowlist.length;
    cfg.security.egress.allowlist = cfg.security.egress.allowlist.filter((r) => r.provider !== provider);
    removedEgress = cfg.security.egress.allowlist.length < before;
  }

  const prefix = `${provider}/`;
  const clearedTiers = new Set<string>();
  const clear = (tiers: Record<string, TierMapping> | undefined, label: string) => {
    if (!tiers) return;
    for (const [name, mapping] of Object.entries(tiers)) {
      let changed = false;
      if (mapping.primary?.startsWith(prefix)) {
        mapping.primary = "";
        changed = true;
      }
      const kept = (mapping.fallback ?? []).filter((m) => !m.startsWith(prefix));
      if (kept.length !== (mapping.fallback ?? []).length) {
        mapping.fallback = kept;
        changed = true;
      }
      if (changed) clearedTiers.add(`${label}${name}`);
    }
  };
  clear(cfg.tiers, "");
  clear(cfg.agenticTiers, "agentic:");

  return { removedEgress, clearedTiers: [...clearedTiers] };
}

/** Persist provider removal to the config file (validated, atomic, backed up). */
export function removeEndpoint(provider: string): { path: string } & RemovalSummary {
  let summary: RemovalSummary = { removedEgress: false, clearedTiers: [] };
  const out = writeConfigFile((cfg) => {
    summary = removeEndpointFromConfig(cfg, provider);
  });
  return { ...out, ...summary };
}

// ─── Edit egress rule ───

/**
 * Update an EXISTING provider's egress allow-list rule in place (allowedHost +
 * authorizedClassifications, and optionally the authorization note). Does not
 * create a new rule — use endpoint/apply to register a provider for the first
 * time. Throws ProviderNotFoundError if the provider isn't configured, or has
 * no existing rule to edit.
 */
export function updateEgressRuleInConfig(
  cfg: FreeRouterConfig,
  provider: string,
  allowedHost: string,
  authorizedClassifications: string[],
  authorization?: string,
): EgressRule {
  if (!cfg.providers?.[provider]) {
    throw new ProviderNotFoundError(provider, "not found");
  }
  const list = cfg.security?.egress?.allowlist;
  const idx = list?.findIndex((r) => r.provider === provider) ?? -1;
  if (!list || idx < 0) {
    throw new ProviderNotFoundError(provider, "has no existing egress rule to update");
  }
  const rule: EgressRule = { provider, allowedHost, authorizedClassifications };
  if (authorization) rule.authorization = authorization;
  list[idx] = rule;
  return rule;
}

/** Persist an egress rule edit to the config file (validated, atomic, backed up). */
export function updateEgressRule(
  provider: string,
  allowedHost: string,
  authorizedClassifications: string[],
  authorization?: string,
): { path: string; rule: EgressRule } {
  let rule!: EgressRule;
  const out = writeConfigFile((cfg) => {
    rule = updateEgressRuleInConfig(cfg, provider, allowedHost, authorizedClassifications, authorization);
  });
  return { ...out, rule };
}
