/**
 * SecRouter Config — loads external configuration from secrouter.config.json
 * Zero external deps. Falls back to hardcoded defaults if no config file exists.
 *
 * Config file search order (legacy freerouter.* names still accepted for back-compat):
 *   1. SECROUTER_CONFIG env var (or legacy FREEROUTER_CONFIG)
 *   2. ./secrouter.config.json (cwd)
 *   3. ~/.config/secrouter/config.json
 */

import { readFileSync, existsSync, writeFileSync, renameSync, copyFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { logger } from "./logger.js";
import type { SecurityConfig, EgressRule } from "./security/types.js";
import { allowedHostsOf } from "./security/egress/allowlist.js";
import type { ExperimentsConfig } from "./router/types.js";

// ─── Config Types ───

export type AuthConfig = {
  type: "profiles" | "env" | "file" | "keychain";
  key?: string;           // env var name for type=env
  profilesPath?: string;  // for type=profiles
  filePath?: string;      // for type=file
  service?: string;       // for type=keychain
  account?: string;       // for type=keychain
};

export type ProviderConfigEntry = {
  /**
   * One upstream endpoint (today's default — unchanged behavior), or several
   * for round-robin, breaker-aware load balancing across replicas of the same
   * backend (e.g. multiple on-prem vLLM instances). Use `endpointsOf()` to
   * normalize either shape into an ordered, non-empty list.
   */
  baseUrl: string | string[];
  api: "anthropic" | "openai" | "bedrock" | "azure";
  headers?: Record<string, string>;
  auth?: AuthConfig;
  /** AWS region for api="bedrock" (e.g. "us-gov-west-1"). */
  region?: string;
  /** Azure OpenAI REST api-version (api="azure"). Default "2024-10-21". */
  apiVersion?: string;
  /** Azure auth mode (api="azure"): "api-key" header (default) or "entra" bearer token. */
  azureAuth?: "api-key" | "entra";
  /** Microsoft Entra ID service principal, used when azureAuth="entra". */
  entra?: {
    tenantId: string;
    clientId: string;
    /** Env var holding the client secret — never stored in config. */
    clientSecretEnv: string;
    /** OAuth authority base. Default commercial; use login.microsoftonline.us for Azure Government. */
    authority?: string;
    /** Token scope. Default https://cognitiveservices.azure.com/.default (…azure.us for Gov). */
    scope?: string;
  };
};

export type TierMapping = {
  primary: string;
  fallback: string[];
};

/**
 * Optional per-model catalog entry. Overlays the hardcoded registry in
 * models.ts (config wins by id) so on-prem / locally-registered models carry
 * pricing for internal cost tracking. Prices are $/1M tokens and default to 0
 * (self-hosted compute has no per-token cost). `classification` is informational
 * — the egress allow-list is what actually authorizes a destination per class.
 */
export type ModelCatalogEntry = {
  id: string;            // "provider/model-id"
  name?: string;
  inputPrice?: number;   // $/1M input tokens (default 0)
  outputPrice?: number;  // $/1M output tokens (default 0)
  contextWindow?: number;
  maxOutput?: number;
  reasoning?: boolean;
  vision?: boolean;
  agentic?: boolean;
  /** "chat" (default) or "embedding" — the router never routes chat traffic to an embedding model. */
  kind?: "chat" | "embedding";
  classification?: string;
};

export type ThinkingConfig = {
  adaptive?: string[];
  enabled?: { models: string[]; budget: number };
};

export type FreeRouterConfig = {
  port: number;
  host: string;
  providers: Record<string, ProviderConfigEntry>;
  tiers: Record<string, TierMapping>;
  /** Optional per-model pricing/metadata catalog overlaid on the models.ts registry. */
  models?: ModelCatalogEntry[];
  /** Governed embeddings: default model for POST /v1/embeddings when the client sends "auto"/none. */
  embeddings?: { default?: string };
  agenticTiers?: Record<string, TierMapping>;
  /**
   * Routing experiments: split (A/B) routing and escalation (draft-judge-escalate)
   * routing. See router/types.ts ExperimentsConfig, router/split.ts, router/escalation.ts.
   * Validated fail-loud by router/config.ts's validateExperimentsConfig (server.ts calls
   * it at startup/reload alongside validateSecurityConfig).
   */
  experiments?: ExperimentsConfig;
  tierBoundaries?: {
    simpleMedium: number;
    mediumComplex: number;
    complexReasoning: number;
  };
  thinking?: ThinkingConfig;
  auth: {
    default: string;
    [strategy: string]: unknown;
  };
  scoring?: Record<string, unknown>;
  /** User auth, per-user governance, and CMMC hardening. See security/types.ts. */
  security?: SecurityConfig;
};

// ─── Defaults (current hardcoded behavior) ───

const DEFAULT_CONFIG: FreeRouterConfig = {
  port: 18800,
  host: "127.0.0.1",
  // NOTE: built-in dev defaults (security disabled), pointed at OpenAI frontier
  // models (gpt-oss) on AWS Bedrock GovCloud. Kimi/Moonshot is intentionally NOT
  // a default — it is a PRC-jurisdiction provider and must never receive CUI. See
  // secrouter.config.hardened.example.json for the full CUI-hardened config.
  providers: {
    bedrock: {
      baseUrl: "https://bedrock-runtime.us-gov-west-1.amazonaws.com/openai/v1",
      api: "openai",
      region: "us-gov-west-1",
    },
  },
  tiers: {
    SIMPLE:    { primary: "bedrock/openai.gpt-oss-20b-1:0",  fallback: ["bedrock/openai.gpt-oss-120b-1:0"] },
    MEDIUM:    { primary: "bedrock/openai.gpt-oss-120b-1:0", fallback: [] },
    COMPLEX:   { primary: "bedrock/openai.gpt-oss-120b-1:0", fallback: [] },
    REASONING: { primary: "bedrock/openai.gpt-oss-120b-1:0", fallback: [] },
  },
  agenticTiers: {
    SIMPLE:    { primary: "bedrock/openai.gpt-oss-20b-1:0",  fallback: ["bedrock/openai.gpt-oss-120b-1:0"] },
    MEDIUM:    { primary: "bedrock/openai.gpt-oss-120b-1:0", fallback: [] },
    COMPLEX:   { primary: "bedrock/openai.gpt-oss-120b-1:0", fallback: [] },
    REASONING: { primary: "bedrock/openai.gpt-oss-120b-1:0", fallback: [] },
  },
  thinking: {
    adaptive: [],
    enabled: { models: [], budget: 4096 },
  },
  auth: {
    default: "profiles",
    profiles: {
      type: "profiles",
      profilesPath: "~/.config/secrouter/upstream-auth.json",
    },
  },
};

// ─── Singleton ───
//
// Two layers: _fileConfig is the immutable baseline (defaults + config file);
// _config is the EFFECTIVE config (baseline + admin DB overrides applied via an
// overlay). Everything downstream reads getConfig() → _config, so live edits to
// policies/tiers/providers from the admin console take effect immediately.

let _config: FreeRouterConfig | null = null;
let _fileConfig: FreeRouterConfig | null = null;
let _configPath: string | null = null;
let _overlay: ((cfg: FreeRouterConfig) => void) | null = null;

/** Apply the registered overlay (admin overrides) to a config clone. */
function applyOverlay(cfg: FreeRouterConfig): FreeRouterConfig {
  if (_overlay) {
    try {
      _overlay(cfg);
    } catch (err) {
      logger.error(`config overlay failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return cfg;
}

/**
 * Default binding of each classification tier to the REAL SecLLM model name
 * (HF basename) it routes to. `applySecllmEndpointsIntake` turnkey-routes
 * SIMPLE/MEDIUM/COMPLEX/REASONING to `secllm/<real-model>` straight from this
 * map; SECROUTER_SECLLM_MODELS can override any tier's model for a pool that
 * serves different real names (see parseSecllmModels). There are no tier tags —
 * the tier binds directly to the served model id.
 */
const SECLLM_TIER_MODELS: Record<string, string> = {
  SIMPLE: "Llama-3.2-3B-Instruct",
  MEDIUM: "gemma-4-26B-A4B-it",
  COMPLEX: "Llama-3.3-70B-Instruct",
  REASONING: "gpt-oss-20b",
};
const SECLLM_TIER_KEYS = new Set(Object.keys(SECLLM_TIER_MODELS).map((t) => t.toLowerCase()));

/**
 * Parse SECROUTER_SECLLM_MODELS — the optional companion to
 * SECROUTER_SECLLM_ENDPOINTS that overrides which REAL model id each tier binds
 * to when a custom pool serves names other than the SECLLM_TIER_MODELS defaults.
 * Format: comma-separated `tier=modelId` pairs, tier ∈
 * {simple,medium,complex,reasoning} (case-insensitive). Returns a possibly-empty
 * map keyed by the UPPERCASE tier name (SIMPLE/MEDIUM/COMPLEX/REASONING) → real
 * model id; malformed pairs, unknown tiers, and empty ids are skipped with a
 * warning rather than failing the load (a typo shouldn't take the router down).
 *
 * Used ONLY to override the tier→model defaults in the turnkey intake — it is
 * not an alias map and is never consulted at forward time. Why: the intake
 * otherwise binds each tier to the default real name (e.g. MEDIUM →
 * gemma-4-26B-A4B-it), which a pool serving a differently-named catalog — e.g.
 * an OpenAI-compatible MLX/vLLM server whose ids are "org/model" — would 404.
 * This var re-points a tier without hand-authoring `providers.secllm` + `tiers`.
 * Example (a quantized Gemma tool-caller + a small Llama):
 *   SECROUTER_SECLLM_MODELS="simple=mlx-community/Llama-3.2-3B-Instruct-4bit,\
 *   medium=lmstudio-community/gemma-4-26B-A4B-it-QAT-MLX-4bit"
 * → MEDIUM routes to that 26B id, SIMPLE to that 3B id; unspecified tiers keep
 * their SECLLM_TIER_MODELS default.
 */
export function parseSecllmModels(raw: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw) return out;
  for (const pair of raw.split(",")) {
    const entry = pair.trim();
    if (!entry) continue;
    const eq = entry.indexOf("=");
    if (eq <= 0) {
      logger.warn(`SECROUTER_SECLLM_MODELS: ignoring malformed entry ${JSON.stringify(entry)} (expected tier=modelId)`);
      continue;
    }
    const tier = entry.slice(0, eq).trim().toLowerCase();
    const id = entry.slice(eq + 1).trim();
    if (!SECLLM_TIER_KEYS.has(tier)) {
      logger.warn(`SECROUTER_SECLLM_MODELS: ignoring unknown tier ${JSON.stringify(tier)} (expected one of ${[...SECLLM_TIER_KEYS].join("/")})`);
      continue;
    }
    if (!id) {
      logger.warn(`SECROUTER_SECLLM_MODELS: ignoring empty model id for tier ${JSON.stringify(tier)}`);
      continue;
    }
    out[tier.toUpperCase()] = id;
  }
  return out;
}

/**
 * SECROUTER_SECLLM_ENDPOINTS — turnkey intake for a self-hosted SecLLM pool.
 *
 * If the env var is set (comma-separated base URLs) this auto-registers a
 * pooled `secllm` provider (`baseUrl: string[]` — round-robin, breaker-aware
 * load balancing across the pool; see `endpointsOf()` / `router/balance.ts`)
 * with bearer-token auth resolved from `SECROUTER_SECLLM_TOKEN`
 * (`auth: {type:"env", key:"SECROUTER_SECLLM_TOKEN"}` — the same env-based
 * `AuthConfig` mechanism every other provider uses; see auth.ts's
 * `getAuth()`/`getEnvAuth()` and provider.ts's `forwardToOpenAI`. An unset
 * token resolves to no header, matching an open/unauthenticated SecLLM —
 * back-compat), and rewires SIMPLE/MEDIUM/COMPLEX/REASONING — in both
 * `tiers` and `agenticTiers` — to route to it (demoting whatever was
 * previously primary into that tier's fallback list, deduped). If the pool
 * is simply unreachable (down, network partition — the breaker trips),
 * requests still gracefully fall back to the demoted prior primary instead
 * of hard-failing.
 *
 * ROUTING + PROVIDER AUTH ONLY — this intake never touches
 * `security.egress` and never authorizes egress on its own. Egress
 * authorization is a human compliance decision (which hosts, for which
 * classifications) and stays explicit: hand-author a `secllm` rule in
 * `security.egress.allowlist`, or point `SECROUTER_EGRESS_FILE` at a
 * deployer-generated rules file (see `applyEgressFileIntake` below). Until
 * one of those exists, a `security.enabled: true` deploy correctly DENIES
 * traffic to the turnkey-registered `secllm` provider — deny-by-default is
 * unchanged; this intake only ever wires up routing + credentials, never a
 * network path.
 *
 * NON-DESTRUCTIVE / explicit-config-always-wins: a strict no-op (nothing
 * below runs) if the loaded config already defines a `secllm` provider, or
 * if ANY tier (in either `tiers` or `agenticTiers`) already routes —
 * primary or fallback — to `secllm/*`; either signal means the operator has
 * already taken ownership of this provider.
 *
 * Each tier binds to its real SecLLM model name from SECLLM_TIER_MODELS
 * (SIMPLE → Llama-3.2-3B-Instruct, MEDIUM → gemma-4-26B-A4B-it, COMPLEX →
 * Llama-3.3-70B-Instruct, REASONING → gpt-oss-20b). A pool serving a CUSTOM
 * catalog (different real names) can override any tier's model id via
 * SECROUTER_SECLLM_MODELS (`tier=modelId,...` — see parseSecllmModels) WITHOUT
 * hand-authoring `providers.secllm` + `tiers`/`agenticTiers`. Hand-config still
 * wins: the whole intake no-ops if the operator already owns `providers.secllm`
 * or any `secllm/*` tier route.
 */
function applySecllmEndpointsIntake(cfg: FreeRouterConfig): void {
  const raw = process.env.SECROUTER_SECLLM_ENDPOINTS;
  if (!raw) return;
  const urls = raw.split(",").map((u) => u.trim()).filter(Boolean);
  if (urls.length === 0) return;

  if (cfg.providers?.secllm) return; // explicit provider config wins

  const SECLLM_PREFIX = "secllm/";
  const routesToSecllm = (tiers?: Record<string, TierMapping>) =>
    Object.values(tiers ?? {}).some(
      (t) => t?.primary?.startsWith(SECLLM_PREFIX) || (t?.fallback ?? []).some((f) => f.startsWith(SECLLM_PREFIX)),
    );
  if (routesToSecllm(cfg.tiers) || routesToSecllm(cfg.agenticTiers)) return; // explicit tier routing wins

  // Defensive shallow-clone: `cfg` here may still share nested objects with
  // the module-level DEFAULT_CONFIG by reference — deepMerge() only recurses
  // into a key that BOTH the file and the defaults define, so a config file
  // that omits `providers`/`tiers`/`agenticTiers` entirely leaves those
  // pointing straight at DEFAULT_CONFIG's own objects. Cloning the top-level
  // dicts before writing keeps DEFAULT_CONFIG pristine across reloads / other
  // callers in the same process; every per-tier value below is freshly
  // constructed (never mutated in place), so a shallow clone is sufficient.
  cfg.providers = { ...(cfg.providers ?? {}) };
  cfg.providers.secllm = {
    api: "openai",
    baseUrl: urls,
    auth: { type: "env", key: "SECROUTER_SECLLM_TOKEN" },
  };

  // Tier → `secllm/<real-model>`. Binds each tier to its default real SecLLM
  // model name (SECLLM_TIER_MODELS); SECROUTER_SECLLM_MODELS overrides a tier's
  // model id for a pool serving a different real name (e.g. MEDIUM → a 26B tool-caller).
  const modelOverrides = parseSecllmModels(process.env.SECROUTER_SECLLM_MODELS);
  const TURNKEY_MODELS: Record<string, string> = {};
  for (const [tier, model] of Object.entries(SECLLM_TIER_MODELS)) {
    TURNKEY_MODELS[tier] = `${SECLLM_PREFIX}${modelOverrides[tier] ?? model}`;
  }
  const rewire = (tiers: Record<string, TierMapping> | undefined): Record<string, TierMapping> => {
    const fresh: Record<string, TierMapping> = { ...(tiers ?? {}) };
    for (const [tierName, primary] of Object.entries(TURNKEY_MODELS)) {
      const prior = tiers?.[tierName];
      const fallback: string[] = [];
      if (prior?.primary && prior.primary !== primary) fallback.push(prior.primary);
      for (const f of prior?.fallback ?? []) {
        if (f !== primary && !fallback.includes(f)) fallback.push(f);
      }
      fresh[tierName] = { primary, fallback };
    }
    return fresh;
  };
  cfg.tiers = rewire(cfg.tiers);
  cfg.agenticTiers = rewire(cfg.agenticTiers);

  const remapNote = Object.keys(modelOverrides).length
    ? `Tier model overrides (SECROUTER_SECLLM_MODELS): ${Object.entries(modelOverrides).map(([t, m]) => `${t}→${m}`).join(", ")}. `
    : "";
  logger.info(
    `SECROUTER_SECLLM_ENDPOINTS set — auto-registered provider 'secllm' (${urls.length} endpoint${urls.length === 1 ? "" : "s"}, auth from $SECROUTER_SECLLM_TOKEN) ` +
      `and turnkey-routed SIMPLE/MEDIUM/COMPLEX/REASONING to it (prior primaries demoted to fallback). ${remapNote}` +
      `Egress is NOT auto-authorized — add a 'secllm' rule to security.egress.allowlist or set SECROUTER_EGRESS_FILE, or the pool stays denied under security.enabled.`,
  );
}

/**
 * Details of a `SECROUTER_EGRESS_FILE` load, handed off for the caller to
 * audit once the security subsystem is live. config.ts has no access to the
 * auditor (it lives in security/*, which itself imports FROM config.ts —
 * importing it back here would be circular, and audit writes need an open
 * store this module never has); server.ts drains this via
 * `takePendingEgressFileAudit()` right after `initSecurity()`, both at
 * startup and on `/reload-config`.
 */
export type EgressFileLoad = {
  path: string;
  addedCount: number;
  totalCount: number;
};

let _pendingEgressFileAudit: EgressFileLoad | null = null;

/**
 * Read-and-clear the pending SECROUTER_EGRESS_FILE load (if any) from the
 * most recent `finalize()`. Returns null when the last (re)load didn't
 * produce one — SECROUTER_EGRESS_FILE isn't set.
 */
export function takePendingEgressFileAudit(): EgressFileLoad | null {
  const v = _pendingEgressFileAudit;
  _pendingEgressFileAudit = null;
  return v;
}

/**
 * SECROUTER_EGRESS_FILE — explicit, deployer-authored egress allow-list.
 *
 * If set, points at a JSON file containing an ARRAY of `EgressRule` objects
 * — the exact shape of `security.egress.allowlist` entries (see
 * `EgressRule` in security/types.ts: `{ provider, allowedHost,
 * authorizedClassifications, authorization? }`, `allowedHost` a single host
 * or an array for a pooled provider). Meant for a deployment tool that
 * generates the enclave's authorized inference hosts as a file rather than
 * hand-editing the main config. Loaded on every config finalize (startup and
 * `/reload-config`) and MERGED additively into `security.egress.allowlist`
 * — creating `security`/`security.egress` if either is absent — never
 * removing or overwriting an existing rule. Deduped by (provider, host set)
 * so reloading the same file, or a file that repeats a rule the config file
 * already declares, never duplicates entries.
 *
 * This is EXPLICIT deployer-authored config, not inference — deny-by-default
 * is unchanged: a host that's neither in the config file's own allowlist nor
 * in this file stays denied.
 *
 * FAIL LOUD: an unset env var is a no-op, but a SET env var naming a
 * missing/unreadable/malformed file THROWS — this is a security control, and
 * silently continuing with an incomplete (or silently-stale) allow-list must
 * never pass for a healthy boot or reload. Neither `finalize()` nor its
 * callers catch this.
 */
function applyEgressFileIntake(cfg: FreeRouterConfig): void {
  _pendingEgressFileAudit = null; // this finalize() hasn't produced one (yet)

  const path = process.env.SECROUTER_EGRESS_FILE;
  if (!path) return;

  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch (err) {
    throw new Error(`SECROUTER_EGRESS_FILE=${path} could not be read: ${err instanceof Error ? err.message : String(err)}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`SECROUTER_EGRESS_FILE=${path} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!Array.isArray(parsed)) {
    throw new Error(`SECROUTER_EGRESS_FILE=${path} must contain a JSON array of egress rules`);
  }
  const rules = parsed as EgressRule[];
  for (const [i, r] of rules.entries()) {
    const hasHost = !!r && (Array.isArray(r.allowedHost) ? r.allowedHost.length > 0 : !!r.allowedHost);
    if (!r || typeof r !== "object" || !r.provider || !hasHost || !Array.isArray(r.authorizedClassifications)) {
      throw new Error(
        `SECROUTER_EGRESS_FILE=${path}: rule[${i}] is missing a required field (provider, allowedHost, authorizedClassifications)`,
      );
    }
  }

  cfg.security = cfg.security ? { ...cfg.security } : { enabled: false };
  const allowlist: EgressRule[] = cfg.security.egress ? [...cfg.security.egress.allowlist] : [];
  const hostKey = (r: EgressRule) => allowedHostsOf(r).slice().sort().join(",");
  const seen = new Set(allowlist.map((r) => `${r.provider}::${hostKey(r)}`));
  let added = 0;
  for (const r of rules) {
    const key = `${r.provider}::${hostKey(r)}`;
    if (seen.has(key)) continue; // dedupe by provider+host — already covered by the config file or an earlier entry in this same file
    seen.add(key);
    allowlist.push(r);
    added++;
  }
  cfg.security.egress = { ...(cfg.security.egress ?? {}), allowlist };
  _pendingEgressFileAudit = { path, addedCount: added, totalCount: rules.length };

  logger.warn(
    `Loaded ${rules.length} egress rule${rules.length === 1 ? "" : "s"} from ${path} (SECROUTER_EGRESS_FILE)` +
      (added < rules.length ? ` — ${added} new, ${rules.length - added} already present (deduped)` : ""),
  );
}

/** Finalize: snapshot the baseline and derive the effective config. */
function finalize(baseline: FreeRouterConfig, path: string | null): FreeRouterConfig {
  applySecllmEndpointsIntake(baseline); // turnkey SECROUTER_SECLLM_ENDPOINTS — routing + provider auth only, no egress
  applyEgressFileIntake(baseline); // explicit SECROUTER_EGRESS_FILE — merges deployer-authored egress rules
  _fileConfig = baseline;
  _configPath = path;
  _config = applyOverlay(structuredClone(baseline));
  return _config;
}

/**
 * Register the admin-overrides overlay and rebuild the effective config.
 * Called by the security layer once the override store is available.
 */
export function setConfigOverlay(fn: ((cfg: FreeRouterConfig) => void) | null): void {
  _overlay = fn;
  if (_fileConfig) _config = applyOverlay(structuredClone(_fileConfig));
}

/** Rebuild the effective config from the baseline (after overrides change). */
export function rebuildEffectiveConfig(): FreeRouterConfig {
  if (!_fileConfig) return loadConfig();
  _config = applyOverlay(structuredClone(_fileConfig));
  return _config;
}

/**
 * Resolve ~ to home directory in paths.
 */
function resolvePath(p: string): string {
  if (p.startsWith("~/") || p === "~") {
    return join(homedir(), p.slice(1));
  }
  return p;
}

/**
 * Resolve $ENV_VAR references in string values.
 */
function resolveEnvVars(value: string): string {
  return value.replace(/\$([A-Z_][A-Z0-9_]*)/g, (_match, name) => {
    return process.env[name] ?? "";
  });
}

/**
 * Deep-merge source into target (source wins). Arrays are replaced, not merged.
 */
function deepMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    const sv = source[key];
    const tv = target[key];
    if (sv && typeof sv === "object" && !Array.isArray(sv) && tv && typeof tv === "object" && !Array.isArray(tv)) {
      result[key] = deepMerge(tv as Record<string, unknown>, sv as Record<string, unknown>);
    } else {
      result[key] = sv;
    }
  }
  return result;
}

/**
 * Find config file path.
 */
function findConfigFile(): string | null {
  // 1. Env var — SECROUTER_CONFIG is canonical; FREEROUTER_CONFIG is still honored so
  //    existing deploys keep working through the rename.
  const envPath = process.env.SECROUTER_CONFIG || process.env.FREEROUTER_CONFIG;
  if (envPath && existsSync(envPath)) return envPath;

  // 2. CWD — prefer secrouter.config.json, fall back to the legacy freerouter.config.json.
  for (const name of ["secrouter.config.json", "freerouter.config.json"]) {
    const p = join(process.cwd(), name);
    if (existsSync(p)) return p;
  }

  // 3. ~/.config/{secrouter,freerouter}/config.json (new dir first, legacy fallback)
  for (const dir of ["secrouter", "freerouter"]) {
    const p = join(homedir(), ".config", dir, "config.json");
    if (existsSync(p)) return p;
  }

  return null;
}

/**
 * Load config from file, merging with defaults.
 */
export function loadConfig(): FreeRouterConfig {
  const configPath = findConfigFile();

  if (!configPath) {
    logger.info("No secrouter.config.json found, using built-in defaults");
    return finalize(structuredClone(DEFAULT_CONFIG), null);
  }

  try {
    const raw = readFileSync(configPath, "utf-8");
    const fileConfig = JSON.parse(raw) as Partial<FreeRouterConfig>;

    // Deep-merge file config over defaults
    const merged = deepMerge(
      DEFAULT_CONFIG as unknown as Record<string, unknown>,
      fileConfig as unknown as Record<string, unknown>,
    ) as unknown as FreeRouterConfig;

    logger.info(`Loaded config from ${configPath}`);
    logger.info(`  Providers: ${Object.keys(merged.providers).join(", ")}`);
    logger.info(`  Tiers: ${Object.keys(merged.tiers).join(", ")}`);

    return finalize(merged, configPath);
  } catch (err) {
    logger.error(`Failed to load config from ${configPath}:`, err);
    logger.info("Falling back to built-in defaults");
    return finalize(structuredClone(DEFAULT_CONFIG), null);
  }
}

/**
 * Reload config from file (for /reload endpoint).
 *
 * A reload that throws (e.g. a bad SECROUTER_EGRESS_FILE — see
 * applyEgressFileIntake's fail-loud contract) restores the previously
 * EFFECTIVE config before rethrowing: the caller sees the failure loudly
 * (server.ts's handleReloadConfig turns it into a 500/never-hot-swaps), but
 * a bad reload attempt must not brick an already-healthy running server —
 * same "never hot-swap into an unsafe state, keep the running config on
 * error" philosophy handleReloadConfig already applies for a failed
 * validateSecurityConfig() check.
 */
export function reloadConfig(): FreeRouterConfig {
  const previous = _config;
  _config = null;
  try {
    return loadConfig();
  } catch (err) {
    _config = previous;
    throw err;
  }
}

/**
 * Get the current config (loads if not yet loaded).
 */
export function getConfig(): FreeRouterConfig {
  if (!_config) return loadConfig();
  return _config;
}

/**
 * Get config path (null if using defaults).
 */
export function getConfigPath(): string | null {
  return _configPath;
}

/**
 * Apply a mutation to the on-disk config FILE (the change-controlled baseline)
 * and persist it — validated-before-write, atomic, with a `.bak` backup.
 *
 * The admin "add endpoint" tooling uses this so changes land in the auditable
 * config file rather than ephemeral DB overrides. The mutation runs against the
 * RAW file object (not the effective config — admin overrides and resolved
 * secrets must never be baked into the file). The merged-over-defaults result is
 * validated with validateSecurityConfig; an invalid result is refused (so a bad
 * write can never crash-loop the server on its next start). Callers must be
 * admin-gated and should audit. Does NOT reload — the caller reloads/restarts.
 *
 * Throws if no config file is in use, the file is unparseable, the result would
 * be invalid, or the filesystem rejects the write (e.g. a read-only mount).
 */
export function writeConfigFile(mutate: (cfg: FreeRouterConfig) => void): { path: string } {
  const path = getConfigPath();
  if (!path) {
    throw new Error(
      "no config file in use (running on built-in defaults) — set FREEROUTER_CONFIG to a writable file",
    );
  }
  let fileObj: Record<string, unknown>;
  try {
    fileObj = JSON.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
  } catch (err) {
    throw new Error(`cannot read/parse existing config at ${path}: ${err instanceof Error ? err.message : String(err)}`);
  }

  const draft = structuredClone(fileObj) as unknown as FreeRouterConfig;
  mutate(draft);

  // Validate exactly as the loader will see it (file merged over defaults).
  const merged = deepMerge(
    DEFAULT_CONFIG as unknown as Record<string, unknown>,
    draft as unknown as Record<string, unknown>,
  ) as unknown as FreeRouterConfig;
  const errors = validateSecurityConfig(merged);
  if (errors.length) {
    throw new Error(`refusing to write — config would be invalid: ${errors.join("; ")}`);
  }

  const serialized = JSON.stringify(draft, null, 2) + "\n";
  try {
    copyFileSync(path, `${path}.bak`); // best-effort backup for recovery
  } catch (err) {
    logger.warn(`config backup failed (continuing): ${err instanceof Error ? err.message : String(err)}`);
  }
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, serialized, { mode: 0o600 });
  renameSync(tmp, path); // atomic swap within the same directory
  logger.info(`Config written to ${path} (backup at ${path}.bak)`);
  return { path };
}

/**
 * Get sanitized config for display (no secrets).
 */
export function getSanitizedConfig(): Record<string, unknown> {
  const cfg = getConfig();
  const sanitized = JSON.parse(JSON.stringify(cfg));

  // Redact auth keys
  if (sanitized.auth) {
    for (const [key, val] of Object.entries(sanitized.auth)) {
      if (key === "default") continue;
      if (val && typeof val === "object" && (val as any).profilesPath) {
        (val as any).profilesPath = "***";
      }
    }
  }

  // Redact provider auth
  for (const prov of Object.values(sanitized.providers ?? {})) {
    if ((prov as any).auth?.key) {
      (prov as any).auth.key = "***";
    }
  }

  return sanitized;
}

/**
 * Normalize a provider's `baseUrl` into an ordered, non-empty list of
 * endpoints: a single string becomes a one-element list (today's behavior,
 * unchanged — index 0 is that same endpoint); an array is used as-is, in the
 * given order (which the round-robin load balancer treats as endpoint
 * indices 0..n-1). Throws on an empty array — a provider must have at least
 * one endpoint to be usable.
 */
export function endpointsOf(entry: { baseUrl: string | string[] }): string[] {
  const list = Array.isArray(entry.baseUrl) ? entry.baseUrl : [entry.baseUrl];
  if (list.length === 0) {
    throw new Error("provider has no endpoints configured (baseUrl is an empty array)");
  }
  return list;
}

/**
 * Convert config api type to internal provider api type.
 */
export function toInternalApiType(
  api: "anthropic" | "openai" | "bedrock" | "azure",
): "anthropic-messages" | "openai-completions" | "bedrock-runtime" | "azure-openai" {
  if (api === "anthropic") return "anthropic-messages";
  if (api === "bedrock") return "bedrock-runtime";
  if (api === "azure") return "azure-openai";
  return "openai-completions";
}

/**
 * Check if a model supports adaptive thinking based on config.
 */
export function supportsAdaptiveThinking(modelId: string): boolean {
  const cfg = getConfig();
  const patterns = cfg.thinking?.adaptive ?? [];
  return patterns.some(p => modelId.includes(p));
}

/**
 * Check if a model has thinking enabled and get the budget.
 */
export function getThinkingBudget(modelId: string): number | null {
  const cfg = getConfig();
  const enabled = cfg.thinking?.enabled;
  if (!enabled) return null;
  if (enabled.models.some(m => modelId.includes(m))) {
    return enabled.budget;
  }
  return null;
}

/**
 * Get the security config block, or undefined if not configured.
 */
export function getSecurityConfig(): SecurityConfig | undefined {
  return getConfig().security;
}

/**
 * Whether user auth / governance / hardening is enabled.
 */
export function isSecurityEnabled(): boolean {
  return getConfig().security?.enabled === true;
}

/**
 * Validate the security block. Returns a list of human-readable errors;
 * an empty list means valid. The server treats a non-empty list as fatal
 * (fail-closed) when security.enabled is true — it must refuse to start
 * rather than run a CUI gateway in an unsafe configuration.
 */
export function validateSecurityConfig(cfg: FreeRouterConfig = getConfig()): string[] {
  const sec = cfg.security;
  const errors: string[] = [];

  // Provider sanity — runs regardless of security.enabled (fail-closed on misconfig).
  for (const [name, p] of Object.entries(cfg.providers ?? {})) {
    if (p.api === "azure") {
      const hasBaseUrl = Array.isArray(p.baseUrl) ? p.baseUrl.length > 0 : !!p.baseUrl;
      if (!hasBaseUrl) errors.push(`provider '${name}' (azure) requires baseUrl (the Azure resource endpoint)`);
      if (p.azureAuth === "entra" && (!p.entra?.tenantId || !p.entra?.clientId || !p.entra?.clientSecretEnv)) {
        errors.push(`provider '${name}' azureAuth="entra" requires entra.tenantId, entra.clientId, and entra.clientSecretEnv`);
      }
    }
  }

  if (!sec || sec.enabled !== true) return errors; // disabled → only provider sanity above

  // Identity (Feature 1) — OIDC is the only configured mechanism.
  if (!sec.oidc) {
    errors.push("security.oidc is required when security.enabled is true");
  } else {
    if (!sec.oidc.issuer) errors.push("security.oidc.issuer is required");
    if (!sec.oidc.audience) errors.push("security.oidc.audience is required");
    const algs = sec.oidc.algorithms ?? ["RS256", "ES256"];
    const banned = algs.filter((a) => a === "none" || a.startsWith("HS"));
    if (banned.length) {
      errors.push(`security.oidc.algorithms must not include symmetric/none algs: ${banned.join(", ")}`);
    }
    // Service-subject MFA/acr exemption allow-list — structural check only
    // (fail-closed on shape). Absent/empty is valid and preserves today's
    // behavior; see OidcConfig.serviceSubjects.
    if (sec.oidc.serviceSubjects !== undefined) {
      if (!Array.isArray(sec.oidc.serviceSubjects)) {
        errors.push("security.oidc.serviceSubjects must be an array of subject (sub) strings");
      } else if (sec.oidc.serviceSubjects.some((s) => typeof s !== "string" || s.trim() === "")) {
        errors.push("security.oidc.serviceSubjects entries must be non-empty strings (exact `sub` claims)");
      }
    }
    // On-behalf-of delegation allow-list — same fail-closed shape check. A
    // delegator normally is ALSO a serviceSubject (it authenticates
    // non-interactively); see OidcConfig.delegatingSubjects.
    if (sec.oidc.delegatingSubjects !== undefined) {
      if (!Array.isArray(sec.oidc.delegatingSubjects)) {
        errors.push("security.oidc.delegatingSubjects must be an array of subject (sub) strings");
      } else if (sec.oidc.delegatingSubjects.some((s) => typeof s !== "string" || s.trim() === "")) {
        errors.push("security.oidc.delegatingSubjects entries must be non-empty strings (exact `sub` claims)");
      }
    }
    for (const hdr of ["actingUserHeader", "actingGroupsHeader"] as const) {
      const v = sec.oidc[hdr];
      if (v !== undefined && (typeof v !== "string" || v.trim() === "")) {
        errors.push(`security.oidc.${hdr} must be a non-empty header name`);
      }
    }
  }

  // Egress deny-by-default (Feature 3) — the allow-list must exist and be non-empty.
  if (!sec.egress || !Array.isArray(sec.egress.allowlist) || sec.egress.allowlist.length === 0) {
    errors.push("security.egress.allowlist must list at least one authorized destination (deny-by-default)");
  } else {
    for (const [i, rule] of sec.egress.allowlist.entries()) {
      if (!rule.provider) errors.push(`security.egress.allowlist[${i}].provider is required`);
      const hasAllowedHost = Array.isArray(rule.allowedHost) ? rule.allowedHost.length > 0 : !!rule.allowedHost;
      if (!hasAllowedHost) errors.push(`security.egress.allowlist[${i}].allowedHost is required`);
      if (!Array.isArray(rule.authorizedClassifications) || rule.authorizedClassifications.length === 0) {
        errors.push(`security.egress.allowlist[${i}].authorizedClassifications must be non-empty`);
      }
    }
  }

  // Classification ladder (used by the egress gate).
  if (sec.classification) {
    if (!Array.isArray(sec.classification.levels) || sec.classification.levels.length === 0) {
      errors.push("security.classification.levels must be a non-empty ordered list (low→high)");
    } else if (!sec.classification.levels.includes(sec.classification.default)) {
      errors.push("security.classification.default must be one of security.classification.levels");
    }
  }

  // TLS native mode needs cert + key.
  if (sec.tls?.mode === "native" && (!sec.tls.certPath || !sec.tls.keyPath)) {
    errors.push("security.tls.mode=native requires certPath and keyPath");
  }

  // MCP gateway (Phase D) — fail-closed structural validation. In-boundary host
  // enforcement is layered at the gateway (registry.isMcpServerInBoundary, which
  // carries the env allow-list + configured-host escape hatches); here we reject
  // the structural misconfigs that should stop startup.
  if (sec.mcp?.enabled) {
    const levels = sec.classification?.levels ?? [];
    if (!Array.isArray(sec.mcp.servers) || sec.mcp.servers.length === 0) {
      errors.push("security.mcp.enabled is true but security.mcp.servers is empty");
    } else {
      for (const [i, s] of sec.mcp.servers.entries()) {
        if (!s.name) errors.push(`security.mcp.servers[${i}].name is required`);
        try {
          new URL(s.url);
        } catch {
          errors.push(`security.mcp.servers[${i}].url is not a valid URL`);
        }
        if (!Array.isArray(s.authorizedClassifications) || s.authorizedClassifications.length === 0) {
          errors.push(`security.mcp.servers[${i}].authorizedClassifications must be non-empty`);
        } else if (levels.length) {
          const unknown = s.authorizedClassifications.filter((c) => !levels.includes(c));
          if (unknown.length) errors.push(`security.mcp.servers[${i}].authorizedClassifications not in the classification ladder: ${unknown.join(", ")}`);
        }
      }
    }
  }

  // Resilience / circuit breaker (all optional; bounds guard against misconfig).
  if (sec.resilience) {
    const r = sec.resilience;
    const posInt = (v: unknown) => v === undefined || (Number.isInteger(v) && (v as number) > 0);
    const nonNegInt = (v: unknown) => v === undefined || (Number.isInteger(v) && (v as number) >= 0);
    if (!posInt(r.circuitThreshold)) errors.push("security.resilience.circuitThreshold must be a positive integer");
    if (!posInt(r.cooldownSec)) errors.push("security.resilience.cooldownSec must be a positive integer (seconds)");
    if (!nonNegInt(r.healthIntervalSec)) errors.push("security.resilience.healthIntervalSec must be a non-negative integer (seconds; 0 = off)");
  }

  return errors;
}

// Export defaults for backward compat
export { DEFAULT_CONFIG };
