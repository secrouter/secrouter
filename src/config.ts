/**
 * SecRouter Config — loads external configuration from freerouter.config.json
 * Zero external deps. Falls back to hardcoded defaults if no config file exists.
 *
 * Config file search order:
 *   1. FREEROUTER_CONFIG env var
 *   2. ./freerouter.config.json (cwd)
 *   3. ~/.config/freerouter/config.json
 */

import { readFileSync, existsSync, writeFileSync, renameSync, copyFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { logger } from "./logger.js";
import type { SecurityConfig } from "./security/types.js";

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
  baseUrl: string;
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
  // freerouter.config.hardened.example.json for the full CUI-hardened config.
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

/** Finalize: snapshot the baseline and derive the effective config. */
function finalize(baseline: FreeRouterConfig, path: string | null): FreeRouterConfig {
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
  // 1. Env var
  const envPath = process.env.FREEROUTER_CONFIG;
  if (envPath && existsSync(envPath)) return envPath;

  // 2. CWD
  const cwdPath = join(process.cwd(), "freerouter.config.json");
  if (existsSync(cwdPath)) return cwdPath;

  // 3. ~/.config/freerouter/config.json
  const homePath = join(homedir(), ".config", "freerouter", "config.json");
  if (existsSync(homePath)) return homePath;

  return null;
}

/**
 * Load config from file, merging with defaults.
 */
export function loadConfig(): FreeRouterConfig {
  const configPath = findConfigFile();

  if (!configPath) {
    logger.info("No freerouter.config.json found, using built-in defaults");
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
 */
export function reloadConfig(): FreeRouterConfig {
  _config = null;
  return loadConfig();
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
  const patterns = cfg.thinking?.adaptive ?? ["claude-opus-4-6", "claude-opus-4.6"];
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
      if (!p.baseUrl) errors.push(`provider '${name}' (azure) requires baseUrl (the Azure resource endpoint)`);
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
  }

  // Egress deny-by-default (Feature 3) — the allow-list must exist and be non-empty.
  if (!sec.egress || !Array.isArray(sec.egress.allowlist) || sec.egress.allowlist.length === 0) {
    errors.push("security.egress.allowlist must list at least one authorized destination (deny-by-default)");
  } else {
    for (const [i, rule] of sec.egress.allowlist.entries()) {
      if (!rule.provider) errors.push(`security.egress.allowlist[${i}].provider is required`);
      if (!rule.allowedHost) errors.push(`security.egress.allowlist[${i}].allowedHost is required`);
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
