/**
 * SecRouter Security — initialization + singletons.
 *
 * The server calls initSecurity(config.security) once at startup. Later phases
 * extend this to construct the identity provider, policy engine, egress gate,
 * and quota enforcer. Phase 1 wires the persistence store and the auditor.
 */

import { SqliteStore } from "./store/sqlite.js";
import { Auditor } from "./audit/audit.js";
import { makeSyslogForwarder } from "./audit/syslog.js";
import { initIdentity } from "./identity/index.js";
import { OverridesManager } from "./overrides.js";
import { setConfigOverlay } from "../config.js";
import { logger } from "../logger.js";
import type { Store, SecurityConfig, FreeRouterConfigLike } from "./types.js";

export { authenticate, AuthError } from "./identity/index.js";
export { getEffectivePolicy, resolvePolicy, authorize, authorizeTool, tierRank, classRank } from "./policy/engine.js";
export { audit, AuditFailureError } from "./audit/audit.js";
export { checkQuota } from "./accounting/quota.js";
export { computeCost, toUsageRecord } from "./accounting/usage.js";
export { checkEgress, EgressDeniedError } from "./egress/allowlist.js";
export { assertFips, isFipsEnabled, httpsOptions, createHttpsServer, FIPS_CIPHERS } from "./transport/tls.js";

let _store: Store | null = null;
let _auditor: Auditor | null = null;
let _overrides: OverridesManager | null = null;
let _config: SecurityConfig | null = null;
let _enabled = false;
let _jtiTimer: ReturnType<typeof setInterval> | null = null;

/**
 * Initialize the security subsystem. No-op (open mode) when security is
 * absent or disabled — preserves the original single-operator dev behavior.
 */
export function initSecurity(sec: SecurityConfig | undefined): void {
  closeSecurity();
  if (!sec || sec.enabled !== true) {
    _enabled = false;
    logger.warn(
      "⚠ Security DISABLED — no client auth, open CORS, no egress control. " +
        "Do NOT use this configuration in a CUI/CMMC environment.",
    );
    return;
  }

  _config = sec;
  _enabled = true;

  const store = new SqliteStore(sec.storePath);
  store.init();
  _store = store;
  // Optional secondary sink → syslog/SIEM (AU 3.3.x; 800-172 SOC integration).
  const forward =
    sec.audit?.sink === "both" ? makeSyslogForwarder(sec.audit.syslog) : undefined;
  _auditor = new Auditor(store, { failClosed: sec.audit?.failClosed !== false, forward });
  initIdentity(sec, store);

  // Register the admin-overrides overlay so DB edits layer over the file config.
  _overrides = new OverridesManager(store, _auditor);
  setConfigOverlay((cfg) => _overrides!.applyTo(cfg as unknown as FreeRouterConfigLike));

  if (forward) logger.info(`📡 Audit forwarding to syslog ${sec.audit?.syslog?.host}:${sec.audit?.syslog?.port}`);

  // Periodically evict expired jti replay entries.
  if (sec.oidc?.trackJti) {
    _jtiTimer = setInterval(
      () => {
        try {
          store.purgeExpiredJti(Math.floor(Date.now() / 1000));
        } catch (err) {
          logger.warn(`jti purge failed: ${err instanceof Error ? err.message : String(err)}`);
        }
      },
      10 * 60 * 1000,
    );
    _jtiTimer.unref?.();
  }

  logger.info(`🔒 Security ENABLED (store: ${sec.storePath ?? "~/.config/secrouter/secrouter.db"})`);
}

export function isEnabled(): boolean {
  return _enabled;
}

export function getSecurityConfigOrThrow(): SecurityConfig {
  if (!_config) throw new Error("security not initialized");
  return _config;
}

export function getStore(): Store {
  if (!_store) throw new Error("security store not initialized");
  return _store;
}

export function getAuditor(): Auditor {
  if (!_auditor) throw new Error("auditor not initialized");
  return _auditor;
}

export function getOverrides(): OverridesManager {
  if (!_overrides) throw new Error("overrides manager not initialized");
  return _overrides;
}

export function closeSecurity(): void {
  if (_jtiTimer) clearInterval(_jtiTimer);
  _jtiTimer = null;
  setConfigOverlay(null);
  _store?.close();
  _store = null;
  _auditor = null;
  _overrides = null;
  _config = null;
  _enabled = false;
}
