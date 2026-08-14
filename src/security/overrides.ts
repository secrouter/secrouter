/**
 * Admin config overrides — DB-backed edits layered over the file config.
 *
 * The file config (secrouter.config.hardened.example.json) is the
 * change-controlled baseline; the admin console writes deltas here. Every edit
 * is validated against the merged result (fail-closed — an edit that would make
 * the security config invalid is rejected and rolled back) and audited.
 *
 * Scope: policy groups/users and tier→model mappings are editable. Providers
 * and the egress allow-list remain file-managed (compliance-critical) and are
 * exposed read-only by the API.
 */

import { getConfig, rebuildEffectiveConfig, validateSecurityConfig } from "../config.js";
import { audit } from "./audit/audit.js";
import type { Auditor } from "./audit/audit.js";
import type { ConfigOverride, FreeRouterConfigLike, OverrideScope, Store } from "./types.js";

/** Structural shape of the config we mutate (avoids importing config types here). */
type Mutable = FreeRouterConfigLike;

export class OverridesManager {
  constructor(
    private readonly store: Store,
    private readonly auditor: Auditor,
  ) {}

  /** Merge all overrides into a config clone (registered as the config overlay). */
  applyTo(cfg: Mutable): void {
    for (const o of this.store.listOverrides()) {
      if (o.scope === "policy.group" || o.scope === "policy.user") {
        cfg.security ??= { enabled: false };
        cfg.security.policy ??= { default: {} };
        const bucket = o.scope === "policy.group" ? "groups" : "users";
        cfg.security.policy[bucket] ??= {};
        cfg.security.policy[bucket]![o.name] = o.value;
      } else if (o.scope === "tier") {
        cfg.tiers ??= {};
        cfg.tiers[o.name] = o.value;
      } else if (o.scope === "provider") {
        cfg.providers ??= {};
        cfg.providers[o.name] = o.value;
      }
    }
  }

  list(): ConfigOverride[] {
    return this.store.listOverrides();
  }

  /** Upsert an override; validate the merged result; roll back + throw if invalid. */
  put(scope: OverrideScope, name: string, value: unknown, by: string, nowIso: string): void {
    if (!name || /[^A-Za-z0-9._@:-]/.test(name)) throw new Error("invalid override name");
    const prev = this.store.listOverrides().find((o) => o.scope === scope && o.name === name);
    this.store.putOverride({ scope, name, value, updatedBy: by, updatedAt: nowIso });
    rebuildEffectiveConfig();
    const errors = validateSecurityConfig(getConfig());
    if (errors.length) {
      if (prev) this.store.putOverride(prev);
      else this.store.deleteOverride(scope, name);
      rebuildEffectiveConfig();
      throw new Error(`override rejected (config would be invalid): ${errors.join("; ")}`);
    }
    this.auditor.emit(audit.adminAction(by, `override.put`, { scope, name }));
  }

  remove(scope: OverrideScope, name: string, by: string): void {
    this.store.deleteOverride(scope, name);
    rebuildEffectiveConfig();
    this.auditor.emit(audit.adminAction(by, `override.delete`, { scope, name }));
  }
}
