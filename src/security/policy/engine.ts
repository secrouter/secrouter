/**
 * Policy engine — resolves a Principal's effective authorization from config.
 *
 * Merge model (additive grants, least-privilege floor):
 *   default rule = the floor applied to everyone
 *   + each matching group rule = ADDITIVE grant (more groups → more access)
 *   + the per-user rule = final override (last word)
 *
 * Tiers are the primary gate; allowedModels is an OPTIONAL finer allow-list.
 * Budgets: the user rule replaces; otherwise the most generous budget per
 * window wins (a privileged group raises caps; set a low default to contain).
 *
 * Controls: AC 3.1.2 (limit transactions), 3.1.5 (least privilege).
 */

import { getSecurityConfig } from "../../config.js";
import type {
  AuthzDecision,
  Budget,
  BudgetWindow,
  EffectivePolicy,
  PolicyRule,
  Principal,
  SecurityConfig,
  Tier,
} from "../types.js";

/** Minimal shape of the routing config needed to pick a downgrade target. */
type RoutingTiers = { tiers: Record<string, { primary: string } | undefined> };

const TIER_RANK: Record<Tier, number> = { SIMPLE: 0, MEDIUM: 1, COMPLEX: 2, REASONING: 3 };
const ALL_TIERS: Tier[] = ["SIMPLE", "MEDIUM", "COMPLEX", "REASONING"];

export function tierRank(t: string): number {
  return TIER_RANK[t as Tier] ?? -1;
}

/** Return the higher-ranked of two tiers (used to widen a ceiling). */
function higherTier(a: Tier | null, b: Tier): Tier {
  if (!a) return b;
  return tierRank(a) >= tierRank(b) ? a : b;
}

/** Compare classifications by their position in the configured ladder (low→high). */
export function classRank(level: string, sec: SecurityConfig): number {
  const levels = sec.classification?.levels ?? [];
  const i = levels.indexOf(level);
  return i === -1 ? 0 : i;
}

function higherClass(a: string, b: string, sec: SecurityConfig): string {
  return classRank(a, sec) >= classRank(b, sec) ? a : b;
}

/** "Generosity" score for picking the most permissive budget per window. */
function budgetScore(b: Budget): number {
  return (b.maxCostUsd ?? Infinity) * 1e6 + (b.maxTotalTokens ?? Infinity) + (b.maxRequests ?? Infinity);
}

/**
 * Resolve the effective policy for a principal. With no policy block at all,
 * returns a deny-everything policy (deny-by-default).
 */
export function resolvePolicy(principal: Principal, sec: SecurityConfig): EffectivePolicy {
  // Phase 1: accumulate additive grants from the default floor + group rules.
  const groupRules: Array<{ name: string; rule: PolicyRule }> = [];
  if (sec.policy?.default) groupRules.push({ name: "default", rule: sec.policy.default });
  for (const g of principal.groups) {
    const r = sec.policy?.groups?.[g];
    if (r) groupRules.push({ name: `group:${g}`, rule: r });
  }

  const tierSet = new Set<Tier>();
  const allowModelSet = new Set<string>();
  let anyAllowModels = false;
  const denyModelSet = new Set<string>();
  const allowToolSet = new Set<string>();
  let anyAllowTools = false;
  const denyToolSet = new Set<string>();
  let maxTier: Tier | null = null;
  let admin = false;
  let onViolation: "deny" | "downgrade" = "deny";
  let maxClassification = sec.classification?.default ?? "UNCLASSIFIED";
  const groupBudgets = new Map<BudgetWindow, Budget>();
  const sources: string[] = [];

  for (const { name, rule } of groupRules) {
    sources.push(name);
    for (const t of rule.allowedTiers ?? []) tierSet.add(t);
    if (rule.allowedModels) {
      anyAllowModels = true;
      for (const m of rule.allowedModels) allowModelSet.add(m);
    }
    for (const m of rule.deniedModels ?? []) denyModelSet.add(m);
    if (rule.allowedTools) {
      anyAllowTools = true;
      for (const t of rule.allowedTools) allowToolSet.add(t);
    }
    for (const t of rule.deniedTools ?? []) denyToolSet.add(t);
    if (rule.maxTier) maxTier = higherTier(maxTier, rule.maxTier);
    if (rule.admin) admin = true;
    if (rule.onViolation) onViolation = rule.onViolation;
    if (rule.maxClassification) maxClassification = higherClass(maxClassification, rule.maxClassification, sec);
    for (const b of rule.budgets ?? []) {
      const cur = groupBudgets.get(b.window);
      if (!cur || budgetScore(b) > budgetScore(cur)) groupBudgets.set(b.window, b);
    }
  }

  let allowedTiers = ALL_TIERS.filter((t) => tierSet.has(t));
  let allowedModels: string[] | null = anyAllowModels ? [...allowModelSet] : null;
  let allowedTools: string[] | null = anyAllowTools ? [...allowToolSet] : null;
  let budgets = [...groupBudgets.values()];

  // Phase 2: the per-user rule is AUTHORITATIVE for the fields it specifies —
  // this is how an account is locked DOWN below the org default (least privilege).
  // Denies always accumulate; admin is granted if any source grants it.
  const userRule = sec.policy?.users?.[principal.id];
  if (userRule) {
    sources.push(`user:${principal.id}`);
    if (userRule.allowedTiers) allowedTiers = ALL_TIERS.filter((t) => userRule.allowedTiers!.includes(t));
    if (userRule.allowedModels) allowedModels = [...userRule.allowedModels];
    for (const m of userRule.deniedModels ?? []) denyModelSet.add(m);
    if (userRule.allowedTools) allowedTools = [...userRule.allowedTools];
    for (const t of userRule.deniedTools ?? []) denyToolSet.add(t);
    if (userRule.maxTier) maxTier = userRule.maxTier;
    if (userRule.admin) admin = true;
    if (userRule.onViolation) onViolation = userRule.onViolation;
    if (userRule.maxClassification) maxClassification = userRule.maxClassification;
    if (userRule.budgets) budgets = userRule.budgets;
  }

  return {
    allowedTiers,
    maxTier,
    allowedModels,
    deniedModels: [...denyModelSet],
    allowedTools,
    deniedTools: [...denyToolSet],
    onViolation,
    budgets,
    maxClassification,
    admin,
    sources,
  };
}

/**
 * Decide whether a principal may use a routed (model, tier). Returns:
 *   allow     — permitted as-is
 *   downgrade — not permitted, but a lower permitted tier exists (onViolation=downgrade)
 *   deny      — not permitted and no fallback (or onViolation=deny)
 *
 * Tier is the primary gate; allowedModels (when set) is an additional allow-list.
 * Controls: AC 3.1.2 (limit transactions), 3.1.5 (least privilege).
 */
export function authorize(
  policy: EffectivePolicy,
  model: string,
  tier: string,
  routing: RoutingTiers,
): AuthzDecision {
  const modelDenied = policy.deniedModels.includes(model);
  const modelAllowed = policy.allowedModels === null || policy.allowedModels.includes(model);

  // Explicit passthrough (user named a model): gate on the model allow-list only.
  if (tier === "EXPLICIT") {
    if (!modelDenied && modelAllowed) {
      return { effect: "allow", model, tier, reason: "explicit model permitted" };
    }
    return {
      effect: "deny",
      model,
      tier,
      reason: modelDenied ? "model explicitly denied" : "model not in allow-list",
    };
  }

  const tierOk =
    policy.allowedTiers.includes(tier as Tier) &&
    (!policy.maxTier || tierRank(tier) <= tierRank(policy.maxTier));

  if (tierOk && modelAllowed && !modelDenied) {
    return { effect: "allow", model, tier, reason: "permitted" };
  }

  const reason = !tierOk
    ? `tier ${tier} not permitted`
    : modelDenied
      ? "model explicitly denied"
      : "model not in allow-list";

  if (policy.onViolation === "deny") {
    return { effect: "deny", model, tier, reason };
  }

  // Downgrade: highest permitted tier (≤ maxTier) whose primary model is allowed.
  const candidates = policy.allowedTiers
    .filter((t) => !policy.maxTier || tierRank(t) <= tierRank(policy.maxTier))
    .sort((a, b) => tierRank(b) - tierRank(a));
  for (const t of candidates) {
    const primary = routing.tiers[t]?.primary;
    if (!primary) continue;
    if (policy.deniedModels.includes(primary)) continue;
    if (policy.allowedModels !== null && !policy.allowedModels.includes(primary)) continue;
    return { effect: "downgrade", model: primary, tier: t, reason: `${reason}; downgraded to ${t}` };
  }

  return { effect: "deny", model, tier, reason: `${reason}; no permitted fallback` };
}

/**
 * Decide whether a principal may use an MCP tool (Phase D). Tools are namespaced
 * `server/tool`; a policy entry may be an exact id or a `server/*` wildcard.
 *
 * DEFAULT-DENY (locked): with no `allowedTools` grant the principal gets NO tools
 * — stricter than models, because tools have no tier gate and are the higher-risk
 * exfiltration surface, so the allow-list IS the gate. Denies always win.
 * Controls: AC 3.1.3 (flow control), AC 3.1.5 (least privilege).
 */
export function authorizeTool(
  policy: EffectivePolicy,
  server: string,
  tool: string,
): { allow: boolean; reason: string } {
  const id = `${server}/${tool}`;
  const wildcard = `${server}/*`;
  const matches = (list: string[]) => list.includes(id) || list.includes(wildcard);

  if (matches(policy.deniedTools)) return { allow: false, reason: "tool explicitly denied" };
  if (policy.allowedTools === null) return { allow: false, reason: "no tools permitted for this principal" };
  if (matches(policy.allowedTools)) return { allow: true, reason: "permitted" };
  return { allow: false, reason: "tool not in allow-list" };
}

/** Convenience: resolve against the live config. */
export function getEffectivePolicy(principal: Principal): EffectivePolicy {
  const sec = getSecurityConfig();
  if (!sec) {
    // Security disabled → permissive (dev mode). Never reached when enabled.
    return {
      allowedTiers: ALL_TIERS,
      maxTier: null,
      allowedModels: null,
      deniedModels: [],
      allowedTools: null, // tools stay default-deny even in dev mode (the /mcp route is off anyway)
      deniedTools: [],
      onViolation: "deny",
      budgets: [],
      maxClassification: "UNCLASSIFIED",
      admin: true,
      sources: ["security-disabled"],
    };
  }
  return resolvePolicy(principal, sec);
}
