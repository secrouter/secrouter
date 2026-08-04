/**
 * Egress control — deny-by-default upstream allow-list + data-residency gate.
 *
 * This is the single most important compliance control: it prevents CUI from
 * being transmitted to an unauthorized destination (e.g. the commercial
 * api.anthropic.com endpoint, which is OUT of the FedRAMP/IL boundary, or any
 * foreign-jurisdiction provider such as Kimi/Moonshot).
 *
 * Enforced at the network choke point in provider.ts, immediately before fetch.
 * Controls: AC 3.1.3 (control CUI flow), SC 3.13.6 (deny-by-default), DFARS
 * 252.204-7012; 800-172 3.1.3e (enhanced flow enforcement).
 */

import type { EgressDecision, SecurityConfig } from "../types.js";

/** Thrown by the network choke point when a destination is not authorized. */
export class EgressDeniedError extends Error {
  constructor(
    message: string,
    public readonly provider: string,
  ) {
    super(message);
    this.name = "EgressDeniedError";
  }
}

/**
 * Normalize an egress rule's `allowedHost` into a non-empty ordered list of
 * hosts: a single string becomes a one-element list (today's default,
 * unchanged), an array is used as-is. Mirrors `config.endpointsOf()`'s
 * string-or-array normalization for a provider's `baseUrl`.
 */
export function allowedHostsOf(rule: { allowedHost: string | string[] }): string[] {
  return Array.isArray(rule.allowedHost) ? rule.allowedHost : [rule.allowedHost];
}

/**
 * Decide whether a request to (provider, host) carrying `classification` data
 * is permitted. Deny-by-default: an unlisted provider, a host mismatch, or a
 * classification the destination is not authorized for all fail closed.
 *
 * A provider with several upstream endpoints (config.endpointsOf) is
 * authorized by ONE rule whose `allowedHost` lists every endpoint host — this
 * matches ANY of them, so a pooled provider's replicas are all reachable
 * under a single egress authorization while any other host still denies.
 */
export function checkEgress(
  provider: string,
  host: string,
  classification: string,
  sec: SecurityConfig,
): EgressDecision {
  const list = sec.egress?.allowlist ?? [];
  const rule = list.find((r) => r.provider === provider);
  if (!rule) {
    return { allowed: false, reason: `provider '${provider}' is not in the egress allow-list` };
  }
  const hosts = allowedHostsOf(rule);
  if (!hosts.includes(host)) {
    return {
      allowed: false,
      reason: `host '${host}' is not authorized for provider '${provider}' (expected ${hosts.map((h) => `'${h}'`).join(" or ")})`,
      rule,
    };
  }
  if (!rule.authorizedClassifications.includes(classification)) {
    return {
      allowed: false,
      reason: `destination '${provider}' is not authorized for classification '${classification}'`,
      rule,
    };
  }
  return { allowed: true, reason: "authorized", rule };
}
