/**
 * Identity registry — runs the configured IdentityProvider chain.
 *
 * Deny-by-default: a request with no usable credential, or an invalid one,
 * never yields a Principal. Absent credential → AuthError("no_credentials");
 * present-but-invalid → the provider's specific AuthError code.
 */

import { OidcProvider } from "./oidc.js";
import { AuthError } from "./errors.js";
import type { IdentityProvider, Principal, SecurityConfig, Store } from "../types.js";

let providers: IdentityProvider[] = [];

export function initIdentity(sec: SecurityConfig, store: Store): void {
  providers = [];
  if (sec.oidc) {
    providers.push(new OidcProvider(sec.oidc, store));
  }
  if (providers.length === 0) {
    throw new Error("security.enabled is true but no identity provider is configured (need security.oidc)");
  }
}

/**
 * Authenticate a request from its headers. Throws AuthError on failure
 * (caller maps every AuthError to a generic 401 + audited reason code).
 */
export async function authenticate(
  headers: Record<string, string | string[] | undefined>,
): Promise<Principal> {
  for (const p of providers) {
    const principal = await p.authenticate(headers); // throws AuthError for present-but-invalid
    if (principal) return principal;
  }
  throw new AuthError("no_credentials");
}

export { AuthError };
