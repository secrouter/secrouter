/**
 * OIDC / JWT identity provider.
 *
 * Validates a bearer JWT issued by the enterprise IdP (Keycloak, Okta, Entra,
 * PingFederate). LDAP/AD group memberships arrive as token claims.
 *
 * Controls: IA 3.5.1 (identify), 3.5.2 (authenticate), 3.5.3 (MFA assertion),
 * 3.5.4 (replay resistance via jti). Signature verification runs through the
 * Node crypto backend so it inherits a FIPS-validated OpenSSL when present
 * (SC 3.13.11).
 *
 * `security.oidc.serviceSubjects` is a narrow, opt-in escape hatch from the
 * MFA/acr gate (3.5.3) for non-interactive machine clients (OIDC
 * client-credentials grant) enumerated by exact `sub`; see the field's doc
 * in security/types.ts. Absent/empty ⇒ no change to today's behavior, and
 * every `sub` not listed still requires MFA/acr exactly as before.
 */

import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from "jose";
import type { JWTPayload, JWTVerifyGetKey } from "jose";
import { logger } from "../../logger.js";
import { AuthError } from "./errors.js";
import type { IdentityProvider, OidcConfig, Principal, Store } from "../types.js";

const DEFAULT_ALGS = ["RS256", "ES256", "RS384", "ES384", "RS512", "ES512", "PS256", "PS384", "PS512"];
const DEFAULT_MFA_AMR = ["mfa", "otp", "hwk", "swk", "pop", "mca", "fpt", "sc"];

/** Read a value at a dotted path (e.g. "realm_access.roles"). */
function getByPath(obj: Record<string, unknown>, path: string): unknown {
  return path.split(".").reduce<unknown>((acc, key) => {
    if (acc && typeof acc === "object" && key in (acc as Record<string, unknown>)) {
      return (acc as Record<string, unknown>)[key];
    }
    return undefined;
  }, obj);
}

/** Coerce a claim into a string[] (accepts array, space-delimited string, or scalar). */
function toStringArray(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v === "string") return v.split(/[\s,]+/).filter(Boolean);
  if (v == null) return [];
  return [String(v)];
}

function extractBearer(headers: Record<string, string | string[] | undefined>): string | null {
  const raw = headers["authorization"] ?? headers["Authorization"];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (!value) return null;
  const m = value.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

export class OidcProvider implements IdentityProvider {
  readonly name = "oidc";
  private jwks: JWTVerifyGetKey | null = null;
  private readonly algorithms: string[];

  constructor(
    private readonly cfg: OidcConfig,
    private readonly store?: Store,
  ) {
    // Defense in depth: config validation already bans none/HS, filter again here.
    this.algorithms = (cfg.algorithms ?? DEFAULT_ALGS).filter((a) => a !== "none" && !a.startsWith("HS"));
    if (this.algorithms.length === 0) {
      throw new Error("OIDC: no asymmetric signature algorithms permitted");
    }
  }

  /** Lazily resolve the JWKS endpoint (discovery if jwksUri not configured). */
  private async getJwks(): Promise<JWTVerifyGetKey> {
    if (this.jwks) return this.jwks;
    let jwksUri = this.cfg.jwksUri;
    if (!jwksUri) {
      const discoveryUrl = `${this.cfg.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
      const res = await fetch(discoveryUrl);
      if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status} ${discoveryUrl}`);
      const doc = (await res.json()) as { jwks_uri?: string };
      if (!doc.jwks_uri) throw new Error(`OIDC discovery doc missing jwks_uri (${discoveryUrl})`);
      jwksUri = doc.jwks_uri;
      logger.info(`OIDC: discovered jwks_uri ${jwksUri}`);
    }
    this.jwks = createRemoteJWKSet(new URL(jwksUri), {
      cacheMaxAge: (this.cfg.jwksCacheTtlSec ?? 600) * 1000,
      cooldownDuration: 30_000,
      timeoutDuration: 5_000,
    });
    return this.jwks;
  }

  async authenticate(
    headers: Record<string, string | string[] | undefined>,
  ): Promise<Principal | null> {
    const token = extractBearer(headers);
    if (!token) return null; // no credential → let the registry fall through

    const jwks = await this.getJwks();
    let payload: JWTPayload;
    try {
      const result = await jwtVerify(token, jwks, {
        issuer: this.cfg.issuer,
        audience: this.cfg.audience,
        algorithms: this.algorithms,
        clockTolerance: this.cfg.clockToleranceSec ?? 60,
      });
      payload = result.payload;
    } catch (err) {
      // Map jose errors to stable codes for audit; never surface details to client.
      if (err instanceof joseErrors.JWTExpired) throw new AuthError("token_expired");
      if (err instanceof joseErrors.JWTClaimValidationFailed) throw new AuthError("claim_invalid");
      if (err instanceof joseErrors.JWSSignatureVerificationFailed)
        throw new AuthError("signature_invalid");
      if (err instanceof joseErrors.JOSEError) throw new AuthError("token_invalid");
      throw new AuthError("token_invalid", err instanceof Error ? err.message : undefined);
    }

    if (!payload.sub) throw new AuthError("missing_sub");
    const sub = String(payload.sub);

    // ── Service-subject exemption (opt-in, narrow) ──
    // A machine client on the client-credentials grant has no interactive
    // login and can never produce an MFA assertion. Rather than weaken
    // requireMfa/requiredAcr globally, an operator may enumerate exact `sub`s
    // here that skip ONLY those two checks below. Everything already verified
    // above (signature, issuer, audience, exp/nbf, algorithm) still applies
    // in full, and any `sub` not in this list is completely unaffected.
    const isServiceSubject = (this.cfg.serviceSubjects ?? []).includes(sub);

    // ── MFA assertion (IA 3.5.3) ──
    const amr = toStringArray(payload["amr"]);
    const mfaValues = this.cfg.mfaAmrValues ?? DEFAULT_MFA_AMR;
    const mfa = amr.some((a) => mfaValues.includes(a));
    if (!isServiceSubject) {
      if (this.cfg.requireMfa && !mfa) throw new AuthError("mfa_required");
      if (this.cfg.requiredAcr && payload["acr"] !== this.cfg.requiredAcr) {
        throw new AuthError("acr_insufficient");
      }
    }

    // ── Replay resistance (IA 3.5.4) ── unaffected by the exemption above.
    if (this.cfg.trackJti && this.store) {
      const jti = typeof payload.jti === "string" ? payload.jti : null;
      if (!jti) throw new AuthError("missing_jti");
      const exp = typeof payload.exp === "number" ? payload.exp : Math.floor(Date.now() / 1000) + 300;
      if (!this.store.recordJtiIfNew(jti, exp)) throw new AuthError("token_replayed");
    }

    // Informational tag only (audit/UI); governance is still the explicit
    // security.policy.users[<sub>] mechanism, same as any other principal.
    const roles = toStringArray(getByPath(payload, this.cfg.rolesClaim ?? "roles"));
    if (isServiceSubject && !roles.includes("service")) roles.push("service");

    const base: Principal = {
      id: sub,
      email: typeof payload["email"] === "string" ? payload["email"] : undefined,
      displayName:
        (typeof payload["name"] === "string" && payload["name"]) ||
        (typeof payload["preferred_username"] === "string" && payload["preferred_username"]) ||
        undefined,
      groups: toStringArray(getByPath(payload, this.cfg.groupsClaim ?? "groups")),
      roles,
      mfa,
      authTime: typeof payload["auth_time"] === "number" ? payload["auth_time"] : undefined,
      jti: typeof payload.jti === "string" ? payload.jti : undefined,
      claims: payload as Record<string, unknown>,
    };

    // ── On-behalf-of delegation (trusted front-end, AC 3.1.x) ──
    // Applied AFTER every token check above. Only a caller whose own `sub` is in
    // delegatingSubjects may swap identity to a forwarded end-user; for everyone
    // else the header is inert, so there is no impersonation path. See the field
    // doc in security/types.ts.
    return this.applyDelegation(base, headers);
  }

  /** Read a single header value case-insensitively (Node lowercases, but be robust). */
  private headerValue(
    headers: Record<string, string | string[] | undefined>,
    name: string,
  ): string | null {
    const raw = headers[name] ?? headers[name.toLowerCase()];
    const v = Array.isArray(raw) ? raw[0] : raw;
    return v ? String(v).trim() : null;
  }

  /**
   * If the authenticated caller is a trusted delegator and forwards an acting
   * end-user, return a principal for THAT user (policy/usage/audit attribute to
   * them) tagged with `delegatedBy`. Otherwise return the caller unchanged.
   */
  private applyDelegation(
    base: Principal,
    headers: Record<string, string | string[] | undefined>,
  ): Principal {
    const delegators = this.cfg.delegatingSubjects ?? [];
    if (delegators.length === 0 || !delegators.includes(base.id)) return base;

    const userHeader = (this.cfg.actingUserHeader ?? "x-sec-acting-user").toLowerCase();
    const actingUser = this.headerValue(headers, userHeader);
    if (!actingUser) return base; // no delegation requested — the service acts as itself

    // A forwarded identity from a trusted service is authoritative, but never
    // trust its shape: reject control chars / absurd length (defense in depth
    // against a header-injection or a misconfigured forwarder).
    if (actingUser.length > 256 || /[\u0000-\u001f\u007f]/.test(actingUser)) {
      throw new AuthError("delegation_invalid");
    }
    const groupsHeader = (this.cfg.actingGroupsHeader ?? "x-sec-acting-groups").toLowerCase();
    const actingGroups = toStringArray(this.headerValue(headers, groupsHeader));
    const looksEmail = /^[^@\s]+@[^@\s]+$/.test(actingUser);

    return {
      id: actingUser,
      email: looksEmail ? actingUser : undefined,
      displayName: actingUser,
      groups: actingGroups,
      roles: [],
      // The end-user's MFA is enforced at the delegator's own OIDC login (SecSSO),
      // not re-attested from this service token — carry the service token's value
      // and let `delegatedBy` in the audit make the trust chain explicit.
      mfa: base.mfa,
      jti: base.jti,
      delegatedBy: base.id,
      // `act` is the RFC 8693 actor claim: who is acting for this subject.
      claims: { sub: actingUser, act: { sub: base.id }, delegated_by: base.id },
    };
  }
}
