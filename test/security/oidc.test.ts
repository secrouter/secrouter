/**
 * OIDC provider tests — validates the security-critical JWT path against an
 * in-process JWKS. Run: npx tsx test/security/oidc.test.ts
 *
 * Covers: valid token, no credential, expired, wrong audience, alg=none
 * rejection (alg-confusion defense), MFA assertion, jti replay, the
 * service-subject MFA/acr exemption (security.oidc.serviceSubjects), and
 * its config validation.
 */

import { createServer, type Server } from "node:http";
import { generateKeyPair, exportJWK, SignJWT, base64url } from "jose";
import { OidcProvider } from "../../src/security/identity/oidc.js";
import { SqliteStore } from "../../src/security/store/sqlite.js";
import { AuthError } from "../../src/security/identity/errors.js";
import { validateSecurityConfig, type FreeRouterConfig } from "../../src/config.js";

const ISS = "https://idp.example.gov/realms/dod";
const AUD = "secrouter";

let pass = 0;
let fail = 0;
function ok(name: string, cond: boolean, extra = "") {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.error(`  ✗ ${name} ${extra}`);
  }
}
async function expectAuthError(name: string, code: string, fn: () => Promise<unknown>) {
  try {
    await fn();
    ok(name, false, "(expected AuthError, got success)");
  } catch (err) {
    ok(name, err instanceof AuthError && err.code === code, `(got ${(err as Error)?.message})`);
  }
}

async function main() {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "k1";
  jwk.alg = "RS256";
  jwk.use = "sig";

  const jwksServer: Server = createServer((req, res) => {
    if (req.url?.startsWith("/jwks")) {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ keys: [jwk] }));
    } else {
      res.statusCode = 404;
      res.end();
    }
  });
  await new Promise<void>((r) => jwksServer.listen(0, "127.0.0.1", r));
  const port = (jwksServer.address() as { port: number }).port;
  const jwksUri = `http://127.0.0.1:${port}/jwks`;

  const mint = (
    claims: Record<string, unknown>,
    opts: { expSec?: number; sub?: string } = {},
  ): Promise<string> =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: "k1" })
      .setIssuer(ISS)
      .setAudience(AUD)
      .setSubject(opts.sub ?? "user-1")
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + (opts.expSec ?? 300))
      .sign(privateKey);

  const bearer = (t: string) => ({ authorization: `Bearer ${t}` });
  const store = new SqliteStore(":memory:");
  store.init();
  const provider = new OidcProvider(
    { issuer: ISS, audience: AUD, jwksUri, groupsClaim: "groups", requireMfa: true, trackJti: true },
    store,
  );

  console.log("OIDC provider:");

  // Valid token
  const good = await mint({ groups: ["analysts", "cui-cleared"], amr: ["pwd", "otp"], email: "a@x.gov", jti: "j1" });
  const p = await provider.authenticate(bearer(good));
  ok("valid token → principal", p?.id === "user-1");
  ok("groups extracted", JSON.stringify(p?.groups) === JSON.stringify(["analysts", "cui-cleared"]));
  ok("email extracted", p?.email === "a@x.gov");
  ok("mfa asserted from amr", p?.mfa === true);

  // No credential → null (registry falls through to 401)
  ok("no Authorization header → null", (await provider.authenticate({})) === null);

  // Expired (beyond the 60s clock-skew tolerance)
  const expiredTok = await mint({ amr: ["otp"], jti: "je" }, { expSec: -120 });
  await expectAuthError("expired token → token_expired", "token_expired", () =>
    provider.authenticate(bearer(expiredTok)),
  );

  // Wrong audience
  const wrongAud = await new SignJWT({ amr: ["otp"], jti: "jw" })
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(ISS)
    .setAudience("some-other-app")
    .setSubject("user-1")
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + 300)
    .sign(privateKey);
  await expectAuthError("wrong audience → claim_invalid", "claim_invalid", () =>
    provider.authenticate(bearer(wrongAud)),
  );

  // alg=none forgery (alg-confusion defense)
  const header = base64url.encode(JSON.stringify({ alg: "none", kid: "k1" }));
  const body = base64url.encode(
    JSON.stringify({ iss: ISS, aud: AUD, sub: "attacker", amr: ["otp"], exp: Math.floor(Date.now() / 1000) + 300 }),
  );
  await expectAuthError("alg=none forgery → rejected", "token_invalid", () =>
    provider.authenticate(bearer(`${header}.${body}.`)),
  );

  // MFA required but absent
  const noMfaTok = await mint({ amr: ["pwd"], jti: "jn" });
  await expectAuthError("missing MFA → mfa_required", "mfa_required", () =>
    provider.authenticate(bearer(noMfaTok)),
  );

  // Replay: same jti twice
  const replayTok = await mint({ amr: ["otp"], jti: "replay-1" });
  await provider.authenticate(bearer(replayTok));
  await expectAuthError("replayed jti → token_replayed", "token_replayed", () =>
    provider.authenticate(bearer(replayTok)),
  );

  // ── Service-subject MFA/acr exemption (security.oidc.serviceSubjects) ──
  console.log("\nService-subject MFA/acr exemption:");
  const svcProvider = new OidcProvider(
    { issuer: ISS, audience: AUD, jwksUri, requireMfa: true, requiredAcr: "acr-gold", serviceSubjects: ["svc-agent-1"] },
    store,
  );

  // Listed sub, no amr, no acr at all → admitted anyway.
  const svcTok = await mint({ roles: ["ci-pipeline"], jti: "svc-1" }, { sub: "svc-agent-1" });
  const svcPrincipal = await svcProvider.authenticate(bearer(svcTok));
  ok("service-subject token (no MFA/acr) → admitted", svcPrincipal?.id === "svc-agent-1");
  ok(
    "service principal tagged roles includes 'service'",
    !!svcPrincipal?.roles.includes("service"),
    JSON.stringify(svcPrincipal?.roles),
  );
  ok(
    "tag is additive — the token's own roles claim survives too",
    !!svcPrincipal?.roles.includes("ci-pipeline"),
    JSON.stringify(svcPrincipal?.roles),
  );
  ok(
    "mfa still reports false — exemption skips the REQUIREMENT, doesn't fake the fact",
    svcPrincipal?.mfa === false,
  );

  // Same provider, a sub NOT on the allow-list → still gated exactly as before.
  const nonSvcNoMfaTok = await mint({ jti: "svc-2" }, { sub: "user-99" });
  await expectAuthError(
    "non-listed sub on the SAME provider → still mfa_required (unaffected)",
    "mfa_required",
    () => svcProvider.authenticate(bearer(nonSvcNoMfaTok)),
  );
  const nonSvcNoAcrTok = await mint({ amr: ["otp"], jti: "svc-3" }, { sub: "user-99" });
  await expectAuthError(
    "non-listed sub with MFA but wrong/missing acr → still acr_insufficient (unaffected)",
    "acr_insufficient",
    () => svcProvider.authenticate(bearer(nonSvcNoAcrTok)),
  );

  // The exemption is scoped to MFA/acr ONLY — an expired service-subject
  // token is still rejected like anyone else (never a general auth bypass).
  const svcExpiredTok = await mint({ jti: "svc-4" }, { sub: "svc-agent-1", expSec: -120 });
  await expectAuthError(
    "service-subject token still fails EXPIRED like anyone else",
    "token_expired",
    () => svcProvider.authenticate(bearer(svcExpiredTok)),
  );

  // Empty list ⇒ identical to absent (opt-in default preserved, not a wildcard).
  const emptyListProvider = new OidcProvider(
    { issuer: ISS, audience: AUD, jwksUri, requireMfa: true, serviceSubjects: [] },
    store,
  );
  const emptyListTok = await mint({ jti: "svc-5" }, { sub: "svc-agent-1" });
  await expectAuthError(
    "empty serviceSubjects list → same sub still requires MFA",
    "mfa_required",
    () => emptyListProvider.authenticate(bearer(emptyListTok)),
  );

  console.log("\nFail-closed security.oidc.serviceSubjects config validation:");
  const secBase = {
    providers: {} as Record<string, unknown>,
    tiers: {},
    security: {
      enabled: true,
      oidc: { issuer: ISS, audience: AUD } as Record<string, unknown>,
      egress: { allowlist: [{ provider: "p", allowedHost: "h", authorizedClassifications: ["UNCLASSIFIED"] }] },
    },
  };
  const serviceSubjectsErrors = (serviceSubjects: unknown) =>
    validateSecurityConfig({
      ...secBase,
      security: { ...secBase.security, oidc: { ...secBase.security.oidc, serviceSubjects } },
    } as unknown as FreeRouterConfig).filter((e) => /serviceSubjects/.test(e));

  ok("serviceSubjects absent → no errors", serviceSubjectsErrors(undefined).length === 0);
  ok("serviceSubjects empty array → no errors", serviceSubjectsErrors([]).length === 0);
  ok("serviceSubjects valid strings → no errors", serviceSubjectsErrors(["svc-1", "svc-2"]).length === 0);
  ok("serviceSubjects not an array → error", serviceSubjectsErrors("svc-1").length === 1);
  ok("serviceSubjects with an empty string → error", serviceSubjectsErrors([""]).length === 1);
  ok("serviceSubjects with a non-string entry → error", serviceSubjectsErrors([123]).length === 1);

  store.close();
  jwksServer.close();

  console.log(`\nOIDC: ${pass} passed, ${fail} failed`);
  if (fail > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
