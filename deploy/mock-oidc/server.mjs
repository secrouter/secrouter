/**
 * Mock OIDC IdP for the SecRouter TEST stack — DO NOT use outside testing.
 *
 * Zero dependencies (node:http + node:crypto). Issues real RS256 JWTs and
 * implements just enough of OIDC to exercise SecRouter end-to-end:
 *   GET  /.well-known/openid-configuration   discovery
 *   GET  /jwks                               public keys
 *   GET  /authorize                          PKCE auth — pick a persona (1 click)
 *   POST /token                              PKCE code exchange → access_token
 *   GET  /mint?persona=admin                 test convenience: mint a token for curl
 *
 * Env: PORT (8080), EXTERNAL_ISSUER (browser-facing base URL used as `iss` and
 * in discovery), AUDIENCE (secrouter).
 */
import { createServer } from "node:http";
import { generateKeyPairSync, createHash, createSign, randomUUID } from "node:crypto";

const PORT = parseInt(process.env.PORT ?? "8080", 10);
const ISSUER = (process.env.EXTERNAL_ISSUER ?? `http://localhost:${PORT}`).replace(/\/$/, "");
const AUDIENCE = process.env.AUDIENCE ?? "secrouter";
const KID = "mock-key-1";

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: KID, alg: "RS256", use: "sig" };

const PERSONAS = {
  admin: { sub: "test-admin", name: "Test Admin", groups: ["secrouter-admins"] },
  power: { sub: "test-power", name: "Power User", groups: ["secrouter-power-users"] },
  basic: { sub: "test-basic", name: "Basic User", groups: [] },
};

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const json64 = (o) => b64url(JSON.stringify(o));

function mintToken(persona) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", kid: KID, typ: "JWT" };
  const payload = {
    iss: ISSUER, aud: AUDIENCE, sub: persona.sub, name: persona.name,
    groups: persona.groups, amr: ["pwd", "otp"], acr: "mfa",
    iat: now, exp: now + 3600, jti: randomUUID(),
  };
  const signingInput = `${json64(header)}.${json64(payload)}`;
  const sig = createSign("RSA-SHA256").update(signingInput).sign(privateKey);
  return `${signingInput}.${b64url(sig)}`;
}

function send(res, code, body, type = "application/json", extra = {}) {
  res.writeHead(code, { "Content-Type": type, "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "*", ...extra });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}

function readBody(req) {
  return new Promise((r) => { let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => r(d)); });
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, ISSUER);
  const path = url.pathname;
  if (req.method === "OPTIONS") return send(res, 204, "");

  if (path === "/.well-known/openid-configuration") {
    return send(res, 200, {
      issuer: ISSUER,
      jwks_uri: `${ISSUER}/jwks`,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
    });
  }

  if (path === "/jwks") return send(res, 200, { keys: [jwk] });

  // Test convenience: mint a token directly (NOT real OIDC).
  if (path === "/mint") {
    const persona = PERSONAS[url.searchParams.get("persona") ?? "admin"] ?? PERSONAS.admin;
    return send(res, 200, { access_token: mintToken(persona), token_type: "Bearer", expires_in: 3600 });
  }

  // PKCE: show a 1-click persona chooser; each link carries a code for that persona.
  if (path === "/authorize") {
    const redirect = url.searchParams.get("redirect_uri") ?? "";
    const state = url.searchParams.get("state") ?? "";
    const cc = url.searchParams.get("code_challenge") ?? "";
    const links = Object.entries(PERSONAS).map(([key, p]) => {
      const code = json64({ persona: key, cc });
      const sep = redirect.includes("?") ? "&" : "?";
      const href = `${redirect}${sep}code=${encodeURIComponent(code)}${state ? `&state=${encodeURIComponent(state)}` : ""}`;
      return `<a class="b" href="${href}"><b>${p.name}</b><span>${key === "admin" ? "secrouter-admins" : p.groups.join(", ") || "no groups"}</span></a>`;
    }).join("");
    const html = `<!doctype html><meta charset=utf-8><title>Mock IdP — sign in</title>
<style>body{font:14px ui-monospace,Menlo,monospace;background:#171511;color:#e8e3d3;display:flex;flex-direction:column;align-items:center;gap:14px;padding-top:70px}
h1{font-size:13px;letter-spacing:.14em;text-transform:uppercase}.note{color:#9a9077;font-size:12px}
.b{display:flex;flex-direction:column;gap:3px;width:300px;padding:12px 16px;background:#201e17;border:1px solid #3a3730;border-left:3px solid #94ad50;color:#e8e3d3;text-decoration:none;border-radius:2px}
.b span{color:#9a9077;font-size:11px}.b:hover{border-color:#94ad50}</style>
<h1>🔒 Mock IdP — choose a test identity</h1>${links}<div class=note>TEST ONLY — any choice issues a valid signed token.</div>`;
    return send(res, 200, html, "text/html; charset=utf-8");
  }

  if (path === "/token" && req.method === "POST") {
    const params = new URLSearchParams(await readBody(req));
    let decoded;
    try { decoded = JSON.parse(Buffer.from(params.get("code") ?? "", "base64url").toString()); } catch { return send(res, 400, { error: "invalid_grant" }); }
    const verifier = params.get("code_verifier") ?? "";
    const expected = b64url(createHash("sha256").update(verifier).digest());
    if (decoded.cc && decoded.cc !== expected) return send(res, 400, { error: "invalid_grant", error_description: "PKCE check failed" });
    const persona = PERSONAS[decoded.persona] ?? PERSONAS.admin;
    return send(res, 200, { access_token: mintToken(persona), token_type: "Bearer", expires_in: 3600 });
  }

  send(res, 404, { error: "not_found", path });
});

server.listen(PORT, () => console.log(`[mock-oidc] issuer=${ISSUER} listening on :${PORT}`));
