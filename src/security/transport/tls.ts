/**
 * Transport security — FIPS assertion + TLS server options.
 *
 * Two supported models (SC 3.13.8/3.13.11/3.13.15, AC 3.1.13):
 *   - tls.mode="frontend" (recommended): TLS terminated by a FIPS-validated
 *     reverse proxy; SecRouter binds localhost and is not the crypto boundary.
 *   - tls.mode="native": SecRouter terminates TLS via node:https. This is only
 *     FIPS-compliant when Node links a CMVP-validated OpenSSL FIPS provider.
 *
 * assertFips() enforces fail-closed startup when requireFips is set.
 */

import { createServer as createHttpsServer, type ServerOptions } from "node:https";
import { readFileSync } from "node:fs";
import crypto from "node:crypto";
import { logger } from "../../logger.js";
import type { SecurityConfig } from "../types.js";

/**
 * FIPS-approved TLS 1.2 cipher suites (NIST SP 800-52r2). TLS 1.3 suites
 * (AES-GCM / ChaCha20 per RFC 8446) are negotiated automatically.
 */
export const FIPS_CIPHERS = [
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256",
].join(":");

export function isFipsEnabled(): boolean {
  try {
    return crypto.getFips() === 1;
  } catch {
    return false;
  }
}

/**
 * Assert FIPS-validated crypto is active when required. Fail-closed: throws so
 * the server refuses to start rather than process CUI with non-validated crypto.
 */
export function assertFips(required: boolean): void {
  if (!required) {
    if (!isFipsEnabled()) {
      logger.warn("FIPS not required and not enabled — acceptable only in dev/non-CUI environments.");
    }
    return;
  }
  if (!isFipsEnabled()) {
    throw new Error(
      "security.requireFips is set but Node crypto is NOT in FIPS mode. Run on a build " +
        "linked against a CMVP-validated OpenSSL FIPS provider (crypto.setFips / --force-fips / " +
        "openssl.cnf fips=yes), OR terminate TLS at a FIPS-validated front end and set tls.mode='frontend'.",
    );
  }
  logger.info("✅ FIPS-validated crypto active (crypto.getFips()=1)");
}

/** Build node:https options for native TLS termination. */
export function httpsOptions(sec: SecurityConfig): ServerOptions {
  const tls = sec.tls;
  if (!tls || tls.mode !== "native") throw new Error("tls.mode must be 'native' for httpsOptions");
  if (!tls.certPath || !tls.keyPath) throw new Error("tls native mode requires certPath and keyPath");
  return {
    cert: readFileSync(tls.certPath),
    key: readFileSync(tls.keyPath),
    minVersion: tls.minVersion ?? "TLSv1.2",
    ciphers: tls.ciphers ?? FIPS_CIPHERS,
    honorCipherOrder: true,
  };
}

export { createHttpsServer };
