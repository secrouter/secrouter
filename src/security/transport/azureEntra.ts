/**
 * Microsoft Entra ID (Azure AD) token acquisition for Azure OpenAI providers
 * configured with azureAuth="entra".
 *
 * Uses the OAuth 2.0 client-credentials grant against the tenant's token
 * endpoint and caches the bearer token in memory until shortly before it
 * expires (Entra tokens live ~1h). Supports Azure commercial and Azure
 * Government via the authority/scope overrides:
 *   commercial → https://login.microsoftonline.com  ·  https://cognitiveservices.azure.com/.default
 *   government → https://login.microsoftonline.us    ·  https://cognitiveservices.azure.us/.default
 *
 * The client secret is read from an env var at call time and never stored.
 */

import { logger } from "../../logger.js";

export type EntraConfig = {
  tenantId: string;
  clientId: string;
  clientSecretEnv: string;
  authority?: string;
  scope?: string;
};

const DEFAULT_AUTHORITY = "https://login.microsoftonline.com";
const DEFAULT_SCOPE = "https://cognitiveservices.azure.com/.default";
const EARLY_REFRESH_MS = 60_000; // renew a minute before expiry

type Cached = { token: string; expiresAt: number };
const cache = new Map<string, Cached>();

/** Acquire (or return a cached) Entra bearer token for an Azure provider. */
export async function getEntraToken(providerKey: string, cfg: EntraConfig): Promise<string> {
  const now = Date.now();
  const hit = cache.get(providerKey);
  if (hit && hit.expiresAt - EARLY_REFRESH_MS > now) return hit.token;

  const secret = process.env[cfg.clientSecretEnv];
  if (!secret) {
    throw new Error(`Entra client secret env '${cfg.clientSecretEnv}' is not set for provider '${providerKey}'`);
  }
  const authority = (cfg.authority ?? DEFAULT_AUTHORITY).replace(/\/+$/, "");
  const scope = cfg.scope ?? DEFAULT_SCOPE;
  const url = `${authority}/${cfg.tenantId}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    client_id: cfg.clientId,
    client_secret: secret,
    grant_type: "client_credentials",
    scope,
  });

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 10_000);
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      signal: ctrl.signal,
    });
  } catch (err) {
    throw new Error(`Entra token request failed for provider '${providerKey}': ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Entra token request for provider '${providerKey}' → HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  const json = (await res.json()) as { access_token?: string; expires_in?: number };
  if (!json.access_token) throw new Error(`Entra token response for provider '${providerKey}' had no access_token`);

  const expiresAt = now + (json.expires_in ?? 3600) * 1000;
  cache.set(providerKey, { token: json.access_token, expiresAt });
  logger.info(`Acquired Entra token for provider '${providerKey}' (expires in ${json.expires_in ?? 3600}s)`);
  return json.access_token;
}

/** Test/ops helper — forget all cached tokens. */
export function clearEntraCache(): void {
  cache.clear();
}
