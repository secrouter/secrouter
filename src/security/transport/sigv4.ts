/**
 * AWS Signature Version 4 signer (zero-dep).
 *
 * Used to authenticate requests to Amazon Bedrock in AWS GovCloud (US) — the
 * only FedRAMP High / DoD IL4-5 authorized path for Claude on CUI. Verified
 * against the published AWS `get-vanilla` SigV4 test vector (see sigv4.test.ts).
 *
 * Signing runs through node:crypto HMAC/SHA-256, inheriting a FIPS-validated
 * OpenSSL when present (SC 3.13.11).
 */

import { createHash, createHmac } from "node:crypto";

export type SignOptions = {
  method: string;
  /** Full request URL (scheme://host/path?query). */
  url: string;
  region: string;
  service: string; // "bedrock" for Bedrock Runtime
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  /** Extra headers to include in the signature (e.g. content-type). */
  headers?: Record<string, string>;
  body?: string;
  /** Injectable clock for deterministic tests. */
  now?: Date;
};

const sha256Hex = (data: string): string => createHash("sha256").update(data, "utf8").digest("hex");
const hmac = (key: Buffer | string, data: string): Buffer => createHmac("sha256", key).update(data, "utf8").digest();

/** RFC 3986 encoding for a path segment (AWS does not double-encode non-S3 paths). */
function encodeSegment(seg: string): string {
  return encodeURIComponent(seg).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function canonicalUri(pathname: string): string {
  if (pathname === "" || pathname === "/") return "/";
  return pathname
    .split("/")
    .map((seg) => (seg ? encodeSegment(decodeURIComponent(seg)) : ""))
    .join("/");
}

function canonicalQuery(search: URLSearchParams): string {
  const pairs: Array<[string, string]> = [];
  for (const [k, v] of search) pairs.push([k, v]);
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : 1));
  return pairs.map(([k, v]) => `${encodeSegment(k)}=${encodeSegment(v)}`).join("&");
}

function amzDates(now: Date): { amzDate: string; dateStamp: string } {
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, ""); // YYYYMMDDTHHMMSSZ
  return { amzDate, dateStamp: amzDate.slice(0, 8) };
}

/**
 * Sign a request. Returns the headers to send (Authorization + x-amz-*),
 * merged with the caller's headers.
 */
export function signRequest(o: SignOptions): Record<string, string> {
  const url = new URL(o.url);
  const now = o.now ?? new Date();
  const { amzDate, dateStamp } = amzDates(now);
  const body = o.body ?? "";
  const payloadHash = sha256Hex(body);

  // Headers to sign: host + x-amz-date + caller extras + optional session token.
  const signed: Record<string, string> = { host: url.host, "x-amz-date": amzDate };
  for (const [k, v] of Object.entries(o.headers ?? {})) signed[k.toLowerCase()] = v.trim();
  if (o.sessionToken) signed["x-amz-security-token"] = o.sessionToken;

  const sortedNames = Object.keys(signed).sort();
  const canonicalHeaders = sortedNames.map((n) => `${n}:${signed[n]}\n`).join("");
  const signedHeaders = sortedNames.join(";");

  const canonicalRequest = [
    o.method.toUpperCase(),
    canonicalUri(url.pathname),
    canonicalQuery(url.searchParams),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const scope = `${dateStamp}/${o.region}/${o.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest)].join("\n");

  const kDate = hmac(`AWS4${o.secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, o.region);
  const kService = hmac(kRegion, o.service);
  const kSigning = hmac(kService, "aws4_request");
  const signature = createHmac("sha256", kSigning).update(stringToSign, "utf8").digest("hex");

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${o.accessKeyId}/${scope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const out: Record<string, string> = {
    ...(o.headers ?? {}),
    "X-Amz-Date": amzDate,
    Authorization: authorization,
  };
  if (o.sessionToken) out["X-Amz-Security-Token"] = o.sessionToken;
  return out;
}
