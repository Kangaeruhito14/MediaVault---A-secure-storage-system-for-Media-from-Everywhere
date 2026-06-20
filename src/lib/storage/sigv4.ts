/**
 * AWS Signature Version 4 — runs in the browser so storage credentials never
 * reach the operator. Works for any S3-compatible service (Cloudflare R2,
 * Backblaze B2, Wasabi, AWS S3). Uses Web Crypto HMAC-SHA256.
 *
 * Verified against AWS's official "get-vanilla" SigV4 test vector (see tests).
 */
import { sha256Hex } from '../e2ee/crypto';

const te = new TextEncoder();

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hmac(key: Uint8Array, data: string | Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const msg = typeof data === 'string' ? te.encode(data) : data;
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
}

/** AWS URI-encoding (RFC 3986); slashes preserved only when encodeSlash=false. */
export function uriEncode(input: string, encodeSlash: boolean): string {
  const bytes = te.encode(input);
  let out = '';
  for (const b of bytes) {
    const unreserved =
      (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) ||
      b === 0x2d || b === 0x5f || b === 0x2e || b === 0x7e; // - _ . ~
    if (unreserved) out += String.fromCharCode(b);
    else if (b === 0x2f) out += encodeSlash ? '%2F' : '/';
    else out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
  }
  return out;
}

export interface SignV4Input {
  method: string;
  /** Absolute path, already split by '/', e.g. "/bucket/key". */
  path: string;
  /** Map of query param name -> value (unencoded). */
  query?: Record<string, string>;
  /** Header name -> value. Must include host. x-amz-date is added if absent. */
  headers: Record<string, string>;
  /** Hex SHA-256 of the body, or "UNSIGNED-PAYLOAD". */
  payloadHash: string;
  region: string;
  service: string; // 's3'
  accessKeyId: string;
  secretAccessKey: string;
  /** Override the timestamp (testing only). Format: YYYYMMDDTHHMMSSZ. */
  amzDate?: string;
}

export interface SignV4Output {
  authorization: string;
  amzDate: string;
  signature: string;
  signedHeaders: string;
}

export async function signV4(input: SignV4Input): Promise<SignV4Output> {
  const amzDate = input.amzDate ?? new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const { region, service, accessKeyId, secretAccessKey } = input;

  // Canonical headers (lowercase name, trimmed value), sorted by name.
  const headerEntries = Object.entries(input.headers).map(
    ([k, v]) => [k.toLowerCase(), v.trim().replace(/\s+/g, ' ')] as [string, string],
  );
  headerEntries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const canonicalHeaders = headerEntries.map(([k, v]) => `${k}:${v}\n`).join('');
  const signedHeaders = headerEntries.map(([k]) => k).join(';');

  // Canonical query string (sorted, encoded).
  const q = input.query ?? {};
  const canonicalQuery = Object.keys(q)
    .sort()
    .map((k) => `${uriEncode(k, true)}=${uriEncode(q[k], true)}`)
    .join('&');

  const canonicalUri = uriEncode(input.path, false);

  const canonicalRequest = [
    input.method.toUpperCase(),
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    input.payloadHash,
  ].join('\n');

  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    await sha256Hex(te.encode(canonicalRequest)),
  ].join('\n');

  // Derive the signing key.
  const kDate = await hmac(te.encode('AWS4' + secretAccessKey), dateStamp);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  const kSigning = await hmac(kService, 'aws4_request');
  const signature = toHex(await hmac(kSigning, stringToSign));

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return { authorization, amzDate, signature, signedHeaders };
}
