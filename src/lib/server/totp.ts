/**
 * RFC 6238 TOTP — the algorithm every authenticator app (Google Authenticator,
 * Authy, 1Password, …) speaks: HMAC-SHA1, 6 digits, 30-second step. Runs on the
 * Cloudflare Worker via Web Crypto.
 *
 * The TOTP secret is a conventional server-side shared secret and gates the
 * LOGIN handshake only. It is unrelated to the vault's end-to-end encryption
 * keys, which are derived in the browser and never reach the server.
 */
import { sha256Hex } from '../e2ee/crypto';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // RFC 4648 base32 alphabet

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Uint8Array {
  const clean = s.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) continue; // ignore stray chars (spaces, dashes)
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** A fresh 160-bit secret, base32-encoded for the otpauth:// URL / manual entry. */
export function generateTotpSecret(): string {
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}

async function hmacSha1(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
}

/** The 6-digit code for a given secret at a given moment (default: now). */
export async function totpCode(
  secretBase32: string,
  timeMs: number = Date.now(),
  step = 30,
  digits = 6,
): Promise<string> {
  let counter = Math.floor(timeMs / 1000 / step);
  const msg = new Uint8Array(8); // 64-bit big-endian counter
  for (let i = 7; i >= 0; i--) {
    msg[i] = counter & 0xff;
    counter = Math.floor(counter / 256);
  }
  const hash = await hmacSha1(base32Decode(secretBase32), msg);
  const offset = hash[hash.length - 1] & 0x0f; // dynamic truncation (RFC 4226 §5.3)
  const bin =
    ((hash[offset] & 0x7f) << 24) |
    (hash[offset + 1] << 16) |
    (hash[offset + 2] << 8) |
    hash[offset + 3];
  return (bin % 10 ** digits).toString().padStart(digits, '0');
}

/** Verify a code, tolerating ±`window` 30-second steps for clock skew. */
export async function verifyTotp(
  secretBase32: string,
  code: string,
  timeMs: number = Date.now(),
  window = 1,
): Promise<boolean> {
  const clean = (code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(clean)) return false;
  for (let w = -window; w <= window; w++) {
    const expected = await totpCode(secretBase32, timeMs + w * 30_000);
    let diff = 0; // compare without early-out
    for (let i = 0; i < 6; i++) diff |= expected.charCodeAt(i) ^ clean.charCodeAt(i);
    if (diff === 0) return true;
  }
  return false;
}

/** otpauth:// URL for the enrolment QR code. */
export function otpauthUrl(secretBase32: string, accountLabel: string, issuer = 'Media Reservoir'): string {
  const label = encodeURIComponent(`${issuer}:${accountLabel}`);
  const params = new URLSearchParams({
    secret: secretBase32,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/** Eight human-friendly one-time codes (xxxx-xxxx) shown ONCE at enrolment. */
export function generateBackupCodes(n = 8): string[] {
  const codes: string[] = [];
  for (let i = 0; i < n; i++) {
    const s = base32Encode(crypto.getRandomValues(new Uint8Array(5))).slice(0, 8).toLowerCase();
    codes.push(`${s.slice(0, 4)}-${s.slice(4, 8)}`);
  }
  return codes;
}

/** Normalise then hash a backup code for storage / comparison. */
export function hashBackupCode(code: string): Promise<string> {
  return sha256Hex(new TextEncoder().encode(code.trim().toLowerCase().replace(/\s+/g, '')));
}
