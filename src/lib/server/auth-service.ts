/**
 * Multi-user auth service — the server-side half of the E2EE handshake.
 *
 * The server NEVER sees a password or an account key. It only:
 *   - stores opaque wrapped-key blobs + salts the client produced,
 *   - verifies a high-entropy "auth key" (HKDF output) by comparing hashes,
 *   - issues/validates/revokes sessions.
 *
 * Login is a two-step handshake (like Bitwarden's prelogin):
 *   1) client asks for the account's KDF salt+params (decoy returned for
 *      unknown emails, to prevent account enumeration),
 *   2) client derives the auth key locally and posts it; the server verifies.
 */
import { DEFAULT_KDF, type KdfParams } from '../e2ee/account';
import { b64decode, sha256Hex, timingSafeEqual } from '../e2ee/crypto';
import type { AccountStore, KVLike, SessionStore, SignupSecrets } from './types';
import { checkRateLimit, resetRateLimit } from './ratelimit';

const te = new TextEncoder();
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function uuid(): string {
  return globalThis.crypto.randomUUID();
}
async function tokenHashHex(token: string): Promise<string> {
  return sha256Hex(te.encode(token));
}
function newToken(): string {
  const b = globalThis.crypto.getRandomValues(new Uint8Array(32));
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}
async function loginHashOf(authKeyB64: string): Promise<string> {
  // authKey is already a 256-bit HKDF output, so a fast hash is sufficient
  // (no slow KDF needed for high-entropy input).
  return sha256Hex(b64decode(authKeyB64));
}
function equalHex(a: string, b: string): boolean {
  return a.length === b.length && timingSafeEqual(te.encode(a), te.encode(b));
}

export type AuthError = 'invalid_email' | 'email_taken' | 'missing_fields' | 'invalid_credentials' | 'rate_limited';

export interface LoginParams {
  kdfSalt: string;
  kdfParams: KdfParams;
}

/** Step 1: return KDF params so the client can derive its auth key. */
export async function getLoginParams(accounts: AccountStore, email: string): Promise<LoginParams> {
  const acct = await accounts.getByEmail(email.toLowerCase().trim());
  if (acct) {
    return { kdfSalt: acct.kdf_salt, kdfParams: JSON.parse(acct.kdf_params) as KdfParams };
  }
  // Deterministic decoy salt so an attacker can't tell real from fake emails.
  const decoy = await sha256Hex(te.encode('mediavault-decoy:' + email.toLowerCase().trim()));
  return { kdfSalt: btoa(decoy.slice(0, 32)), kdfParams: DEFAULT_KDF };
}

export async function signup(
  accounts: AccountStore,
  input: { email: string; secrets: SignupSecrets },
): Promise<{ ok: true; accountId: string } | { ok: false; error: AuthError }> {
  const email = input.email?.toLowerCase().trim();
  if (!email || !EMAIL_RE.test(email)) return { ok: false, error: 'invalid_email' };

  const s = input.secrets;
  if (!s?.authKeyB64 || !s.wrappedAccountKey || !s.wrappedAccountKeyRecovery || !s.recoveryKeyHash || !s.kdfSalt || !s.recoverySalt) {
    return { ok: false, error: 'missing_fields' };
  }
  if (await accounts.getByEmail(email)) return { ok: false, error: 'email_taken' };

  const now = Date.now();
  const id = uuid();
  await accounts.insert({
    id,
    email,
    email_verified: 0,
    kdf: 'argon2id',
    kdf_salt: s.kdfSalt,
    kdf_params: JSON.stringify(s.kdfParams),
    login_hash: await loginHashOf(s.authKeyB64),
    wrapped_account_key: s.wrappedAccountKey,
    wrapped_account_key_recovery: s.wrappedAccountKeyRecovery,
    recovery_key_hash: s.recoveryKeyHash,
    created_at: now,
    updated_at: now,
  });
  return { ok: true, accountId: id };
}

export interface LoginResult {
  token: string;
  accountId: string;
  emailVerified: boolean;
  // The client needs these to unlock its account key locally.
  wrappedAccountKey: string;
  kdfSalt: string;
  kdfParams: KdfParams;
}

export async function login(
  deps: { accounts: AccountStore; sessions: SessionStore; kv: KVLike },
  input: { email: string; authKeyB64: string; ipKey: string },
): Promise<{ ok: true; result: LoginResult } | { ok: false; error: AuthError }> {
  const email = input.email?.toLowerCase().trim();
  if (!email || !input.authKeyB64) return { ok: false, error: 'missing_fields' };

  // Per-email and per-IP limiter (5 tries / 15 min). Generic failure either way.
  const limited =
    !(await checkRateLimit(deps.kv, `login:e:${email}`, 5, 900)).allowed ||
    !(await checkRateLimit(deps.kv, `login:i:${input.ipKey}`, 30, 900)).allowed;
  if (limited) return { ok: false, error: 'rate_limited' };

  const acct = await deps.accounts.getByEmail(email);
  if (!acct || !equalHex(await loginHashOf(input.authKeyB64), acct.login_hash)) {
    return { ok: false, error: 'invalid_credentials' };
  }

  // Successful login clears the throttle so normal use never locks out.
  await resetRateLimit(deps.kv, `login:e:${email}`);
  await resetRateLimit(deps.kv, `login:i:${input.ipKey}`);

  const token = newToken();
  const now = Date.now();
  await deps.sessions.insert({
    id: uuid(),
    account_id: acct.id,
    token_hash: await tokenHashHex(token),
    created_at: now,
    expires_at: now + SESSION_TTL_MS,
  });

  return {
    ok: true,
    result: {
      token,
      accountId: acct.id,
      emailVerified: acct.email_verified === 1,
      wrappedAccountKey: acct.wrapped_account_key,
      kdfSalt: acct.kdf_salt,
      kdfParams: JSON.parse(acct.kdf_params) as KdfParams,
    },
  };
}

export async function validateSession(
  sessions: SessionStore,
  token: string | undefined,
): Promise<{ accountId: string } | null> {
  if (!token) return null;
  const row = await sessions.getByTokenHash(await tokenHashHex(token));
  if (!row || Date.now() >= row.expires_at) return null;
  return { accountId: row.account_id };
}

export async function logout(sessions: SessionStore, token: string | undefined): Promise<void> {
  if (token) await sessions.deleteByTokenHash(await tokenHashHex(token));
}
