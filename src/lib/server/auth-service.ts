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
import { DEFAULT_KDF, type KdfParams } from '../e2ee/params';
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
    recovery_salt: s.recoverySalt,
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

  const token = await startSession(deps.sessions, acct.id);

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

/** Create a session and return the raw token (the cookie value). */
export async function startSession(sessions: SessionStore, accountId: string): Promise<string> {
  const token = newToken();
  const now = Date.now();
  await sessions.insert({
    id: uuid(),
    account_id: accountId,
    token_hash: await tokenHashHex(token),
    created_at: now,
    expires_at: now + SESSION_TTL_MS,
  });
  return token;
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

// ── Recovery-key password reset + change password ──────────────────────────────

export interface RecoveryParams {
  recoverySalt: string;
  wrappedAccountKeyRecovery: string;
}

/**
 * Step 1 of recovery: hand back what the client needs to attempt a recovery-key
 * unlock. A deterministic decoy is returned for unknown emails so an attacker
 * can't enumerate accounts; the client-side unwrap simply fails for a decoy.
 */
export async function getRecoveryParams(accounts: AccountStore, email: string): Promise<RecoveryParams> {
  const e = email.toLowerCase().trim();
  const acct = await accounts.getByEmail(e);
  if (acct && acct.recovery_salt) {
    return { recoverySalt: acct.recovery_salt, wrappedAccountKeyRecovery: acct.wrapped_account_key_recovery };
  }
  const decoy = await sha256Hex(te.encode('mediavault-recovery-decoy:' + e));
  return { recoverySalt: btoa(decoy.slice(0, 16)), wrappedAccountKeyRecovery: btoa(decoy.slice(0, 64)) };
}

/**
 * Reset the password using the recovery key. The client proves possession of the
 * recovery key by sending its hash, which the server compares (constant-time) to
 * the stored recovery_key_hash. On success all sessions are revoked and a fresh
 * one is issued.
 */
export async function resetPassword(
  deps: { accounts: AccountStore; sessions: SessionStore; kv: KVLike },
  input: { email: string; recoveryKeyHash: string; secrets: SignupSecrets; ipKey: string },
): Promise<{ ok: true; token: string } | { ok: false; error: AuthError }> {
  const email = input.email?.toLowerCase().trim();
  const s = input.secrets;
  if (!email || !input.recoveryKeyHash || !s) return { ok: false, error: 'missing_fields' };
  if (!s.authKeyB64 || !s.wrappedAccountKey || !s.wrappedAccountKeyRecovery || !s.recoveryKeyHash || !s.kdfSalt || !s.recoverySalt) {
    return { ok: false, error: 'missing_fields' };
  }

  const limited =
    !(await checkRateLimit(deps.kv, `reset:e:${email}`, 5, 900)).allowed ||
    !(await checkRateLimit(deps.kv, `reset:i:${input.ipKey}`, 15, 900)).allowed;
  if (limited) return { ok: false, error: 'rate_limited' };

  const acct = await deps.accounts.getByEmail(email);
  if (!acct || !equalHex(input.recoveryKeyHash, acct.recovery_key_hash)) {
    return { ok: false, error: 'invalid_credentials' };
  }

  await deps.accounts.updateSecrets(acct.id, {
    kdf_salt: s.kdfSalt,
    kdf_params: JSON.stringify(s.kdfParams),
    login_hash: await loginHashOf(s.authKeyB64),
    wrapped_account_key: s.wrappedAccountKey,
    wrapped_account_key_recovery: s.wrappedAccountKeyRecovery,
    recovery_key_hash: s.recoveryKeyHash,
    recovery_salt: s.recoverySalt,
    updated_at: Date.now(),
  });
  await resetRateLimit(deps.kv, `reset:e:${email}`);
  await deps.sessions.deleteAllForAccount(acct.id); // revoke everything after a reset
  return { ok: true, token: await startSession(deps.sessions, acct.id) };
}

/**
 * Change password for an already-authenticated account. The current password is
 * re-proven (its auth key vs the stored login_hash) so a hijacked session alone
 * can't change it. Other sessions are revoked; the caller gets a fresh one.
 */
export async function changePassword(
  deps: { accounts: AccountStore; sessions: SessionStore },
  input: { accountId: string; currentAuthKeyB64: string; secrets: SignupSecrets },
): Promise<{ ok: true; token: string } | { ok: false; error: AuthError }> {
  const s = input.secrets;
  if (!input.currentAuthKeyB64 || !s) return { ok: false, error: 'missing_fields' };
  if (!s.authKeyB64 || !s.wrappedAccountKey || !s.wrappedAccountKeyRecovery || !s.recoveryKeyHash || !s.kdfSalt || !s.recoverySalt) {
    return { ok: false, error: 'missing_fields' };
  }

  const acct = await deps.accounts.getById(input.accountId);
  if (!acct || !equalHex(await loginHashOf(input.currentAuthKeyB64), acct.login_hash)) {
    return { ok: false, error: 'invalid_credentials' };
  }

  await deps.accounts.updateSecrets(acct.id, {
    kdf_salt: s.kdfSalt,
    kdf_params: JSON.stringify(s.kdfParams),
    login_hash: await loginHashOf(s.authKeyB64),
    wrapped_account_key: s.wrappedAccountKey,
    wrapped_account_key_recovery: s.wrappedAccountKeyRecovery,
    recovery_key_hash: s.recoveryKeyHash,
    recovery_salt: s.recoverySalt,
    updated_at: Date.now(),
  });
  await deps.sessions.deleteAllForAccount(acct.id); // boot other devices after a password change
  return { ok: true, token: await startSession(deps.sessions, acct.id) };
}
