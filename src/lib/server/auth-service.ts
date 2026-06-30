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
import type { AccountStore, KVLike, SessionStore, SignupSecrets, TotpRow, TotpStore } from './types';
import { checkRateLimit, resetRateLimit } from './ratelimit';
import { generateBackupCodes, generateTotpSecret, hashBackupCode, otpauthUrl, verifyTotp } from './totp';

const te = new TextEncoder();
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const TOUCH_AFTER_MS = 60 * 60 * 1000; // refresh last_seen at most hourly
const TWOFA_PENDING_TTL = 300; // seconds a half-finished (password-ok) login may wait for a code
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

export type AuthError =
  | 'invalid_email'
  | 'email_taken'
  | 'missing_fields'
  | 'invalid_credentials'
  | 'rate_limited'
  | 'twofa_invalid'   // wrong/expired 6-digit (or backup) code
  | 'twofa_expired';  // the half-finished login (or setup) is no longer valid

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

/** Either a finished login (result) or a 2FA challenge (pendingToken). */
export type LoginOutcome =
  | { ok: true; twofaRequired: false; result: LoginResult }
  | { ok: true; twofaRequired: true; pendingToken: string }
  | { ok: false; error: AuthError };

export async function login(
  deps: { accounts: AccountStore; sessions: SessionStore; totp?: TotpStore; kv: KVLike },
  input: { email: string; authKeyB64: string; ipKey: string; userAgent?: string | null },
): Promise<LoginOutcome> {
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

  // If 2FA is on, DON'T issue a session or hand back the wrapped key yet — the
  // client must clear the second factor first (see verifyTwoFactorLogin).
  const tf = deps.totp ? await deps.totp.get(acct.id) : null;
  if (tf?.enabled) {
    const pendingToken = newToken();
    await deps.kv.put(`2fa:${await tokenHashHex(pendingToken)}`, acct.id, { expirationTtl: TWOFA_PENDING_TTL });
    return { ok: true, twofaRequired: true, pendingToken };
  }

  const token = await startSession(deps.sessions, acct.id, { userAgent: input.userAgent, ip: input.ipKey });
  return { ok: true, twofaRequired: false, result: loginResult(acct, token) };
}

function loginResult(acct: NonNullable<Awaited<ReturnType<AccountStore['getByEmail']>>>, token: string): LoginResult {
  return {
    token,
    accountId: acct.id,
    emailVerified: acct.email_verified === 1,
    wrappedAccountKey: acct.wrapped_account_key,
    kdfSalt: acct.kdf_salt,
    kdfParams: JSON.parse(acct.kdf_params) as KdfParams,
  };
}

/**
 * Step 3 (only when 2FA is on): exchange the pending token + a valid TOTP or
 * backup code for a real session and the wrapped account key.
 */
export async function verifyTwoFactorLogin(
  deps: { accounts: AccountStore; sessions: SessionStore; totp: TotpStore; kv: KVLike },
  input: { pendingToken: string; code: string; ipKey: string; userAgent?: string | null },
): Promise<{ ok: true; result: LoginResult } | { ok: false; error: AuthError }> {
  if (!input.pendingToken || !input.code) return { ok: false, error: 'missing_fields' };
  const keyHash = await tokenHashHex(input.pendingToken);
  const accountId = await deps.kv.get(`2fa:${keyHash}`);
  if (!accountId) return { ok: false, error: 'twofa_expired' };

  // Bound brute force: ≤5 code tries per pending token, plus a per-IP ceiling.
  const limited =
    !(await checkRateLimit(deps.kv, `2fa:t:${keyHash}`, 5, TWOFA_PENDING_TTL)).allowed ||
    !(await checkRateLimit(deps.kv, `2fa:i:${input.ipKey}`, 30, 900)).allowed;
  if (limited) {
    await deps.kv.delete(`2fa:${keyHash}`); // force a fresh login
    return { ok: false, error: 'rate_limited' };
  }

  const acct = await deps.accounts.getById(accountId);
  const tf = await deps.totp.get(accountId);
  if (!acct || !tf?.enabled) return { ok: false, error: 'twofa_expired' };
  if (!(await consumeSecondFactor(deps.totp, tf, input.code))) return { ok: false, error: 'twofa_invalid' };

  await deps.kv.delete(`2fa:${keyHash}`);
  const token = await startSession(deps.sessions, acct.id, { userAgent: input.userAgent, ip: input.ipKey });
  return { ok: true, result: loginResult(acct, token) };
}

/** Accept a current TOTP code, or consume a one-time backup code. */
async function consumeSecondFactor(totp: TotpStore, tf: TotpRow, code: string): Promise<boolean> {
  const codes: string[] = tf.backup_codes ? JSON.parse(tf.backup_codes) : [];
  const idx = codes.indexOf(await hashBackupCode(code));
  if (idx >= 0) {
    codes.splice(idx, 1); // single use
    await totp.upsert({ ...tf, backup_codes: JSON.stringify(codes) });
    return true;
  }
  return verifyTotp(tf.secret, code);
}

/** Create a session and return the raw token (the cookie value). */
export async function startSession(
  sessions: SessionStore,
  accountId: string,
  meta?: { userAgent?: string | null; ip?: string | null },
): Promise<string> {
  const token = newToken();
  const now = Date.now();
  await sessions.insert({
    id: uuid(),
    account_id: accountId,
    token_hash: await tokenHashHex(token),
    created_at: now,
    expires_at: now + SESSION_TTL_MS,
    user_agent: meta?.userAgent ?? null,
    ip: meta?.ip ?? null,
    last_seen: now,
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
  const now = Date.now();
  if (!row.last_seen || now - row.last_seen > TOUCH_AFTER_MS) {
    try {
      await sessions.touch(row.id, now); // keep "last active" fresh without writing every request
    } catch {
      /* non-critical */
    }
  }
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

// ── Two-factor (TOTP) enrolment ─────────────────────────────────────────────────

/** Whether 2FA is on, or half-enrolled (secret created, not yet confirmed). */
export async function getTotpStatus(totp: TotpStore, accountId: string): Promise<{ enabled: boolean; pending: boolean }> {
  const tf = await totp.get(accountId);
  return { enabled: !!tf?.enabled, pending: !!tf && !tf.enabled };
}

/** Begin enrolment: mint a secret and return it + the otpauth URL for the QR.
 *  Not active until enableTotp() confirms a code. */
export async function setupTotp(
  totp: TotpStore,
  accountId: string,
  email: string,
): Promise<{ ok: true; secret: string; otpauthUrl: string } | { ok: false; error: AuthError }> {
  const existing = await totp.get(accountId);
  if (existing?.enabled) return { ok: false, error: 'twofa_invalid' }; // already on — disable first
  const secret = generateTotpSecret();
  await totp.upsert({ account_id: accountId, secret, enabled: 0, backup_codes: null, created_at: Date.now(), confirmed_at: null });
  return { ok: true, secret, otpauthUrl: otpauthUrl(secret, email) };
}

/** Confirm enrolment: re-prove the password AND a fresh code, then turn 2FA on
 *  and hand back one-time backup codes (shown to the user exactly once). */
export async function enableTotp(
  deps: { accounts: AccountStore; totp: TotpStore },
  input: { accountId: string; currentAuthKeyB64: string; code: string },
): Promise<{ ok: true; backupCodes: string[] } | { ok: false; error: AuthError }> {
  if (!input.currentAuthKeyB64 || !input.code) return { ok: false, error: 'missing_fields' };
  const acct = await deps.accounts.getById(input.accountId);
  if (!acct || !equalHex(await loginHashOf(input.currentAuthKeyB64), acct.login_hash)) {
    return { ok: false, error: 'invalid_credentials' };
  }
  const tf = await deps.totp.get(input.accountId);
  if (!tf) return { ok: false, error: 'twofa_expired' }; // no setup in progress
  if (tf.enabled) return { ok: false, error: 'twofa_invalid' };
  if (!(await verifyTotp(tf.secret, input.code))) return { ok: false, error: 'twofa_invalid' };

  const backupCodes = generateBackupCodes();
  const hashes = await Promise.all(backupCodes.map(hashBackupCode));
  await deps.totp.upsert({ ...tf, enabled: 1, confirmed_at: Date.now(), backup_codes: JSON.stringify(hashes) });
  return { ok: true, backupCodes };
}

/** Turn 2FA off (requires re-proving the password). */
export async function disableTotp(
  deps: { accounts: AccountStore; totp: TotpStore },
  input: { accountId: string; currentAuthKeyB64: string },
): Promise<{ ok: true } | { ok: false; error: AuthError }> {
  if (!input.currentAuthKeyB64) return { ok: false, error: 'missing_fields' };
  const acct = await deps.accounts.getById(input.accountId);
  if (!acct || !equalHex(await loginHashOf(input.currentAuthKeyB64), acct.login_hash)) {
    return { ok: false, error: 'invalid_credentials' };
  }
  await deps.totp.delete(input.accountId);
  return { ok: true };
}

// ── Active sessions (devices) ───────────────────────────────────────────────────

export interface PublicSession {
  id: string;
  device: string;
  ip: string | null;
  createdAt: number;
  lastSeen: number;
  current: boolean;
}

/** List the account's live sessions, flagging the one making this request. */
export async function listSessions(
  sessions: SessionStore,
  accountId: string,
  currentToken: string | undefined,
): Promise<PublicSession[]> {
  const curHash = currentToken ? await tokenHashHex(currentToken) : '';
  const rows = await sessions.listForAccount(accountId);
  return rows.map((r) => ({
    id: r.id,
    device: r.user_agent || 'Unknown device',
    ip: r.ip ?? null,
    createdAt: r.created_at,
    lastSeen: r.last_seen ?? r.created_at,
    current: r.token_hash === curHash,
  }));
}

/** Revoke one session by id (scoped to the account). */
export function revokeSession(sessions: SessionStore, accountId: string, id: string): Promise<boolean> {
  return sessions.deleteByIdForAccount(accountId, id);
}

/** Revoke every session except the current one (sign out everywhere else). */
export async function revokeOtherSessions(
  sessions: SessionStore,
  accountId: string,
  currentToken: string,
): Promise<void> {
  await sessions.deleteOthersForAccount(accountId, await tokenHashHex(currentToken));
}
