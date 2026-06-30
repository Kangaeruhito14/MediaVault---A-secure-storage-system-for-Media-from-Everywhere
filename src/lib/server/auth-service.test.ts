import { describe, it, expect } from 'vitest';
import {
  createAccount,
  deriveAuthKey,
  normalizeRecoveryKey,
  rewrapForNewPassword,
  unlockWithRecovery,
  type KdfParams,
} from '../e2ee/account';
import { sha256Hex } from '../e2ee/crypto';
import {
  getLoginParams,
  getRecoveryParams,
  signup,
  login,
  logout,
  resetPassword,
  changePassword,
  startSession,
  validateSession,
  setupTotp,
  enableTotp,
  disableTotp,
  getTotpStatus,
  verifyTwoFactorLogin,
  listSessions,
  revokeSession,
  revokeOtherSessions,
} from './auth-service';
import { totpCode } from './totp';
import type { AccountRow, AccountStore, KVLike, SessionRow, SessionStore, SignupSecrets, TotpRow, TotpStore } from './types';

const FAST: KdfParams = { m: 256, t: 1, p: 1 };

// ── In-memory fakes (test-only; the real stores hit D1/KV) ─────────────────────
class MemAccounts implements AccountStore {
  rows = new Map<string, AccountRow>();
  async getByEmail(email: string) {
    return [...this.rows.values()].find((r) => r.email === email) ?? null;
  }
  async getById(id: string) {
    return this.rows.get(id) ?? null;
  }
  async insert(row: AccountRow) {
    this.rows.set(row.id, row);
  }
  async deleteById(id: string) {
    this.rows.delete(id);
  }
  async updateSecrets(id: string, f: Parameters<AccountStore['updateSecrets']>[1]) {
    this.rows.set(id, { ...this.rows.get(id)!, ...f });
  }
}
class MemSessions implements SessionStore {
  rows = new Map<string, SessionRow>();
  async insert(s: SessionRow) {
    this.rows.set(s.token_hash, s);
  }
  async getByTokenHash(h: string) {
    return this.rows.get(h) ?? null;
  }
  async deleteByTokenHash(h: string) {
    this.rows.delete(h);
  }
  async deleteAllForAccount(id: string) {
    for (const [k, v] of this.rows) if (v.account_id === id) this.rows.delete(k);
  }
  async listForAccount(id: string) {
    return [...this.rows.values()].filter((r) => r.account_id === id && r.expires_at > Date.now());
  }
  async deleteByIdForAccount(id: string, sid: string) {
    for (const [k, v] of this.rows)
      if (v.account_id === id && v.id === sid) {
        this.rows.delete(k);
        return true;
      }
    return false;
  }
  async deleteOthersForAccount(id: string, keepHash: string) {
    for (const [k, v] of this.rows) if (v.account_id === id && k !== keepHash) this.rows.delete(k);
  }
  async touch(sid: string, ts: number) {
    for (const v of this.rows.values()) if (v.id === sid) v.last_seen = ts;
  }
}
class MemTotp implements TotpStore {
  rows = new Map<string, TotpRow>();
  async get(id: string) {
    return this.rows.get(id) ?? null;
  }
  async upsert(r: TotpRow) {
    this.rows.set(r.account_id, { ...r });
  }
  async delete(id: string) {
    this.rows.delete(id);
  }
}
class MemKV implements KVLike {
  m = new Map<string, string>();
  async get(k: string) {
    return this.m.get(k) ?? null;
  }
  async put(k: string, v: string) {
    this.m.set(k, v);
  }
  async delete(k: string) {
    this.m.delete(k);
  }
}

async function newSecrets(password = 'Sup3r-secret-pw!'): Promise<{ email: string; secrets: SignupSecrets }> {
  const acct = await createAccount(password, FAST);
  return { email: 'user@example.com', secrets: acct.secrets };
}

describe('signup', () => {
  it('creates an account', async () => {
    const accounts = new MemAccounts();
    const res = await signup(accounts, await newSecrets());
    expect(res.ok).toBe(true);
    expect(accounts.rows.size).toBe(1);
  });

  it('rejects an invalid email', async () => {
    const accounts = new MemAccounts();
    const s = await newSecrets();
    const res = await signup(accounts, { ...s, email: 'not-an-email' });
    expect(res).toEqual({ ok: false, error: 'invalid_email' });
  });

  it('rejects missing secret fields', async () => {
    const accounts = new MemAccounts();
    const res = await signup(accounts, { email: 'a@b.com', secrets: {} as SignupSecrets });
    expect(res).toEqual({ ok: false, error: 'missing_fields' });
  });

  it('rejects a duplicate email', async () => {
    const accounts = new MemAccounts();
    const s = await newSecrets();
    await signup(accounts, s);
    const res = await signup(accounts, s);
    expect(res).toEqual({ ok: false, error: 'email_taken' });
  });

  it('never stores the password or account key (only opaque blobs)', async () => {
    const accounts = new MemAccounts();
    const s = await newSecrets('My-Plaintext-Password-123');
    await signup(accounts, s);
    const row = [...accounts.rows.values()][0];
    const dump = JSON.stringify(row);
    expect(dump).not.toContain('My-Plaintext-Password-123');
    expect(row.login_hash).toBeTruthy();
    expect(row.login_hash).not.toBe(s.secrets.authKeyB64); // stored hashed, not raw
  });
});

describe('login handshake', () => {
  it('returns real KDF params for a known email and decoy for unknown', async () => {
    const accounts = new MemAccounts();
    const s = await newSecrets();
    await signup(accounts, s);

    const real = await getLoginParams(accounts, s.email);
    expect(real.kdfSalt).toBe(s.secrets.kdfSalt);

    const decoy = await getLoginParams(accounts, 'ghost@nowhere.com');
    expect(decoy.kdfSalt).toBeTruthy();
    // Decoy is stable across calls (no enumeration signal from changing salts).
    const decoy2 = await getLoginParams(accounts, 'ghost@nowhere.com');
    expect(decoy2.kdfSalt).toBe(decoy.kdfSalt);
  });

  it('logs in with the correct auth key and returns the wrapped account key', async () => {
    const accounts = new MemAccounts();
    const sessions = new MemSessions();
    const kv = new MemKV();
    const s = await newSecrets();
    await signup(accounts, s);

    const res = await login({ accounts, sessions, kv }, { email: s.email, authKeyB64: s.secrets.authKeyB64, ipKey: '1.1.1.1' });
    expect(res.ok).toBe(true);
    if (res.ok && !res.twofaRequired) {
      expect(res.result.token).toBeTruthy();
      expect(res.result.wrappedAccountKey).toBe(s.secrets.wrappedAccountKey);
      expect(res.result.kdfSalt).toBe(s.secrets.kdfSalt);
    }
  });

  it('rejects a wrong auth key', async () => {
    const accounts = new MemAccounts();
    const sessions = new MemSessions();
    const kv = new MemKV();
    const s = await newSecrets();
    await signup(accounts, s);
    const res = await login({ accounts, sessions, kv }, { email: s.email, authKeyB64: btoa('wrong-key-bytes-32-aaaaaaaaaaaa'), ipKey: '1.1.1.1' });
    expect(res).toEqual({ ok: false, error: 'invalid_credentials' });
  });

  it('rejects an unknown email without revealing it exists', async () => {
    const accounts = new MemAccounts();
    const sessions = new MemSessions();
    const kv = new MemKV();
    const res = await login({ accounts, sessions, kv }, { email: 'ghost@nowhere.com', authKeyB64: btoa('anything'), ipKey: '1.1.1.1' });
    expect(res).toEqual({ ok: false, error: 'invalid_credentials' });
  });

  it('rate-limits after repeated failures', async () => {
    const accounts = new MemAccounts();
    const sessions = new MemSessions();
    const kv = new MemKV();
    const s = await newSecrets();
    await signup(accounts, s);
    for (let i = 0; i < 5; i++) {
      await login({ accounts, sessions, kv }, { email: s.email, authKeyB64: btoa('bad'), ipKey: '9.9.9.9' });
    }
    const res = await login({ accounts, sessions, kv }, { email: s.email, authKeyB64: s.secrets.authKeyB64, ipKey: '9.9.9.9' });
    expect(res).toEqual({ ok: false, error: 'rate_limited' });
  });

  it('clears the throttle on a successful login', async () => {
    const accounts = new MemAccounts();
    const sessions = new MemSessions();
    const kv = new MemKV();
    const s = await newSecrets();
    await signup(accounts, s);
    // a few failures, then succeed, then succeed again — must not lock out
    for (let i = 0; i < 3; i++) await login({ accounts, sessions, kv }, { email: s.email, authKeyB64: btoa('bad'), ipKey: '2.2.2.2' });
    const good1 = await login({ accounts, sessions, kv }, { email: s.email, authKeyB64: s.secrets.authKeyB64, ipKey: '2.2.2.2' });
    const good2 = await login({ accounts, sessions, kv }, { email: s.email, authKeyB64: s.secrets.authKeyB64, ipKey: '2.2.2.2' });
    expect(good1.ok && good2.ok).toBe(true);
  });
});

describe('sessions', () => {
  it('validates a live session, rejects after logout', async () => {
    const accounts = new MemAccounts();
    const sessions = new MemSessions();
    const kv = new MemKV();
    const s = await newSecrets();
    await signup(accounts, s);
    const res = await login({ accounts, sessions, kv }, { email: s.email, authKeyB64: s.secrets.authKeyB64, ipKey: '1.1.1.1' });
    if (!res.ok || res.twofaRequired) throw new Error('login failed');

    const v = await validateSession(sessions, res.result.token);
    expect(v?.accountId).toBe(res.result.accountId);

    await logout(sessions, res.result.token);
    expect(await validateSession(sessions, res.result.token)).toBeNull();
  });

  it('rejects an unknown / missing token', async () => {
    const sessions = new MemSessions();
    expect(await validateSession(sessions, undefined)).toBeNull();
    expect(await validateSession(sessions, 'not-a-real-token')).toBeNull();
  });
});

const te = new TextEncoder();
const recoveryProof = (key: string) => sha256Hex(te.encode(normalizeRecoveryKey(key)));

describe('getRecoveryParams', () => {
  it('returns the stored recovery salt + wrapped key for a real account, decoy otherwise', async () => {
    const accounts = new MemAccounts();
    const acct = await createAccount('pw-12345678', FAST);
    await signup(accounts, { email: 'r@example.com', secrets: acct.secrets });

    const real = await getRecoveryParams(accounts, 'r@example.com');
    expect(real.recoverySalt).toBe(acct.secrets.recoverySalt);
    expect(real.wrappedAccountKeyRecovery).toBe(acct.secrets.wrappedAccountKeyRecovery);

    const decoy = await getRecoveryParams(accounts, 'nobody@example.com');
    expect(decoy.recoverySalt).not.toBe(real.recoverySalt);
  });
});

describe('resetPassword', () => {
  it('resets with the recovery key: new password works, old fails, sessions revoked', async () => {
    const accounts = new MemAccounts(), sessions = new MemSessions(), kv = new MemKV();
    const acct = await createAccount('old-pw-123', FAST);
    await signup(accounts, { email: 'u@example.com', secrets: acct.secrets });
    const id = (await accounts.getByEmail('u@example.com'))!.id;
    const oldToken = await startSession(sessions, id);

    // Client side: unlock with recovery key, re-wrap for the new password.
    const params = await getRecoveryParams(accounts, 'u@example.com');
    const ak = await unlockWithRecovery(acct.recoveryKey, params.recoverySalt, params.wrappedAccountKeyRecovery);
    expect(ak).not.toBeNull();
    const { secrets } = await rewrapForNewPassword(ak!, 'new-pw-456', FAST);

    const r = await resetPassword(
      { accounts, sessions, kv },
      { email: 'u@example.com', recoveryKeyHash: await recoveryProof(acct.recoveryKey), secrets, ipKey: 't' },
    );
    expect(r.ok).toBe(true);
    expect(await validateSession(sessions, oldToken)).toBeNull(); // old session revoked

    const newAuth = await deriveAuthKey('new-pw-456', secrets.kdfSalt, secrets.kdfParams);
    expect((await login({ accounts, sessions, kv }, { email: 'u@example.com', authKeyB64: newAuth, ipKey: 'a' })).ok).toBe(true);
    const oldAuth = await deriveAuthKey('old-pw-123', acct.secrets.kdfSalt, acct.secrets.kdfParams);
    expect((await login({ accounts, sessions, kv }, { email: 'u@example.com', authKeyB64: oldAuth, ipKey: 'b' })).ok).toBe(false);
  });

  it('rejects a wrong recovery key', async () => {
    const accounts = new MemAccounts(), sessions = new MemSessions(), kv = new MemKV();
    const acct = await createAccount('old-pw-123', FAST);
    await signup(accounts, { email: 'u2@example.com', secrets: acct.secrets });
    const params = await getRecoveryParams(accounts, 'u2@example.com');
    const ak = await unlockWithRecovery(acct.recoveryKey, params.recoverySalt, params.wrappedAccountKeyRecovery);
    const { secrets } = await rewrapForNewPassword(ak!, 'new-pw-456', FAST);
    const r = await resetPassword(
      { accounts, sessions, kv },
      { email: 'u2@example.com', recoveryKeyHash: 'deadbeef', secrets, ipKey: 't' },
    );
    expect(r.ok).toBe(false);
  });
});

describe('changePassword', () => {
  it('changes with the correct current password; new password works', async () => {
    const accounts = new MemAccounts(), sessions = new MemSessions(), kv = new MemKV();
    const acct = await createAccount('cur-pw-123', FAST);
    await signup(accounts, { email: 'c@example.com', secrets: acct.secrets });
    const id = (await accounts.getByEmail('c@example.com'))!.id;

    const curAuth = await deriveAuthKey('cur-pw-123', acct.secrets.kdfSalt, acct.secrets.kdfParams);
    const { secrets } = await rewrapForNewPassword(acct.accountKey, 'new-pw-789', FAST);
    const r = await changePassword({ accounts, sessions }, { accountId: id, currentAuthKeyB64: curAuth, secrets });
    expect(r.ok).toBe(true);

    const newAuth = await deriveAuthKey('new-pw-789', secrets.kdfSalt, secrets.kdfParams);
    expect((await login({ accounts, sessions, kv }, { email: 'c@example.com', authKeyB64: newAuth, ipKey: 'a' })).ok).toBe(true);
  });

  it('rejects a wrong current password', async () => {
    const accounts = new MemAccounts(), sessions = new MemSessions();
    const acct = await createAccount('cur-pw-123', FAST);
    await signup(accounts, { email: 'c2@example.com', secrets: acct.secrets });
    const id = (await accounts.getByEmail('c2@example.com'))!.id;
    const { secrets } = await rewrapForNewPassword(acct.accountKey, 'new-pw-789', FAST);
    const wrongAuth = await deriveAuthKey('WRONG-password', acct.secrets.kdfSalt, acct.secrets.kdfParams);
    const r = await changePassword({ accounts, sessions }, { accountId: id, currentAuthKeyB64: wrongAuth, secrets });
    expect(r.ok).toBe(false);
  });
});

describe('two-factor (TOTP)', () => {
  async function enrolled(pw = 'tf-pw-12345') {
    const accounts = new MemAccounts(), sessions = new MemSessions(), totp = new MemTotp(), kv = new MemKV();
    const acct = await createAccount(pw, FAST);
    await signup(accounts, { email: 't@example.com', secrets: acct.secrets });
    const id = (await accounts.getByEmail('t@example.com'))!.id;
    const authKey = await deriveAuthKey(pw, acct.secrets.kdfSalt, acct.secrets.kdfParams);
    const setup = await setupTotp(totp, id, 't@example.com');
    if (!setup.ok) throw new Error('setup failed');
    return { accounts, sessions, totp, kv, id, authKey, secret: setup.secret, acct };
  }

  it('setup → enable with a valid code turns 2FA on and yields backup codes', async () => {
    const { accounts, totp, id, authKey, secret } = await enrolled();
    expect((await getTotpStatus(totp, id))).toEqual({ enabled: false, pending: true });

    const bad = await enableTotp({ accounts, totp }, { accountId: id, currentAuthKeyB64: authKey, code: '000000' });
    expect(bad).toEqual({ ok: false, error: 'twofa_invalid' });

    const ok = await enableTotp({ accounts, totp }, { accountId: id, currentAuthKeyB64: authKey, code: await totpCode(secret) });
    expect(ok.ok).toBe(true);
    if (ok.ok) expect(ok.backupCodes).toHaveLength(8);
    expect((await getTotpStatus(totp, id))).toEqual({ enabled: true, pending: false });
  });

  it('enable rejects a wrong password even with a valid code', async () => {
    const { accounts, totp, id, secret } = await enrolled();
    const r = await enableTotp({ accounts, totp }, { accountId: id, currentAuthKeyB64: btoa('not-the-key'), code: await totpCode(secret) });
    expect(r).toEqual({ ok: false, error: 'invalid_credentials' });
  });

  it('once enabled, login requires a code; verifying with a TOTP code completes it', async () => {
    const { accounts, sessions, totp, kv, id, authKey, secret, acct } = await enrolled();
    await enableTotp({ accounts, totp }, { accountId: id, currentAuthKeyB64: authKey, code: await totpCode(secret) });

    const first = await login({ accounts, sessions, totp, kv }, { email: 't@example.com', authKeyB64: acct.secrets.authKeyB64, ipKey: 'x' });
    expect(first.ok && first.twofaRequired).toBe(true);
    if (!first.ok || !first.twofaRequired) throw new Error('expected 2FA challenge');
    expect(sessions.rows.size).toBe(0); // no session issued before the 2nd factor

    const wrong = await verifyTwoFactorLogin({ accounts, sessions, totp, kv }, { pendingToken: first.pendingToken, code: '000000', ipKey: 'x' });
    expect(wrong).toEqual({ ok: false, error: 'twofa_invalid' });

    const done = await verifyTwoFactorLogin({ accounts, sessions, totp, kv }, { pendingToken: first.pendingToken, code: await totpCode(secret), ipKey: 'x' });
    expect(done.ok).toBe(true);
    if (done.ok) {
      expect(done.result.wrappedAccountKey).toBe(acct.secrets.wrappedAccountKey);
      expect(await validateSession(sessions, done.result.token)).not.toBeNull();
    }
  });

  it('a backup code works exactly once', async () => {
    const { accounts, sessions, totp, kv, id, authKey, secret, acct } = await enrolled();
    const en = await enableTotp({ accounts, totp }, { accountId: id, currentAuthKeyB64: authKey, code: await totpCode(secret) });
    if (!en.ok) throw new Error('enable failed');
    const backup = en.backupCodes[0];

    const l1 = await login({ accounts, sessions, totp, kv }, { email: 't@example.com', authKeyB64: acct.secrets.authKeyB64, ipKey: 'x' });
    if (!l1.ok || !l1.twofaRequired) throw new Error('expected challenge');
    expect((await verifyTwoFactorLogin({ accounts, sessions, totp, kv }, { pendingToken: l1.pendingToken, code: backup, ipKey: 'x' })).ok).toBe(true);

    // Same backup code must now be rejected.
    const l2 = await login({ accounts, sessions, totp, kv }, { email: 't@example.com', authKeyB64: acct.secrets.authKeyB64, ipKey: 'x' });
    if (!l2.ok || !l2.twofaRequired) throw new Error('expected challenge');
    expect((await verifyTwoFactorLogin({ accounts, sessions, totp, kv }, { pendingToken: l2.pendingToken, code: backup, ipKey: 'x' })).ok).toBe(false);
  });

  it('disable (with password) removes the 2FA requirement', async () => {
    const { accounts, sessions, totp, kv, id, authKey, secret, acct } = await enrolled();
    await enableTotp({ accounts, totp }, { accountId: id, currentAuthKeyB64: authKey, code: await totpCode(secret) });
    expect((await disableTotp({ accounts, totp }, { accountId: id, currentAuthKeyB64: authKey })).ok).toBe(true);

    const l = await login({ accounts, sessions, totp, kv }, { email: 't@example.com', authKeyB64: acct.secrets.authKeyB64, ipKey: 'x' });
    expect(l.ok && !l.twofaRequired).toBe(true); // straight through, no challenge
  });

  it('expired/unknown pending token is rejected', async () => {
    const { accounts, sessions, totp, kv } = await enrolled();
    const r = await verifyTwoFactorLogin({ accounts, sessions, totp, kv }, { pendingToken: 'nope', code: '123456', ipKey: 'x' });
    expect(r).toEqual({ ok: false, error: 'twofa_expired' });
  });
});

describe('active sessions', () => {
  it('lists sessions (flagging current), revokes one, and revokes all others', async () => {
    const sessions = new MemSessions();
    const id = 'acct-1';
    const t1 = await startSession(sessions, id, { userAgent: 'Chrome · macOS', ip: '1.1.1.1' });
    const t2 = await startSession(sessions, id, { userAgent: 'Firefox · Linux', ip: '2.2.2.2' });
    const t3 = await startSession(sessions, id, { userAgent: 'Safari · iOS', ip: '3.3.3.3' });

    let list = await listSessions(sessions, id, t2);
    expect(list).toHaveLength(3);
    expect(list.filter((s) => s.current)).toHaveLength(1);
    expect(list.find((s) => s.current)!.device).toBe('Firefox · Linux');

    // Revoke a specific (non-current) session.
    const target = list.find((s) => s.device === 'Chrome · macOS')!;
    expect(await revokeSession(sessions, id, target.id)).toBe(true);
    expect(await validateSession(sessions, t1)).toBeNull();
    expect((await listSessions(sessions, id, t2))).toHaveLength(2);

    // Sign out everywhere else — only t2 survives.
    await revokeOtherSessions(sessions, id, t2);
    expect(await validateSession(sessions, t2)).not.toBeNull();
    expect(await validateSession(sessions, t3)).toBeNull();
    expect((await listSessions(sessions, id, t2))).toHaveLength(1);
  });
});
