import { describe, it, expect } from 'vitest';
import { createAccount, type KdfParams } from '../e2ee/account';
import {
  getLoginParams,
  signup,
  login,
  logout,
  validateSession,
} from './auth-service';
import type { AccountRow, AccountStore, KVLike, SessionRow, SessionStore, SignupSecrets } from './types';

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
    if (res.ok) {
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
    if (!res.ok) throw new Error('login failed');

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
