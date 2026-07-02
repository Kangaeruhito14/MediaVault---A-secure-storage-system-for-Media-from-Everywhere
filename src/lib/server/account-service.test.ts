import { describe, it, expect } from 'vitest';
import { exportAccount, deleteAccount } from './account-service';
import type {
  AccountRow, AccountStore, SessionRow, SessionStore,
  StorageConnectionRow, StorageConnectionStore, TotpRow, TotpStore, VaultItemRow, VaultItemStore, ItemCursor,
  FolderRow, FolderStore,
} from './types';

class MemAccounts implements AccountStore {
  rows = new Map<string, AccountRow>();
  async getByEmail(e: string) { return [...this.rows.values()].find((r) => r.email === e) ?? null; }
  async getById(id: string) { return this.rows.get(id) ?? null; }
  async insert(r: AccountRow) { this.rows.set(r.id, r); }
  async deleteById(id: string) { this.rows.delete(id); }
  async updateSecrets() {}
}
class MemSessions implements SessionStore {
  rows = new Map<string, SessionRow>();
  async insert(s: SessionRow) { this.rows.set(s.token_hash, s); }
  async getByTokenHash(h: string) { return this.rows.get(h) ?? null; }
  async deleteByTokenHash(h: string) { this.rows.delete(h); }
  async deleteAllForAccount(a: string) { for (const [k, v] of this.rows) if (v.account_id === a) this.rows.delete(k); }
  async listForAccount(a: string) { return [...this.rows.values()].filter((r) => r.account_id === a); }
  async deleteByIdForAccount(a: string, id: string) { for (const [k, v] of this.rows) if (v.account_id === a && v.id === id) { this.rows.delete(k); return true; } return false; }
  async deleteOthersForAccount(a: string, keep: string) { for (const [k, v] of this.rows) if (v.account_id === a && k !== keep) this.rows.delete(k); }
  async touch(id: string, ts: number) { for (const v of this.rows.values()) if (v.id === id) v.last_seen = ts; }
}
class MemItems implements VaultItemStore {
  rows: VaultItemRow[] = [];
  async countForAccount(a: string) { return this.rows.filter((r) => r.account_id === a).length; }
  async insert(r: VaultItemRow) { this.rows.push(r); }
  async page(_a: string, _o: { limit: number; bookmarked?: boolean; cursor?: ItemCursor }) { return []; }
  async allForAccount(a: string) { return this.rows.filter((r) => r.account_id === a); }
  async getById(a: string, id: string) { return this.rows.find((r) => r.account_id === a && r.id === id) ?? null; }
  async setBookmark() { return true; }
  async updateMetadata() { return true; }
  async setDeleted() { return true; }
  async remove() { return true; }
  async deleteAllForAccount(a: string) { this.rows = this.rows.filter((r) => r.account_id !== a); }
}
class MemConns implements StorageConnectionStore {
  rows: StorageConnectionRow[] = [];
  async listForAccount(a: string) { return this.rows.filter((r) => r.account_id === a); }
  async insert(r: StorageConnectionRow) { this.rows.push(r); }
  async remove() { return true; }
  async deleteAllForAccount(a: string) { this.rows = this.rows.filter((r) => r.account_id !== a); }
}
class MemTotp implements TotpStore {
  rows = new Map<string, TotpRow>();
  async get(a: string) { return this.rows.get(a) ?? null; }
  async upsert(r: TotpRow) { this.rows.set(r.account_id, { ...r }); }
  async delete(a: string) { this.rows.delete(a); }
}
class MemFolders implements FolderStore {
  rows: FolderRow[] = [];
  async listForAccount(a: string) { return this.rows.filter((r) => r.account_id === a); }
  async insert(r: FolderRow) { this.rows.push(r); }
  async rename() { return true; }
  async remove() { return true; }
  async deleteAllForAccount(a: string) { this.rows = this.rows.filter((r) => r.account_id !== a); }
}

function seed() {
  const accounts = new MemAccounts(), sessions = new MemSessions(), items = new MemItems(), connections = new MemConns(), totp = new MemTotp(), folders = new MemFolders();
  const now = Date.now();
  const acct: AccountRow = {
    id: 'acc-1', email: 'z@example.com', email_verified: 0, kdf: 'argon2id',
    kdf_salt: 'salt', kdf_params: '{"m":1,"t":1,"p":1}', login_hash: 'LOGINHASH',
    wrapped_account_key: 'WAK', wrapped_account_key_recovery: 'WAKR', recovery_key_hash: 'RKH',
    created_at: now, updated_at: now,
  };
  accounts.rows.set(acct.id, acct);
  // A second account whose data must NOT be touched.
  accounts.rows.set('acc-2', { ...acct, id: 'acc-2', email: 'other@example.com' });
  connections.rows.push({ id: 'c1', account_id: 'acc-1', provider: 'dropbox', enc_config: 'ENCCFG', label: 'Dropbox', created_at: now });
  connections.rows.push({ id: 'c2', account_id: 'acc-2', provider: 's3', enc_config: 'OTHER', label: null, created_at: now });
  items.rows.push({ id: 'i1', account_id: 'acc-1', enc_metadata: 'M1', wrapped_item_key: 'K1', connection_id: 'c1', object_key: 'mv/a.enc', thumb_key: 'mv/a.thumb', size: 10, bookmarked: 1, created_at: now, updated_at: now });
  items.rows.push({ id: 'i2', account_id: 'acc-1', enc_metadata: 'M2', wrapped_item_key: 'K2', connection_id: 'c1', object_key: 'mv/b.enc', thumb_key: null, size: 20, bookmarked: 0, created_at: now, updated_at: now });
  items.rows.push({ id: 'i3', account_id: 'acc-2', enc_metadata: 'X', wrapped_item_key: 'X', connection_id: 'c2', object_key: 'mv/x.enc', thumb_key: null, size: 5, bookmarked: 0, created_at: now, updated_at: now });
  sessions.rows.set('t1', { id: 's1', account_id: 'acc-1', token_hash: 't1', created_at: now, expires_at: now + 1000 });
  sessions.rows.set('t2', { id: 's2', account_id: 'acc-2', token_hash: 't2', created_at: now, expires_at: now + 1000 });
  totp.rows.set('acc-1', { account_id: 'acc-1', secret: 'S1', enabled: 1, backup_codes: null, created_at: now, confirmed_at: now });
  totp.rows.set('acc-2', { account_id: 'acc-2', secret: 'S2', enabled: 1, backup_codes: null, created_at: now, confirmed_at: now });
  folders.rows.push({ id: 'f1', account_id: 'acc-1', enc_name: 'ENC1', created_at: now });
  folders.rows.push({ id: 'f2', account_id: 'acc-2', enc_name: 'ENC2', created_at: now });
  return { accounts, sessions, items, connections, totp, folders };
}

describe('exportAccount', () => {
  it('returns the account profile, encrypted crypto material, connections, and all items', async () => {
    const ctx = seed();
    const exp = (await exportAccount(ctx, 'acc-1'))!;
    expect(exp.account).toEqual({ id: 'acc-1', email: 'z@example.com', createdAt: expect.any(Number) });
    expect(exp.crypto.wrappedAccountKey).toBe('WAK');
    expect(exp.crypto.wrappedAccountKeyRecovery).toBe('WAKR');
    // Never leak server-side auth secrets.
    expect(JSON.stringify(exp)).not.toContain('LOGINHASH');
    expect(JSON.stringify(exp)).not.toContain('RKH');
    expect(exp.connections).toHaveLength(1);
    expect(exp.connections[0].encConfig).toBe('ENCCFG');
    expect(exp.items.map((i) => i.id).sort()).toEqual(['i1', 'i2']);
    expect(exp.items.find((i) => i.id === 'i1')!.bookmarked).toBe(true);
  });

  it('returns null for an unknown account', async () => {
    const ctx = seed();
    expect(await exportAccount(ctx, 'nope')).toBeNull();
  });
});

describe('deleteAccount', () => {
  it('removes the account, its items, connections, and sessions — and nothing else', async () => {
    const ctx = seed();
    expect(await deleteAccount(ctx, 'acc-1')).toBe(true);
    expect(ctx.accounts.rows.has('acc-1')).toBe(false);
    expect(ctx.items.rows.filter((r) => r.account_id === 'acc-1')).toHaveLength(0);
    expect(ctx.connections.rows.filter((r) => r.account_id === 'acc-1')).toHaveLength(0);
    expect([...ctx.sessions.rows.values()].filter((s) => s.account_id === 'acc-1')).toHaveLength(0);
    expect(ctx.totp.rows.has('acc-1')).toBe(false); // 2FA secret removed too
    expect(ctx.folders.rows.filter((r) => r.account_id === 'acc-1')).toHaveLength(0); // folders removed too
    // The other account is untouched.
    expect(ctx.accounts.rows.has('acc-2')).toBe(true);
    expect(ctx.items.rows.filter((r) => r.account_id === 'acc-2')).toHaveLength(1);
    expect(ctx.connections.rows.filter((r) => r.account_id === 'acc-2')).toHaveLength(1);
    expect(ctx.totp.rows.has('acc-2')).toBe(true);
    expect(ctx.folders.rows.filter((r) => r.account_id === 'acc-2')).toHaveLength(1);
  });

  it('returns false for an unknown account', async () => {
    const ctx = seed();
    expect(await deleteAccount(ctx, 'nope')).toBe(false);
  });
});
