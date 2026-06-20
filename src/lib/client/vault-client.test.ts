import { describe, it, expect } from 'vitest';
import { VaultClient } from './vault-client';
import type { KdfParams } from '../e2ee/account';
import type { ProviderConfig } from '../storage/object-store';
import {
  getLoginParams, signup, login, logout, validateSession, startSession,
} from '../server/auth-service';
import {
  createItem, listItems, deleteItem, setBookmark, createConnection, listConnections,
} from '../server/vault-service';
import type {
  AccountRow, AccountStore, KVLike, SessionRow, SessionStore,
  StorageConnectionRow, StorageConnectionStore, ItemCursor, VaultItemRow, VaultItemStore,
} from '../server/types';

const FAST: KdfParams = { m: 256, t: 1, p: 1 };

// ── Minimal in-memory stores (mirror the D1 stores' semantics) ─────────────────
class MemAccounts implements AccountStore {
  rows = new Map<string, AccountRow>();
  async getByEmail(e: string) { return [...this.rows.values()].find((r) => r.email === e) ?? null; }
  async getById(id: string) { return this.rows.get(id) ?? null; }
  async insert(r: AccountRow) { this.rows.set(r.id, r); }
  async updateSecrets() {}
}
class MemSessions implements SessionStore {
  rows = new Map<string, SessionRow>();
  async insert(s: SessionRow) { this.rows.set(s.token_hash, s); }
  async getByTokenHash(h: string) { return this.rows.get(h) ?? null; }
  async deleteByTokenHash(h: string) { this.rows.delete(h); }
  async deleteAllForAccount(a: string) { for (const [k, v] of this.rows) if (v.account_id === a) this.rows.delete(k); }
}
class MemKV implements KVLike {
  m = new Map<string, string>();
  async get(k: string) { return this.m.get(k) ?? null; }
  async put(k: string, v: string) { this.m.set(k, v); }
  async delete(k: string) { this.m.delete(k); }
}
class MemItems implements VaultItemStore {
  rows: VaultItemRow[] = [];
  async countForAccount(a: string) { return this.rows.filter((r) => r.account_id === a).length; }
  async insert(r: VaultItemRow) { this.rows.push(r); }
  async page(a: string, o: { limit: number; bookmarked?: boolean; cursor?: ItemCursor }) {
    let rows = this.rows.filter((r) => r.account_id === a);
    if (o.bookmarked) rows = rows.filter((r) => r.bookmarked === 1);
    rows.sort((x, y) => y.created_at - x.created_at || (x.id < y.id ? 1 : -1));
    if (o.cursor) { const c = o.cursor; rows = rows.filter((r) => r.created_at < c.createdAt || (r.created_at === c.createdAt && r.id < c.id)); }
    return rows.slice(0, o.limit);
  }
  async getById(a: string, id: string) { return this.rows.find((r) => r.account_id === a && r.id === id) ?? null; }
  async setBookmark(a: string, id: string, b: boolean) { const r = this.rows.find((x) => x.account_id === a && x.id === id); if (!r) return false; r.bookmarked = b ? 1 : 0; return true; }
  async remove(a: string, id: string) { const i = this.rows.findIndex((r) => r.account_id === a && r.id === id); if (i < 0) return false; this.rows.splice(i, 1); return true; }
}
class MemConns implements StorageConnectionStore {
  rows: StorageConnectionRow[] = [];
  async listForAccount(a: string) { return this.rows.filter((r) => r.account_id === a); }
  async insert(r: StorageConnectionRow) { this.rows.push(r); }
  async remove(a: string, id: string) { const i = this.rows.findIndex((r) => r.account_id === a && r.id === id); if (i < 0) return false; this.rows.splice(i, 1); return true; }
}

// ── Fake API server (routes to the REAL services) + a cookie jar ───────────────
function makeFakeApi() {
  const accounts = new MemAccounts(), sessions = new MemSessions(), kv = new MemKV();
  const items = new MemItems(), conns = new MemConns();
  const jar: { token: string | null } = { token: null };
  const J = (o: unknown, s = 200) => new Response(JSON.stringify(o), { status: s });

  const apiFetch = async (path: string, init: RequestInit = {}) => {
    const method = (init.method || 'GET').toUpperCase();
    const url = new URL(path, 'http://test');
    const p = url.pathname;
    const body = init.body ? JSON.parse(init.body as string) : {};

    if (p === '/api/auth/signup') {
      const r = await signup(accounts, body);
      if (!r.ok) return J({ error: r.error }, 400);
      jar.token = await startSession(sessions, r.accountId);
      return J({ ok: true });
    }
    if (p === '/api/auth/prelogin') return J(await getLoginParams(accounts, body.email));
    if (p === '/api/auth/login') {
      const r = await login({ accounts, sessions, kv }, { email: body.email, authKeyB64: body.authKeyB64, ipKey: 't' });
      if (!r.ok) return J({ error: r.error }, 401);
      jar.token = r.result.token;
      return J({ ok: true, wrappedAccountKey: r.result.wrappedAccountKey, kdfSalt: r.result.kdfSalt, kdfParams: r.result.kdfParams });
    }
    if (p === '/api/auth/logout') { await logout(sessions, jar.token ?? undefined); jar.token = null; return J({ ok: true }); }

    const accountId = (await validateSession(sessions, jar.token ?? undefined))?.accountId;
    if (!accountId) return J({ error: 'unauthorized' }, 401);

    if (p === '/api/vault/connections' && method === 'GET') return J({ connections: await listConnections(conns, accountId) });
    if (p === '/api/vault/connections' && method === 'POST') { const r = await createConnection(conns, accountId, body); return r.ok ? J(r, 201) : J({ error: r.error }, 400); }
    if (p === '/api/vault/items' && method === 'GET') {
      return J(await listItems(items, accountId, {
        limit: Number(url.searchParams.get('limit')) || 60,
        bookmarked: url.searchParams.get('bookmarked') === '1',
        cursor: url.searchParams.get('cursor'),
      }));
    }
    if (p === '/api/vault/items' && method === 'POST') { const r = await createItem(items, accountId, body); return r.ok ? J(r, 201) : J({ error: r.error }, 400); }
    const m = p.match(/^\/api\/vault\/items\/(.+)$/);
    if (m) {
      if (method === 'DELETE') return (await deleteItem(items, accountId, m[1])) ? J({ ok: true }) : J({ error: 'not_found' }, 404);
      if (method === 'PATCH') return (await setBookmark(items, accountId, m[1], !!body.bookmarked)) ? J({ ok: true }) : J({ error: 'not_found' }, 404);
    }
    return J({ error: 'not_found' }, 404);
  };
  return { apiFetch, stores: { accounts, items, conns } };
}

// ── Fake bucket (in-memory ObjectStore) ────────────────────────────────────────
function makeFakeStore() {
  const store = new Map<string, Uint8Array>();
  const makeStore = () => ({
    async put(key: string, body: Uint8Array) { store.set(key, body); return key; },
    async get(key: string) { return new Response(store.get(key) ?? new Uint8Array()); },
    async del(key: string) { store.delete(key); },
    async test() { return { ok: true as const }; },
  });
  return { makeStore, store };
}

const S3CFG: ProviderConfig = {
  kind: 's3', endpoint: 'https://x.r2.cloudflarestorage.com', region: 'auto', bucket: 'b',
  accessKeyId: 'AK', secretAccessKey: 'sk-sk-sk-sk-sk-sk-sk-sk-sk-sk-sk',
};

describe('VaultClient full lifecycle (real services + crypto, fake transport)', () => {
  it('signup → connect → upload → list → download → bookmark → delete → relogin', async () => {
    const { apiFetch } = makeFakeApi();
    const { makeStore, store } = makeFakeStore();
    const client = new VaultClient({ apiFetch, makeStore });

    // signup
    const { recoveryKey } = await client.signup('alice@example.com', 'password-123', FAST);
    expect(recoveryKey).toMatch(/^[0-9A-F-]+$/);
    expect(client.isUnlocked()).toBe(true);

    // connect storage
    const { id: connId } = await client.addConnection(S3CFG, 'My R2');
    const conns = await client.getConnections();
    expect(conns).toHaveLength(1);
    expect(conns[0].id).toBe(connId);
    expect(conns[0].config.kind).toBe('s3');
    if (conns[0].config.kind === 's3') expect(conns[0].config.bucket).toBe('b'); // decrypted locally

    // upload (with an encrypted thumbnail)
    const original = new Uint8Array([10, 20, 30, 40, 50, 60]);
    const thumb = new Uint8Array([1, 2, 3, 4]);
    await client.upload(conns[0], { bytes: original, name: 'beach.jpg', mime: 'image/jpeg', thumbnail: thumb });
    expect(store.size).toBe(2); // file + thumbnail, both ciphertext
    for (const onDisk of store.values()) {
      expect(onDisk.slice(0, 3)).toEqual(new Uint8Array([0x4d, 0x56, 0x31])); // "MV1" — encrypted
    }

    // list + decrypt metadata
    const page = await client.listPage();
    expect(page.items).toHaveLength(1);
    expect(page.items[0].metadata.name).toBe('beach.jpg');
    expect(page.items[0].metadata.mime).toBe('image/jpeg');
    expect(page.items[0].thumbKey).toBeTruthy();

    // thumbnail round-trips
    const t = await client.getThumbnail(page.items[0], conns[0]);
    expect(t && Array.from(t)).toEqual(Array.from(thumb));

    // download + decrypt
    const dl = await client.download(page.items[0], conns[0]);
    expect(Array.from(dl.bytes)).toEqual(Array.from(original));

    // bookmark
    await client.setBookmark(page.items[0], true);
    const booked = await client.listPage({ bookmarked: true });
    expect(booked.items).toHaveLength(1);

    // delete (removes bucket object + index row)
    await client.remove(page.items[0], conns[0]);
    expect(store.size).toBe(0);
    expect((await client.listPage()).items).toHaveLength(0);

    // relogin
    await client.logout();
    expect(client.isUnlocked()).toBe(false);
    await client.login('alice@example.com', 'password-123');
    expect(client.isUnlocked()).toBe(true);
  });

  it('a wrong password cannot log in', async () => {
    const { apiFetch } = makeFakeApi();
    const { makeStore } = makeFakeStore();
    const client = new VaultClient({ apiFetch, makeStore });
    await client.signup('bob@example.com', 'correct-pw-1', FAST);
    await client.logout();
    await expect(client.login('bob@example.com', 'wrong-pw-2')).rejects.toBeDefined();
  });
});
