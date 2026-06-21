/**
 * Deep end-to-end integration test for the Dropbox connector. It drives the REAL
 * VaultClient, the REAL E2EE crypto, the REAL server services, and the REAL
 * DropboxStore/DropboxClient — only the network is faked, by an in-memory Dropbox
 * API that faithfully implements upload, ranged download (206), delete, the
 * account check, and token refresh. This proves the whole pipeline over Dropbox:
 * encrypt → upload → index → list → download → seekable range-decrypt → delete,
 * plus access-token refresh mid-session.
 */
import { describe, it, expect } from 'vitest';
import { VaultClient } from './vault-client';
import { streamRange } from './stream';
import { DropboxStore } from '../storage/dropbox-store';
import type { ProviderConfig } from '../storage/object-store';
import type { KdfParams } from '../e2ee/account';
import { getLoginParams, signup, login, logout, validateSession, startSession } from '../server/auth-service';
import { createItem, listItems, deleteItem, setBookmark, createConnection, listConnections } from '../server/vault-service';
import type {
  AccountRow, AccountStore, KVLike, SessionRow, SessionStore,
  StorageConnectionRow, StorageConnectionStore, ItemCursor, VaultItemRow, VaultItemStore,
} from '../server/types';

const FAST: KdfParams = { m: 256, t: 1, p: 1 };

// ── In-memory server stores (mirror the D1 stores' semantics) ──────────────────
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
    const mm = p.match(/^\/api\/vault\/items\/(.+)$/);
    if (mm) {
      if (method === 'DELETE') return (await deleteItem(items, accountId, mm[1])) ? J({ ok: true }) : J({ error: 'not_found' }, 404);
      if (method === 'PATCH') return (await setBookmark(items, accountId, mm[1], !!body.bookmarked)) ? J({ ok: true }) : J({ error: 'not_found' }, 404);
    }
    return J({ error: 'not_found' }, 404);
  };
  return { apiFetch };
}

// ── Faithful in-memory Dropbox HTTP API ────────────────────────────────────────
function makeFakeDropbox() {
  const files = new Map<string, Uint8Array>();
  const log: string[] = [];
  let serveCount = 0;
  let failNextDownloadWith401 = false;
  const J = (o: unknown, s = 200) => new Response(JSON.stringify(o), { status: s });
  const bodyBytes = async (b: unknown) => new Uint8Array(await new Response((b ?? new Uint8Array()) as BodyInit).arrayBuffer());

  const fetchImpl = async (url: string, init: RequestInit = {}) => {
    const h = new Headers(init.headers);
    const arg = h.get('dropbox-api-arg') ? JSON.parse(h.get('dropbox-api-arg')!) : {};
    log.push(url.replace('https://', '').replace(/^[^/]+\/2/, '').replace('content.dropboxapi.com', ''));

    if (url.endsWith('/oauth2/token')) return J({ access_token: `srv-token-${++serveCount}`, expires_in: 14400 });
    if (!h.get('authorization')?.startsWith('Bearer ')) return new Response('missing auth', { status: 401 });

    if (url.endsWith('/files/upload')) { files.set(arg.path, await bodyBytes(init.body)); return J({ name: arg.path }); }
    if (url.endsWith('/files/download')) {
      if (failNextDownloadWith401) { failNextDownloadWith401 = false; return new Response('expired', { status: 401 }); }
      const bytes = files.get(arg.path);
      if (!bytes) return new Response('path/not_found', { status: 409 });
      const range = h.get('range');
      if (range) {
        const m = /bytes=(\d+)-(\d+)/.exec(range)!;
        const lo = +m[1], hi = Math.min(+m[2], bytes.length - 1);
        return new Response(bytes.subarray(lo, hi + 1), { status: 206 });
      }
      return new Response(bytes, { status: 200 });
    }
    if (url.endsWith('/files/delete_v2')) {
      const b = JSON.parse(init.body as string);
      return files.delete(b.path) ? J({}) : new Response('path/not_found', { status: 409 });
    }
    if (url.endsWith('/users/get_current_account')) return J({ account_id: 'acc-1' });
    return new Response('unhandled', { status: 500 });
  };
  return { fetchImpl, files, log, expire401Once: () => { failNextDownloadWith401 = true; } };
}

describe('Dropbox connector — full vault lifecycle over a faithful Dropbox API', () => {
  it('signup → connect Dropbox → upload → list → download → seek → delete', async () => {
    const { apiFetch } = makeFakeApi();
    const dbx = makeFakeDropbox();
    const makeStore = (cfg: ProviderConfig) => new DropboxStore(cfg as never, dbx.fetchImpl);
    const client = new VaultClient({ apiFetch, makeStore });

    await client.signup('dave@example.com', 'password-123', FAST);

    const dbxCfg: ProviderConfig = {
      kind: 'dropbox', clientId: 'pc4qfb65x6bpowd',
      accessToken: 'srv-token-0', refreshToken: 'refresh-abc', expiresAt: Date.now() + 3_600_000,
    };
    const { id: connId } = await client.addConnection(dbxCfg, 'Dropbox'); // calls store.test() → get_current_account
    const conns = await client.getConnections();
    expect(conns).toHaveLength(1);
    expect(conns[0].config.kind).toBe('dropbox');
    if (conns[0].config.kind === 'dropbox') expect(conns[0].config.clientId).toBe('pc4qfb65x6bpowd'); // decrypted locally
    expect(conns[0].id).toBe(connId);

    // A 5 MiB file so a later seek crosses the 4 MiB chunk boundary.
    const SIZE = 5 * 1024 * 1024;
    const original = new Uint8Array(SIZE);
    for (let i = 0; i < SIZE; i++) original[i] = (i * 31 + 7) & 0xff;
    const thumb = new Uint8Array([9, 8, 7, 6, 5]);

    await client.upload(conns[0], { bytes: original, name: 'clip.mp4', mime: 'video/mp4', thumbnail: thumb });
    expect(dbx.files.size).toBe(2); // file + thumbnail
    for (const onDisk of dbx.files.values()) {
      expect(onDisk.slice(0, 3)).toEqual(new Uint8Array([0x4d, 0x56, 0x31])); // "MV1" — ciphertext on disk
    }
    // Stored under the app-folder "/mv/..." path convention.
    expect([...dbx.files.keys()].every((k) => k.startsWith('/mv/'))).toBe(true);

    const page = await client.listPage();
    expect(page.items).toHaveLength(1);
    const item = page.items[0];
    expect(item.metadata.name).toBe('clip.mp4');
    expect(item.metadata.size).toBe(SIZE);

    // Thumbnail round-trips.
    const t = await client.getThumbnail(item, conns[0]);
    expect(t && Array.from(t)).toEqual(Array.from(thumb));

    // Full download decrypts byte-for-byte.
    const dl = await client.download(item, conns[0]);
    expect(dl.bytes.length).toBe(SIZE);
    expect(Array.from(dl.bytes.subarray(0, 64))).toEqual(Array.from(original.subarray(0, 64)));
    expect(Array.from(dl.bytes.subarray(SIZE - 64))).toEqual(Array.from(original.subarray(SIZE - 64)));

    // Seekable range over Dropbox (206) crossing the 4 MiB chunk boundary,
    // using the SAME stream params the Service Worker uses.
    const store = makeStore(conns[0].config);
    const sp = await client.getStreamParams(item, conns[0]);
    const lo = 4 * 1024 * 1024 - 50, hi = 4 * 1024 * 1024 + 49;
    const ranged = await streamRange(store, sp.objectKey, sp.header, sp.fileKey, sp.plaintextSize, lo, hi);
    expect(Array.from(ranged)).toEqual(Array.from(original.subarray(lo, hi + 1)));

    // Delete removes both objects (file + thumb) from Dropbox and the index row.
    await client.remove(item, conns[0]);
    expect(dbx.files.size).toBe(0);
    expect((await client.listPage()).items).toHaveLength(0);
  });

  it('recovers from an expired access token mid-download via a silent refresh', async () => {
    const { apiFetch } = makeFakeApi();
    const dbx = makeFakeDropbox();
    const makeStore = (cfg: ProviderConfig) => new DropboxStore(cfg as never, dbx.fetchImpl);
    const client = new VaultClient({ apiFetch, makeStore });

    await client.signup('erin@example.com', 'password-123', FAST);
    const dbxCfg: ProviderConfig = {
      kind: 'dropbox', clientId: 'pc4qfb65x6bpowd',
      accessToken: 'srv-token-0', refreshToken: 'refresh-abc', expiresAt: Date.now() + 3_600_000,
    };
    await client.addConnection(dbxCfg, 'Dropbox');
    const conn = (await client.getConnections())[0];

    const original = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    await client.upload(conn, { bytes: original, name: 'note.bin', mime: 'application/octet-stream' });
    const item = (await client.listPage()).items[0];

    dbx.expire401Once(); // next Dropbox download returns 401 → client must refresh + retry
    const dl = await client.download(item, conn);
    expect(Array.from(dl.bytes)).toEqual(Array.from(original));
    expect(dbx.log.some((l) => l.includes('oauth2/token'))).toBe(true); // a refresh happened
  });
});
