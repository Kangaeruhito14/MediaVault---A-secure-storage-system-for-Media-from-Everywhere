import { describe, it, expect } from 'vitest';
import {
  createItem,
  listItems,
  deleteItem,
  setBookmark,
  updateItemMetadata,
  trashItem,
  restoreItem,
  createConnection,
  listConnections,
  deleteConnection,
} from './vault-service';
import type {
  ItemCursor,
  StorageConnectionRow,
  StorageConnectionStore,
  VaultItemRow,
  VaultItemStore,
} from './types';

// In-memory fakes mirroring the D1 stores' semantics.
class MemItems implements VaultItemStore {
  rows: VaultItemRow[] = [];
  async countForAccount(a: string) {
    return this.rows.filter((r) => r.account_id === a).length;
  }
  async insert(r: VaultItemRow) {
    this.rows.push(r);
  }
  async page(a: string, o: { limit: number; bookmarked?: boolean; trashed?: boolean; cursor?: ItemCursor }) {
    let rows = this.rows.filter((r) => r.account_id === a);
    rows = rows.filter((r) => (o.trashed ? r.deleted_at != null : r.deleted_at == null));
    if (o.bookmarked) rows = rows.filter((r) => r.bookmarked === 1);
    rows.sort((x, y) => y.created_at - x.created_at || (x.id < y.id ? 1 : x.id > y.id ? -1 : 0));
    if (o.cursor) {
      const c = o.cursor;
      rows = rows.filter((r) => r.created_at < c.createdAt || (r.created_at === c.createdAt && r.id < c.id));
    }
    return rows.slice(0, o.limit);
  }
  async allForAccount(a: string) {
    return this.rows.filter((r) => r.account_id === a);
  }
  async deleteAllForAccount(a: string) {
    this.rows = this.rows.filter((r) => r.account_id !== a);
  }
  async getById(a: string, id: string) {
    return this.rows.find((r) => r.account_id === a && r.id === id) ?? null;
  }
  async setBookmark(a: string, id: string, b: boolean) {
    const r = this.rows.find((x) => x.account_id === a && x.id === id);
    if (!r) return false;
    r.bookmarked = b ? 1 : 0;
    return true;
  }
  async updateMetadata(a: string, id: string, enc: string) {
    const r = this.rows.find((x) => x.account_id === a && x.id === id);
    if (!r) return false;
    r.enc_metadata = enc;
    return true;
  }
  async setDeleted(a: string, id: string, deletedAt: number | null) {
    const r = this.rows.find((x) => x.account_id === a && x.id === id);
    if (!r) return false;
    r.deleted_at = deletedAt;
    return true;
  }
  async remove(a: string, id: string) {
    const i = this.rows.findIndex((r) => r.account_id === a && r.id === id);
    if (i < 0) return false;
    this.rows.splice(i, 1);
    return true;
  }
}
class MemConns implements StorageConnectionStore {
  rows: StorageConnectionRow[] = [];
  async listForAccount(a: string) {
    return this.rows.filter((r) => r.account_id === a);
  }
  async insert(r: StorageConnectionRow) {
    this.rows.push(r);
  }
  async remove(a: string, id: string) {
    const i = this.rows.findIndex((r) => r.account_id === a && r.id === id);
    if (i < 0) return false;
    this.rows.splice(i, 1);
    return true;
  }
  async deleteAllForAccount(a: string) {
    this.rows = this.rows.filter((r) => r.account_id !== a);
  }
}

function seed(store: MemItems, account: string, n: number) {
  const ids = 'abcdefghij';
  for (let i = 1; i <= n; i++) {
    store.rows.push({
      id: ids[i - 1],
      account_id: account,
      enc_metadata: 'm',
      wrapped_item_key: 'k',
      connection_id: 'c1',
      object_key: 'mv/' + i,
      thumb_key: null,
      size: 100,
      bookmarked: 0,
      created_at: i, // distinct, ascending
      updated_at: i,
    });
  }
}

const goodItem = {
  encMetadata: 'enc',
  wrappedItemKey: 'wk',
  connectionId: 'c1',
  objectKey: 'mv/x',
  size: 10,
};

describe('createItem', () => {
  it('creates an item', async () => {
    const items = new MemItems();
    const r = await createItem(items, 'A', goodItem);
    expect(r.ok).toBe(true);
    expect(items.rows).toHaveLength(1);
  });
  it('rejects missing fields', async () => {
    const items = new MemItems();
    const r = await createItem(items, 'A', { ...goodItem, objectKey: '' });
    expect(r).toEqual({ ok: false, error: 'missing_fields' });
  });
  it('enforces the per-account item limit', async () => {
    const items = new MemItems();
    items.countForAccount = async () => 50_000; // at the cap
    const r = await createItem(items, 'A', goodItem);
    expect(r).toEqual({ ok: false, error: 'item_limit_reached' });
  });
});

describe('listItems keyset pagination', () => {
  it('walks newest-first pages via cursor', async () => {
    const items = new MemItems();
    seed(items, 'A', 5); // created_at 1..5, ids a..e

    const p1 = await listItems(items, 'A', { limit: 2 });
    expect(p1.items.map((i) => i.createdAt)).toEqual([5, 4]);
    expect(p1.nextCursor).toBe('4_d');

    const p2 = await listItems(items, 'A', { limit: 2, cursor: p1.nextCursor });
    expect(p2.items.map((i) => i.createdAt)).toEqual([3, 2]);
    expect(p2.nextCursor).toBe('2_b');

    const p3 = await listItems(items, 'A', { limit: 2, cursor: p2.nextCursor });
    expect(p3.items.map((i) => i.createdAt)).toEqual([1]);
    expect(p3.nextCursor).toBeNull(); // last page
  });

  it('filters to bookmarked only', async () => {
    const items = new MemItems();
    seed(items, 'A', 3);
    await setBookmark(items, 'A', 'b', true);
    const r = await listItems(items, 'A', { bookmarked: true });
    expect(r.items.map((i) => i.id)).toEqual(['b']);
    expect(r.items[0].bookmarked).toBe(true);
  });

  it('never returns another account\'s items', async () => {
    const items = new MemItems();
    seed(items, 'A', 3);
    seed(items, 'B', 2);
    const r = await listItems(items, 'B', { limit: 100 });
    expect(r.items).toHaveLength(2);
  });
});

describe('mutations are account-scoped', () => {
  it('delete / bookmark only affect the owner', async () => {
    const items = new MemItems();
    seed(items, 'A', 1); // id 'a'
    expect(await deleteItem(items, 'B', 'a')).toBe(false); // wrong account
    expect(await setBookmark(items, 'B', 'a', true)).toBe(false);
    expect(await deleteItem(items, 'A', 'a')).toBe(true);
  });
});

describe('trash / restore', () => {
  it('trashed items leave the live list, appear in trash, and restore back', async () => {
    const items = new MemItems();
    seed(items, 'A', 3); // ids a, b, c — all live
    const live = () => listItems(items, 'A', {});
    const trash = () => listItems(items, 'A', { trashed: true });

    expect((await live()).items.map((i) => i.id).sort()).toEqual(['a', 'b', 'c']);
    expect((await trash()).items).toHaveLength(0);

    expect(await trashItem(items, 'A', 'b')).toBe(true);
    expect((await live()).items.map((i) => i.id).sort()).toEqual(['a', 'c']); // 'b' gone from live
    expect((await trash()).items.map((i) => i.id)).toEqual(['b']);            // 'b' in trash

    expect(await restoreItem(items, 'A', 'b')).toBe(true);
    expect((await live()).items.map((i) => i.id).sort()).toEqual(['a', 'b', 'c']);
    expect((await trash()).items).toHaveLength(0);
  });

  it('trash / restore are account-scoped and permanent delete still works from trash', async () => {
    const items = new MemItems();
    seed(items, 'A', 1); // id 'a'
    expect(await trashItem(items, 'B', 'a')).toBe(false); // wrong account
    expect(await trashItem(items, 'A', 'a')).toBe(true);
    expect(await deleteItem(items, 'A', 'a')).toBe(true); // purge from trash
    expect((await listItems(items, 'A', { trashed: true })).items).toHaveLength(0);
  });
});

describe('updateItemMetadata (rename)', () => {
  it('replaces the encrypted metadata blob for the owner only', async () => {
    const items = new MemItems();
    seed(items, 'A', 1); // id 'a'
    expect(await updateItemMetadata(items, 'B', 'a', 'NEWENC')).toBe(false); // wrong account
    expect((await items.getById('A', 'a'))!.enc_metadata).not.toBe('NEWENC');
    expect(await updateItemMetadata(items, 'A', 'a', 'NEWENC')).toBe(true);
    expect((await items.getById('A', 'a'))!.enc_metadata).toBe('NEWENC');
    expect(await updateItemMetadata(items, 'A', 'missing', 'X')).toBe(false); // unknown id
  });
});

describe('storage connections', () => {
  it('rejects unknown providers, stores valid ones, lists and deletes scoped', async () => {
    const conns = new MemConns();
    expect((await createConnection(conns, 'A', { provider: 'ftp', encConfig: 'x' })).ok).toBe(false);
    const c = await createConnection(conns, 'A', { provider: 's3', encConfig: 'enc', label: 'R2' });
    expect(c.ok).toBe(true);

    const list = await listConnections(conns, 'A');
    expect(list).toHaveLength(1);
    expect(list[0].encConfig).toBe('enc'); // returned so the client can decrypt creds

    if (c.ok) {
      expect(await deleteConnection(conns, 'B', c.id)).toBe(false); // wrong account
      expect(await deleteConnection(conns, 'A', c.id)).toBe(true);
    }
  });
});
