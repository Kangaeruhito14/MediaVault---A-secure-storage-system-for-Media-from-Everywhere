/**
 * Vault index service — manages the ENCRYPTED metadata index and storage
 * connections. The server stores only opaque blobs and pointers; it never sees
 * file bytes (those live in the user's bucket) or any plaintext.
 *
 * Pagination is keyset (created_at, id) so a library of a million items stays
 * fast — no large OFFSET scans.
 */
import { LIMITS } from '../storage/provider';
import type {
  ItemCursor,
  StorageConnectionStore,
  VaultItemRow,
  VaultItemStore,
} from './types';

const ALLOWED_PROVIDERS = new Set(['s3', 'gdrive', 'dropbox', 'local']);

function uuid(): string {
  return globalThis.crypto.randomUUID();
}

// ── Items ──────────────────────────────────────────────────────────────────────
export interface CreateItemInput {
  encMetadata: string;
  wrappedItemKey: string;
  iv: string;
  connectionId: string;
  objectKey: string;
  thumbKey?: string | null;
  size?: number;
}

export interface PublicItem {
  id: string;
  encMetadata: string;
  wrappedItemKey: string;
  iv: string;
  connectionId: string;
  objectKey: string;
  thumbKey: string | null;
  size: number;
  bookmarked: boolean;
  createdAt: number;
}

function toPublic(r: VaultItemRow): PublicItem {
  return {
    id: r.id,
    encMetadata: r.enc_metadata,
    wrappedItemKey: r.wrapped_item_key,
    iv: r.iv,
    connectionId: r.connection_id,
    objectKey: r.object_key,
    thumbKey: r.thumb_key,
    size: r.size,
    bookmarked: r.bookmarked === 1,
    createdAt: r.created_at,
  };
}

function encodeCursor(r: VaultItemRow): string {
  return `${r.created_at}_${r.id}`;
}
function decodeCursor(s?: string | null): ItemCursor | undefined {
  if (!s) return undefined;
  const i = s.indexOf('_');
  if (i < 0) return undefined;
  const createdAt = Number(s.slice(0, i));
  const id = s.slice(i + 1);
  if (!Number.isFinite(createdAt) || !id) return undefined;
  return { createdAt, id };
}

export async function createItem(
  items: VaultItemStore,
  accountId: string,
  input: CreateItemInput,
): Promise<{ ok: true; id: string; createdAt: number } | { ok: false; error: string }> {
  if (!input.encMetadata || !input.wrappedItemKey || !input.iv || !input.connectionId || !input.objectKey) {
    return { ok: false, error: 'missing_fields' };
  }
  if ((await items.countForAccount(accountId)) >= LIMITS.MAX_ITEMS_PER_ACCOUNT) {
    return { ok: false, error: 'item_limit_reached' };
  }
  const id = uuid();
  const t = Date.now();
  await items.insert({
    id,
    account_id: accountId,
    enc_metadata: input.encMetadata,
    wrapped_item_key: input.wrappedItemKey,
    iv: input.iv,
    connection_id: input.connectionId,
    object_key: input.objectKey,
    thumb_key: input.thumbKey ?? null,
    size: input.size ?? 0,
    bookmarked: 0,
    created_at: t,
    updated_at: t,
  });
  return { ok: true, id, createdAt: t };
}

export async function listItems(
  items: VaultItemStore,
  accountId: string,
  opts: { limit?: number; bookmarked?: boolean; cursor?: string | null },
): Promise<{ items: PublicItem[]; nextCursor: string | null }> {
  const limit = Math.min(Math.max(opts.limit ?? 60, 1), 200);
  // Fetch one extra to detect whether another page exists.
  const rows = await items.page(accountId, { limit: limit + 1, bookmarked: opts.bookmarked, cursor: decodeCursor(opts.cursor) });
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;
  return {
    items: page.map(toPublic),
    nextCursor: hasMore ? encodeCursor(page[page.length - 1]) : null,
  };
}

export function deleteItem(items: VaultItemStore, accountId: string, id: string): Promise<boolean> {
  return items.remove(accountId, id);
}

export function setBookmark(items: VaultItemStore, accountId: string, id: string, bookmarked: boolean): Promise<boolean> {
  return items.setBookmark(accountId, id, bookmarked);
}

// ── Storage connections ────────────────────────────────────────────────────────
export interface PublicConnection {
  id: string;
  provider: string;
  encConfig: string; // client decrypts this locally
  label: string | null;
  createdAt: number;
}

export async function createConnection(
  conns: StorageConnectionStore,
  accountId: string,
  input: { provider?: string; encConfig?: string; label?: string },
): Promise<{ ok: true; id: string } | { ok: false; error: string }> {
  if (!input.provider || !ALLOWED_PROVIDERS.has(input.provider)) return { ok: false, error: 'invalid_provider' };
  if (!input.encConfig) return { ok: false, error: 'missing_fields' };
  const id = uuid();
  await conns.insert({
    id,
    account_id: accountId,
    provider: input.provider,
    enc_config: input.encConfig,
    label: input.label ?? null,
    created_at: Date.now(),
  });
  return { ok: true, id };
}

export async function listConnections(conns: StorageConnectionStore, accountId: string): Promise<PublicConnection[]> {
  const rows = await conns.listForAccount(accountId);
  return rows.map((r) => ({
    id: r.id,
    provider: r.provider,
    encConfig: r.enc_config,
    label: r.label,
    createdAt: r.created_at,
  }));
}

export function deleteConnection(conns: StorageConnectionStore, accountId: string, id: string): Promise<boolean> {
  return conns.remove(accountId, id);
}
