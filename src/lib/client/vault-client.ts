/**
 * VaultClient — the browser-side orchestrator the UI calls. It owns the account
 * key (in memory only) and ties together: E2EE crypto, the user's S3 storage,
 * and the server's encrypted index. The server never receives plaintext, keys,
 * or storage credentials.
 *
 * Dependencies (apiFetch, makeStore) are injectable so the whole flow is
 * testable without a browser, a server, or a real bucket.
 */
import {
  createAccount,
  decryptDownloaded,
  deriveAuthKey,
  encryptForUpload,
  encryptThumbnail,
  normalizeRecoveryKey,
  prepareStreamingUpload,
  readMetadata,
  rewrapForNewPassword,
  unlockWithPassword,
  unlockWithRecovery,
  type FileMetadata,
  type KdfParams,
} from '../e2ee/account';
import { DEFAULT_CHUNK_SIZE, decryptJson, encryptJson, sha256Hex, unwrapKey, type FileHeader } from '../e2ee/crypto';
import { makeStore, type ObjectStore, type ProviderConfig } from '../storage/object-store';
import { ciphertextSize, fetchHeader } from './stream';

// Below this size, the simple (read-whole-file) path is used; at/above it we
// stream-encrypt + stream-upload so memory stays flat for large files.
const STREAM_THRESHOLD = 8 * 1024 * 1024;

type ApiFetch = (path: string, init?: RequestInit) => Promise<Response>;
type MakeStore = (config: ProviderConfig) => ObjectStore;

export interface VaultClientDeps {
  apiFetch?: ApiFetch;
  makeStore?: MakeStore;
}

export interface Connection {
  id: string;
  provider: string;
  label: string | null;
  config: ProviderConfig; // decrypted locally
}

export interface VaultItem {
  id: string;
  metadata: FileMetadata; // decrypted locally
  wrappedItemKey: string; // unwrapped locally at download time
  connectionId: string;
  objectKey: string;
  thumbKey: string | null;
  size: number;
  bookmarked: boolean;
  createdAt: number;
}

async function asJson(res: Response): Promise<any> {
  const text = await res.text();
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return {};
  }
}

export class VaultClient {
  private accountKey: Uint8Array | null = null;
  private api: ApiFetch;
  private store: MakeStore;

  constructor(deps: VaultClientDeps = {}) {
    this.api = deps.apiFetch ?? ((path, init) => fetch(path, { ...init, credentials: 'same-origin' }));
    this.store = deps.makeStore ?? ((config) => makeStore(config));
  }

  isUnlocked(): boolean {
    return this.accountKey !== null;
  }
  lock(): void {
    this.accountKey?.fill(0);
    this.accountKey = null;
  }

  /**
   * Export/restore the in-memory account key as base64 so the UI can optionally
   * keep the vault unlocked across reloads within a tab (sessionStorage). This
   * is an explicit, opt-in convenience — storing the key anywhere is a tradeoff,
   * so callers gate it behind a user choice and tab-scoped storage only.
   */
  exportSessionKey(): string | null {
    if (!this.accountKey) return null;
    let s = '';
    for (const b of this.accountKey) s += String.fromCharCode(b);
    return btoa(s);
  }
  restoreSessionKey(b64: string): boolean {
    try {
      const bin = atob(b64);
      const k = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) k[i] = bin.charCodeAt(i);
      if (k.length < 16) return false;
      this.accountKey = k;
      return true;
    } catch {
      return false;
    }
  }

  // ── Auth ──────────────────────────────────────────────────────────────────
  /** Create an account; returns the one-time recovery key to show the user. */
  async signup(email: string, password: string, kdfParams?: KdfParams): Promise<{ recoveryKey: string }> {
    const acct = await createAccount(password, kdfParams);
    const res = await this.api('/api/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, secrets: acct.secrets }),
    });
    if (!res.ok) throw new Error((await asJson(res)).error || 'signup_failed');
    this.accountKey = acct.accountKey;
    return { recoveryKey: acct.recoveryKey };
  }

  async login(email: string, password: string): Promise<void> {
    const pre = await asJson(await this.api('/api/auth/prelogin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    }));
    const authKeyB64 = await deriveAuthKey(password, pre.kdfSalt, pre.kdfParams);
    const res = await this.api('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, authKeyB64 }),
    });
    if (!res.ok) throw new Error((await asJson(res)).error || 'login_failed');
    const data = await asJson(res);
    const key = await unlockWithPassword(password, data.kdfSalt, data.kdfParams, data.wrappedAccountKey);
    if (!key) throw new Error('unlock_failed');
    this.accountKey = key;
  }

  async logout(): Promise<void> {
    await this.api('/api/auth/logout', { method: 'POST', headers: { Origin: '' } }).catch(() => {});
    this.lock();
  }

  /**
   * Forgot-password reset using the recovery key. Unlocks the account key with
   * the recovery key, re-wraps everything under the new password (minting a fresh
   * recovery key), and proves possession of the old recovery key to the server.
   * Leaves the vault unlocked and returns the NEW recovery key to show once.
   */
  async resetWithRecovery(
    email: string,
    recoveryKey: string,
    newPassword: string,
    kdfParams?: KdfParams,
  ): Promise<{ recoveryKey: string }> {
    const params = await asJson(
      await this.api('/api/auth/recovery-params', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      }),
    );
    const accountKey = await unlockWithRecovery(recoveryKey, params.recoverySalt, params.wrappedAccountKeyRecovery);
    if (!accountKey) throw new Error('invalid_recovery_key');

    const { secrets, recoveryKey: newRecoveryKey } = await rewrapForNewPassword(accountKey, newPassword, kdfParams);
    const proof = await sha256Hex(new TextEncoder().encode(normalizeRecoveryKey(recoveryKey)));
    const res = await this.api('/api/auth/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, recoveryKeyHash: proof, secrets }),
    });
    if (!res.ok) throw new Error((await asJson(res)).error || 'reset_failed');
    this.accountKey = accountKey; // now unlocked under the new password
    return { recoveryKey: newRecoveryKey };
  }

  /**
   * Change password while unlocked. Proves the current password to the server,
   * re-wraps under the new password (minting a fresh recovery key), and returns
   * that new recovery key to show once.
   */
  async changePassword(
    email: string,
    currentPassword: string,
    newPassword: string,
    kdfParams?: KdfParams,
  ): Promise<{ recoveryKey: string }> {
    this.requireKey();
    const pre = await asJson(
      await this.api('/api/auth/prelogin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      }),
    );
    const currentAuthKeyB64 = await deriveAuthKey(currentPassword, pre.kdfSalt, pre.kdfParams);
    const { secrets, recoveryKey: newRecoveryKey } = await rewrapForNewPassword(this.accountKey!, newPassword, kdfParams);
    const res = await this.api('/api/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentAuthKeyB64, secrets }),
    });
    if (!res.ok) throw new Error((await asJson(res)).error || 'change_password_failed');
    return { recoveryKey: newRecoveryKey };
  }

  async getProfile(): Promise<{ email: string; createdAt: number; itemCount: number; connectionCount: number }> {
    const res = await this.api('/api/account');
    if (!res.ok) throw new Error('profile_failed');
    return asJson(res);
  }

  /**
   * Permanently delete the account and everything the server holds for it. Files
   * in the user's own storage are NOT touched — only the encrypted index, the
   * storage connections, and the sessions are removed.
   */
  async deleteAccount(): Promise<void> {
    this.requireKey();
    const res = await this.api('/api/account', { method: 'DELETE' });
    if (!res.ok) throw new Error((await asJson(res)).error || 'delete_account_failed');
    this.lock();
  }

  // ── Storage connections ─────────────────────────────────────────────────────
  async addConnection(config: ProviderConfig, label?: string): Promise<{ id: string }> {
    this.requireKey();
    const test = await this.store(config).test();
    if (!test.ok) throw new Error(test.error || 'connection_test_failed');

    const encConfig = await encryptJson(config, this.accountKey!);
    const res = await this.api('/api/vault/connections', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: config.kind, encConfig, label }),
    });
    if (!res.ok) throw new Error((await asJson(res)).error || 'add_connection_failed');
    return { id: (await asJson(res)).id };
  }

  async getConnections(): Promise<Connection[]> {
    this.requireKey();
    const data = await asJson(await this.api('/api/vault/connections'));
    const out: Connection[] = [];
    for (const c of data.connections ?? []) {
      const cfg = await decryptJson<ProviderConfig>(c.encConfig, this.accountKey!);
      out.push({ id: c.id, provider: c.provider, label: c.label, config: cfg });
    }
    return out;
  }

  // ── Files ─────────────────────────────────────────────────────────────────
  async upload(
    conn: Connection,
    file: { bytes: Uint8Array; name: string; mime: string; thumbnail?: Uint8Array | null },
    onProgress?: (loaded: number, total: number) => void,
  ): Promise<{ id: string }> {
    this.requireKey();
    const meta: FileMetadata = { name: file.name, mime: file.mime, size: file.bytes.length };
    const enc = await encryptForUpload(file.bytes, meta, this.accountKey!, file.thumbnail ?? undefined);
    const base = `mv/${globalThis.crypto.randomUUID()}`;
    const store = this.store(conn.config);

    // put() returns the canonical key/id to persist (S3: our key, Drive: file id).
    const objectKey = await store.put(`${base}.enc`, enc.ciphertext, undefined, onProgress);

    let thumbKey: string | null = null;
    if (enc.encThumbnail) {
      try {
        thumbKey = await store.put(`${base}.thumb.enc`, enc.encThumbnail);
      } catch {
        thumbKey = null; // a thumbnail is optional — never fail the upload over it
      }
    }

    const res = await this.api('/api/vault/items', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        encMetadata: enc.encMetadata,
        wrappedItemKey: enc.wrappedFileKey,
        connectionId: conn.id,
        objectKey,
        thumbKey,
        size: enc.ciphertext.length,
      }),
    });
    if (!res.ok) {
      // best-effort: don't leave orphan objects if the index write failed
      await store.del(objectKey).catch(() => {});
      if (thumbKey) await store.del(thumbKey).catch(() => {});
      throw new Error((await asJson(res)).error || 'index_write_failed');
    }
    return { id: (await asJson(res)).id };
  }

  /**
   * Upload a File. Large files are STREAM-encrypted and STREAM-uploaded (the file
   * is read slice-by-slice and each encrypted chunk is pushed to a resumable
   * provider upload), so memory stays flat regardless of file size. Small files
   * (or providers without a streaming writer) fall back to the simple buffered
   * path. Same E2EE + same MV1 format → downloads/seeking are unaffected.
   */
  async uploadFile(
    conn: Connection,
    file: { file: File; name: string; mime: string; thumbnail?: Uint8Array | null },
    onProgress?: (loaded: number, total: number) => void,
  ): Promise<{ id: string }> {
    this.requireKey();
    const store = this.store(conn.config);

    if (file.file.size < STREAM_THRESHOLD || !store.createWriter) {
      const bytes = new Uint8Array(await file.file.arrayBuffer());
      return this.upload(conn, { bytes, name: file.name, mime: file.mime, thumbnail: file.thumbnail }, onProgress);
    }

    const meta: FileMetadata = { name: file.name, mime: file.mime, size: file.file.size };
    const prep = await prepareStreamingUpload(file.file, meta, this.accountKey!);
    const base = `mv/${globalThis.crypto.randomUUID()}`;
    const objectKey = `${base}.enc`;
    const total = ciphertextSize(file.file.size, DEFAULT_CHUNK_SIZE);

    const writer = store.createWriter(objectKey);
    let written = 0;
    try {
      for await (const piece of prep.stream) {
        await writer.write(piece);
        written += piece.length;
        onProgress?.(written, total);
      }
      await writer.close();
    } catch (e) {
      await writer.abort().catch(() => {});
      await store.del(objectKey).catch(() => {});
      throw e;
    }

    let thumbKey: string | null = null;
    if (file.thumbnail) {
      try {
        thumbKey = await store.put(`${base}.thumb.enc`, await encryptThumbnail(file.thumbnail, prep.fileKey));
      } catch {
        thumbKey = null; // optional
      }
    }

    const res = await this.api('/api/vault/items', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        encMetadata: prep.encMetadata,
        wrappedItemKey: prep.wrappedFileKey,
        connectionId: conn.id,
        objectKey,
        thumbKey,
        size: total,
      }),
    });
    if (!res.ok) {
      await store.del(objectKey).catch(() => {});
      if (thumbKey) await store.del(thumbKey).catch(() => {});
      throw new Error((await asJson(res)).error || 'index_write_failed');
    }
    return { id: (await asJson(res)).id };
  }

  /** One page of the library, with decrypted metadata. */
  async listPage(opts: { cursor?: string | null; bookmarked?: boolean; limit?: number } = {}): Promise<{
    items: VaultItem[];
    nextCursor: string | null;
  }> {
    this.requireKey();
    const q = new URLSearchParams();
    if (opts.cursor) q.set('cursor', opts.cursor);
    if (opts.bookmarked) q.set('bookmarked', '1');
    if (opts.limit) q.set('limit', String(opts.limit));
    const data = await asJson(await this.api(`/api/vault/items?${q.toString()}`));

    const items: VaultItem[] = [];
    for (const raw of data.items ?? []) {
      let metadata: FileMetadata;
      try {
        metadata = await readMetadata(raw.encMetadata, this.accountKey!);
      } catch {
        metadata = { name: '(unreadable)', mime: 'application/octet-stream', size: raw.size };
      }
      items.push({
        id: raw.id,
        metadata,
        wrappedItemKey: raw.wrappedItemKey,
        connectionId: raw.connectionId,
        objectKey: raw.objectKey,
        thumbKey: raw.thumbKey ?? null,
        size: raw.size,
        bookmarked: raw.bookmarked,
        createdAt: raw.createdAt,
      });
    }
    return { items, nextCursor: data.nextCursor ?? null };
  }

  async download(item: VaultItem, conn: Connection): Promise<{ bytes: Uint8Array; metadata: FileMetadata }> {
    const bytes = await this.fetchDecrypt(conn, item.objectKey, item.wrappedItemKey);
    return { bytes, metadata: item.metadata };
  }

  /** Fetch + decrypt the encrypted thumbnail, or null if the item has none. */
  async getThumbnail(item: VaultItem, conn: Connection): Promise<Uint8Array | null> {
    if (!item.thumbKey) return null;
    try {
      return await this.fetchDecrypt(conn, item.thumbKey, item.wrappedItemKey);
    } catch {
      return null;
    }
  }

  private async fetchDecrypt(conn: Connection, objectKey: string, wrappedItemKey: string): Promise<Uint8Array> {
    this.requireKey();
    const res = await this.store(conn.config).get(objectKey);
    const ciphertext = new Uint8Array(await res.arrayBuffer());
    return decryptDownloaded(ciphertext, wrappedItemKey, this.accountKey!);
  }

  /**
   * Everything the streaming Service Worker needs to serve seekable, decrypted
   * media for one item. The file key is unwrapped here (in the page) and handed
   * to the SW in memory — it is never persisted or sent to the server.
   */
  async getStreamParams(item: VaultItem, conn: Connection): Promise<{
    objectKey: string;
    config: ProviderConfig;
    fileKey: Uint8Array;
    header: FileHeader;
    plaintextSize: number;
    mime: string;
  }> {
    this.requireKey();
    const fileKey = await unwrapKey(item.wrappedItemKey, this.accountKey!);
    if (!fileKey) throw new Error('Cannot unwrap file key');
    const header = await fetchHeader(this.store(conn.config), item.objectKey);
    return {
      objectKey: item.objectKey,
      config: conn.config,
      fileKey,
      header,
      plaintextSize: item.metadata.size,
      mime: item.metadata.mime,
    };
  }

  async remove(item: VaultItem, conn: Connection): Promise<void> {
    this.requireKey();
    const store = this.store(conn.config);
    await store.del(item.objectKey).catch(() => {}); // remove bytes from the user's bucket
    if (item.thumbKey) await store.del(item.thumbKey).catch(() => {}); // and its thumbnail
    const res = await this.api(`/api/vault/items/${item.id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('delete_failed');
  }

  async setBookmark(item: VaultItem, bookmarked: boolean): Promise<void> {
    this.requireKey();
    const res = await this.api(`/api/vault/items/${item.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bookmarked }),
    });
    if (!res.ok) throw new Error('bookmark_failed');
  }

  private requireKey(): void {
    if (!this.accountKey) throw new Error('vault_locked');
  }
}
