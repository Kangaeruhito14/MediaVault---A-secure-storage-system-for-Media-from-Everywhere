/**
 * VaultClient — the browser-side orchestrator the UI calls. It owns the account
 * key (in memory only) and ties together: E2EE crypto, the user's S3 storage,
 * and the server's encrypted index. The server never receives plaintext, keys,
 * or storage credentials.
 *
 * Dependencies (apiFetch, makeS3) are injectable so the whole flow is testable
 * without a browser, a server, or a real bucket.
 */
import {
  createAccount,
  decryptDownloaded,
  deriveAuthKey,
  encryptForUpload,
  readMetadata,
  unlockWithPassword,
  type FileMetadata,
  type KdfParams,
} from '../e2ee/account';
import { decryptJson, encryptJson } from '../e2ee/crypto';
import { S3Client, type S3Config } from '../storage/s3';

type ApiFetch = (path: string, init?: RequestInit) => Promise<Response>;
type MakeS3 = (cfg: S3Config) => Pick<S3Client, 'put' | 'get' | 'del' | 'testConnection'>;

export interface VaultClientDeps {
  apiFetch?: ApiFetch;
  makeS3?: MakeS3;
}

export interface Connection {
  id: string;
  provider: string;
  label: string | null;
  config: S3Config; // decrypted locally
}

export interface VaultItem {
  id: string;
  metadata: FileMetadata; // decrypted locally
  wrappedItemKey: string; // unwrapped locally at download time
  connectionId: string;
  objectKey: string;
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
  private makeS3: MakeS3;

  constructor(deps: VaultClientDeps = {}) {
    this.api = deps.apiFetch ?? ((path, init) => fetch(path, { ...init, credentials: 'same-origin' }));
    this.makeS3 = deps.makeS3 ?? ((cfg) => new S3Client(cfg));
  }

  isUnlocked(): boolean {
    return this.accountKey !== null;
  }
  lock(): void {
    this.accountKey?.fill(0);
    this.accountKey = null;
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

  // ── Storage connections ─────────────────────────────────────────────────────
  async addConnection(config: S3Config, label?: string): Promise<{ id: string }> {
    this.requireKey();
    const probe = this.makeS3(config);
    const test = await probe.testConnection();
    if (!test.ok) throw new Error(test.error || 'connection_test_failed');

    const encConfig = await encryptJson({ kind: 's3', ...config }, this.accountKey!);
    const res = await this.api('/api/vault/connections', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 's3', encConfig, label }),
    });
    if (!res.ok) throw new Error((await asJson(res)).error || 'add_connection_failed');
    return { id: (await asJson(res)).id };
  }

  async getConnections(): Promise<Connection[]> {
    this.requireKey();
    const data = await asJson(await this.api('/api/vault/connections'));
    const out: Connection[] = [];
    for (const c of data.connections ?? []) {
      const cfg = await decryptJson<{ kind: string } & S3Config>(c.encConfig, this.accountKey!);
      out.push({ id: c.id, provider: c.provider, label: c.label, config: cfg });
    }
    return out;
  }

  // ── Files ─────────────────────────────────────────────────────────────────
  async upload(
    conn: Connection,
    file: { bytes: Uint8Array; name: string; mime: string },
  ): Promise<{ id: string }> {
    this.requireKey();
    const meta: FileMetadata = { name: file.name, mime: file.mime, size: file.bytes.length };
    const enc = await encryptForUpload(file.bytes, meta, this.accountKey!);
    const objectKey = `mv/${globalThis.crypto.randomUUID()}.enc`;

    await this.makeS3(conn.config).put(objectKey, enc.ciphertext);

    const res = await this.api('/api/vault/items', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        encMetadata: enc.encMetadata,
        wrappedItemKey: enc.wrappedFileKey,
        connectionId: conn.id,
        objectKey,
        size: enc.ciphertext.length,
      }),
    });
    if (!res.ok) {
      // best-effort: don't leave an orphan object if the index write failed
      await this.makeS3(conn.config).del(objectKey).catch(() => {});
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
        size: raw.size,
        bookmarked: raw.bookmarked,
        createdAt: raw.createdAt,
      });
    }
    return { items, nextCursor: data.nextCursor ?? null };
  }

  async download(item: VaultItem, conn: Connection): Promise<{ bytes: Uint8Array; metadata: FileMetadata }> {
    this.requireKey();
    const res = await this.makeS3(conn.config).get(item.objectKey);
    const ciphertext = new Uint8Array(await res.arrayBuffer());
    const bytes = await decryptDownloaded(ciphertext, item.wrappedItemKey, this.accountKey!);
    return { bytes, metadata: item.metadata };
  }

  async remove(item: VaultItem, conn: Connection): Promise<void> {
    this.requireKey();
    await this.makeS3(conn.config).del(item.objectKey).catch(() => {}); // remove bytes from user's bucket
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
