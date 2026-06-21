/**
 * Server-side data contracts. Auth logic depends on these interfaces, not on
 * Cloudflare directly — so it is unit-testable with in-memory fakes and the
 * real D1/KV implementations stay thin. The server only ever handles opaque,
 * encrypted blobs; it can never derive an account key or read a file.
 */
import type { KdfParams } from '../e2ee/params';

export interface AccountRow {
  id: string;
  email: string;
  email_verified: number;
  kdf: string;
  kdf_salt: string;
  kdf_params: string; // JSON-encoded KdfParams
  login_hash: string; // server-side hash of the client-sent auth key
  wrapped_account_key: string;
  wrapped_account_key_recovery: string;
  recovery_key_hash: string;
  recovery_salt?: string | null; // KDF salt for the recovery-key unlock (added in 0002)
  created_at: number;
  updated_at: number;
}

export interface SessionRow {
  id: string;
  account_id: string;
  token_hash: string;
  created_at: number;
  expires_at: number;
}

/** Secrets the client produces at signup; the server stores them verbatim. */
export interface SignupSecrets {
  kdfSalt: string;
  kdfParams: KdfParams;
  recoverySalt: string;
  authKeyB64: string;
  wrappedAccountKey: string;
  wrappedAccountKeyRecovery: string;
  recoveryKeyHash: string;
}

export interface AccountStore {
  getByEmail(email: string): Promise<AccountRow | null>;
  getById(id: string): Promise<AccountRow | null>;
  insert(row: AccountRow): Promise<void>;
  deleteById(id: string): Promise<void>;
  updateSecrets(
    id: string,
    fields: Pick<
      AccountRow,
      'kdf_salt' | 'kdf_params' | 'login_hash' | 'wrapped_account_key' | 'wrapped_account_key_recovery' | 'recovery_key_hash' | 'recovery_salt' | 'updated_at'
    >,
  ): Promise<void>;
}

export interface SessionStore {
  insert(row: SessionRow): Promise<void>;
  getByTokenHash(tokenHash: string): Promise<SessionRow | null>;
  deleteByTokenHash(tokenHash: string): Promise<void>;
  deleteAllForAccount(accountId: string): Promise<void>;
}

// ── Encrypted file index ───────────────────────────────────────────────────────
export interface VaultItemRow {
  id: string;
  account_id: string;
  enc_metadata: string;     // encrypted JSON {name, mime, size, ...}
  wrapped_item_key: string; // per-file key wrapped by the account key (carries its own IV)
  connection_id: string;
  object_key: string;       // key in the USER's bucket
  thumb_key: string | null;
  size: number;             // ciphertext size (not sensitive)
  bookmarked: number;
  created_at: number;
  updated_at: number;
}

/** A keyset page cursor: items strictly older than (created_at, id). */
export interface ItemCursor {
  createdAt: number;
  id: string;
}

export interface VaultItemStore {
  countForAccount(accountId: string): Promise<number>;
  insert(row: VaultItemRow): Promise<void>;
  /** Newest-first page; optional bookmarked-only; keyset paginated. */
  page(accountId: string, opts: { limit: number; bookmarked?: boolean; cursor?: ItemCursor }): Promise<VaultItemRow[]>;
  /** Every row for an account, oldest-first — used for data export. */
  allForAccount(accountId: string): Promise<VaultItemRow[]>;
  getById(accountId: string, id: string): Promise<VaultItemRow | null>;
  setBookmark(accountId: string, id: string, bookmarked: boolean): Promise<boolean>;
  remove(accountId: string, id: string): Promise<boolean>;
  deleteAllForAccount(accountId: string): Promise<void>;
}

export interface StorageConnectionRow {
  id: string;
  account_id: string;
  provider: string;
  enc_config: string;       // encrypted creds/tokens (server can't read)
  label: string | null;
  created_at: number;
}

export interface StorageConnectionStore {
  listForAccount(accountId: string): Promise<StorageConnectionRow[]>;
  insert(row: StorageConnectionRow): Promise<void>;
  remove(accountId: string, id: string): Promise<boolean>;
  deleteAllForAccount(accountId: string): Promise<void>;
}

/** Minimal Cloudflare KV surface used for rate limiting. */
export interface KVLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

/** Minimal Cloudflare D1 surface used by the real stores. */
export interface D1Like {
  prepare(query: string): D1Stmt;
}
export interface D1Stmt {
  bind(...values: unknown[]): D1Stmt;
  first<T = unknown>(): Promise<T | null>;
  run(): Promise<unknown>;
  all<T = unknown>(): Promise<{ results: T[] }>;
}
