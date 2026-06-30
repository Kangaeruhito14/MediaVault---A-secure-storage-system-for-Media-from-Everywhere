/**
 * Account-level operations: full data export and account deletion.
 *
 * Everything the server holds for an account is encrypted, so an export is a
 * complete, portable, ENCRYPTED backup (useless without the user's password).
 * Deletion removes the account's index, storage connections, and sessions. The
 * user's actual files live in their OWN storage and are never touched here — we
 * have no key to read them and no business deleting someone's bucket.
 */
import type {
  AccountStore,
  SessionStore,
  StorageConnectionStore,
  TotpStore,
  VaultItemStore,
} from './types';

export interface AccountExport {
  exportedAt: number;
  account: { id: string; email: string; createdAt: number };
  crypto: {
    kdf: string;
    kdfSalt: string;
    kdfParams: string;
    wrappedAccountKey: string;
    wrappedAccountKeyRecovery: string;
  };
  connections: { id: string; provider: string; label: string | null; encConfig: string; createdAt: number }[];
  items: {
    id: string;
    encMetadata: string;
    wrappedItemKey: string;
    connectionId: string;
    objectKey: string;
    thumbKey: string | null;
    size: number;
    bookmarked: boolean;
    createdAt: number;
  }[];
}

export interface AccountProfile {
  email: string;
  createdAt: number;
  itemCount: number;
  connectionCount: number;
}

export async function getProfile(ctx: ExportCtx, accountId: string): Promise<AccountProfile | null> {
  const a = await ctx.accounts.getById(accountId);
  if (!a) return null;
  const [itemCount, conns] = await Promise.all([
    ctx.items.countForAccount(accountId),
    ctx.connections.listForAccount(accountId),
  ]);
  return { email: a.email, createdAt: a.created_at, itemCount, connectionCount: conns.length };
}

interface ExportCtx {
  accounts: AccountStore;
  connections: StorageConnectionStore;
  items: VaultItemStore;
}

export async function exportAccount(ctx: ExportCtx, accountId: string): Promise<AccountExport | null> {
  const a = await ctx.accounts.getById(accountId);
  if (!a) return null;
  const [conns, items] = await Promise.all([
    ctx.connections.listForAccount(accountId),
    ctx.items.allForAccount(accountId),
  ]);
  return {
    exportedAt: Date.now(),
    account: { id: a.id, email: a.email, createdAt: a.created_at },
    crypto: {
      kdf: a.kdf,
      kdfSalt: a.kdf_salt,
      kdfParams: a.kdf_params,
      wrappedAccountKey: a.wrapped_account_key,
      wrappedAccountKeyRecovery: a.wrapped_account_key_recovery,
    },
    connections: conns.map((c) => ({
      id: c.id,
      provider: c.provider,
      label: c.label,
      encConfig: c.enc_config,
      createdAt: c.created_at,
    })),
    items: items.map((r) => ({
      id: r.id,
      encMetadata: r.enc_metadata,
      wrappedItemKey: r.wrapped_item_key,
      connectionId: r.connection_id,
      objectKey: r.object_key,
      thumbKey: r.thumb_key,
      size: r.size,
      bookmarked: r.bookmarked === 1,
      createdAt: r.created_at,
    })),
  };
}

interface DeleteCtx {
  accounts: AccountStore;
  connections: StorageConnectionStore;
  items: VaultItemStore;
  sessions: SessionStore;
  totp: TotpStore;
}

/**
 * Delete an account and everything the server holds for it. Dependent rows are
 * removed explicitly (not relying on SQLite FK cascade, which is off unless
 * `PRAGMA foreign_keys=ON`), so this is correct regardless of D1 settings.
 */
export async function deleteAccount(ctx: DeleteCtx, accountId: string): Promise<boolean> {
  const a = await ctx.accounts.getById(accountId);
  if (!a) return false;
  await ctx.items.deleteAllForAccount(accountId);
  await ctx.connections.deleteAllForAccount(accountId);
  await ctx.sessions.deleteAllForAccount(accountId);
  await ctx.totp.delete(accountId);
  await ctx.accounts.deleteById(accountId);
  return true;
}
