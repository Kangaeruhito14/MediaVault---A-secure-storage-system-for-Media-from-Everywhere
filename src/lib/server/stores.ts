/**
 * D1-backed implementations of the store interfaces. Deliberately thin: just
 * the SQL. All correctness logic lives in auth-service.ts and is unit-tested
 * against in-memory fakes; these get validated under local wrangler dev.
 */
import type {
  AccountRow,
  AccountStore,
  D1Like,
  ItemCursor,
  SessionRow,
  SessionStore,
  StorageConnectionRow,
  StorageConnectionStore,
  VaultItemRow,
  VaultItemStore,
} from './types';

/**
 * Idempotent schema self-heal. D1 migrations are applied via wrangler on deploy,
 * but local miniflare dev and older databases drift from the current schema.
 * This reconciles the known drifts once per worker instance (shared promise so
 * concurrent cold-start requests don't race the ALTERs):
 *   - accounts.recovery_salt: ADD if missing (migration 0002).
 *   - vault_items.iv: DROP if present — an older schema had `iv NOT NULL`, which
 *     makes every current insert (no `iv`) fail with a NOT NULL constraint.
 */
let schemaEnsure: Promise<void> | null = null;
async function ensureSchema(db: D1Like): Promise<void> {
  if (schemaEnsure) return schemaEnsure;
  schemaEnsure = (async () => {
    const accCols = (await db.prepare('PRAGMA table_info(accounts)').all<{ name: string }>()).results ?? [];
    if (!accCols.some((c) => c.name === 'recovery_salt')) {
      await db.prepare('ALTER TABLE accounts ADD COLUMN recovery_salt TEXT').run();
    }
    const itemCols = (await db.prepare('PRAGMA table_info(vault_items)').all<{ name: string }>()).results ?? [];
    if (itemCols.some((c) => c.name === 'iv')) {
      await db.prepare('ALTER TABLE vault_items DROP COLUMN iv').run();
    }
  })().catch((e) => {
    schemaEnsure = null; // allow a retry on a later request
    throw e;
  });
  return schemaEnsure;
}

export class D1AccountStore implements AccountStore {
  constructor(private db: D1Like) {}

  getByEmail(email: string): Promise<AccountRow | null> {
    return this.db.prepare('SELECT * FROM accounts WHERE email = ?').bind(email).first<AccountRow>();
  }

  getById(id: string): Promise<AccountRow | null> {
    return this.db.prepare('SELECT * FROM accounts WHERE id = ?').bind(id).first<AccountRow>();
  }

  async deleteById(id: string): Promise<void> {
    await this.db.prepare('DELETE FROM accounts WHERE id = ?').bind(id).run();
  }

  async insert(r: AccountRow): Promise<void> {
    await ensureSchema(this.db);
    await this.db
      .prepare(
        `INSERT INTO accounts
         (id, email, email_verified, kdf, kdf_salt, kdf_params, login_hash,
          wrapped_account_key, wrapped_account_key_recovery, recovery_key_hash, recovery_salt, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      )
      .bind(
        r.id, r.email, r.email_verified, r.kdf, r.kdf_salt, r.kdf_params, r.login_hash,
        r.wrapped_account_key, r.wrapped_account_key_recovery, r.recovery_key_hash, r.recovery_salt ?? null,
        r.created_at, r.updated_at,
      )
      .run();
  }

  async updateSecrets(id: string, f: Parameters<AccountStore['updateSecrets']>[1]): Promise<void> {
    await ensureSchema(this.db);
    await this.db
      .prepare(
        `UPDATE accounts SET kdf_salt=?, kdf_params=?, login_hash=?, wrapped_account_key=?,
         wrapped_account_key_recovery=?, recovery_key_hash=?, recovery_salt=?, updated_at=? WHERE id=?`,
      )
      .bind(
        f.kdf_salt, f.kdf_params, f.login_hash, f.wrapped_account_key,
        f.wrapped_account_key_recovery, f.recovery_key_hash, f.recovery_salt ?? null, f.updated_at, id,
      )
      .run();
  }
}

export class D1SessionStore implements SessionStore {
  constructor(private db: D1Like) {}

  async insert(s: SessionRow): Promise<void> {
    await this.db
      .prepare('INSERT INTO sessions (id, account_id, token_hash, created_at, expires_at) VALUES (?,?,?,?,?)')
      .bind(s.id, s.account_id, s.token_hash, s.created_at, s.expires_at)
      .run();
  }

  getByTokenHash(tokenHash: string): Promise<SessionRow | null> {
    return this.db.prepare('SELECT * FROM sessions WHERE token_hash = ?').bind(tokenHash).first<SessionRow>();
  }

  async deleteByTokenHash(tokenHash: string): Promise<void> {
    await this.db.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run();
  }

  async deleteAllForAccount(accountId: string): Promise<void> {
    await this.db.prepare('DELETE FROM sessions WHERE account_id = ?').bind(accountId).run();
  }
}

export class D1VaultItemStore implements VaultItemStore {
  constructor(private db: D1Like) {}

  async countForAccount(accountId: string): Promise<number> {
    const row = await this.db
      .prepare('SELECT COUNT(*) AS n FROM vault_items WHERE account_id = ?')
      .bind(accountId)
      .first<{ n: number }>();
    return row?.n ?? 0;
  }

  async insert(r: VaultItemRow): Promise<void> {
    await ensureSchema(this.db);
    await this.db
      .prepare(
        `INSERT INTO vault_items
         (id, account_id, enc_metadata, wrapped_item_key, connection_id, object_key, thumb_key, size, bookmarked, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      )
      .bind(
        r.id, r.account_id, r.enc_metadata, r.wrapped_item_key, r.connection_id,
        r.object_key, r.thumb_key, r.size, r.bookmarked, r.created_at, r.updated_at,
      )
      .run();
  }

  // Keyset pagination on (created_at DESC, id DESC) — stable and fast even at
  // a million rows (no large OFFSET scans).
  async page(
    accountId: string,
    opts: { limit: number; bookmarked?: boolean; cursor?: ItemCursor },
  ): Promise<VaultItemRow[]> {
    const where: string[] = ['account_id = ?'];
    const binds: unknown[] = [accountId];
    if (opts.bookmarked) where.push('bookmarked = 1');
    if (opts.cursor) {
      where.push('(created_at < ? OR (created_at = ? AND id < ?))');
      binds.push(opts.cursor.createdAt, opts.cursor.createdAt, opts.cursor.id);
    }
    binds.push(opts.limit);
    const res = await this.db
      .prepare(
        `SELECT * FROM vault_items WHERE ${where.join(' AND ')}
         ORDER BY created_at DESC, id DESC LIMIT ?`,
      )
      .bind(...binds)
      .all<VaultItemRow>();
    return res.results ?? [];
  }

  async allForAccount(accountId: string): Promise<VaultItemRow[]> {
    const res = await this.db
      .prepare('SELECT * FROM vault_items WHERE account_id = ? ORDER BY created_at ASC, id ASC')
      .bind(accountId)
      .all<VaultItemRow>();
    return res.results ?? [];
  }

  getById(accountId: string, id: string): Promise<VaultItemRow | null> {
    return this.db
      .prepare('SELECT * FROM vault_items WHERE account_id = ? AND id = ?')
      .bind(accountId, id)
      .first<VaultItemRow>();
  }

  async setBookmark(accountId: string, id: string, bookmarked: boolean): Promise<boolean> {
    const res: any = await this.db
      .prepare('UPDATE vault_items SET bookmarked = ?, updated_at = ? WHERE account_id = ? AND id = ?')
      .bind(bookmarked ? 1 : 0, Date.now(), accountId, id)
      .run();
    return (res?.meta?.changes ?? 0) > 0;
  }

  async remove(accountId: string, id: string): Promise<boolean> {
    const res: any = await this.db
      .prepare('DELETE FROM vault_items WHERE account_id = ? AND id = ?')
      .bind(accountId, id)
      .run();
    return (res?.meta?.changes ?? 0) > 0;
  }

  async deleteAllForAccount(accountId: string): Promise<void> {
    await this.db.prepare('DELETE FROM vault_items WHERE account_id = ?').bind(accountId).run();
  }
}

export class D1StorageConnectionStore implements StorageConnectionStore {
  constructor(private db: D1Like) {}

  async listForAccount(accountId: string): Promise<StorageConnectionRow[]> {
    const res = await this.db
      .prepare('SELECT * FROM storage_connections WHERE account_id = ? ORDER BY created_at DESC')
      .bind(accountId)
      .all<StorageConnectionRow>();
    return res.results ?? [];
  }

  async insert(r: StorageConnectionRow): Promise<void> {
    await this.db
      .prepare('INSERT INTO storage_connections (id, account_id, provider, enc_config, label, created_at) VALUES (?,?,?,?,?,?)')
      .bind(r.id, r.account_id, r.provider, r.enc_config, r.label, r.created_at)
      .run();
  }

  async remove(accountId: string, id: string): Promise<boolean> {
    const res: any = await this.db
      .prepare('DELETE FROM storage_connections WHERE account_id = ? AND id = ?')
      .bind(accountId, id)
      .run();
    return (res?.meta?.changes ?? 0) > 0;
  }

  async deleteAllForAccount(accountId: string): Promise<void> {
    await this.db.prepare('DELETE FROM storage_connections WHERE account_id = ?').bind(accountId).run();
  }
}
