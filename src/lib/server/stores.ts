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
  FolderRow,
  FolderStore,
  StorageConnectionRow,
  StorageConnectionStore,
  TotpRow,
  TotpStore,
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
 *   - account_totp table + sessions.{user_agent,ip,last_seen}: ADD if missing (0003).
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
    if (!itemCols.some((c) => c.name === 'deleted_at')) {
      await db.prepare('ALTER TABLE vault_items ADD COLUMN deleted_at INTEGER').run(); // migration 0004
    }
    // migration 0005 — folders (names encrypted; membership lives in item metadata).
    await db
      .prepare(
        `CREATE TABLE IF NOT EXISTS folders (
           id TEXT PRIMARY KEY,
           account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
           enc_name TEXT NOT NULL, created_at INTEGER NOT NULL)`,
      )
      .run();
    // migration 0003 — 2FA table + session device metadata.
    await db
      .prepare(
        `CREATE TABLE IF NOT EXISTS account_totp (
           account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
           secret TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0,
           backup_codes TEXT, created_at INTEGER NOT NULL, confirmed_at INTEGER)`,
      )
      .run();
    const sessCols = (await db.prepare('PRAGMA table_info(sessions)').all<{ name: string }>()).results ?? [];
    for (const col of ['user_agent TEXT', 'ip TEXT', 'last_seen INTEGER']) {
      if (!sessCols.some((c) => c.name === col.split(' ')[0])) {
        await db.prepare(`ALTER TABLE sessions ADD COLUMN ${col}`).run();
      }
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
    await ensureSchema(this.db);
    await this.db
      .prepare(
        `INSERT INTO sessions (id, account_id, token_hash, created_at, expires_at, user_agent, ip, last_seen)
         VALUES (?,?,?,?,?,?,?,?)`,
      )
      .bind(s.id, s.account_id, s.token_hash, s.created_at, s.expires_at, s.user_agent ?? null, s.ip ?? null, s.last_seen ?? s.created_at)
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

  async listForAccount(accountId: string): Promise<SessionRow[]> {
    const now = Date.now();
    const res = await this.db
      .prepare('SELECT * FROM sessions WHERE account_id = ? AND expires_at > ? ORDER BY last_seen DESC, created_at DESC')
      .bind(accountId, now)
      .all<SessionRow>();
    return res.results ?? [];
  }

  async deleteByIdForAccount(accountId: string, id: string): Promise<boolean> {
    const res: any = await this.db
      .prepare('DELETE FROM sessions WHERE account_id = ? AND id = ?')
      .bind(accountId, id)
      .run();
    return (res?.meta?.changes ?? 0) > 0;
  }

  async deleteOthersForAccount(accountId: string, keepTokenHash: string): Promise<void> {
    await this.db
      .prepare('DELETE FROM sessions WHERE account_id = ? AND token_hash != ?')
      .bind(accountId, keepTokenHash)
      .run();
  }

  async touch(id: string, lastSeen: number): Promise<void> {
    await this.db.prepare('UPDATE sessions SET last_seen = ? WHERE id = ?').bind(lastSeen, id).run();
  }
}

export class D1TotpStore implements TotpStore {
  constructor(private db: D1Like) {}

  async get(accountId: string): Promise<TotpRow | null> {
    await ensureSchema(this.db);
    return this.db.prepare('SELECT * FROM account_totp WHERE account_id = ?').bind(accountId).first<TotpRow>();
  }

  async upsert(r: TotpRow): Promise<void> {
    await ensureSchema(this.db);
    await this.db
      .prepare(
        `INSERT INTO account_totp (account_id, secret, enabled, backup_codes, created_at, confirmed_at)
         VALUES (?,?,?,?,?,?)
         ON CONFLICT(account_id) DO UPDATE SET
           secret=excluded.secret, enabled=excluded.enabled, backup_codes=excluded.backup_codes,
           confirmed_at=excluded.confirmed_at`,
      )
      .bind(r.account_id, r.secret, r.enabled, r.backup_codes ?? null, r.created_at, r.confirmed_at ?? null)
      .run();
  }

  async delete(accountId: string): Promise<void> {
    await this.db.prepare('DELETE FROM account_totp WHERE account_id = ?').bind(accountId).run();
  }
}

export class D1VaultItemStore implements VaultItemStore {
  constructor(private db: D1Like) {}

  async countForAccount(accountId: string): Promise<number> {
    await ensureSchema(this.db);
    const row = await this.db
      .prepare('SELECT COUNT(*) AS n FROM vault_items WHERE account_id = ? AND deleted_at IS NULL')
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
    opts: { limit: number; bookmarked?: boolean; trashed?: boolean; cursor?: ItemCursor },
  ): Promise<VaultItemRow[]> {
    await ensureSchema(this.db); // page() filters on deleted_at (0004); make sure it exists
    const where: string[] = ['account_id = ?'];
    const binds: unknown[] = [accountId];
    where.push(opts.trashed ? 'deleted_at IS NOT NULL' : 'deleted_at IS NULL');
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

  async updateMetadata(accountId: string, id: string, encMetadata: string): Promise<boolean> {
    const res: any = await this.db
      .prepare('UPDATE vault_items SET enc_metadata = ?, updated_at = ? WHERE account_id = ? AND id = ?')
      .bind(encMetadata, Date.now(), accountId, id)
      .run();
    return (res?.meta?.changes ?? 0) > 0;
  }

  async setDeleted(accountId: string, id: string, deletedAt: number | null): Promise<boolean> {
    const res: any = await this.db
      .prepare('UPDATE vault_items SET deleted_at = ?, updated_at = ? WHERE account_id = ? AND id = ?')
      .bind(deletedAt, Date.now(), accountId, id)
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

export class D1FolderStore implements FolderStore {
  constructor(private db: D1Like) {}

  async listForAccount(accountId: string): Promise<FolderRow[]> {
    await ensureSchema(this.db);
    const res = await this.db
      .prepare('SELECT * FROM folders WHERE account_id = ? ORDER BY created_at ASC')
      .bind(accountId)
      .all<FolderRow>();
    return res.results ?? [];
  }

  async insert(r: FolderRow): Promise<void> {
    await ensureSchema(this.db);
    await this.db
      .prepare('INSERT INTO folders (id, account_id, enc_name, created_at) VALUES (?,?,?,?)')
      .bind(r.id, r.account_id, r.enc_name, r.created_at)
      .run();
  }

  async rename(accountId: string, id: string, encName: string): Promise<boolean> {
    const res: any = await this.db
      .prepare('UPDATE folders SET enc_name = ? WHERE account_id = ? AND id = ?')
      .bind(encName, accountId, id)
      .run();
    return (res?.meta?.changes ?? 0) > 0;
  }

  async remove(accountId: string, id: string): Promise<boolean> {
    const res: any = await this.db
      .prepare('DELETE FROM folders WHERE account_id = ? AND id = ?')
      .bind(accountId, id)
      .run();
    return (res?.meta?.changes ?? 0) > 0;
  }

  async deleteAllForAccount(accountId: string): Promise<void> {
    await this.db.prepare('DELETE FROM folders WHERE account_id = ?').bind(accountId).run();
  }
}
