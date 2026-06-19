/**
 * D1-backed implementations of the store interfaces. Deliberately thin: just
 * the SQL. All correctness logic lives in auth-service.ts and is unit-tested
 * against in-memory fakes; these get validated under local wrangler dev.
 */
import type { AccountRow, AccountStore, D1Like, SessionRow, SessionStore } from './types';

export class D1AccountStore implements AccountStore {
  constructor(private db: D1Like) {}

  getByEmail(email: string): Promise<AccountRow | null> {
    return this.db.prepare('SELECT * FROM accounts WHERE email = ?').bind(email).first<AccountRow>();
  }

  getById(id: string): Promise<AccountRow | null> {
    return this.db.prepare('SELECT * FROM accounts WHERE id = ?').bind(id).first<AccountRow>();
  }

  async insert(r: AccountRow): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO accounts
         (id, email, email_verified, kdf, kdf_salt, kdf_params, login_hash,
          wrapped_account_key, wrapped_account_key_recovery, recovery_key_hash, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      )
      .bind(
        r.id, r.email, r.email_verified, r.kdf, r.kdf_salt, r.kdf_params, r.login_hash,
        r.wrapped_account_key, r.wrapped_account_key_recovery, r.recovery_key_hash, r.created_at, r.updated_at,
      )
      .run();
  }

  async updateSecrets(id: string, f: Parameters<AccountStore['updateSecrets']>[1]): Promise<void> {
    await this.db
      .prepare(
        `UPDATE accounts SET kdf_salt=?, kdf_params=?, login_hash=?, wrapped_account_key=?,
         wrapped_account_key_recovery=?, recovery_key_hash=?, updated_at=? WHERE id=?`,
      )
      .bind(
        f.kdf_salt, f.kdf_params, f.login_hash, f.wrapped_account_key,
        f.wrapped_account_key_recovery, f.recovery_key_hash, f.updated_at, id,
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
