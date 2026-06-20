-- MediaVault D1 schema — v3 multi-user, end-to-end encrypted.
-- Everything user-identifying about files is stored ENCRYPTED (opaque blobs).
-- The operator cannot read media, keys, or storage credentials from this DB.

-- ── Accounts ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS accounts (
  id                            TEXT PRIMARY KEY,           -- uuid
  email                         TEXT NOT NULL UNIQUE,
  email_verified                INTEGER NOT NULL DEFAULT 0,
  kdf                           TEXT NOT NULL DEFAULT 'argon2id',
  kdf_salt                      TEXT NOT NULL,              -- client KDF salt (hex)
  kdf_params                    TEXT NOT NULL,              -- JSON: {m,t,p}
  -- Server stores a hash OF the client-sent login hash (defense in depth).
  login_hash                    TEXT NOT NULL,
  -- Account key wrapped two ways; server can never unwrap either.
  wrapped_account_key           TEXT NOT NULL,             -- wrapped by password key
  wrapped_account_key_recovery  TEXT NOT NULL,             -- wrapped by recovery key
  recovery_key_hash             TEXT NOT NULL,
  created_at                    INTEGER NOT NULL,
  updated_at                    INTEGER NOT NULL
);

-- ── Sessions (revocable; token stored hashed) ────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);

-- ── Encrypted file metadata index ────────────────────────────────────────────
-- enc_metadata holds the encrypted JSON {name, mime, size, width, height, ...}.
-- object_key points into the USER'S own storage, not ours.
CREATE TABLE IF NOT EXISTS vault_items (
  id                TEXT PRIMARY KEY,
  account_id        TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  enc_metadata      TEXT NOT NULL,
  wrapped_item_key  TEXT NOT NULL,  -- per-file key wrapped by the account key (carries its own IV)
  connection_id     TEXT NOT NULL REFERENCES storage_connections(id) ON DELETE CASCADE,
  object_key        TEXT NOT NULL,         -- path/key in the user's bucket
  thumb_key         TEXT,                  -- encrypted thumbnail object key
  size              INTEGER NOT NULL DEFAULT 0,  -- ciphertext size (not sensitive)
  bookmarked        INTEGER NOT NULL DEFAULT 0,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL
);

-- ── Storage connections (user-owned; config encrypted client-side) ───────────
CREATE TABLE IF NOT EXISTS storage_connections (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  provider    TEXT NOT NULL,               -- 's3' | 'gdrive' | 'dropbox' | 'local'
  enc_config  TEXT NOT NULL,               -- encrypted creds/tokens (server can't read)
  label       TEXT,
  created_at  INTEGER NOT NULL
);

-- ── Short-lived email tokens (verification) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS email_tokens (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  purpose     TEXT NOT NULL,               -- 'verify'
  token_hash  TEXT NOT NULL,
  expires_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_account     ON sessions(account_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires     ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_items_account_time   ON vault_items(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_items_account_book   ON vault_items(account_id, bookmarked);
CREATE INDEX IF NOT EXISTS idx_conn_account         ON storage_connections(account_id);
CREATE INDEX IF NOT EXISTS idx_email_tokens_hash    ON email_tokens(token_hash);
