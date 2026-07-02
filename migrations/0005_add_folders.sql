-- Folders. Only the folder's NAME is stored here (encrypted, opaque to us).
-- An item's membership is kept INSIDE its own end-to-end-encrypted metadata
-- (metadata.folderId), so the server can't even tell which items are grouped
-- together — it just sees a list of opaque folder ids with encrypted labels.
CREATE TABLE IF NOT EXISTS folders (
  id          TEXT PRIMARY KEY,       -- uuid; appears (encrypted) inside item metadata
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  enc_name    TEXT NOT NULL,          -- encrypted folder name (client-decrypts)
  created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_folders_account ON folders(account_id);
