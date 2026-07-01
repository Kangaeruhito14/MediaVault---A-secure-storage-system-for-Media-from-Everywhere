-- Soft-delete ("Trash"): a nullable timestamp instead of a hard DELETE, so an
-- accidental deletion is recoverable. NULL = live; a timestamp = in the trash
-- (and still encrypted in the user's own storage until permanently purged).
ALTER TABLE vault_items ADD COLUMN deleted_at INTEGER;

-- The main gallery lists live items newest-first; this index keeps that fast
-- while excluding trashed rows.
CREATE INDEX IF NOT EXISTS idx_items_account_live ON vault_items(account_id, deleted_at, created_at DESC);
