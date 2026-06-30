-- 2FA (TOTP) for the account login + richer session metadata for the
-- "active devices" list. Both are about ACCOUNT access, not file encryption.
--
-- A TOTP secret is a conventional server-side shared secret (this is how every
-- RFC 6238 authenticator works). It gates the login handshake only. It does NOT
-- protect or derive the vault's end-to-end encryption keys — those are produced
-- in the browser and the server never sees them. So enabling 2FA hardens who can
-- start a session; it does not change the zero-knowledge property of the data.

CREATE TABLE IF NOT EXISTS account_totp (
  account_id    TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  secret        TEXT NOT NULL,              -- base32 TOTP secret
  enabled       INTEGER NOT NULL DEFAULT 0, -- 0 until the user confirms a code
  backup_codes  TEXT,                       -- JSON array of sha256(hex) of UNUSED one-time codes
  created_at    INTEGER NOT NULL,
  confirmed_at  INTEGER                     -- when 2FA was turned on
);

-- Best-effort device info so the owner can recognise & revoke their own sessions.
ALTER TABLE sessions ADD COLUMN user_agent TEXT;
ALTER TABLE sessions ADD COLUMN ip TEXT;
ALTER TABLE sessions ADD COLUMN last_seen INTEGER;
