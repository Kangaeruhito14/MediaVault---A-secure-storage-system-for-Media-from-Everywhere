-- Store the recovery-key KDF salt so a forgotten password can be reset with the
-- recovery key. (v3 signups generated this salt but never persisted it, which
-- made the recovery path impossible — this column fixes that.)
ALTER TABLE accounts ADD COLUMN recovery_salt TEXT;
