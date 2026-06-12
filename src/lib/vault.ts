import { randomBytes } from 'node:crypto';
import { getSetting, setSetting } from './db';
import {
  deriveKek,
  generateKey,
  generateRecoveryKey,
  hashPassword,
  hashRecoveryKey,
  normaliseRecoveryKey,
  unwrapKey,
  verifyPassword,
  verifyRecoveryKeyHash,
  wrapKey,
} from './crypto';

/**
 * Sealed-vault state machine.
 *
 * The 256-bit master key exists ONLY in server memory while the vault is
 * unlocked. On disk it is stored twice, wrapped (AES-256-GCM):
 *   - by a KEK derived from the password   (settings.master_wrapped_password)
 *   - by a KEK derived from the recovery key (settings.master_wrapped_recovery)
 *
 * A server restart, crash, or "Lock Vault" seals everything: media files on
 * disk are AES-256-CTR ciphertext and stay unreadable until someone presents
 * the password (or recovery key) again. Stealing the disk gets an attacker
 * nothing.
 */

let masterKey: Buffer | null = null;

export function isUnlocked(): boolean {
  return masterKey !== null;
}

export function getMasterKey(): Buffer | null {
  return masterKey;
}

export function lockVault(): void {
  if (masterKey) masterKey.fill(0); // zero the key material before dropping it
  masterKey = null;
}

export function isPasswordSet(): boolean {
  return getSetting('password_hash') !== null;
}

/** First-time setup. Returns the recovery key — shown once, never stored. */
export async function setupVault(password: string): Promise<string> {
  const recoveryKey = generateRecoveryKey();
  const master = generateKey();

  const kekSalt = randomBytes(16).toString('hex');
  const recoverySalt = randomBytes(16).toString('hex');
  const kek = await deriveKek(password, kekSalt);
  const rKek = await deriveKek(normaliseRecoveryKey(recoveryKey), recoverySalt);

  setSetting('password_hash', await hashPassword(password));
  setSetting('recovery_key_hash', hashRecoveryKey(recoveryKey));
  setSetting('kek_salt', kekSalt);
  setSetting('recovery_salt', recoverySalt);
  setSetting('master_wrapped_password', wrapKey(master, kek));
  setSetting('master_wrapped_recovery', wrapKey(master, rKek));
  setSetting('created_at', new Date().toISOString());

  masterKey = master;
  return recoveryKey;
}

/** Verify password; on success unlock the vault and return true. */
export async function unlockWithPassword(password: string): Promise<boolean> {
  const stored = getSetting('password_hash');
  if (!stored) return false;
  if (!(await verifyPassword(password, stored))) return false;

  const kekSalt = getSetting('kek_salt');
  const wrapped = getSetting('master_wrapped_password');
  if (!kekSalt || !wrapped) return false;

  const kek = await deriveKek(password, kekSalt);
  const master = unwrapKey(wrapped, kek);
  if (!master) return false;

  masterKey = master;
  return true;
}

/** Change password (requires current). Re-wraps the master key; files untouched. */
export async function changeVaultPassword(
  currentPassword: string,
  newPassword: string,
): Promise<boolean> {
  const stored = getSetting('password_hash');
  if (!stored || !(await verifyPassword(currentPassword, stored))) return false;

  const kekSalt = getSetting('kek_salt');
  const wrapped = getSetting('master_wrapped_password');
  if (!kekSalt || !wrapped) return false;

  const oldKek = await deriveKek(currentPassword, kekSalt);
  const master = unwrapKey(wrapped, oldKek);
  if (!master) return false;

  const newSalt = randomBytes(16).toString('hex');
  const newKek = await deriveKek(newPassword, newSalt);

  setSetting('password_hash', await hashPassword(newPassword));
  setSetting('kek_salt', newSalt);
  setSetting('master_wrapped_password', wrapKey(master, newKek));

  masterKey = master;
  return true;
}

/**
 * Reset password with recovery key. Recovers the master key through the
 * recovery wrap, sets the new password, and rotates the recovery key.
 * Returns the NEW recovery key, or null if the key was wrong.
 */
export async function resetWithRecoveryKey(
  recoveryKey: string,
  newPassword: string,
): Promise<string | null> {
  const storedHash = getSetting('recovery_key_hash');
  if (!storedHash || !verifyRecoveryKeyHash(recoveryKey, storedHash)) return null;

  const recoverySalt = getSetting('recovery_salt');
  const wrapped = getSetting('master_wrapped_recovery');
  if (!recoverySalt || !wrapped) return null;

  const rKek = await deriveKek(normaliseRecoveryKey(recoveryKey), recoverySalt);
  const master = unwrapKey(wrapped, rKek);
  if (!master) return null;

  const newRecoveryKey = generateRecoveryKey();
  const newKekSalt = randomBytes(16).toString('hex');
  const newRecoverySalt = randomBytes(16).toString('hex');
  const newKek = await deriveKek(newPassword, newKekSalt);
  const newRKek = await deriveKek(normaliseRecoveryKey(newRecoveryKey), newRecoverySalt);

  setSetting('password_hash', await hashPassword(newPassword));
  setSetting('recovery_key_hash', hashRecoveryKey(newRecoveryKey));
  setSetting('kek_salt', newKekSalt);
  setSetting('recovery_salt', newRecoverySalt);
  setSetting('master_wrapped_password', wrapKey(master, newKek));
  setSetting('master_wrapped_recovery', wrapKey(master, newRKek));

  masterKey = master;
  return newRecoveryKey;
}
