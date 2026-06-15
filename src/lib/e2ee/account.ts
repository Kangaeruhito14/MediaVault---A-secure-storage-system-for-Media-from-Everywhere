/**
 * E2EE account lifecycle — the browser-side flows that keep the operator
 * blind. The server only ever receives: an auth key (which it hashes again),
 * wrapped key blobs, salts, KDF params, and a recovery-key hash. None of these
 * let the server derive the account key or read any file.
 *
 * Key hierarchy:
 *   password ──Argon2id(salt)──▶ masterKey
 *        masterKey ──HKDF "enc"──▶ encKey   (wraps the account key, stays local)
 *        masterKey ──HKDF "auth"─▶ authKey  (sent to server; server stores a hash)
 *   accountKey (random) ── wrapped by encKey ──▶ stored on server
 *   accountKey ── wrapped by recoveryKey ──────▶ stored on server (reset path)
 *   accountKey ── wraps each per-file key, and encrypts all metadata
 */
import { argon2id } from 'hash-wasm';
import {
  KEY_LEN,
  b64decode,
  b64encode,
  decryptJson,
  encryptJson,
  deriveSubkey,
  generateKey,
  randomBytes,
  sha256Hex,
  unwrapKey,
  wrapKey,
  encryptFile,
  decryptFile,
} from './crypto';

// OWASP-leaning Argon2id parameters (tunable; stored per-account so we can
// raise them later without breaking existing accounts).
export interface KdfParams {
  m: number; // memory in KiB
  t: number; // iterations
  p: number; // parallelism
}
export const DEFAULT_KDF: KdfParams = { m: 19456, t: 2, p: 1 };

const enc = new TextEncoder();

async function deriveMasterKey(password: string, salt: Uint8Array, params: KdfParams): Promise<Uint8Array> {
  const hash = await argon2id({
    password: enc.encode(password),
    salt,
    memorySize: params.m,
    iterations: params.t,
    parallelism: params.p,
    hashLength: KEY_LEN,
    outputType: 'binary',
  });
  return new Uint8Array(hash);
}

// ── Recovery key (shown once; 256-bit) ─────────────────────────────────────────
export function generateRecoveryKey(): string {
  // 256 bits of entropy, shown as uppercase hex groups (print/QR friendly).
  const hex = [...randomBytes(32)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return hex.match(/.{8}/g)!.join('-');
}
export function normalizeRecoveryKey(key: string): string {
  return key.replace(/[^A-Fa-f0-9]/g, '').toUpperCase();
}
async function recoveryWrapKey(recoveryKey: string, salt: Uint8Array): Promise<Uint8Array> {
  // Recovery key is already high-entropy (256-bit); a light Argon2id pass with
  // its own salt is plenty and keeps the derivation uniform with the password path.
  return deriveMasterKey(normalizeRecoveryKey(recoveryKey), salt, { m: 8192, t: 1, p: 1 });
}

// ── What the server gets to store (all opaque) ─────────────────────────────────
export interface AccountSecrets {
  kdfSalt: string;          // base64
  kdfParams: KdfParams;
  recoverySalt: string;     // base64
  authKeyB64: string;       // sent once at signup/login; server hashes it
  wrappedAccountKey: string;
  wrappedAccountKeyRecovery: string;
  recoveryKeyHash: string;  // sha256(normalized recovery key)
}

export interface CreatedAccount {
  secrets: AccountSecrets;
  recoveryKey: string;      // SHOW ONCE, never stored in plaintext
  accountKey: Uint8Array;   // kept in memory for the session
}

/** Sign-up: generate all keys in the browser. Returns secrets for the server. */
export async function createAccount(password: string, params: KdfParams = DEFAULT_KDF): Promise<CreatedAccount> {
  const kdfSalt = randomBytes(16);
  const recoverySalt = randomBytes(16);
  const masterKey = await deriveMasterKey(password, kdfSalt, params);
  const encKey = await deriveSubkey(masterKey, 'mediavault-enc');
  const authKey = await deriveSubkey(masterKey, 'mediavault-auth');

  const accountKey = generateKey();
  const recoveryKey = generateRecoveryKey();
  const recKey = await recoveryWrapKey(recoveryKey, recoverySalt);

  return {
    secrets: {
      kdfSalt: b64encode(kdfSalt),
      kdfParams: params,
      recoverySalt: b64encode(recoverySalt),
      authKeyB64: b64encode(authKey),
      wrappedAccountKey: await wrapKey(accountKey, encKey),
      wrappedAccountKeyRecovery: await wrapKey(accountKey, recKey),
      recoveryKeyHash: await sha256Hex(enc.encode(normalizeRecoveryKey(recoveryKey))),
    },
    recoveryKey,
    accountKey,
  };
}

/** Derive the auth key to send to the server when logging in. */
export async function deriveAuthKey(password: string, kdfSalt: string, params: KdfParams): Promise<string> {
  const masterKey = await deriveMasterKey(password, b64decode(kdfSalt), params);
  return b64encode(await deriveSubkey(masterKey, 'mediavault-auth'));
}

/** Unlock: re-derive keys and recover the account key into memory. Null = wrong password. */
export async function unlockWithPassword(
  password: string,
  kdfSalt: string,
  params: KdfParams,
  wrappedAccountKey: string,
): Promise<Uint8Array | null> {
  const masterKey = await deriveMasterKey(password, b64decode(kdfSalt), params);
  const encKey = await deriveSubkey(masterKey, 'mediavault-enc');
  return unwrapKey(wrappedAccountKey, encKey);
}

/** Recover the account key using the recovery key. Null = wrong key. */
export async function unlockWithRecovery(
  recoveryKey: string,
  recoverySalt: string,
  wrappedAccountKeyRecovery: string,
): Promise<Uint8Array | null> {
  const recKey = await recoveryWrapKey(recoveryKey, b64decode(recoverySalt));
  return unwrapKey(wrappedAccountKeyRecovery, recKey);
}

/** Re-wrap the (already recovered) account key under a new password + new recovery key. */
export async function rewrapForNewPassword(
  accountKey: Uint8Array,
  newPassword: string,
  params: KdfParams = DEFAULT_KDF,
): Promise<{ secrets: Omit<AccountSecrets, 'authKeyB64'> & { authKeyB64: string }; recoveryKey: string }> {
  const kdfSalt = randomBytes(16);
  const recoverySalt = randomBytes(16);
  const masterKey = await deriveMasterKey(newPassword, kdfSalt, params);
  const encKey = await deriveSubkey(masterKey, 'mediavault-enc');
  const authKey = await deriveSubkey(masterKey, 'mediavault-auth');
  const recoveryKey = generateRecoveryKey();
  const recKey = await recoveryWrapKey(recoveryKey, recoverySalt);

  return {
    secrets: {
      kdfSalt: b64encode(kdfSalt),
      kdfParams: params,
      recoverySalt: b64encode(recoverySalt),
      authKeyB64: b64encode(authKey),
      wrappedAccountKey: await wrapKey(accountKey, encKey),
      wrappedAccountKeyRecovery: await wrapKey(accountKey, recKey),
      recoveryKeyHash: await sha256Hex(enc.encode(normalizeRecoveryKey(recoveryKey))),
    },
    recoveryKey,
  };
}

// ── Per-file operations (account key in memory) ────────────────────────────────
export interface FileMetadata {
  name: string;
  mime: string;
  size: number; // plaintext size
  [extra: string]: unknown;
}

export interface EncryptedFile {
  ciphertext: Uint8Array;   // upload these bytes to the user's storage
  wrappedFileKey: string;   // store in the index
  encMetadata: string;      // store in the index (encrypted name/mime/size…)
}

export async function encryptForUpload(
  plaintext: Uint8Array,
  metadata: FileMetadata,
  accountKey: Uint8Array,
): Promise<EncryptedFile> {
  const fileKey = generateKey();
  return {
    ciphertext: await encryptFile(plaintext, fileKey),
    wrappedFileKey: await wrapKey(fileKey, accountKey),
    encMetadata: await encryptJson(metadata, accountKey),
  };
}

export async function decryptDownloaded(
  ciphertext: Uint8Array,
  wrappedFileKey: string,
  accountKey: Uint8Array,
): Promise<Uint8Array> {
  const fileKey = await unwrapKey(wrappedFileKey, accountKey);
  if (!fileKey) throw new Error('Cannot unwrap file key');
  return decryptFile(ciphertext, fileKey);
}

export async function readMetadata(encMetadata: string, accountKey: Uint8Array): Promise<FileMetadata> {
  return decryptJson<FileMetadata>(encMetadata, accountKey);
}
