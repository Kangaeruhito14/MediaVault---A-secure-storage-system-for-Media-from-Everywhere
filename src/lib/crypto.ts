import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scrypt,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';
import { createReadStream } from 'node:fs';
import { Transform } from 'node:stream';

/**
 * MediaVault crypto core — envelope encryption, sealed vault.
 *
 *   password ──scrypt──▶ KEK ──unwraps──▶ master key ──unwraps──▶ per-file key
 *   recovery key ─scrypt─▶ rKEK ─unwraps─▶ master key (same master, second wrap)
 *
 * Files are encrypted with AES-256-CTR so ciphertext length equals plaintext
 * length and any byte offset can be decrypted independently — which is what
 * keeps HTTP Range / video seeking working on encrypted files.
 * Key wrapping uses AES-256-GCM (authenticated), so a tampered wrapped key
 * fails loudly instead of silently decrypting garbage.
 */

const SCRYPT_N = 16384;
const KEY_LEN = 32;

// ── Password hashing ──────────────────────────────────────────────────────────

export function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString('hex');
  return new Promise((resolve, reject) => {
    scrypt(password, salt, 64, { N: SCRYPT_N }, (err, derived) => {
      if (err) reject(err);
      else resolve(`${salt}:${derived.toString('hex')}`);
    });
  });
}

export function verifyPassword(password: string, stored: string): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      const [salt, hash] = stored.split(':');
      const hashBuffer = Buffer.from(hash, 'hex');
      scrypt(password, salt, 64, { N: SCRYPT_N }, (err, derived) => {
        if (err || hashBuffer.length !== derived.length) resolve(false);
        else resolve(timingSafeEqual(hashBuffer, derived));
      });
    } catch {
      resolve(false);
    }
  });
}

// ── Key derivation (KEK from password or recovery key) ───────────────────────

export function deriveKek(secret: string, saltHex: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(secret, Buffer.from(saltHex, 'hex'), KEY_LEN, { N: SCRYPT_N }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

/** Synchronous variant for CLI scripts. */
export function deriveKekSync(secret: string, saltHex: string): Buffer {
  return scryptSync(secret, Buffer.from(saltHex, 'hex'), KEY_LEN, { N: SCRYPT_N });
}

// ── Recovery key ──────────────────────────────────────────────────────────────

export function generateRecoveryKey(): string {
  const raw = randomBytes(32).toString('hex').toUpperCase();
  return raw.match(/.{8}/g)!.join('-');
}

export function normaliseRecoveryKey(key: string): string {
  return key.replace(/[^A-Fa-f0-9]/g, '').toUpperCase();
}

export function hashRecoveryKey(key: string): string {
  return createHash('sha256').update(normaliseRecoveryKey(key)).digest('hex');
}

export function verifyRecoveryKeyHash(key: string, storedHash: string): boolean {
  try {
    const h = hashRecoveryKey(key);
    return timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(storedHash, 'hex'));
  } catch {
    return false;
  }
}

// ── Key wrapping (AES-256-GCM) ───────────────────────────────────────────────
// Wrapped format (base64): iv(12) ‖ authTag(16) ‖ ciphertext

export function wrapKey(keyToWrap: Buffer, wrappingKey: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', wrappingKey, iv);
  const ct = Buffer.concat([cipher.update(keyToWrap), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString('base64');
}

export function unwrapKey(wrapped: string, wrappingKey: Buffer): Buffer | null {
  try {
    const buf = Buffer.from(wrapped, 'base64');
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const ct = buf.subarray(28);
    const decipher = createDecipheriv('aes-256-gcm', wrappingKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    return null; // wrong key or tampered data — GCM authentication failed
  }
}

export function generateKey(): Buffer {
  return randomBytes(KEY_LEN);
}

export function generateFileIv(): Buffer {
  return randomBytes(16);
}

// ── Streaming file encryption (AES-256-CTR, seekable) ───────────────────────

/** 128-bit big-endian addition: counterIv = iv + blockIndex. */
function addToIv(iv: Buffer, blocks: bigint): Buffer {
  const out = Buffer.from(iv);
  let carry = blocks;
  for (let i = 15; i >= 0 && carry > 0n; i--) {
    const sum = BigInt(out[i]) + (carry & 0xffn);
    out[i] = Number(sum & 0xffn);
    carry = (carry >> 8n) + (sum >> 8n);
  }
  return out;
}

/** Cipher stream for encrypting a whole file during upload. */
export function createEncryptStream(fileKey: Buffer, iv: Buffer) {
  return createCipheriv('aes-256-ctr', fileKey, iv);
}

/**
 * Decrypting read stream for an arbitrary byte range [start, end] (inclusive).
 * CTR mode lets us begin at any 16-byte block boundary, then drop the first
 * `start % 16` bytes so the caller receives exactly the requested range.
 */
export function createDecryptStreamRange(
  filePath: string,
  fileKey: Buffer,
  iv: Buffer,
  start: number,
  end: number,
) {
  const blockIndex = Math.floor(start / 16);
  const blockStart = blockIndex * 16;
  let dropBytes = start - blockStart;

  const counterIv = addToIv(iv, BigInt(blockIndex));
  const decipher = createDecipheriv('aes-256-ctr', fileKey, counterIv);
  const fileStream = createReadStream(filePath, { start: blockStart, end });

  const dropper = new Transform({
    transform(chunk: Buffer, _enc, cb) {
      if (dropBytes > 0) {
        if (chunk.length <= dropBytes) {
          dropBytes -= chunk.length;
          cb();
          return;
        }
        chunk = chunk.subarray(dropBytes);
        dropBytes = 0;
      }
      cb(null, chunk);
    },
  });

  // Surface read errors to the consumer instead of hanging the pipeline
  fileStream.on('error', (err) => dropper.destroy(err));
  decipher.on('error', (err) => dropper.destroy(err));

  return fileStream.pipe(decipher).pipe(dropper);
}

// ── Session tokens ────────────────────────────────────────────────────────────

export function generateSessionToken(): string {
  return randomBytes(32).toString('base64url');
}

export function hashSessionToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
