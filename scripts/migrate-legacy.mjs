#!/usr/bin/env node
/**
 * MediaVault legacy migration: JSON-file vault (v1) → encrypted SQLite vault (v2).
 *
 * - Re-uses the existing password hash (formats are compatible).
 * - Generates the master key and a NEW recovery key (the old one cannot be
 *   recovered from its hash) — the new key is printed ONCE at the end.
 * - Encrypts every plaintext file in uploads/ to AES-256-CTR ciphertext.
 *   Each file is decrypt-verified (SHA-256 compare) before the plaintext
 *   original is deleted, so a bug cannot destroy data.
 *
 * Usage:  MV_PASSWORD='your-vault-password' node scripts/migrate-legacy.mjs
 */
import { DatabaseSync } from 'node:sqlite';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';
import { createReadStream, createWriteStream, existsSync, mkdirSync, renameSync, unlinkSync } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { join } from 'node:path';

const ROOT = process.cwd();
const DATA = join(ROOT, 'data');
const UPLOADS = join(ROOT, 'uploads');
const SCRYPT_N = 16384;

const password = process.env.MV_PASSWORD;
if (!password) {
  console.error('Set MV_PASSWORD to your current vault password and re-run.');
  process.exit(1);
}

// ── Load legacy state ─────────────────────────────────────────────────────────
const configPath = join(DATA, 'config.json');
const mediaPath = join(DATA, 'media.json');
if (!existsSync(configPath)) {
  console.error('No legacy data/config.json found — nothing to migrate.');
  process.exit(1);
}
const legacyConfig = JSON.parse(await readFile(configPath, 'utf-8'));
const legacyMedia = existsSync(mediaPath) ? JSON.parse(await readFile(mediaPath, 'utf-8')) : [];

// Verify password against the legacy scrypt hash (same format as v2)
const [salt, hash] = legacyConfig.passwordHash.split(':');
const derived = scryptSync(password, salt, 64, { N: SCRYPT_N });
if (!timingSafeEqual(Buffer.from(hash, 'hex'), derived)) {
  console.error('MV_PASSWORD does not match the existing vault password. Aborting.');
  process.exit(1);
}
console.log('✓ Password verified against legacy vault');

// ── Crypto helpers (must mirror src/lib/crypto.ts exactly) ───────────────────
const deriveKek = (secret, saltHex) =>
  scryptSync(secret, Buffer.from(saltHex, 'hex'), 32, { N: SCRYPT_N });

const wrapKey = (keyToWrap, wrappingKey) => {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', wrappingKey, iv);
  const ct = Buffer.concat([cipher.update(keyToWrap), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64');
};

const generateRecoveryKey = () =>
  randomBytes(32).toString('hex').toUpperCase().match(/.{8}/g).join('-');

const normaliseRecoveryKey = (k) => k.replace(/[^A-Fa-f0-9]/g, '').toUpperCase();
const hashRecoveryKey = (k) => createHash('sha256').update(normaliseRecoveryKey(k)).digest('hex');

// ── Build v2 database ─────────────────────────────────────────────────────────
const dbPath = join(DATA, 'vault.db');
if (existsSync(dbPath)) {
  console.error('data/vault.db already exists — refusing to overwrite. Delete it to re-run.');
  process.exit(1);
}
const db = new DatabaseSync(dbPath);
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
  CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE media (
    id TEXT PRIMARY KEY, filename TEXT NOT NULL, original_name TEXT NOT NULL,
    mime_type TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0, uploaded_at TEXT NOT NULL,
    bookmarked INTEGER NOT NULL DEFAULT 0, encrypted INTEGER NOT NULL DEFAULT 0,
    key_wrapped TEXT, iv TEXT
  );
  CREATE TABLE sessions (
    id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE TABLE login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, attempted_at INTEGER NOT NULL);
  CREATE INDEX idx_media_uploaded ON media(uploaded_at);
  CREATE INDEX idx_sessions_expires ON sessions(expires_at);
  CREATE INDEX idx_attempts_time ON login_attempts(attempted_at);
`);

// Master key + envelopes
const masterKey = randomBytes(32);
const recoveryKey = generateRecoveryKey();
const kekSalt = randomBytes(16).toString('hex');
const recoverySalt = randomBytes(16).toString('hex');
const kek = deriveKek(password, kekSalt);
const rKek = deriveKek(normaliseRecoveryKey(recoveryKey), recoverySalt);

const setSetting = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)');
setSetting.run('password_hash', legacyConfig.passwordHash);
setSetting.run('recovery_key_hash', hashRecoveryKey(recoveryKey));
setSetting.run('kek_salt', kekSalt);
setSetting.run('recovery_salt', recoverySalt);
setSetting.run('master_wrapped_password', wrapKey(masterKey, kek));
setSetting.run('master_wrapped_recovery', wrapKey(masterKey, rKek));
setSetting.run('created_at', legacyConfig.createdAt ?? new Date().toISOString());
console.log('✓ Master key generated and wrapped (password + recovery envelopes)');

// ── Encrypt every media file ─────────────────────────────────────────────────
const sha256File = (path, decipher = null) =>
  new Promise((resolve, reject) => {
    const h = createHash('sha256');
    let stream = createReadStream(path);
    if (decipher) stream = stream.pipe(decipher);
    stream.on('data', (c) => h.update(c));
    stream.on('end', () => resolve(h.digest('hex')));
    stream.on('error', reject);
  });

const insertMedia = db.prepare(
  `INSERT INTO media (id, filename, original_name, mime_type, size, uploaded_at, bookmarked, encrypted, key_wrapped, iv)
   VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
);

let migrated = 0;
for (const item of legacyMedia) {
  const src = join(UPLOADS, item.filename);
  if (!existsSync(src)) {
    console.warn(`  ! ${item.originalName}: file missing on disk, skipping`);
    continue;
  }
  const id = item.id ?? randomUUID();
  const fileKey = randomBytes(32);
  const iv = randomBytes(16);
  const dst = join(UPLOADS, `${id}.enc`);

  const plainHash = await sha256File(src);
  await pipeline(
    createReadStream(src),
    createCipheriv('aes-256-ctr', fileKey, iv),
    createWriteStream(dst),
  );

  // decrypt-verify before touching the original
  const roundTrip = await sha256File(dst, createDecipheriv('aes-256-ctr', fileKey, iv));
  if (roundTrip !== plainHash) {
    unlinkSync(dst);
    console.error(`  ✗ ${item.originalName}: round-trip verification FAILED — original kept, aborting.`);
    process.exit(1);
  }

  const { size } = await stat(src);
  insertMedia.run(
    id, `${id}.enc`, item.originalName, item.mimeType, size,
    item.uploadedAt ?? new Date().toISOString(), item.bookmarked ? 1 : 0,
    wrapKey(fileKey, masterKey), iv.toString('hex'),
  );
  unlinkSync(src); // plaintext gone only after verified ciphertext exists
  migrated++;
  console.log(`  ✓ ${item.originalName} (${size} bytes) encrypted + verified`);
}

// ── Retire legacy files ───────────────────────────────────────────────────────
const backupDir = join(DATA, 'legacy-v1-backup');
mkdirSync(backupDir, { recursive: true });
renameSync(configPath, join(backupDir, 'config.json'));
if (existsSync(mediaPath)) renameSync(mediaPath, join(backupDir, 'media.json'));

console.log(`\n✓ Migration complete: ${migrated}/${legacyMedia.length} files encrypted`);
console.log('✓ Legacy config moved to data/legacy-v1-backup/');
console.log('\n┌──────────────────────────────────────────────────────────────────┐');
console.log('│  NEW RECOVERY KEY — the old one is now invalid. SAVE THIS NOW:   │');
console.log('└──────────────────────────────────────────────────────────────────┘\n');
console.log(`  ${recoveryKey}\n`);
