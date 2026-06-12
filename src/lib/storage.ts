import { existsSync, mkdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { getDb } from './db';
import { generateFileIv, generateKey, unwrapKey, wrapKey } from './crypto';
import { getMasterKey } from './vault';

const UPLOADS_DIR = join(process.cwd(), 'uploads');

export interface MediaItem {
  id: string;
  filename: string;       // stored filename (UUID-based, ciphertext on disk)
  originalName: string;   // original uploaded name
  mimeType: string;
  size: number;           // plaintext bytes (CTR ciphertext is the same length)
  uploadedAt: string;     // ISO date
  bookmarked?: boolean;
  encrypted: boolean;
}

interface MediaRow {
  id: string;
  filename: string;
  original_name: string;
  mime_type: string;
  size: number;
  uploaded_at: string;
  bookmarked: number;
  encrypted: number;
  key_wrapped: string | null;
  iv: string | null;
}

function rowToItem(r: MediaRow): MediaItem {
  return {
    id: r.id,
    filename: r.filename,
    originalName: r.original_name,
    mimeType: r.mime_type,
    size: r.size,
    uploadedAt: r.uploaded_at,
    bookmarked: !!r.bookmarked,
    encrypted: !!r.encrypted,
  };
}

export function ensureDirs(): void {
  if (!existsSync(UPLOADS_DIR)) mkdirSync(UPLOADS_DIR, { recursive: true });
}

// ── Queries ───────────────────────────────────────────────────────────────────

export function listMedia(): MediaItem[] {
  const rows = getDb()
    .prepare('SELECT * FROM media ORDER BY bookmarked DESC, uploaded_at DESC')
    .all() as unknown as MediaRow[];
  return rows.map(rowToItem);
}

export function getMediaById(id: string): MediaItem | undefined {
  const row = getDb().prepare('SELECT * FROM media WHERE id = ?').get(id) as
    | MediaRow
    | undefined;
  return row ? rowToItem(row) : undefined;
}

/**
 * Returns the per-file decryption material for an encrypted item.
 * Requires the vault to be unlocked (master key in memory).
 */
export function getFileCrypto(id: string): { fileKey: Buffer; iv: Buffer } | null {
  const row = getDb()
    .prepare('SELECT key_wrapped, iv FROM media WHERE id = ?')
    .get(id) as Pick<MediaRow, 'key_wrapped' | 'iv'> | undefined;
  if (!row?.key_wrapped || !row.iv) return null;

  const master = getMasterKey();
  if (!master) return null;

  const fileKey = unwrapKey(row.key_wrapped, master);
  if (!fileKey) return null;
  return { fileKey, iv: Buffer.from(row.iv, 'hex') };
}

// ── Mutations ─────────────────────────────────────────────────────────────────

/**
 * Allocates an id, a per-file encryption key wrapped with the master key, and
 * a target path. The caller streams ciphertext to `filePath`, then calls
 * finalizeMedia() — metadata only becomes visible once bytes are safely on disk.
 */
export function prepareUpload(
  originalName: string,
  mimeType: string,
): { id: string; filePath: string; fileKey: Buffer; iv: Buffer } | null {
  ensureDirs();
  const master = getMasterKey();
  if (!master) return null; // vault sealed — cannot encrypt

  const id = randomUUID();
  const fileKey = generateKey();
  const iv = generateFileIv();
  // Stored name is opaque: no user-controlled extension touches the filesystem
  const filePath = join(UPLOADS_DIR, `${id}.enc`);

  pendingUploads.set(id, {
    originalName,
    mimeType,
    keyWrapped: wrapKey(fileKey, master),
    iv: iv.toString('hex'),
  });

  return { id, filePath, fileKey, iv };
}

const pendingUploads = new Map<
  string,
  { originalName: string; mimeType: string; keyWrapped: string; iv: string }
>();

/** Commits metadata after the encrypted bytes are fully written. */
export function finalizeMedia(id: string, size: number): MediaItem | null {
  const pending = pendingUploads.get(id);
  if (!pending) return null;
  pendingUploads.delete(id);

  getDb()
    .prepare(
      `INSERT INTO media (id, filename, original_name, mime_type, size, uploaded_at, bookmarked, encrypted, key_wrapped, iv)
       VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, ?)`,
    )
    .run(id, `${id}.enc`, pending.originalName, pending.mimeType, size, new Date().toISOString(), pending.keyWrapped, pending.iv);

  return getMediaById(id) ?? null;
}

/** Discards a pending upload (abort, error, over-limit). */
export function abortUpload(id: string, filePath: string): void {
  pendingUploads.delete(id);
  try {
    if (existsSync(filePath)) unlinkSync(filePath);
  } catch {
    // best-effort cleanup
  }
}

export function deleteMedia(id: string): boolean {
  const row = getDb().prepare('SELECT filename FROM media WHERE id = ?').get(id) as
    | { filename: string }
    | undefined;
  if (!row) return false;

  try {
    const filePath = join(UPLOADS_DIR, row.filename);
    if (existsSync(filePath)) unlinkSync(filePath);
  } catch {
    // file already gone — still remove metadata
  }

  getDb().prepare('DELETE FROM media WHERE id = ?').run(id);
  return true;
}

export function toggleBookmark(id: string): { success: boolean; bookmarked?: boolean; error?: string } {
  const db = getDb();
  const row = db.prepare('SELECT bookmarked FROM media WHERE id = ?').get(id) as
    | { bookmarked: number }
    | undefined;
  if (!row) return { success: false, error: 'File not found.' };

  if (!row.bookmarked) {
    const { n } = db.prepare('SELECT COUNT(*) AS n FROM media WHERE bookmarked = 1').get() as { n: number };
    if (n >= 10) {
      return { success: false, error: 'Maximum of 10 bookmarks reached. Please un-bookmark another file first.' };
    }
  }

  db.prepare('UPDATE media SET bookmarked = ? WHERE id = ?').run(row.bookmarked ? 0 : 1, id);
  return { success: true, bookmarked: !row.bookmarked };
}

// ── Stats & helpers ───────────────────────────────────────────────────────────

export function getUploadPath(filename: string): string {
  return join(UPLOADS_DIR, filename);
}

export function totalStorageUsed(): number {
  const { total } = getDb().prepare('SELECT COALESCE(SUM(size), 0) AS total FROM media').get() as { total: number };
  return total;
}

export function mediaTypeCounts(): { images: number; videos: number; audio: number } {
  const db = getDb();
  const count = (prefix: string) =>
    (db.prepare("SELECT COUNT(*) AS n FROM media WHERE mime_type LIKE ?").get(`${prefix}/%`) as { n: number }).n;
  return { images: count('image'), videos: count('video'), audio: count('audio') };
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function mediaTypeFromMime(mimeType: string): 'image' | 'video' | 'audio' | 'other' {
  if (mimeType.startsWith('image/')) return 'image';
  if (mimeType.startsWith('video/')) return 'video';
  if (mimeType.startsWith('audio/')) return 'audio';
  return 'other';
}
