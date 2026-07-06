/**
 * E2EE crypto primitives — runs in the browser (and in Node for tests).
 *
 * Standard, audited building blocks only:
 *   - AES-256-GCM for all encryption (authenticated; tamper is detected).
 *   - HKDF-SHA256 to split one master key into purpose-specific sub-keys.
 *   - Web Crypto (`crypto.subtle`) everywhere — no hand-rolled algorithms.
 *
 * All keys are raw 32-byte Uint8Arrays. Stored blobs are base64. The file
 * format is chunked so a future range request can decrypt one chunk without
 * the whole file (see encryptFile / decryptFileRange).
 */

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();

export const KEY_LEN = 32;
const GCM_IV_LEN = 12;
const GCM_TAG_LEN = 16;
const WRAP_VERSION = 1;

// ── randomness ────────────────────────────────────────────────────────────────
export function randomBytes(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}
export function generateKey(): Uint8Array {
  return randomBytes(KEY_LEN);
}

// ── base64 (portable across browser + Node) ────────────────────────────────────
export function b64encode(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
export function b64decode(str: string): Uint8Array {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// ── constant-time comparison ────────────────────────────────────────────────
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ── SHA-256 ────────────────────────────────────────────────────────────────────
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', bytes));
}
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const h = await sha256(bytes);
  return [...h].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ── HKDF: derive a purpose-specific sub-key from a master key ──────────────────
export async function deriveSubkey(masterKey: Uint8Array, info: string, length = KEY_LEN): Promise<Uint8Array> {
  const base = await subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(info) },
    base,
    length * 8,
  );
  return new Uint8Array(bits);
}

// ── AES-256-GCM core ───────────────────────────────────────────────────────────
async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function aesGcmEncrypt(
  keyRaw: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const key = await importAesKey(keyRaw);
  const params: AesGcmParams = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = aad;
  return new Uint8Array(await subtle.encrypt(params, key, plaintext));
}

/** Throws if the ciphertext or tag was tampered with (authentication failure). */
export async function aesGcmDecrypt(
  keyRaw: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const key = await importAesKey(keyRaw);
  const params: AesGcmParams = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = aad;
  return new Uint8Array(await subtle.decrypt(params, key, ciphertext));
}

// ── Key wrapping (AES-GCM) ──────────────────────────────────────────────────────
// blob bytes: version(1) | iv(12) | ciphertext+tag ; serialized as base64.

export async function wrapKey(rawKey: Uint8Array, wrappingKey: Uint8Array): Promise<string> {
  const iv = randomBytes(GCM_IV_LEN);
  const ct = await aesGcmEncrypt(wrappingKey, iv, rawKey);
  const blob = new Uint8Array(1 + GCM_IV_LEN + ct.length);
  blob[0] = WRAP_VERSION;
  blob.set(iv, 1);
  blob.set(ct, 1 + GCM_IV_LEN);
  return b64encode(blob);
}

/** Returns the unwrapped key, or null if the wrapping key is wrong / data tampered. */
export async function unwrapKey(blobB64: string, wrappingKey: Uint8Array): Promise<Uint8Array | null> {
  try {
    const blob = b64decode(blobB64);
    if (blob[0] !== WRAP_VERSION) return null;
    const iv = blob.subarray(1, 1 + GCM_IV_LEN);
    const ct = blob.subarray(1 + GCM_IV_LEN);
    return await aesGcmDecrypt(wrappingKey, iv, ct);
  } catch {
    return null;
  }
}

// ── JSON metadata encryption (filenames, mime, dimensions…) ────────────────────
export async function encryptJson(obj: unknown, key: Uint8Array): Promise<string> {
  const iv = randomBytes(GCM_IV_LEN);
  const ct = await aesGcmEncrypt(key, iv, te.encode(JSON.stringify(obj)));
  const blob = new Uint8Array(GCM_IV_LEN + ct.length);
  blob.set(iv, 0);
  blob.set(ct, GCM_IV_LEN);
  return b64encode(blob);
}
export async function decryptJson<T = unknown>(blobB64: string, key: Uint8Array): Promise<T> {
  const blob = b64decode(blobB64);
  const iv = blob.subarray(0, GCM_IV_LEN);
  const ct = blob.subarray(GCM_IV_LEN);
  const pt = await aesGcmDecrypt(key, iv, ct);
  return JSON.parse(td.decode(pt)) as T;
}

// ── Chunked file encryption (seekable) ─────────────────────────────────────────
// Header: magic "MV1"(3) | chunkSize(4 BE) | baseNonce(8).
// Each chunk i: AES-GCM over plaintext slice, iv = baseNonce(8) || counter_i(4 BE),
// aad = counter_i (binds position, blocks reordering). Ciphertext chunk is
// plaintextLen + 16 (tag) bytes; the final chunk may be short.

export const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024; // 4 MiB
const MAGIC = te.encode('MV1');
export const HEADER_LEN = 3 + 4 + 8; // magic(3) + chunkSize(4) + baseNonce(8)

function chunkIv(baseNonce: Uint8Array, counter: number): Uint8Array {
  const iv = new Uint8Array(GCM_IV_LEN);
  iv.set(baseNonce, 0);
  new DataView(iv.buffer).setUint32(8, counter, false);
  return iv;
}
function counterAad(counter: number): Uint8Array {
  const a = new Uint8Array(4);
  new DataView(a.buffer).setUint32(0, counter, false);
  return a;
}

export interface FileHeader {
  chunkSize: number;
  baseNonce: Uint8Array;
}

export function parseFileHeader(bytes: Uint8Array): FileHeader {
  if (bytes.length < HEADER_LEN || bytes[0] !== MAGIC[0] || bytes[1] !== MAGIC[1] || bytes[2] !== MAGIC[2]) {
    throw new Error('Not a Media Reservoir encrypted file');
  }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return { chunkSize: dv.getUint32(3, false), baseNonce: bytes.slice(7, 15) };
}

export async function encryptFile(
  plaintext: Uint8Array,
  fileKey: Uint8Array,
  chunkSize: number = DEFAULT_CHUNK_SIZE,
): Promise<Uint8Array> {
  const baseNonce = randomBytes(8);
  const header = new Uint8Array(HEADER_LEN);
  header.set(MAGIC, 0);
  new DataView(header.buffer).setUint32(3, chunkSize, false);
  header.set(baseNonce, 7);

  const parts: Uint8Array[] = [header];
  let counter = 0;
  for (let off = 0; off < plaintext.length || (plaintext.length === 0 && counter === 0); off += chunkSize) {
    const slice = plaintext.subarray(off, off + chunkSize);
    parts.push(await aesGcmEncrypt(fileKey, chunkIv(baseNonce, counter), slice, counterAad(counter)));
    counter++;
    if (plaintext.length === 0) break; // emit a single (empty) chunk for empty input
  }
  // concat
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

/**
 * Streaming variant of encryptFile: reads the file slice-by-slice and yields the
 * MV1 header followed by each encrypted chunk, so a multi-GB file never sits in
 * memory whole. Output bytes are byte-identical in FORMAT to encryptFile, so
 * decryptFile / decryptFileRange (and seekable streaming) work unchanged.
 */
export async function* encryptFileStream(
  file: Blob,
  fileKey: Uint8Array,
  chunkSize: number = DEFAULT_CHUNK_SIZE,
): AsyncGenerator<Uint8Array, void, unknown> {
  const baseNonce = randomBytes(8);
  const header = new Uint8Array(HEADER_LEN);
  header.set(MAGIC, 0);
  new DataView(header.buffer).setUint32(3, chunkSize, false);
  header.set(baseNonce, 7);
  yield header;

  const total = file.size;
  let counter = 0;
  for (let off = 0; off < total || (total === 0 && counter === 0); off += chunkSize) {
    const slice = new Uint8Array(await file.slice(off, off + chunkSize).arrayBuffer());
    yield await aesGcmEncrypt(fileKey, chunkIv(baseNonce, counter), slice, counterAad(counter));
    counter++;
    if (total === 0) break;
  }
}

export async function decryptFile(ciphertext: Uint8Array, fileKey: Uint8Array): Promise<Uint8Array> {
  const { chunkSize, baseNonce } = parseFileHeader(ciphertext);
  const encChunkLen = chunkSize + GCM_TAG_LEN;
  const body = ciphertext.subarray(HEADER_LEN);
  const out: Uint8Array[] = [];
  let counter = 0;
  for (let off = 0; off < body.length; off += encChunkLen) {
    const encChunk = body.subarray(off, off + encChunkLen);
    out.push(await aesGcmDecrypt(fileKey, chunkIv(baseNonce, counter), encChunk, counterAad(counter)));
    counter++;
  }
  const total = out.reduce((n, p) => n + p.length, 0);
  const result = new Uint8Array(total);
  let pos = 0;
  for (const p of out) {
    result.set(p, pos);
    pos += p.length;
  }
  return result;
}

/**
 * Decrypt exactly the plaintext byte range [start, end] (inclusive). Used for
 * seeking: maps the range to whole chunks, decrypts only those, trims the edges.
 * `fetchChunks(firstChunk, lastChunk)` returns the ciphertext bytes for the
 * encrypted chunks in [firstChunk, lastChunk] (each `chunkSize+16`, last short).
 */
export async function decryptFileRange(
  header: FileHeader,
  fileKey: Uint8Array,
  start: number,
  end: number,
  fetchChunks: (firstEncByteOffset: number, lastEncByteOffsetInclusive: number) => Promise<Uint8Array>,
): Promise<Uint8Array> {
  const { chunkSize, baseNonce } = header;
  const encChunkLen = chunkSize + GCM_TAG_LEN;
  const firstChunk = Math.floor(start / chunkSize);
  const lastChunk = Math.floor(end / chunkSize);

  const encBytes = await fetchChunks(firstChunk * encChunkLen, (lastChunk + 1) * encChunkLen - 1);
  const decrypted: Uint8Array[] = [];
  for (let c = firstChunk; c <= lastChunk; c++) {
    const localOff = (c - firstChunk) * encChunkLen;
    const encChunk = encBytes.subarray(localOff, localOff + encChunkLen);
    decrypted.push(await aesGcmDecrypt(fileKey, chunkIv(baseNonce, c), encChunk, counterAad(c)));
  }
  const total = decrypted.reduce((n, p) => n + p.length, 0);
  const joined = new Uint8Array(total);
  let pos = 0;
  for (const p of decrypted) {
    joined.set(p, pos);
    pos += p.length;
  }
  const innerStart = start - firstChunk * chunkSize;
  return joined.subarray(innerStart, innerStart + (end - start + 1));
}
