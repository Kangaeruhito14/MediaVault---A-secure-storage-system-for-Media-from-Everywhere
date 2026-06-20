/**
 * Range streaming core — fetches only the ciphertext chunks needed for a
 * plaintext byte range from the user's bucket and decrypts them. This is what
 * lets encrypted video/audio seek without downloading the whole file: the media
 * player asks for a byte range, we map it to whole AES-CTR chunks, fetch just
 * those, decrypt, and trim to the exact range.
 *
 * Pure + testable (inject any object with a ranged `get`); the Service Worker
 * builds on this for native media playback.
 */
import { HEADER_LEN, decryptFileRange, parseFileHeader, type FileHeader } from '../e2ee/crypto';

export interface RangedGetter {
  get(key: string, range?: { start: number; end: number }): Promise<Response>;
}

/** Read + parse the 15-byte MV1 header (chunk size + base nonce) from storage. */
export async function fetchHeader(s3: RangedGetter, objectKey: string): Promise<FileHeader> {
  const res = await s3.get(objectKey, { start: 0, end: HEADER_LEN - 1 });
  return parseFileHeader(new Uint8Array(await res.arrayBuffer()));
}

/** Total ciphertext object size, derived from plaintext size + chunk size. */
export function ciphertextSize(plaintextSize: number, chunkSize: number): number {
  const nChunks = Math.max(1, Math.ceil(plaintextSize / chunkSize));
  return HEADER_LEN + plaintextSize + nChunks * 16; // +16 GCM tag per chunk
}

/** Decrypt exactly the plaintext byte range [start, end] (inclusive). */
export async function streamRange(
  s3: RangedGetter,
  objectKey: string,
  header: FileHeader,
  fileKey: Uint8Array,
  plaintextSize: number,
  start: number,
  end: number,
): Promise<Uint8Array> {
  const lastByte = Math.min(end, plaintextSize - 1);
  const objSize = ciphertextSize(plaintextSize, header.chunkSize);

  return decryptFileRange(header, fileKey, start, lastByte, async (encLo, encHi) => {
    // encLo/encHi are offsets into the ciphertext BODY (after the header).
    const absLo = HEADER_LEN + encLo;
    const absHi = Math.min(HEADER_LEN + encHi, objSize - 1);
    const res = await s3.get(objectKey, { start: absLo, end: absHi });
    return new Uint8Array(await res.arrayBuffer());
  });
}
