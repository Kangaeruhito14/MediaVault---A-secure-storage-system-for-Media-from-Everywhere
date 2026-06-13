/**
 * Image metadata stripping — removes EXIF (including GPS), XMP, and text
 * chunks that can silently leak where and when a photo was taken.
 *
 * Operates on a full in-memory Buffer (images only; callers cap the size).
 * On any parse uncertainty it returns the ORIGINAL bytes unchanged — never
 * risk corrupting a user's file for the sake of stripping.
 */

export const STRIPPABLE = new Set(['image/jpeg', 'image/png', 'image/webp']);

export function stripImageMetadata(buf: Buffer, mimeType: string): Buffer {
  try {
    if (mimeType === 'image/jpeg') return stripJpeg(buf);
    if (mimeType === 'image/png') return stripPng(buf);
    if (mimeType === 'image/webp') return stripWebp(buf);
  } catch {
    /* fall through — return original on any error */
  }
  return buf;
}

/**
 * JPEG: a sequence of marker segments. We drop APP1..APP15 (EXIF/XMP/etc.)
 * and COM (comment) markers, keep APP0 (JFIF) for compatibility, and copy the
 * compressed scan data after SOS verbatim.
 */
function stripJpeg(buf: Buffer): Buffer {
  if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8) return buf; // not a JPEG (no SOI)

  const out: Buffer[] = [buf.subarray(0, 2)]; // SOI
  let i = 2;

  while (i < buf.length - 1) {
    if (buf[i] !== 0xff) return buf; // misaligned — bail safely
    const marker = buf[i + 1];

    // Start of Scan: copy the rest of the file as-is (entropy-coded data)
    if (marker === 0xda) {
      out.push(buf.subarray(i));
      return Buffer.concat(out);
    }
    // Standalone markers without a length payload
    if (marker === 0xd9 || (marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) {
      out.push(buf.subarray(i, i + 2));
      i += 2;
      continue;
    }

    const len = buf.readUInt16BE(i + 2); // segment length includes these 2 bytes
    const segEnd = i + 2 + len;
    if (segEnd > buf.length) return buf; // truncated — bail

    const isApp = marker >= 0xe1 && marker <= 0xef; // APP1..APP15
    const isComment = marker === 0xfe;
    if (!isApp && !isComment) {
      out.push(buf.subarray(i, segEnd)); // keep (APP0/JFIF, quant tables, frames, etc.)
    }
    i = segEnd;
  }
  return Buffer.concat(out);
}

/**
 * PNG: 8-byte signature followed by length+type+data+crc chunks. Drop
 * metadata chunks (eXIf, tEXt, iTXt, zTXt, and time), keep everything else.
 */
function stripPng(buf: Buffer): Buffer {
  const SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (buf.length < 8 || !buf.subarray(0, 8).equals(SIG)) return buf;

  const DROP = new Set(['eXIf', 'tEXt', 'iTXt', 'zTXt', 'tIME']);
  const out: Buffer[] = [buf.subarray(0, 8)];
  let i = 8;

  while (i + 8 <= buf.length) {
    const len = buf.readUInt32BE(i);
    const type = buf.toString('latin1', i + 4, i + 8);
    const chunkEnd = i + 12 + len; // length(4)+type(4)+data(len)+crc(4)
    if (chunkEnd > buf.length) return buf; // truncated — bail

    if (!DROP.has(type)) out.push(buf.subarray(i, chunkEnd));
    if (type === 'IEND') break;
    i = chunkEnd;
  }
  return Buffer.concat(out);
}

/**
 * WebP (RIFF): drop 'EXIF' and 'XMP ' chunks. If the file is a simple
 * (non-extended) WebP with no metadata, it is returned unchanged.
 */
function stripWebp(buf: Buffer): Buffer {
  if (buf.length < 12) return buf;
  if (buf.toString('latin1', 0, 4) !== 'RIFF' || buf.toString('latin1', 8, 12) !== 'WEBP') return buf;

  const DROP = new Set(['EXIF', 'XMP ']);
  const out: Buffer[] = [buf.subarray(0, 12)];
  let i = 12;
  let removed = false;

  while (i + 8 <= buf.length) {
    const fourcc = buf.toString('latin1', i, i + 4);
    const size = buf.readUInt32LE(i + 4);
    const padded = size + (size % 2); // chunks are padded to even length
    const chunkEnd = i + 8 + padded;
    if (chunkEnd > buf.length) return buf; // truncated — bail

    if (DROP.has(fourcc)) {
      removed = true;
    } else {
      out.push(buf.subarray(i, chunkEnd));
    }
    i = chunkEnd;
  }

  if (!removed) return buf;
  const result = Buffer.concat(out);
  result.writeUInt32LE(result.length - 8, 4); // fix RIFF size field
  return result;
}
