import type { APIRoute } from 'astro';
import { createWriteStream, writeFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import Busboy from 'busboy';
import { abortUpload, ensureDirs, finalizeMedia, prepareUpload, totalStorageUsed } from '../../../lib/storage';
import { createEncryptStream } from '../../../lib/crypto';
import { STRIPPABLE, stripImageMetadata } from '../../../lib/strip-metadata';

// Cap for buffering an image in memory to strip metadata. Larger images skip
// stripping concerns by being rejected with a clear message (rare in practice).
const STRIP_BUFFER_CAP = 64 * 1024 * 1024; // 64 MB

const MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024; // 5 GB per file
// Optional total-vault quota (bytes) via env; 0 = unlimited (it's your own disk)
const MAX_TOTAL_STORAGE = Number(process.env.MEDIAVAULT_MAX_STORAGE ?? 0);

const ALLOWED_TYPES = [
  'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif', 'image/svg+xml',
  'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime', 'video/x-msvideo',
  'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/webm', 'audio/flac', 'audio/aac', 'audio/mp4',
];

/**
 * Magic-byte verification: the declared MIME type must match what the bytes
 * actually are. A renamed .exe or an HTML file claiming to be a PNG is
 * rejected at the first chunk, before anything touches disk permanently.
 */
function sniffMatches(mime: string, head: Buffer): boolean {
  if (head.length < 12) return false;
  const ascii = head.subarray(0, 12).toString('latin1');
  const hex = head.subarray(0, 12).toString('hex');

  switch (mime) {
    case 'image/jpeg':    return hex.startsWith('ffd8ff');
    case 'image/png':     return hex.startsWith('89504e47');
    case 'image/gif':     return ascii.startsWith('GIF8');
    case 'image/webp':    return ascii.startsWith('RIFF') && ascii.includes('WEBP');
    case 'image/avif':    return ascii.includes('ftyp');
    case 'image/svg+xml': {
      const text = head.toString('utf-8').trimStart().toLowerCase();
      return text.startsWith('<svg') || text.startsWith('<?xml');
    }
    case 'video/mp4':
    case 'video/quicktime':
    case 'audio/mp4':     return ascii.includes('ftyp');
    case 'video/webm':
    case 'audio/webm':    return hex.startsWith('1a45dfa3');
    case 'video/ogg':
    case 'audio/ogg':     return ascii.startsWith('OggS');
    case 'video/x-msvideo': return ascii.startsWith('RIFF') && ascii.includes('AVI');
    case 'audio/mpeg':    return ascii.startsWith('ID3') || hex.startsWith('fff') || hex.startsWith('ffe');
    case 'audio/wav':     return ascii.startsWith('RIFF') && ascii.includes('WAVE');
    case 'audio/flac':    return ascii.startsWith('fLaC');
    case 'audio/aac':     return hex.startsWith('fff1') || hex.startsWith('fff9') || ascii.startsWith('ID3');
    default:              return false;
  }
}

const json = (body: unknown, status: number) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

export const POST: APIRoute = async ({ request }) => {
  // Auth + sealed-vault checks happen in middleware before we get here
  ensureDirs();

  const contentType = request.headers.get('content-type') ?? '';
  if (!contentType.includes('multipart/form-data')) {
    return json({ error: 'Expected multipart/form-data.' }, 400);
  }
  if (!request.body) {
    return json({ error: 'No body provided.' }, 400);
  }

  if (MAX_TOTAL_STORAGE > 0 && totalStorageUsed() >= MAX_TOTAL_STORAGE) {
    return json({ error: 'Vault storage quota reached. Delete files to free space.' }, 507);
  }

  // Opt-in EXIF/GPS stripping, requested via ?strip=1 (order-independent).
  const wantStrip = new URL(request.url).searchParams.get('strip') === '1';

  return new Promise<Response>((resolve) => {
    let settled = false;
    let sawFile = false;
    const finish = (r: Response) => {
      if (!settled) {
        settled = true;
        resolve(r);
      }
    };

    const busboy = Busboy({
      headers: { 'content-type': contentType },
      limits: { files: 1, fileSize: MAX_FILE_SIZE },
    });

    busboy.on('file', (fieldname, fileStream, info) => {
      if (fieldname !== 'file') {
        fileStream.resume();
        return;
      }
      sawFile = true;

      const { filename: originalName, mimeType } = info;
      if (!ALLOWED_TYPES.includes(mimeType)) {
        fileStream.resume();
        finish(json({ error: `File type "${mimeType}" is not supported. Upload images, videos, or audio.` }, 415));
        return;
      }

      const prepared = prepareUpload(originalName ?? 'unnamed', mimeType);
      if (!prepared) {
        fileStream.resume();
        finish(json({ error: 'Vault is sealed. Log in again.' }, 403));
        return;
      }
      const { id, filePath, fileKey, iv } = prepared;
      let failed = false;
      let sniffed = false;

      const commit = (size: number) => {
        if (MAX_TOTAL_STORAGE > 0 && totalStorageUsed() + size > MAX_TOTAL_STORAGE) {
          return false;
        }
        return finalizeMedia(id, size);
      };

      // Whether we buffer the whole image to strip metadata before encrypting.
      const stripping = wantStrip && STRIPPABLE.has(mimeType);

      if (stripping) {
        // ── Buffered path: collect → strip EXIF/GPS → encrypt → write ──
        const parts: Buffer[] = [];
        let bufSize = 0;
        const failB = (r: Response) => {
          if (failed) return;
          failed = true;
          fileStream.destroy();
          abortUpload(id, filePath);
          finish(r);
        };
        fileStream.on('data', (chunk: Buffer) => {
          if (failed) return;
          if (!sniffed) {
            sniffed = true;
            if (!sniffMatches(mimeType, chunk)) {
              failB(json({ error: 'File content does not match its declared type.' }, 415));
              return;
            }
          }
          bufSize += chunk.length;
          if (bufSize > STRIP_BUFFER_CAP) {
            failB(json({ error: 'Image too large for metadata stripping (64 MB max). Disable stripping for this file.' }, 413));
            return;
          }
          parts.push(chunk);
        });
        fileStream.on('limit', () => failB(json({ error: 'File exceeds the 5 GB limit.' }, 413)));
        fileStream.on('error', () => failB(json({ error: 'Upload interrupted.' }, 400)));
        fileStream.on('end', () => {
          if (failed) return;
          try {
            const cleaned = stripImageMetadata(Buffer.concat(parts), mimeType);
            const cipher = createEncryptStream(fileKey, iv);
            const ciphertext = Buffer.concat([cipher.update(cleaned), cipher.final()]);
            writeFileSync(filePath, ciphertext);
            const item = commit(cleaned.length);
            if (!item) { abortUpload(id, filePath); finish(json({ error: 'Vault storage quota reached. Delete files to free space.' }, 507)); return; }
            finish(json(item, 201));
          } catch {
            failB(json({ error: 'Failed to process image.' }, 500));
          }
        });
        return;
      }

      // ── Streaming path: encrypt chunk-by-chunk straight to disk ──
      const cipher = createEncryptStream(fileKey, iv);
      const writeStream = createWriteStream(filePath);
      let size = 0;

      const fail = (response: Response) => {
        if (failed) return;
        failed = true;
        fileStream.unpipe(cipher);
        cipher.destroy();
        writeStream.destroy();
        abortUpload(id, filePath);
        finish(response);
      };

      fileStream.on('data', (chunk: Buffer) => {
        if (failed) return;
        if (!sniffed) {
          sniffed = true;
          if (!sniffMatches(mimeType, chunk)) {
            fail(json({ error: 'File content does not match its declared type.' }, 415));
            return;
          }
        }
        size += chunk.length;
      });

      // busboy enforces fileSize: the stream is truncated, not errored
      fileStream.on('limit', () => {
        fail(json({ error: 'File exceeds the 5 GB limit.' }, 413));
      });

      // client disconnected mid-upload — clean up the partial ciphertext
      fileStream.on('error', () => {
        fail(json({ error: 'Upload interrupted.' }, 400));
      });
      cipher.on('error', () => {
        fail(json({ error: 'Encryption error.' }, 500));
      });
      writeStream.on('error', () => {
        fail(json({ error: 'Failed to save file.' }, 500));
      });

      writeStream.on('finish', () => {
        if (failed) return;
        // Metadata is committed only now — no phantom entries from failed uploads
        const item = commit(size);
        if (!item) {
          fail(json({ error: 'Vault storage quota reached. Delete files to free space.' }, 507));
          return;
        }
        finish(json(item, 201));
      });

      fileStream.pipe(cipher).pipe(writeStream);
    });

    busboy.on('error', () => finish(json({ error: 'Multipart parsing error.' }, 400)));
    busboy.on('finish', () => {
      if (!sawFile) finish(json({ error: 'No file provided.' }, 400));
    });

    try {
      const nodeStream = Readable.fromWeb(request.body as any);
      nodeStream.on('error', () => finish(json({ error: 'Upload interrupted.' }, 400)));
      nodeStream.pipe(busboy);
    } catch {
      finish(json({ error: 'Failed to stream request.' }, 500));
    }
  });
};
