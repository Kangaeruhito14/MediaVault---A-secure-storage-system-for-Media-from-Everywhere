import type { APIRoute } from 'astro';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { Readable } from 'node:stream';
import { createDecryptStreamRange } from '../../../lib/crypto';
import { deleteMedia, getFileCrypto, getMediaById, getUploadPath } from '../../../lib/storage';

const jsonError = (msg: string, status: number) =>
  new Response(JSON.stringify({ error: msg }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

/** Parse a Range header against a known total size. Returns null when invalid. */
function parseRange(header: string, totalSize: number): { start: number; end: number } | null {
  const m = header.match(/^bytes=(\d*)-(\d*)$/);
  if (!m) return null;
  const [, rawStart, rawEnd] = m;

  if (rawStart === '' && rawEnd === '') return null;
  if (rawStart === '') {
    // suffix range: last N bytes
    const n = parseInt(rawEnd, 10);
    if (n === 0) return null;
    return { start: Math.max(0, totalSize - n), end: totalSize - 1 };
  }
  const start = parseInt(rawStart, 10);
  const end = rawEnd === '' ? totalSize - 1 : Math.min(parseInt(rawEnd, 10), totalSize - 1);
  if (start >= totalSize || start > end) return null;
  return { start, end };
}

export const GET: APIRoute = async ({ request, params }) => {
  const id = params.id;
  if (!id) return jsonError('Missing media ID.', 400);

  const item = getMediaById(id);
  if (!item) return jsonError('Media not found.', 404);

  const filePath = getUploadPath(item.filename);
  if (!existsSync(filePath)) return jsonError('File not found on disk.', 404);

  // SVG can carry scripts — never let it render as a same-origin document.
  // <img> tags still display it fine; direct navigation downloads instead.
  const isSvg = item.mimeType === 'image/svg+xml';
  const baseHeaders: Record<string, string> = {
    'Accept-Ranges': 'bytes',
    'Content-Type': item.mimeType,
    'Cache-Control': 'private, max-age=3600',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "sandbox; default-src 'none'",
    'Content-Disposition': `${isSvg ? 'attachment' : 'inline'}; filename="${encodeURIComponent(item.originalName)}"`,
  };

  try {
    // Plaintext size: for CTR-encrypted files ciphertext length == plaintext length
    const totalSize = item.encrypted ? item.size : statSync(filePath).size;

    let start = 0;
    let end = totalSize - 1;
    let status = 200;

    const rangeHeader = request.headers.get('range');
    if (rangeHeader) {
      const range = parseRange(rangeHeader, totalSize);
      if (!range) {
        return new Response(JSON.stringify({ error: 'Range not satisfiable.' }), {
          status: 416,
          headers: {
            'Content-Type': 'application/json',
            'Content-Range': `bytes */${totalSize}`,
            'Accept-Ranges': 'bytes',
          },
        });
      }
      ({ start, end } = range);
      status = 206;
      baseHeaders['Content-Range'] = `bytes ${start}-${end}/${totalSize}`;
    }

    baseHeaders['Content-Length'] = String(end - start + 1);

    let nodeStream: NodeJS.ReadableStream;
    if (item.encrypted) {
      const crypto = getFileCrypto(id);
      if (!crypto) return jsonError('Vault is sealed. Log in again to unlock.', 403);
      // AES-256-CTR is seekable: decryption starts exactly at the requested offset
      nodeStream = createDecryptStreamRange(filePath, crypto.fileKey, crypto.iv, start, end);
    } else {
      nodeStream = createReadStream(filePath, { start, end });
    }

    return new Response(Readable.toWeb(nodeStream as Readable) as any, {
      status,
      headers: baseHeaders,
    });
  } catch {
    return jsonError('Internal server error.', 500);
  }
};

export const DELETE: APIRoute = async ({ params }) => {
  const id = params.id;
  if (!id) return jsonError('Missing ID.', 400);

  const success = deleteMedia(id);
  if (!success) return jsonError('Not found.', 404);

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
};
