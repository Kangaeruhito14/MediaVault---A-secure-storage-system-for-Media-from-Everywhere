/// <reference lib="webworker" />
/**
 * Media Reservoir Service Worker (bundled to public/sw.js by scripts/build-sw.mjs).
 *
 * Two jobs:
 *  1. PWA shell + offline fallback (never caches /api or authenticated pages).
 *  2. Encrypted media streaming: the page registers a media item (with its
 *     file key, held only in memory), and the SW serves seekable, decrypted
 *     206 responses at /__mv_stream/<id> by fetching only the needed ciphertext
 *     chunks from the user's bucket and decrypting them on the fly.
 *
 * The file key reaches the SW only via postMessage (same-origin, in-memory) and
 * is dropped when the page unregisters or the SW restarts. Nothing is persisted.
 */
import { makeStore, type ProviderConfig } from '../lib/storage/object-store';
import { streamRange } from '../lib/client/stream';
import type { FileHeader } from '../lib/e2ee/crypto';

declare const self: ServiceWorkerGlobalScope;

const CACHE = 'mediareservoir-shell-v4';
const SHELL = ['/', '/offline.html', '/favicon.svg', '/web-app-manifest-192x192.png', '/site.webmanifest'];
const STREAM_PREFIX = '/__mv_stream/';
const WINDOW = 4 * 1024 * 1024; // max plaintext bytes served per range request

interface StreamEntry {
  config: ProviderConfig;
  objectKey: string;
  fileKey: Uint8Array;
  header: FileHeader;
  plaintextSize: number;
  mime: string;
}
const streams = new Map<string, StreamEntry>();

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()),
  );
});

self.addEventListener('message', (event) => {
  const d = event.data;
  if (!d || typeof d !== 'object') return;
  if (d.type === 'mv-register-stream') {
    streams.set(d.id, {
      config: d.config,
      objectKey: d.objectKey,
      fileKey: d.fileKey,
      header: { chunkSize: d.chunkSize, baseNonce: d.baseNonce },
      plaintextSize: d.plaintextSize,
      mime: d.mime,
    });
  } else if (d.type === 'mv-unregister-stream') {
    streams.delete(d.id);
  }
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // ── Encrypted media streaming ───────────────────────────────────────────────
  if (url.origin === self.location.origin && url.pathname.startsWith(STREAM_PREFIX)) {
    event.respondWith(handleStream(request, url.pathname.slice(STREAM_PREFIX.length)));
    return;
  }

  if (request.method !== 'GET' || url.origin !== self.location.origin) return;
  // Never cache private or dynamic endpoints.
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/vault') || url.pathname.startsWith('/app') || url.pathname.startsWith('/login')) {
    return;
  }

  if (request.mode === 'navigate') {
    event.respondWith(
      (async () => {
        try {
          return await fetch(request);
        } catch {
          return (await caches.match('/offline.html')) || (await caches.match('/')) || new Response('Offline', { status: 503 });
        }
      })(),
    );
    return;
  }

  event.respondWith(
    (async () => {
      const cached = await caches.match(request);
      if (cached) return cached;
      try {
        const resp = await fetch(request);
        if (resp.ok && (url.pathname.startsWith('/vendor/') || /\.(css|js|svg|png|webmanifest|woff2?)$/.test(url.pathname))) {
          const copy = resp.clone();
          caches.open(CACHE).then((c) => c.put(request, copy));
        }
        return resp;
      } catch {
        return new Response('', { status: 504 });
      }
    })(),
  );
});

async function handleStream(request: Request, id: string): Promise<Response> {
  const s = streams.get(id);
  if (!s) return new Response('Not registered', { status: 404 });

  const total = s.plaintextSize;
  const rangeHeader = request.headers.get('range');
  let start = 0;
  let end = total - 1;
  let partial = false;
  if (rangeHeader) {
    const m = /bytes=(\d*)-(\d*)/.exec(rangeHeader);
    if (m) {
      partial = true;
      if (m[1] === '' && m[2] !== '') {
        start = Math.max(0, total - parseInt(m[2], 10)); // suffix range
      } else {
        start = parseInt(m[1], 10) || 0;
        end = m[2] ? parseInt(m[2], 10) : total - 1;
      }
    }
  }
  end = Math.min(end, total - 1, start + WINDOW - 1); // cap each response

  if (start > end || start >= total) {
    return new Response('Range Not Satisfiable', { status: 416, headers: { 'Content-Range': `bytes */${total}` } });
  }

  try {
    const store = makeStore(s.config);
    const bytes = await streamRange(store, s.objectKey, s.header, s.fileKey, total, start, end);
    const headers: Record<string, string> = {
      'Content-Type': s.mime || 'application/octet-stream',
      'Content-Length': String(bytes.length),
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'no-store',
    };
    if (partial) headers['Content-Range'] = `bytes ${start}-${end}/${total}`;
    return new Response(bytes, { status: partial ? 206 : 200, headers });
  } catch (e) {
    return new Response('Stream error: ' + (e as Error).message, { status: 500 });
  }
}
