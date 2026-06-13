/**
 * MediaVault service worker — PWA shell + offline fallback.
 *
 * Deliberately conservative for a security app:
 *  - NEVER caches /api/* (media bytes, auth) or /vault* (private HTML).
 *  - Caches only the static marketing/app shell and brand assets.
 *  - Navigations: network-first, falling back to a cached offline page.
 * This keeps encrypted media and authenticated pages out of any cache.
 */
const CACHE = 'mediavault-shell-v2';
const SHELL = [
  '/',
  '/offline.html',
  '/favicon.svg',
  '/icon-192.png',
  '/icon-512.png',
  '/manifest.webmanifest',
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))),
    ).then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Never touch private or dynamic endpoints.
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/vault') || url.pathname.startsWith('/login')) {
    return;
  }

  // Navigations: network-first, offline fallback.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(() => caches.match('/offline.html').then((r) => r || caches.match('/'))),
    );
    return;
  }

  // Static assets: cache-first, then network (and cache the result).
  event.respondWith(
    caches.match(request).then((cached) =>
      cached ||
      fetch(request).then((resp) => {
        if (resp.ok && (url.pathname.startsWith('/vendor/') || /\.(css|js|svg|png|webmanifest|woff2?)$/.test(url.pathname))) {
          const copy = resp.clone();
          caches.open(CACHE).then((c) => c.put(request, copy));
        }
        return resp;
      }).catch(() => cached),
    ),
  );
});
