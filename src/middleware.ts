import { defineMiddleware } from 'astro:middleware';

/**
 * Security headers on every response. The /app experience is a client-side SPA
 * that manages its own auth/unlock states (the account key lives only in the
 * browser), and every /api/* data route self-guards with a session check — so
 * no server-side page redirect is needed or wanted here.
 */
// SHA-256 of the two (and only two) inline scripts we ship — both in
// BaseLayout.astro: (1) the pre-paint theme setter, (2) the service-worker
// registration. Hash-allowlisting them lets us DROP 'unsafe-inline' from
// script-src, so an injected <script> can't run even if markup is compromised.
// Verified exhaustive across every page (public, auth, app, recovery-kit).
// ⚠️ If you edit either inline script, recompute its hash:
//    printf %s '<exact script text>' | openssl dgst -sha256 -binary | openssl base64
const INLINE_SCRIPT_HASHES = [
  "'sha256-j7JEbXP5+JOj//G0ohUIZsRT7yUHLdjp8oUQ1ns6Dyc='", // theme setter
  "'sha256-90IWy2I8NfkGWgNGIYs5IwCuZvEvp+XZFF057jJxXxM='", // service-worker registration
].join(' ');

const CSP = [
  "default-src 'self'",
  // No 'unsafe-inline': inline scripts run only if their hash is allow-listed
  // above. 'wasm-unsafe-eval' is required to run the Argon2id WASM (key
  // derivation) in the browser; it permits only WebAssembly compilation, not JS eval().
  `script-src 'self' ${INLINE_SCRIPT_HASHES} 'wasm-unsafe-eval'`,
  // style-src keeps 'unsafe-inline': Astro emits many scoped/inline <style>
  // blocks; inline CSS can't execute code, so the risk is far lower than scripts.
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: blob:",
  "media-src 'self' blob:",
  // Decrypted PDFs are previewed in a blob: iframe (in-page document viewer).
  "frame-src 'self' blob:",
  // hash-wasm runs Argon2id in a blob: Web Worker (off the main thread). Without
  // this, worker-src falls back to script-src, blocking it → slow main-thread KDF.
  "worker-src 'self' blob:",
  // The browser talks directly to the user's own S3-compatible bucket, so any
  // HTTPS origin must be allowed for storage upload/download.
  "connect-src 'self' https:",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

export const onRequest = defineMiddleware(async (context, next) => {
  const { url } = context;
  const response = await next();

  const h = response.headers;
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('X-Frame-Options', 'DENY');
  // Our responses are never meant to be embedded by another origin (frame-ancestors
  // 'none' already blocks framing); this also blocks cross-origin no-cors reads.
  // Note: we deliberately do NOT set COOP same-origin — it would sever window.opener
  // and break the Dropbox OAuth popup's postMessage handshake.
  h.set('Cross-Origin-Resource-Policy', 'same-origin');
  h.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  if (!h.has('Content-Security-Policy')) h.set('Content-Security-Policy', CSP);
  const proto = context.request.headers.get('x-forwarded-proto') ?? url.protocol.replace(':', '');
  if (proto === 'https') h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

  return response;
});
