import { defineMiddleware } from 'astro:middleware';

/**
 * Security headers on every response. The /app experience is a client-side SPA
 * that manages its own auth/unlock states (the account key lives only in the
 * browser), and every /api/* data route self-guards with a session check — so
 * no server-side page redirect is needed or wanted here.
 */
const CSP = [
  "default-src 'self'",
  // 'wasm-unsafe-eval' is required to run the Argon2id WASM (key derivation) in
  // the browser; it does NOT permit JS eval(), only WebAssembly compilation.
  "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: blob:",
  "media-src 'self' blob:",
  // Decrypted PDFs are previewed in a blob: iframe (in-page document viewer).
  "frame-src 'self' blob:",
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
  h.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  if (!h.has('Content-Security-Policy')) h.set('Content-Security-Policy', CSP);
  const proto = context.request.headers.get('x-forwarded-proto') ?? url.protocol.replace(':', '');
  if (proto === 'https') h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

  return response;
});
