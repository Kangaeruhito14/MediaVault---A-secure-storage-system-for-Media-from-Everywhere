import { defineMiddleware } from 'astro:middleware';
import { isAuthenticated } from './lib/auth';
import { isUnlocked } from './lib/vault';

/**
 * Single gatekeeper for the whole app:
 *  1. Auth gate for /vault* pages and /api/media* endpoints (one place, not
 *     copy-pasted checks in every file).
 *  2. Sealed-vault gate: a valid session cookie is not enough after a server
 *     restart — until a password unseals the master key, media stays locked.
 *  3. Security headers on every response.
 */

const PROTECTED_PAGE = /^\/vault(\/|$)/;
const PROTECTED_API = /^\/api\/media(\/|$)/;

export const onRequest = defineMiddleware(async (context, next) => {
  const { pathname } = context.url;
  const isApi = PROTECTED_API.test(pathname);
  const isPage = PROTECTED_PAGE.test(pathname);

  if (isApi || isPage) {
    if (!isAuthenticated(context.request)) {
      if (isApi) {
        return new Response(JSON.stringify({ error: 'Unauthorized.' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return context.redirect('/login');
    }

    if (!isUnlocked()) {
      // Session survived a restart but the vault is sealed — password required.
      if (isApi) {
        return new Response(
          JSON.stringify({ error: 'Vault is sealed. Log in again to unlock.', code: 'vault_locked' }),
          { status: 403, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return context.redirect('/login?locked=1');
    }
  }

  const response = await next();

  // ── Security headers (every response) ──────────────────────────────────────
  const h = response.headers;
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('X-Frame-Options', 'DENY');
  h.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  if (!h.has('Content-Security-Policy')) {
    h.set(
      'Content-Security-Policy',
      [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: blob:",
        "media-src 'self' blob:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
      ].join('; '),
    );
  }
  const proto = context.request.headers.get('x-forwarded-proto') ?? context.url.protocol.replace(':', '');
  if (proto === 'https') {
    h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  return response;
});
