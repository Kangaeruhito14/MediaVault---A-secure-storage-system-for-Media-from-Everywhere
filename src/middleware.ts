import { defineMiddleware } from 'astro:middleware';
import { D1SessionStore } from './lib/server/stores';
import { validateSession } from './lib/server/auth-service';
import { SESSION_COOKIE } from './lib/server/http';

/**
 * One gatekeeper:
 *  1. Auth gate for the (future) authenticated app under /app — validates the
 *     session against D1 before the page renders.
 *  2. Security headers on every response.
 */
const PROTECTED = /^\/app(\/|$)/;

const CSP = [
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
].join('; ');

export const onRequest = defineMiddleware(async (context, next) => {
  const { url, locals, cookies } = context;

  if (PROTECTED.test(url.pathname)) {
    const env = locals.runtime?.env;
    const token = cookies.get(SESSION_COOKIE)?.value;
    const session = env?.DB ? await validateSession(new D1SessionStore(env.DB), token) : null;
    if (!session) return context.redirect('/login');
  }

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
