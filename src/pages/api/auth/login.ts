import type { APIRoute } from 'astro';
import { clientIp, getServerContext } from '../../../lib/server/context';
import { login } from '../../../lib/server/auth-service';
import { SESSION_COOKIE, cookieOptions, json } from '../../../lib/server/http';

// Step 2 of login: client posts its derived auth key. The session token is set
// as an httpOnly cookie (never returned in the body). The wrapped account key
// is returned so the client can unlock it locally — the server can't.
export const POST: APIRoute = async ({ request, locals, cookies }) => {
  let body: { email?: string; authKeyB64?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const ctx = getServerContext(locals);
  const r = await login(ctx, {
    email: String(body.email ?? ''),
    authKeyB64: String(body.authKeyB64 ?? ''),
    ipKey: clientIp(request),
  });
  if (!r.ok) return json({ error: r.error }, r.error === 'rate_limited' ? 429 : 401);

  cookies.set(SESSION_COOKIE, r.result.token, cookieOptions(new URL(request.url)));
  return json({
    ok: true,
    wrappedAccountKey: r.result.wrappedAccountKey,
    kdfSalt: r.result.kdfSalt,
    kdfParams: r.result.kdfParams,
    emailVerified: r.result.emailVerified,
  });
};
