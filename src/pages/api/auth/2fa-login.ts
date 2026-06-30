import type { APIRoute } from 'astro';
import { clientIp, deviceLabel, getServerContext } from '../../../lib/server/context';
import { verifyTwoFactorLogin } from '../../../lib/server/auth-service';
import { SESSION_COOKIE, cookieOptions, json } from '../../../lib/server/http';

// Step 3 of login (only when 2FA is on): exchange the pending token + a TOTP or
// backup code for a real session + the wrapped account key.
export const POST: APIRoute = async ({ request, cookies }) => {
  let body: { pendingToken?: string; code?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const ctx = getServerContext();
  const r = await verifyTwoFactorLogin(ctx, {
    pendingToken: String(body.pendingToken ?? ''),
    code: String(body.code ?? ''),
    ipKey: clientIp(request),
    userAgent: deviceLabel(request),
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
