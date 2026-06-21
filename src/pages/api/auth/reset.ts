import type { APIRoute } from 'astro';
import { clientIp, getServerContext } from '../../../lib/server/context';
import { resetPassword } from '../../../lib/server/auth-service';
import { SESSION_COOKIE, cookieOptions, json } from '../../../lib/server/http';
import type { SignupSecrets } from '../../../lib/server/types';

// Step 2 of recovery: the client proves it holds the recovery key (by its hash)
// and posts freshly re-wrapped secrets for the new password. On success the old
// sessions are revoked and a new session cookie is set.
export const POST: APIRoute = async ({ request, cookies }) => {
  let body: { email?: string; recoveryKeyHash?: string; secrets?: SignupSecrets };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const ctx = getServerContext();
  const r = await resetPassword(ctx, {
    email: String(body.email ?? ''),
    recoveryKeyHash: String(body.recoveryKeyHash ?? ''),
    secrets: body.secrets as SignupSecrets,
    ipKey: clientIp(request),
  });
  if (!r.ok) return json({ error: r.error }, r.error === 'rate_limited' ? 429 : 400);

  cookies.set(SESSION_COOKIE, r.token, cookieOptions(new URL(request.url)));
  return json({ ok: true });
};
