import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../../lib/server/context';
import { changePassword } from '../../../lib/server/auth-service';
import { SESSION_COOKIE, cookieOptions, json } from '../../../lib/server/http';
import type { SignupSecrets } from '../../../lib/server/types';

// Change password for a logged-in account. The current password is re-proven via
// its auth key; other sessions are revoked and this one is refreshed.
export const POST: APIRoute = async ({ request, cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);

  let body: { currentAuthKeyB64?: string; secrets?: SignupSecrets };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const r = await changePassword(ctx, {
    accountId,
    currentAuthKeyB64: String(body.currentAuthKeyB64 ?? ''),
    secrets: body.secrets as SignupSecrets,
  });
  if (!r.ok) return json({ error: r.error }, 400);

  cookies.set(SESSION_COOKIE, r.token, cookieOptions(new URL(request.url)));
  return json({ ok: true });
};
