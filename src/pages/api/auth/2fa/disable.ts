import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../../../lib/server/context';
import { disableTotp } from '../../../../lib/server/auth-service';
import { json } from '../../../../lib/server/http';

// Turn 2FA off. Requires re-proving the current password (so a hijacked session
// alone can't strip the second factor).
export const POST: APIRoute = async ({ request, cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);

  let body: { currentAuthKeyB64?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const r = await disableTotp(ctx, { accountId, currentAuthKeyB64: String(body.currentAuthKeyB64 ?? '') });
  if (!r.ok) return json({ error: r.error }, 400);
  return json({ ok: true });
};
