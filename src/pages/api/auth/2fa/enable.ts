import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../../../lib/server/context';
import { enableTotp } from '../../../../lib/server/auth-service';
import { json } from '../../../../lib/server/http';

// Confirm enrolment: re-prove the password AND a fresh 6-digit code, then turn
// 2FA on. Returns one-time backup codes — shown to the user exactly once.
export const POST: APIRoute = async ({ request, cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);

  let body: { currentAuthKeyB64?: string; code?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const r = await enableTotp(ctx, {
    accountId,
    currentAuthKeyB64: String(body.currentAuthKeyB64 ?? ''),
    code: String(body.code ?? ''),
  });
  if (!r.ok) return json({ error: r.error }, 400);
  return json({ ok: true, backupCodes: r.backupCodes });
};
