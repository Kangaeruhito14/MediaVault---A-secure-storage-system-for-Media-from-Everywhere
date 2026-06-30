import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../../../lib/server/context';
import { getTotpStatus } from '../../../../lib/server/auth-service';
import { json } from '../../../../lib/server/http';

// Whether 2FA is on (or half-enrolled) for the logged-in account — drives the UI.
export const GET: APIRoute = async ({ cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);
  return json(await getTotpStatus(ctx.totp, accountId));
};
