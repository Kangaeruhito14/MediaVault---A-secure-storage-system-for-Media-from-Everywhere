import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../../lib/server/context';
import { exportAccount } from '../../../lib/server/account-service';
import { json } from '../../../lib/server/http';

/** Download a complete, encrypted backup of everything we hold for this account. */
export const GET: APIRoute = async ({ cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);

  const data = await exportAccount(ctx, accountId);
  if (!data) return json({ error: 'not_found' }, 404);

  const date = new Date().toISOString().slice(0, 10);
  return new Response(JSON.stringify(data, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="mediavault-export-${date}.json"`,
      'Cache-Control': 'no-store',
    },
  });
};
