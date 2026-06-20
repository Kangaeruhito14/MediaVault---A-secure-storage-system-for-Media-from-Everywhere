import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../../../lib/server/context';
import { deleteConnection } from '../../../../lib/server/vault-service';
import { json } from '../../../../lib/server/http';

export const DELETE: APIRoute = async ({ params, cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);
  if (!params.id) return json({ error: 'missing_id' }, 400);

  const ok = await deleteConnection(ctx.connections, accountId, params.id);
  return ok ? json({ ok: true }) : json({ error: 'not_found' }, 404);
};
