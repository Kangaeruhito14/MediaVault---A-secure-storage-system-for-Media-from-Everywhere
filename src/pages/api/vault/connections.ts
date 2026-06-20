import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../../lib/server/context';
import { createConnection, listConnections } from '../../../lib/server/vault-service';
import { json } from '../../../lib/server/http';

export const GET: APIRoute = async ({ cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);
  return json({ connections: await listConnections(ctx.connections, accountId) });
};

// Store an encrypted storage-connection config. enc_config is wrapped by the
// account key client-side — the server can never read the credentials.
export const POST: APIRoute = async ({ request, cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }
  const res = await createConnection(ctx.connections, accountId, body);
  if (!res.ok) return json({ error: res.error }, 400);
  return json(res, 201);
};
