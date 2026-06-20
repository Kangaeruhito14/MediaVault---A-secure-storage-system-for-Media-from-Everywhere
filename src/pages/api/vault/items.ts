import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../../lib/server/context';
import { createItem, listItems } from '../../../lib/server/vault-service';
import { json } from '../../../lib/server/http';

// List the encrypted index (keyset-paginated). The client decrypts metadata
// locally; the server only returns opaque blobs + pointers.
export const GET: APIRoute = async ({ request, cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);

  const url = new URL(request.url);
  const result = await listItems(ctx.items, accountId, {
    limit: Number(url.searchParams.get('limit')) || 60,
    bookmarked: url.searchParams.get('bookmarked') === '1',
    cursor: url.searchParams.get('cursor'),
  });
  return json(result);
};

// Record one encrypted item after the client has uploaded its ciphertext to
// the user's own bucket.
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
  const res = await createItem(ctx.items, accountId, body);
  if (!res.ok) return json({ error: res.error }, res.error === 'item_limit_reached' ? 409 : 400);
  return json(res, 201);
};
