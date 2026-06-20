import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../../../lib/server/context';
import { deleteItem, setBookmark } from '../../../../lib/server/vault-service';
import { json } from '../../../../lib/server/http';

// Remove the index row (the client deletes the bucket object itself, since only
// the client holds the storage credentials).
export const DELETE: APIRoute = async ({ params, cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);
  if (!params.id) return json({ error: 'missing_id' }, 400);

  const ok = await deleteItem(ctx.items, accountId, params.id);
  return ok ? json({ ok: true }) : json({ error: 'not_found' }, 404);
};

export const PATCH: APIRoute = async ({ params, request, cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);
  if (!params.id) return json({ error: 'missing_id' }, 400);

  let body: { bookmarked?: boolean };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }
  const ok = await setBookmark(ctx.items, accountId, params.id, !!body.bookmarked);
  return ok ? json({ ok: true, bookmarked: !!body.bookmarked }) : json({ error: 'not_found' }, 404);
};
