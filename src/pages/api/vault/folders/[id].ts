import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../../../lib/server/context';
import { deleteFolder, renameFolder } from '../../../../lib/server/vault-service';
import { json } from '../../../../lib/server/http';

// Rename a folder (new encrypted name).
export const PATCH: APIRoute = async ({ params, request, cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);
  if (!params.id) return json({ error: 'missing_id' }, 400);

  let body: { encName?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }
  if (!body.encName) return json({ error: 'missing_fields' }, 400);
  const ok = await renameFolder(ctx.folders, accountId, params.id, body.encName);
  return ok ? json({ ok: true }) : json({ error: 'not_found' }, 404);
};

// Delete the folder. The client re-files its items to "All files" first (each
// item's encrypted metadata is rewritten to drop the folder id).
export const DELETE: APIRoute = async ({ params, cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);
  if (!params.id) return json({ error: 'missing_id' }, 400);
  const ok = await deleteFolder(ctx.folders, accountId, params.id);
  return ok ? json({ ok: true }) : json({ error: 'not_found' }, 404);
};
