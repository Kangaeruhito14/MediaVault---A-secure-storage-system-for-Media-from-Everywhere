import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../../lib/server/context';
import { createFolder, listFolders } from '../../../lib/server/vault-service';
import { json } from '../../../lib/server/http';

// Folders: only the encrypted name is stored here. Membership lives inside each
// item's E2E-encrypted metadata, so the server can't tell what's in a folder.
export const GET: APIRoute = async ({ cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);
  return json({ folders: await listFolders(ctx.folders, accountId) });
};

export const POST: APIRoute = async ({ request, cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);

  let body: { encName?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }
  const r = await createFolder(ctx.folders, accountId, String(body.encName ?? ''));
  if (!r.ok) return json({ error: r.error }, r.error === 'folder_limit_reached' ? 409 : 400);
  return json({ ok: true, id: r.id }, 201);
};
