import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../lib/server/context';
import { deleteAccount, getProfile } from '../../lib/server/account-service';
import { json, SESSION_COOKIE } from '../../lib/server/http';

/** Profile summary for the account panel (email, member-since, counts). */
export const GET: APIRoute = async ({ cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);
  const profile = await getProfile(ctx, accountId);
  return profile ? json(profile) : json({ error: 'not_found' }, 404);
};

/** Permanently delete this account + its index/connections/sessions. */
export const DELETE: APIRoute = async ({ cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);

  const ok = await deleteAccount(ctx, accountId);
  cookies.delete(SESSION_COOKIE, { path: '/' });
  return ok ? json({ ok: true }) : json({ error: 'not_found' }, 404);
};
