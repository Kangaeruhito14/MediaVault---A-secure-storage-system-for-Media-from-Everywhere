import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../../lib/server/context';
import { listSessions, revokeOtherSessions, revokeSession } from '../../../lib/server/auth-service';
import { SESSION_COOKIE, json } from '../../../lib/server/http';

// GET: the account's active sessions (the current one is flagged).
export const GET: APIRoute = async ({ cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);
  const token = cookies.get(SESSION_COOKIE)?.value;
  return json({ sessions: await listSessions(ctx.sessions, accountId, token) });
};

// POST { id } revokes one session; POST { all: true } signs out everywhere else.
export const POST: APIRoute = async ({ request, cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);
  const token = cookies.get(SESSION_COOKIE)?.value;

  let body: { id?: string; all?: boolean };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  if (body.all === true) {
    if (!token) return json({ error: 'unauthorized' }, 401);
    await revokeOtherSessions(ctx.sessions, accountId, token);
    return json({ ok: true });
  }
  if (body.id) {
    return json({ ok: await revokeSession(ctx.sessions, accountId, String(body.id)) });
  }
  return json({ error: 'missing_fields' }, 400);
};
