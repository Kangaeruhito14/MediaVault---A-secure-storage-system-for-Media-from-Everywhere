import type { APIRoute } from 'astro';
import { getServerContext } from '../../../lib/server/context';
import { validateSession } from '../../../lib/server/auth-service';
import { SESSION_COOKIE, json } from '../../../lib/server/http';

export const GET: APIRoute = async ({ cookies }) => {
  const { sessions } = getServerContext();
  const s = await validateSession(sessions, cookies.get(SESSION_COOKIE)?.value);
  if (!s) return json({ authenticated: false }, 401);
  return json({ authenticated: true, accountId: s.accountId });
};
