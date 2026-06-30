import type { APIRoute } from 'astro';
import { getServerContext } from '../../../lib/server/context';
import { validateSession } from '../../../lib/server/auth-service';
import { SESSION_COOKIE, json } from '../../../lib/server/http';

export const GET: APIRoute = async ({ cookies }) => {
  const { sessions } = getServerContext();
  const s = await validateSession(sessions, cookies.get(SESSION_COOKIE)?.value);
  // This is a status probe (every page load calls it), so return 200 with the
  // boolean either way — a 401 here would log a console error for every guest.
  return json({ authenticated: !!s, accountId: s?.accountId });
};
