import type { APIRoute } from 'astro';
import { getServerContext } from '../../../lib/server/context';
import { logout } from '../../../lib/server/auth-service';
import { SESSION_COOKIE, json } from '../../../lib/server/http';

export const POST: APIRoute = async ({ locals, cookies }) => {
  const { sessions } = getServerContext(locals);
  await logout(sessions, cookies.get(SESSION_COOKIE)?.value);
  cookies.delete(SESSION_COOKIE, { path: '/' });
  return json({ ok: true });
};
