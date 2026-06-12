import type { APIRoute } from 'astro';
import {
  createSession,
  isAuthenticated,
  revokeAllSessions,
  sessionCookie,
} from '../../../lib/auth';
import { changeVaultPassword } from '../../../lib/vault';

const json = (body: unknown, status: number, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });

export const POST: APIRoute = async ({ request }) => {
  if (!isAuthenticated(request)) {
    return json({ error: 'Unauthorized.' }, 401);
  }

  let body: { currentPassword?: string; newPassword?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON.' }, 400);
  }

  const { currentPassword, newPassword } = body;
  if (!currentPassword || !newPassword) {
    return json({ error: 'Both current and new password are required.' }, 400);
  }
  if (newPassword.trim().length < 8) {
    return json({ error: 'New password must be at least 8 characters.' }, 400);
  }

  // Re-wraps the master key under the new password — files are untouched
  const ok = await changeVaultPassword(currentPassword.trim(), newPassword.trim());
  if (!ok) {
    return json({ error: 'Current password is incorrect.' }, 401);
  }

  // Every existing session dies (a stolen token is now useless);
  // hand the legitimate user a fresh one so they stay logged in.
  revokeAllSessions();
  const token = createSession();

  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie(token, request) });
};
