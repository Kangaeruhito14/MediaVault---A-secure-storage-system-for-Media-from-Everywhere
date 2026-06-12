import type { APIRoute } from 'astro';
import { isPasswordSet, unlockWithPassword } from '../../../lib/vault';
import {
  clearAttempts,
  createSession,
  isRateLimited,
  recordFailedAttempt,
  sessionCookie,
} from '../../../lib/auth';

const json = (body: unknown, status: number, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });

export const POST: APIRoute = async ({ request }) => {
  if (!isPasswordSet()) {
    return json({ error: 'No password set. Complete setup first.' }, 403);
  }

  // Global lockout — not keyed on spoofable client headers
  if (isRateLimited()) {
    return json({ error: 'Too many failed attempts. Try again in 15 minutes.', locked: true }, 429);
  }

  let body: { password?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON.' }, 400);
  }

  const password = body.password?.trim();
  if (!password) {
    return json({ error: 'Password required.' }, 400);
  }

  // Verifies the password AND unseals the vault (master key into memory)
  const ok = await unlockWithPassword(password);
  if (!ok) {
    const { remaining, locked } = recordFailedAttempt();
    return json(
      {
        error: locked
          ? 'Too many failed attempts. Locked for 15 minutes.'
          : `Incorrect password. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`,
        remaining,
        locked,
      },
      401,
    );
  }

  clearAttempts();
  const token = createSession();

  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie(token, request) });
};
