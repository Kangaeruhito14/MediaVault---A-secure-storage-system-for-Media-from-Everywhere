import type { APIRoute } from 'astro';
import { isPasswordSet, setupVault } from '../../../lib/vault';
import { createSession, sessionCookie } from '../../../lib/auth';

const json = (body: unknown, status: number, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });

export const POST: APIRoute = async ({ request }) => {
  if (isPasswordSet()) {
    return json({ error: 'Password already set.' }, 403);
  }

  let body: { password?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON.' }, 400);
  }

  const password = body.password?.trim();
  if (!password || password.length < 8) {
    return json({ error: 'Password must be at least 8 characters.' }, 400);
  }

  // Creates master key + recovery key, wraps both, unlocks the vault.
  // The recovery key is returned exactly once and never stored in plaintext.
  const recoveryKey = await setupVault(password);
  const token = createSession();

  return json({ ok: true, recoveryKey }, 200, { 'Set-Cookie': sessionCookie(token, request) });
};
