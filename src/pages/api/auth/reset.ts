import type { APIRoute } from 'astro';
import {
  isAuthenticated,
  isRateLimited,
  recordFailedAttempt,
  clearAttempts,
  revokeAllSessions,
} from '../../../lib/auth';
import { resetWithRecoveryKey } from '../../../lib/vault';

const json = (body: unknown, status: number) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

export const POST: APIRoute = async ({ request }) => {
  // Recovery flow is for locked-out users only
  if (isAuthenticated(request)) {
    return json({ error: 'Already authenticated.' }, 400);
  }

  // Same global lockout as login — recovery attempts are login attempts
  if (isRateLimited()) {
    return json({ error: 'Too many failed attempts. Try again in 15 minutes.', locked: true }, 429);
  }

  let body: { recoveryKey?: string; newPassword?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON.' }, 400);
  }

  const { recoveryKey, newPassword } = body;
  if (!recoveryKey || !newPassword) {
    return json({ error: 'Recovery key and new password are required.' }, 400);
  }
  if (newPassword.trim().length < 8) {
    return json({ error: 'New password must be at least 8 characters.' }, 400);
  }

  // Unwraps the master key via the recovery wrap, sets the new password,
  // rotates the recovery key. Old key is dead after this.
  const newRecoveryKey = await resetWithRecoveryKey(recoveryKey.trim(), newPassword.trim());
  if (!newRecoveryKey) {
    recordFailedAttempt();
    return json({ error: 'Invalid recovery key.' }, 401);
  }

  clearAttempts();
  revokeAllSessions(); // any session an attacker holds dies with the old password

  return json({ ok: true, newRecoveryKey }, 200);
};
