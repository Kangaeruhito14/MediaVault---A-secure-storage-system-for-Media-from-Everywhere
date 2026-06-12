import type { APIRoute } from 'astro';
import { clearSessionCookie, getSessionFromCookies, revokeSession } from '../../../lib/auth';
import { lockVault } from '../../../lib/vault';

export const POST: APIRoute = async ({ request }) => {
  // Revoke server-side — the token dies now, not when the cookie expires
  revokeSession(getSessionFromCookies(request.headers.get('cookie')));
  // "Lock Vault" means exactly that: wipe the master key from memory.
  // Files on disk return to sealed ciphertext until the next login.
  lockVault();

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': clearSessionCookie(),
    },
  });
};
