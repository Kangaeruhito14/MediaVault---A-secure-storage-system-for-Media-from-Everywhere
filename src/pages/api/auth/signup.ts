import type { APIRoute } from 'astro';
import { getServerContext } from '../../../lib/server/context';
import { signup, startSession } from '../../../lib/server/auth-service';
import type { SignupSecrets } from '../../../lib/server/types';
import { SESSION_COOKIE, cookieOptions, json } from '../../../lib/server/http';

// The client has already generated all keys locally; the server only stores
// the opaque blobs it sends. On success we open a session (auto-login).
export const POST: APIRoute = async ({ request, cookies }) => {
  let body: { email?: string; secrets?: SignupSecrets };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }
  if (!body.email || !body.secrets) return json({ error: 'missing_fields' }, 400);

  const ctx = getServerContext();
  const res = await signup(ctx.accounts, { email: body.email, secrets: body.secrets });
  if (!res.ok) return json({ error: res.error }, res.error === 'email_taken' ? 409 : 400);

  const token = await startSession(ctx.sessions, res.accountId);
  cookies.set(SESSION_COOKIE, token, cookieOptions(new URL(request.url)));
  return json({ ok: true });
};
