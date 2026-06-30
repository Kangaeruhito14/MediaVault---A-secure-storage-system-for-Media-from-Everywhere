import type { APIRoute } from 'astro';
import { getServerContext, requireAccountId } from '../../../../lib/server/context';
import { setupTotp } from '../../../../lib/server/auth-service';
import { json } from '../../../../lib/server/http';

// Begin 2FA enrolment: mint a secret + otpauth URL for the QR code. Not active
// until /api/auth/2fa/enable confirms a code. The secret is a server-side shared
// secret (RFC 6238) and gates login only — never the vault's encryption keys.
export const POST: APIRoute = async ({ cookies }) => {
  const ctx = getServerContext();
  const accountId = await requireAccountId(ctx, cookies);
  if (!accountId) return json({ error: 'unauthorized' }, 401);

  const acct = await ctx.accounts.getById(accountId);
  if (!acct) return json({ error: 'unauthorized' }, 401);

  const r = await setupTotp(ctx.totp, accountId, acct.email);
  if (!r.ok) return json({ error: r.error }, 400);
  return json({ ok: true, secret: r.secret, otpauthUrl: r.otpauthUrl });
};
