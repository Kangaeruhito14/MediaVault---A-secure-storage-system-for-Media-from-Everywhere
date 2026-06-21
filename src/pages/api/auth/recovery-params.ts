import type { APIRoute } from 'astro';
import { getServerContext } from '../../../lib/server/context';
import { getRecoveryParams } from '../../../lib/server/auth-service';
import { json } from '../../../lib/server/http';

// Step 1 of recovery: return the recovery salt + recovery-wrapped account key so
// the client can attempt to unlock with the recovery key. Decoy for unknown emails.
export const POST: APIRoute = async ({ request }) => {
  let body: { email?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }
  const ctx = getServerContext();
  return json(await getRecoveryParams(ctx.accounts, String(body.email ?? '')));
};
