import type { APIRoute } from 'astro';
import { getServerContext } from '../../../lib/server/context';
import { getLoginParams } from '../../../lib/server/auth-service';
import { json } from '../../../lib/server/http';

// Step 1 of login: the client needs the account's KDF salt + params to derive
// its auth key. Unknown emails get a stable decoy, so this never reveals
// whether an account exists.
export const POST: APIRoute = async ({ request }) => {
  let body: { email?: string };
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }
  const { accounts } = getServerContext();
  return json(await getLoginParams(accounts, String(body.email ?? '')));
};
