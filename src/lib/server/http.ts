/** Shared HTTP helpers for the auth API + session cookie policy. */

export const SESSION_COOKIE = 'mv_sess';
export const SESSION_MAX_AGE = 30 * 24 * 60 * 60; // 30 days (seconds)

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** httpOnly, SameSite=Strict; Secure whenever the request is over HTTPS. */
export function cookieOptions(url: URL) {
  return {
    httpOnly: true,
    sameSite: 'strict' as const,
    secure: url.protocol === 'https:',
    path: '/',
    maxAge: SESSION_MAX_AGE,
  };
}
