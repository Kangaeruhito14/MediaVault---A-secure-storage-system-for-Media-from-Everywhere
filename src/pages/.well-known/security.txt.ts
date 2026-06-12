import type { APIRoute } from 'astro';

/**
 * RFC 9116 security.txt — tells security researchers where to report
 * vulnerabilities. Expiry rolls forward so the file never goes stale.
 */
export const GET: APIRoute = ({ url }) => {
  const origin = import.meta.env.PUBLIC_SITE_URL?.replace(/\/$/, '') || url.origin;
  const expires = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

  const body = `Contact: mailto:fantasyfalcoon91@gmail.com
Expires: ${expires}
Preferred-Languages: en
Canonical: ${origin}/.well-known/security.txt
Policy: ${origin}/terms
`;

  return new Response(body, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=86400',
    },
  });
};
