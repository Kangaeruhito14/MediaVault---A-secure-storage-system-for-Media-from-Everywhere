import type { APIRoute } from 'astro';

/**
 * robots.txt — allow the marketing site, keep crawlers out of the app
 * interior and the API. Sitemap URL is derived from the live origin so
 * every self-hosted instance serves a correct absolute link.
 */
export const GET: APIRoute = ({ url }) => {
  const origin = import.meta.env.PUBLIC_SITE_URL?.replace(/\/$/, '') || url.origin;

  const body = `User-agent: *
Allow: /
Disallow: /vault
Disallow: /api/
Disallow: /login

Sitemap: ${origin}/sitemap.xml
`;

  return new Response(body, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  });
};
