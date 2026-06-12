import type { APIRoute } from 'astro';

/**
 * sitemap.xml — every indexable public page with priority hints.
 * The app interior (/vault, /login) is intentionally absent: those pages
 * are noindex and disallowed in robots.txt.
 */
const PAGES: { path: string; priority: string; changefreq: string }[] = [
  { path: '/', priority: '1.0', changefreq: 'weekly' },
  { path: '/about', priority: '0.8', changefreq: 'monthly' },
  { path: '/faq', priority: '0.9', changefreq: 'weekly' },
  { path: '/contact', priority: '0.6', changefreq: 'yearly' },
  { path: '/terms', priority: '0.3', changefreq: 'yearly' },
  { path: '/privacy', priority: '0.3', changefreq: 'yearly' },
];

export const GET: APIRoute = ({ url }) => {
  const origin = import.meta.env.PUBLIC_SITE_URL?.replace(/\/$/, '') || url.origin;
  const lastmod = new Date().toISOString().split('T')[0];

  const entries = PAGES.map(
    (p) => `  <url>
    <loc>${origin}${p.path}</loc>
    <lastmod>${lastmod}</lastmod>
    <changefreq>${p.changefreq}</changefreq>
    <priority>${p.priority}</priority>
  </url>`,
  ).join('\n');

  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${entries}
</urlset>
`;

  return new Response(body, {
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  });
};
