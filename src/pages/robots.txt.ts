import type { APIRoute } from 'astro';

/**
 * robots.txt — tuned for BOTH classic SEO and AI visibility (GEO/AEO).
 *
 * We explicitly WELCOME AI crawlers (most sites block them). Media Reservoir WANTS
 * to be read, summarized, and cited by ChatGPT, Claude, Gemini, Perplexity,
 * Grok, and friends — that is how new users discover a privacy tool today.
 * The app interior (/vault, /api, /login) stays disallowed for everyone.
 */
const AI_BOTS = [
  'GPTBot',            // OpenAI training
  'OAI-SearchBot',     // ChatGPT Search
  'ChatGPT-User',      // ChatGPT live browsing
  'ClaudeBot',         // Anthropic training
  'Claude-Web',        // Claude browsing
  'anthropic-ai',      // Anthropic
  'Claude-SearchBot',  // Claude search
  'PerplexityBot',     // Perplexity index
  'Perplexity-User',   // Perplexity live fetch
  'Google-Extended',   // Gemini / Vertex grounding
  'Applebot-Extended', // Apple Intelligence
  'Amazonbot',         // Alexa / Amazon
  'Bytespider',        // TikTok / Doubao
  'CCBot',             // Common Crawl (feeds many models)
  'cohere-ai',         // Cohere
  'Diffbot',           // Diffbot KG
  'Meta-ExternalAgent',// Meta AI
  'meta-externalagent',
  'DuckAssistBot',     // DuckDuckGo AI
  'YouBot',            // You.com
  'Timpibot',          // Timpi
];

export const GET: APIRoute = ({ url }) => {
  const origin = import.meta.env.PUBLIC_SITE_URL?.replace(/\/$/, '') || url.origin;

  const aiBlocks = AI_BOTS.map(
    (bot) => `User-agent: ${bot}
Allow: /
Disallow: /vault
Disallow: /api/
Disallow: /login
`,
  ).join('\n');

  const body = `# Media Reservoir (Open Media Vault) — robots.txt
# Classic crawlers + AI assistants are all welcome on the public site.

User-agent: *
Allow: /
Disallow: /vault
Disallow: /api/
Disallow: /login

${aiBlocks}
# AI content map (llmstxt.org standard)
# ${origin}/llms.txt

Sitemap: ${origin}/sitemap.xml
`;

  return new Response(body, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  });
};
