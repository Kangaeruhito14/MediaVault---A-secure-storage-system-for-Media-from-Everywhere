/// <reference types="astro/client" />

// Cloudflare bindings (declared in wrangler.jsonc). In Astro v6 + adapter v13
// these are read via `import { env } from 'cloudflare:workers'` (the old
// Astro.locals.runtime.env was removed).
type D1Database = import('@cloudflare/workers-types').D1Database;
type KVNamespace = import('@cloudflare/workers-types').KVNamespace;

declare module 'cloudflare:workers' {
  export const env: {
    DB: D1Database;
    KV: KVNamespace;
  };
}
