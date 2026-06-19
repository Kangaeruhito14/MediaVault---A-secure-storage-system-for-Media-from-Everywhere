/// <reference types="astro/client" />

// Cloudflare runtime bindings (declared in wrangler.jsonc). Read via
// Astro.locals.runtime.env — D1 for the encrypted index, KV for rate limiting.
type D1Database = import('@cloudflare/workers-types').D1Database;
type KVNamespace = import('@cloudflare/workers-types').KVNamespace;

interface CloudflareEnv {
  DB: D1Database;
  KV: KVNamespace;
}

declare namespace App {
  interface Locals {
    runtime: {
      env: CloudflareEnv;
      cf?: unknown;
      ctx?: { waitUntil(promise: Promise<unknown>): void; passThroughOnException(): void };
    };
  }
}
