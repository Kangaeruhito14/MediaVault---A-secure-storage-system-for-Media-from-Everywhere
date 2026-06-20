/**
 * Bridge from the Cloudflare runtime to the server stores. In Astro v6 +
 * adapter v13, bindings come from the `cloudflare:workers` module (request-
 * scoped), not from Astro.locals.runtime.
 */
import { env } from 'cloudflare:workers';
import { D1AccountStore, D1SessionStore } from './stores';
import type { AccountStore, KVLike, SessionStore } from './types';

export interface ServerContext {
  accounts: AccountStore;
  sessions: SessionStore;
  kv: KVLike;
}

export function getServerContext(): ServerContext {
  const e = env as unknown as { DB?: unknown; KV?: unknown };
  if (!e?.DB || !e?.KV) {
    throw new Error('Cloudflare bindings (DB, KV) are not available in this context');
  }
  return {
    accounts: new D1AccountStore(e.DB as never),
    sessions: new D1SessionStore(e.DB as never),
    kv: e.KV as unknown as KVLike,
  };
}

/** Best-effort client IP for rate-limiting keys (Cloudflare sets this header). */
export function clientIp(request: Request): string {
  return request.headers.get('cf-connecting-ip') ?? 'local';
}
