/**
 * Bridge from Astro's request context to the server stores. Reads the
 * Cloudflare runtime bindings (D1 + KV) off `Astro.locals.runtime.env` and
 * wires up the concrete D1/KV-backed stores the auth service depends on.
 */
import type { APIContext } from 'astro';
import { D1AccountStore, D1SessionStore } from './stores';
import type { AccountStore, KVLike, SessionStore } from './types';

export interface ServerContext {
  accounts: AccountStore;
  sessions: SessionStore;
  kv: KVLike;
}

export function getServerContext(locals: APIContext['locals']): ServerContext {
  const env = locals.runtime?.env;
  if (!env?.DB || !env?.KV) {
    throw new Error('Cloudflare bindings (DB, KV) are not available in this context');
  }
  return {
    accounts: new D1AccountStore(env.DB),
    sessions: new D1SessionStore(env.DB),
    kv: env.KV as unknown as KVLike,
  };
}

/** Best-effort client IP for rate-limiting keys (Cloudflare sets this header). */
export function clientIp(request: Request): string {
  return request.headers.get('cf-connecting-ip') ?? 'local';
}
