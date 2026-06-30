/**
 * Bridge from the Cloudflare runtime to the server stores. In Astro v6 +
 * adapter v13, bindings come from the `cloudflare:workers` module (request-
 * scoped), not from Astro.locals.runtime.
 */
import { env } from 'cloudflare:workers';
import { D1AccountStore, D1SessionStore, D1StorageConnectionStore, D1TotpStore, D1VaultItemStore } from './stores';
import { validateSession } from './auth-service';
import { SESSION_COOKIE } from './http';
import type { AccountStore, KVLike, SessionStore, StorageConnectionStore, TotpStore, VaultItemStore } from './types';

export interface ServerContext {
  accounts: AccountStore;
  sessions: SessionStore;
  items: VaultItemStore;
  connections: StorageConnectionStore;
  totp: TotpStore;
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
    items: new D1VaultItemStore(e.DB as never),
    connections: new D1StorageConnectionStore(e.DB as never),
    totp: new D1TotpStore(e.DB as never),
    kv: e.KV as unknown as KVLike,
  };
}

/** A coarse, human-readable device label from the User-Agent (best effort). */
export function deviceLabel(request: Request): string {
  const ua = request.headers.get('user-agent') ?? '';
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\/|Opera/.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox'
    : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad|iOS/.test(ua) ? 'iOS' : /Mac OS X/.test(ua) ? 'macOS'
    : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : '';
  return os ? `${browser} · ${os}` : browser;
}

/** Resolve the logged-in account id from the session cookie, or null. */
export async function requireAccountId(
  ctx: ServerContext,
  cookies: { get(name: string): { value: string } | undefined },
): Promise<string | null> {
  const session = await validateSession(ctx.sessions, cookies.get(SESSION_COOKIE)?.value);
  return session?.accountId ?? null;
}

/** Best-effort client IP for rate-limiting keys (Cloudflare sets this header). */
export function clientIp(request: Request): string {
  return request.headers.get('cf-connecting-ip') ?? 'local';
}
