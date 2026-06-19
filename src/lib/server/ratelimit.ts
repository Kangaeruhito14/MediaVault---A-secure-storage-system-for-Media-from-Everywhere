/**
 * KV-backed rate limiter. Fixed window per key, TTL handles expiry. A small
 * read-modify-write race is acceptable for abuse throttling; for stricter
 * guarantees a Durable Object can replace this later without changing callers.
 */
import type { KVLike } from './types';

export async function checkRateLimit(
  kv: KVLike,
  key: string,
  limit: number,
  windowSec: number,
): Promise<{ allowed: boolean; remaining: number }> {
  const raw = await kv.get(key);
  const count = raw ? parseInt(raw, 10) || 0 : 0;
  if (count >= limit) return { allowed: false, remaining: 0 };
  await kv.put(key, String(count + 1), { expirationTtl: windowSec });
  return { allowed: true, remaining: limit - (count + 1) };
}

export async function resetRateLimit(kv: KVLike, key: string): Promise<void> {
  await kv.delete(key);
}
