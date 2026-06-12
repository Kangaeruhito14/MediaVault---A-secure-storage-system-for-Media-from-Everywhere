import { randomUUID } from 'node:crypto';
import { getDb } from './db';
import { generateSessionToken, hashSessionToken } from './crypto';

export { isPasswordSet } from './vault';

/**
 * Sessions are random 256-bit tokens stored HASHED in SQLite, so they are
 * individually revocable: logout deletes the row, password change/reset wipes
 * the table, a restart keeps valid sessions but the vault itself stays sealed
 * until a password unlocks it. No signing secret exists to leak or misconfigure.
 */

const SESSION_DURATION_MS = 24 * 60 * 60 * 1000; // 24 h

// ── Session lifecycle ─────────────────────────────────────────────────────────

export function createSession(): string {
  const token = generateSessionToken();
  const now = Date.now();
  getDb()
    .prepare('INSERT INTO sessions (id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .run(randomUUID(), hashSessionToken(token), now, now + SESSION_DURATION_MS);
  // opportunistic cleanup of expired rows
  getDb().prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
  return token;
}

export function validateSession(token: string | undefined): boolean {
  if (!token) return false;
  const row = getDb()
    .prepare('SELECT expires_at FROM sessions WHERE token_hash = ?')
    .get(hashSessionToken(token)) as { expires_at: number } | undefined;
  return !!row && Date.now() < row.expires_at;
}

export function revokeSession(token: string | undefined): void {
  if (!token) return;
  getDb().prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashSessionToken(token));
}

/** Revoke every session — used on password change and recovery reset. */
export function revokeAllSessions(): void {
  getDb().prepare('DELETE FROM sessions').run();
}

// ── Request helpers ───────────────────────────────────────────────────────────

export function getSessionFromCookies(cookieHeader: string | null): string | undefined {
  if (!cookieHeader) return undefined;
  const match = cookieHeader.match(/(?:^|;\s*)mv_session=([^;]+)/);
  return match?.[1];
}

export function isAuthenticated(request: Request): boolean {
  return validateSession(getSessionFromCookies(request.headers.get('cookie')));
}

export function sessionCookie(token: string, request: Request): string {
  // Secure flag whenever the request arrived over TLS (directly or via proxy)
  const proto = request.headers.get('x-forwarded-proto') ?? new URL(request.url).protocol.replace(':', '');
  const secure = proto === 'https' ? '; Secure' : '';
  return `mv_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_DURATION_MS / 1000}${secure}`;
}

export function clearSessionCookie(): string {
  return 'mv_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0';
}

// ── Rate limiting ─────────────────────────────────────────────────────────────
// GLOBAL, persisted in SQLite. A single-owner vault has exactly one legitimate
// guesser — everyone else is an attacker — so limiting per-IP is pointless and
// trusting X-Forwarded-For (attacker-controlled) would be a bypass. Five failed
// attempts in 15 minutes locks the door for everyone, survives restarts.

const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

export function recordFailedAttempt(): { remaining: number; locked: boolean } {
  const db = getDb();
  const now = Date.now();
  db.prepare('INSERT INTO login_attempts (attempted_at) VALUES (?)').run(now);
  db.prepare('DELETE FROM login_attempts WHERE attempted_at < ?').run(now - LOCKOUT_MS);
  const { n } = db
    .prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE attempted_at >= ?')
    .get(now - LOCKOUT_MS) as { n: number };
  return { remaining: Math.max(0, MAX_ATTEMPTS - n), locked: n >= MAX_ATTEMPTS };
}

export function clearAttempts(): void {
  getDb().prepare('DELETE FROM login_attempts').run();
}

export function isRateLimited(): boolean {
  const { n } = getDb()
    .prepare('SELECT COUNT(*) AS n FROM login_attempts WHERE attempted_at >= ?')
    .get(Date.now() - LOCKOUT_MS) as { n: number };
  return n >= MAX_ATTEMPTS;
}
