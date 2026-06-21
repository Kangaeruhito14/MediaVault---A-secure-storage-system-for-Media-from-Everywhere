/**
 * Dropbox client that runs IN THE BROWSER. Encrypted bytes move directly between
 * the browser and the user's own Dropbox (scoped to the app folder); the operator
 * never sees them. Access tokens are refreshed in-browser using the PKCE refresh
 * token — no client secret and no operator round-trip is ever involved.
 *
 * - Files over Dropbox's single-shot limit are sent via an upload session
 *   (start / append / finish).
 * - Downloads honour HTTP Range, so the streaming Service Worker can fetch and
 *   decrypt only the bytes being watched.
 */
import { refreshDropboxToken, type DropboxTokens } from './dropbox-oauth';

export interface DropboxConfig {
  clientId: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number; // epoch ms
}

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

const CONTENT = 'https://content.dropboxapi.com/2';
const RPC = 'https://api.dropboxapi.com/2';
// Dropbox caps single-shot uploads at 150 MB; stay well under it.
const DEFAULT_SIMPLE_LIMIT = 140 * 1024 * 1024;
const DEFAULT_SESSION_CHUNK = 64 * 1024 * 1024;

/** Tuning seam — overridable so the session-upload path is testable with tiny data. */
export interface DropboxClientOptions {
  simpleLimit?: number;
  sessionChunk?: number;
}

/** App-folder paths are relative to the app root and must start with "/". */
function toPath(key: string): string {
  return key.startsWith('/') ? key : `/${key}`;
}

export class DropboxClient {
  private fetchImpl: FetchLike;
  private accessToken: string;
  private refreshToken?: string;
  private expiresAt?: number;
  private onTokenRefresh?: (t: DropboxTokens) => void;
  private simpleLimit: number;
  private sessionChunk: number;

  constructor(
    private cfg: DropboxConfig,
    fetchImpl?: FetchLike,
    onTokenRefresh?: (t: DropboxTokens) => void,
    opts: DropboxClientOptions = {},
  ) {
    this.fetchImpl = fetchImpl ?? (globalThis.fetch as FetchLike);
    this.accessToken = cfg.accessToken;
    this.refreshToken = cfg.refreshToken;
    this.expiresAt = cfg.expiresAt;
    this.onTokenRefresh = onTokenRefresh;
    this.simpleLimit = opts.simpleLimit ?? DEFAULT_SIMPLE_LIMIT;
    this.sessionChunk = opts.sessionChunk ?? DEFAULT_SESSION_CHUNK;
  }

  private async ensureFresh(): Promise<void> {
    if (!this.refreshToken) return; // nothing we can do; rely on 401-retry
    if (this.expiresAt && Date.now() < this.expiresAt - 60_000) return;
    await this.refresh();
  }

  private async refresh(): Promise<void> {
    if (!this.refreshToken) throw new Error('Dropbox session expired — please reconnect.');
    const t = await refreshDropboxToken(this.cfg.clientId, this.refreshToken, this.fetchImpl);
    this.accessToken = t.accessToken;
    this.expiresAt = t.expiresAt;
    if (t.refreshToken) this.refreshToken = t.refreshToken;
    this.onTokenRefresh?.(t);
  }

  /** Bearer-authed fetch, refreshing the token once on a 401. */
  private async authed(url: string, init: RequestInit, retry = true): Promise<Response> {
    await this.ensureFresh();
    const headers = new Headers(init.headers);
    headers.set('Authorization', `Bearer ${this.accessToken}`);
    const res = await this.fetchImpl(url, { ...init, headers });
    if (res.status === 401 && retry && this.refreshToken) {
      await this.refresh();
      return this.authed(url, init, false);
    }
    return res;
  }

  /** Upload ciphertext to the user's Dropbox. */
  async put(key: string, body: Uint8Array, _contentType?: string): Promise<void> {
    const path = toPath(key);
    if (body.length <= this.simpleLimit) {
      const res = await this.authed(`${CONTENT}/files/upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'Dropbox-API-Arg': JSON.stringify({ path, mode: 'overwrite', mute: true }),
        },
        body: body as BodyInit,
      });
      if (!res.ok) throw new Error(`Dropbox upload failed: ${res.status} ${await safeText(res)}`);
      return;
    }
    await this.sessionUpload(path, body);
  }

  /** Chunked upload session for files above the single-shot limit. */
  private async sessionUpload(path: string, body: Uint8Array): Promise<void> {
    const first = body.subarray(0, this.sessionChunk);
    const startRes = await this.authed(`${CONTENT}/files/upload_session/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'Dropbox-API-Arg': JSON.stringify({ close: false }),
      },
      body: first as BodyInit,
    });
    if (!startRes.ok) throw new Error(`Dropbox session start failed: ${startRes.status} ${await safeText(startRes)}`);
    const sessionId: string = (await startRes.json()).session_id;

    let offset = first.length;
    while (offset < body.length) {
      const chunk = body.subarray(offset, Math.min(offset + this.sessionChunk, body.length));
      const isLast = offset + chunk.length >= body.length;
      if (isLast) {
        const finRes = await this.authed(`${CONTENT}/files/upload_session/finish`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/octet-stream',
            'Dropbox-API-Arg': JSON.stringify({
              cursor: { session_id: sessionId, offset },
              commit: { path, mode: 'overwrite', mute: true },
            }),
          },
          body: chunk as BodyInit,
        });
        if (!finRes.ok) throw new Error(`Dropbox session finish failed: ${finRes.status} ${await safeText(finRes)}`);
      } else {
        const appRes = await this.authed(`${CONTENT}/files/upload_session/append_v2`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/octet-stream',
            'Dropbox-API-Arg': JSON.stringify({ cursor: { session_id: sessionId, offset }, close: false }),
          },
          body: chunk as BodyInit,
        });
        if (!appRes.ok) throw new Error(`Dropbox session append failed: ${appRes.status} ${await safeText(appRes)}`);
      }
      offset += chunk.length;
    }
  }

  /** Fetch ciphertext, optionally a byte range. Returns the raw Response. */
  async get(key: string, range?: { start: number; end: number }): Promise<Response> {
    const headers: Record<string, string> = {
      'Dropbox-API-Arg': JSON.stringify({ path: toPath(key) }),
    };
    if (range) headers['Range'] = `bytes=${range.start}-${range.end}`;
    const res = await this.authed(`${CONTENT}/files/download`, { method: 'POST', headers });
    if (!res.ok && res.status !== 206) throw new Error(`Dropbox download failed: ${res.status}`);
    return res;
  }

  async del(key: string): Promise<void> {
    const res = await this.authed(`${RPC}/files/delete_v2`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: toPath(key) }),
    });
    // 409 = path/not_found: already gone, treat as success.
    if (!res.ok && res.status !== 409) throw new Error(`Dropbox delete failed: ${res.status}`);
  }

  /** Validate the token + reachability by reading the account profile. */
  async testConnection(): Promise<{ ok: boolean; error?: string }> {
    try {
      const res = await this.authed(`${RPC}/users/get_current_account`, { method: 'POST' });
      if (res.ok) return { ok: true };
      return { ok: false, error: `Dropbox returned HTTP ${res.status} — try reconnecting.` };
    } catch (e) {
      return { ok: false, error: (e as Error).message || 'Dropbox connection failed.' };
    }
  }
}

async function safeText(res: Response): Promise<string> {
  try {
    return (await res.text()).slice(0, 200);
  } catch {
    return '';
  }
}
