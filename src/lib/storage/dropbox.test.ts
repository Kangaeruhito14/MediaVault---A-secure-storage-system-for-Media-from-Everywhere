import { describe, it, expect } from 'vitest';
import { DropboxClient, type DropboxConfig } from './dropbox';

const cfg: DropboxConfig = {
  clientId: 'appkey',
  accessToken: 'access-1',
  refreshToken: 'refresh-1',
  expiresAt: Date.now() + 3_600_000,
};

function captureFetch(responder?: (url: string, init: RequestInit, n: number) => Response) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchImpl = async (url: string, init?: RequestInit) => {
    const i = init ?? {};
    calls.push({ url, init: i });
    return responder ? responder(url, i, calls.length) : new Response('{}', { status: 200 });
  };
  return { calls, fetchImpl };
}

function headers(init: RequestInit): Record<string, string> {
  const h = new Headers(init.headers);
  const out: Record<string, string> = {};
  h.forEach((v, k) => (out[k] = v));
  return out;
}

describe('DropboxClient', () => {
  it('uploads small files via files/upload using the app-folder path', async () => {
    const { calls, fetchImpl } = captureFetch();
    const c = new DropboxClient(cfg, fetchImpl);
    await c.put('mv/abc.enc', new Uint8Array([1, 2, 3]));
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://content.dropboxapi.com/2/files/upload');
    const h = headers(calls[0].init);
    expect(h['authorization']).toBe('Bearer access-1');
    expect(h['content-type']).toBe('application/octet-stream');
    const arg = JSON.parse(h['dropbox-api-arg']);
    expect(arg.path).toBe('/mv/abc.enc');
    expect(arg.mode).toBe('overwrite');
  });

  it('sends a Range header on a ranged download', async () => {
    const { calls, fetchImpl } = captureFetch(() => new Response('x', { status: 206 }));
    const c = new DropboxClient(cfg, fetchImpl);
    await c.get('mv/abc.enc', { start: 10, end: 19 });
    expect(calls[0].url).toBe('https://content.dropboxapi.com/2/files/download');
    const h = headers(calls[0].init);
    expect(h['range']).toBe('bytes=10-19');
    expect(JSON.parse(h['dropbox-api-arg']).path).toBe('/mv/abc.enc');
  });

  it('treats a 409 (not found) delete as success', async () => {
    const { fetchImpl } = captureFetch(() => new Response('path/not_found', { status: 409 }));
    const c = new DropboxClient(cfg, fetchImpl);
    await expect(c.del('mv/gone.enc')).resolves.toBeUndefined();
  });

  it('refreshes the token once on a 401 and retries with the new token', async () => {
    const { calls, fetchImpl } = captureFetch((url, _init, n) => {
      if (url.endsWith('/oauth2/token')) {
        return new Response(JSON.stringify({ access_token: 'access-2', expires_in: 14400 }), { status: 200 });
      }
      return new Response('', { status: n === 1 ? 401 : 200 });
    });
    const c = new DropboxClient(cfg, fetchImpl);
    await c.put('mv/x.enc', new Uint8Array([9]));
    expect(calls.some((cl) => cl.url.endsWith('/oauth2/token'))).toBe(true);
    const retry = calls[calls.length - 1];
    expect(headers(retry.init)['authorization']).toBe('Bearer access-2');
  });

  it('proactively refreshes an expired token before the request', async () => {
    const expired: DropboxConfig = { ...cfg, accessToken: 'old', expiresAt: Date.now() - 1000 };
    const { calls, fetchImpl } = captureFetch((url) =>
      url.endsWith('/oauth2/token')
        ? new Response(JSON.stringify({ access_token: 'fresh', expires_in: 14400 }), { status: 200 })
        : new Response('', { status: 200 }),
    );
    const c = new DropboxClient(expired, fetchImpl);
    await c.put('mv/x.enc', new Uint8Array([1]));
    expect(calls[0].url).toBe('https://api.dropboxapi.com/oauth2/token'); // refresh happens first
    expect(headers(calls[1].init)['authorization']).toBe('Bearer fresh');
  });

  it('reports a failed testConnection instead of throwing', async () => {
    const { fetchImpl } = captureFetch(() => new Response('', { status: 401 }));
    const c = new DropboxClient({ ...cfg, refreshToken: undefined }, fetchImpl);
    const r = await c.testConnection();
    expect(r.ok).toBe(false);
  });

  it('uploads large files via a start/append/finish session and reassembles correctly', async () => {
    const stored = new Map<string, Uint8Array>();
    const sessions = new Map<string, Uint8Array[]>();
    const bytesOf = async (b: unknown) => new Uint8Array(await new Response((b ?? new Uint8Array()) as BodyInit).arrayBuffer());
    const fetchImpl = async (url: string, init?: RequestInit) => {
      const h = new Headers((init ?? {}).headers);
      const arg = h.get('dropbox-api-arg') ? JSON.parse(h.get('dropbox-api-arg')!) : {};
      const chunk = await bytesOf((init ?? {}).body);
      if (url.endsWith('/upload_session/start')) { sessions.set('s1', [chunk]); return new Response(JSON.stringify({ session_id: 's1' }), { status: 200 }); }
      if (url.endsWith('/upload_session/append_v2')) { sessions.get(arg.cursor.session_id)!.push(chunk); return new Response('{}', { status: 200 }); }
      if (url.endsWith('/upload_session/finish')) {
        const parts = sessions.get(arg.cursor.session_id)!; parts.push(chunk);
        const total = parts.reduce((n, p) => n + p.length, 0);
        const out = new Uint8Array(total); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
        stored.set(arg.commit.path, out);
        return new Response('{}', { status: 200 });
      }
      return new Response('{}', { status: 200 });
    };
    // simpleLimit 4 forces a session for a 10-byte body; chunks of 4 ⇒ start(4)+append(4)+finish(2).
    const c = new DropboxClient(cfg, fetchImpl, undefined, { simpleLimit: 4, sessionChunk: 4 });
    const data = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    await c.put('mv/big.enc', data);
    expect(Array.from(stored.get('/mv/big.enc')!)).toEqual(Array.from(data));
  });
});
