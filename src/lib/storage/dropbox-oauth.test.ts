import { describe, it, expect } from 'vitest';
import { startDropboxAuth, exchangeDropboxCode, refreshDropboxToken } from './dropbox-oauth';

describe('startDropboxAuth', () => {
  it('builds a PKCE consent URL requesting an offline refresh token', async () => {
    const a = await startDropboxAuth('appkey123', 'https://x.test/app/connect/dropbox');
    const u = new URL(a.url);
    expect(u.origin + u.pathname).toBe('https://www.dropbox.com/oauth2/authorize');
    expect(u.searchParams.get('client_id')).toBe('appkey123');
    expect(u.searchParams.get('response_type')).toBe('code');
    expect(u.searchParams.get('redirect_uri')).toBe('https://x.test/app/connect/dropbox');
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    expect(u.searchParams.get('token_access_type')).toBe('offline');
    expect(u.searchParams.get('state')).toBe(a.state);
    expect(u.searchParams.get('code_challenge')).toBeTruthy();
    expect(a.verifier.length).toBeGreaterThanOrEqual(43);
  });

  it('produces a fresh verifier and state each call', async () => {
    const a = await startDropboxAuth('k', 'https://x.test/cb');
    const b = await startDropboxAuth('k', 'https://x.test/cb');
    expect(a.verifier).not.toBe(b.verifier);
    expect(a.state).not.toBe(b.state);
  });
});

describe('exchangeDropboxCode', () => {
  it('posts the code + verifier with NO secret and returns tokens', async () => {
    let captured: { url: string; init: RequestInit } | null = null;
    const fetchImpl = async (url: string, init?: RequestInit) => {
      captured = { url, init: init ?? {} };
      return new Response(JSON.stringify({ access_token: 'at', refresh_token: 'rt', expires_in: 14400 }), {
        status: 200,
      });
    };
    const before = Date.now();
    const t = await exchangeDropboxCode(
      { clientId: 'appkey', code: 'thecode', verifier: 'theverifier', redirectUri: 'https://x.test/cb' },
      fetchImpl,
    );
    expect(captured!.url).toBe('https://api.dropboxapi.com/oauth2/token');
    const body = new URLSearchParams(captured!.init.body as string);
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('code')).toBe('thecode');
    expect(body.get('code_verifier')).toBe('theverifier');
    expect(body.get('client_id')).toBe('appkey');
    expect(body.has('client_secret')).toBe(false);
    expect(t.accessToken).toBe('at');
    expect(t.refreshToken).toBe('rt');
    expect(t.expiresAt!).toBeGreaterThanOrEqual(before + 14400 * 1000);
  });

  it('throws on a non-OK token response', async () => {
    const fetchImpl = async () => new Response('bad', { status: 400 });
    await expect(
      exchangeDropboxCode({ clientId: 'k', code: 'c', verifier: 'v', redirectUri: 'r' }, fetchImpl),
    ).rejects.toThrow(/400/);
  });
});

describe('refreshDropboxToken', () => {
  it('carries the existing refresh token forward when none is returned', async () => {
    const fetchImpl = async () =>
      new Response(JSON.stringify({ access_token: 'new', expires_in: 14400 }), { status: 200 });
    const t = await refreshDropboxToken('k', 'origRefresh', fetchImpl);
    expect(t.accessToken).toBe('new');
    expect(t.refreshToken).toBe('origRefresh');
  });
});
