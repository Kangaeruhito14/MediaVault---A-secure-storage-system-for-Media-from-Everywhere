/**
 * Dropbox OAuth 2.0 with PKCE — runs entirely in the browser. No client secret
 * is ever used, so the user's Dropbox tokens never pass through (or get held by)
 * the operator. The gateway only ever stores them ENCRYPTED, wrapped by the
 * account key, exactly like the user's S3 credentials.
 */
import { generateCodeVerifier, codeChallenge, randomState } from './pkce';

const AUTH_URL = 'https://www.dropbox.com/oauth2/authorize';
const TOKEN_URL = 'https://api.dropboxapi.com/oauth2/token';

export interface DropboxTokens {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number; // epoch ms
}

export interface DropboxAuthStart {
  /** Consent URL to open (in a popup). */
  url: string;
  /** Anti-CSRF state — verify it matches on the callback. */
  state: string;
  /** PKCE verifier — needed to exchange the returned code. */
  verifier: string;
}

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** Build the consent URL plus the PKCE/state values to keep for the callback. */
export async function startDropboxAuth(clientId: string, redirectUri: string): Promise<DropboxAuthStart> {
  const verifier = generateCodeVerifier();
  const challenge = await codeChallenge(verifier);
  const state = randomState();
  const q = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    token_access_type: 'offline', // ask for a refresh token, not just a 4h access token
    state,
  });
  return { url: `${AUTH_URL}?${q.toString()}`, state, verifier };
}

function tokensFrom(json: {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
}): DropboxTokens {
  return {
    accessToken: json.access_token,
    refreshToken: json.refresh_token,
    expiresAt: json.expires_in ? Date.now() + json.expires_in * 1000 : undefined,
  };
}

/** Exchange the authorization code for tokens (PKCE; no secret). */
export async function exchangeDropboxCode(
  opts: { clientId: string; code: string; verifier: string; redirectUri: string },
  fetchImpl: FetchLike = fetch,
): Promise<DropboxTokens> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: opts.code,
    code_verifier: opts.verifier,
    client_id: opts.clientId,
    redirect_uri: opts.redirectUri,
  });
  const res = await fetchImpl(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!res.ok) throw new Error(`Dropbox token exchange failed: ${res.status}`);
  return tokensFrom(await res.json());
}

/**
 * Refresh an access token. Dropbox returns only a fresh access token; the
 * refresh token stays valid, so we carry it forward.
 */
export async function refreshDropboxToken(
  clientId: string,
  refreshToken: string,
  fetchImpl: FetchLike = fetch,
): Promise<DropboxTokens> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId,
  });
  const res = await fetchImpl(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!res.ok) throw new Error(`Dropbox token refresh failed: ${res.status}`);
  const t = tokensFrom(await res.json());
  if (!t.refreshToken) t.refreshToken = refreshToken;
  return t;
}
