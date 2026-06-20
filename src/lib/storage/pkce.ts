/**
 * OAuth 2.0 PKCE (RFC 7636) helpers — shared by the Dropbox and Google Drive
 * connectors. PKCE lets the token exchange happen entirely in the browser with
 * no client secret, so storage tokens never need to pass through (or be held
 * by) the operator.
 */
import { sha256 } from '../e2ee/crypto';

function base64url(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** A high-entropy code verifier (43 chars, URL-safe). */
export function generateCodeVerifier(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}

/** S256 challenge = base64url(SHA-256(ASCII(verifier))). */
export async function codeChallenge(verifier: string): Promise<string> {
  return base64url(await sha256(new TextEncoder().encode(verifier)));
}

/** Opaque anti-CSRF state value. */
export function randomState(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(16)));
}
