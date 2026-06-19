/**
 * Shared KDF parameters — dependency-free so both the browser (account.ts,
 * which pulls in the Argon2id WASM) and the server (auth-service, which must
 * NOT bundle that WASM) can import them. Stored per-account so the cost can be
 * raised later without breaking existing accounts.
 */
export interface KdfParams {
  m: number; // memory in KiB
  t: number; // iterations
  p: number; // parallelism
}

// OWASP-leaning Argon2id defaults.
export const DEFAULT_KDF: KdfParams = { m: 19456, t: 2, p: 1 };
