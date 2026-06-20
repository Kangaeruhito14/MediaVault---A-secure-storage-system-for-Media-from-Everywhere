import { describe, it, expect } from 'vitest';
import { generateCodeVerifier, codeChallenge, randomState } from './pkce';

describe('PKCE', () => {
  it('matches the RFC 7636 S256 test vector', async () => {
    // From RFC 7636 Appendix B.
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(await codeChallenge(verifier)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('generates URL-safe verifiers and unique states', () => {
    const v = generateCodeVerifier();
    expect(v).toMatch(/^[A-Za-z0-9\-_]+$/);
    expect(v.length).toBeGreaterThanOrEqual(43);
    expect(randomState()).not.toBe(randomState());
  });
});
