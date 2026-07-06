import { describe, it, expect } from 'vitest';
import {
  base32Encode,
  base32Decode,
  generateTotpSecret,
  totpCode,
  verifyTotp,
  otpauthUrl,
  generateBackupCodes,
} from './totp';

// RFC 6238 reference secret: ASCII "12345678901234567890" (20 bytes, SHA1).
const RFC_SECRET = base32Encode(new TextEncoder().encode('12345678901234567890'));

describe('base32', () => {
  it('round-trips arbitrary bytes', () => {
    const b = crypto.getRandomValues(new Uint8Array(23));
    expect([...base32Decode(base32Encode(b))]).toEqual([...b]);
  });
  it('ignores spaces/case when decoding', () => {
    const enc = base32Encode(new Uint8Array([1, 2, 3, 4, 5]));
    const spaced = enc.toLowerCase().match(/.{1,4}/g)!.join(' ');
    expect([...base32Decode(spaced)]).toEqual([...base32Decode(enc)]);
  });
});

describe('TOTP (RFC 6238 vectors, 6-digit)', () => {
  // Official 8-digit values truncated to the low 6 digits.
  const cases: [number, string][] = [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
  ];
  for (const [t, code] of cases) {
    it(`T=${t}s → ${code}`, async () => {
      expect(await totpCode(RFC_SECRET, t * 1000)).toBe(code);
    });
  }
});

describe('verifyTotp', () => {
  it('accepts the current code and tolerates ±1 step of skew', async () => {
    const t = 1111111109 * 1000;
    expect(await verifyTotp(RFC_SECRET, '081804', t)).toBe(true);
    // code from the previous 30s step is still accepted (window=1)
    const prev = await totpCode(RFC_SECRET, t - 30_000);
    expect(await verifyTotp(RFC_SECRET, prev, t)).toBe(true);
  });
  it('rejects a wrong / malformed code', async () => {
    const t = 1111111109 * 1000;
    expect(await verifyTotp(RFC_SECRET, '000000', t)).toBe(false);
    expect(await verifyTotp(RFC_SECRET, '12345', t)).toBe(false);
    expect(await verifyTotp(RFC_SECRET, 'abcdef', t)).toBe(false);
  });
  it('rejects a code two steps away (outside the window)', async () => {
    const t = 1111111109 * 1000;
    const far = await totpCode(RFC_SECRET, t + 90_000);
    expect(await verifyTotp(RFC_SECRET, far, t)).toBe(false);
  });
});

describe('secret + otpauth + backup codes', () => {
  it('generates a decodable 160-bit secret', () => {
    const s = generateTotpSecret();
    expect(base32Decode(s).length).toBe(20);
  });
  it('builds a scannable otpauth URL', () => {
    const url = otpauthUrl('JBSWY3DPEHPK3PXP', 'user@example.com');
    expect(url).toMatch(/^otpauth:\/\/totp\/Media%20Reservoir%3Auser%40example\.com\?/);
    expect(url).toContain('secret=JBSWY3DPEHPK3PXP');
    expect(url).toContain('issuer=Media+Reservoir');
  });
  it('mints 8 distinct xxxx-xxxx backup codes', () => {
    const codes = generateBackupCodes();
    expect(codes).toHaveLength(8);
    expect(new Set(codes).size).toBe(8);
    for (const c of codes) expect(c).toMatch(/^[a-z2-7]{4}-[a-z2-7]{4}$/);
  });
});
