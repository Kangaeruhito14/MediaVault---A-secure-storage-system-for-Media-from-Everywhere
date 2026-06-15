import { describe, it, expect } from 'vitest';
import {
  b64encode,
  b64decode,
  timingSafeEqual,
  sha256Hex,
  deriveSubkey,
  generateKey,
  randomBytes,
  wrapKey,
  unwrapKey,
  encryptJson,
  decryptJson,
  encryptFile,
  decryptFile,
  decryptFileRange,
  parseFileHeader,
} from './crypto';

const bytes = (n: number) => new Uint8Array(Array.from({ length: n }, (_, i) => (i * 7 + 3) & 0xff));

describe('base64', () => {
  it('round-trips arbitrary bytes', () => {
    const b = randomBytes(257);
    expect(b64decode(b64encode(b))).toEqual(b);
  });
});

describe('timingSafeEqual', () => {
  it('true for equal, false for different / different length', () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });
});

describe('sha256', () => {
  it('matches the known empty-string vector', async () => {
    expect(await sha256Hex(new Uint8Array(0))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });
});

describe('HKDF deriveSubkey', () => {
  it('is deterministic and info-separated', async () => {
    const master = bytes(32);
    const a1 = await deriveSubkey(master, 'enc');
    const a2 = await deriveSubkey(master, 'enc');
    const b = await deriveSubkey(master, 'auth');
    expect(a1).toEqual(a2);
    expect(timingSafeEqual(a1, b)).toBe(false);
  });
});

describe('key wrapping', () => {
  it('round-trips', async () => {
    const key = generateKey();
    const wrap = generateKey();
    const blob = await wrapKey(key, wrap);
    expect(await unwrapKey(blob, wrap)).toEqual(key);
  });
  it('returns null for the wrong wrapping key', async () => {
    const blob = await wrapKey(generateKey(), generateKey());
    expect(await unwrapKey(blob, generateKey())).toBeNull();
  });
  it('returns null when the blob is tampered', async () => {
    const wrap = generateKey();
    const blob = await wrapKey(generateKey(), wrap);
    const raw = b64decode(blob);
    raw[raw.length - 1] ^= 0xff;
    expect(await unwrapKey(b64encode(raw), wrap)).toBeNull();
  });
});

describe('JSON metadata encryption', () => {
  it('round-trips an object', async () => {
    const key = generateKey();
    const meta = { name: 'beach 🏖️.jpg', mime: 'image/jpeg', size: 12345 };
    expect(await decryptJson(await encryptJson(meta, key), key)).toEqual(meta);
  });
  it('fails to decrypt with the wrong key', async () => {
    const blob = await encryptJson({ a: 1 }, generateKey());
    await expect(decryptJson(blob, generateKey())).rejects.toBeDefined();
  });
});

describe('chunked file encryption', () => {
  const key = generateKey();
  const CHUNK = 64; // tiny chunk to exercise boundaries

  for (const size of [0, 1, 63, 64, 65, 128, 200]) {
    it(`round-trips ${size} bytes across chunk boundaries`, async () => {
      const data = bytes(size);
      const ct = await encryptFile(data, key, CHUNK);
      expect(await decryptFile(ct, key)).toEqual(data);
    });
  }

  it('produces a parseable header', async () => {
    const ct = await encryptFile(bytes(100), key, CHUNK);
    const h = parseFileHeader(ct);
    expect(h.chunkSize).toBe(CHUNK);
    expect(h.baseNonce.length).toBe(8);
  });

  it('rejects a tampered chunk', async () => {
    const ct = await encryptFile(bytes(200), key, CHUNK);
    ct[ct.length - 5] ^= 0xff;
    await expect(decryptFile(ct, key)).rejects.toBeDefined();
  });

  it('rejects the wrong key', async () => {
    const ct = await encryptFile(bytes(200), key, CHUNK);
    await expect(decryptFile(ct, generateKey())).rejects.toBeDefined();
  });

  it('decryptFileRange returns the exact plaintext slice', async () => {
    const CHUNK2 = 64;
    const data = bytes(300);
    const ct = await encryptFile(data, key, CHUNK2);
    const header = parseFileHeader(ct);
    const body = ct.subarray(15); // header is 15 bytes
    const fetchChunks = async (lo: number, hi: number) => body.subarray(lo, hi + 1);

    for (const [start, end] of [[0, 9], [60, 130], [128, 128], [250, 299]] as const) {
      const slice = await decryptFileRange(header, key, start, end, fetchChunks);
      expect(slice).toEqual(data.subarray(start, end + 1));
    }
  });
});
