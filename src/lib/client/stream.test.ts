import { describe, it, expect } from 'vitest';
import { encryptFile, parseFileHeader, generateKey } from '../e2ee/crypto';
import { fetchHeader, ciphertextSize, streamRange, type RangedGetter } from './stream';

// A fake bucket that serves ranged GETs over one encrypted object.
function fakeBucket(bytes: Uint8Array): RangedGetter {
  return {
    async get(_key, range) {
      const slice = range ? bytes.subarray(range.start, range.end + 1) : bytes;
      return new Response(slice);
    },
  };
}

const plain = (n: number) => new Uint8Array(Array.from({ length: n }, (_, i) => (i * 13 + 7) & 0xff));

describe('range streaming', () => {
  it('fetchHeader recovers chunk size + base nonce', async () => {
    const key = generateKey();
    const ct = await encryptFile(plain(300), key, 64);
    const h = await fetchHeader(fakeBucket(ct), 'k');
    expect(h.chunkSize).toBe(64);
    expect(h.baseNonce.length).toBe(8);
  });

  it('ciphertextSize matches the real encrypted length', async () => {
    const key = generateKey();
    for (const [size, chunk] of [[300, 64], [0, 64], [128, 64], [130, 64], [1000, 256]] as const) {
      const ct = await encryptFile(plain(size), key, chunk);
      expect(ciphertextSize(size, chunk)).toBe(ct.length);
    }
  });

  it('decrypts arbitrary plaintext ranges by fetching only the needed chunks', async () => {
    const key = generateKey();
    const data = plain(300);
    const ct = await encryptFile(data, key, 64);
    const bucket = fakeBucket(ct);
    const header = parseFileHeader(ct.subarray(0, 15));

    for (const [start, end] of [[0, 9], [60, 130], [128, 128], [250, 299], [0, 299]] as const) {
      const got = await streamRange(bucket, 'k', header, key, data.length, start, end);
      expect(Array.from(got)).toEqual(Array.from(data.subarray(start, end + 1)));
    }
  });

  it('clamps an over-long end to the file size', async () => {
    const key = generateKey();
    const data = plain(100);
    const ct = await encryptFile(data, key, 64);
    const header = parseFileHeader(ct.subarray(0, 15));
    const got = await streamRange(fakeBucket(ct), 'k', header, key, data.length, 80, 9999);
    expect(Array.from(got)).toEqual(Array.from(data.subarray(80, 100)));
  });
});
