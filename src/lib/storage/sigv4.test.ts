import { describe, it, expect } from 'vitest';
import { signV4, uriEncode } from './sigv4';
import { sha256Hex } from '../e2ee/crypto';

const te = new TextEncoder();

describe('SigV4 — official AWS get-vanilla test vector', () => {
  it('produces the documented signature', async () => {
    const emptyHash = await sha256Hex(te.encode('')); // e3b0c4...
    const res = await signV4({
      method: 'GET',
      path: '/',
      headers: {
        host: 'example.amazonaws.com',
        'x-amz-date': '20150830T123600Z',
      },
      payloadHash: emptyHash,
      region: 'us-east-1',
      service: 'service',
      accessKeyId: 'AKIDEXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      amzDate: '20150830T123600Z',
    });

    expect(res.signedHeaders).toBe('host;x-amz-date');
    expect(res.signature).toBe('5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
    expect(res.authorization).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, ' +
        'SignedHeaders=host;x-amz-date, ' +
        'Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31',
    );
  });
});

describe('uriEncode', () => {
  it('leaves unreserved characters and encodes the rest', () => {
    expect(uriEncode('abcXYZ0-9_.~', true)).toBe('abcXYZ0-9_.~');
    expect(uriEncode('a b+c', true)).toBe('a%20b%2Bc');
  });
  it('preserves or encodes slashes per flag', () => {
    expect(uriEncode('a/b', false)).toBe('a/b');
    expect(uriEncode('a/b', true)).toBe('a%2Fb');
  });
});
