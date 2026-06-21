import { describe, it, expect } from 'vitest';
import { S3Client, type S3Config } from './s3';

const cfg: S3Config = {
  endpoint: 'https://acct123.r2.cloudflarestorage.com',
  region: 'auto',
  bucket: 'my-vault',
  accessKeyId: 'AKIATESTKEY',
  secretAccessKey: 'secretsecretsecretsecretsecret123456',
};

// Capture the request the client would send, without touching the network.
function captureFetch() {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchImpl = async (url: string, init?: RequestInit) => {
    calls.push({ url, init: init ?? {} });
    return new Response('', { status: 200 });
  };
  return { calls, fetchImpl };
}

describe('S3Client request signing', () => {
  it('signs a PUT to the right URL with SigV4 + UNSIGNED-PAYLOAD, no host header', async () => {
    const { calls, fetchImpl } = captureFetch();
    const c = new S3Client(cfg, fetchImpl);
    await c.put('mv/abc.enc', new Uint8Array([1, 2, 3]));

    expect(calls).toHaveLength(1);
    const { url, init } = calls[0];
    expect(url).toBe('https://acct123.r2.cloudflarestorage.com/my-vault/mv/abc.enc');
    expect(init.method).toBe('PUT');
    const h = init.headers as Record<string, string>;
    expect(h.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIATESTKEY\/\d{8}\/auto\/s3\/aws4_request/);
    expect(h.authorization).toContain('Signature=');
    expect(h['x-amz-content-sha256']).toBe('UNSIGNED-PAYLOAD');
    expect(h['x-amz-date']).toMatch(/^\d{8}T\d{6}Z$/);
    expect(h.host).toBeUndefined(); // browser sets Host; we must not
  });

  it('sends a Range header on ranged GET', async () => {
    const { calls, fetchImpl } = captureFetch();
    const c = new S3Client(cfg, fetchImpl);
    await c.get('mv/abc.enc', { start: 100, end: 199 });
    const h = calls[0].init.headers as Record<string, string>;
    expect(h.range).toBe('bytes=100-199');
    expect(calls[0].init.method).toBe('GET');
  });

  it('builds a list query for testConnection', async () => {
    const { calls, fetchImpl } = captureFetch();
    const c = new S3Client(cfg, fetchImpl);
    const r = await c.testConnection();
    expect(r.ok).toBe(true);
    expect(calls[0].url).toBe('https://acct123.r2.cloudflarestorage.com/my-vault?list-type=2&max-keys=1');
  });

  it('reports a failed connection instead of throwing', async () => {
    const fetchImpl = async () => new Response('AccessDenied', { status: 403 });
    const c = new S3Client(cfg, fetchImpl);
    const r = await c.testConnection();
    expect(r.ok).toBe(false);
    expect(r.error).toContain('403');
  });

  it('invokes the global fetch with the correct receiver when none is injected', async () => {
    // Regression guard for the "Illegal invocation" bug (fetch called as a method).
    const orig = globalThis.fetch;
    let called = false;
    const guarded = function (this: unknown) {
      if (this !== undefined && this !== globalThis) throw new TypeError('Illegal invocation');
      called = true;
      return Promise.resolve(new Response('', { status: 200 }));
    };
    globalThis.fetch = guarded as typeof fetch;
    try {
      const c = new S3Client(cfg); // no fetchImpl → default path
      const r = await c.testConnection();
      expect(called).toBe(true);
      expect(r.ok).toBe(true);
    } finally {
      globalThis.fetch = orig;
    }
  });
});
