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

  it('multipart: streams parts, completes in order, reassembles intact', async () => {
    // A faithful in-memory S3 multipart endpoint.
    const log: string[] = [];
    const parts = new Map<number, Uint8Array>();
    const objects = new Map<string, Uint8Array>();
    let completedOrder: number[] = [];
    let completedEtags: string[] = [];

    const fetchImpl = async (url: string, init?: RequestInit) => {
      const u = new URL(url);
      const q = u.searchParams;
      const method = init?.method ?? 'GET';
      const key = decodeURIComponent(u.pathname.replace('/my-vault/', ''));
      const body = init?.body ? new Uint8Array(init.body as ArrayBuffer) : new Uint8Array(0);

      if (method === 'POST' && q.has('uploads')) {
        log.push('initiate');
        return new Response('<InitiateMultipartUploadResult><UploadId>up-9</UploadId></InitiateMultipartUploadResult>', {
          status: 200,
        });
      }
      if (method === 'PUT' && q.has('partNumber')) {
        const pn = Number(q.get('partNumber'));
        expect(q.get('uploadId')).toBe('up-9');
        parts.set(pn, body.slice());
        log.push(`part:${pn}:${body.length}`);
        return new Response('', { status: 200, headers: { ETag: `"etag-${pn}"` } });
      }
      if (method === 'POST' && q.has('uploadId')) {
        const xml = new TextDecoder().decode(body);
        completedOrder = [...xml.matchAll(/<PartNumber>(\d+)<\/PartNumber>/g)].map((m) => Number(m[1]));
        completedEtags = [...xml.matchAll(/<ETag>([^<]+)<\/ETag>/g)].map((m) => m[1]);
        const assembled = new Uint8Array(completedOrder.reduce((n, pn) => n + parts.get(pn)!.length, 0));
        let o = 0;
        for (const pn of completedOrder) {
          assembled.set(parts.get(pn)!, o);
          o += parts.get(pn)!.length;
        }
        objects.set(key, assembled);
        log.push('complete');
        return new Response('<CompleteMultipartUploadResult/>', { status: 200 });
      }
      if (method === 'PUT') {
        objects.set(key, body.slice()); // simple-PUT fallback
        log.push('put');
        return new Response('', { status: 200 });
      }
      return new Response('', { status: 200 });
    };

    const c = new S3Client(cfg, fetchImpl);
    const writer = c.createWriter('mv/big.enc');

    // ~18 MiB of patterned bytes, fed in irregular chunks (like encrypted MV1 pieces).
    const TOTAL = 18 * 1024 * 1024 + 777;
    const src = new Uint8Array(TOTAL);
    for (let i = 0; i < TOTAL; i++) src[i] = (i * 31 + 7) & 0xff;
    for (let off = 0; off < TOTAL; off += 3_000_000) await writer.write(src.subarray(off, off + 3_000_000));
    await writer.close();

    expect(log[0]).toBe('initiate');
    expect(log.filter((l) => l.startsWith('part:'))).toHaveLength(3); // 8+8+~2 MiB
    expect(log[log.length - 1]).toBe('complete');
    expect(completedOrder).toEqual([1, 2, 3]); // parts listed in order
    expect(completedEtags).toEqual(['"etag-1"', '"etag-2"', '"etag-3"']);

    const out = objects.get('mv/big.enc')!;
    expect(out.length).toBe(TOTAL); // nothing lost or duplicated
    for (const i of [0, 8 * 1024 * 1024 - 1, 8 * 1024 * 1024, TOTAL - 1]) {
      expect(out[i]).toBe((i * 31 + 7) & 0xff); // boundary bytes intact
    }
  });

  it('multipart writer: falls back to a single PUT for sub-part content', async () => {
    const log: string[] = [];
    const fetchImpl = async (url: string, init?: RequestInit) => {
      log.push(`${init?.method}:${new URL(url).search}`);
      return new Response('', { status: 200 });
    };
    const c = new S3Client(cfg, fetchImpl);
    const writer = c.createWriter('mv/small.enc');
    await writer.write(new Uint8Array(1024)); // well under the 8 MiB part size
    await writer.close();
    expect(log).toEqual(['PUT:']); // one plain PUT, no ?uploads / multipart calls
  });

  it('multipart writer: abort cancels the upload session', async () => {
    const log: string[] = [];
    const fetchImpl = async (url: string, init?: RequestInit) => {
      const q = new URL(url).searchParams;
      if (init?.method === 'POST' && q.has('uploads'))
        return new Response('<InitiateMultipartUploadResult><UploadId>up-1</UploadId></InitiateMultipartUploadResult>', {
          status: 200,
        });
      if (init?.method === 'PUT') return new Response('', { status: 200, headers: { ETag: '"e1"' } });
      if (init?.method === 'DELETE') {
        log.push('abort');
        return new Response('', { status: 204 });
      }
      return new Response('', { status: 200 });
    };
    const c = new S3Client(cfg, fetchImpl);
    const writer = c.createWriter('mv/x.enc');
    await writer.write(new Uint8Array(9 * 1024 * 1024)); // forces a multipart session
    await writer.abort();
    expect(log).toContain('abort');
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
