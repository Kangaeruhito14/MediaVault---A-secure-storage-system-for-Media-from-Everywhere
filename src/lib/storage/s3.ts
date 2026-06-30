/**
 * S3-compatible client that runs IN THE BROWSER. It signs every request with
 * SigV4 using credentials the user provides — those credentials are stored only
 * as ciphertext the operator can't read, and requests go directly from the
 * browser to the user's own bucket. The operator never sees the bytes or the keys.
 *
 * Works with Cloudflare R2, Backblaze B2, Wasabi, and AWS S3 (path-style).
 * The user's bucket must allow CORS from the app origin.
 *
 * Payloads use `x-amz-content-sha256: UNSIGNED-PAYLOAD` — integrity is already
 * guaranteed by TLS in transit and our own AES-GCM at rest, so we skip hashing
 * multi-GB bodies for the signature.
 */
import { signV4, uriEncode } from './sigv4';
import { hasXhr, xhrUpload, type ProgressFn } from './http-upload';
import type { UploadWriter } from './object-store';

const te = new TextEncoder();

export interface S3Config {
  endpoint: string; // e.g. https://<acct>.r2.cloudflarestorage.com (no bucket, no trailing slash)
  region: string; // 'auto' for R2
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
}

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

const UNSIGNED = 'UNSIGNED-PAYLOAD';

export class S3Client {
  private fetchImpl: FetchLike;
  constructor(private cfg: S3Config, fetchImpl?: FetchLike) {
    // Wrap (don't assign) so fetch keeps the global as its receiver — calling
    // this.fetchImpl(...) with a bare global fetch throws "Illegal invocation".
    this.fetchImpl = fetchImpl ?? ((input, init) => globalThis.fetch(input, init));
  }

  private host(): string {
    return new URL(this.cfg.endpoint).host;
  }

  private urlFor(key: string, query?: Record<string, string>): string {
    const base =
      `${this.cfg.endpoint.replace(/\/$/, '')}/${uriEncode(this.cfg.bucket, false)}` +
      (key ? `/${uriEncode(key, false)}` : '');
    if (!query || Object.keys(query).length === 0) return base;
    const qs = Object.keys(query)
      .sort()
      .map((k) => `${uriEncode(k, true)}=${uriEncode(query[k], true)}`)
      .join('&');
    return `${base}?${qs}`;
  }

  /** Build SigV4 fetch headers. `host` is signed but not set on the request
   *  (browsers forbid setting Host — the browser sends the matching value). */
  private async signedFetchHeaders(
    method: string,
    key: string,
    opts: { contentType?: string; range?: string; query?: Record<string, string> } = {},
  ): Promise<Record<string, string>> {
    const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
    const signingHeaders: Record<string, string> = {
      host: this.host(),
      'x-amz-content-sha256': UNSIGNED,
      'x-amz-date': amzDate,
    };
    if (opts.contentType) signingHeaders['content-type'] = opts.contentType;
    if (opts.range) signingHeaders['range'] = opts.range;

    const { authorization } = await signV4({
      method,
      path: `/${this.cfg.bucket}${key ? '/' + key : ''}`,
      query: opts.query,
      headers: signingHeaders,
      payloadHash: UNSIGNED,
      region: this.cfg.region,
      service: 's3',
      accessKeyId: this.cfg.accessKeyId,
      secretAccessKey: this.cfg.secretAccessKey,
      amzDate,
    });

    const out: Record<string, string> = {
      authorization,
      'x-amz-content-sha256': UNSIGNED,
      'x-amz-date': amzDate,
    };
    if (opts.contentType) out['content-type'] = opts.contentType;
    if (opts.range) out['range'] = opts.range;
    return out; // note: no 'host' (browser sets it)
  }

  /** Upload ciphertext bytes to the user's bucket. */
  async put(
    key: string,
    body: Uint8Array | Blob,
    contentType = 'application/octet-stream',
    onProgress?: ProgressFn,
  ): Promise<void> {
    const headers = await this.signedFetchHeaders('PUT', key, { contentType });
    // Use XHR when a progress bar is requested (fetch can't report upload bytes).
    if (onProgress && hasXhr && body instanceof Uint8Array) {
      const r = await xhrUpload('PUT', this.urlFor(key), headers, body, onProgress);
      if (r.status < 200 || r.status >= 300) throw new Error(`S3 PUT failed: ${r.status} ${r.text.slice(0, 200)}`);
      return;
    }
    const res = await this.fetchImpl(this.urlFor(key), { method: 'PUT', headers, body: body as BodyInit });
    if (!res.ok) throw new Error(`S3 PUT failed: ${res.status} ${await safeText(res)}`);
  }

  /** Fetch ciphertext (optionally a byte range). Returns the raw Response so the
   *  caller can stream or read .arrayBuffer() before decrypting. */
  async get(key: string, range?: { start: number; end: number }): Promise<Response> {
    const rangeHeader = range ? `bytes=${range.start}-${range.end}` : undefined;
    const headers = await this.signedFetchHeaders('GET', key, { range: rangeHeader });
    const res = await this.fetchImpl(this.urlFor(key), { method: 'GET', headers });
    if (!res.ok && res.status !== 206) throw new Error(`S3 GET failed: ${res.status}`);
    return res;
  }

  async del(key: string): Promise<void> {
    const headers = await this.signedFetchHeaders('DELETE', key);
    const res = await this.fetchImpl(this.urlFor(key), { method: 'DELETE', headers });
    if (!res.ok && res.status !== 204) throw new Error(`S3 DELETE failed: ${res.status}`);
  }

  // ---- Multipart upload (streaming large files, never buffering the whole) ----

  /** Begin a multipart upload; returns the UploadId. */
  async createMultipart(key: string, contentType = 'application/octet-stream'): Promise<string> {
    const query = { uploads: '' };
    const headers = await this.signedFetchHeaders('POST', key, { query, contentType });
    const res = await this.fetchImpl(this.urlFor(key, query), { method: 'POST', headers });
    if (!res.ok) throw new Error(`S3 multipart init failed: ${res.status} ${await safeText(res)}`);
    const m = /<UploadId>([^<]+)<\/UploadId>/.exec(await res.text());
    if (!m) throw new Error('S3 multipart init: no UploadId in response');
    return m[1];
  }

  /** Upload one part (>= 5 MiB except the last); returns its ETag. */
  async uploadPart(key: string, uploadId: string, partNumber: number, body: Uint8Array): Promise<string> {
    const query = { partNumber: String(partNumber), uploadId };
    const headers = await this.signedFetchHeaders('PUT', key, { query });
    const res = await this.fetchImpl(this.urlFor(key, query), { method: 'PUT', headers, body: body as BodyInit });
    if (!res.ok) throw new Error(`S3 uploadPart ${partNumber} failed: ${res.status} ${await safeText(res)}`);
    const etag = res.headers.get('ETag') ?? res.headers.get('etag');
    if (!etag) throw new Error(`S3 uploadPart ${partNumber}: no ETag (bucket CORS must expose the ETag header)`);
    return etag;
  }

  /** Finish a multipart upload by listing the parts, in order. */
  async completeMultipart(
    key: string,
    uploadId: string,
    parts: { partNumber: number; etag: string }[],
  ): Promise<void> {
    const body = te.encode(
      '<CompleteMultipartUpload>' +
        parts.map((p) => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${p.etag}</ETag></Part>`).join('') +
        '</CompleteMultipartUpload>',
    );
    const query = { uploadId };
    const headers = await this.signedFetchHeaders('POST', key, { query, contentType: 'application/xml' });
    const res = await this.fetchImpl(this.urlFor(key, query), { method: 'POST', headers, body: body as BodyInit });
    if (!res.ok) throw new Error(`S3 complete failed: ${res.status} ${await safeText(res)}`);
    // S3 can return 200 with an <Error> body if finalize fails late.
    if ((await res.text()).includes('<Error>')) throw new Error('S3 complete returned an error body');
  }

  /** Discard a multipart upload so no orphaned parts are billed. */
  async abortMultipart(key: string, uploadId: string): Promise<void> {
    const query = { uploadId };
    const headers = await this.signedFetchHeaders('DELETE', key, { query });
    await this.fetchImpl(this.urlFor(key, query), { method: 'DELETE', headers });
  }

  /** A writer that streams a large object to the bucket as a multipart upload. */
  createWriter(key: string, contentType = 'application/octet-stream'): UploadWriter {
    return new S3UploadWriter(this, key, contentType);
  }

  /** Validate credentials + CORS by listing one object. */
  async testConnection(): Promise<{ ok: boolean; error?: string }> {
    try {
      const query = { 'list-type': '2', 'max-keys': '1' };
      const headers = await this.signedFetchHeaders('GET', '', { query });
      const res = await this.fetchImpl(this.urlFor('', query), { method: 'GET', headers });
      if (res.ok) return { ok: true };
      return { ok: false, error: `HTTP ${res.status} — check credentials, bucket, and CORS.` };
    } catch (e) {
      return { ok: false, error: (e as Error).message || 'Connection failed (often a CORS misconfiguration).' };
    }
  }
}

async function safeText(res: Response): Promise<string> {
  try {
    return (await res.text()).slice(0, 200);
  } catch {
    return '';
  }
}

/**
 * Buffers incoming ciphertext and flushes it as >= 5 MiB multipart parts, so a
 * multi-GB upload never sits whole in memory. If the object turns out smaller
 * than one part, close() falls back to a single PUT (cheaper, no multipart).
 */
class S3UploadWriter implements UploadWriter {
  private bufs: Uint8Array[] = [];
  private bufLen = 0;
  private uploadId: string | null = null;
  private partNumber = 0;
  private etags: { partNumber: number; etag: string }[] = [];
  private closed = false;
  private readonly flushAt = 8 * 1024 * 1024; // comfortably above S3's 5 MiB minimum

  constructor(
    private client: S3Client,
    private key: string,
    private contentType: string,
  ) {}

  async write(chunk: Uint8Array): Promise<void> {
    if (this.closed) throw new Error('S3UploadWriter: write after close');
    if (chunk.length) {
      this.bufs.push(chunk);
      this.bufLen += chunk.length;
    }
    while (this.bufLen >= this.flushAt) await this.flushPart(this.flushAt);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (this.uploadId === null) {
      // Never reached the multipart threshold — a single PUT is simpler/cheaper.
      await this.client.put(this.key, this.merged(), this.contentType);
      return;
    }
    if (this.bufLen > 0) await this.flushPart(this.bufLen); // final part, any size
    await this.client.completeMultipart(this.key, this.uploadId, this.etags);
  }

  async abort(): Promise<void> {
    this.closed = true;
    if (this.uploadId) {
      try {
        await this.client.abortMultipart(this.key, this.uploadId);
      } catch {
        /* best effort — abort failures shouldn't mask the original error */
      }
    }
    this.bufs = [];
    this.bufLen = 0;
  }

  private merged(): Uint8Array {
    if (this.bufs.length === 1) return this.bufs[0];
    const out = new Uint8Array(this.bufLen);
    let o = 0;
    for (const b of this.bufs) {
      out.set(b, o);
      o += b.length;
    }
    return out;
  }

  private async flushPart(n: number): Promise<void> {
    if (this.uploadId === null) this.uploadId = await this.client.createMultipart(this.key, this.contentType);
    const all = this.merged();
    const piece = all.subarray(0, n);
    const rest = all.subarray(n);
    this.bufs = rest.length ? [rest.slice()] : [];
    this.bufLen = rest.length;
    this.partNumber += 1;
    const etag = await this.client.uploadPart(this.key, this.uploadId, this.partNumber, piece);
    this.etags.push({ partNumber: this.partNumber, etag });
  }
}
