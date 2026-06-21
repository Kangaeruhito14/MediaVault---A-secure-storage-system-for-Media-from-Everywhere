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
  async put(key: string, body: Uint8Array | Blob, contentType = 'application/octet-stream'): Promise<void> {
    const headers = await this.signedFetchHeaders('PUT', key, { contentType });
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
