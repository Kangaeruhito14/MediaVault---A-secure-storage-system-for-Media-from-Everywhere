/** S3-compatible ObjectStore (R2 / B2 / Wasabi / AWS S3), wrapping S3Client. */
import { S3Client, type S3Config } from './s3';
import type { ObjectStore } from './object-store';

export class S3Store implements ObjectStore {
  private client: S3Client;
  constructor(config: S3Config, fetchImpl?: (input: string, init?: RequestInit) => Promise<Response>) {
    this.client = new S3Client(config, fetchImpl);
  }
  async put(key: string, body: Uint8Array, contentType?: string): Promise<string> {
    await this.client.put(key, body, contentType);
    return key; // S3 keys are caller-chosen
  }
  get(key: string, range?: { start: number; end: number }): Promise<Response> {
    return this.client.get(key, range);
  }
  del(key: string): Promise<void> {
    return this.client.del(key);
  }
  test(): Promise<{ ok: boolean; error?: string }> {
    return this.client.testConnection();
  }
}
