/** Dropbox-backed ObjectStore, wrapping DropboxClient. */
import { DropboxClient, type DropboxConfig } from './dropbox';
import type { DropboxTokens } from './dropbox-oauth';
import type { ObjectStore, UploadWriter } from './object-store';

export class DropboxStore implements ObjectStore {
  private client: DropboxClient;
  constructor(
    config: DropboxConfig,
    fetchImpl?: (input: string, init?: RequestInit) => Promise<Response>,
    onTokenRefresh?: (t: DropboxTokens) => void,
  ) {
    this.client = new DropboxClient(config, fetchImpl, onTokenRefresh);
  }
  async put(
    key: string,
    body: Uint8Array,
    contentType?: string,
    onProgress?: (loaded: number, total: number) => void,
  ): Promise<string> {
    await this.client.put(key, body, contentType, onProgress);
    return key; // Dropbox keys are caller-chosen app-folder paths
  }
  createWriter(key: string): UploadWriter {
    return this.client.createWriter(key);
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
