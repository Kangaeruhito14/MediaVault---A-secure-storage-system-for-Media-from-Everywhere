/**
 * Storage-provider abstraction. The vault client and the streaming Service
 * Worker talk to this interface, not to any specific cloud — so S3-compatible,
 * Google Drive, and Dropbox can all back the same encrypted vault. Every byte
 * handed in/out is already ciphertext (encryption happens above this layer).
 */
import type { S3Config } from './s3';
import { S3Store } from './s3-store';

/** Discriminated config; stored ENCRYPTED (wrapped by the account key). */
export type ProviderConfig =
  | ({ kind: 's3' } & S3Config)
  | {
      kind: 'dropbox';
      clientId: string;
      accessToken: string;
      refreshToken?: string;
      expiresAt?: number; // epoch ms
    }
  | {
      kind: 'gdrive';
      clientId: string;
      accessToken: string;
      refreshToken?: string;
      expiresAt?: number;
      folderId?: string;
    };

export type ProviderKind = ProviderConfig['kind'];

export interface ObjectStore {
  /** Store ciphertext; returns the canonical object key/id to persist (for S3
   *  the given key, for Drive the assigned file id). */
  put(key: string, body: Uint8Array, contentType?: string): Promise<string>;
  /** Fetch ciphertext, optionally a byte range. */
  get(key: string, range?: { start: number; end: number }): Promise<Response>;
  del(key: string): Promise<void>;
  /** Validate the connection (credentials/token + reachability). */
  test(): Promise<{ ok: boolean; error?: string }>;
}

export function makeStore(config: ProviderConfig): ObjectStore {
  switch (config.kind) {
    case 's3':
      return new S3Store(config);
    default:
      // Drive/Dropbox stores are added in the consumer-cloud phase; until their
      // OAuth client IDs are configured the UI never offers them.
      throw new Error(`Storage provider "${(config as { kind: string }).kind}" is not available yet`);
  }
}
