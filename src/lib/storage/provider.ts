/**
 * StorageProvider — the contract every storage backend implements.
 *
 * Core principle: file bytes move DIRECTLY between the user's browser and the
 * user's own storage. The operator's server only issues short-lived transfer
 * targets (e.g. presigned URLs) or, for OAuth providers, the browser uses
 * client-held tokens. The server never streams, stores, or can read the bytes.
 *
 * All bytes handed to/received from a provider are already CIPHERTEXT —
 * encryption and decryption happen in the browser, above this layer.
 */

export type ProviderKind = 's3' | 'gdrive' | 'dropbox' | 'local';

/** Opaque, provider-specific configuration. Stored ENCRYPTED (client-wrapped). */
export interface ProviderConfig {
  kind: ProviderKind;
  /** Decrypted only in the browser; never logged, never sent in plaintext. */
  [key: string]: unknown;
}

/** A short-lived target the browser uses to upload ciphertext directly. */
export interface UploadTarget {
  url: string;
  method: 'PUT' | 'POST';
  headers?: Record<string, string>;
  /** Echo back the object key the caller should persist in the index. */
  objectKey: string;
  expiresAt: number;
}

/** A short-lived URL the browser uses to download ciphertext directly. */
export interface DownloadTarget {
  url: string;
  headers?: Record<string, string>;
  expiresAt: number;
}

export interface StorageProvider {
  readonly kind: ProviderKind;

  /** Validate that the connection works (e.g. can list/head the bucket). */
  test(config: ProviderConfig): Promise<{ ok: boolean; error?: string }>;

  /** Create a direct-upload target for one ciphertext object. */
  createUpload(config: ProviderConfig, objectKey: string, byteLength: number): Promise<UploadTarget>;

  /** Create a direct-download target, optionally for an HTTP byte range. */
  createDownload(
    config: ProviderConfig,
    objectKey: string,
    range?: { start: number; end: number },
  ): Promise<DownloadTarget>;

  /** Remove one object from the user's storage. */
  remove(config: ProviderConfig, objectKey: string): Promise<void>;
}

/** Limits enforced by the control plane (see docs/ARCHITECTURE.md). */
export const LIMITS = {
  MAX_FILE_BYTES: 2 * 1024 * 1024 * 1024, // 2 GB
  MAX_ITEMS_PER_ACCOUNT: 50_000,
  MAX_FOLDERS_PER_ACCOUNT: 500,
} as const;
