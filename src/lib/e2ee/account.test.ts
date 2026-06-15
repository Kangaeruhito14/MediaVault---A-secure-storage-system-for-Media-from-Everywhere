import { describe, it, expect } from 'vitest';
import {
  createAccount,
  deriveAuthKey,
  unlockWithPassword,
  unlockWithRecovery,
  rewrapForNewPassword,
  encryptForUpload,
  decryptDownloaded,
  readMetadata,
  normalizeRecoveryKey,
  type KdfParams,
} from './account';
import { timingSafeEqual, sha256Hex } from './crypto';

// Fast KDF params for tests (production uses the stronger default).
const FAST: KdfParams = { m: 256, t: 1, p: 1 };
const enc = new TextEncoder();

describe('account lifecycle', () => {
  it('unlocks with the correct password and recovers the same account key', async () => {
    const acct = await createAccount('correct horse battery staple', FAST);

    const viaPassword = await unlockWithPassword(
      'correct horse battery staple',
      acct.secrets.kdfSalt,
      acct.secrets.kdfParams,
      acct.secrets.wrappedAccountKey,
    );
    expect(viaPassword).not.toBeNull();
    expect(timingSafeEqual(viaPassword!, acct.accountKey)).toBe(true);
  });

  it('rejects the wrong password', async () => {
    const acct = await createAccount('right-password-123', FAST);
    const wrong = await unlockWithPassword('wrong-password-123', acct.secrets.kdfSalt, acct.secrets.kdfParams, acct.secrets.wrappedAccountKey);
    expect(wrong).toBeNull();
  });

  it('recovers the account key with the recovery key', async () => {
    const acct = await createAccount('pw-abc-123', FAST);
    const recovered = await unlockWithRecovery(acct.recoveryKey, acct.secrets.recoverySalt, acct.secrets.wrappedAccountKeyRecovery);
    expect(recovered).not.toBeNull();
    expect(timingSafeEqual(recovered!, acct.accountKey)).toBe(true);
  });

  it('rejects a wrong recovery key', async () => {
    const acct = await createAccount('pw-abc-123', FAST);
    const bad = await unlockWithRecovery('0000-0000', acct.secrets.recoverySalt, acct.secrets.wrappedAccountKeyRecovery);
    expect(bad).toBeNull();
  });

  it('stores a recovery-key hash the server can verify', async () => {
    const acct = await createAccount('pw-abc-123', FAST);
    const expected = await sha256Hex(enc.encode(normalizeRecoveryKey(acct.recoveryKey)));
    expect(acct.secrets.recoveryKeyHash).toBe(expected);
  });

  it('derives a deterministic auth key for login', async () => {
    const acct = await createAccount('login-pw-456', FAST);
    const again = await deriveAuthKey('login-pw-456', acct.secrets.kdfSalt, acct.secrets.kdfParams);
    expect(again).toBe(acct.secrets.authKeyB64);
  });
});

describe('password reset via recovery key', () => {
  it('recovers, re-wraps under a new password, old password stops working', async () => {
    const acct = await createAccount('old-password-1', FAST);

    const accountKey = await unlockWithRecovery(acct.recoveryKey, acct.secrets.recoverySalt, acct.secrets.wrappedAccountKeyRecovery);
    expect(accountKey).not.toBeNull();

    const reset = await rewrapForNewPassword(accountKey!, 'new-password-2', FAST);

    // New password unlocks the SAME account key.
    const viaNew = await unlockWithPassword('new-password-2', reset.secrets.kdfSalt, reset.secrets.kdfParams, reset.secrets.wrappedAccountKey);
    expect(viaNew).not.toBeNull();
    expect(timingSafeEqual(viaNew!, acct.accountKey)).toBe(true);

    // Old password no longer unlocks the new blob.
    const viaOld = await unlockWithPassword('old-password-1', reset.secrets.kdfSalt, reset.secrets.kdfParams, reset.secrets.wrappedAccountKey);
    expect(viaOld).toBeNull();

    // New recovery key works; the old one is rotated out.
    const viaNewRecovery = await unlockWithRecovery(reset.recoveryKey, reset.secrets.recoverySalt, reset.secrets.wrappedAccountKeyRecovery);
    expect(viaNewRecovery).not.toBeNull();
    expect(timingSafeEqual(viaNewRecovery!, acct.accountKey)).toBe(true);
  });
});

describe('file encryption with the account key', () => {
  it('encrypts for upload and decrypts back, recovering metadata', async () => {
    const acct = await createAccount('file-pw-789', FAST);
    const plaintext = new Uint8Array(Array.from({ length: 5000 }, (_, i) => i & 0xff));
    const meta = { name: 'holiday video.mp4', mime: 'video/mp4', size: plaintext.length };

    const enc = await encryptForUpload(plaintext, meta, acct.accountKey);
    expect(enc.ciphertext.slice(0, 3)).toEqual(new Uint8Array([0x4d, 0x56, 0x31])); // "MV1"

    const back = await decryptDownloaded(enc.ciphertext, enc.wrappedFileKey, acct.accountKey);
    expect(back).toEqual(plaintext);

    expect(await readMetadata(enc.encMetadata, acct.accountKey)).toEqual(meta);
  });

  it('a different account cannot decrypt another account file', async () => {
    const a = await createAccount('aaa-111', FAST);
    const b = await createAccount('bbb-222', FAST);
    const enc = await encryptForUpload(new Uint8Array([1, 2, 3, 4]), { name: 'x', mime: 'application/octet-stream', size: 4 }, a.accountKey);
    await expect(decryptDownloaded(enc.ciphertext, enc.wrappedFileKey, b.accountKey)).rejects.toBeDefined();
  });
});
