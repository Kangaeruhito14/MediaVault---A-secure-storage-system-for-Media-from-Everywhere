# MediaVault Architecture (v3 — multi-user, end-to-end encrypted)

> Status: rebuild in progress on branch `rebuild/e2ee-multiuser`. This document
> is the source of truth for design decisions. We do not ship a claim until the
> feature behind it is real and verifiable.

## What MediaVault is

A multi-user, **end-to-end encrypted** media vault that acts as a **gateway** over
storage the user already owns. Files are encrypted in the user's browser and
stored in the user's own cloud. The operator runs only a thin control plane and
**never holds, sees, or can decrypt user media**.

## The trust model (client-side keys)

Adapted from the audited Bitwarden / Proton design — we follow the proven
pattern rather than invent cryptography.

1. **Sign up (in the browser):** the password is stretched with **Argon2id**
   into a *master key*. From it we derive:
   - a **login hash** sent to the server only to authenticate, and
   - an **encryption key** that never leaves the device.
2. A random **account key** is generated in the browser, wrapped by the
   encryption key, and only the *wrapped* form is sent to the server.
3. A one-time **recovery key** independently wraps the account key. It is the
   only password-reset path — true E2EE means the operator cannot reset it.
4. **Per file:** a random file key encrypts the file (chunked AES-GCM) in the
   browser; the file key is wrapped by the account key. Filenames and all
   metadata are encrypted too.

## Data boundary — what the operator stores vs never stores

| The operator stores (Cloudflare D1, all unreadable) | The operator NEVER stores |
|---|---|
| Account record: email, KDF salt/params, server-side hash of the login hash | Plaintext password |
| Wrapped account key (by password) + wrapped account key (by recovery key) | Account key in usable form |
| Encrypted file metadata index (name, size, type — ciphertext blobs) | Any media file bytes (plaintext or ciphertext) |
| Encrypted storage-connection config | Storage credentials in usable form |
| Session token hashes | Decryption keys of any kind |

**File bytes flow directly between the user's browser and the user's own
storage** (presigned/direct transfer). They never pass through or rest on the
operator's servers. This minimizes both attack surface and legal exposure: a
breach or legal demand against the operator yields only unreadable blobs.

## Storage providers (pluggable)

Users connect storage they control. Built behind a single `StorageProvider`
interface so providers are added without touching the rest of the app.

- **S3-compatible** (Cloudflare R2 / Backblaze B2 / Wasabi / AWS S3) — first
  reference implementation. Credentials stay encrypted client-side; the browser
  talks to the bucket directly (bucket CORS required).
- **Google Drive / Dropbox** (OAuth + PKCE, browser-only token flow) — planned,
  for mainstream ease. `drive.file` scope = app only sees files it created.
- **Local device** (File System Access API) — planned, single-device.

## Limits (protect the index + curb abuse; tunable)

- Max file size: **2 GB** (client-side chunked encryption; raised later with streaming).
- Max files per account: **50,000** (D1 friendliness).
- Total capacity is bounded by the user's own connected storage, not the operator.

## Security posture

- Strict CSP and security headers on every response.
- Turnstile on signup/login (bot/abuse protection).
- Per-account rate limiting (not global).
- Secure, httpOnly, SameSite session cookies; server-side revocable sessions.
- Server stores only ciphertext, wrapped keys, and hashes.
- `prefers-reduced-motion` respected; accessible by default.

## Honesty policy

No marketing copy claims a capability that is not shipped and verifiable. The
public `/security` page lets anyone watch the encryption work in their own
browser. "We cannot read your files" is stated only because the architecture
above makes it literally true.

## Tech stack

Astro (SSR) on **Cloudflare Workers** · **D1** (encrypted metadata) · **KV**
(sessions, rate limits) · Web Crypto + Argon2id (client-side) · Tailwind CSS.
Self-hosting via Node/Docker remains possible through the storage abstraction.
