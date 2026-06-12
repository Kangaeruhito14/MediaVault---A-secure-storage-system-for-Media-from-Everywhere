# MediaVault 🔐

**Free, self-hosted, encrypted media vault — your private Google Photos alternative.**

Store photos, videos, and audio on hardware *you* own. Every file is sealed with AES-256 encryption at rest, unlocked only by your password, and never touches anyone else's server.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Node.js ≥22.12](https://img.shields.io/badge/Node.js-%E2%89%A522.12-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![Built with Astro](https://img.shields.io/badge/Built_with-Astro_6-BC52EE?logo=astro&logoColor=white)](https://astro.build)
[![Zero native deps](https://img.shields.io/badge/native_dependencies-zero-success)](#why-mediavault)

---

## Why MediaVault?

| | MediaVault | Google Photos / iCloud | Immich / PhotoPrism |
|---|---|---|---|
| Your files on your hardware | ✅ | ❌ | ✅ |
| **Encrypted at rest (sealed vault)** | ✅ AES-256 by default | ⚠️ provider-held keys | ❌ plaintext on disk |
| No Docker / DB server needed | ✅ one Node process | — | ❌ usually required |
| Subscription cost | **$0 forever** | 💸 | $0 |
| Telemetry / scanning | None | Extensive | None |
| Recovery-key password reset | ✅ | account-based | varies |

**The sealed vault is the difference.** When the server stops — or you press *Lock Vault* — the master key is wiped from memory. Everything on disk is ciphertext. A stolen laptop, a seized server, a copied backup drive: all useless without your password or recovery key.

## Features

- 🔒 **Sealed-at-rest encryption** — per-file AES-256 keys, envelope-wrapped by a master key that only exists in memory while you're logged in
- 🎞️ **Encrypted streaming with instant seeking** — AES-256-CTR decrypts from any byte offset, so skipping through a movie answers HTTP Range requests in milliseconds
- 🔑 **Recovery-key reset** — forget your password and recover with a one-time 256-bit key; lose both and *nobody* can read your files (that's the point)
- 🛡️ **Hardened by default** — scrypt password hashing, revocable DB-backed sessions, global brute-force lockout that can't be bypassed with spoofed headers, magic-byte upload verification, strict security headers on every response
- ⬆️ **5 GB uploads** — streamed and encrypted chunk-by-chunk with flat memory use
- ⭐ Bookmarks, search, filters, bulk delete with 5-second undo, dark/light themes, fully responsive
- 🗃️ **Zero external dependencies** — metadata in SQLite via Node's built-in driver; no database server, no Docker required (but a Dockerfile is included if you want one)

## Quick start

Requires [Node.js 22.12+](https://nodejs.org).

```bash
git clone https://github.com/Kangaeruhito14/MediaVault---A-secure-storage-system-for-Media-from-Everywhere.git mediavault
cd mediavault
npm install
npm run dev          # development → http://localhost:4321
```

Production:

```bash
npm run build
npm start            # serves dist/ on http://localhost:4321
```

Docker:

```bash
docker build -t mediavault .
docker run -p 4321:4321 -v mv_data:/app/data -v mv_uploads:/app/uploads mediavault
```

First visit walks you through creating a password and shows your **recovery key exactly once** — print it and put it somewhere physically safe.

## Security model

```
password ──scrypt──▶ KEK ─────────┐
                                  ├──unwraps──▶ master key ──unwraps──▶ per-file keys
recovery key ──scrypt──▶ rKEK ────┘                 │
                                                    ▼
                              files encrypted with AES-256-CTR (seekable)
                              key-wraps use AES-256-GCM (tamper-evident)
```

- Passwords are stored only as scrypt hashes; sessions are random 256-bit tokens stored hashed in SQLite and individually revocable
- Changing your password re-wraps one key — your files are never re-encrypted
- Five failed logins lock the vault globally for 15 minutes, surviving restarts
- Uploads are verified against magic bytes; SVGs are never served inline; every response carries CSP, `nosniff`, `frame-ancestors 'none'`, and friends
- Report vulnerabilities: see `/.well-known/security.txt` or email **fantasyfalcoon91@gmail.com**

## Configuration (all optional)

Copy `.env.example` to `.env`:

| Variable | Purpose | Default |
|---|---|---|
| `PUBLIC_SITE_URL` | Canonical URL for SEO/sitemap | derived from request |
| `MEDIAVAULT_MAX_STORAGE` | Total vault quota in bytes | unlimited |
| `HOST` / `PORT` | Bind address / port | `127.0.0.1` / `4321` |

## Accessing from other devices

MediaVault binds to localhost by default. Options, safest first:

1. **VPN (recommended):** Tailscale or WireGuard — vault stays invisible to the internet
2. **LAN:** `HOST=0.0.0.0 npm start`, then visit `http://<machine-ip>:4321` from any device on your network
3. **Public:** put it behind a reverse proxy with HTTPS (Caddy makes this two lines); the session cookie automatically turns on its `Secure` flag behind TLS

## Backups

Copy two folders — that's the whole vault:

- `data/` — SQLite database (metadata + wrapped keys)
- `uploads/` — your media, already encrypted

Since `uploads/` is ciphertext, it's safe to back up to *any* untrusted disk or cloud. Without your password or recovery key it's noise.

## Migrating from MediaVault v1 (JSON storage)

```bash
MV_PASSWORD='your-vault-password' npm run migrate:legacy
```

Encrypts every existing file (with a decrypt-verify round-trip before any plaintext is deleted), moves metadata into SQLite, and prints a **new recovery key**.

## Tech stack

[Astro 6](https://astro.build) SSR · Node adapter · Tailwind CSS 4 · `node:sqlite` · `node:crypto` · Busboy — and nothing else.

## License

[AGPL-3.0](LICENSE) — free to use, self-host, and modify; if you run a modified version as a service, you must share your changes.
