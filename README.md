# Secret Media

A simple secure media vault that encrypts and stores your media files. Built with Node.js, Express and SQLite. Each post holds a title, description, tags and up to **20 media files**, browsed with a carousel.

## Security model

- Files encrypted at rest with **AES-256-GCM** (authenticated). Encryption/decryption is streamed, so plaintext never lands on disk.
- **Metadata is encrypted.** Title, description and tags are stored as AES-256-GCM ciphertext (`title_enc` / `desc_enc` / `tags_enc`) — the database holds no plaintext title/description/tags. They're decrypted only in memory to render.
- **Search is tags + date only.** Tags are searchable via a blind index (`search_index`) of keyed-hash trigram tokens — `HMAC(key, trigram)` — which prunes candidates server-side, then verifies the real substring against decrypted tags (so partial-tag substring search works). Date search runs as plain SQL on the unencrypted `created_at` (e.g. search `2026-05`). **Title and description are never indexed and are not searchable** — they stay fully encrypted.
- The AES key is derived **in the browser** from your passcode via **PBKDF2-HMAC-SHA256** (600,000 iterations) with a random salt. The passcode and key are never stored server-side — only a salt + an encrypted check token (`vault.json`). The server is stateless about your key.
- Encrypted files on disk have opaque random names — the original filename is never written anywhere (disk or DB).
- Login is stateless: the derived key is sent per request, no session tokens are stored.
- Hardening: strict Content-Security-Policy, security headers, upload size limit, and per-IP rate limiting on auth endpoints.

> ⚠️ **Blind-index leakage (tags only).** The trigram tokens are deterministic, so anyone who reads the database file can observe tag token frequency/co-occurrence patterns and infer *something* about your tags. Title and description leak nothing beyond ciphertext length, since they aren't indexed. `created_at` is plaintext (needed for date search). This is the inherent trade-off of searchable encryption — far better than plaintext, weaker than zero-leak.

> ⚠️ **Serve over HTTPS (or localhost).** The browser `crypto.subtle` API used for key derivation only works in a *secure context*. Over plain `http://` to a remote host it is unavailable and login will fail. Put a TLS reverse proxy (Caddy/nginx/Traefik) in front for remote use.

> ⚠️ Lose the passcode = lose the data. There is no recovery.

*I take no responsibility for any misuse of this software. Use at your own risk.*

## Get the code

```bash
git clone https://github.com/MrTigerST/secret-media.git
cd secret-media
```

## Run with Docker Compose

```bash
docker compose up -d --build
```

Open http://localhost:3000 and set a passcode on first launch.

All persistent state (SQLite DB, encrypted uploads, `vault.json`) lives in the `secret-media-data` named volume mounted at `/data`, so it survives container restarts and rebuilds.

### Configuration (env vars)

| Variable        | Default | Description                          |
| --------------- | ------- | ------------------------------------ |
| `PORT`          | `3000`  | Host port to expose                  |
| `DATA_DIR`      | `/data` | Where DB + uploads are stored        |
| `MAX_UPLOAD_MB` | `100`   | Max upload size per file (megabytes) |

Override at launch, e.g.:

```bash
PORT=8080 MAX_UPLOAD_MB=500 docker compose up -d --build
```

Stop / wipe:

```bash
docker compose down            # stop, keep data
docker compose down -v         # stop and delete the data volume
```

## Run locally (without Docker)

Requires Node.js >= 18.

```bash
npm install
npm start
```

Data is written to `./data` by default (override with `DATA_DIR`).
