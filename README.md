# Secret Media

A simple secure media vault that encrypts and stores your media files. Built with Node.js, Express and SQLite. Files are encrypted at rest with AES-256-GCM; the key is derived from your passcode and never stored on disk.

*I take no responsibility for any misuse of this software. Use at your own risk.*

## Run with Docker Compose

```bash
docker compose up -d --build
```

Open http://localhost:3000 and set a passcode on first launch.

All persistent state (SQLite DB, encrypted uploads, `keycheck.bin`) lives in the `secret-media-data` named volume mounted at `/data`, so it survives container restarts and rebuilds.

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
