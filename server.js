const express = require("express");
const multer = require("multer");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const crypto = require("crypto");
const { pipeline } = require("stream");
const { encryptBuffer, decryptBuffer } = require("./encrypt");
const { encField, decField, tokenize, NGRAM } = require("./metacrypto");
const { DATA_DIR, stmts, createMedia, candidateIds, db } = require("./db");

const PORT = process.env.PORT || 3000;
const MAX_UPLOAD_MB = parseInt(process.env.MAX_UPLOAD_MB || "100", 10);
const PER_PAGE = 10;
const TITLE_MAX = 200;
const DESC_MAX = 7000;
const MAX_TAGS = 15;
const MAX_FILES = 20;
const TAG_LEN = 16; // AES-GCM auth tag bytes
const KDF_MIN_ITER = 100000; // reject clients trying to weaken their own vault
const KDF_MAX_ITER = 10000000;

const uploadsDir = path.join(DATA_DIR, "uploads", "encrypted");
const vaultPath = path.join(DATA_DIR, "vault.json");
fs.mkdirSync(uploadsDir, { recursive: true });

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

// Security headers. script-src 'self' = no inline JS (blocks injected scripts).
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; img-src 'self' blob:; " +
      "media-src 'self' blob:; style-src 'self' 'unsafe-inline'; " +
      "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  next();
});

// ---- In-memory rate limiter (per IP, sliding window). No dependency. ----
const hits = new Map();
function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const now = Date.now();
    const arr = (hits.get(req.ip) || []).filter((t) => now - t < windowMs);
    if (arr.length >= max) {
      return res.status(429).json({ error: "too_many_attempts" });
    }
    arr.push(now);
    hits.set(req.ip, arr);
    next();
  };
}
// Prune idle IPs periodically so the map can't grow unbounded.
setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of hits) {
    if (arr.every((t) => now - t > 60000)) hits.delete(ip);
  }
}, 60000).unref();

const authLimit = rateLimit(10, 60000); // 10 attempts / minute / IP

// ---- Vault (KDF params + keycheck), cached in memory. ----
let vaultCache;
function loadVault() {
  if (vaultCache === undefined) {
    vaultCache = fs.existsSync(vaultPath)
      ? JSON.parse(fs.readFileSync(vaultPath, "utf8"))
      : null;
  }
  return vaultCache;
}

// Validate a 32-byte hex key against the vault keycheck. Returns key or null.
function verifyKey(hexHash) {
  const vault = loadVault();
  if (!vault || !hexHash) return null;
  let key;
  try {
    key = Buffer.from(hexHash, "hex");
  } catch {
    return null;
  }
  if (key.length !== 32) return null;
  try {
    const data = Buffer.from(vault.keycheck, "hex");
    const iv = data.subarray(0, 12);
    const tag = data.subarray(data.length - TAG_LEN);
    const enc = data.subarray(12, data.length - TAG_LEN);
    return decryptBuffer(enc, iv, tag, key).toString() === "VALID_KEY"
      ? key
      : null;
  } catch {
    return null;
  }
}

function auth(req, res, next) {
  const key = verifyKey(req.headers["x-passcode"]);
  if (!key) return res.status(401).json({ error: "invalid_passcode" });
  req.aesKey = key;
  next();
}

// ---- Streaming multer storage: file -> AES-GCM cipher -> disk. ----
// Plaintext never touches disk; original filename never stored.
const storage = {
  _handleFile(req, file, cb) {
    const key = req.aesKey;
    if (!key) return cb(new Error("no_key"));
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const savePath = path.join(
      uploadsDir,
      crypto.randomBytes(16).toString("hex") + ".enc"
    );
    const out = fs.createWriteStream(savePath);
    pipeline(file.stream, cipher, out, (err) => {
      if (err) return cb(err);
      // Append the GCM auth tag after the ciphertext.
      fs.appendFile(savePath, cipher.getAuthTag(), (e) => {
        if (e) return cb(e);
        cb(null, { path: savePath, iv: iv.toString("hex") });
      });
    });
  },
  _removeFile(req, file, cb) {
    fs.unlink(file.path, () => cb());
  },
};
const uploadMw = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: MAX_FILES },
}).array("file", MAX_FILES);

// ---- Routes ----
app.get("/api/status", (req, res) => {
  const vault = loadVault();
  res.json(
    vault
      ? { passcodeSet: true, salt: vault.salt, iterations: vault.iterations }
      : { passcodeSet: false }
  );
});

app.post("/api/set-passcode", authLimit, (req, res) => {
  const { salt, iterations, code_hash } = req.body || {};
  if (loadVault()) return res.status(400).json({ error: "already_set" });

  const iter = parseInt(iterations, 10);
  const saltOk = typeof salt === "string" && /^[0-9a-f]{32}$/i.test(salt);
  const iterOk = Number.isInteger(iter) && iter >= KDF_MIN_ITER && iter <= KDF_MAX_ITER;
  let key;
  try {
    key = Buffer.from(code_hash, "hex");
  } catch {
    key = Buffer.alloc(0);
  }
  if (!saltOk || !iterOk || key.length !== 32) {
    return res.status(400).json({ error: "invalid_params" });
  }

  const { encrypted, iv, tag } = encryptBuffer(Buffer.from("VALID_KEY"), key);
  const keycheck = Buffer.concat([iv, encrypted, tag]).toString("hex");
  const vault = { kdf: "PBKDF2-SHA256", iterations: iter, salt, keycheck };
  fs.writeFileSync(vaultPath, JSON.stringify(vault));
  vaultCache = vault;
  res.json({ success: true });
});

app.post("/api/auth-check", authLimit, (req, res) => {
  const { code_hash } = req.body || {};
  if (!loadVault()) return res.status(400).json({ error: "no_key_set" });
  if (!verifyKey(code_hash)) {
    return res.status(401).json({ error: "invalid_passcode" });
  }
  res.json({ success: true });
});

app.post("/api/upload", auth, (req, res) => {
  uploadMw(req, res, (err) => {
    const files = req.files || []; // 0..MAX_FILES
    const cleanup = () => files.forEach((f) => fs.unlink(f.path, () => {}));

    if (err) {
      cleanup();
      const code = err.code === "LIMIT_FILE_SIZE" ? 413 : 400;
      const error =
        err.code === "LIMIT_FILE_SIZE"
          ? "file_too_large"
          : err.code === "LIMIT_FILE_COUNT" || err.code === "LIMIT_UNEXPECTED_FILE"
          ? "too_many_files"
          : "upload_failed";
      return res.status(code).json({ error });
    }

    const { title, description, tags } = req.body;

    if (!title) {
      cleanup();
      return res.status(400).json({ error: "missing_title" });
    }
    if (title.length > TITLE_MAX) {
      cleanup();
      return res.status(400).json({ error: "title_too_long" });
    }
    if ((description || "").length > DESC_MAX) {
      cleanup();
      return res.status(400).json({ error: "description_too_long" });
    }
    if (files.length > MAX_FILES) {
      cleanup();
      return res.status(400).json({ error: "too_many_files" });
    }

    const tagList = (tags || "")
      .split(",")
      .map((t) => t.trim().toLowerCase())
      .filter(Boolean);
    if (tagList.length > MAX_TAGS) {
      cleanup();
      return res.status(400).json({ error: "too_many_tags" });
    }

    try {
      const key = req.aesKey;
      // Only tags are indexed for search; title/description stay fully encrypted.
      const tokens = tokenize(tagList.join("\n"), key);
      const id = createMedia(
        {
          title_enc: encField(title, key),
          desc_enc: encField(description || "", key),
          tags_enc: tagList.length ? encField(JSON.stringify(tagList), key) : "",
        },
        tokens,
        files
      );
      res.json({ success: true, id: Number(id) });
    } catch (e) {
      cleanup();
      console.error("DB error:", e);
      res.status(500).json({ error: "db_error" });
    }
  });
});

app.post("/api/file/:fileId", auth, async (req, res) => {
  const row = stmts.getFileById.get(req.params.fileId);
  if (!row || !row.encrypted_path) {
    return res.status(404).json({ error: "not_found" });
  }

  try {
    const stat = await fsp.stat(row.encrypted_path);
    if (stat.size < TAG_LEN) throw new Error("corrupt");
    const cipherLen = stat.size - TAG_LEN;

    // Read the auth tag (last 16 bytes) so it can be set before final().
    const fh = await fsp.open(row.encrypted_path, "r");
    const tagBuf = Buffer.alloc(TAG_LEN);
    await fh.read(tagBuf, 0, TAG_LEN, cipherLen);
    await fh.close();

    const iv = Buffer.from(row.iv, "hex");
    const decipher = crypto.createDecipheriv("aes-256-gcm", req.aesKey, iv);
    decipher.setAuthTag(tagBuf);

    // Stream ciphertext (excluding tag) -> decipher -> response.
    // NOTE: GCM verifies authenticity at stream end; on tamper the connection
    // is destroyed mid-stream rather than serving a clean error. Acceptable
    // for a single-user vault where the threat is disk tampering.
    const rs = fs.createReadStream(row.encrypted_path, {
      start: 0,
      end: cipherLen - 1,
    });
    res.setHeader("Content-Type", row.mimetype);
    res.setHeader("Content-Length", cipherLen);
    pipeline(rs, decipher, res, (err) => {
      if (err) {
        if (!res.headersSent) res.status(500).json({ error: "decrypt_failed" });
        else res.destroy();
      }
    });
  } catch (e) {
    if (!res.headersSent) res.status(500).json({ error: "decrypt_failed" });
  }
});

// Decrypt a stored row into the client-facing shape (+ ordered file list).
function decryptRow(row, key) {
  return {
    id: row.id,
    created_at: row.created_at,
    title: decField(row.title_enc, key),
    description: row.desc_enc ? decField(row.desc_enc, key) : "",
    tags: row.tags_enc ? JSON.parse(decField(row.tags_enc, key)) : [],
    files: stmts.getFiles.all(row.id).map((f) => ({ id: f.id, mimetype: f.mimetype || "" })),
  };
}

app.get("/api/media", auth, (req, res) => {
  const key = req.aesKey;
  const q = (req.query.q || "").trim();
  let page = parseInt(req.query.page, 10);
  if (!Number.isFinite(page) || page < 1) page = 1;
  const offset = (page - 1) * PER_PAGE;

  const respond = (ids, total) => {
    const data = ids
      .slice(offset, offset + PER_PAGE)
      .map((id) => decryptRow(stmts.getMeta.get(id), key));
    res.json({ data, total, page, perPage: PER_PAGE, totalPages: Math.ceil(total / PER_PAGE) });
  };

  // No query -> list recent (paginated in SQL).
  if (!q) {
    const rows = stmts.listPage.all(PER_PAGE, offset);
    const total = stmts.countAll.get().total;
    return res.json({
      data: rows.map((r) => decryptRow(r, key)),
      total,
      page,
      perPage: PER_PAGE,
      totalPages: Math.ceil(total / PER_PAGE),
    });
  }

  // Match = tag (blind index) OR date (plaintext created_at). Title/description
  // are NOT searchable — they stay fully encrypted.
  const found = new Map(); // id -> created_at

  // Date search: plain SQL on the unencrypted created_at, any query length.
  for (const r of stmts.searchByDate.all("%" + q + "%")) {
    found.set(r.id, r.created_at);
  }

  // Tag search: trigram blind index prunes candidates, then verify the real
  // substring against decrypted tags only. Needs >= NGRAM chars.
  if (q.length >= NGRAM) {
    const needle = q.toLowerCase();
    for (const id of candidateIds(tokenize(q.toLowerCase(), key))) {
      const row = stmts.getMeta.get(id);
      if (!row || !row.tags_enc) continue;
      const tags = JSON.parse(decField(row.tags_enc, key));
      if (tags.join("\n").toLowerCase().includes(needle)) {
        found.set(id, row.created_at);
      }
    }
  }

  const ids = [...found.entries()]
    .sort((a, b) => (a[1] < b[1] ? 1 : -1))
    .map((e) => e[0]);
  respond(ids, ids.length);
});

app.delete("/api/media/:id", auth, (req, res) => {
  const paths = stmts.getFilePaths.all(req.params.id);
  if (paths.length === 0 && !stmts.getMeta.get(req.params.id)) {
    return res.status(404).json({ error: "not_found" });
  }
  for (const p of paths) {
    try {
      if (p.encrypted_path) fs.unlinkSync(p.encrypted_path);
    } catch {
      /* already gone */
    }
  }
  stmts.deleteMedia.run(req.params.id); // cascade removes file + token rows
  res.json({ success: true });
});

app.use(express.static(path.join(__dirname, "public")));

const server = app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
