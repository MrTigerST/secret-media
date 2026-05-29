const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { encryptBuffer, decryptBuffer } = require("./encrypt");
const { DATA_DIR, stmts, createMedia, db } = require("./db");

const PORT = process.env.PORT || 3000;
const MAX_UPLOAD_MB = parseInt(process.env.MAX_UPLOAD_MB || "100", 10);
const PER_PAGE = 10;

const uploadsDir = path.join(DATA_DIR, "uploads", "encrypted");
const keycheckPath = path.join(DATA_DIR, "keycheck.bin");
fs.mkdirSync(uploadsDir, { recursive: true });

const app = express();
const upload = multer({ limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 } });

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

// Minimal security headers (no extra dependency).
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
});

// Cache keycheck contents in memory; invalidated when passcode is set.
let keycheckCache = null;
function readKeycheck() {
  if (keycheckCache === null && fs.existsSync(keycheckPath)) {
    keycheckCache = fs.readFileSync(keycheckPath);
  }
  return keycheckCache;
}

// Validate a 32-byte hex key against keycheck.bin. Returns Buffer key or null.
function verifyKey(hexHash) {
  if (!hexHash) return null;
  const key = Buffer.from(hexHash, "hex");
  if (key.length !== 32) return null;

  const data = readKeycheck();
  if (!data) return null;

  try {
    const iv = data.subarray(0, 12);
    const tag = data.subarray(data.length - 16);
    const encrypted = data.subarray(12, data.length - 16);
    const result = decryptBuffer(encrypted, iv, tag, key).toString();
    return result === "VALID_KEY" ? key : null;
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

app.get("/api/status", (req, res) => {
  res.json({ passcodeSet: fs.existsSync(keycheckPath) });
});

app.post("/api/set-passcode", (req, res) => {
  const { code_hash } = req.body || {};
  if (!code_hash) return res.status(400).json({ error: "invalid_code_hash" });

  const key = Buffer.from(code_hash, "hex");
  if (key.length !== 32) {
    return res.status(400).json({ error: "invalid_code_hash" });
  }
  if (fs.existsSync(keycheckPath)) {
    return res.status(400).json({ error: "already_set" });
  }

  const { encrypted, iv, tag } = encryptBuffer(Buffer.from("VALID_KEY"), key);
  const file = Buffer.concat([iv, encrypted, tag]);
  fs.writeFileSync(keycheckPath, file);
  keycheckCache = file;

  res.json({ success: true });
});

app.post("/api/auth-check", (req, res) => {
  const { code_hash } = req.body || {};
  if (!code_hash) return res.status(400).json({ error: "missing_key" });
  if (!fs.existsSync(keycheckPath)) {
    return res.status(400).json({ error: "no_key_set" });
  }
  if (!verifyKey(code_hash)) {
    return res.status(401).json({ error: "invalid_passcode" });
  }
  res.json({ success: true });
});

app.post("/api/upload", auth, upload.single("file"), (req, res) => {
  const { title, description, tags } = req.body;
  const file = req.file;
  if (!file || !title) {
    return res.status(400).json({ error: "missing_file_or_title" });
  }

  const { encrypted, iv, tag } = encryptBuffer(file.buffer, req.aesKey);
  // Opaque random filename — original name is never written to disk.
  const filename = `${crypto.randomBytes(16).toString("hex")}.enc`;
  const savePath = path.join(uploadsDir, filename);
  fs.writeFileSync(savePath, Buffer.concat([encrypted, tag]));

  const tagList = (tags || "")
    .split(",")
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean);

  try {
    const id = createMedia(
      {
        title,
        description: description || "",
        encrypted_path: savePath,
        iv: iv.toString("hex"),
        mimetype: file.mimetype,
      },
      tagList
    );
    res.json({ success: true, id: Number(id) });
  } catch (e) {
    fs.unlink(savePath, () => {});
    console.error("DB error:", e);
    res.status(500).json({ error: "db_error" });
  }
});

app.post("/api/file/:id", auth, (req, res) => {
  const row = stmts.getMedia.get(req.params.id);
  if (!row) return res.status(404).json({ error: "not_found" });

  try {
    const data = fs.readFileSync(row.encrypted_path);
    const authTag = data.subarray(data.length - 16);
    const encryptedContent = data.subarray(0, data.length - 16);
    const iv = Buffer.from(row.iv, "hex");
    const decrypted = decryptBuffer(encryptedContent, iv, authTag, req.aesKey);

    res.setHeader("Content-Type", row.mimetype);
    res.send(decrypted);
  } catch (e) {
    console.error("Decrypt error:", e);
    res.status(500).json({ error: "decrypt_failed" });
  }
});

app.get("/api/media", auth, (req, res) => {
  const q = "%" + (req.query.q || "") + "%";
  let page = parseInt(req.query.page, 10);
  if (!Number.isFinite(page) || page < 1) page = 1;
  const offset = (page - 1) * PER_PAGE;

  const data = stmts.searchMedia.all({ q, limit: PER_PAGE, offset });
  const total = stmts.countMedia.get({ q }).total;

  res.json({
    data,
    total,
    page,
    perPage: PER_PAGE,
    totalPages: Math.ceil(total / PER_PAGE),
  });
});

app.delete("/api/media/:id", auth, (req, res) => {
  const row = stmts.getMediaPath.get(req.params.id);
  if (!row) return res.status(404).json({ error: "not_found" });

  try {
    fs.unlinkSync(row.encrypted_path);
  } catch {
    /* file already gone */
  }
  stmts.deleteMedia.run(req.params.id);
  res.json({ success: true });
});

app.use(express.static(path.join(__dirname, "public")));

const server = app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Graceful shutdown (clean SQLite close on container stop).
function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
