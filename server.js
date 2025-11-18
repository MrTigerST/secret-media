const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const { encryptBuffer, decryptBuffer } = require("./encrypt");
const crypto = require("crypto");


const app = express();
const db = new sqlite3.Database("database.sqlite");
const upload = multer();

const uploadsDir = path.join(__dirname, "uploads", "encrypted");
fs.mkdirSync(uploadsDir, { recursive: true });

app.use(express.json());

function auth(req, res, next) {
  const hash = req.headers["x-passcode"];
  if (!hash) return res.status(401).json({ error: "missing_passcode" });

  try {
    const key = Buffer.from(hash, "hex");
    const data = fs.readFileSync("keycheck.bin");

    const iv = data.slice(0, 12);
    const tag = data.slice(data.length - 16);
    const encrypted = data.slice(12, data.length - 16);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const result = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]).toString();

    if (result !== "VALID_KEY") {
      return res.status(401).json({ error: "invalid_passcode" });
    }

    req.aesKey = key;

    next();

  } catch {
    return res.status(401).json({ error: "invalid_passcode" });
  }
}

app.post("/api/set-passcode", (req, res) => {
  const { code_hash } = req.body || {};
  const key = Buffer.from(code_hash, "hex");

  if (!code_hash || key.length !== 32) {
    return res.status(400).json({ error: "invalid_code_hash" });
  }

  if (fs.existsSync("keycheck.bin")) {
    return res.status(400).json({ error: "already_set" });
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const encrypted = Buffer.concat([
    cipher.update("VALID_KEY"),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  const file = Buffer.concat([iv, encrypted, tag]);
  fs.writeFileSync("keycheck.bin", file);

  return res.json({ success: true });
});

app.get("/api/status", (req, res) => {
  const passcodeSet = fs.existsSync("keycheck.bin");
  res.json({ passcodeSet });
});


app.post("/api/auth-check", (req, res) => {
  const { code_hash } = req.body;
  if (!code_hash) return res.status(400).json({ error: "missing_key" });

  if (!fs.existsSync("keycheck.bin")) {
    return res.status(400).json({ error: "no_key_set" });
  }

  const key = Buffer.from(code_hash, "hex");
  if (key.length !== 32) return res.status(400).json({ error: "invalid_hash" });

  const data = fs.readFileSync("keycheck.bin");

  const iv = data.slice(0, 12);
  const tag = data.slice(data.length - 16);
  const encrypted = data.slice(12, data.length - 16);

  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);

    const result = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]).toString();

    if (result !== "VALID_KEY") {
      return res.status(401).json({ error: "invalid_passcode" });
    }

    return res.json({ success: true });

  } catch (err) {
    return res.status(401).json({ error: "invalid_passcode" });
  }
});



app.post("/api/upload", auth, upload.single("file"), (req, res) => {
  const { title, description, tags } = req.body;
  const file = req.file;

  if (!file || !title) {
    return res.status(400).json({ error: "missing_file_or_title" });
  }

  const { encrypted, iv, tag } = encryptBuffer(file.buffer, req.aesKey);

  const safeName = file.originalname.replace(/[^a-zA-Z0-9_.-]/g, "_");
  const filename = Date.now() + "_" + safeName + ".enc";
  const savePath = path.join(uploadsDir, filename);

  fs.writeFileSync(savePath, Buffer.concat([encrypted, tag]));

  db.run(
    `INSERT INTO media (title, description, encrypted_path, iv, mimetype)
      VALUES (?, ?, ?, ?, ?)`,
    [title, description || "", savePath, iv.toString("hex"), file.mimetype],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "db_error" });
      }

      const mediaId = this.lastID;

      if (tags && tags.trim() !== "") {
        const tagList = tags
          .split(",")
          .map((t) => t.trim().toLowerCase())
          .filter(Boolean);

        tagList.forEach((tagName) => {
          db.run(`INSERT OR IGNORE INTO tags (name) VALUES (?)`, [tagName]);
          db.get(
            `SELECT id FROM tags WHERE name = ?`,
            [tagName],
            (err2, tagRow) => {
              if (!err2 && tagRow) {
                db.run(
                  `INSERT OR IGNORE INTO media_tags (media_id, tag_id) VALUES (?, ?)`,
                  [mediaId, tagRow.id]
                );
              }
            }
          );
        });
      }

      res.json({ success: true, id: mediaId });
    }
  );
});


app.post("/api/file/:id", auth, (req, res) => {
  db.get("SELECT * FROM media WHERE id = ?", [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: "not_found" });

    try {
      const data = fs.readFileSync(row.encrypted_path);

      const authTag = data.slice(data.length - 16);
      const encryptedContent = data.slice(0, data.length - 16);

      const iv = Buffer.from(row.iv, "hex");

      const decrypted = decryptBuffer(
        encryptedContent,
        iv,
        authTag,
        req.aesKey
      );

      res.setHeader("Content-Type", row.mimetype);
      res.send(decrypted);
    } catch (e) {
      console.error("Decrypt error:", e);
      return res.status(500).json({ error: "decrypt_failed" });
    }
  });
});

app.get("/api/media", auth, (req, res) => {
  const q = "%" + (req.query.q || "") + "%";
  const page = parseInt(req.query.page || 1);
  const perPage = 10;
  const offset = (page - 1) * perPage;

  const sql = `
    SELECT DISTINCT m.*
    FROM media m
    LEFT JOIN media_tags mt ON m.id = mt.media_id
    LEFT JOIN tags t ON t.id = mt.tag_id
    WHERE m.title LIKE ? OR m.description LIKE ? OR t.name LIKE ?
    ORDER BY m.created_at DESC
    LIMIT ? OFFSET ?
  `;

  db.all(sql, [q, q, q, perPage, offset], (err, rows) => {
    if (err) return res.status(500).json({ error: "db_error" });

    db.get(
      `SELECT COUNT(DISTINCT m.id) AS total
       FROM media m
       LEFT JOIN media_tags mt ON m.id = mt.media_id
       LEFT JOIN tags t ON t.id = mt.tag_id
       WHERE m.title LIKE ? OR m.description LIKE ? OR t.name LIKE ?`,
      [q, q, q],
      (err2, r2) => {
        res.json({
          data: rows,
          total: r2.total,
          page,
          perPage,
          totalPages: Math.ceil(r2.total / perPage),
        });
      }
    );
  });
});

app.delete("/api/media/:id", auth, (req, res) => {
  const id = req.params.id;

  db.get("SELECT encrypted_path FROM media WHERE id = ?", [id], (err, row) => {
    if (err) return res.status(500).json({ error: "db_error" });
    if (!row) return res.status(404).json({ error: "not_found" });

    try {
      fs.unlinkSync(row.encrypted_path);
    } catch (_) {}

    db.run("DELETE FROM media WHERE id = ?", [id], (err2) => {
      if (err2) return res.status(500).json({ error: "db_error" });
      res.json({ success: true });
    });
  });
});

app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
