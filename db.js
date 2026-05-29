const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "database.sqlite"));

db.pragma("journal_mode = WAL");
db.pragma("synchronous = NORMAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title_enc TEXT NOT NULL,
    desc_enc TEXT,
    tags_enc TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Up to 20 encrypted files per post.
  CREATE TABLE IF NOT EXISTS media_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    media_id INTEGER NOT NULL,
    encrypted_path TEXT NOT NULL,
    iv TEXT NOT NULL,
    mimetype TEXT,
    ord INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (media_id) REFERENCES media(id) ON DELETE CASCADE
  );

  -- Blind index: HMAC(key, trigram) tokens over tags only.
  CREATE TABLE IF NOT EXISTS search_index (
    media_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    PRIMARY KEY (media_id, token),
    FOREIGN KEY (media_id) REFERENCES media(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_media_created_at ON media(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_files_media ON media_files(media_id);
  CREATE INDEX IF NOT EXISTS idx_search_token ON search_index(token);
`);

const stmts = {
  insertMedia: db.prepare(
    `INSERT INTO media (title_enc, desc_enc, tags_enc)
     VALUES (@title_enc, @desc_enc, @tags_enc)`
  ),
  insertToken: db.prepare(
    `INSERT OR IGNORE INTO search_index (media_id, token) VALUES (?, ?)`
  ),
  insertFile: db.prepare(
    `INSERT INTO media_files (media_id, encrypted_path, iv, mimetype, ord)
     VALUES (?, ?, ?, ?, ?)`
  ),
  getMeta: db.prepare(
    `SELECT id, title_enc, desc_enc, tags_enc, created_at FROM media WHERE id = ?`
  ),
  listPage: db.prepare(
    `SELECT id, title_enc, desc_enc, tags_enc, created_at
     FROM media ORDER BY created_at DESC LIMIT ? OFFSET ?`
  ),
  // Ordered file list for a post (no path leaked to client).
  getFiles: db.prepare(
    `SELECT id, mimetype FROM media_files WHERE media_id = ? ORDER BY ord, id`
  ),
  // Single file for streaming download.
  getFileById: db.prepare(
    `SELECT encrypted_path, iv, mimetype FROM media_files WHERE id = ?`
  ),
  // All file paths of a post (for unlinking on delete).
  getFilePaths: db.prepare(
    `SELECT encrypted_path FROM media_files WHERE media_id = ?`
  ),
  deleteMedia: db.prepare(`DELETE FROM media WHERE id = ?`),
  countAll: db.prepare(`SELECT COUNT(*) AS total FROM media`),
  searchByDate: db.prepare(
    `SELECT id, created_at FROM media WHERE created_at LIKE ?`
  ),
};

// Insert a post + its search tokens + its files atomically.
const createMedia = db.transaction((media, tokens, files) => {
  const id = stmts.insertMedia.run(media).lastInsertRowid;
  for (const t of tokens) stmts.insertToken.run(id, t);
  files.forEach((f, i) => stmts.insertFile.run(id, f.path, f.iv, f.mimetype || "", i));
  return id;
});

// Candidate media ids whose index contains ALL given tokens.
function candidateIds(tokens) {
  if (tokens.length === 0) return [];
  const ph = tokens.map(() => "?").join(",");
  const sql = `SELECT media_id FROM search_index WHERE token IN (${ph})
               GROUP BY media_id HAVING COUNT(DISTINCT token) = ?`;
  return db.prepare(sql).all(...tokens, tokens.length).map((r) => r.media_id);
}

module.exports = { db, DATA_DIR, stmts, createMedia, candidateIds };
