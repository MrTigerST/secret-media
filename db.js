const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");
const { encField, tokenize } = require("./metacrypto");

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "database.sqlite"));

db.pragma("journal_mode = WAL");
db.pragma("synchronous = NORMAL");
db.pragma("foreign_keys = ON");

function tableExists(name) {
  return Boolean(
    db
      .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?")
      .get(name)
  );
}

function columnNames(table) {
  return new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name));
}

function ensureColumn(table, column, definition) {
  if (!columnNames(table).has(column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

function initializeSchema() {
  const hadMedia = tableExists("media");

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

  if (hadMedia) {
    // Existing volumes may have the v1/v2 plaintext metadata schema. SQLite's
    // CREATE TABLE IF NOT EXISTS will not add missing columns, so do it here.
    ensureColumn("media", "title_enc", "TEXT");
    ensureColumn("media", "desc_enc", "TEXT");
    ensureColumn("media", "tags_enc", "TEXT");
    ensureColumn("media", "created_at", "DATETIME");
    db.exec("UPDATE media SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL");
  }

  const mediaCols = columnNames("media");
  if (mediaCols.has("encrypted_path") && mediaCols.has("iv")) {
    db.exec(`
      INSERT INTO media_files (media_id, encrypted_path, iv, mimetype, ord)
      SELECT m.id, m.encrypted_path, m.iv,
             COALESCE(m.mimetype, ''), 0
      FROM media m
      WHERE m.encrypted_path IS NOT NULL
        AND m.encrypted_path <> ''
        AND m.iv IS NOT NULL
        AND m.iv <> ''
        AND NOT EXISTS (
          SELECT 1 FROM media_files f WHERE f.media_id = m.id
        );
    `);
  }
}

initializeSchema();

function buildInsertMediaStatement() {
  const mediaCols = columnNames("media");
  const columns = ["title_enc", "desc_enc", "tags_enc"];
  const values = ["@title_enc", "@desc_enc", "@tags_enc"];

  // Legacy media tables still contain NOT NULL columns that are no longer used.
  // Supplying harmless placeholders keeps new inserts working until a future
  // table rebuild can drop those columns.
  for (const legacyColumn of ["title", "description", "encrypted_path", "iv", "mimetype"]) {
    if (mediaCols.has(legacyColumn)) {
      columns.push(legacyColumn);
      values.push("''");
    }
  }

  return db.prepare(
    `INSERT INTO media (${columns.join(", ")})
     VALUES (${values.join(", ")})`
  );
}

const stmts = {
  insertMedia: buildInsertMediaStatement(),
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

function legacyTagTablesExist() {
  return tableExists("tags") && tableExists("media_tags");
}

function getLegacyTags(mediaId) {
  if (!legacyTagTablesExist()) return [];
  return db
    .prepare(
      `SELECT t.name
       FROM tags t
       JOIN media_tags mt ON mt.tag_id = t.id
       WHERE mt.media_id = ?
       ORDER BY t.name`
    )
    .all(mediaId)
    .map((r) => String(r.name || "").trim().toLowerCase())
    .filter(Boolean);
}

const migrateLegacyMetadataTx = db.transaction((key) => {
  const mediaCols = columnNames("media");
  const hasLegacyTitle = mediaCols.has("title");
  const hasLegacyDescription = mediaCols.has("description");
  const hasLegacyTags = legacyTagTablesExist();

  if (!hasLegacyTitle && !hasLegacyDescription && !hasLegacyTags) {
    return { migrated: 0 };
  }

  const titleExpr = hasLegacyTitle ? "title AS title" : "'' AS title";
  const descExpr = hasLegacyDescription ? "description AS description" : "'' AS description";
  const rows = db
    .prepare(
      `SELECT id, title_enc, desc_enc, tags_enc, ${titleExpr}, ${descExpr}
       FROM media`
    )
    .all();

  const updateEncrypted = db.prepare(
    `UPDATE media
     SET title_enc = ?, desc_enc = ?, tags_enc = ?
     WHERE id = ?`
  );
  const clearPlainSet = [
    hasLegacyTitle ? "title = ''" : null,
    hasLegacyDescription ? "description = ''" : null,
  ]
    .filter(Boolean)
    .join(", ");
  const clearPlain = clearPlainSet
    ? db.prepare(`UPDATE media SET ${clearPlainSet} WHERE id = ?`)
    : null;

  let migrated = 0;
  let clearedPlain = 0;
  for (const row of rows) {
    const tags = getLegacyTags(row.id);
    const title = row.title || "";
    const description = row.description || "";
    const hasPlainMetadata =
      (hasLegacyTitle && title) || (hasLegacyDescription && description);
    const needsMetadata =
      (!row.title_enc && title) ||
      (!row.desc_enc && description) ||
      (!row.tags_enc && tags.length > 0);

    if (needsMetadata) {
      const titleEnc = row.title_enc || encField(title, key);
      const descEnc = row.desc_enc || encField(description, key);
      const tagsEnc = row.tags_enc || (tags.length ? encField(JSON.stringify(tags), key) : "");

      updateEncrypted.run(titleEnc, descEnc, tagsEnc, row.id);
      for (const token of tokenize(tags.join("\n"), key)) {
        stmts.insertToken.run(row.id, token);
      }
      migrated += 1;
    }

    if (clearPlain && hasPlainMetadata && (needsMetadata || row.title_enc)) {
      clearPlain.run(row.id);
      clearedPlain += 1;
    }
  }

  if (hasLegacyTags && (migrated > 0 || clearedPlain > 0)) {
    db.exec("DELETE FROM media_tags; DELETE FROM tags;");
  }

  return { migrated };
});

function migrateLegacyMetadata(key) {
  return migrateLegacyMetadataTx(key);
}

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

module.exports = { db, DATA_DIR, stmts, createMedia, candidateIds, migrateLegacyMetadata };
