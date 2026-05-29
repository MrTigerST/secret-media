const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "database.sqlite"));

// Performance + integrity pragmas.
db.pragma("journal_mode = WAL");
db.pragma("synchronous = NORMAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    encrypted_path TEXT NOT NULL,
    iv TEXT NOT NULL,
    mimetype TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
  );

  CREATE TABLE IF NOT EXISTS media_tags (
    media_id INTEGER NOT NULL,
    tag_id INTEGER NOT NULL,
    PRIMARY KEY (media_id, tag_id),
    FOREIGN KEY (media_id) REFERENCES media(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_media_created_at ON media(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_media_tags_tag ON media_tags(tag_id);
`);

// Prepared statements (compiled once, reused).
const stmts = {
  insertMedia: db.prepare(
    `INSERT INTO media (title, description, encrypted_path, iv, mimetype)
     VALUES (@title, @description, @encrypted_path, @iv, @mimetype)`
  ),
  insertTag: db.prepare(`INSERT OR IGNORE INTO tags (name) VALUES (?)`),
  getTagId: db.prepare(`SELECT id FROM tags WHERE name = ?`),
  linkTag: db.prepare(
    `INSERT OR IGNORE INTO media_tags (media_id, tag_id) VALUES (?, ?)`
  ),
  getMediaPath: db.prepare(`SELECT encrypted_path FROM media WHERE id = ?`),
  getMedia: db.prepare(`SELECT * FROM media WHERE id = ?`),
  deleteMedia: db.prepare(`DELETE FROM media WHERE id = ?`),
  searchMedia: db.prepare(`
    SELECT DISTINCT m.*
    FROM media m
    LEFT JOIN media_tags mt ON m.id = mt.media_id
    LEFT JOIN tags t ON t.id = mt.tag_id
    WHERE m.title LIKE @q OR m.description LIKE @q OR t.name LIKE @q
    ORDER BY m.created_at DESC
    LIMIT @limit OFFSET @offset
  `),
  countMedia: db.prepare(`
    SELECT COUNT(DISTINCT m.id) AS total
    FROM media m
    LEFT JOIN media_tags mt ON m.id = mt.media_id
    LEFT JOIN tags t ON t.id = mt.tag_id
    WHERE m.title LIKE @q OR m.description LIKE @q OR t.name LIKE @q
  `),
};

// Insert media + tags atomically.
const createMedia = db.transaction((media, tagList) => {
  const info = stmts.insertMedia.run(media);
  const mediaId = info.lastInsertRowid;
  for (const name of tagList) {
    stmts.insertTag.run(name);
    const tag = stmts.getTagId.get(name);
    if (tag) stmts.linkTag.run(mediaId, tag.id);
  }
  return mediaId;
});

module.exports = { db, DATA_DIR, stmts, createMedia };
