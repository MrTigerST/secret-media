const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("database.sqlite");

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS media (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      encrypted_path TEXT NOT NULL,
      iv TEXT NOT NULL,
      mimetype TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS tags (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS media_tags (
      media_id INTEGER NOT NULL,
      tag_id INTEGER NOT NULL,
      PRIMARY KEY (media_id, tag_id),
      FOREIGN KEY (media_id) REFERENCES media(id) ON DELETE CASCADE,
      FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
    );
  `);

  console.log("Database initialized.");
});

db.close();
