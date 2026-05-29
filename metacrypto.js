const crypto = require("crypto");

const ALGO = "aes-256-gcm";
const TOKEN_LEN = 24; // hex chars of truncated HMAC (12 bytes) — ample for personal scale
const NGRAM = 3;

// --- Field encryption: returns hex of (iv | ciphertext | tag) ---
function encField(text, key) {
  if (text === undefined || text === null || text === "") return "";
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv(ALGO, key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(text, "utf8")), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]).toString("hex");
}

function decField(hex, key) {
  if (!hex) return "";
  const d = Buffer.from(hex, "hex");
  const iv = d.subarray(0, 12);
  const tag = d.subarray(d.length - 16);
  const ct = d.subarray(12, d.length - 16);
  const dec = crypto.createDecipheriv(ALGO, key, iv);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(ct), dec.final()]).toString("utf8");
}

// --- Blind index: deterministic keyed-hash trigram tokens ---
function trigramSet(text) {
  const s = (text || "").toLowerCase();
  const set = new Set();
  for (let i = 0; i + NGRAM <= s.length; i++) set.add(s.slice(i, i + NGRAM));
  return set;
}

// HMAC each trigram with the user key (domain-separated). Returns deduped tokens.
function tokenize(text, key) {
  const out = [];
  for (const g of trigramSet(text)) {
    out.push(
      crypto.createHmac("sha256", key).update("idx\0" + g).digest("hex").slice(0, TOKEN_LEN)
    );
  }
  return out;
}

// Combined searchable haystack for a post (matches old "title OR desc OR tag").
function haystack(title, description, tags) {
  return [title || "", description || "", ...(tags || [])].join("\n");
}

module.exports = { encField, decField, tokenize, haystack, NGRAM };
