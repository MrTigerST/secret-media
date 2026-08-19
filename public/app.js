let passcodeHash = null; // Browser-derived key (hex), used as the credential
let currentPage = 1;

const DEFAULT_ITERATIONS = 600000; // PBKDF2-HMAC-SHA256 (OWASP-recommended)

// KDF params for the existing vault, fetched from /api/status.
let vaultSalt = null;
let vaultIterations = null;
let vaultKdf = "PBKDF2-SHA256";

const $ = (id) => document.getElementById(id);

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function cryptoUnavailableMessage() {
  return "Browser crypto is unavailable. Open this app through http://localhost:3000 or HTTPS.";
}

function requireBrowserCrypto() {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error("webcrypto_unavailable");
  }
  return globalThis.crypto;
}

async function sha256(passcode) {
  const cryptoApi = requireBrowserCrypto();
  const enc = new TextEncoder();
  const buf = await cryptoApi.subtle.digest("SHA-256", enc.encode(passcode));
  return bytesToHex(new Uint8Array(buf));
}

// JS-driven typewriter: types real characters, independent of element width.
function typeWriter(el, speed = 45) {
  if (!el) return;
  const text = el.dataset.text ?? el.textContent;
  el.dataset.text = text; // remember original so re-runs work
  clearInterval(el._tw);

  // Separate text node + persistent caret span (caret stays blinking when done).
  el.textContent = "";
  const txt = document.createTextNode("");
  const caret = document.createElement("span");
  caret.className = "caret";
  el.append(txt, caret);

  let i = 0;
  el._tw = setInterval(() => {
    txt.textContent = text.slice(0, ++i);
    if (i >= text.length) clearInterval(el._tw);
  }, speed);
}

// Derive the 32-byte AES key from passcode via PBKDF2 in the browser.
async function deriveKey(passcode, saltHex, iterations) {
  const cryptoApi = requireBrowserCrypto();
  const enc = new TextEncoder();
  const baseKey = await cryptoApi.subtle.importKey(
    "raw",
    enc.encode(passcode),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await cryptoApi.subtle.deriveBits(
    { name: "PBKDF2", salt: hexToBytes(saltHex), iterations, hash: "SHA-256" },
    baseKey,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

async function deriveCredential(passcode) {
  if (vaultKdf === "SHA-256") return sha256(passcode);
  if (!vaultSalt || !vaultIterations) throw new Error("missing_kdf_params");
  return deriveKey(passcode, vaultSalt, vaultIterations);
}

window.addEventListener("DOMContentLoaded", () => {
  // Wire up event listeners (no inline handlers — strict CSP).
  $("setupForm").addEventListener("submit", (e) => {
    e.preventDefault();
    setPasscode();
  });
  $("loginForm").addEventListener("submit", (e) => {
    e.preventDefault();
    login();
  });
  $("uploadBtn").addEventListener("click", uploadFile);
  $("search").addEventListener("input", () => searchMedia());
  $("fsCloseBtn").addEventListener("click", closeFullscreen);

  fetch("/api/status")
    .then((r) => r.json())
    .then((s) => {
      vaultSalt = s.salt || null;
      vaultIterations = s.iterations || null;
      vaultKdf = s.kdf || (s.passcodeSet && !s.salt ? "SHA-256" : "PBKDF2-SHA256");
      if (s.passcodeSet) {
        $("login").style.display = "block";
        typeWriter($("login").querySelector(".typewriter"));
      } else {
        $("setup").style.display = "block";
        typeWriter($("setup").querySelector(".typewriter"));
      }
    })
    .catch(() => {});
});

async function setPasscode() {
  const secret = $("secretSetup").value.trim();
  const status = $("setupStatus");
  status.textContent = "";
  if (!secret) {
    status.textContent = "Enter a passcode.";
    return;
  }

  // Client generates a random salt; key derived locally, never the passcode.
  let salt;
  let hash;
  const iterations = DEFAULT_ITERATIONS;
  try {
    const cryptoApi = requireBrowserCrypto();
    salt = bytesToHex(cryptoApi.getRandomValues(new Uint8Array(16)));
    status.textContent = "Deriving key...";
    hash = await deriveKey(secret, salt, iterations);
    vaultKdf = "PBKDF2-SHA256";
  } catch (e) {
    status.textContent = cryptoUnavailableMessage();
    return;
  }
  fetch("/api/set-passcode", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ salt, iterations, code_hash: hash }),
  })
    .then((r) => r.json())
    .then((res) => {
      if (res.success) {
        vaultSalt = salt;
        vaultIterations = iterations;
        status.textContent = "Passcode set! Please log in.";
        $("setup").style.display = "none";
        $("login").style.display = "block";
        typeWriter($("login").querySelector(".typewriter"));
      } else {
        status.textContent = "Error: " + (res.error || "unknown");
      }
    })
    .catch(() => {
      status.textContent = "Network error.";
    });
}

async function login() {
  const secret = $("secretLogin").value.trim();
  const status = $("loginStatus");
  status.textContent = "";
  if (!secret) {
    status.textContent = "Enter the passcode.";
    return;
  }
  if (vaultKdf === "PBKDF2-SHA256" && (!vaultSalt || !vaultIterations)) {
    status.textContent = "Vault not initialized.";
    return;
  }

  status.textContent = "Deriving key...";
  try {
    passcodeHash = await deriveCredential(secret);
  } catch (e) {
    passcodeHash = null;
    status.textContent =
      e.message === "missing_kdf_params"
        ? "Vault KDF parameters are missing."
        : cryptoUnavailableMessage();
    return;
  }

  fetch("/api/auth-check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code_hash: passcodeHash }),
  })
    .then((r) => r.json())
    .then((res) => {
      if (!res.success) {
        passcodeHash = null;
        status.textContent = "Wrong passcode.";
        return;
      }
      status.textContent = "";
      $("login").style.display = "none";
      $("app").style.display = "block";
      searchMedia();
    })
    .catch(() => {
      status.textContent = "Network error.";
    });
}

function uploadFile() {
  const status = $("uploadStatus");
  status.textContent = "";
  if (!passcodeHash) {
    status.textContent = "You are not logged in.";
    return;
  }

  const title = $("title").value.trim();
  const description = $("desc").value.trim();
  const tagsRaw = $("tags").value.trim();
  const files = $("file").files;

  if (!title) {
    status.textContent = "Title is required.";
    return;
  }
  if (title.length > 200) {
    status.textContent = "Title too long (max 200).";
    return;
  }
  if (description.length > 7000) {
    status.textContent = "Description too long (max 7000).";
    return;
  }
  const tagCount = tagsRaw
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean).length;
  if (tagCount > 15) {
    status.textContent = "Too many tags (max 15).";
    return;
  }
  if (files.length > 20) {
    status.textContent = "Too many files (max 20).";
    return;
  }

  const fd = new FormData();
  fd.append("title", title);
  fd.append("description", description);
  fd.append("tags", tagsRaw);
  for (const f of files) fd.append("file", f); // 0..20 files

  fetch("/api/upload", {
    method: "POST",
    headers: { "x-passcode": passcodeHash },
    body: fd,
  })
    .then((r) => r.json())
    .then((res) => {
      if (res.success) {
        status.textContent = "Uploaded!";
        $("title").value = "";
        $("desc").value = "";
        $("tags").value = "";
        $("file").value = "";
        searchMedia();
      } else {
        status.textContent = "Error: " + (res.error || "unknown");
      }
    })
    .catch(() => {
      status.textContent = "Network error.";
    });
}

function loadMedia(id, el) {
  fetch(`/api/file/${id}`, {
    method: "POST",
    headers: { "x-passcode": passcodeHash },
  })
    .then((r) => r.blob())
    .then((blob) => {
      el.src = URL.createObjectURL(blob);
    })
    .catch((err) => console.error("Error loading media:", err));
}

function openMedia(id) {
  fetch(`/api/file/${id}`, {
    method: "POST",
    headers: { "x-passcode": passcodeHash },
  })
    .then((r) => (r.ok ? r.blob() : null))
    .then((blob) => {
      if (!blob) return;
      const url = URL.createObjectURL(blob);
      if (
        blob.type.startsWith("text/") ||
        blob.type === "application/pdf" ||
        blob.type.startsWith("audio/") ||
        blob.type.startsWith("video/") ||
        blob.type.includes("json")
      ) {
        window.open(url, "_blank");
        return;
      }
      const a = document.createElement("a");
      a.href = url;
      a.download = `file_${id}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    })
    .catch((err) => console.error("Error opening file:", err));
}

// One carousel slide for a file {id, mimetype}.
function makeSlide(f) {
  const mt = f.mimetype || "";
  if (mt.startsWith("image")) {
    const img = document.createElement("img");
    img.style.cursor = "zoom-in";
    img.addEventListener("click", () => openMediaFullscreen(f.id));
    loadMedia(f.id, img);
    return img;
  }
  if (mt.startsWith("video")) {
    const v = document.createElement("video");
    v.controls = true;
    loadMedia(f.id, v);
    return v;
  }
  if (mt.startsWith("audio")) {
    const player = document.createElement("div");
    player.className = "audio-player";
    const icon = document.createElement("div");
    icon.className = "audio-icon";
    icon.textContent = "♪";
    const audio = document.createElement("audio");
    audio.controls = true;
    audio.preload = "none";
    player.append(icon, audio);
    loadMedia(f.id, audio);
    return player;
  }
  const btn = document.createElement("button");
  btn.textContent = "Open file";
  btn.addEventListener("click", () => openMedia(f.id));
  return btn;
}

// Carousel with ‹ › arrows; slides built lazily and cached.
function buildCarousel(files) {
  const wrap = document.createElement("div");
  wrap.className = "carousel";

  const stage = document.createElement("div");
  stage.className = "carousel-stage";

  const cache = new Array(files.length).fill(null);
  let idx = 0;

  function show(i) {
    idx = (i + files.length) % files.length;
    if (!cache[idx]) cache[idx] = makeSlide(files[idx]);
    stage.replaceChildren(cache[idx]);
    counter.textContent = `${idx + 1} / ${files.length}`;
  }

  const nav = document.createElement("div");
  nav.className = "carousel-nav";
  const prev = document.createElement("button");
  prev.className = "carousel-arrow";
  prev.textContent = "‹";
  prev.addEventListener("click", () => show(idx - 1));
  const counter = document.createElement("span");
  counter.className = "carousel-counter";
  const next = document.createElement("button");
  next.className = "carousel-arrow";
  next.textContent = "›";
  next.addEventListener("click", () => show(idx + 1));
  nav.append(prev, counter, next);

  wrap.append(stage, nav);
  if (files.length <= 1) nav.style.display = "none"; // single file: no arrows
  show(0);
  return wrap;
}

// Build a media item with DOM APIs (textContent) — no innerHTML, no XSS.
function renderItem(r) {
  const item = document.createElement("div");
  item.className = "item";

  const h3 = document.createElement("h3");
  h3.textContent = r.title;
  item.appendChild(h3);

  const date = document.createElement("p");
  date.className = "date";
  date.textContent = new Date(r.created_at).toLocaleString();
  item.appendChild(date);

  if (r.description) {
    const desc = document.createElement("p");
    desc.textContent = r.description;
    item.appendChild(desc);
  }

  if (r.tags && r.tags.length) {
    const tagWrap = document.createElement("div");
    tagWrap.className = "tags";
    r.tags.forEach((name) => {
      const chip = document.createElement("span");
      chip.className = "tag";
      chip.textContent = "#" + name;
      tagWrap.appendChild(chip);
    });
    item.appendChild(tagWrap);
  }

  if (r.files && r.files.length) {
    item.appendChild(buildCarousel(r.files));
  }

  const del = document.createElement("button");
  del.className = "del";
  del.textContent = "Delete";
  del.addEventListener("click", () => deleteMedia(r.id));
  item.appendChild(del);

  return item;
}

function searchMedia(page = 1) {
  if (!passcodeHash) return;
  currentPage = page;
  const q = $("search").value || "";

  fetch(`/api/media?q=${encodeURIComponent(q)}&page=${page}`, {
    headers: { "x-passcode": passcodeHash },
  })
    .then((r) => r.json())
    .then((res) => {
      const container = $("results");
      container.replaceChildren();

      if (!res.data || res.data.length === 0) {
        const p = document.createElement("p");
        p.textContent = "No results.";
        container.appendChild(p);
        return;
      }

      res.data.forEach((r) => container.appendChild(renderItem(r)));

      const pag = document.createElement("div");
      pag.className = "pagination";

      if (page > 1) {
        const prev = document.createElement("button");
        prev.textContent = "‹ Prev";
        prev.addEventListener("click", () => searchMedia(page - 1));
        pag.appendChild(prev);
      }

      const span = document.createElement("span");
      span.textContent = `${page} / ${res.totalPages}`;
      pag.appendChild(span);

      if (page < res.totalPages) {
        const next = document.createElement("button");
        next.textContent = "Next ›";
        next.addEventListener("click", () => searchMedia(page + 1));
        pag.appendChild(next);
      }

      container.appendChild(pag);
    });
}

function deleteMedia(id) {
  if (!confirm("Are you sure you want to delete this file?")) return;
  fetch(`/api/media/${id}`, {
    method: "DELETE",
    headers: { "x-passcode": passcodeHash },
  })
    .then((r) => r.json())
    .then((res) => {
      if (res.success) searchMedia(currentPage);
      else alert("Error: " + res.error);
    });
}

// ---- Fullscreen image viewer (pan + zoom) ----
const fsOverlay = $("fullscreenOverlay");
const fsContainer = $("fsContainer");
const fsImage = $("fsImage");
const fsVideo = $("fsVideo");

let scale = 1;
let posX = 0;
let posY = 0;
let isDragging = false;
let lastX = 0;
let lastY = 0;

function openMediaFullscreen(id) {
  fetch(`/api/file/${id}`, {
    method: "POST",
    headers: { "x-passcode": passcodeHash },
  })
    .then((r) => r.blob())
    .then((blob) => {
      fsOverlay.style.display = "block";
      scale = 1;
      posX = 0;
      posY = 0;
      fsImage.src = URL.createObjectURL(blob);
      fsImage.style.display = "block";
      fsVideo.style.display = "none";
      applyTransform();
    });
}

function closeFullscreen() {
  fsOverlay.style.display = "none";
  fsVideo.pause();
}

function applyTransform() {
  const t = `translate(calc(-50% + ${posX}px), calc(-50% + ${posY}px)) scale(${scale})`;
  if (fsImage.style.display !== "none") fsImage.style.transform = t;
  if (fsVideo.style.display !== "none") fsVideo.style.transform = t;
}

fsContainer.addEventListener("wheel", (e) => {
  e.preventDefault();
  scale = Math.min(Math.max(scale + (e.deltaY > 0 ? -0.1 : 0.1), 0.2), 5);
  applyTransform();
});
fsContainer.addEventListener("dragstart", (e) => e.preventDefault());
fsContainer.addEventListener("mousedown", (e) => {
  isDragging = true;
  lastX = e.clientX;
  lastY = e.clientY;
});
window.addEventListener("mouseup", () => {
  isDragging = false;
});
window.addEventListener("mousemove", (e) => {
  if (!isDragging) return;
  posX += e.clientX - lastX;
  posY += e.clientY - lastY;
  lastX = e.clientX;
  lastY = e.clientY;
  applyTransform();
});
fsOverlay.addEventListener("click", (e) => {
  if (e.target === fsOverlay) closeFullscreen();
});
