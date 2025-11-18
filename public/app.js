let passcodeHash = null;
let currentPage = 1;
const perPage = 10;

async function sha256(str) {
  const enc = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

window.addEventListener("DOMContentLoaded", () => {
  fetch("/api/status")
    .then((r) => r.json())
    .then((s) => {
      if (s.passcodeSet) {
        document.getElementById("setup").style.display = "none";
      } else {
        document.getElementById("login").style.display = "none";
        document.getElementById("setup").style.display = "block";
      }
    })
    .catch(() => {});
});

async function setPasscode() {
  const secret = document.getElementById("secretSetup").value.trim();
  const status = document.getElementById("setupStatus");
  status.textContent = "";

  if (!secret) {
    status.textContent = "Enter a passcode.";
    return;
  }

  const hash = await sha256(secret);

  fetch("/api/set-passcode", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code_hash: hash }),
  })
    .then((r) => r.json())
    .then((res) => {
      if (res.error === "already_set") {
        status.textContent = "Passcode already set.";
        document.getElementById("setup").style.display = "none";
        document.getElementById("login").style.display = "block";
      } else if (res.success) {
        status.textContent = "Passcode set! Please log in.";
        document.getElementById("setup").style.display = "none";
        document.getElementById("login").style.display = "block";
      } else if (res.error) {
        status.textContent = "Error: " + res.error;
      }
    })
    .catch(() => {
      status.textContent = "Network error.";
    });
}

async function login() {
  const secret = document.getElementById("secretLogin").value.trim();
  const status = document.getElementById("loginStatus");
  status.textContent = "";

  if (!secret) {
    status.textContent = "Enter the passcode.";
    return;
  }

  const hash = await sha256(secret);
  passcodeHash = hash;

  fetch("/api/auth-check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code_hash: passcodeHash }),
  })
    .then((r) => r.json())
    .then((res) => {
      if (!res.success) {
        status.textContent = "Wrong passcode.";
        return;
      }

      document.getElementById("login").style.display = "none";
      document.getElementById("app").style.display = "block";
      searchMedia();
    });
}

function uploadFile() {
  const status = document.getElementById("uploadStatus");
  status.textContent = "";

  if (!passcodeHash) {
    status.textContent = "You are not logged in.";
    return;
  }

  const title = document.getElementById("title").value.trim();
  const fileInput = document.getElementById("file");
  const file = fileInput.files[0];

  if (!title || !file) {
    status.textContent = "Title and file are required.";
    return;
  }

  const fd = new FormData();
  fd.append("title", title);
  fd.append("description", document.getElementById("desc").value.trim());
  fd.append("tags", document.getElementById("tags").value.trim());
  fd.append("file", file);

  fetch("/api/upload", {
    method: "POST",
    headers: { "x-passcode": passcodeHash },
    body: fd,
  })
    .then((r) => r.json())
    .then((res) => {
      if (res.success) {
        status.textContent = "Uploaded!";
        document.getElementById("title").value = "";
        document.getElementById("desc").value = "";
        document.getElementById("tags").value = "";
        document.getElementById("file").value = "";
        searchMedia();
      } else if (res.error) {
        status.textContent = "Error: " + res.error;
      }
    })
    .catch(() => {
      status.textContent = "Network error.";
    });
}

function loadMedia(id) {
  fetch(`/api/file/${id}`, {
    method: "POST",
    headers: { "x-passcode": passcodeHash },
  })
    .then((r) => r.blob())
    .then((blob) => {
      const url = URL.createObjectURL(blob);

      const element = document.getElementById(`media-${id}`);
      element.src = url;
    })
    .catch((err) => {
      console.error("Error loading media:", err);
    });
}

function openMedia(id, type) {
  if (type !== "file") return;

  fetch(`/api/file/${id}`, {
    method: "POST",
    headers: { "x-passcode": passcodeHash },
  })
    .then((r) => {
      if (!r.ok) {
        console.error("Error opening file");
        return;
      }
      return r.blob();
    })
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
    .catch((err) => {
      console.error("Error opening file:", err);
    });
}

function searchMedia(page = 1) {
  if (!passcodeHash) return;

  currentPage = page;

  const q = document.getElementById("search").value || "";

  fetch(`/api/media?q=${encodeURIComponent(q)}&page=${page}`, {
    headers: { "x-passcode": passcodeHash },
  })
    .then((r) => r.json())
    .then((res) => {
      const container = document.getElementById("results");

      if (!res.data || res.data.length === 0) {
        container.innerHTML = "<p>No results.</p>";
        return;
      }

      const rows = res.data;
      const totalPages = res.totalPages;

      container.innerHTML = rows
        .map((r) => {
          const isImage = r.mimetype && r.mimetype.startsWith("image");
          const isVideoOrAudio =
            r.mimetype &&
            (r.mimetype.startsWith("video") || r.mimetype.startsWith("audio"));

          let mediaHtml = "";
          if (isImage) {
            mediaHtml = `<img id="media-${r.id}" style="cursor: zoom-in;" onclick="openMediaFullscreen(${r.id}, 'image')" />`;
          } else if (isVideoOrAudio) {
            mediaHtml = `<video id="media-${r.id}" controls></video>`;
          } else {
            mediaHtml = `<button onclick="openMedia(${r.id}, 'file')">Open file</button>`;
          }

          loadMedia(r.id);

          return `
            <div class="item">
              <h3>${r.title}</h3>
              <p class="date">${new Date(r.created_at).toLocaleString()}</p>
              <p>${r.description || ""}</p>
              ${mediaHtml}

              <button class="del" onclick="deleteMedia(${r.id})">Delete</button>
            </div>
          `;
        })
        .join("");

      container.innerHTML += `
        <div class="pagination">
          <button ${page <= 1 ? "disabled" : ""} onclick="searchMedia(${
        page - 1
      })">‹ Prev</button>
          <span>${page} / ${totalPages}</span>
          <button ${
            page >= totalPages ? "disabled" : ""
          } onclick="searchMedia(${page + 1})">Next ›</button>
        </div>
      `;
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
      if (res.success) {
        searchMedia(currentPage);
      } else {
        alert("Error: " + res.error);
      }
    });
}

let fsOverlay = document.getElementById("fullscreenOverlay");
let fsContainer = document.getElementById("fsContainer");
let fsImage = document.getElementById("fsImage");
let fsVideo = document.getElementById("fsVideo");

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
      const url = URL.createObjectURL(blob);

      fsOverlay.style.display = "block";
      scale = 1;
      posX = 0;
      posY = 0;

      fsImage.src = url;
      fsImage.style.display = "block";
      fsVideo.style.display = "none";

      applyTransform();
    });
}

function closeFullscreen() {
  fsOverlay.style.display = "none";
  fsVideo.pause();
}

fsContainer.addEventListener("wheel", (e) => {
  e.preventDefault();

  const delta = e.deltaY > 0 ? -0.1 : 0.1;
  scale = Math.min(Math.max(scale + delta, 0.2), 5);

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

function applyTransform() {
  const t = `translate(calc(-50% + ${posX}px), calc(-50% + ${posY}px)) scale(${scale})`;
  if (fsImage.style.display !== "none") fsImage.style.transform = t;
  if (fsVideo.style.display !== "none") fsVideo.style.transform = t;
}

fsOverlay.addEventListener("click", (e) => {
  if (e.target === fsOverlay) closeFullscreen();
});