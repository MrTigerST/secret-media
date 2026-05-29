# ---- Build stage: compile native deps (better-sqlite3) ----
FROM node:20-alpine AS build

# Toolchain needed to build better-sqlite3 native bindings.
RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package.json package-lock.json* ./
# Install prod deps only; build native modules from source.
RUN npm install --omit=dev --build-from-source

# ---- Runtime stage: small image, no toolchain ----
FROM node:20-alpine AS runtime

ENV NODE_ENV=production \
    PORT=3000 \
    DATA_DIR=/data

WORKDIR /app

# Copy installed (already-compiled) node_modules and app source.
COPY --from=build /app/node_modules ./node_modules
COPY package.json ./
COPY server.js db.js encrypt.js metacrypto.js init-db.js ./
COPY public ./public

# Persistent state lives here (db, encrypted uploads, keycheck.bin).
RUN mkdir -p /data && chown -R node:node /data /app

USER node
VOLUME ["/data"]
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||3000)+'/api/status').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
