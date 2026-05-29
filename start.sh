#!/usr/bin/env sh
set -e

# Install deps if missing, init the DB schema, then start the server.
[ -d node_modules ] || npm install
node init-db.js
node server.js
