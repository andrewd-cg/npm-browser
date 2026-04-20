#!/usr/bin/env bash
set -e

BUN="${HOME}/.bun/bin/bun"

if [ ! -f "$BUN" ]; then
  echo "Bun not found at $BUN"
  echo "Install it: curl -fsSL https://bun.sh/install | bash"
  exit 1
fi

echo "Starting npm-browser at http://localhost:3000"
"$BUN" server.js
