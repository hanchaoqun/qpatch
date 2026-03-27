#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "[SMOKE] building binaries..."
bash ./build.sh

echo "[SMOKE] checking qpatch usage output..."
if (./qpatch.bin 2>&1 || true) | grep -Eiq "usage|QPATCH"; then
  echo "[SMOKE] qpatch usage ok"
else
  echo "[SMOKE] qpatch usage check failed" >&2
  exit 1
fi

echo "[SMOKE] checking gotrace usage output..."
if (./gotrace.bin 2>&1 || true) | grep -Eiq "usage|gotrace"; then
  echo "[SMOKE] gotrace usage ok"
else
  echo "[SMOKE] gotrace usage check failed" >&2
  exit 1
fi

echo "[SMOKE] all smoke checks passed."
