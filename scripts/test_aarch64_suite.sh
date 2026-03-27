#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ "$(uname -m)" != "aarch64" ]; then
  echo "[SKIP] aarch64 suite requires native aarch64 host (current: $(uname -m))"
  exit 0
fi

./scripts/smoke_build_help.sh
./scripts/test_aarch64_qpatch_replace.sh
./scripts/test_aarch64_qpatch_stress.sh

echo "[PASS] aarch64 suite completed"
