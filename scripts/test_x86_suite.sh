#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

./scripts/smoke_build_help.sh
./scripts/test_x86_qpatch_replace.sh
./scripts/test_x86_qpatch_smallfunc_guard.sh
./scripts/test_x86_qpatch_stress.sh
./scripts/test_x86_gotrace_smoke.sh

echo "[PASS] x86 suite completed"
