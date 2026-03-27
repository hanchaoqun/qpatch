#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ "$(uname -m)" != "x86_64" ]; then
  echo "[SKIP] x86_64 only test (current: $(uname -m))"
  exit 0
fi

if ! command -v go >/dev/null 2>&1; then
  echo "[SKIP] go toolchain not found"
  exit 0
fi

bash ./build.sh >/tmp/gotrace_build.log 2>&1
cat > /tmp/gomain_qpatch_test.go <<'GEOF'
package main

import (
  "fmt"
  "time"
)

func worker() {
  fmt.Printf("hello\n")
}

func main() {
  for {
    worker()
    time.Sleep(200 * time.Millisecond)
  }
}
GEOF

if ! GO111MODULE=off go build -o /tmp/gomain_qpatch_test /tmp/gomain_qpatch_test.go; then
  echo "[SKIP] failed to build temporary go target"
  exit 0
fi

timeout 8s ./gotrace.bin /tmp/gomain_qpatch_test >/tmp/gotrace_smoke.log 2>&1 || true
if ! grep -Eq "main\.worker|main\.main|runtime\." /tmp/gotrace_smoke.log; then
  echo "[FAIL] gotrace did not emit expected symbols"
  exit 1
fi

echo "[PASS] x86 gotrace smoke"
