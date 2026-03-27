#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ "$(uname -m)" != "x86_64" ]; then
  echo "[SKIP] x86_64 only test (current: $(uname -m))"
  exit 0
fi

bash ./build.sh >/tmp/qpatch_build_small.log 2>&1

cat >/tmp/qpatch_small_main.c <<'MEOF'
#include <unistd.h>
__attribute__((noinline)) int tiny_func(void) { return 1; }
int main(void) { while (1) { tiny_func(); usleep(200000); } return 0; }
MEOF
cat >/tmp/qpatch_small_patch.c <<'PEOF'
int tiny_func(void) { return 2; }
PEOF

gcc -g -O0 -fno-pie -no-pie -rdynamic /tmp/qpatch_small_main.c -o /tmp/qpatch_small_main
gcc -g -O0 -fno-pie -c /tmp/qpatch_small_patch.c -o /tmp/qpatch_small_patch.o

/tmp/qpatch_small_main >/tmp/qpatch_small_main.log 2>&1 &
TPID=$!
trap 'kill -9 "$TPID" >/dev/null 2>&1 || true' EXIT
sleep 1

./qpatch.bin -o /tmp/qpatch_small_patch.o -p "$TPID" -l >/tmp/qpatch_small_l.log 2>&1
if ./qpatch.bin -o /tmp/qpatch_small_patch.o -p "$TPID" -a >/tmp/qpatch_small_a.log 2>&1; then
  echo "[FAIL] tiny function activation unexpectedly succeeded"
  exit 1
fi

echo "[PASS] tiny function activation rejected as expected"
