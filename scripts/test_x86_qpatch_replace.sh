#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ "$(uname -m)" != "x86_64" ]; then
  echo "[SKIP] x86_64 only test (current: $(uname -m))"
  exit 0
fi

if [ ! -f "./distorm64-v1.7.30/distorm.h" ] && \
   [ ! -f "./distorm64-v1.7.30/distorm64.a" ]; then
  echo "[SKIP] distorm artifacts not found; qpatch runtime patch test skipped"
  exit 0
fi

bash ./build.sh >/tmp/qpatch_build.log 2>&1

gcc -g -O0 -fno-pie -no-pie tests/x86/fixtures/cmain.c -o /tmp/qpatch_cmain
gcc -g -O0 -fno-pie -c tests/x86/fixtures/cpatch_replace.c -o /tmp/cpatch_replace.o

/tmp/qpatch_cmain >/tmp/qpatch_target.log 2>&1 &
TPID=$!
cleanup() {
  kill -9 "$TPID" >/dev/null 2>&1 || true
}
trap cleanup EXIT
sleep 1

if ./qpatch.bin -o /tmp/cpatch_replace.o -p "$TPID" -a >/tmp/qpatch_act_before_load.log 2>&1; then
  echo "[FAIL] activate-before-load unexpectedly succeeded"
  exit 1
fi

./qpatch.bin -o /tmp/cpatch_replace.o -p "$TPID" -l
./qpatch.bin -o /tmp/cpatch_replace.o -p "$TPID" -a
sleep 1
if ! kill -0 "$TPID" >/dev/null 2>&1; then
  echo "[FAIL] target process exited unexpectedly"
  cat /tmp/qpatch_target.log
  exit 1
fi
if ! grep -q "patched-target-func" /tmp/qpatch_target.log; then
  echo "[FAIL] patched output not observed"
  exit 1
fi

STATUS_OUT="$(./qpatch.bin -o /tmp/cpatch_replace.o -p "$TPID" -q)"
echo "$STATUS_OUT" | grep -Eq "ACTIVED"

./qpatch.bin -o /tmp/cpatch_replace.o -p "$TPID" -r
sleep 1
if ! grep -q "orig-target-func" /tmp/qpatch_target.log; then
  echo "[FAIL] original output not observed after rollback"
  exit 1
fi
STATUS_OUT_AFTER_ROLLBACK="$(./qpatch.bin -o /tmp/cpatch_replace.o -p "$TPID" -q)"
echo "$STATUS_OUT_AFTER_ROLLBACK" | grep -Eq "INIT"

echo "[PASS] x86 qpatch replace flow"
