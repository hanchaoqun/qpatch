#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ "$(uname -m)" != "aarch64" ]; then
  echo "[SKIP] aarch64 only test (current: $(uname -m))"
  exit 0
fi

bash ./build.sh >/tmp/qpatch_aarch64_build.log 2>&1

gcc -g -O0 -fno-pie -no-pie -rdynamic tests/aarch64/fixtures/cmain.c -o /tmp/qpatch_aarch64_cmain
gcc -g -O0 -fno-pie -c tests/aarch64/fixtures/cpatch_replace.c -o /tmp/qpatch_aarch64_patch_replace.o

# AArch64 fixed-width instruction check: every instruction is 4 bytes.
TINY_SIZE="$(readelf -s /tmp/qpatch_aarch64_cmain | awk '$8=="tiny_func" {print $3; exit}')"
if [ -z "$TINY_SIZE" ]; then
  echo "[FAIL] failed to locate tiny_func symbol size"
  exit 1
fi
if [ $((TINY_SIZE % 4)) -ne 0 ]; then
  echo "[FAIL] tiny_func size ($TINY_SIZE) is not 4-byte aligned instruction width"
  exit 1
fi
if [ "$TINY_SIZE" -ge 14 ]; then
  echo "[FAIL] tiny_func unexpectedly >= 14 bytes ($TINY_SIZE); cannot validate minimum overwrite guard"
  exit 1
fi

/tmp/qpatch_aarch64_cmain >/tmp/qpatch_aarch64_target.log 2>&1 &
TPID=$!
cleanup() {
  kill -9 "$TPID" >/dev/null 2>&1 || true
}
trap cleanup EXIT
sleep 1

./qpatch.bin -o /tmp/qpatch_aarch64_patch_replace.o -p "$TPID" -l
./qpatch.bin -o /tmp/qpatch_aarch64_patch_replace.o -p "$TPID" -a
sleep 1

if ! grep -q "patched-target-func" /tmp/qpatch_aarch64_target.log; then
  echo "[FAIL] patched output not observed"
  exit 1
fi
if grep -q "bad-abi-target-func" /tmp/qpatch_aarch64_target.log; then
  echo "[FAIL] detected bad ABI behavior (AArch64 x0/x1 calling convention mismatch)"
  exit 1
fi

# tiny_func replacement should be rejected due to overwrite bytes requirement (14 bytes).
gcc -g -O0 -fno-pie -c tests/aarch64/fixtures/cpatch_tiny_replace.c -o /tmp/qpatch_aarch64_patch_tiny.o
./qpatch.bin -o /tmp/qpatch_aarch64_patch_tiny.o -p "$TPID" -l >/tmp/qpatch_aarch64_tiny_load.log 2>&1
if ./qpatch.bin -o /tmp/qpatch_aarch64_patch_tiny.o -p "$TPID" -a >/tmp/qpatch_aarch64_tiny_activate.log 2>&1; then
  echo "[FAIL] tiny function activation unexpectedly succeeded on aarch64"
  exit 1
fi

echo "[PASS] aarch64 qpatch replace flow"
