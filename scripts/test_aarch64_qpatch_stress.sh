#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ "$(uname -m)" != "aarch64" ]; then
  echo "[SKIP] aarch64 only test (current: $(uname -m))"
  exit 0
fi

bash ./build.sh >/tmp/qpatch_aarch64_stress_build.log 2>&1

gcc -g -O0 -fno-pie -no-pie -rdynamic tests/aarch64/fixtures/cmain.c -o /tmp/qpatch_aarch64_cmain_stress
gcc -g -O0 -fno-pie -c tests/aarch64/fixtures/cpatch_replace.c -o /tmp/qpatch_aarch64_patch_replace_stress.o

/tmp/qpatch_aarch64_cmain_stress >/tmp/qpatch_aarch64_stress_target.log 2>&1 &
TPID=$!
trap 'kill -9 "$TPID" >/dev/null 2>&1 || true' EXIT
sleep 1

for i in 1 2 3; do
  ./qpatch.bin -o /tmp/qpatch_aarch64_patch_replace_stress.o -p "$TPID" -l
  ./qpatch.bin -o /tmp/qpatch_aarch64_patch_replace_stress.o -p "$TPID" -a
  ./qpatch.bin -o /tmp/qpatch_aarch64_patch_replace_stress.o -p "$TPID" -q | grep -Eq "ACTIVED"
  ./qpatch.bin -o /tmp/qpatch_aarch64_patch_replace_stress.o -p "$TPID" -r
  ./qpatch.bin -o /tmp/qpatch_aarch64_patch_replace_stress.o -p "$TPID" -q | grep -Eq "INIT"
  echo "[PASS] cycle $i"
done

if grep -q "bad-abi-target-func" /tmp/qpatch_aarch64_stress_target.log; then
  echo "[FAIL] ABI mismatch observed during stress"
  exit 1
fi

echo "[PASS] aarch64 qpatch stress"
