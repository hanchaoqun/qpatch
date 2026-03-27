#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ "$(uname -m)" != "x86_64" ]; then
  echo "[SKIP] x86_64 only test (current: $(uname -m))"
  exit 0
fi

bash ./build.sh >/tmp/qpatch_stress_build.log 2>&1

gcc -g -O0 -fno-pie -no-pie -rdynamic tests/x86/fixtures/cmain.c -o /tmp/qpatch_cmain_stress
gcc -g -O0 -fno-pie -c tests/x86/fixtures/cpatch_replace.c -o /tmp/cpatch_replace_stress.o

/tmp/qpatch_cmain_stress >/tmp/qpatch_stress_target.log 2>&1 &
TPID=$!
trap 'kill -9 "$TPID" >/dev/null 2>&1 || true' EXIT
sleep 1

for i in 1 2 3; do
  ./qpatch.bin -o /tmp/cpatch_replace_stress.o -p "$TPID" -l
  ./qpatch.bin -o /tmp/cpatch_replace_stress.o -p "$TPID" -a
  ./qpatch.bin -o /tmp/cpatch_replace_stress.o -p "$TPID" -q | grep -Eq "ACTIVED"
  ./qpatch.bin -o /tmp/cpatch_replace_stress.o -p "$TPID" -r
  ./qpatch.bin -o /tmp/cpatch_replace_stress.o -p "$TPID" -q | grep -Eq "INIT"
  echo "[PASS] cycle $i"
done

# target short-exit robustness
cat >/tmp/qpatch_short_exit.c <<'SEOF'
#include <stdio.h>
#include <unistd.h>
int main(void) {
  puts("short-run");
  fflush(stdout);
  usleep(500000);
  return 0;
}
SEOF
gcc -g -O0 -fno-pie -no-pie -rdynamic /tmp/qpatch_short_exit.c -o /tmp/qpatch_short_exit

/tmp/qpatch_short_exit >/tmp/qpatch_short_exit.log 2>&1 &
SPID=$!
sleep 1
if timeout 5s ./qpatch.bin -o /tmp/cpatch_replace_stress.o -p "$SPID" -l >/tmp/qpatch_short_load.log 2>&1; then
  echo "[WARN] short-lived process load unexpectedly succeeded"
else
  echo "[PASS] short-lived process load failed fast as expected"
fi

echo "[PASS] x86 qpatch stress"
