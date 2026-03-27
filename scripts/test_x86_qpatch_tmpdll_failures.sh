#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -x "./qpatch.bin" ]; then
  echo "[SKIP] qpatch.bin not found; run build first"
  exit 0
fi

TMPDIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

# 1) 非法路径（包含 shell 元字符）不应被解释执行
INJECTION_MARKER="$TMPDIR/injection_marker"
BAD_PATH="$TMPDIR/not_exists;touch $INJECTION_MARKER"
if ./qpatch.bin -o /tmp/none.o -p 1 -q -f "$BAD_PATH" >/tmp/qpatch_bad_path.log 2>&1; then
  echo "[FAIL] invalid-path case unexpectedly succeeded"
  exit 1
fi
if ! grep -q "Failed to open source file" /tmp/qpatch_bad_path.log; then
  echo "[FAIL] invalid-path failure reason not observed"
  cat /tmp/qpatch_bad_path.log
  exit 1
fi
if [ -e "$INJECTION_MARKER" ]; then
  echo "[FAIL] shell injection marker was created"
  exit 1
fi

# 2) 权限不足：源文件不可读
PERM_ENTRY="$(ls /proc/1/map_files 2>/dev/null | head -n 1 || true)"
if [ -z "$PERM_ENTRY" ]; then
  echo "[SKIP] no /proc/1/map_files entries available for EPERM case"
  exit 0
fi
PERM_PATH="/proc/1/map_files/$PERM_ENTRY"
if ./qpatch.bin -o /tmp/none.o -p 1 -q -f "$PERM_PATH" >/tmp/qpatch_perm_denied.log 2>&1; then
  echo "[FAIL] permission-denied case unexpectedly succeeded"
  exit 1
fi
if ! grep -q "errno=1" /tmp/qpatch_perm_denied.log; then
  echo "[FAIL] permission-denied errno not observed"
  cat /tmp/qpatch_perm_denied.log
  exit 1
fi

# 3) 目标文件不存在：指定不存在的补丁库路径
if ./qpatch.bin -o /tmp/none.o -p 1 -q -f "$TMPDIR/missing.so" >/tmp/qpatch_missing_target.log 2>&1; then
  echo "[FAIL] missing-target case unexpectedly succeeded"
  exit 1
fi
if ! grep -q "Failed to open source file" /tmp/qpatch_missing_target.log; then
  echo "[FAIL] missing-target failure reason not observed"
  cat /tmp/qpatch_missing_target.log
  exit 1
fi

echo "[PASS] x86 qpatch temp dll negative cases"
