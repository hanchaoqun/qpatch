# Test Cases

This document defines static test plans for validating `qpatch` and `gotrace` behavior.

## 1. qpatch Core Lifecycle

### TC-QP-001: Load -> Activate -> Query -> Rollback
- **Precondition**: target process is running and periodically calls target function.
- **Steps**:
  1. `./qpatch.bin -o patch.o -p <pid> -l`
  2. `./qpatch.bin -o patch.o -p <pid> -a`
  3. `./qpatch.bin -o patch.o -p <pid> -q`
  4. `./qpatch.bin -o patch.o -p <pid> -r`
  5. `./qpatch.bin -o patch.o -p <pid> -q`
- **Expected**:
  - State transitions are consistent with `INIT -> LOADED -> ACTIVED -> INIT`.
  - Patched behavior appears after activation and disappears after rollback.

### TC-QP-002: Repeated Load Idempotency
- **Steps**: Execute load twice with same object and PID.
- **Expected**: Second load does not corrupt state or crash target process.

### TC-QP-003: Activate Without Load
- **Steps**: Run `-a` directly on a process with no loaded patch.
- **Expected**: Command fails with status mismatch prompt (expected `LOADED`).

### TC-QP-004: Rollback Without Load
- **Steps**: Run `-r` directly.
- **Expected**: Graceful handling; no crash; state remains valid.

### TC-QP-005: Query Status in Each Stage
- **Steps**: Query before load, after load, after activate, after rollback.
- **Expected**: `INIT`, `LOADED`, `ACTIVED`, `INIT` respectively.

## 2. Patch Object Semantics

### TC-QP-101: Function Replacement
- **Precondition**: patch object defines same symbol as target function.
- **Expected**: target function calls routed to replacement implementation after activate.

### TC-QP-102: Hook Naming Convention
- **Precondition**: patch object defines `_qpatch_hookfun_<symbol>`.
- **Expected**: hook wrapper behavior appears while keeping original callable path.

### TC-QP-103: Multiple Symbols in One Patch
- **Precondition**: patch contains multiple replacement/hook symbols.
- **Expected**: all valid symbols applied; rollback restores all modified functions.

### TC-QP-104: Boundary of Hook/Replace Limits
- **Input**: construct patch approaching/exceeding internal limits (`LNK_MAX_HOOK_FUNC_COUNT`, `LNK_MAX_REP_FUNC_COUNT`).
- **Expected**: safe rejection with logs when exceeding limits; no memory corruption.

## 3. Robustness & Error Handling

### TC-QP-201: Invalid CLI Parameters
- **Cases**:
  - missing `-o`
  - missing action
  - invalid `-e` value
- **Expected**: usage displayed and non-zero exit.

### TC-QP-202: Permission Failure
- **Scenario**: no ptrace permission to target.
- **Expected**: clear attach/injection failure and graceful exit.

### TC-QP-203: Target Exits During Operation
- **Scenario**: target terminates while patch command runs.
- **Expected**: operation aborts safely; no uncontrolled loop.

## 4. gotrace

### TC-GT-001: Launch and Trace Go Program
- **Steps**: `./gotrace.bin ./go_binary`
- **Expected**: function-call stream is printed; session exits cleanly.

### TC-GT-002: Attach to Running Go Process
- **Steps**: `./gotrace.bin -p <pid>`
- **Expected**: function-call events are printed for running process.

### TC-GT-003: Disable Demangle
- **Steps**: run with `-c`.
- **Expected**: output symbol names are raw (non-demangled) where applicable.

### TC-GT-004: Filter Verification
- **Focus**: ensure filtered symbols (e.g., `runtime.text`) are excluded.
- **Expected**: excluded symbols do not appear in output stream.

## 5. Regression Checklist

- Patch room state is always recoverable after failed activation.
- Rollback restores original function prologue bytes.
- No persistent side effects after repeated load/activate/rollback cycles.
- `qpatch` and `gotrace` commands return non-zero on fatal failures.
