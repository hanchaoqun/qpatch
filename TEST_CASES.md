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

### TC-QP-104: Hook/Replace Limit Guidance (User-Facing)

#### Limit Description
- In a single patch object, the Hook function upper bound is `LNK_MAX_HOOK_FUNC_COUNT = 20`.
- In a single patch object, the Replace function upper bound is `LNK_MAX_REP_FUNC_COUNT = 200`.
- When limits are exceeded, the operation should be safely rejected (with logs), with no memory corruption or target process crash.

#### Mitigation Recommendations
- **Split patch objects**: break oversized patches into multiple `.o` files by functional domain.
- **Prioritize critical paths**: patch high-priority functions first; schedule non-critical functions in later batches.
- **Preflight validation in build pipeline**: count `_qpatch_hookfun_` prefixed functions and replacement functions; fail fast when over threshold.
- **Phased rollout**: validate `load -> active -> query -> rollback` in pre-production or low-traffic stages first.

#### Test Input and Expected Result
- **Input**: construct patch objects near and beyond the limits above.
- **Expected**: over-limit cases return clear errors and exit safely; within-limit cases execute normally.

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

### TC-QP-204: Fault Injection - Load/Activate Recoverability
- **Purpose**: verify `load/activate` mid-flight failures always roll back to a retryable patch-room state and leave no half-activated state.
- **Cases**:
  1. **Target process exits mid-operation**  
     - Injection point: after `qpatch_open_room` succeeded, before final room status update.
     - Expected recovery:
       - command returns non-zero with structured log fields (`action`, `pid`, `symbol`, `phase`);
       - room is not left in `ACTIVED` with partial function writes;
       - next run can retry from clean state (`INIT` for load failure, `LOADED` for activate failure after rollback).
  2. **Symbol resolution failure**  
     - Injection point: unresolved replacement/hook symbol while building linkable object.
     - Expected recovery:
       - load fails with unified symbol-related error code;
       - room is closed/reset to retryable state (no stale half-loaded metadata);
       - subsequent fixed patch file can be loaded without manual cleanup.
  3. **Target memory write failure**  
     - Injection point: force `ptrace` write failure when writing function jump or room header.
     - Expected recovery:
       - activate path performs reverse write-back of already replaced prologues using saved backups;
       - room header is restored to `LOADED` (not `ACTIVED`) so activation can be retried;
       - failure path emits rollback error code when reverse write-back itself fails.

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

## 6. Build & CLI Smoke Guard

Use a minimal guard script to keep build and CLI entrypoints healthy:

```bash
./scripts/smoke_build_help.sh
```

The script verifies:
- project build succeeds (`qpatch.bin`, `qpatch.so`, `gotrace.bin`)
- `qpatch` prints usage/help-like output
- `gotrace` prints usage/help-like output

## 7. x86 Regression Guard Scripts

For x86_64 environments, run:

```bash
./scripts/test_x86_suite.sh
```

This suite currently includes:
- `scripts/smoke_build_help.sh`: build + CLI smoke
- `scripts/test_x86_qpatch_replace.sh`: end-to-end `qpatch` load/activate/query/rollback replacement flow on a local C target process
- `scripts/test_x86_qpatch_smallfunc_guard.sh`: verifies activation is rejected for tiny functions that cannot satisfy minimum overwrite length
- `scripts/test_x86_qpatch_stress.sh`: multi-cycle load/active/rollback stability and short-lived target robustness check
- `scripts/test_x86_gotrace_smoke.sh`: currently forced skip in this phase (focus is x86 qpatch core path)

Notes:
- `scripts/test_x86_qpatch_replace.sh` auto-skips when `distorm` artifacts are unavailable, because runtime patch rewriting depends on instruction decode support.
- `scripts/test_x86_gotrace_smoke.sh` is intentionally skipped until gotrace is brought back into the active regression scope.


## 8. AArch64 Regression Guard Scripts

For AArch64 environments, run:

```bash
./scripts/test_aarch64_suite.sh
```

This suite currently includes:
- `scripts/smoke_build_help.sh`: build + CLI smoke
- `scripts/test_aarch64_qpatch_replace.sh`: end-to-end `qpatch` load/activate flow + AArch64-specific ABI and overwrite-size guards
- `scripts/test_aarch64_qpatch_stress.sh`: repeated load/activate/rollback stability with ABI mismatch guard

AArch64-specific boundary differences from x86:
- **Fixed-width instruction encoding**: AArch64 instructions are 4 bytes each. The tiny fixture (`tiny_func`) is asserted to have symbol size divisible by 4 before running activation tests.
- **Minimum overwrite length for entry jump**: current runtime patch logic requires at least `JMP_OPER_CODELEN` bytes (14 bytes on 64-bit builds). For AArch64 this implies at least 4 instructions are usually needed to satisfy overwrite room.
- **Register calling convention assertion**: replace fixture validates argument/return path via `target_func(long a, long b)`, asserting patched behavior only when `(a, b) == (7, 5)` (AArch64 argument registers `x0/x1`, return register `x0`).
