# qpatch Completed Feature List

This file summarizes capabilities that are already implemented in the current repository.

## 1. Patch Lifecycle (Implemented)

- Load patch object into target process runtime room (`-l`).
- Activate loaded patch by rewriting target function entries (`-a`).
- Roll back active patch to restore original function bytes (`-r`).
- Query patch state from target runtime (`-q`).
- Enforced state machine: `INIT -> LOADED -> ACTIVED` with transition checks.

## 2. Patch Modes (Implemented)

- **Function replacement**: same-name symbol in patch object replaces target implementation.
- **Function hook**: `_qpatch_hookfun_<symbol>` naming convention for wrapper-style interception.
- **Lifecycle callbacks** in patch payload:
  - `_pat_callback_active_before`
  - `_pat_callback_active_after`
  - `_pat_callback_deactive_before`
  - `_pat_callback_deactive_after`

## 3. Runtime Injection & Memory Room (Implemented)

- Runtime shared object (`qpatch.so`) injection into target process.
- Runtime API handshake/version check (`qpatch_check`).
- Persistent target-side mmap patch room allocation/reuse (`qpatch_open_room`).
- Runtime room release (`qpatch_close_room`).
- Room layout includes metadata, relocated payload, PLTGOT region, and BSS region.

## 4. Safety and Recoverability (Implemented)

- Structured error code taxonomy (`QPATCH_ERR_*`).
- Contextual logging (`action`, `pid`, `symbol`, `phase`, `err`).
- Activation rollback mechanism to reverse partial writes.
- Retry-oriented cleanup path for load/activate failure handling.
- Temporary copied runtime library (`_qpatch.so`) handling with cleanup.

## 5. Multi-Architecture Support (Implemented)

- Architecture abstraction via `qpatch_arch_ops`.
- x86_64 support path.
- AArch64 support path.

## 6. Symbol and Relocation Toolchain (Implemented)

- ELF symbol extraction for target and object files.
- Linkable object processing with relocation and metadata generation.
- Hook/replacement record model with per-function backup buffers.
- Instruction-length-aware overwrite guard integration.

## 7. gotrace Capabilities (Implemented)

- Launch-and-trace mode for executable targets.
- Attach-and-trace mode for running process by PID.
- Breakpoint-based function call tracing.
- C++ demangle output toggle (`-c` disables demangle).
- Go prologue pattern handling (multiple versions) and C/C++ entry support.

## 8. Automated Test Assets (Implemented)

- Smoke build/help script.
- x86 suite wrapper and targeted regression scripts.
- AArch64 suite wrapper and architecture-specific regression scripts.
- Fixture programs/patch objects for x86 and AArch64.
- Static test scenario matrix in `TEST_CASES.md`.

## 9. Current Boundaries (By Design)

- Linux user-space only.
- Requires ptrace permissions.
- Patch capacity bounded by compile-time limits.
- Some tiny/prologue-incompatible functions are intentionally rejected for safe patching.
