# qpatch Detailed Technical Design

## 1. Design Objectives

- Patch function behavior in a running process with no restart.
- Keep all operations in user space (`ptrace` + injected shared object).
- Preserve rollbackability and retryability after partial failures.
- Support both replacement and hook styles using object-file-based patch payloads.

## 2. Binary and Module Responsibilities

## 2.1 Host executables

- `qpatch.bin`
  - Accepts `-l/-a/-r/-q` actions.
  - Manages transient `_qpatch.so` lifecycle.
  - Coordinates remote room state transitions.
- `gotrace.bin`
  - Attaches/launches target process.
  - Sets breakpoints on eligible function symbols.

## 2.2 Target runtime

- `qpatch.so`
  - Provides runtime APIs for room setup and teardown.
  - Stores singleton room pointer and size in process-global variables.

## 2.3 Shared infrastructure

- `ptrace.*`: remote memory/register/function-call primitives.
- `symbol.*`: process/object ELF symbol discovery.
- `linkable.*`: relocation and replacement/hook metadata construction.
- `opcode.*`: instruction length decode utility for safe jump overwrite windows.
- `arch/*`: ABI and register handling abstraction by architecture.

## 3. Core Data Structures

## 3.1 `qpatch_call_in`

A fixed ABI packet for host→runtime RPC:
- `version`, `hostpid`, and generic parameters (`para1..para6`).

## 3.2 `qpatch_mmap_room_hdr`

Persistent room metadata in target process:
- `version`, `hostpid`, `status`, `roomlen`.

## 3.3 `qpatch_mmap_room`

Composite room layout containing:
- room header,
- pointers/lengths for object data, replacement header, PLTGOT, BSS,
- `linkable_elf_rep_hdr` replacement/hook entries.

## 3.4 `linkable_elf_rep_hdr`

Contains:
- callback addresses (`_pat_callback_*`),
- array of hook entries,
- array of replacement entries,
- per-function backups for rollback.

## 4. Control Flow Design

## 4.1 Load path (`qpatch_lod_patch`)

1. Resolve object size and compute room size.
2. Create ptrace process context.
3. Inject runtime library and handshake with `qpatch_check`.
4. Call `qpatch_open_room` and read room header.
5. Enforce `status == INIT`.
6. Build linkable object image and replacement/hook metadata.
7. Write object payload + updated room metadata into target memory.
8. Transition status to `LOADED`.
9. On failure, attempt `qpatch_close_room` recovery path.

## 4.2 Activate path (`qpatch_act_patch`)

1. Inject/check/open room.
2. Enforce `status == LOADED`.
3. For each replacement and hook candidate:
   - validate target symbol and overwrite size,
   - backup original bytes,
   - write redirection code.
4. Trigger activation callbacks if available.
5. Set `status = ACTIVED`.
6. If any patch write fails, restore previously modified entries and set room back to `LOADED`.

## 4.3 Rollback path (`qpatch_rol_patch`)

1. Open room and validate rollback-eligible status.
2. Trigger deactivation callbacks if defined.
3. Restore original bytes for replacement/hook entries.
4. Set status to `INIT` and optionally close room.

## 4.4 Query path (`qpatch_dsp_patch`)

- Read room status and print textual state.

## 5. Hook/Replace Semantics

## 5.1 Replace

A patch object function with same exported symbol name replaces target entry behavior after activation.

## 5.2 Hook

Hook functions are discovered by prefix:
- `_qpatch_hookfun_<target_symbol>`

The runtime prepares trampoline/original-head handling metadata so wrapper code can call through and return.

## 5.3 Lifecycle callbacks

Optional callback symbols in patch object:
- `_pat_callback_active_before`
- `_pat_callback_active_after`
- `_pat_callback_deactive_before`
- `_pat_callback_deactive_after`

## 6. Error Handling Design

- Unified negative error code families (`QPATCH_ERR_*`).
- Context-rich log entries include action, pid, symbol, phase, and typed error code.
- Activation rollback path returns `QPATCH_ERR_ROLLBACK` on reverse-write failures.
- CLI exits with non-zero status when operation result `< 0`.

## 7. Multi-Architecture Design

Architecture-specific behaviors are hidden behind `qpatch_arch_ops`:
- register access (IP/SP/return value),
- remote function calling sequence,
- syscall helpers (6-arg and optional 7-arg behavior).

Current implementations:
- x86_64
- AArch64

## 8. Test Design and Coverage Mapping

## 8.1 Smoke
- Build and CLI help checks (`scripts/smoke_build_help.sh`).

## 8.2 x86 suite
- replacement lifecycle,
- activate-before-load rejection,
- tiny-function overwrite guard,
- stress/repeat cycles,
- temporary runtime library path/permission/missing-file negative checks.

## 8.3 AArch64 suite
- replacement lifecycle,
- ABI-sensitive behavior checks,
- fixed-width instruction assumptions,
- tiny-function activation rejection.

## 8.4 Scenario specification
- `TEST_CASES.md` defines lifecycle, semantics, robustness, and regression checklist entries.

## 9. Operational Constraints

- Requires sufficient privileges for ptrace operations.
- Runtime patching depends on instruction decode path availability (`distorm` or fallback logic).
- Function size and prologue shape can make some symbols non-patchable by design.
