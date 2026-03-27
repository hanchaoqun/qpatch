# qpatch Architecture Design

## 1. Goals and Scope

`qpatch` is a Linux user-space hot patching framework that updates function behavior in a live process without restarting it. The repository also includes `gotrace`, a ptrace-based runtime function tracer for Go/C/C++ processes.

This architecture document describes the current implementation reflected in this repository.

---

## 2. High-Level Architecture

The system is organized into four layers:

1. **Control Plane (Host CLI)**
   - `qpatch.bin` orchestrates patch lifecycle actions: load, activate, rollback, query.
   - `gotrace.bin` orchestrates function breakpoint tracing.
2. **Injection/Execution Plane (ptrace + remote call)**
   - Attaches to target process threads.
   - Injects shared library and calls exported runtime functions in target context.
3. **Patch Runtime Plane (inside target process)**
   - `qpatch.so` allocates and manages a persistent executable memory room (`mmap`).
   - Stores patch object image, relocation output, and patch metadata.
4. **ELF/Relocation + Architecture Plane**
   - Parses object and process symbols.
   - Resolves replacement/hook symbols.
   - Performs architecture-specific call/syscall/register handling (x86_64, AArch64).

---

## 3. Main Components

## 3.1 `qpatch.bin` (Lifecycle Orchestrator)

Core responsibilities:
- Parse CLI actions/options.
- Copy `qpatch.so` to a temporary `_qpatch.so` file before injection.
- Attach and inspect target process state.
- Call runtime APIs (`qpatch_check`, `qpatch_open_room`, `qpatch_close_room`).
- Build and write relocatable patch payload into target room.
- Activate function redirection (replace/hook) and perform rollback on failures.

Primary lifecycle entry points:
- `qpatch_lod_patch` (load)
- `qpatch_act_patch` (activate)
- `qpatch_rol_patch` (rollback)
- `qpatch_dsp_patch` (query)

## 3.2 `qpatch.so` (Injected Runtime)

Exported runtime APIs:
- `qpatch_check`: ABI/version handshake.
- `qpatch_open_room`: allocate/reuse mmap room and initialize header.
- `qpatch_close_room`: release mmap room.

It stores global room pointer/size per target process and returns stable room address to host operations.

## 3.3 `ptrace.*` (Remote Control Infrastructure)

Capabilities:
- Attach/wait/detach target threads.
- Read/write target memory.
- Backup/restore registers.
- Run remote functions/syscalls with ABI-safe stack/register setup.
- Inject shared libraries into target process.

## 3.4 `linkable.*` + `symbol.*` + `opcode.*`

- Parse ELF symbols/sections for target and patch object.
- Build replacement/hook metadata (`linkable_elf_rep_hdr`).
- Resolve callback symbols (`_pat_callback_*`) and hook symbol prefix (`_qpatch_hookfun_`).
- Decode instruction boundaries to ensure safe minimum overwrite length before patch jump writes.

## 3.5 `arch/*`

Architecture abstraction (`qpatch_arch_ops`) selects implementation by target ELF machine:
- x86_64
- AArch64

It provides register accessors, function call convention support, and syscall helpers.

## 3.6 `gotrace.bin`

- Uses ptrace breakpoints to observe function entry calls.
- Supports attach-to-running process or launch-and-trace.
- Includes Go prologue pattern handling for multiple versions plus C/C++ pattern.
- Optional C++ demangle display.

---

## 4. Runtime Data Model

## 4.1 Patch Room Memory Layout

Target-side memory block is represented by `struct qpatch_mmap_room` and includes:
- room header (`version`, `hostpid`, `status`, `roomlen`)
- relocated replacement/hook metadata (`rephdr`)
- object payload area
- PLTGOT area
- BSS area

The layout is sized with `LNK_MIN_MMAP_ROOM_LEN` and aligned to page boundaries.

## 4.2 Patch State Machine

Room status transitions:
- `INIT` → after room creation or post-rollback cleanup
- `LOADED` → patch object and metadata are loaded and ready
- `ACTIVED` → function entry redirection is applied

Validation is enforced before each operation.

---

## 5. End-to-End Lifecycle Flows

## 5.1 Load (`-l`)

1. Validate patch object and target process.
2. Inject runtime library and open room.
3. Require room state = `INIT`.
4. Build linkable image (symbols/relocations/replacement/hook metadata).
5. Write payload and metadata into target room.
6. Update room state to `LOADED`.
7. On failures, attempt room close/reset for retryability.

## 5.2 Activate (`-a`)

1. Open room and validate state = `LOADED`.
2. For each replacement/hook entry:
   - backup original function bytes,
   - validate overwrite safety,
   - write jump/bridge instructions.
3. Execute activation callback hooks if present.
4. Mark room state to `ACTIVED`.
5. If any operation fails mid-flight, execute reverse writes and restore room to `LOADED` when possible.

## 5.3 Rollback (`-r`)

1. Open room and validate rollback-eligible state.
2. Execute deactivation callbacks if configured.
3. Restore original function prologue bytes from backups.
4. Set state back to `INIT`.
5. Optionally close room.

## 5.4 Query (`-q`)

- Open room and print current patch state (`INIT`/`LOADED`/`ACTIVED`).

---

## 6. Reliability and Safety Controls

- Structured error codes (`QPATCH_ERR_*`) and contextual log macro (`QPATCH_LOG_CTX`).
- Activation rollback helper restores modified code bytes when partial activation fails.
- State gating avoids illegal transitions (e.g., activate before load).
- Temporary runtime library copy (`_qpatch.so`) avoids direct mutation of base artifact during command execution.
- Instruction-length guards prevent unsafe overwrite on short functions.

---

## 7. Test Architecture

The test strategy is script-driven:
- `scripts/smoke_build_help.sh`: build + CLI smoke.
- `scripts/test_x86_suite.sh`: x86 regression suite wrapper.
- `scripts/test_aarch64_suite.sh`: AArch64 regression suite wrapper.

Representative coverage includes:
- lifecycle correctness,
- tiny-function overwrite guard,
- stress cycles,
- temporary runtime library failure cases,
- architecture-specific ABI expectations.

Detailed scenario matrix is in `TEST_CASES.md`.

---

## 8. Known Boundaries

- Linux user-space only.
- Requires ptrace capability/permission for target process.
- Tested architecture paths focus on x86_64 and AArch64.
- Patch symbol capacities are bounded by compile-time limits (`LNK_MAX_REP_FUNC_COUNT`, `LNK_MAX_HOOK_FUNC_COUNT`).
