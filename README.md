# qpatch

Hot patching for Linux user-space processes (C/C++/Go support).

## Features

- Patch running user-space processes without restart.
- Replace existing functions in target process.
- Hook functions (including glibc functions) via naming convention.
- Patch lifecycle callbacks for activation/deactivation.
- Works in pure user-space (no kernel modification).
- Includes `gotrace` for Go function-call tracing.

---

## Repository Layout

- `qpatch.c` - CLI for patch lifecycle (`load/active/rollback/query`)
- `libqpatch.c` - injected shared library (`qpatch.so`) managing remote mmap room
- `gotrace.c` - Go function-call tracer based on ptrace breakpoints
- `ptrace.c/.h` - low-level process control and remote call/injection
- `symbol.c/.h` - ELF/proc maps parsing and symbol resolution
- `linkable.c/.h` - relocatable object loading and patch metadata building
- `opcode.c/.h` - instruction length decoding
- `arch/` - architecture-specific register/call implementation (`x86_64`, `aarch64`)
- `build.sh` - build script

---

## Architecture Overview

`qpatch` consists of three layers:

1. **CLI control layer (`qpatch.bin`)**  
   Handles patch lifecycle commands and remote orchestration.
2. **Injected runtime layer (`qpatch.so`)**  
   Provides remote mmap room management and state persistence inside target process.
3. **Low-level infrastructure**  
   `ptrace` + ELF symbol/linking components to resolve symbols, relocate patch objects,
   and modify target function entry code safely.

Patch state machine (`libqpatch.h`):

- `INIT -> LOADED -> ACTIVED`

---

## Build

> Requires Linux toolchain and project dependencies available locally.

```bash
./build.sh
```

Outputs:

- `qpatch.bin`
- `qpatch.so`
- `gotrace.bin`

---

## qpatch CLI

```bash
./qpatch.bin -o <patch.obj> -p <pid> [ACTION] [OPTION]
```

### Actions

- `-l` load patch
- `-a` activate patch
- `-r` rollback patch
- `-q` query patch status

### Options

- `-s <file>` patch symbol file
- `-d <level>` debug level (`1:debug`, `2:info`)
- `-e <lang>` target language (`c` or `go`)
- `-f <file>` custom path to `qpatch.so`

---

## Patch Object Specification

> Practical patch-authoring rules. Check these items before shipping a patch object (`.o`).

### 1) Recommended Compile Flags

Build patch objects with relocatability, symbol resolvability, and reduced inlining risk:

```bash
gcc -c patch.c -o patch.o \
  -g -O0 -fno-inline -fno-ipa-cp -fno-omit-frame-pointer \
  -fno-pie
```

Notes:
- `-c`: emits an object file (`patch.o`) for `qpatch` to load.
- `-O0`, `-fno-inline`: lowers failure risk caused by optimization/inlining.
- `-fno-omit-frame-pointer`: keeps function prologues more stable for debugging/symbol analysis.
- `-fno-pie`: matches repository test script defaults and avoids addressing-model mismatch.

### 2) Symbol Visibility and Replaceability

- The target function must be resolvable in the target process symbol table (export/preserve symbols when possible).
- In replacement scenarios, patch function name and signature should match the target function.
- In hook scenarios, keep a declaration of the original target symbol in patch source so the call path stays explicit.

### 3) Hook Naming Rule

Hook function names must use the following prefix (constant: `LNK_HOOK_FUN_NAME_PREFIX`):

- `_qpatch_hookfun_<target_symbol>`

For example, to hook `sleep`, use `_qpatch_hookfun_sleep`.

### 4) Function Replacement

Define function with same name/signature in patch object:

```c
void sleep(int i) {
  printf("sleep called!\n");
}
```

### 5) Function Hook

Use hook naming prefix:

- `_qpatch_hookfun_<target_symbol>`

Example:

```c
void sleep(int i);

void _qpatch_hookfun_sleep(int i) {
  printf("before sleep called!\n");
  sleep(i);
  printf("after sleep called!\n");
}
```

### 6) Prohibited Scenarios (High Failure Risk)

Avoid direct production rollout in these cases:

- **Function is too short**: insufficient overwrite bytes in function head (current 64-bit minimum jump overwrite length is `JMP_OPER_CODELEN=14` bytes).
- **Function is inlined**: compiler inlining bypasses the original symbol entry address.
- **Heavily optimized / hand-written asm entry**: unstable prologue and complex instruction boundaries increase overwrite failure risk.
- **Symbol is invisible or stripped**: strip/LTO may remove resolvable symbols and break mapping.

Before production, validate the full `load -> active -> query -> rollback` flow in pre-production.

---

## Typical Workflow

1. Compile patch source to object:

```bash
gcc -c patch.c -o patch.o
```

2. Load patch:

```bash
./qpatch.bin -o ./patch.o -p <pid> -l
```

3. Activate patch:

```bash
./qpatch.bin -o ./patch.o -p <pid> -a
```

4. Query status:

```bash
./qpatch.bin -o ./patch.o -p <pid> -q
```

5. Rollback:

```bash
./qpatch.bin -o ./patch.o -p <pid> -r
```

---

## gotrace

Track and print function calls of a Go process.

### Start and trace a program

```bash
./gotrace.bin ./your_go_binary
```

### Attach to a running process

```bash
./gotrace.bin -p <pid>
```

Options:

- `-c` disable C++ demangle
- `-v <level>` log verbosity

---

## Version Compatibility Matrix (with Verified Scope)

> “Verified” below means evidence exists in repository scripts/source. Unmarked areas do not yet have reproducible version-pinned records in this repo.

### qpatch (hot patching)

| Dimension | Scope | Verified scope | Evidence |
|---|---|---|---|
| Kernel / distro | Linux user-space processes | ⚠️ No kernel/distro version numbers are currently pinned in repository records | Project scope and scripts are Linux-only |
| Architecture | x86_64 / aarch64 | ✅ x86_64, aarch64 | `scripts/test_x86_suite.sh`, `scripts/test_aarch64_suite.sh` |
| glibc | Hooking glibc functions is supported | ⚠️ No glibc version interval is currently pinned in repository records | README feature statement (hook glibc functions) |

### gotrace (Go call tracing)

| Dimension | Scope | Verified scope | Evidence |
|---|---|---|---|
| Go version | Go 1.16 / 1.17 function-prologue patterns | ✅ 1.16–1.17 | Predefined patterns `GOTRACE_GO_116` and `GOTRACE_GO_117` in `gotrace.c` |
| Newer Go versions | Function prologues may change across versions | ⚠️ Add and verify new prologue signatures before claiming support | Fixed opcode matching mechanism in `gotrace.c` |

---

## Testing

See [`TEST_CASES.md`](./TEST_CASES.md) for functional, boundary, and regression test cases
covering both `qpatch` and `gotrace` workflows.

---

## License

See `LICENSE`.
