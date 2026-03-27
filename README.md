# qpatch

Hot patching for Linux user-space processes, with function replacement/hook support and companion runtime tracing (`gotrace`).

## Why qpatch

`qpatch` is designed for **in-process hot updates** where restarting a service is expensive or risky. It patches live function entry points through ptrace-assisted remote writes, while preserving a rollback path.

The repository also includes `gotrace`, a ptrace breakpoint tracer that helps inspect runtime call behavior in Go/C/C++ binaries.

## Core Principles

1. **User-space only**: no kernel module dependency.
2. **State-driven lifecycle**: `INIT -> LOADED -> ACTIVED`.
3. **Recoverability first**: partial activation failures attempt reverse write-back.
4. **Architecture-aware implementation**: x86_64 and AArch64 execution models are handled explicitly.
5. **Patch payload as object file**: keeps integration simple with standard toolchains.

## Components

- `qpatch.bin`: lifecycle CLI (`load`, `activate`, `rollback`, `query`).
- `qpatch.so`: injected runtime that owns target process patch room.
- `gotrace.bin`: function-call tracer for attach/launch workflows.
- `ptrace.*`: remote memory/register/call primitives.
- `symbol.*`, `linkable.*`, `opcode.*`: ELF parsing, relocation, patch metadata, instruction safety checks.
- `arch/*`: architecture dispatch and ABI-specific operations.

## Patch Lifecycle

```text
INIT --load--> LOADED --activate--> ACTIVED --rollback--> INIT
```

- `load` writes prepared patch payload and metadata into target room.
- `activate` rewrites target function entries to replacement/hook handlers.
- `rollback` restores original bytes from backups.
- `query` reads and prints current room state.

## Patch Semantics

### 1) Function replacement

Define same symbol in patch object:

```c
void sleep(int i) {
  printf("sleep called from patch\n");
}
```

### 2) Function hook

Use hook symbol prefix:

- `_qpatch_hookfun_<target_symbol>`

```c
void sleep(int i);

void _qpatch_hookfun_sleep(int i) {
  printf("before sleep\n");
  sleep(i);
  printf("after sleep\n");
}
```

## Build

```bash
./build.sh
```

Build outputs:
- `qpatch.bin`
- `qpatch.so`
- `gotrace.bin`

## CLI Usage

```bash
./qpatch.bin -o <patch.obj> -p <pid> [ACTION] [OPTION]
```

Actions:
- `-l` load patch
- `-a` activate patch
- `-r` rollback patch
- `-q` query patch status

Options:
- `-s <file>` patch symbol file
- `-d <level>` debug level (`1:debug`, `2:info`)
- `-e <lang>` target language (`c` or `go`)
- `-f <file>` runtime library path (defaults to `qpatch.so`)

## Quick Workflow

```bash
# 1) build patch object
gcc -c patch.c -o patch.o

# 2) load
./qpatch.bin -o ./patch.o -p <pid> -l

# 3) activate
./qpatch.bin -o ./patch.o -p <pid> -a

# 4) query
./qpatch.bin -o ./patch.o -p <pid> -q

# 5) rollback
./qpatch.bin -o ./patch.o -p <pid> -r
```

## gotrace

Launch and trace:

```bash
./gotrace.bin ./your_go_binary
```

Attach and trace:

```bash
./gotrace.bin -p <pid>
```

Common options:
- `-c`: disable C++ demangle
- `-v <level>`: log verbosity

## Documentation Map

- Architecture design: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Detailed technical design: [`docs/DETAILED_DESIGN.md`](docs/DETAILED_DESIGN.md)
- Completed feature list: [`docs/FEATURE_STATUS.md`](docs/FEATURE_STATUS.md)
- Test scenarios and regression matrix: [`TEST_CASES.md`](TEST_CASES.md)

## Testing

Smoke check:

```bash
./scripts/smoke_build_help.sh
```

x86 suite:

```bash
./scripts/test_x86_suite.sh
```

AArch64 suite:

```bash
./scripts/test_aarch64_suite.sh
```

## License

See `LICENSE`.
