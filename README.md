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

## Patch Object Rules

### 1) Function Replacement

Define function with same name/signature in patch object:

```c
void sleep(int i) {
  printf("sleep called!\n");
}
```

### 2) Function Hook

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

## Testing

See [`TEST_CASES.md`](./TEST_CASES.md) for functional, boundary, and regression test cases
covering both `qpatch` and `gotrace` workflows.

---

## License

See `LICENSE`.
