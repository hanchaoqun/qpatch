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

## 补丁对象规范

> 面向补丁编写者的“可直接落地”约束，建议在提交补丁对象（`.o`）前逐项自检。

### 1) 编译参数建议

推荐以“可重定位、可符号解析、避免内联优化”为目标构建补丁对象：

```bash
gcc -c patch.c -o patch.o \
  -g -O0 -fno-inline -fno-ipa-cp -fno-omit-frame-pointer \
  -fno-pie
```

说明：
- `-c`：仅产出目标文件（`patch.o`），供 `qpatch` 装载。
- `-O0`、`-fno-inline`：降低函数被优化/内联导致无法替换的概率。
- `-fno-omit-frame-pointer`：保留更稳定的函数序言，便于排障与符号分析。
- `-fno-pie`：与仓库测试脚本默认构建方式保持一致，减少地址模型差异。

### 2) 符号可见性与可替换性

- 目标函数必须能在目标进程符号表中被定位（建议导出/保留符号）。
- 补丁函数名称与签名需与目标函数一致（替换场景）。
- Hook 场景下，建议将真实目标函数声明保留在补丁源码中，确保调用路径清晰。

### 3) Hook 命名规则

Hook 函数名必须使用以下前缀（代码常量：`LNK_HOOK_FUN_NAME_PREFIX`）：

- `_qpatch_hookfun_<target_symbol>`

例如要 Hook `sleep`，函数名应为 `_qpatch_hookfun_sleep`。

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

### 6) 禁止场景（高失败风险）

以下场景建议禁止直接投产：

- **函数过短**：函数头可覆盖字节不足（当前 64 位构建最小跳转覆盖长度为 `JMP_OPER_CODELEN=14` 字节）。
- **被内联函数**：目标函数被编译器内联后，调用点不再进入原符号地址。
- **高度优化/手写汇编入口**：函数序言不稳定、指令边界复杂，容易导致覆盖失败。
- **符号不可见或被裁剪**：strip/LTO 后符号不可解析，补丁无法建立映射。

建议先在预发环境用 `-q` + 回滚路径验证 `load/active/rollback` 全流程再上线。

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

## 版本兼容矩阵（含已验证范围）

> 以下“已验证”仅表示仓库中已有脚本/代码证据覆盖的范围；未标注项表示当前仓库未沉淀可复现验证记录。

### qpatch（热补丁）

| 维度 | 范围 | 已验证范围 | 依据 |
|---|---|---|---|
| 内核/发行版 | Linux 用户态进程 | ⚠️ 未在仓库中固化具体 Kernel/发行版版本号 | 项目定位与脚本均为 Linux 场景 |
| 架构 | x86_64 / aarch64 | ✅ x86_64、aarch64 | `scripts/test_x86_suite.sh`、`scripts/test_aarch64_suite.sh` |
| glibc | 支持 Hook glibc 函数 | ⚠️ 未在仓库中固化 glibc 版本区间 | README 特性说明（Hook glibc functions） |

### gotrace（Go 调用跟踪）

| 维度 | 范围 | 已验证范围 | 依据 |
|---|---|---|---|
| Go 版本 | Go 1.16 / 1.17 函数序言模式 | ✅ 1.16–1.17 | `gotrace.c` 中 `GOTRACE_GO_116`、`GOTRACE_GO_117` 预置模式 |
| 更新 Go 版本 | 新版 Go 可能调整函数序言 | ⚠️ 需补充新序言匹配后再声明支持 | `gotrace.c` 的固定 opcode 匹配机制 |

---

## Testing

See [`TEST_CASES.md`](./TEST_CASES.md) for functional, boundary, and regression test cases
covering both `qpatch` and `gotrace` workflows.

---

## License

See `LICENSE`.
