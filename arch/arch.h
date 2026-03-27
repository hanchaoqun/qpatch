//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#ifndef __HPATCH_ARCH_H__
#define __HPATCH_ARCH_H__

#include "../define.h"
#include "../symbol.h"

enum qpatch_arch_cpu {
  QPATCH_ARCH_CPU_UNKNOWN = 0,
  QPATCH_ARCH_CPU_X86_64,
  QPATCH_ARCH_CPU_AARCH64
};

struct qpatch_arch_ops {
  enum qpatch_arch_cpu cpu;
  const char *name;
  enum symbol_elf_bit elf_bit;
  size_t stack_alignment;

  const char *(*reg_ip_name)(void);
  uintptr_t (*reg_get_ip)(const struct user *regs);
  void (*reg_set_ip)(struct user *regs, uintptr_t ip);
  uintptr_t (*reg_get_sp)(const struct user *regs);
  void (*reg_set_sp)(struct user *regs, uintptr_t sp);
  uintptr_t (*reg_get_ret)(const struct user *regs);

  int (*call_func)(pid_t pid, const char *fn_name, struct user *iregs,
                   uintptr_t fn, uintptr_t arg1, uintptr_t arg2,
                   uintptr_t *out_ret);
  int (*run_syscall6)(pid_t pid, const char *sys_name, struct user *iregs,
                      uintptr_t syscallno, uintptr_t arg1, uintptr_t arg2,
                      uintptr_t arg3, uintptr_t arg4, uintptr_t arg5,
                      uintptr_t arg6, uintptr_t *out_ret);
  /*
   * Note: some architectures (e.g. AArch64) only support up to 6 syscall args.
   * Implementations may reject non-zero arg7 with EINVAL and require callers to
   * pass arg7 == 0.
   */
  int (*run_syscall7)(pid_t pid, const char *sys_name, struct user *iregs,
                      uintptr_t syscallno, uintptr_t arg1, uintptr_t arg2,
                      uintptr_t arg3, uintptr_t arg4, uintptr_t arg5,
                      uintptr_t arg6, uintptr_t arg7, uintptr_t *out_ret);
};

const struct qpatch_arch_ops *qpatch_arch_select(
    const struct symbol_elf_pid *hp);
const struct qpatch_arch_ops *qpatch_arch_default(void);

#endif /* __HPATCH_ARCH_H__ */
