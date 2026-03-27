//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#include <errno.h>

#include "arch_aarch64.h"

static const char *qpatch_arch_aarch64_reg_ip_name(void) {
  return "PC";
}

static uintptr_t qpatch_arch_aarch64_reg_get_zero(const struct user *regs) {
  (void)regs;
  return 0;
}

static void qpatch_arch_aarch64_reg_set_noop(struct user *regs, uintptr_t v) {
  (void)regs;
  (void)v;
}

static int qpatch_arch_aarch64_not_implemented(void) {
  errno = ENOSYS;
  return -1;
}

static int qpatch_arch_aarch64_call_func(pid_t pid, const char *fn_name,
                                         struct user *iregs, uintptr_t fn,
                                         uintptr_t arg1, uintptr_t arg2,
                                         uintptr_t *out_ret) {
  (void)pid;
  (void)fn_name;
  (void)iregs;
  (void)fn;
  (void)arg1;
  (void)arg2;
  if (out_ret) {
    *out_ret = 0;
  }
  return qpatch_arch_aarch64_not_implemented();
}

static int qpatch_arch_aarch64_run_syscall6(
    pid_t pid, const char *sys_name, struct user *iregs, uintptr_t syscallno,
    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5, uintptr_t arg6, uintptr_t *out_ret) {
  (void)pid;
  (void)sys_name;
  (void)iregs;
  (void)syscallno;
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  (void)arg5;
  (void)arg6;
  if (out_ret) {
    *out_ret = 0;
  }
  return qpatch_arch_aarch64_not_implemented();
}

static int qpatch_arch_aarch64_run_syscall7(
    pid_t pid, const char *sys_name, struct user *iregs, uintptr_t syscallno,
    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5, uintptr_t arg6, uintptr_t arg7, uintptr_t *out_ret) {
  (void)pid;
  (void)sys_name;
  (void)iregs;
  (void)syscallno;
  (void)arg1;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  (void)arg5;
  (void)arg6;
  (void)arg7;
  if (out_ret) {
    *out_ret = 0;
  }
  return qpatch_arch_aarch64_not_implemented();
}

const struct qpatch_arch_ops *qpatch_arch_aarch64_get(void) {
  static const struct qpatch_arch_ops k_ops = {
      .cpu = QPATCH_ARCH_CPU_AARCH64,
      .name = "aarch64(todo)",
      .elf_bit = ELF_IS_64BIT,
      .reg_ip_name = qpatch_arch_aarch64_reg_ip_name,
      .reg_get_ip = qpatch_arch_aarch64_reg_get_zero,
      .reg_set_ip = qpatch_arch_aarch64_reg_set_noop,
      .reg_get_sp = qpatch_arch_aarch64_reg_get_zero,
      .reg_set_sp = qpatch_arch_aarch64_reg_set_noop,
      .reg_get_ret = qpatch_arch_aarch64_reg_get_zero,
      .call_func = qpatch_arch_aarch64_call_func,
      .run_syscall6 = qpatch_arch_aarch64_run_syscall6,
      .run_syscall7 = qpatch_arch_aarch64_run_syscall7,
  };
  return &k_ops;
}
