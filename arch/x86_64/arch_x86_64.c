//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#include <errno.h>

#include "arch_x86_64.h"
#include "../../ptrace.h"

static const char *qpatch_arch_x86_64_reg_ip_name(void) {
  return "RIP";
}

#if defined(__x86_64__)

static uintptr_t qpatch_arch_x86_64_reg_get_ip(const struct user *regs) {
  return regs->regs.rip;
}

static void qpatch_arch_x86_64_reg_set_ip(struct user *regs, uintptr_t ip) {
  regs->regs.rip = ip;
}

static uintptr_t qpatch_arch_x86_64_reg_get_sp(const struct user *regs) {
  return regs->regs.rsp;
}

static void qpatch_arch_x86_64_reg_set_sp(struct user *regs, uintptr_t sp) {
  regs->regs.rsp = sp;
}

static uintptr_t qpatch_arch_x86_64_reg_get_ret(const struct user *regs) {
  return regs->regs.rax;
}

static int qpatch_arch_x86_64_call_func(pid_t pid, const char *fn_name,
                                        struct user *io_regs, uintptr_t fn,
                                        uintptr_t arg1, uintptr_t arg2,
                                        uintptr_t *out_ret) {
  int rc = 0;
  uintptr_t result = 0;
  struct user iregs;
  if (!io_regs || !fn) {
    return -1;
  }
  memcpy(&iregs, io_regs, sizeof(iregs));
  do {
    PTRACE_ASM_SET_BREAKPOINT(pid, iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
    PTRACE_ASM_PASS_ARGS2FUNC(pid, iregs, fn, arg1, arg2, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2FUNC");
    PTRACE_ASM_SET_REGS(pid, fn_name ? fn_name : "func", iregs, rc);
    PTRACE_ASM_CALL_FUNC(pid, fn_name ? fn_name : "func", iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "CALL_FUNC");
    result = PTRACE_REG_AX(iregs);
  } while (0);
  if (rc < 0) {
    return -1;
  }
  memcpy(io_regs, &iregs, sizeof(iregs));
  if (out_ret) {
    *out_ret = result;
  }
  return 0;
}

static int qpatch_arch_x86_64_run_syscall6(
    pid_t pid, const char *sys_name, struct user *io_regs, uintptr_t syscallno,
    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5, uintptr_t arg6, uintptr_t *out_ret) {
  int rc = 0;
  uintptr_t result = 0;
  struct user iregs;
  if (!io_regs) {
    return -1;
  }
  memcpy(&iregs, io_regs, sizeof(iregs));
  do {
    PTRACE_ASM_PASS_ARGS2SYSCALL6(pid, iregs, syscallno, arg1, arg2, arg3,
                                  arg4, arg5, arg6, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2SYSCALL6");
    PTRACE_ASM_SET_REGS(pid, sys_name ? sys_name : "syscall6", iregs, rc);
    PTRACE_ASM_RUN_SYSCALL6(pid, iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "RUN_SYSCALL6");
    result = PTRACE_REG_AX(iregs);
  } while (0);
  if (rc < 0) {
    return -1;
  }
  memcpy(io_regs, &iregs, sizeof(iregs));
  if (out_ret) {
    *out_ret = result;
  }
  return 0;
}

static int qpatch_arch_x86_64_run_syscall7(
    pid_t pid, const char *sys_name, struct user *io_regs, uintptr_t syscallno,
    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5, uintptr_t arg6, uintptr_t arg7, uintptr_t *out_ret) {
  int rc = 0;
  uintptr_t result = 0;
  struct user iregs;
  if (!io_regs) {
    return -1;
  }
  memcpy(&iregs, io_regs, sizeof(iregs));
  do {
    PTRACE_ASM_SET_BREAKPOINT(pid, iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
    PTRACE_ASM_PASS_ARGS2SYSCALL7(pid, iregs, syscallno, arg1, arg2, arg3,
                                  arg4, arg5, arg6, arg7, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2SYSCALL7");
    PTRACE_ASM_SET_REGS(pid, sys_name ? sys_name : "syscall7", iregs, rc);
    PTRACE_ASM_RUN_SYSCALL7(pid, iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "RUN_SYSCALL7");
    result = PTRACE_REG_AX(iregs);
  } while (0);
  if (rc < 0) {
    return -1;
  }
  memcpy(io_regs, &iregs, sizeof(iregs));
  if (out_ret) {
    *out_ret = result;
  }
  return 0;
}

#else

static int qpatch_arch_x86_64_not_implemented(void) {
  errno = ENOSYS;
  return -1;
}

static uintptr_t qpatch_arch_x86_64_reg_get_ip(const struct user *regs) {
  (void)regs;
  return 0;
}

static void qpatch_arch_x86_64_reg_set_ip(struct user *regs, uintptr_t ip) {
  (void)regs;
  (void)ip;
}

static uintptr_t qpatch_arch_x86_64_reg_get_sp(const struct user *regs) {
  (void)regs;
  return 0;
}

static void qpatch_arch_x86_64_reg_set_sp(struct user *regs, uintptr_t sp) {
  (void)regs;
  (void)sp;
}

static uintptr_t qpatch_arch_x86_64_reg_get_ret(const struct user *regs) {
  (void)regs;
  return 0;
}

static int qpatch_arch_x86_64_call_func(pid_t pid, const char *fn_name,
                                        struct user *io_regs, uintptr_t fn,
                                        uintptr_t arg1, uintptr_t arg2,
                                        uintptr_t *out_ret) {
  (void)pid;
  (void)fn_name;
  (void)io_regs;
  (void)fn;
  (void)arg1;
  (void)arg2;
  if (out_ret) {
    *out_ret = 0;
  }
  return qpatch_arch_x86_64_not_implemented();
}

static int qpatch_arch_x86_64_run_syscall6(
    pid_t pid, const char *sys_name, struct user *io_regs, uintptr_t syscallno,
    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5, uintptr_t arg6, uintptr_t *out_ret) {
  (void)pid;
  (void)sys_name;
  (void)io_regs;
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
  return qpatch_arch_x86_64_not_implemented();
}

static int qpatch_arch_x86_64_run_syscall7(
    pid_t pid, const char *sys_name, struct user *io_regs, uintptr_t syscallno,
    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5, uintptr_t arg6, uintptr_t arg7, uintptr_t *out_ret) {
  (void)pid;
  (void)sys_name;
  (void)io_regs;
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
  return qpatch_arch_x86_64_not_implemented();
}

#endif

const struct qpatch_arch_ops *qpatch_arch_x86_64_get(void) {
  static const struct qpatch_arch_ops k_ops = {
      .cpu = QPATCH_ARCH_CPU_X86_64,
      .name = "x86_64",
      .elf_bit = ELF_IS_64BIT,
      .stack_alignment = 16,
      .reg_ip_name = qpatch_arch_x86_64_reg_ip_name,
      .reg_get_ip = qpatch_arch_x86_64_reg_get_ip,
      .reg_set_ip = qpatch_arch_x86_64_reg_set_ip,
      .reg_get_sp = qpatch_arch_x86_64_reg_get_sp,
      .reg_set_sp = qpatch_arch_x86_64_reg_set_sp,
      .reg_get_ret = qpatch_arch_x86_64_reg_get_ret,
      .call_func = qpatch_arch_x86_64_call_func,
      .run_syscall6 = qpatch_arch_x86_64_run_syscall6,
      .run_syscall7 = qpatch_arch_x86_64_run_syscall7,
  };
  return &k_ops;
}
