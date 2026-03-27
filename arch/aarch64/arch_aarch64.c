//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include "arch_aarch64.h"

#if defined(__aarch64__)
#include <asm/ptrace.h>
#include <elf.h>
#endif

static const char *qpatch_arch_aarch64_reg_ip_name(void) {
  return "PC";
}

#if defined(__aarch64__)
static int qpatch_arch_aarch64_getregs(pid_t pid, struct user_pt_regs *regs) {
  struct iovec iov = {.iov_base = regs, .iov_len = sizeof(*regs)};
  return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

static int qpatch_arch_aarch64_setregs(pid_t pid, struct user_pt_regs *regs) {
  struct iovec iov = {.iov_base = regs, .iov_len = sizeof(*regs)};
  return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}
#endif

static uintptr_t qpatch_arch_aarch64_reg_get_ip(const struct user *regs) {
#if defined(__aarch64__)
  if (!regs) {
    return 0;
  }
  return regs->regs.pc;
#else
  (void)regs;
  return 0;
#endif
}

static void qpatch_arch_aarch64_reg_set_ip(struct user *regs, uintptr_t ip) {
#if defined(__aarch64__)
  if (!regs) {
    return;
  }
  regs->regs.pc = ip;
#else
  (void)regs;
  (void)ip;
#endif
}

static uintptr_t qpatch_arch_aarch64_reg_get_sp(const struct user *regs) {
#if defined(__aarch64__)
  if (!regs) {
    return 0;
  }
  return regs->regs.sp;
#else
  (void)regs;
  return 0;
#endif
}

static void qpatch_arch_aarch64_reg_set_sp(struct user *regs, uintptr_t sp) {
#if defined(__aarch64__)
  if (!regs) {
    return;
  }
  regs->regs.sp = sp;
#else
  (void)regs;
  (void)sp;
#endif
}

static uintptr_t qpatch_arch_aarch64_reg_get_ret(const struct user *regs) {
#if defined(__aarch64__)
  if (!regs) {
    return 0;
  }
  return regs->regs.regs[0];
#else
  (void)regs;
  return 0;
#endif
}

static int qpatch_arch_aarch64_not_implemented(void) {
  errno = ENOSYS;
  return -1;
}

static int qpatch_arch_aarch64_call_func(pid_t pid, const char *fn_name,
                                         struct user *iregs, uintptr_t fn,
                                         uintptr_t arg1, uintptr_t arg2,
                                         uintptr_t *out_ret) {
#if defined(__aarch64__)
  int rc = -1;
  int status = 0;
  struct user_pt_regs regs;
  struct user_pt_regs orig_regs;
  struct user_pt_regs ret_regs;
  int has_orig = 0;
  int has_ret = 0;
  (void)fn_name;
  if (!fn) {
    errno = EINVAL;
    return -1;
  }
  memset(&regs, 0, sizeof(regs));
  memset(&orig_regs, 0, sizeof(orig_regs));
  memset(&ret_regs, 0, sizeof(ret_regs));
  do {
    if (qpatch_arch_aarch64_getregs(pid, &regs) < 0) {
      break;
    }
    memcpy(&orig_regs, &regs, sizeof(orig_regs));
    has_orig = 1;

    regs.sp = (regs.sp - 16) & (~0xFUL);
    if (ptrace(PTRACE_POKEDATA, pid, (void *)regs.sp, (void *)0UL) < 0) {
      break;
    }
    regs.regs[0] = arg1;
    regs.regs[1] = arg2;
    regs.regs[30] = 0; /* LR */
    regs.pc = fn;
    if (qpatch_arch_aarch64_setregs(pid, &regs) < 0) {
      break;
    }
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
      break;
    }
    if (waitpid(pid, &status, 0) < 0) {
      break;
    }
    if (qpatch_arch_aarch64_getregs(pid, &ret_regs) < 0) {
      break;
    }
    has_ret = 1;
    if (out_ret) {
      *out_ret = ret_regs.regs[0];
    }
    if (iregs) {
      memset(iregs, 0, sizeof(*iregs));
    }
    rc = 0;
  } while (0);

  if (has_orig) {
    if (qpatch_arch_aarch64_setregs(pid, &orig_regs) < 0) {
      if (rc == 0) {
        rc = -1;
      }
    }
  }
  if (rc < 0 && has_ret && out_ret) {
    *out_ret = ret_regs.regs[0];
  }
  return rc;
#else
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
#endif
}

static int qpatch_arch_aarch64_run_syscall6(
    pid_t pid, const char *sys_name, struct user *iregs, uintptr_t syscallno,
    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5, uintptr_t arg6, uintptr_t *out_ret) {
#if defined(__aarch64__)
  int status = 0;
  struct user_pt_regs regs;
  (void)sys_name;
  memset(&regs, 0, sizeof(regs));
  if (qpatch_arch_aarch64_getregs(pid, &regs) < 0) {
    return -1;
  }
  regs.regs[8] = syscallno;
  regs.regs[0] = arg1;
  regs.regs[1] = arg2;
  regs.regs[2] = arg3;
  regs.regs[3] = arg4;
  regs.regs[4] = arg5;
  regs.regs[5] = arg6;
  if (qpatch_arch_aarch64_setregs(pid, &regs) < 0) {
    return -1;
  }
  if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
    return -1;
  }
  if (waitpid(pid, &status, 0) < 0) {
    return -1;
  }
  if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
    return -1;
  }
  if (waitpid(pid, &status, 0) < 0) {
    return -1;
  }
  if (qpatch_arch_aarch64_getregs(pid, &regs) < 0) {
    return -1;
  }
  if (out_ret) {
    *out_ret = regs.regs[0];
  }
  if (iregs) {
    memset(iregs, 0, sizeof(*iregs));
  }
  return 0;
#else
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
#endif
}

static int qpatch_arch_aarch64_run_syscall7(
    pid_t pid, const char *sys_name, struct user *iregs, uintptr_t syscallno,
    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5, uintptr_t arg6, uintptr_t arg7, uintptr_t *out_ret) {
#if defined(__aarch64__)
  if (arg7 != 0) {
    fprintf(stderr,
            "aarch64 syscall adapter(%s) does not support arg7=%p (expected "
            "0)\n",
            sys_name ? sys_name : "unknown", (void *)arg7);
    errno = EINVAL;
    return -1;
  }
  return qpatch_arch_aarch64_run_syscall6(pid, sys_name, iregs, syscallno, arg1,
                                          arg2, arg3, arg4, arg5, arg6,
                                          out_ret);
#else
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
#endif
}

const struct qpatch_arch_ops *qpatch_arch_aarch64_get(void) {
  static const struct qpatch_arch_ops k_ops = {
      .cpu = QPATCH_ARCH_CPU_AARCH64,
      .name = "aarch64",
      .elf_bit = ELF_IS_64BIT,
      .stack_alignment = 16,
      .reg_ip_name = qpatch_arch_aarch64_reg_ip_name,
      .reg_get_ip = qpatch_arch_aarch64_reg_get_ip,
      .reg_set_ip = qpatch_arch_aarch64_reg_set_ip,
      .reg_get_sp = qpatch_arch_aarch64_reg_get_sp,
      .reg_set_sp = qpatch_arch_aarch64_reg_set_sp,
      .reg_get_ret = qpatch_arch_aarch64_reg_get_ret,
      .call_func = qpatch_arch_aarch64_call_func,
      .run_syscall6 = qpatch_arch_aarch64_run_syscall6,
      .run_syscall7 = qpatch_arch_aarch64_run_syscall7,
  };
  return &k_ops;
}
