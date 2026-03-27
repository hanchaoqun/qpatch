//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#include "arch_x86_64.h"

static const char *qpatch_arch_x86_64_reg_ip_name(void) {
  return "RIP";
}

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

const struct qpatch_arch_ops *qpatch_arch_x86_64_get(void) {
  static const struct qpatch_arch_ops k_ops = {
      .cpu = QPATCH_ARCH_CPU_X86_64,
      .name = "x86_64",
      .elf_bit = ELF_IS_64BIT,
      .reg_ip_name = qpatch_arch_x86_64_reg_ip_name,
      .reg_get_ip = qpatch_arch_x86_64_reg_get_ip,
      .reg_set_ip = qpatch_arch_x86_64_reg_set_ip,
      .reg_get_sp = qpatch_arch_x86_64_reg_get_sp,
      .reg_set_sp = qpatch_arch_x86_64_reg_set_sp,
      .reg_get_ret = qpatch_arch_x86_64_reg_get_ret,
  };
  return &k_ops;
}
