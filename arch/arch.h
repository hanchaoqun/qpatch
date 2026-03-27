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

enum qpatch_arch_cpu { QPATCH_ARCH_CPU_UNKNOWN = 0, QPATCH_ARCH_CPU_X86_64 };

struct qpatch_arch_ops {
  enum qpatch_arch_cpu cpu;
  const char *name;
  enum symbol_elf_bit elf_bit;

  const char *(*reg_ip_name)(void);
  uintptr_t (*reg_get_ip)(const struct user *regs);
  void (*reg_set_ip)(struct user *regs, uintptr_t ip);
  uintptr_t (*reg_get_sp)(const struct user *regs);
  void (*reg_set_sp)(struct user *regs, uintptr_t sp);
  uintptr_t (*reg_get_ret)(const struct user *regs);
};

const struct qpatch_arch_ops *qpatch_arch_select(
    const struct symbol_elf_pid *hp);

#endif /* __HPATCH_ARCH_H__ */
