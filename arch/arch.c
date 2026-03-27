//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#include "arch.h"

#include "aarch64/arch_aarch64.h"
#include "x86_64/arch_x86_64.h"

const struct qpatch_arch_ops *qpatch_arch_select(
    const struct symbol_elf_pid *hp) {
  if (!hp) {
    return NULL;
  }
  if (hp->is64 == ELF_IS_64BIT) {
    return qpatch_arch_x86_64_get();
  }
  return NULL;
}

const struct qpatch_arch_ops *qpatch_arch_default(void) {
#if defined(__aarch64__)
  return qpatch_arch_aarch64_get();
#else
  return qpatch_arch_x86_64_get();
#endif
}
