//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#ifndef __HPATCH_OPCODE_H__
#define __HPATCH_OPCODE_H__

#include "define.h"
#include "arch/arch.h"

extern unsigned long get_opcode_size_64(unsigned char* startaddress);
extern unsigned long get_opcode_size_arch(unsigned char* startaddress,
                                          enum qpatch_arch_cpu cpu);

#define get_opcode_size(a) get_opcode_size_64((a))

#endif /* __HPATCH_OPCODE_H__ */
