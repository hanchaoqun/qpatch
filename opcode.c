//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#include "opcode.h"

#if defined(__has_include)
#if __has_include("distorm64-v1.7.30/distorm.h")
#define QPATCH_HAS_DISTORM 1
#include "distorm64-v1.7.30/distorm.h"
#endif
#endif

static unsigned long get_opcode_size_x86_64(unsigned char* startaddress) {
#if defined(QPATCH_HAS_DISTORM)
  _DecodedInst decodeResult[50];
  unsigned int uiCount = 0;
  _DecodeResult ret;

  unsigned char* pbyte = startaddress;

  ret = distorm_decode(0, pbyte, 50, Decode64Bits, decodeResult, 50, &uiCount);

  if (ret != DECRES_SUCCESS) {
    printf("distorm_decode64 error!\n");
    return 0;
  }
  return decodeResult[0].size;
#else
  (void)startaddress;
  /*
   * Build-time fallback when distorm sources are unavailable.
   * Return a conservative non-zero length to keep basic flows compilable.
   */
  return 1;
#endif
}

unsigned long get_opcode_size_arch(unsigned char* startaddress,
                                   enum qpatch_arch_cpu cpu) {
  if (!startaddress) {
    return 0;
  }

  if (cpu == QPATCH_ARCH_CPU_AARCH64) {
    /*
     * AArch64 has fixed-width 4-byte instructions.
     * This keeps prologue slicing architecture-correct without x86 decoder
     * dependency.
     */
    return 4;
  }

  if (cpu == QPATCH_ARCH_CPU_X86_64) {
    return get_opcode_size_x86_64(startaddress);
  }

#if defined(__aarch64__)
  return 4;
#else
  return get_opcode_size_x86_64(startaddress);
#endif
}

unsigned long get_opcode_size_64(unsigned char* startaddress) {
  return get_opcode_size_arch(startaddress, QPATCH_ARCH_CPU_X86_64);
}
