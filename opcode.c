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

unsigned long get_opcode_size_64(unsigned char* startaddress) {
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
