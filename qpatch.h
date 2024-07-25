//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#ifndef __HPATCH_QPATCH_H__
#define __HPATCH_QPATCH_H__

#include "define.h"
#include "libqpatch.h"
#include "linkable.h"
#include "opcode.h"
#include "ptrace.h"
#include "symbol.h"

/*
Mem Layerout:
----------qpatch_mmap_room_hdr -> mhdr---------
----------long ptr2data---------
----------long ptr2rephdr---------
----------linkable_elf_rep_hdr rephdr---------
----------long prt2bss---------
----------long bsslen---------
----------long datalen---------
----------long prt2pltgot---------
----------long pltgotlen---------
----------char data*   objbase    ---------
----------char pltgot* pltgotbase ---------
----------char bss*    bssbase    ---------
*/

struct qpatch_mmap_room {
  struct qpatch_mmap_room_hdr mhdr;
  long ptr2data;
  long ptr2rephdr;
  struct linkable_elf_rep_hdr rephdr;
  /* BEGIN add for version 2 */
  long prt2bss;
  long bsslen;
  long datalen;
  /* END add for version 2 */
  /* BEGIN add for version 3 */
  long prt2pltgot;
  long pltgotlen;
  /* END add for version 3 */
  char data[0]; /* objbase */
} __attribute__((aligned(8)));

#define LNK_MAX_BSS_LEN (1024 * 1024 * 4)
#define LNK_MAX_PLTGOT_LEN (14 * 1024)
#define LNK_MIN_MMAP_ROOM_LEN(datalen)                          \
  ((sizeof(struct qpatch_mmap_room) + 0 + LNK_MAX_REP_GAP_LEN + \
    LNK_MAX_PLTGOT_LEN + LNK_MAX_BSS_LEN + (long)datalen) &     \
   0xFFFFF000) +                                                \
      0x1000;
#define LNK_BSS_BASE_OFFSET_IN_ROOM(datalen)                                  \
  ((void *)((char *)&(((struct qpatch_mmap_room *)0)->data) + (long)datalen + \
            LNK_MAX_PLTGOT_LEN))
#define LNK_PLTGOT_BASE_OFFSET_IN_ROOM(datalen) \
  ((void *)((char *)&(((struct qpatch_mmap_room *)0)->data) + (long)datalen))

#define LNK_MAX_REP_GAP_LEN (32)
/* #define LNK_MIN_MMAP_ROOM_LEN (sizeof(struct
 * qpatch_mmap_room)+0+LNK_MAX_REP_GAP_LEN) */
#define LNK_OBJ_BASE_OFFSET_IN_ROOM \
  ((void *)&(((struct qpatch_mmap_room *)0)->data))
#define LNK_REPHDR_OFFSET_IN_ROOM \
  ((void *)&(((struct qpatch_mmap_room *)0)->rephdr))

#endif /* __HPATCH_QPATCH_H__ */
