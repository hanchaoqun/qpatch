//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//

#ifndef __HPATCH_LINKABLE_H__
#define __HPATCH_LINKABLE_H__

#include "define.h"
#include "symbol.h"

/*
080484d4 <testFunction>:
80484d4: 55        push   %ebp
80484d5: 89 e5     mov    %esp,%ebp
80484d7: 83 ec 18  sub    $0x18,%esp
...
8048500: c9        leave
8048501: c3        ret
*/

#define LNK_MAX_HOOK_FUNC_COUNT 20
#define LNK_MAX_REP_FUNC_COUNT 200
#define LNK_MAX_NAME_LEN 128

#if __WORDSIZE == 64

//#define JMP_OPER_CODE    0xE9
#define JMP_OPER_CODELEN 14
#define NOP_OPER_CODE 0x90
#define NOP_OPER_CODELEN 1

//(JMP_OPER_CODELEN+4)
#define LNK_MAX_CODE_BAK_LEN 18
//(JMP_OPER_CODELEN+4+8)
#define LNK_MAX_CODE_ORIG_FUNHEAD_LEN 26
//(JMP_OPER_CODELEN+4)
#define LNK_MAX_CODE_JMP_ORIG_FUNTAIL_LEN 18
#define LNK_MAX_CODE_ORIG_FUNHEAD_SEARCH_LEN (LNK_MAX_CODE_ORIG_FUNHEAD_LEN * 3)

#else

#define JMP_OPER_CODE 0xE9
#define JMP_OPER_CODELEN 5
#define NOP_OPER_CODE 0x90
#define NOP_OPER_CODELEN 1

//(JMP_OPER_CODELEN+3)
#define LNK_MAX_CODE_BAK_LEN 8
//(JMP_OPER_CODELEN+3+8)
#define LNK_MAX_CODE_ORIG_FUNHEAD_LEN 16
//(JMP_OPER_CODELEN+3)
#define LNK_MAX_CODE_JMP_ORIG_FUNTAIL_LEN 8
#define LNK_MAX_CODE_ORIG_FUNHEAD_SEARCH_LEN (LNK_MAX_CODE_ORIG_FUNHEAD_LEN * 3)

#endif

#define LNK_BSS_BASE_OFFSET_IN_OBJ(datalen) \
  ((void*)((char*)0 + (long)datalen) + LNK_MAX_PLTGOT_LEN)
#define LNK_PLTGOT_BASE_OFFSET_IN_OBJ(datalen) \
  ((void*)((char*)0 + (long)datalen))

//#if __WORDSIZE == 64
#pragma pack(1)
struct linkable_elf_pltgot_item {
  unsigned char jmpopcode[6];  //"\xff\x25\x0\x0\x0\x0";
                               // union{
  //	unsigned char addrchars[8];  //\x0\x0\x0\x0\x0\x0\x0\x0
  long addrlong;
  //} addr;
};
#pragma pack()
//#endif
#define LNK_ELF_PLTGOT_ADDRLONG_OFFSET \
  ((size_t) & (((struct linkable_elf_pltgot_item*)0)->addrlong))

struct linkable_elf_rep_fun {
  char name[LNK_MAX_NAME_LEN]; /* null terminated symbol name */
  long newaddr;                /* address at which it is available */
  long oldaddr;                /* address at which it is available */
  size_t newsize;              /* size of the symbol if available */
  size_t oldsize;              /* size of the symbol if available */
  size_t isreplaced;           /* is done for replace */
  size_t funbaklen;
  unsigned char funbak[LNK_MAX_CODE_BAK_LEN];
} __attribute__((aligned(8)));

struct linkable_elf_hook_fun {
  size_t idx;
  char newname[LNK_MAX_NAME_LEN]; /* null terminated symbol name */
  char oldname[LNK_MAX_NAME_LEN]; /* null terminated symbol name */
  long newaddr;                   /* address at which it is available */
  long oldaddr;                   /* address at which it is available */
  size_t newsize;                 /* size of the symbol if available */
  size_t oldsize;                 /* size of the symbol if available */
  size_t isreplaced;              /* is done for replace */
  size_t funbaklen;
  unsigned char funbak[LNK_MAX_CODE_BAK_LEN];
  unsigned char origfunhead[LNK_MAX_CODE_ORIG_FUNHEAD_LEN];
  unsigned char jmporigfuntail[LNK_MAX_CODE_JMP_ORIG_FUNTAIL_LEN];
} __attribute__((aligned(8)));

struct linkable_elf_rep_hdr {
  long _pat_callback_active_before;
  long _pat_callback_active_after;
  long _pat_callback_deactive_before;
  long _pat_callback_deactive_after;
  size_t hookfuns_num;
  struct linkable_elf_hook_fun hookfuns[LNK_MAX_HOOK_FUNC_COUNT];
  size_t repfuns_num;
  struct linkable_elf_rep_fun repfuns[LNK_MAX_REP_FUNC_COUNT];
} __attribute__((aligned(8)));

#define LNK_HOOK_FUN_STRU_SIZE (sizeof(struct linkable_elf_hook_fun))
#define LNK_HOOK_FUNS_OFFSET_OF_HDR \
  ((size_t)((struct linkable_elf_rep_hdr*)0)->hookfuns)
#define LNK_HOOK_FUN_OFFSET_OF_STRU \
  ((size_t)((struct linkable_elf_hook_fun*)0)->origfunhead)
#define LNK_HOOK_FUN_JMPTAIL_OFFSET_OF_STRU \
  ((size_t)((struct linkable_elf_hook_fun*)0)->jmporigfuntail)
#define LNK_HOOK_FUN_ORIGFUNHEAD_ENTRY(rephdr, idx)                        \
  (rephdr + LNK_HOOK_FUNS_OFFSET_OF_HDR + (idx * LNK_HOOK_FUN_STRU_SIZE) + \
   LNK_HOOK_FUN_OFFSET_OF_STRU)
#define LNK_HOOK_FUN_ORIGFUNTAIL_ENTRY(rephdr, idx)                        \
  (rephdr + LNK_HOOK_FUNS_OFFSET_OF_HDR + (idx * LNK_HOOK_FUN_STRU_SIZE) + \
   LNK_HOOK_FUN_JMPTAIL_OFFSET_OF_STRU)

struct linkable_elf_rela_info {
  size_t sechdr_idx;
  size_t sechdr_type;
  /* size_t sechdr_dst_idx; */
  size_t sechdr_sym_idx;
  size_t sechdr_str_idx;
} __attribute__((aligned(8)));

#define LNK_HOOK_FUN_NAME_PREFIX "_qpatch_hookfun_"

// struct linkable_elf_hook_info {
//    struct linkable_elf_hook_fun hf;
//    symbol_elf_sym newsym;
//};

struct linkable_elf_internals {
  struct symbol_elf_internals ei;
  struct symbol_elf_pid* hp;
  struct linkable_elf_rela_info* relahdr_infos;
  size_t relahdr_info_num;
  // struct linkable_elf_hook_info hook_infos[LNK_MAX_HOOK_FUNC_COUNT];
  // size_t hookinfo_num;
  void* objptr;
  size_t objlen;
  void* baseptr;
  void* bssptr;
  size_t bsslen;
  void* pltgotptr;
  size_t pltgotlen;
  struct linkable_elf_rep_hdr rephdr;
  void* base_rephdr_ptr;
} __attribute__((aligned(8)));

enum linkable_search_type {
  LNK_SH_TYPE_EITHER,
  LNK_SH_TYPE_FUN,
  LNK_SH_TYPE_OBJ
};

extern long linkable_get_file_size(const char* filename);

struct linkable_elf_internals* linkable_elf_obj_create(
    pid_t pid, int elang, const char* filename, void* baseptr,
    void* base_rephdr_ptr, void* bssptr, long bsslen, void* pltgotptr,
    long pltgotlen, const char* pat_symbol);

void linkable_elf_obj_destory(struct linkable_elf_internals* li);

#endif /* __HPATCH_LINKABLE_H__ */
