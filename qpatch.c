//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#include <unistd.h>

#include "qpatch.h"

void qpatch_status_error(int act, int status) {
  // int state = -1;
  char *state_str = NULL;
  if (status == QPATCH_STATUS_ACTIVED) {
    // state =  2;
    state_str = "ACTIVED";
  } else if (status == QPATCH_STATUS_LOADED) {
    // state =  1;
    state_str = "LOADED";
  } else if (status == QPATCH_STATUS_INIT) {
    // state =  0;
    state_str = "INIT";
  } else {
    // state =  -1;
    state_str = "ERROR";
  }
  if (act == 3) {
    LOG(LOG_ERR, "PatchState:(%s)  ExpectState:(INIT or LOADED or ACTIVED)!",
        state_str);
  }
  if (act == 2) {
    LOG(LOG_ERR, "PatchState:(%s)  ExpectState:(LOADED or ACTIVED)!",
        state_str);
  }
  if (act == 1) {
    LOG(LOG_ERR, "PatchState:(%s)  ExpectState:(LOADED)!", state_str);
  }
  if (act == 0) {
    LOG(LOG_ERR, "PatchState:(%s)  ExpectState:(INIT)!", state_str);
  }
}

int qpatch_dsp_patch(pid_t pid, const char *objname, const char *dllname,
                     int symelang) {
  int rc = 0;
  struct linkable_elf_internals *li = NULL;
  struct ptrace_pid *pp = NULL;
  const unsigned char *paradata = 0;
  size_t paradatalen = 0; /* MAX is QPATCH_MAX_DATALEN */
  uintptr_t dllhandle = 0;
  uintptr_t callret = 0;
  // uintptr_t patfuncallret = 0;
  struct qpatch_call_in qci;
  void *baseptr = NULL;
  size_t objsize = 0;
  struct qpatch_mmap_room mroom;
  size_t mroom_total_len = 0;
  /* rep */
  size_t repfuns_num = 0;
  // size_t rel_repfuns_num = 0;
  struct linkable_elf_rep_fun *repf = NULL;
  // long offset = 0;
  // unsigned char jumpcode[LNK_MAX_CODE_BAK_LEN];
  /* hook */
  void *base_rephdr_ptr = NULL;
  size_t hokfuns_num = 0;
  // size_t rel_hokfuns_num = 0;
  struct linkable_elf_hook_fun *hokf = NULL;
  unsigned char tmpopcode[LNK_MAX_CODE_ORIG_FUNHEAD_SEARCH_LEN];
  // size_t searchsize = LNK_MAX_CODE_ORIG_FUNHEAD_SEARCH_LEN;
  // size_t origheadersize = 0;

  /* fill with NOP */
  memset(tmpopcode, NOP_OPER_CODE, LNK_MAX_CODE_ORIG_FUNHEAD_SEARCH_LEN);
  do {
    objsize = linkable_get_file_size(objname);
    if (!objsize) {
      LOG(LOG_ERR, "Error to get objsize %s!", objname);
      rc = -1;
      break;
    }
    objsize = (objsize & 0xFFFFFFF0) + 0x10;

    pp = (struct ptrace_pid *)ptrace_pp_create(pid, symelang);
    if (!pp) {
      LOG(LOG_ERR, "Error to create ptrace_pid!");
      rc = -1;
      break;
    }

    memset(&qci, 0, sizeof(qci));
    qci.hostpid = pid;
    qci.version = QPATCH_VERSION;
    paradata = (unsigned char *)&qci;
    paradatalen = sizeof(qci);
    callret = 0;
    if ((rc = ptrace_pp_inject_library(pp, dllname, "qpatch_check", paradata,
                                       paradatalen, &dllhandle, &callret)) <
        0) {
      LOG(LOG_ERR, "Error to inject library!");
      rc = -1;
      break;
    }
    long qpatch_check_ret = (long)callret;
    if ((qpatch_check_ret != QPATCH_RET_OK) &&
        (qpatch_check_ret != QPATCH_RET_DUP)) {
      LOG(LOG_ERR, "Error to call qpatch_check() ret %d!", qpatch_check_ret);
      rc = -1;
      break;
    }
    LOG(LOG_INFO, "Call qpatch_check() ret %d.", qpatch_check_ret);

    memset(&qci, 0, sizeof(qci));
    qci.hostpid = pid;
    qci.version = QPATCH_VERSION;
    /* qci.para1   = objsize + LNK_MAX_REP_GAP_LEN + LNK_MAX_REP_BUF_LEN; */
    /* align to page */
    mroom_total_len = LNK_MIN_MMAP_ROOM_LEN(objsize);
    qci.para1 = mroom_total_len;
    paradata = (unsigned char *)&qci;
    paradatalen = sizeof(qci);
    callret = 0;
    if ((rc = ptrace_pp_call_library(pp, dllhandle, "qpatch_open_room",
                                     paradata, paradatalen, &callret, 1)) < 0) {
      LOG(LOG_ERR, "Error to inject library!");
      rc = -1;
      break;
    }
    void *qpatch_open_room_ret = (void *)callret;
    if (!qpatch_open_room_ret) {
      LOG(LOG_ERR, "Error to call qpatch_open_room() ret %d!",
          qpatch_open_room_ret);
      rc = -1;
      break;
    }
    LOG(LOG_INFO, "Call qpatch_open_room() ret %p.", qpatch_open_room_ret);

    memset(&mroom, 0, sizeof(struct qpatch_mmap_room));
    if ((rc = ptrace_pp_read_data(pp, (uintptr_t)qpatch_open_room_ret,
                                  (unsigned char *)&mroom,
                                  sizeof(struct qpatch_mmap_room))) < 0) {
      LOG(LOG_ERR, "Read mmap room error!");
      rc = -1;
      break;
    }
    if (mroom.mhdr.version != QPATCH_VERSION) {
      LOG(LOG_ERR, "Read mmap room version(%u) is not expect(%u)!",
          mroom.mhdr.version, QPATCH_VERSION);
      rc = -1;
      break;
    }

    if (mroom.mhdr.status == QPATCH_STATUS_INIT) {
      printf("INIT\n");
      rc = 0;
      break;
    } else if (mroom.mhdr.status == QPATCH_STATUS_LOADED) {
      printf("LOADED\n");
    } else if (mroom.mhdr.status == QPATCH_STATUS_ACTIVED) {
      printf("ACTIVED\n");
    } else {
      LOG(LOG_INFO, "Read mmap room status(%u) is not expect!",
          mroom.mhdr.status);
      qpatch_status_error(3, mroom.mhdr.status);
      rc = -1;
      break;
    }

    baseptr = (void *)mroom.ptr2data;
    if (baseptr != (void *)((size_t)qpatch_open_room_ret +
                            (size_t)LNK_OBJ_BASE_OFFSET_IN_ROOM)) {
      LOG(LOG_ERR,
          "Qpatch room error ptr2data(baseptr), addr(%p) + baseoff(%p) != "
          "baseptr(%p)!!",
          qpatch_open_room_ret, LNK_OBJ_BASE_OFFSET_IN_ROOM, baseptr);
      rc = -1;
      break;
    }
    base_rephdr_ptr = (void *)mroom.ptr2rephdr;
    if (base_rephdr_ptr != (void *)((size_t)qpatch_open_room_ret +
                                    (size_t)LNK_REPHDR_OFFSET_IN_ROOM)) {
      LOG(LOG_ERR,
          "Qpatch room error base_rephdr_ptr, addr(%p) + rephdroff(%p) != "
          "rephdrptr(%p)!!",
          qpatch_open_room_ret, LNK_REPHDR_OFFSET_IN_ROOM, base_rephdr_ptr);
      rc = -1;
      break;
    }
    repfuns_num = mroom.rephdr.repfuns_num;
    if (repfuns_num < 0 || repfuns_num > LNK_MAX_REP_FUNC_COUNT) {
      LOG(LOG_ERR, "Qpatch room error repfuns_num(%u) MAX(%u)!!", repfuns_num,
          LNK_MAX_REP_FUNC_COUNT);
      rc = -1;
      break;
    }
    hokfuns_num = mroom.rephdr.hookfuns_num;
    if (hokfuns_num < 0 || hokfuns_num > LNK_MAX_HOOK_FUNC_COUNT) {
      LOG(LOG_ERR, "Qpatch room error hokfuns_num(%u) MAX(%u)!!", hokfuns_num,
          LNK_MAX_HOOK_FUNC_COUNT);
      rc = -1;
      break;
    }

    /* rep func begin */
    int fidx = 0;
    for (fidx = 0; fidx < repfuns_num; fidx++) {
      repf = &(mroom.rephdr.repfuns[fidx]);
      LOG(LOG_INFO,
          "Actived(%s) repfun<%s> oldaddr(%p) newaddr(%p) oldsize(%u) "
          "newsize(%u) ",
          (repf->isreplaced) ? "YES" : "NO", repf->name, repf->oldaddr,
          repf->newaddr, repf->oldsize, repf->newsize);
    }
    if (rc < 0) {
      break;
    }
    /* rep fun end */

    /* hook fun begin */
    int hidx = 0;
    for (hidx = 0; hidx < hokfuns_num; hidx++) {
      hokf = &(mroom.rephdr.hookfuns[hidx]);
      LOG(LOG_INFO,
          "Actived(%s) hookfun<%s> oldaddr(%p) newaddr(%p) oldsize(%u) "
          "newsize(%u) ",
          (hokf->isreplaced) ? "YES" : "NO", hokf->oldname, hokf->oldaddr,
          hokf->newaddr, hokf->oldsize, hokf->newsize);
    }
    if (rc < 0) {
      break;
    }
    /* hook fun end */

    /*
    LOG(LOG_DEBUG, "Detaching from PID %d.", pp->hp->pid);
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
            LOG(LOG_DEBUG, "Error detaching from PID %d", pp->hp->pid);
            rc = -1;
    }*/

    LOG(LOG_DEBUG,
        "Qpatch room addr(%p) len(%u) baseoff(%p) baseptr(%p) rephdroff(%p) "
        "rephdrptr(%p) repfuns(%u) hookfuns(%u)",
        qpatch_open_room_ret, mroom_total_len, LNK_OBJ_BASE_OFFSET_IN_ROOM,
        baseptr, LNK_REPHDR_OFFSET_IN_ROOM, base_rephdr_ptr,
        mroom.rephdr.repfuns_num, mroom.rephdr.hookfuns_num);
    LOG(LOG_DEBUG, "Dsp patch is ok status is (%u).", mroom.mhdr.status);
  } while (0);

  if (rc < 0) {
    /*
    LOG(LOG_DEBUG, "Detaching from PID %d.", pp->hp->pid);
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
            LOG(LOG_DEBUG, "Error detaching from PID %d", pp->hp->pid);
            rc = -1;
    }*/
  }

  if (li) {
    linkable_elf_obj_destory(li);
    li = 0;
  }
  if (pp) {
    ptrace_pp_destroy(pp);
    pp = 0;
  }

  return rc;
}

int qpatch_rol_patch(pid_t pid, const char *objname, const char *dllname,
                     int symelang) {
  int rc = 0;
  struct linkable_elf_internals *li = NULL;
  struct ptrace_pid *pp = NULL;
  const unsigned char *paradata = 0;
  size_t paradatalen = 0; /* MAX is QPATCH_MAX_DATALEN */
  uintptr_t dllhandle = 0;
  uintptr_t callret = 0;
  struct qpatch_call_in qci;
  void *baseptr = NULL;
  size_t objsize = 0;
  struct qpatch_mmap_room mroom;
  size_t mroom_total_len = 0;
  /*rep*/
  size_t repfuns_num = 0;
  size_t rel_repfuns_num = 0;
  struct linkable_elf_rep_fun *repf = NULL;
  long offset = 0;
  unsigned char jumpcode[LNK_MAX_CODE_BAK_LEN];
  /*hook*/
  size_t hokfuns_num = 0;
  size_t rel_hokfuns_num = 0;
  struct linkable_elf_hook_fun *hokf = NULL;

  void *base_rephdr_ptr = NULL;

  /* no use */
  offset = offset;

  do {
    objsize = linkable_get_file_size(objname);
    if (!objsize) {
      LOG(LOG_ERR, "Error to get objsize %s!", objname);
      rc = -1;
      break;
    }
    objsize = (objsize & 0xFFFFFFF0) + 0x10;

    pp = (struct ptrace_pid *)ptrace_pp_create(pid, symelang);
    if (!pp) {
      LOG(LOG_ERR, "Error to create ptrace_pid!");
      rc = -1;
      break;
    }

    memset(&qci, 0, sizeof(qci));
    qci.hostpid = pid;
    qci.version = QPATCH_VERSION;
    paradata = (unsigned char *)&qci;
    paradatalen = sizeof(qci);
    callret = 0;
    if ((rc = ptrace_pp_inject_library(pp, dllname, "qpatch_check", paradata,
                                       paradatalen, &dllhandle, &callret)) <
        0) {
      LOG(LOG_ERR, "Error to inject library!");
      rc = -1;
      break;
    }
    long qpatch_check_ret = (long)callret;
    if ((qpatch_check_ret != QPATCH_RET_OK) &&
        (qpatch_check_ret != QPATCH_RET_DUP)) {
      LOG(LOG_ERR, "Error to call qpatch_check() ret %d!", qpatch_check_ret);
      rc = -1;
      break;
    }
    LOG(LOG_INFO, "Call qpatch_check() ret %d.", qpatch_check_ret);

    memset(&qci, 0, sizeof(qci));
    qci.hostpid = pid;
    qci.version = QPATCH_VERSION;
    /* qci.para1   = objsize + LNK_MAX_REP_GAP_LEN + LNK_MAX_REP_BUF_LEN; */
    /* align to page */
    mroom_total_len = LNK_MIN_MMAP_ROOM_LEN(objsize);
    qci.para1 = mroom_total_len;
    paradata = (unsigned char *)&qci;
    paradatalen = sizeof(qci);
    callret = 0;
    if ((rc = ptrace_pp_call_library(pp, dllhandle, "qpatch_open_room",
                                     paradata, paradatalen, &callret, 1)) < 0) {
      LOG(LOG_ERR, "Error to inject library!");
      rc = -1;
      break;
    }
    void *qpatch_open_room_ret = (void *)callret;
    if (!qpatch_open_room_ret) {
      LOG(LOG_ERR, "Error to call qpatch_open_room() ret %d!",
          qpatch_open_room_ret);
      rc = -1;
      break;
    }
    LOG(LOG_INFO, "Call qpatch_open_room() ret %p.", qpatch_open_room_ret);

    memset(&mroom, 0, sizeof(struct qpatch_mmap_room));
    if ((rc = ptrace_pp_read_data(pp, (uintptr_t)qpatch_open_room_ret,
                                  (unsigned char *)&mroom,
                                  sizeof(struct qpatch_mmap_room))) < 0) {
      LOG(LOG_ERR, "Read mmap room error!");
      rc = -1;
      break;
    }
    if (mroom.mhdr.version != QPATCH_VERSION) {
      LOG(LOG_ERR, "Read mmap room version(%u) is not expect(%u)!",
          mroom.mhdr.version, QPATCH_VERSION);
      rc = -1;
      break;
    }
    if (mroom.mhdr.status == QPATCH_STATUS_INIT) {
      /* clear room any way */
      do {
        memset(&qci, 0, sizeof(qci));
        qci.hostpid = pid;
        qci.version = QPATCH_VERSION;
        qci.para1 = mroom.mhdr.roomlen;
        paradata = (unsigned char *)&qci;
        paradatalen = sizeof(qci);
        callret = 0;
        if ((rc = ptrace_pp_call_library(pp, dllhandle, "qpatch_close_room",
                                         paradata, paradatalen, &callret, 1)) <
            0) {
          LOG(LOG_ERR, "Error to inject library!");
          rc = -1;
          break;
        }
        void *qpatch_close_room_ret = (void *)callret;
        if (!qpatch_close_room_ret) {
          LOG(LOG_ERR, "Error to call qpatch_close_room() ret %d!",
              qpatch_close_room_ret);
          rc = -1;
          break;
        }
        LOG(LOG_INFO, "Call qpatch_close_room() ret %p.",
            qpatch_close_room_ret);
      } while (0);
      break;
    }
    if (mroom.mhdr.status != QPATCH_STATUS_LOADED &&
        mroom.mhdr.status != QPATCH_STATUS_ACTIVED) {
      LOG(LOG_INFO,
          "Read mmap room status(%u) is not expect(QPATCH_STATUS_LOADED:%u or "
          "QPATCH_STATUS_ACTIVED:%u)!",
          mroom.mhdr.status, QPATCH_STATUS_LOADED, QPATCH_STATUS_ACTIVED);
      qpatch_status_error(2, mroom.mhdr.status);
      rc = -1;
      break;
    }
    LOG(LOG_INFO, "Read mmap room len(%u)  calc mroom_total_len(%u)!",
        mroom.mhdr.roomlen, mroom_total_len);
    mroom_total_len = mroom.mhdr.roomlen;
    /*
    if(mroom.roomlen != mroom_total_len){
        LOG(LOG_ERR, "Read mmap room len(%u) is not equal(%u), will force rmv
    patch!", mroom.roomlen, mroom_total_len); rc = -1; break;
    }*/
    baseptr = (void *)mroom.ptr2data;
    if (baseptr != (void *)((size_t)qpatch_open_room_ret +
                            (size_t)LNK_OBJ_BASE_OFFSET_IN_ROOM)) {
      LOG(LOG_ERR,
          "Qpatch room error ptr2data(baseptr), addr(%p) + baseoff(%p) != "
          "baseptr(%p)!!",
          qpatch_open_room_ret, LNK_OBJ_BASE_OFFSET_IN_ROOM, baseptr);
      rc = -1;
      break;
    }
    base_rephdr_ptr = (void *)mroom.ptr2rephdr;
    if (base_rephdr_ptr != (void *)((size_t)qpatch_open_room_ret +
                                    (size_t)LNK_REPHDR_OFFSET_IN_ROOM)) {
      LOG(LOG_ERR,
          "Qpatch room error base_rephdr_ptr, addr(%p) + rephdroff(%p) != "
          "rephdrptr(%p)!!",
          qpatch_open_room_ret, LNK_REPHDR_OFFSET_IN_ROOM, base_rephdr_ptr);
      rc = -1;
      break;
    }
    repfuns_num = mroom.rephdr.repfuns_num;
    if (repfuns_num < 0 || repfuns_num > LNK_MAX_REP_FUNC_COUNT) {
      LOG(LOG_ERR, "Qpatch room error repfuns_num(%u) MAX(%u)!!", repfuns_num,
          LNK_MAX_REP_FUNC_COUNT);
      rc = -1;
      break;
    }
    hokfuns_num = mroom.rephdr.hookfuns_num;
    if (hokfuns_num < 0 || hokfuns_num > LNK_MAX_HOOK_FUNC_COUNT) {
      LOG(LOG_ERR, "Qpatch room error hokfuns_num(%u) MAX(%u)!!", hokfuns_num,
          LNK_MAX_HOOK_FUNC_COUNT);
      rc = -1;
      break;
    }

    LOG(LOG_DEBUG, "Attaching to PID %d", pp->hp->pid);
    if ((rc = ptrace_pid_attach(pp->hp->pid)) < 0) break;
    LOG(LOG_DEBUG, "Waiting attach request to complete...");
    if ((rc = ptrace_pid_wait(pp->hp->pid)) < 0) break;
    if (pp->hp->elang == ELF_E_LANG_GO) {
      LOG(LOG_DEBUG, "Set trace syscall...");
      if ((rc = ptrace_pid_syscall(pp->hp->pid)) < 0) break;
      LOG(LOG_DEBUG, "Waiting an syscall ...");
      if ((rc = ptrace_pid_wait(pp->hp->pid)) < 0) break;
    }
    if (mroom.rephdr._pat_callback_deactive_before) {
      LOG(LOG_INFO, "Call patchfun: void _pat_callback_deactive_before()...");
      if ((rc = ptrace_pid_call_func_noparam(
               pp->hp->pid, mroom.rephdr._pat_callback_deactive_before, NULL)) <
          0) {
        LOG(LOG_ERR, "Call patchfun: long _pat_callback_deactive_before()<%p>",
            mroom.rephdr._pat_callback_deactive_before);
        break;
      }
      LOG(LOG_INFO,
          "Call patchfun: void _pat_callback_deactive_before()<%p> ok.",
          mroom.rephdr._pat_callback_deactive_before);
    }

    /* rep func begin */
    int fidx = 0;
    for (fidx = 0; fidx < repfuns_num; fidx++) {
      repf = &(mroom.rephdr.repfuns[fidx]);
      if (!repf->isreplaced) {
        LOG(LOG_DEBUG, "Act-Fun<%s> is not replaced(%u), ignore.", repf->name,
            repf->isreplaced);
        rel_repfuns_num++;
        continue;
      }
      if (repf->oldsize <= LNK_MAX_CODE_BAK_LEN) {
        LOG(LOG_DEBUG,
            "Act-Fun<%s> oldsize(%u) need at least large(%u), ignore.",
            repf->name, repf->oldsize, LNK_MAX_CODE_BAK_LEN);
        continue;
      }
      if (repf->funbaklen != LNK_MAX_CODE_BAK_LEN) {
        LOG(LOG_DEBUG, "Act-Fun<%s> funbaklen(%u) not equal to (%u), ignore.",
            repf->name, repf->funbaklen, LNK_MAX_CODE_BAK_LEN);
        continue;
      }
      memset(jumpcode, 0, LNK_MAX_CODE_BAK_LEN);
      if ((rc = ptrace_pid_readarray(pp->hp->pid, repf->oldaddr, jumpcode,
                                     LNK_MAX_CODE_BAK_LEN)) < 0) {
        LOG(LOG_ERR,
            "Act-Fun<%s> can't read fun from(%p) to(%p) len(%u), ignore.",
            repf->name, repf->oldaddr, jumpcode, LNK_MAX_CODE_BAK_LEN);
        break;
      }

#if __WORDSIZE != 64
      offset = repf->newaddr - repf->oldaddr - JMP_OPER_CODELEN;
      LOG(LOG_DEBUG,
          "Act-Fun<%s> replacing from(%p)[%02x%02x%02x%02x%02x%02x%02x%02x] "
          "to(%p)[%02x%02x%02x%02x%02x%02x%02x%02x] offset(%p)...",
          repf->name, repf->newaddr, jumpcode[0], jumpcode[1], jumpcode[2],
          jumpcode[3], jumpcode[4], jumpcode[5], jumpcode[6], jumpcode[7],
          repf->oldaddr, repf->funbak[0], repf->funbak[1], repf->funbak[2],
          repf->funbak[3], repf->funbak[4], repf->funbak[5], repf->funbak[6],
          repf->funbak[7], offset);
      if (jumpcode[0] != JMP_OPER_CODE) {
        LOG(LOG_DEBUG, "Act-Fun<%s> first opercode(%02x) is not(%02x), ignore.",
            repf->name, jumpcode[0], JMP_OPER_CODE);
        continue;
      }
      if (offset != *((long *)(&jumpcode[1]))) {
        LOG(LOG_DEBUG, "Act-Fun<%s> offset(%p) is not(%p), ignore.", repf->name,
            *((long *)(&jumpcode[1])), offset);
        continue;
      }
#else
      const char *g_pMac = "\xff\x25\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0";
      const int N_OFFSET = 6;
      if (memcmp(jumpcode, g_pMac, N_OFFSET) != 0) {
        LOG(LOG_DEBUG, "Act-Fun<%s> first opercode(%02x) is not(%02x), ignore.",
            repf->name, jumpcode[0], 0xff);
        continue;
      }
      if (repf->newaddr != *((long *)(&jumpcode[N_OFFSET]))) {
        LOG(LOG_DEBUG, "Act-Fun<%s> offset(%p) is not(%p), ignore.", repf->name,
            *((long *)(&jumpcode[N_OFFSET])), repf->newaddr);
        continue;
      }
#endif

      if ((rc = ptrace_pid_writearray(pp->hp->pid, repf->oldaddr, repf->funbak,
                                      LNK_MAX_CODE_BAK_LEN)) < 0) {
        LOG(LOG_ERR,
            "Act-Fun<%s> can't write fun from(%p) to(%p) len(%u), ignore.",
            repf->name, repf->funbak, repf->oldaddr, LNK_MAX_CODE_BAK_LEN);
        break;
      }
      repf->funbaklen = 0;
      repf->isreplaced = FALSE;

      rel_repfuns_num++;
      LOG(LOG_INFO, "Act-Fun<%s> replace from(%p) to(%p) ok.", repf->name,
          repf->oldaddr, repf->newaddr);
    }
    if (rc < 0) {
      break;
    }
    /* rep fun end */

    /* hook fun begin */
    int hidx = 0;
    for (hidx = 0; hidx < hokfuns_num; hidx++) {
      hokf = &(mroom.rephdr.hookfuns[hidx]);
      if (!hokf->isreplaced) {
        LOG(LOG_DEBUG, "Act-Fun-Hook<%s> is not replaced(%u), ignore.",
            hokf->oldname, hokf->isreplaced);
        rel_hokfuns_num++;
        continue;
      }
      if (hokf->oldsize <= LNK_MAX_CODE_BAK_LEN) {
        LOG(LOG_DEBUG,
            "Act-Fun-Hook<%s> oldsize(%u) need at least large(%u), ignore.",
            hokf->oldname, hokf->oldsize, LNK_MAX_CODE_BAK_LEN);
        continue;
      }
      if (hokf->funbaklen != LNK_MAX_CODE_BAK_LEN) {
        LOG(LOG_DEBUG,
            "Act-Fun-Hook<%s> funbaklen(%u) not equal to (%u), ignore.",
            hokf->oldname, hokf->funbaklen, LNK_MAX_CODE_BAK_LEN);
        continue;
      }
      memset(jumpcode, 0, LNK_MAX_CODE_BAK_LEN);
      if ((rc = ptrace_pid_readarray(pp->hp->pid, hokf->oldaddr, jumpcode,
                                     LNK_MAX_CODE_BAK_LEN)) < 0) {
        LOG(LOG_ERR,
            "Act-Fun-Hook<%s> can't read fun from(%p) to(%p) len(%u), ignore.",
            hokf->oldname, hokf->oldaddr, jumpcode, LNK_MAX_CODE_BAK_LEN);
        break;
      }

#if __WORDSIZE != 64
      offset = hokf->newaddr - hokf->oldaddr - JMP_OPER_CODELEN;
      LOG(LOG_DEBUG,
          "Act-Fun-Hook<%s> replacing "
          "from(%p)[%02x%02x%02x%02x%02x%02x%02x%02x] "
          "to(%p)[%02x%02x%02x%02x%02x%02x%02x%02x] offset(%p)...",
          hokf->oldname, hokf->newaddr, jumpcode[0], jumpcode[1], jumpcode[2],
          jumpcode[3], jumpcode[4], jumpcode[5], jumpcode[6], jumpcode[7],
          hokf->oldaddr, hokf->funbak[0], hokf->funbak[1], hokf->funbak[2],
          hokf->funbak[3], hokf->funbak[4], hokf->funbak[5], hokf->funbak[6],
          hokf->funbak[7], offset);
      if (jumpcode[0] != JMP_OPER_CODE) {
        LOG(LOG_DEBUG,
            "Act-Fun-Hook<%s> first opercode(%02x) is not(%02x), ignore.",
            hokf->oldname, jumpcode[0], JMP_OPER_CODE);
        continue;
      }
      if (offset != *((long *)(&jumpcode[1]))) {
        LOG(LOG_DEBUG, "Act-Fun-Hook<%s> offset(%p) is not(%p), ignore.",
            hokf->oldname, *((long *)(&jumpcode[1])), offset);
        continue;
      }
#else
      const char *g_pMac = "\xff\x25\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0";
      const int N_OFFSET = 6;
      if (memcmp(jumpcode, g_pMac, N_OFFSET) != 0) {
        LOG(LOG_DEBUG, "Act-Fun<%s> first opercode(%02x) is not(%02x), ignore.",
            repf->name, jumpcode[0], 0xff);
        continue;
      }
      if (hokf->newaddr != *((long *)(&jumpcode[N_OFFSET]))) {
        LOG(LOG_DEBUG, "Act-Fun<%s> offset(%p) is not(%p), ignore.", repf->name,
            *((long *)(&jumpcode[N_OFFSET])), repf->newaddr);
        continue;
      }
#endif

      if ((rc = ptrace_pid_writearray(pp->hp->pid, hokf->oldaddr, hokf->funbak,
                                      LNK_MAX_CODE_BAK_LEN)) < 0) {
        LOG(LOG_ERR,
            "Act-Fun-Hook<%s> can't write fun from(%p) to(%p) len(%u), ignore.",
            hokf->oldname, hokf->funbak, hokf->oldaddr, LNK_MAX_CODE_BAK_LEN);
        break;
      }
      hokf->funbaklen = 0;
      hokf->isreplaced = FALSE;

      rel_hokfuns_num++;
      LOG(LOG_INFO, "Act-Fun-Hook<%s> replace from(%p) to(%p) ok.",
          hokf->oldname, hokf->oldaddr, hokf->newaddr);
    }
    if (rc < 0) {
      break;
    }
    /* hook fun end */

    mroom.mhdr.status = QPATCH_STATUS_INIT;
    if ((rc = ptrace_pid_writearray(
             pp->hp->pid, (uintptr_t)qpatch_open_room_ret,
             (unsigned char *)&mroom, sizeof(struct qpatch_mmap_room))) < 0) {
      LOG(LOG_ERR, "Qpatch load patch write room header to dest error!");
      rc = -1;
      break;
    }

    if (mroom.rephdr._pat_callback_deactive_after) {
      LOG(LOG_INFO, "Call patchfun: void _pat_callback_deactive_after()...");
      if ((rc = ptrace_pid_call_func_noparam(
               pp->hp->pid, mroom.rephdr._pat_callback_deactive_after, NULL)) <
          0) {
        LOG(LOG_ERR, "Call patchfun: long _pat_callback_deactive_after()<%p>",
            mroom.rephdr._pat_callback_deactive_after);
        break;
      }
      LOG(LOG_INFO,
          "Call patchfun: void _pat_callback_deactive_after()<%p> ok.",
          mroom.rephdr._pat_callback_deactive_after);
    }

    /* clear room any way */
    do {
      memset(&qci, 0, sizeof(qci));
      qci.hostpid = pid;
      qci.version = QPATCH_VERSION;
      // mroom_total_len = LNK_MIN_MMAP_ROOM_LEN(objsize);
      qci.para1 = mroom_total_len;
      paradata = (unsigned char *)&qci;
      paradatalen = sizeof(qci);
      callret = 0;
      if ((rc = ptrace_pp_call_library(pp, dllhandle, "qpatch_close_room",
                                       paradata, paradatalen, &callret, 0)) <
          0) {
        LOG(LOG_ERR, "Error to inject library!");
        rc = -1;
        break;
      }
      void *qpatch_close_room_ret = (void *)callret;
      if (!qpatch_close_room_ret) {
        LOG(LOG_ERR, "Error to call qpatch_close_room() ret %d!",
            qpatch_close_room_ret);
        rc = -1;
        break;
      }
      LOG(LOG_INFO, "Call qpatch_close_room() ret %p.", qpatch_close_room_ret);
    } while (0);

    LOG(LOG_DEBUG, "Continue PID %d.", pp->hp->pid);
    ptrace_pid_cont(pp->hp->pid);
    LOG(LOG_DEBUG, "Detaching from PID %d.", pp->hp->pid);
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
      LOG(LOG_DEBUG, "Error detaching from PID %d", pp->hp->pid);
      rc = -1;
    }

    LOG(LOG_INFO,
        "Qpatch room addr(%p) len(%u) baseoff(%p) baseptr(%p) rephdroff(%p) "
        "rephdrptr(%p) repfuns(%u) hookfuns(%u)",
        qpatch_open_room_ret, mroom_total_len, LNK_OBJ_BASE_OFFSET_IN_ROOM,
        baseptr, LNK_REPHDR_OFFSET_IN_ROOM, base_rephdr_ptr,
        mroom.rephdr.repfuns_num, mroom.rephdr.hookfuns_num);
    LOG(LOG_INFO, "Rol patch is ok status change to QPATCH_STATUS_INIT(%u).",
        QPATCH_STATUS_INIT);
  } while (0);

  if (rc < 0) {
    /* clear room again */
    /*
   do{
        memset(&qci, 0, sizeof(qci));
        qci.hostpid = pid;
        qci.version = QPATCH_VERSION;
        //mroom_total_len = LNK_MIN_MMAP_ROOM_LEN(objsize);
        qci.para1 = mroom_total_len;
        paradata  = (unsigned char *)&qci;
        paradatalen = sizeof(qci);
        callret = 0;
        if((rc = ptrace_pp_call_library(pp, dllhandle, "qpatch_close_room",
   paradata, paradatalen, &callret)) < 0){ LOG(LOG_ERR, "Error to inject
   library!"); rc = -1; break;
        }
        void * qpatch_close_room_ret = (void *)callret;
        if(!qpatch_close_room_ret)
        {
            LOG(LOG_ERR, "Error to call qpatch_close_room() ret %d!",
   qpatch_close_room_ret); rc = -1; break;
        }
        LOG(LOG_INFO, "Call qpatch_close_room() ret %p.",
   qpatch_close_room_ret); }while(0);
   */
    LOG(LOG_DEBUG, "Detaching from PID %d.", pp->hp->pid);
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
      LOG(LOG_DEBUG, "Error detaching from PID %d", pp->hp->pid);
      rc = -1;
    }
  }

  if (li) {
    linkable_elf_obj_destory(li);
    li = 0;
  }
  if (pp) {
    ptrace_pp_destroy(pp);
    pp = 0;
  }

  return rc;
}

int qpatch_act_patch(pid_t pid, const char *objname, const char *dllname,
                     int symelang) {
  int rc = 0;
  struct linkable_elf_internals *li = NULL;
  struct ptrace_pid *pp = NULL;
  const unsigned char *paradata = 0;
  size_t paradatalen = 0; /* MAX is QPATCH_MAX_DATALEN */
  uintptr_t dllhandle = 0;
  uintptr_t callret = 0;
  uintptr_t patfuncallret = 0;
  struct qpatch_call_in qci;
  void *baseptr = NULL;
  size_t objsize = 0;
  struct qpatch_mmap_room mroom;
  size_t mroom_total_len = 0;
  /* rep */
  size_t repfuns_num = 0;
  size_t rel_repfuns_num = 0;
  struct linkable_elf_rep_fun *repf = NULL;
  long offset = 0;
  unsigned char jumpcode[LNK_MAX_CODE_BAK_LEN];
  /* hook */
  void *base_rephdr_ptr = NULL;
  size_t hokfuns_num = 0;
  size_t rel_hokfuns_num = 0;
  struct linkable_elf_hook_fun *hokf = NULL;
  unsigned char tmpopcode[LNK_MAX_CODE_ORIG_FUNHEAD_SEARCH_LEN];
  size_t searchsize = LNK_MAX_CODE_ORIG_FUNHEAD_SEARCH_LEN;
  size_t origheadersize = 0;

  /* fill with NOP */
  memset(tmpopcode, NOP_OPER_CODE, LNK_MAX_CODE_ORIG_FUNHEAD_SEARCH_LEN);
  do {
    objsize = linkable_get_file_size(objname);
    if (!objsize) {
      LOG(LOG_ERR, "Error to get objsize %s!", objname);
      rc = -1;
      break;
    }
    objsize = (objsize & 0xFFFFFFF0) + 0x10;

    pp = (struct ptrace_pid *)ptrace_pp_create(pid, symelang);
    if (!pp) {
      LOG(LOG_ERR, "Error to create ptrace_pid!");
      rc = -1;
      break;
    }

    memset(&qci, 0, sizeof(qci));
    qci.hostpid = pid;
    qci.version = QPATCH_VERSION;
    paradata = (unsigned char *)&qci;
    paradatalen = sizeof(qci);
    callret = 0;
    if ((rc = ptrace_pp_inject_library(pp, dllname, "qpatch_check", paradata,
                                       paradatalen, &dllhandle, &callret)) <
        0) {
      LOG(LOG_ERR, "Error to inject library!");
      rc = -1;
      break;
    }
    long qpatch_check_ret = (long)callret;
    if ((qpatch_check_ret != QPATCH_RET_OK) &&
        (qpatch_check_ret != QPATCH_RET_DUP)) {
      LOG(LOG_ERR, "Error to call qpatch_check() ret %d!", qpatch_check_ret);
      rc = -1;
      break;
    }
    LOG(LOG_INFO, "Call qpatch_check() ret %d.", qpatch_check_ret);

    memset(&qci, 0, sizeof(qci));
    qci.hostpid = pid;
    qci.version = QPATCH_VERSION;
    /* qci.para1   = objsize + LNK_MAX_REP_GAP_LEN + LNK_MAX_REP_BUF_LEN; */
    /* align to page */
    mroom_total_len = LNK_MIN_MMAP_ROOM_LEN(objsize);
    qci.para1 = mroom_total_len;
    paradata = (unsigned char *)&qci;
    paradatalen = sizeof(qci);
    callret = 0;
    if ((rc = ptrace_pp_call_library(pp, dllhandle, "qpatch_open_room",
                                     paradata, paradatalen, &callret, 1)) < 0) {
      LOG(LOG_ERR, "Error to inject library!");
      rc = -1;
      break;
    }
    void *qpatch_open_room_ret = (void *)callret;
    if (!qpatch_open_room_ret) {
      LOG(LOG_ERR, "Error to call qpatch_open_room() ret %d!",
          qpatch_open_room_ret);
      rc = -1;
      break;
    }
    LOG(LOG_INFO, "Call qpatch_open_room() ret %p.", qpatch_open_room_ret);

    memset(&mroom, 0, sizeof(struct qpatch_mmap_room));
    if ((rc = ptrace_pp_read_data(pp, (uintptr_t)qpatch_open_room_ret,
                                  (unsigned char *)&mroom,
                                  sizeof(struct qpatch_mmap_room))) < 0) {
      LOG(LOG_ERR, "Read mmap room error!");
      rc = -1;
      break;
    }
    if (mroom.mhdr.version != QPATCH_VERSION) {
      LOG(LOG_ERR, "Read mmap room version(%u) is not expect(%u)!",
          mroom.mhdr.version, QPATCH_VERSION);
      rc = -1;
      break;
    }
    if (mroom.mhdr.status != QPATCH_STATUS_LOADED) {
      LOG(LOG_INFO,
          "Read mmap room status(%u) is not expect(QPATCH_STATUS_LOADED:%u)!",
          mroom.mhdr.status, QPATCH_STATUS_LOADED);
      qpatch_status_error(1, mroom.mhdr.status);
      rc = -1;
      break;
    }
    if (mroom.mhdr.roomlen != mroom_total_len) {
      LOG(LOG_ERR,
          "Read mmap room len(%u) is not equal(%u), please rol patch and "
          "retry!",
          mroom.mhdr.roomlen, mroom_total_len);
      rc = -1;
      break;
    }
    baseptr = (void *)mroom.ptr2data;
    if (baseptr != (void *)((size_t)qpatch_open_room_ret +
                            (size_t)LNK_OBJ_BASE_OFFSET_IN_ROOM)) {
      LOG(LOG_ERR,
          "Qpatch room error ptr2data(baseptr), addr(%p) + baseoff(%p) != "
          "baseptr(%p)!!",
          qpatch_open_room_ret, LNK_OBJ_BASE_OFFSET_IN_ROOM, baseptr);
      rc = -1;
      break;
    }
    base_rephdr_ptr = (void *)mroom.ptr2rephdr;
    if (base_rephdr_ptr != (void *)((size_t)qpatch_open_room_ret +
                                    (size_t)LNK_REPHDR_OFFSET_IN_ROOM)) {
      LOG(LOG_ERR,
          "Qpatch room error base_rephdr_ptr, addr(%p) + rephdroff(%p) != "
          "rephdrptr(%p)!!",
          qpatch_open_room_ret, LNK_REPHDR_OFFSET_IN_ROOM, base_rephdr_ptr);
      rc = -1;
      break;
    }
    repfuns_num = mroom.rephdr.repfuns_num;
    if (repfuns_num < 0 || repfuns_num > LNK_MAX_REP_FUNC_COUNT) {
      LOG(LOG_ERR, "Qpatch room error repfuns_num(%u) MAX(%u)!!", repfuns_num,
          LNK_MAX_REP_FUNC_COUNT);
      rc = -1;
      break;
    }
    hokfuns_num = mroom.rephdr.hookfuns_num;
    if (hokfuns_num < 0 || hokfuns_num > LNK_MAX_HOOK_FUNC_COUNT) {
      LOG(LOG_ERR, "Qpatch room error hokfuns_num(%u) MAX(%u)!!", hokfuns_num,
          LNK_MAX_HOOK_FUNC_COUNT);
      rc = -1;
      break;
    }

    LOG(LOG_DEBUG, "Attaching to PID %d", pp->hp->pid);
    if ((rc = ptrace_pid_attach(pp->hp->pid)) < 0) break;
    LOG(LOG_DEBUG, "Waiting attach request to complete...");
    if ((rc = ptrace_pid_wait(pp->hp->pid)) < 0) break;
    if (pp->hp->elang == ELF_E_LANG_GO) {
      LOG(LOG_DEBUG, "Set trace syscall...");
      if ((rc = ptrace_pid_syscall(pp->hp->pid)) < 0) break;
      LOG(LOG_DEBUG, "Waiting an syscall ...");
      if ((rc = ptrace_pid_wait(pp->hp->pid)) < 0) break;
    }
    if (mroom.rephdr._pat_callback_active_before) {
      LOG(LOG_INFO, "Call patchfun: long _pat_callback_active_before()...");
      if ((rc = ptrace_pid_call_func_noparam(
               pp->hp->pid, mroom.rephdr._pat_callback_active_before,
               &patfuncallret)) < 0) {
        LOG(LOG_ERR,
            "Call patchfun: long _pat_callback_active_before()<%p> ret<%u>",
            mroom.rephdr._pat_callback_active_before, patfuncallret);
        break;
      }
      LOG(LOG_INFO,
          "Call patchfun: long _pat_callback_active_before()<%p> ret<%u>",
          mroom.rephdr._pat_callback_active_before, patfuncallret);
      if (OK != patfuncallret) {
        rc = -1;
        LOG(LOG_ERR, "_pat_callback_active_before ret<%u> != OK<%u>",
            patfuncallret, OK);
        break;
      }
    }

    /* hook functions begin */
    int hidx = 0;
    for (hidx = 0; hidx < hokfuns_num; hidx++) {
      hokf = &(mroom.rephdr.hookfuns[hidx]);
      if (hokf->isreplaced) {
        LOG(LOG_INFO, "Act-Fun-Hook<%s> isreplaced(%u).", hokf->oldname,
            hokf->isreplaced);
        rel_hokfuns_num++;
        continue;
      }
      if (hokf->oldsize <= LNK_MAX_CODE_BAK_LEN) {
        LOG(LOG_INFO, "Act-Fun-Hook<%s> oldsize(%u) need at least large(%u).",
            hokf->oldname, hokf->oldsize, LNK_MAX_CODE_BAK_LEN);
        continue;
      }

      if ((rc = ptrace_pid_readarray(pp->hp->pid, hokf->oldaddr, hokf->funbak,
                                     LNK_MAX_CODE_BAK_LEN)) < 0) {
        LOG(LOG_ERR, "Act-Fun-Hook<%s> can't read fun from(%p) to(%p) len(%u).",
            hokf->oldname, hokf->oldaddr, hokf->funbak, LNK_MAX_CODE_BAK_LEN);
        break;
      }
      searchsize = (hokf->oldsize < LNK_MAX_CODE_ORIG_FUNHEAD_SEARCH_LEN)
                       ? hokf->oldsize
                       : LNK_MAX_CODE_ORIG_FUNHEAD_SEARCH_LEN;

      if ((rc = ptrace_pid_readarray(pp->hp->pid, hokf->oldaddr, tmpopcode,
                                     searchsize)) < 0) {
        LOG(LOG_ERR, "Act-Fun-Hook<%s> can't read fun from(%p) to(%p) len(%u).",
            hokf->oldname, hokf->oldaddr, tmpopcode, searchsize);
        break;
      }
      origheadersize = get_opcode_size(tmpopcode);
      while (origheadersize < JMP_OPER_CODELEN) {
        origheadersize += get_opcode_size(&(tmpopcode[origheadersize]));
      }
      if (origheadersize > LNK_MAX_CODE_ORIG_FUNHEAD_LEN) {
        LOG(LOG_INFO,
            "Act-Fun-Hook<%s> oldsize(%u) passheadersize(%u) "
            "exceed(LNK_MAX_CODE_ORIG_FUNHEAD_LEN:%u).",
            hokf->oldname, hokf->oldsize, origheadersize,
            LNK_MAX_CODE_ORIG_FUNHEAD_LEN);
        continue;
      }

      memset(hokf->origfunhead, NOP_OPER_CODE, LNK_MAX_CODE_ORIG_FUNHEAD_LEN);
      memcpy(hokf->origfunhead, tmpopcode, origheadersize);
      memset(hokf->jmporigfuntail, NOP_OPER_CODE,
             LNK_MAX_CODE_JMP_ORIG_FUNTAIL_LEN);

#if __WORDSIZE == 64
      const char *g_pMac = "\xff\x25\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0";
      memcpy(hokf->jmporigfuntail, g_pMac, JMP_OPER_CODELEN);
      const int N_OFFSET = 6;
      offset = (hokf->oldaddr + origheadersize);
      memcpy(&hokf->jmporigfuntail[N_OFFSET], (unsigned char *)&(offset),
             sizeof(long));
#else
      hokf->jmporigfuntail[0] = JMP_OPER_CODE;
      size_t origfun_entry =
          LNK_HOOK_FUN_ORIGFUNTAIL_ENTRY((size_t)base_rephdr_ptr, hidx);
      offset =
          (hokf->oldaddr + origheadersize) - origfun_entry - JMP_OPER_CODELEN;
      memcpy(&hokf->jmporigfuntail[1], (unsigned char *)&(offset),
             sizeof(long));
#endif

#if __WORDSIZE == 64
      /*
      const char *g_pMac = "\x48\xb8\x0\x0\x0\x0\x0\x0\x0\x0\xff\xe0";
      const int N_OFFSET         = 2;
      memcpy(jumpcode, g_pMac, LNK_MAX_CODE_BAK_LEN);

      offset = hokf->newaddr - hokf->oldaddr - JMP_OPER_CODELEN;
      LOG(LOG_ERR,
      "origfun_entry:%d,newaddr:%p,offset:%d",origfun_entry,hokf->newaddr,offset);
      memcpy(&jumpcode[N_OFFSET], &hokf->newaddr, sizeof(long));
      */
      memset(jumpcode, 0, LNK_MAX_CODE_BAK_LEN);
      const char *g_pMac2 = "\xff\x25\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0";
      const int N_OFFSET2 = 6;
      memset(jumpcode, 0, LNK_MAX_CODE_BAK_LEN);
      memcpy(jumpcode, hokf->funbak, LNK_MAX_CODE_BAK_LEN);
      memcpy(jumpcode, g_pMac2, JMP_OPER_CODELEN);

      LOG(LOG_ERR, "hokf newaddr:%p,oldaddr:%p", hokf->newaddr, hokf->oldaddr);
      memcpy(&jumpcode[N_OFFSET2], &hokf->newaddr, sizeof(long));
#else
      memset(jumpcode, 0, LNK_MAX_CODE_BAK_LEN);
      memcpy(jumpcode, hokf->funbak, LNK_MAX_CODE_BAK_LEN);
      jumpcode[0] = JMP_OPER_CODE;
      offset = hokf->newaddr - hokf->oldaddr - JMP_OPER_CODELEN;
      LOG(LOG_ERR, "origfun_entry:%d,newaddr:%p,offset:%d", origfun_entry,
          hokf->newaddr, offset);
      memcpy(&jumpcode[1], (unsigned char *)&(offset), sizeof(long));
      LOG(LOG_INFO,
          "Act-Fun-Hook replacing "
          "from<%s>(%p)[%02x%02x%02x%02x%02x%02x%02x%02x] "
          "to<%s>(%p)[%02x%02x%02x%02x%02x%02x%02x%02x] offset(%p)...",
          hokf->oldname, hokf->oldaddr, hokf->funbak[0], hokf->funbak[1],
          hokf->funbak[2], hokf->funbak[3], hokf->funbak[4], hokf->funbak[5],
          hokf->funbak[6], hokf->funbak[7], hokf->newname, hokf->newaddr,
          jumpcode[0], jumpcode[1], jumpcode[2], jumpcode[3], jumpcode[4],
          jumpcode[5], jumpcode[6], jumpcode[7], offset);
#endif

      hokf->funbaklen = LNK_MAX_CODE_BAK_LEN;
      hokf->isreplaced = TRUE;
      if ((rc = ptrace_pid_writearray(pp->hp->pid, hokf->oldaddr,
                                      (unsigned char *)jumpcode,
                                      LNK_MAX_CODE_BAK_LEN)) < 0) {
        LOG(LOG_ERR,
            "Act-Fun-Hook<%s> can't write fun from(%p) to(%p) len(%u).",
            hokf->oldname, jumpcode, hokf->oldaddr, LNK_MAX_CODE_BAK_LEN);
        break;
      }
      LOG(LOG_INFO, "Act-Fun-Hook replace from<%s>(%p) to<%s>(%p) ok.",
          hokf->oldname, hokf->oldaddr, hokf->newname, hokf->newaddr);
      rel_hokfuns_num++;
    }
    if (rc < 0) {
      break;
    }
    /* hooks functions end */

    /* replace functions begin */
    int fidx = 0;
    for (fidx = 0; fidx < repfuns_num; fidx++) {
      repf = &(mroom.rephdr.repfuns[fidx]);
      if (repf->isreplaced) {
        LOG(LOG_INFO, "Act-Fun<%s> isreplaced(%u).", repf->name,
            repf->isreplaced);
        rel_repfuns_num++;
        continue;
      }
      if (repf->oldsize <= LNK_MAX_CODE_BAK_LEN) {
        LOG(LOG_INFO, "Act-Fun<%s> oldsize(%u) need at least large(%u).",
            repf->name, repf->oldsize, LNK_MAX_CODE_BAK_LEN);
        continue;
      }
      if ((rc = ptrace_pid_readarray(pp->hp->pid, repf->oldaddr, repf->funbak,
                                     LNK_MAX_CODE_BAK_LEN)) < 0) {
        LOG(LOG_ERR, "Act-Fun<%s> can't read fun from(%p) to(%p) len(%u).",
            repf->name, repf->oldaddr, repf->funbak, LNK_MAX_CODE_BAK_LEN);
        break;
      }
#if __WORDSIZE == 64
      /*
                  test:
                      jmp test           ; eb fb
                      jmp near test      ; e9 f6 ff ff ff

      jmp [a]                ; ff 24 25 00 00 00 00 - 32-bit absolute
      jmp [rel a]            ; ff 25 e7 ff ff ff    - RIP + 32-bit displacement
      jmp [rdi]              ; ff 27                - base pointer
      jmp [rdi +4*rsi + a]   ; ff a4 b7 00 00 00 00 - base pointer +4*index +
      displacement


                  MOV RAX, 0x0           ; 48 b8 00 00 00 00 00 00 00 00
                  JMP RAX                ; ff e0

      const char *g_pMac = "\x48\xb8\x0\x0\x0\x0\x0\x0\x0\x0\xff\xe0";
      const int N_OFFSET         = 2;
      memcpy(jumpcode, g_pMac, LNK_MAX_CODE_BAK_LEN);
      LOG(LOG_ERR, "repf newaddr:%p,osdaddr:%p",repf->newaddr,repf->oldaddr);
      memcpy(&jumpcode[N_OFFSET], &repf->newaddr, sizeof(long));
      */

      // jmp [rel a]            ; ff 25 e7 ff ff ff    - RIP + 32-bit
      // displacement  == jmp *[rip+0]
      const char *g_pMac = "\xff\x25\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0";
      const int N_OFFSET = 6;
      memset(jumpcode, 0, LNK_MAX_CODE_BAK_LEN);
      memcpy(jumpcode, repf->funbak, LNK_MAX_CODE_BAK_LEN);
      memcpy(jumpcode, g_pMac, JMP_OPER_CODELEN);

      LOG(LOG_INFO, "repf newaddr:%p,osdaddr:%p", repf->newaddr, repf->oldaddr);
      memcpy(&jumpcode[N_OFFSET], &repf->newaddr, sizeof(long));
#else
      memset(jumpcode, 0, LNK_MAX_CODE_BAK_LEN);
      memcpy(jumpcode, repf->funbak, LNK_MAX_CODE_BAK_LEN);
      jumpcode[0] = JMP_OPER_CODE;
      offset = repf->newaddr - repf->oldaddr - JMP_OPER_CODELEN;
      memcpy(&jumpcode[1], (unsigned char *)&(offset), sizeof(long));
      LOG(LOG_DEBUG,
          "Act-Fun<%s> replacing from(%p)[%02x%02x%02x%02x%02x%02x%02x%02x] "
          "to(%p)[%02x%02x%02x%02x%02x%02x%02x%02x] offset(%p)...",
          repf->name, repf->oldaddr, repf->funbak[0], repf->funbak[1],
          repf->funbak[2], repf->funbak[3], repf->funbak[4], repf->funbak[5],
          repf->funbak[6], repf->funbak[7], repf->newaddr, jumpcode[0],
          jumpcode[1], jumpcode[2], jumpcode[3], jumpcode[4], jumpcode[5],
          jumpcode[6], jumpcode[7], offset);
#endif
      repf->funbaklen = LNK_MAX_CODE_BAK_LEN;
      repf->isreplaced = TRUE;
      if ((rc = ptrace_pid_writearray(pp->hp->pid, repf->oldaddr,
                                      (unsigned char *)jumpcode,
                                      LNK_MAX_CODE_BAK_LEN)) < 0) {
        LOG(LOG_ERR, "Act-Fun<%s> can't write fun from(%p) to(%p) len(%u).",
            repf->name, jumpcode, repf->oldaddr, LNK_MAX_CODE_BAK_LEN);
        break;
      }
      LOG(LOG_INFO, "Act-Fun<%s> replace from(%p) to(%p) ok.", repf->name,
          repf->oldaddr, repf->newaddr);
      rel_repfuns_num++;
    }
    if (rc < 0) {
      break;
    }
    /* replace functions end */

    if (rel_hokfuns_num || rel_repfuns_num) {
      mroom.mhdr.status = QPATCH_STATUS_ACTIVED;
      if ((rc = ptrace_pid_writearray(
               pp->hp->pid, (uintptr_t)qpatch_open_room_ret,
               (unsigned char *)&mroom, sizeof(struct qpatch_mmap_room))) < 0) {
        LOG(LOG_ERR, "Qpatch load patch write room header to dest error!");
        rc = -1;
        break;
      }
    }

    if (mroom.rephdr._pat_callback_active_after) {
      LOG(LOG_INFO, "Call patchfun: void _pat_callback_active_after()...");
      if ((rc = ptrace_pid_call_func_noparam(
               pp->hp->pid, mroom.rephdr._pat_callback_active_after, NULL)) <
          0) {
        LOG(LOG_ERR, "Call patchfun: long _pat_callback_active_after()<%p>",
            mroom.rephdr._pat_callback_active_after);
        break;
      }
      LOG(LOG_INFO, "Call patchfun: void _pat_callback_active_after()<%p> ok.",
          mroom.rephdr._pat_callback_active_after);
    }

    LOG(LOG_DEBUG, "Detaching from PID %d.", pp->hp->pid);
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
      LOG(LOG_DEBUG, "Error detaching from PID %d", pp->hp->pid);
      rc = -1;
    }

    LOG(LOG_INFO,
        "Qpatch room addr(%p) len(%u) baseoff(%p) baseptr(%p) rephdroff(%p) "
        "rephdrptr(%p) repfuns(%u) hookfuns(%u)",
        qpatch_open_room_ret, mroom_total_len, LNK_OBJ_BASE_OFFSET_IN_ROOM,
        baseptr, LNK_REPHDR_OFFSET_IN_ROOM, base_rephdr_ptr,
        mroom.rephdr.repfuns_num, mroom.rephdr.hookfuns_num);
    LOG(LOG_INFO, "Act patch is ok status change to QPATCH_STATUS_ACTIVED(%u).",
        QPATCH_STATUS_ACTIVED);
  } while (0);
  if (rc < 0) {
    LOG(LOG_DEBUG, "Detaching from PID %d.", pp->hp->pid);
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
      LOG(LOG_DEBUG, "Error detaching from PID %d", pp->hp->pid);
      rc = -1;
    }
  }

  if (li) {
    linkable_elf_obj_destory(li);
    li = 0;
  }
  if (pp) {
    ptrace_pp_destroy(pp);
    pp = 0;
  }

  return rc;
}

int qpatch_lod_patch(pid_t pid, const char *objname, const char *dllname,
                     int symelang, const char *pat_symbol) {
  int rc = 0;
  struct linkable_elf_internals *li = NULL;
  struct ptrace_pid *pp = NULL;
  const unsigned char *paradata = 0;
  size_t paradatalen = 0; /* MAX is QPATCH_MAX_DATALEN */
  uintptr_t dllhandle = 0;
  uintptr_t callret = 0;
  struct qpatch_call_in qci;
  void *bssptr = NULL;
  void *pltgotptr = NULL;
  void *baseptr = NULL;
  void *base_rephdr_ptr = NULL;
  size_t objsize = 0;
  struct qpatch_mmap_room_hdr mhdr;
  struct qpatch_mmap_room mroom;
  size_t mroom_total_len = 0;

  // char * libcname = "/mnt/d/gopath/src/0318/libc.so";
  // size_t libcsize = linkable_get_file_size(libcname);

  do {
    // ptrace_pid_inject_libc(pid, symelang, libcname, libcsize);

    objsize = linkable_get_file_size(objname);
    if (!objsize) {
      LOG(LOG_ERR, "Error to get objsize %s!", objname);
      rc = -1;
      break;
    }
    objsize = (objsize & 0xFFFFFFF0) + 0x10;

    pp = (struct ptrace_pid *)ptrace_pp_create(pid, symelang);
    if (!pp) {
      LOG(LOG_ERR, "Error to create ptrace_pid!");
      rc = -1;
      break;
    }

    memset(&qci, 0, sizeof(qci));
    qci.hostpid = pid;
    qci.version = QPATCH_VERSION;
    paradata = (unsigned char *)&qci;
    paradatalen = sizeof(qci);
    callret = 0;
    if ((rc = ptrace_pp_inject_library(pp, dllname, "qpatch_check", paradata,
                                       paradatalen, &dllhandle, &callret)) <
        0) {
      LOG(LOG_ERR, "Error to inject library!");
      rc = -1;
      break;
    }
    long qpatch_check_ret = (long)callret;
    if ((qpatch_check_ret != QPATCH_RET_OK) &&
        (qpatch_check_ret != QPATCH_RET_DUP)) {
      LOG(LOG_ERR, "Error to call qpatch_check() ret %d!", qpatch_check_ret);
      rc = -1;
      break;
    }
    LOG(LOG_INFO, "Call qpatch_check() ret %d.", qpatch_check_ret);

    memset(&qci, 0, sizeof(qci));
    qci.hostpid = pid;
    qci.version = QPATCH_VERSION;
    /* qci.para1   = objsize + LNK_MAX_REP_GAP_LEN + LNK_MAX_REP_BUF_LEN; */
    /* align to page */
    mroom_total_len = LNK_MIN_MMAP_ROOM_LEN(objsize);
    qci.para1 = mroom_total_len;
    paradata = (unsigned char *)&qci;
    paradatalen = sizeof(qci);
    callret = 0;
    if ((rc = ptrace_pp_call_library(pp, dllhandle, "qpatch_open_room",
                                     paradata, paradatalen, &callret, 1)) < 0) {
      LOG(LOG_ERR, "Error to inject library!");
      rc = -1;
      break;
    }
    void *qpatch_open_room_ret = (void *)callret;
    if (!qpatch_open_room_ret) {
      LOG(LOG_ERR, "Error to call qpatch_open_room() ret %d!",
          qpatch_open_room_ret);
      rc = -1;
      break;
    }
    LOG(LOG_INFO, "Call qpatch_open_room() ret %d.", qpatch_open_room_ret);

    memset(&mhdr, 0, sizeof(struct qpatch_mmap_room_hdr));
    if ((rc = ptrace_pp_read_data(pp, (uintptr_t)qpatch_open_room_ret,
                                  (unsigned char *)&mhdr,
                                  sizeof(struct qpatch_mmap_room_hdr))) < 0) {
      LOG(LOG_ERR, "Read mmap room header error!");
      rc = -1;
      break;
    }
    if (mhdr.version != QPATCH_VERSION) {
      LOG(LOG_ERR, "Read mmap room version(%u) is not expect(%u)!",
          mhdr.version, QPATCH_VERSION);
      rc = -1;
      break;
    }
    if (mhdr.status != QPATCH_STATUS_INIT) {
      LOG(LOG_ERR,
          "Read mmap room status(%u) is not expect(QPATCH_STATUS_INIT:%u)!",
          mhdr.status, QPATCH_STATUS_INIT);
      qpatch_status_error(0, mhdr.status);
      rc = -1;
      break;
    }
    if (mhdr.roomlen != 0 && mhdr.roomlen != mroom_total_len) {
      LOG(LOG_ERR,
          "Read mmap room len(%u) is not equal(%u), please rol patch and "
          "retry!",
          mhdr.roomlen, mroom_total_len);
      rc = -1;
      break;
    }
    pltgotptr = (void *)((size_t)qpatch_open_room_ret +
                         (size_t)LNK_PLTGOT_BASE_OFFSET_IN_ROOM(objsize));
    bssptr = (void *)((size_t)qpatch_open_room_ret +
                      (size_t)LNK_BSS_BASE_OFFSET_IN_ROOM(objsize));
    baseptr = (void *)((size_t)qpatch_open_room_ret +
                       (size_t)LNK_OBJ_BASE_OFFSET_IN_ROOM);
    base_rephdr_ptr = (void *)((size_t)qpatch_open_room_ret +
                               (size_t)LNK_REPHDR_OFFSET_IN_ROOM);
    LOG(LOG_INFO,
        "Qpatch room addr(%p) baseoff(%p) baseptr(%p) rephdroff(%p) "
        "rephdrprt(%p) bssptr(%p) pltgotptr(%p) objsize(%d)",
        qpatch_open_room_ret, LNK_OBJ_BASE_OFFSET_IN_ROOM, baseptr,
        LNK_REPHDR_OFFSET_IN_ROOM, base_rephdr_ptr, bssptr, pltgotptr, objsize);
    li = (struct linkable_elf_internals *)linkable_elf_obj_create(
        pid, symelang, objname, (void *)baseptr, (void *)base_rephdr_ptr,
        bssptr, LNK_MAX_BSS_LEN, pltgotptr, LNK_MAX_PLTGOT_LEN, pat_symbol);
    if (!li) {
      LOG(LOG_ERR, "Error to create obj_image!");
      rc = -1;
      break;
    }
    if (li->objlen != objsize) {
      LOG(LOG_ERR, "Error to match the obj_image<%d> size to obj_file<%d> !",
          li->objlen, objsize);
      rc = -1;
      break;
    }

    /* li->objptr has addtional bss len: li->objlen + LNK_MAX_PLTGOT_LEN +
     * LNK_MAX_BSS_LEN */
    if ((rc = ptrace_pp_write_data(
             pp, (uintptr_t)baseptr, (unsigned char *)li->objptr,
             li->objlen + LNK_MAX_PLTGOT_LEN + LNK_MAX_BSS_LEN)) < 0) {
      LOG(LOG_ERR, "Qpatch load patch write objbuf to dest error!");
      rc = -1;
      break;
    }

    /*
    if((rc = ptrace_pp_write_zero_data(pp, (uintptr_t)bssptr, LNK_MAX_BSS_LEN))
    < 0){ LOG(LOG_ERR, "Qpatch load patch write zero to bssptr error!"); rc =
    -1; break;
    }
    */

    memset(&mroom, 0, sizeof(struct qpatch_mmap_room));
    mroom.mhdr = mhdr;
    mroom.ptr2data = (long)baseptr;
    mroom.ptr2rephdr = (long)base_rephdr_ptr;
    mroom.rephdr = li->rephdr;
    mroom.bsslen = LNK_MAX_BSS_LEN;
    mroom.datalen = objsize;
    mroom.prt2bss = (long)bssptr;
    mroom.prt2pltgot = (long)pltgotptr;
    mroom.pltgotlen = LNK_MAX_PLTGOT_LEN;
    mroom.mhdr.status = QPATCH_STATUS_LOADED;
    mroom.mhdr.roomlen = mroom_total_len;
    if ((rc = ptrace_pp_write_data(pp, (uintptr_t)qpatch_open_room_ret,
                                   (unsigned char *)&mroom,
                                   sizeof(struct qpatch_mmap_room))) < 0) {
      LOG(LOG_ERR, "Qpatch load patch write room header to dest error!");
      rc = -1;
      break;
    }
    LOG(LOG_INFO,
        "Qpatch room addr(%p) len(%u) baseoff(%p) baseptr(%p) rephdroff(%p) "
        "rephdrptr(%p) repfuns(%u) hookfuns(%u)",
        qpatch_open_room_ret, mroom_total_len, LNK_OBJ_BASE_OFFSET_IN_ROOM,
        baseptr, LNK_REPHDR_OFFSET_IN_ROOM, base_rephdr_ptr,
        mroom.rephdr.repfuns_num, mroom.rephdr.hookfuns_num);
    LOG(LOG_INFO, "Lod patch is ok status change to QPATCH_STATUS_LOADED(%u).",
        QPATCH_STATUS_LOADED);
  } while (0);

  if (li) {
    linkable_elf_obj_destory(li);
    li = 0;
  }
  if (pp) {
    ptrace_pp_destroy(pp);
    pp = 0;
  }

  return rc;
}

void usage_exit(char *binname) {
  printf(
      "QPATCH V2.3.1 \n"
      "Usage: \n"
      "        %s  -o <OBJ>  -p <PID>  [ACTION]  [OPTION]\n",
      binname);
  printf("          -o <file>    the object file name\n");
  printf("          -p <pid>     the process pid\n");
  printf("       [ACTION] : \n");
  printf("          -l           load patch\n");
  printf("          -a           act patch\n");
  printf("          -r           rollback patch\n");
  printf("          -q           query patch status\n");
  printf("       [OPTION] : \n");
  printf("          -s <file>    patch symbol file name\n");
  printf("          -d <level>   debug level [ 1: debug 2: info ]\n");
  printf("          -e <lang>    process file language [ 'c' , 'go' ]\n");
  exit(-1);
}

#define CMD_BUFFERSIZE 4096
#define PATH_BUFFERSIZE 1024
#define FILENAME_BUFFERSIZE 512
extern UINT32 g_ucurLogLevel;
int main(int argc, char *argv[]) {
  int rc = -1;
  int ch = 0;

  int action = -1;
  int pid = 0;
  char *objname = NULL;
  char *dllnamepa = NULL;
  char *pat_symbol = NULL;
  char *elang = NULL;
  enum symbol_elf_elang symelang = ELF_E_LANG_C;

  opterr = 0;
  while ((ch = getopt(argc, argv, "larqp:o:s:d:f:e:")) != -1) {
    switch (ch) {
      case 'l':
        if (-1 == action)
          action = 0;  // lod patch
        else
          usage_exit(argv[0]);
        break;
      case 'a':
        if (-1 == action)
          action = 1;  // act patch
        else
          usage_exit(argv[0]);
        break;
      case 'r':
        if (-1 == action)
          action = 2;  // rul patch
        else
          usage_exit(argv[0]);
        break;
      case 'q':
        if (-1 == action)
          action = 3;  // dsp patch
        else
          usage_exit(argv[0]);
        break;
      case 'p':
        pid = atoi(optarg);  // pid
        break;
      case 'o':
        objname = optarg;  // obj
        break;
      case 's':
        pat_symbol = optarg;  // pat_symbol
        break;
      case 'd':
        g_ucurLogLevel = atoi(optarg);  // debuglevel
        break;
      case 'f':
        dllnamepa = optarg;  // so file
        break;
      case 'e':
        elang = optarg;  // exe language
        break;
    }
  }

  if (NULL == objname) {
    printf("PARAM ERROR: -o objfile is needed!\n");
    usage_exit(argv[0]);
  }

  if (0 != action && 1 != action && 2 != action && 3 != action) {
    printf("PARAM ERROR: -l, -a, -r, or -q  is needed!\n");
    usage_exit(argv[0]);
  }

  if (elang != NULL && strcmp(elang, "go") != 0 && strcmp(elang, "c") != 0) {
    printf("PARAM ERROR: -e param %s is invalid!\n", elang);
    usage_exit(argv[0]);
  }
  if (elang != NULL && strcmp(elang, "go") == 0) {
    symelang = ELF_E_LANG_GO;
  }

  char cmd[CMD_BUFFERSIZE] = {0};

  char dllpath[FILENAME_BUFFERSIZE] = {0};
  char dllfullname[PATH_BUFFERSIZE] = {0};
  char tmpdllfullname[PATH_BUFFERSIZE] = {0};
  char pat_symbol_file[PATH_BUFFERSIZE] = {0};

  char *dllname = "qpatch.so";
  char *tmpdllname = "_qpatch.so";

  getcwd(dllpath, FILENAME_BUFFERSIZE);
  dllpath[FILENAME_BUFFERSIZE - 1] = '\0';
  sprintf(tmpdllfullname, "%s/%s", dllpath, tmpdllname);

  if (dllnamepa != NULL && strlen(dllnamepa) > 0) {
    sprintf(dllfullname, "%s", dllnamepa);
  } else {
    sprintf(dllfullname, "%s/%s", dllpath, dllname);
  }

  memset(pat_symbol_file, 0, PATH_BUFFERSIZE);
  if ((pat_symbol != NULL) && (strlen(pat_symbol) > 0)) {
    sprintf(pat_symbol_file, "%s/%s", dllpath, pat_symbol);
  }
  memset(cmd, 0, CMD_BUFFERSIZE);
  sprintf(cmd, "rm %s >/dev/null 2>&1", tmpdllfullname);
  system(cmd);

  memset(cmd, 0, CMD_BUFFERSIZE);
  sprintf(cmd, "cp %s %s", dllfullname, tmpdllfullname);
  system(cmd);

  memset(cmd, 0, CMD_BUFFERSIZE);
  sprintf(cmd, "chmod 755 %s", tmpdllfullname);
  system(cmd);

  if (action == 0) {
    rc = qpatch_lod_patch((pid_t)pid, objname, tmpdllfullname, symelang,
                          pat_symbol_file);
  } else if (action == 1) {
    rc = qpatch_act_patch((pid_t)pid, objname, tmpdllfullname, symelang);
  } else if (action == 2) {
    rc = qpatch_rol_patch((pid_t)pid, objname, tmpdllfullname, symelang);
  } else if (action == 3) {
    rc = qpatch_dsp_patch((pid_t)pid, objname, tmpdllfullname, symelang);
  }

  memset(cmd, 0, CMD_BUFFERSIZE);
  sprintf(cmd, "rm %s", tmpdllfullname);
  system(cmd);

  if (rc < 0) {
    exit(-1);
  }

  return 0;
}
