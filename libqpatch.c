//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "libqpatch.h"

// typedef char*   va_list;
//#define _INTSIZEOF(n)   ( (sizeof(n) + sizeof(int) - 1) & ~(sizeof(int) - 1) )
//#define va_start(ap,v)  ( ap = (va_list)&v + _INTSIZEOF(v) )
//#define va_arg(ap,t)    ( *(t *)((ap += _INTSIZEOF(t)) - _INTSIZEOF(t)) )
//#define va_end(ap)      ( ap = (va_list)0 )
typedef unsigned long UINT32;
typedef signed long INT32;
typedef char CHAR;
typedef int INT;
#define OK 0
#define ERR 1
#define ERROR (-1)
#define MAX_TRACE_LEN 3072
#define MAX_BUFF_LEN 1024

#define LOG_IMPORTENT 4
#define LOG_ERR 3
#define LOG_INFO 2
#define LOG_DEBUG 1
#define LOG_NULL 0

static UINT32 g_ucurLogLevel = LOG_ERR;
static UINT32 LOG_TextAdapt(UINT32 enLevel, UINT32 ulModule, UINT32 enLogType,
                            CHAR* pMessage, ...) {
  if (enLevel < g_ucurLogLevel) {
    return OK;
  }

  va_list varPara;
  INT32 lOffset = 0;
  CHAR logText[MAX_TRACE_LEN];
  INT boolRet;
  time_t now = time(0);
  struct tm* tnow = 0;
  memset(logText, 0x00, MAX_TRACE_LEN);
  time(&now);
  tnow = localtime(&now);
  lOffset =
      snprintf(logText, MAX_TRACE_LEN - 1, "%04d_%02d_%02d %02d:%02d:%02d ",
               1900 + tnow->tm_year, tnow->tm_mon + 1, tnow->tm_mday,
               tnow->tm_hour, tnow->tm_min, tnow->tm_sec);
  va_start(varPara, pMessage);
  lOffset += vsnprintf(logText + lOffset, MAX_TRACE_LEN - 1, pMessage, varPara);
  va_end(varPara);
  if (lOffset < (MAX_TRACE_LEN - 1)) {
    logText[lOffset] = '\n';
  }
  printf("%s", logText);
  return OK;
}

#define LOG_TextEx(Level, module, LogType, fmt, args...)          \
  {                                                               \
    LOG_TextAdapt(Level, module, LogType,                         \
                  #Level " [" __FILE__ ":%d]<%s> " fmt, __LINE__, \
                  __FUNCTION__, ##args);                          \
  }

#define LOG(Level, fmt, args...)                                               \
  {                                                                            \
    LOG_TextAdapt(Level, 0, 0, #Level " [" __FILE__ ":%d]<%s> " fmt, __LINE__, \
                  __FUNCTION__, ##args);                                       \
  }

#define PROCESS_CALL_IN_PARAM(A, data, len, rc) \
  do {                                          \
    if (len < sizeof(struct qpatch_call_in)) {  \
      rc = -1;                                  \
      break;                                    \
    }                                           \
    A = (struct qpatch_call_in*)data;           \
  } while (0)

#if 0
#define DLL_TEST_LOG(STR)                        \
  do {                                           \
    FILE* ff = fopen("/tmp/libqpatch.log", "a"); \
    if (ff) {                                    \
      fprintf(ff, "%s", STR);                    \
      fclose(ff);                                \
    }                                            \
  } while (0)
#endif

void* g_qpatch_room_ptr = 0;
size_t g_qpatch_room_size = 0;

int qpatch_check(char* data, size_t len) {
  // DLL_TEST_LOG("BEGIN qpatch_check()\n");
  int rc = 0;
  struct qpatch_call_in* A = 0;
  PROCESS_CALL_IN_PARAM(A, data, len, rc);
  if (rc < 0 || !data || !len) {
    return QPATCH_RET_PARA_ERR;
  }
  if (A->version < QPATCH_VERSION) {
    return QPATCH_RET_VER_ERR;
  }
  // DLL_TEST_LOG("END qpatch_check()\n");
  return QPATCH_RET_OK;
}

void* qpatch_open_room(char* data, size_t len) {
  int rc = 0;
  void* baseptr = 0;
  struct qpatch_mmap_room_hdr* mhdr = 0;
  struct qpatch_call_in* A = 0;
  PROCESS_CALL_IN_PARAM(A, data, len, rc);
  if (rc < 0 || !data || !len) {
    return 0;
  }
  if (A->version < QPATCH_VERSION) {
    return 0;
  }
  if (A->para1 <= 0) {
    return 0;
  }
  if (g_qpatch_room_ptr) {
    if (g_qpatch_room_size == A->para1) {
      return g_qpatch_room_ptr;
    } else {
      LOG(LOG_ERR, "mmap(%p) can't resize len from(%u) to(%u)",
          g_qpatch_room_ptr, g_qpatch_room_size, A->para1);
      return g_qpatch_room_ptr;
    }
  }
  do {
    baseptr = mmap(0, A->para1, PROT_EXEC | PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, 0, 0);
    if (MAP_FAILED == baseptr || !baseptr) {
      rc = -1;
      baseptr = 0;
      LOG(LOG_ERR, "mmap len(%u) error: %s", A->para1, strerror(errno));
      break;
    }
    /* OK */
    mhdr = (struct qpatch_mmap_room_hdr*)baseptr;
    mhdr->version = A->version;
    mhdr->hostpid = A->hostpid;
    mhdr->status = QPATCH_STATUS_INIT;
    mhdr->roomlen = A->para1;
  } while (0);
  if (baseptr) {
    g_qpatch_room_size = A->para1;
    g_qpatch_room_ptr = baseptr;
  }
  return g_qpatch_room_ptr;
}

int qpatch_close_room(char* data, size_t len) {
  int rc = 0;
  struct qpatch_call_in* A = 0;
  PROCESS_CALL_IN_PARAM(A, data, len, rc);
  if (rc < 0 || !data || !len) {
    return QPATCH_RET_PARA_ERR;
  }
  if (A->version < QPATCH_VERSION) {
    return QPATCH_RET_VER_ERR;
  }
  if (!g_qpatch_room_ptr || !g_qpatch_room_size) {
    return QPATCH_RET_NOT_MAPPED;
  }
  do {
    rc = munmap(g_qpatch_room_ptr, g_qpatch_room_size);
    if (rc != 0) {
      rc = -1;
      LOG(LOG_ERR, "munmap(%p) len(%u) error: %s", g_qpatch_room_ptr,
          g_qpatch_room_size, strerror(errno));
      break;
    }
    g_qpatch_room_ptr = 0;
    g_qpatch_room_size = 0;
    /* OK */
  } while (0);
  if (rc < 0) {
    return QPATCH_RET_UNMAP_ERR;
  }
  return QPATCH_RET_OK;
}
