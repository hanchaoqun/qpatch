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

#define MAX_TRACE_LEN 3072

enum qpatch_log_level {
  LOG_IMPORTENT = 4,
  LOG_ERR = 3,
  LOG_INFO = 2,
  LOG_DEBUG = 1,
  LOG_NULL = 0
};

static unsigned long g_current_log_level = LOG_ERR;

static unsigned long log_text_adapt(unsigned long level, const char* message,
                                    ...) {
  if (level < g_current_log_level) {
    return 0;
  }

  va_list varPara;
  long offset = 0;
  char logText[MAX_TRACE_LEN];
  time_t now = time(NULL);
  struct tm* tnow = NULL;

  memset(logText, 0x00, MAX_TRACE_LEN);
  time(&now);
  tnow = localtime(&now);
  if (!tnow) {
    return 0;
  }
  offset =
      snprintf(logText, MAX_TRACE_LEN - 1, "%04d_%02d_%02d %02d:%02d:%02d ",
               1900 + tnow->tm_year, tnow->tm_mon + 1, tnow->tm_mday,
               tnow->tm_hour, tnow->tm_min, tnow->tm_sec);
  va_start(varPara, message);
  offset += vsnprintf(logText + offset, MAX_TRACE_LEN - 1, message, varPara);
  va_end(varPara);
  if (offset < (MAX_TRACE_LEN - 1)) {
    logText[offset] = '\n';
  }
  printf("%s", logText);
  return 0;
}

#define LOG(Level, fmt, args...)                                               \
  {                                                                            \
    log_text_adapt(Level, #Level " [" __FILE__ ":%d]<%s> " fmt, __LINE__,      \
                  __FUNCTION__, ##args);                                       \
  }

static int parse_call_in(const char* data, size_t len,
                         struct qpatch_call_in** out_call_in) {
  if (!data || len < sizeof(struct qpatch_call_in) || !out_call_in) {
    return -1;
  }
  *out_call_in = (struct qpatch_call_in*)data;
  return 0;
}

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

void* g_qpatch_room_ptr = NULL;
size_t g_qpatch_room_size = 0;

int qpatch_check(char* data, size_t len) {
  struct qpatch_call_in* call_in = NULL;
  if (parse_call_in(data, len, &call_in) < 0) {
    return QPATCH_RET_PARA_ERR;
  }
  if (call_in->version < QPATCH_VERSION) {
    return QPATCH_RET_VER_ERR;
  }
  return QPATCH_RET_OK;
}

void* qpatch_open_room(char* data, size_t len) {
  int rc = 0;
  void* baseptr = NULL;
  struct qpatch_mmap_room_hdr* room_hdr = NULL;
  struct qpatch_call_in* call_in = NULL;
  if (parse_call_in(data, len, &call_in) < 0) {
    return NULL;
  }
  if (call_in->version < QPATCH_VERSION) {
    return NULL;
  }
  if (call_in->para1 <= 0) {
    return NULL;
  }
  if (g_qpatch_room_ptr) {
    if (g_qpatch_room_size == call_in->para1) {
      return g_qpatch_room_ptr;
    } else {
      LOG(LOG_ERR, "mmap(%p) can't resize len from(%zu) to(%ld)",
          g_qpatch_room_ptr, g_qpatch_room_size, call_in->para1);
      return g_qpatch_room_ptr;
    }
  }
  do {
    baseptr = mmap(NULL, call_in->para1, PROT_EXEC | PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, 0, 0);
    if (MAP_FAILED == baseptr || !baseptr) {
      rc = -1;
      baseptr = NULL;
      LOG(LOG_ERR, "mmap len(%ld) error: %s", call_in->para1, strerror(errno));
      break;
    }
    /* OK */
    room_hdr = (struct qpatch_mmap_room_hdr*)baseptr;
    room_hdr->version = call_in->version;
    room_hdr->hostpid = call_in->hostpid;
    room_hdr->status = QPATCH_STATUS_INIT;
    room_hdr->roomlen = call_in->para1;
  } while (0);
  if (baseptr) {
    g_qpatch_room_size = call_in->para1;
    g_qpatch_room_ptr = baseptr;
  }
  return g_qpatch_room_ptr;
}

int qpatch_close_room(char* data, size_t len) {
  int rc = 0;
  struct qpatch_call_in* call_in = NULL;
  if (parse_call_in(data, len, &call_in) < 0) {
    return QPATCH_RET_PARA_ERR;
  }
  if (call_in->version < QPATCH_VERSION) {
    return QPATCH_RET_VER_ERR;
  }
  if (!g_qpatch_room_ptr || !g_qpatch_room_size) {
    return QPATCH_RET_NOT_MAPPED;
  }
  do {
    rc = munmap(g_qpatch_room_ptr, g_qpatch_room_size);
    if (rc != 0) {
      rc = -1;
      LOG(LOG_ERR, "munmap(%p) len(%zu) error: %s", g_qpatch_room_ptr,
          g_qpatch_room_size, strerror(errno));
      break;
    }
    g_qpatch_room_ptr = NULL;
    g_qpatch_room_size = 0;
    /* OK */
  } while (0);
  if (rc < 0) {
    return QPATCH_RET_UNMAP_ERR;
  }
  return QPATCH_RET_OK;
}
