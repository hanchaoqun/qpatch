//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#ifndef __HPATCH_DEFINE_H__
#define __HPATCH_DEFINE_H__

#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
//#include <linux/user.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>

// typedef char*   va_list;
//#define _INTSIZEOF(n)   ( (sizeof(n) + sizeof(int) - 1) & ~(sizeof(int) - 1) )
//#define va_start(ap,v)  ( ap = (va_list)&v + _INTSIZEOF(v) )
//#define va_arg(ap,t)    ( *(t *)((ap += _INTSIZEOF(t)) - _INTSIZEOF(t)) )
//#define va_end(ap)      ( ap = (va_list)0 )

typedef void VOID;
typedef unsigned char UINT8;
typedef unsigned char UCHAR;
typedef unsigned short UINT16;
typedef char CHAR;
typedef unsigned long UINT32;
typedef signed long INT32;
typedef signed char INT8;
typedef unsigned long BOOL;
typedef int INT;
typedef float FLOAT; /* 32 bits float */
typedef UINT32 UINTPTR;
#define IN
#define OUT

// #define  NULL 0
#define NULL_PTR 0L
#define NULL_BYTE 0XFF
#define NULL_WORD 0xFFFF
#define NULL_DWORD 0xFFFFFFFF
#define NULL_LONG NULL_DWORD

#define NULL_INT64 0xFFFFFFFFFFFFFFFF

#define TRUE 1
#define FALSE 0
#define INVALID_PARAM 2

#define OK 0
#define ERR 1 /* For VRP VOS adaptation */
#define ERROR (-1)

#define YES 1
#define NO 0

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#define MAX_TRACE_LEN 3072
#define MAX_BUFF_LEN 1024

#define LOG_IMPORTENT 4
#define LOG_ERR 3
#define LOG_INFO 2
#define LOG_DEBUG 1
#define LOG_NULL 0

/* UINT32 _pat_callback_active_before(VOID) */
#define PAT_ACT_BEFORE_FUN_NAME "_pat_callback_active_before"
/* VOID _pat_callback_active_after(VOID) */
#define PAT_ACT_AFTER_FUN_NAME "_pat_callback_active_after"
/* VOID _pat_callback_deactive_before(VOID) */
#define PAT_DEACT_BEFORE_FUN_NAME "_pat_callback_deactive_before"
/* VOID _pat_callback_deactive_after(VOID) */
#define PAT_DEACT_AFTER_FUN_NAME "_pat_callback_deactive_after"

UINT32 LOG_TextAdapt(UINT32 enLevel, UINT32 ulModule, UINT32 enLogType,
                     CHAR* pMessage, ...);
char* trimstr(char* str);

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

typedef enum qpatch_error_code {
  QPATCH_ERR_OK = 0,
  QPATCH_ERR_INVALID_PARAM = -1,
  QPATCH_ERR_NOT_FOUND = -2,
  QPATCH_ERR_ATTACH = -3,
  QPATCH_ERR_INJECT = -4,
  QPATCH_ERR_CALL = -5,
  QPATCH_ERR_READ = -6,
  QPATCH_ERR_WRITE = -7,
  QPATCH_ERR_SYMBOL = -8,
  QPATCH_ERR_STATE = -9,
  QPATCH_ERR_IO = -10,
  QPATCH_ERR_INTERNAL = -11,
  QPATCH_ERR_ROLLBACK = -12
} qpatch_error_code_t;

static inline const char* qpatch_errstr(int code) {
  switch (code) {
    case QPATCH_ERR_OK:
      return "OK";
    case QPATCH_ERR_INVALID_PARAM:
      return "INVALID_PARAM";
    case QPATCH_ERR_NOT_FOUND:
      return "NOT_FOUND";
    case QPATCH_ERR_ATTACH:
      return "ATTACH";
    case QPATCH_ERR_INJECT:
      return "INJECT";
    case QPATCH_ERR_CALL:
      return "CALL";
    case QPATCH_ERR_READ:
      return "READ";
    case QPATCH_ERR_WRITE:
      return "WRITE";
    case QPATCH_ERR_SYMBOL:
      return "SYMBOL";
    case QPATCH_ERR_STATE:
      return "STATE";
    case QPATCH_ERR_IO:
      return "IO";
    case QPATCH_ERR_INTERNAL:
      return "INTERNAL";
    case QPATCH_ERR_ROLLBACK:
      return "ROLLBACK";
    default:
      return "UNKNOWN";
  }
}

#define QPATCH_LOG_CTX(Level, action, pid, symbol, phase, errcode, fmt, args...) \
  LOG(Level,                                                                        \
      "[action=%s pid=%d symbol=%s phase=%s err=%d(%s)] " fmt,                     \
      ((action) ? (action) : "unknown"), (int)(pid),                                \
      ((symbol) ? (symbol) : "-"), ((phase) ? (phase) : "unknown"),                \
      (int)(errcode), qpatch_errstr((int)(errcode)), ##args)

#endif /* __HPATCH_DEFINE_H__ */
