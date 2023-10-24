//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#ifndef __HPATCH_DEFINE_H__
#define __HPATCH_DEFINE_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
//#include <linux/user.h>
#include <sys/user.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <memory.h>
#include <time.h>
#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>


//typedef char*   va_list;
//#define _INTSIZEOF(n)   ( (sizeof(n) + sizeof(int) - 1) & ~(sizeof(int) - 1) )
//#define va_start(ap,v)  ( ap = (va_list)&v + _INTSIZEOF(v) )
//#define va_arg(ap,t)    ( *(t *)((ap += _INTSIZEOF(t)) - _INTSIZEOF(t)) )
//#define va_end(ap)      ( ap = (va_list)0 )

typedef void           VOID;
typedef unsigned char  UINT8;
typedef unsigned char  UCHAR;
typedef unsigned short UINT16;
typedef char           CHAR;
typedef unsigned long  UINT32;
typedef signed   long  INT32;
typedef signed   char  INT8;
typedef unsigned long  BOOL;
typedef int            INT;
typedef float          FLOAT;          /* 32 bits float */
typedef UINT32     UINTPTR;
#define IN
#define OUT

#define  NULL 0
#define  NULL_PTR 0L
#define  NULL_BYTE 0XFF
#define  NULL_WORD 0xFFFF
#define  NULL_DWORD 0xFFFFFFFF
#define  NULL_LONG NULL_DWORD

#define  NULL_INT64 0xFFFFFFFFFFFFFFFF

#define  TRUE    1
#define  FALSE   0
#define  INVALID_PARAM 2

#define  OK          0
#define  ERR         1   /* For VRP VOS adaptation */
#define  ERROR       (-1)

#define  YES         1
#define  NO          0


#ifndef FALSE
#define FALSE                          0
#endif
#ifndef TRUE
#define TRUE                           1
#endif

#define  MAX_TRACE_LEN  3072
#define  MAX_BUFF_LEN  1024

#define  LOG_IMPORTENT 4
#define  LOG_ERR    3
#define  LOG_INFO   2
#define  LOG_DEBUG  1
#define  LOG_NULL   0

/* UINT32 _pat_callback_active_before(VOID) */
#define PAT_ACT_BEFORE_FUN_NAME    "_pat_callback_active_before"
/* VOID _pat_callback_active_after(VOID) */
#define PAT_ACT_AFTER_FUN_NAME     "_pat_callback_active_after"
/* VOID _pat_callback_deactive_before(VOID) */
#define PAT_DEACT_BEFORE_FUN_NAME  "_pat_callback_deactive_before"
/* VOID _pat_callback_deactive_after(VOID) */
#define PAT_DEACT_AFTER_FUN_NAME   "_pat_callback_deactive_after"

UINT32 LOG_TextAdapt (UINT32 enLevel,
                          UINT32 ulModule,
                          UINT32 enLogType,
                          CHAR* pMessage,
                          ...);
char* trimstr(char* str);

#define LOG_TextEx(Level, module, LogType, fmt, args...) \
    {LOG_TextAdapt(Level, module, LogType, #Level " [" __FILE__ ":%d]<%s> " fmt, __LINE__, __FUNCTION__ , ##args);}

#define LOG(Level, fmt, args...) \
    {LOG_TextAdapt(Level, 0, 0, #Level " [" __FILE__ ":%d]<%s> " fmt, __LINE__, __FUNCTION__ , ##args);}

#endif /* __HPATCH_DEFINE_H__ */
