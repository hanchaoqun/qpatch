//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#include "define.h"

UINT32 g_ucurLogLevel = LOG_ERR;

UINT32 LOG_TextAdapt(UINT32 enLevel, UINT32 ulModule, UINT32 enLogType,
                     CHAR* pMessage, ...) {
  if (enLevel < g_ucurLogLevel) {
    return OK;
  }

  va_list varPara;
  INT32 lOffset = 0;
  CHAR logText[MAX_TRACE_LEN];
  time_t now = time(0);
  struct tm* tnow = NULL;

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

char* trimstr(char* str) {
  int len, i;
  len = strlen(str);
  for (i = 0; i < len; i++) {
    if (str[i] == '\n' || str[i] == '\r') {
      str[i] = '\0';
      i = len + 1;
    }
  }
  return str;
}
