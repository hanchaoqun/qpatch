//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#ifndef __HPATCH_LIBQPATCH_H__
#define __HPATCH_LIBQPATCH_H__

struct qpatch_call_in {
  long version;
  long hostpid;
  long para1;
  long para2;
  long para3;
  long para4;
  long para5;
  long para6;
} __attribute__((aligned(8)));

struct qpatch_mmap_room_hdr {
  long version;
  long hostpid;
  long status;
  long roomlen;
} __attribute__((aligned(8)));

#define QPATCH_VERSION 5
#define QPATCH_MAX_DATALEN 512

#define QPATCH_RET_UNKNOWN 0
#define QPATCH_RET_OK 1
#define QPATCH_RET_DUP 2
#define QPATCH_RET_VER_ERR 3
#define QPATCH_RET_PARA_ERR 4
#define QPATCH_RET_NOT_MAPPED 5
#define QPATCH_RET_UNMAP_ERR 6

#define QPATCH_STATUS_UNKNOWN 0
#define QPATCH_STATUS_INIT 1
#define QPATCH_STATUS_LOADED 2
//#define QPATCH_STATUS_ACTIVING  3
#define QPATCH_STATUS_ACTIVED 4
#define QPATCH_STATUS_ERR -1

#endif /* __HPATCH_LIBQPATCH_H__ */
