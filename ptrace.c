//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#include "ptrace.h"

int ptrace_pp_detach(struct ptrace_pid *pp);

int ptrace_traceme() {
  if (ptrace(PTRACE_TRACEME, NULL, NULL, NULL) < 0) {
    int err = errno;
    LOG(LOG_ERR, "Ptrace traceme failed with error: %s", strerror(err));
    return -1;
  }
  return 0;
}

int ptrace_pid_attach(pid_t pid) {
  long result;
  while (1) {
    result = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (result == -1L &&
        (errno == ESRCH || errno == EBUSY || errno == EFAULT || errno == EIO)) {
      /* To avoid burning up CPU for nothing: */
      sched_yield(); /* or nanosleep(), or usleep() */
      continue;
    }
    break;
  }
  if (result == -1L) {
    int err = errno;
    LOG(LOG_ERR, "Ptrace Attach for PID %d failed with error: %s", pid,
        strerror(err));
    return -1;
  }
  return 0;
}

int ptrace_pid_detach(pid_t pid) {
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
    int err = errno;
    LOG(LOG_DEBUG, "Ptrace Detach for PID %d failed with error: %s", pid,
        strerror(err));
    return -1;
  }
  return 0;
}

int ptrace_pid_cont(pid_t pid) {
  if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
    int err = errno;
    LOG(LOG_ERR, "Ptrace Continue for PID %d failed with error: %s", pid,
        strerror(err));
    return -1;
  }
  return 0;
}

int ptrace_pid_cont_one(pid_t pid) {
  if (ptrace(PTRACE_CONT, pid, 1, NULL) < 0) {
    int err = errno;
    LOG(LOG_ERR, "Ptrace Continue for PID %d failed with error: %s", pid,
        strerror(err));
    return -1;
  }
  return 0;
}

int ptrace_pid_syscall(pid_t pid) {
  if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
    int err = errno;
    LOG(LOG_ERR, "Ptrace Syscall for PID %d failed with error: %s", pid,
        strerror(err));
    return -1;
  }
  return 0;
}

int ptrace_pid_set_watchthread(pid_t pid) {
  /* PTRACE_O_EXITKILL */
  if (ptrace(PTRACE_SETOPTIONS, pid, NULL,
             PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) <
      0) {
    int err = errno;
    LOG(LOG_ERR, "Ptrace setoptions for PID %d failed with error: %s", pid,
        strerror(err));
    return -1;
  }
  return 0;
}

int ptrace_pid_wait_thread(pid_t pid, pid_t *childpid, pid_t *newpid) {
  int status = 0;
  int signum = 0;
  pid_t new_pid = 0;
  pid_t child_pid = 0;
  *newpid = 0;
  *childpid = 0;
  // TODO: change to use : ptrace(PTRACE_GETSIGINFO, 25618, NULL,
  // {si_signo=SIGTRAP, si_code=SI_KERNEL, si_value={int=-1447215360,
  // ptr=0x7ffda9bd3f00}}) = 0
  while (1) {
    new_pid = 0;
    status = 0;
    // if (waitpid(pid, &status, 0) < 0) { /* __WALL */
    child_pid = waitpid(-1, &status, __WALL); /* __WALL ?? WCONTINUED */
    *childpid = child_pid;
    if (child_pid < 0) {
      int err = errno;
      LOG(LOG_ERR, "Waitpid for PID %d failed with error: %s", pid,
          strerror(err));
      return -1;
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      LOG(LOG_ERR, "PID %d was terminated.", child_pid);
      return -1;
    }
    if (WIFSTOPPED(status)) {
      signum = WSTOPSIG(status);
      if (signum == SIGTRAP) {
        if (((status >> 16) & 0xFFFF) == PTRACE_EVENT_CLONE ||
            ((status >> 16) & 0xFFFF) == PTRACE_EVENT_FORK ||
            ((status >> 16) & 0xFFFF) == PTRACE_EVENT_VFORK) {
          if (ptrace(PTRACE_GETEVENTMSG, childpid, 0, &new_pid) != -1) {
            *newpid = new_pid;
            LOG(LOG_INFO, "New thread %d created.", new_pid);
            return 1;
          }
        }
        break;
      } else if (signum == SIGSTOP) {
        LOG(LOG_ERR, "SIG SIGSTOP");
        break;
      } else if (signum == SIGSEGV) {
        LOG(LOG_ERR, "SIG SIGSEGV");
        break;
      } else if (signum == SIGINT) {
        LOG(LOG_ERR, "SIG SIGINT : User terminated!!");
        return -1;
      } else {
        LOG(LOG_INFO, "SIG(%d) resent to TID %d PID %d.", signum, child_pid,
            pid);
        // resend signal to pid
        ptrace(PTRACE_CONT, child_pid, 0, signum);
        continue;
      }
    }
  }
  return 0;
}

int ptrace_pid_wait_attach(pid_t pid, pid_t tid) {
  int status = 0;
  waitpid(tid, &status, __WALL);

  int sig = WSTOPSIG(status);
  while (!WIFSTOPPED(status) || sig != SIGSTOP) {
    syscall(234 /*SYS_tgkill*/, pid, tid, sig);
    waitpid(tid, &status, __WALL);
  }
  return 0;
}

int ptrace_pid_wait(pid_t pid) {
  int status = 0;
  int signum = 0;
  int trytimes = 3;
  // TODO: change to use : ptrace(PTRACE_GETSIGINFO, 25618, NULL,
  // {si_signo=SIGTRAP, si_code=SI_KERNEL, si_value={int=-1447215360,
  // ptr=0x7ffda9bd3f00}}) = 0
  while (1) {
    if (waitpid(pid, &status, 0) < 0) {
      int err = errno;
      LOG(LOG_ERR, "Waitpid for PID %d failed with error: %s", pid,
          strerror(err));
      return -1;
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      LOG(LOG_ERR, "PID %d was terminated.", pid);
      return -1;
    }
    if (WIFSTOPPED(status)) {
      signum = WSTOPSIG(status);
      if (signum == SIGTRAP || signum == SIGSTOP || signum == SIGSEGV) {
        break;
      } else {
        LOG(LOG_INFO,
            "PID %d was not traced by me, signum(%d) not SIGTRAP(%d) or "
            "SIGSTOP(%d), continue waiting...",
            pid, signum, SIGTRAP, SIGSTOP);
        ptrace(PTRACE_CONT, pid, 0, 0);
        if (trytimes > 0) {
          trytimes--;
          continue;
        }
        return -1;
      }
    }
  }
  return 0;
}

int ptrace_pid_getregs(pid_t pid, struct user *regs) {
  if (!regs) return -1;
  memset(regs, 0, sizeof(*regs));
  if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
    int err = errno;
    LOG(LOG_ERR, "Ptrace Getregs for PID %d failed with error: %s", pid,
        strerror(err));
    return -1;
  }
  return 0;
}

int ptrace_pid_setregs(pid_t pid, const struct user *regs) {
  if (!regs) return -1;
  if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
    int err = errno;
    LOG(LOG_ERR, "Ptrace Setregs for PID %d failed with error: %s", pid,
        strerror(err));
    return -1;
  }
  return 0;
}

int ptrace_pid_readarray(pid_t pid, uintptr_t target, unsigned char *data,
                         size_t datasz) {
  size_t pos = 0;
  size_t idx = 0;
  if (!data || !datasz) return -1;
  while (pos < datasz) {
    int err = 0;
    long peekdata = ptrace(PTRACE_PEEKDATA, pid, target + idx, NULL);
    err = errno;
    if (err != 0) {
      LOG(LOG_ERR, "Ptrace ReadArray for PID %d failed with error: %s", pid,
          strerror(err));
      return -1;
    }
    idx += sizeof(size_t);

    size_t jdx = 0;
    const size_t pksz = sizeof(size_t);
    for (jdx = 0; jdx < pksz && pos < datasz; ++jdx) {
      data[pos++] = ((unsigned char *)&peekdata)[jdx];
    }
  }
  return 0;
}

int ptrace_pid_writezero(pid_t pid, uintptr_t target, size_t datasz) {
  int err = 0;

  if (datasz == 0) {
    LOG(LOG_ERR, "datasz is 0");
    return -1;
  }

  // 32bit 4, 64bit 8
  if (sizeof(size_t) != sizeof(long)) {
    LOG(LOG_ERR, "sizeof: size_t %d, long %d, not equal", sizeof(size_t),
        sizeof(long));
    return -1;
  }

  int idx = 0;
  const size_t word_size = sizeof(size_t);
  size_t pokedata = 0;
  for (idx = 0; idx < (datasz / word_size); idx++) {
    if (ptrace(PTRACE_POKEDATA, pid, target + (idx * word_size), pokedata) <
        0) {
      int err = errno;
      LOG(LOG_ERR, "Ptrace WriteArray for PID %d failed with error: %s", pid,
          strerror(err));
      return -1;
    }
  }

  int spare_len = datasz % word_size;
  // long            peekdata    = 0;
  if (spare_len > 0) {
    pokedata = ptrace(PTRACE_PEEKDATA, pid, target + (idx * word_size), NULL);
    err = errno;
    if (err != 0) {
      LOG(LOG_ERR, "Ptrace ReadInt for PID %d failed with error: %s", pid,
          strerror(err));
      return -1;
    }

    memset(&pokedata, 0, spare_len);
    if (ptrace(PTRACE_POKEDATA, pid, target + (idx * word_size), pokedata) <
        0) {
      err = errno;
      LOG(LOG_ERR, "Ptrace WriteArray for PID %d failed with error: %s", pid,
          strerror(err));
      return -1;
    }
  }

#if 0
    size_t pos = 0;
    size_t idx = 0;
    if ( !datasz)
    { return -1; }
    while (pos < datasz)
    {
        size_t pokedata = 0, jdx = 0;
        const size_t pksz = sizeof(size_t);
        for (jdx = 0; jdx < pksz && pos < datasz; ++jdx)
        {
            ((unsigned char*)&pokedata)[jdx] = 0;
        }
        if (ptrace(PTRACE_POKEDATA, pid, target + idx, pokedata) < 0)
        {
            int err = errno;
            LOG(LOG_ERR, "Ptrace WriteArray for PID %d failed with error: %s", pid, strerror(err));
            return -1;
        }
        idx += sizeof(size_t);
    }
#endif

  return 0;
}

int ptrace_pid_writearray(pid_t pid, uintptr_t target,
                          const unsigned char *data, size_t datasz) {
  int err = 0;

  if (data == NULL) {
    LOG(LOG_ERR, "data is null");
    return -1;
  }

  if (datasz == 0) {
    LOG(LOG_ERR, "datasz is 0");
    return -1;
  }

  // 32bit 4, 64bit 8
  if (sizeof(size_t) != sizeof(long)) {
    LOG(LOG_ERR, "sizeof: size_t %d, long %d, not equal", sizeof(size_t),
        sizeof(long));
    return -1;
  }

  int idx = 0;
  const size_t word_size = sizeof(size_t);
  size_t pokedata = 0;
  for (idx = 0; idx < (datasz / word_size); idx++) {
    memcpy(&pokedata, data + (idx * word_size), word_size);
    if (ptrace(PTRACE_POKEDATA, pid, target + (idx * word_size), pokedata) <
        0) {
      err = errno;
      LOG(LOG_ERR, "Ptrace WriteArray for PID %d failed with error: %s", pid,
          strerror(err));
      return -1;
    }
  }

  int spare_len = datasz % word_size;
  // long            peekdata    = 0;
  if (spare_len > 0) {
    pokedata = ptrace(PTRACE_PEEKDATA, pid, target + (idx * word_size), NULL);
    err = errno;
    if (err != 0) {
      LOG(LOG_ERR, "Ptrace ReadInt for PID %d failed with error: %s", pid,
          strerror(err));
      return -1;
    }

    memcpy(&pokedata, data + (idx * word_size), spare_len);
    if (ptrace(PTRACE_POKEDATA, pid, target + (idx * word_size), pokedata) <
        0) {
      err = errno;
      LOG(LOG_ERR, "Ptrace WriteArray for PID %d failed with error: %s", pid,
          strerror(err));
      return -1;
    }
  }

  return 0;

#if 0
    size_t pos = 0;
    size_t idx = 0;
    if (!data || !datasz)
    { return -1; }
    while (pos < datasz)
    {
        size_t pokedata = 0, jdx = 0;
        const size_t pksz = sizeof(size_t);
        for (jdx = 0; jdx < pksz && pos < datasz; ++jdx)
        {
            ((unsigned char*)&pokedata)[jdx] = data[pos++];
        }
        if (ptrace(PTRACE_POKEDATA, pid, target + idx, pokedata) < 0)
        {
            int err = errno;
            LOG(LOG_ERR, "Ptrace WriteArray for PID %d failed with error: %s", pid, strerror(err));
            return -1;
        }
        idx += sizeof(size_t);
    }
    return 0;
#endif
}

int ptrace_pid_readlong(pid_t pid, uintptr_t target, uintptr_t *outvalue) {
  int err = 0;
  long peekdata = ptrace(PTRACE_PEEKDATA, pid, target, NULL);
  err = errno;
  if (err != 0) {
    LOG(LOG_ERR, "Ptrace ReadInt for PID %d failed with error: %s", pid,
        strerror(err));
    return -1;
  }
  if (outvalue) {
    *outvalue = peekdata;
  } else {
    LOG(LOG_ERR, "Invalid arguments.");
  }
  return outvalue ? 0 : -1;
}

int ptrace_pid_writelong(pid_t pid, uintptr_t target, uintptr_t invalue) {
  int err = 0;
  /* LOG(LOG_INFO, "WriteInt: %p", (void *)invalue); */
  if (ptrace(PTRACE_POKEDATA, pid, target, (void *)invalue) < 0) {
    LOG(LOG_ERR, "Ptrace WriteInt for PID %d failed with error: %s", pid,
        strerror(err));
    return -1;
  }
  return 0;
}

int ptrace_pid_call_func_noparam(pid_t pid, uintptr_t funcaddr,
                                 uintptr_t *outcallret) {
  int rc = 0;
  /* The stack is read-write and not executable */
  struct user iregs; /* intermediate registers */
  struct user oregs; /* original registers */
  uintptr_t result = 0;
  uintptr_t stack[4] = {0, 0, 0,
                        0}; /* max arguments of the functions we are using */
  int idx = 0;

  if (!funcaddr) {
    LOG(LOG_ERR, "Invalid arguments.");
    return -1;
  }
  do {
    LOG(LOG_INFO, "Getting original registers.");
    if ((rc = ptrace_pid_getregs(pid, &oregs)) < 0) break;
    memcpy(&iregs, &oregs, sizeof(oregs));
    LOG(LOG_INFO, "Copying stack out...");
    for (idx = 0; idx < sizeof(stack) / sizeof(uintptr_t); ++idx) {
      if ((rc = ptrace_pid_readlong(
               pid, PTRACE_REG_SP(iregs) + idx * sizeof(size_t), &stack[idx])) <
          0)
        break;
      LOG(LOG_INFO, "CopyFrom idx[%u] SP[%p] V[%p].", idx,
          PTRACE_REG_SP(iregs) + idx * sizeof(size_t), stack[idx]);
    }
    if (rc < 0) {
      LOG(LOG_ERR, "Copy stack error %s.", strerror(errno));
      break;
    }
    LOG(LOG_INFO, "Copy stack out ok.");

    /* call funcaddr */
    if (funcaddr) {
      LOG(LOG_INFO, "call function<%p>...", funcaddr);
      PTRACE_ASM_SET_BREAKPOINT(pid, iregs, rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
      PTRACE_ASM_PASS_ARGS2FUNC(pid, iregs, funcaddr, 0, 0, rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2FUNC");
      PTRACE_ASM_SET_REGS(pid, "[funcaddr]", iregs, rc);
      PTRACE_ASM_CALL_FUNC(pid, "[funcaddr]", iregs, rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "CALL_FUNC [funcaddr]");
      result = PTRACE_REG_AX(iregs);
      PTRACE_ASM_RECOVER_REGS(pid, iregs, oregs, rc);
      LOG(LOG_INFO, "End call function [funcaddr].");
      if (outcallret) {
        *outcallret = result;
      }
      LOG(LOG_INFO, "Call function<%p> ret<%u>.", funcaddr, result);
    }
    /* Original reset */
    LOG(LOG_INFO, "Setting original registers...");
    if ((rc = ptrace_pid_setregs(pid, &oregs)) < 0) {
      LOG(LOG_ERR, "PID %d will be unstable, set original registers error : %s",
          pid, strerror(errno));
      break;
    }
    LOG(LOG_INFO, "Copying stack back...");
    for (idx = 0; idx < sizeof(stack) / sizeof(uintptr_t); ++idx) {
      if ((rc = ptrace_pid_writelong(
               pid, PTRACE_REG_SP(oregs) + idx * sizeof(size_t), stack[idx])) <
          0)
        break;
      LOG(LOG_INFO, "CopyBack idx[%u] SP[%p] V[%p].", idx,
          PTRACE_REG_SP(oregs) + idx * sizeof(size_t), stack[idx]);
    }
    if (rc < 0) {
      LOG(LOG_ERR, "Copy stack back error %s.", strerror(errno));
      break;
    }
    LOG(LOG_INFO, "Copy stack back out ok.");
  } while (0);
  return rc;
}

void ptrace_pp_destroy(struct ptrace_pid *pp) {
  if (pp) {
    ptrace_pp_detach(pp);
    if (pp->hp) {
      symbol_pid_destroy(pp->hp);
      pp->hp = NULL;
    }
    free(pp);
    pp = NULL;
  }
}

struct ptrace_pid *ptrace_pp_create(pid_t pid, int symelang) {
  return ptrace_pp_create_inner(pid, symelang, 1);
}

struct ptrace_pid *ptrace_pp_create_nolibc(pid_t pid, int symelang) {
  return ptrace_pp_create_inner(pid, symelang, 0);
}

struct ptrace_pid *ptrace_pp_create_inner(pid_t pid, int symelang,
                                          int needlibc) {
  struct ptrace_pid *pp = NULL;
  struct symbol_elf_pid *hp = NULL;

  hp = symbol_pid_create_inner(pid, symelang, needlibc);
  if (!hp) {
    LOG(LOG_ERR, "Create pid error.");
    return 0;
  }
  pp = malloc(sizeof(*pp));
  if (!pp) {
    LOG(LOG_ERR, "malloc error: size %d, %s", sizeof(*pp), strerror(errno));
    return 0;
  }
  memset(pp, 0, sizeof(*pp));
  pp->hp = hp;
  pp->attached = FALSE;
  pp->pid = pid;

  return pp;
}

int ptrace_pp_attach(struct ptrace_pid *pp) {
  if (!pp) return -1;
  if (!(pp->hp)) return -1;
  if (!pp->attached) {
    pp->attached = FALSE;
    LOG(LOG_DEBUG, "Trying to attach to PID %d", pp->hp->pid);
    if (ptrace(PTRACE_ATTACH, pp->hp->pid, NULL, NULL) < 0) {
      int err = errno;
      LOG(LOG_ERR, "Ptrace Attach failed with error %s", strerror(err));
    } else {
      LOG(LOG_INFO, "Waiting for the child.");
      if (ptrace_pid_wait(pp->hp->pid) == 0) {
        pp->attached = TRUE;
        LOG(LOG_INFO, "Attached to PID %d", pp->hp->pid);
      }
    }
  }
  return pp->attached ? 0 : -1;
}

int ptrace_pp_detach(struct ptrace_pid *pp) {
  int rc = -1;
  if (pp && pp->attached && pp->hp) {
    LOG(LOG_INFO, "Detaching from PID %d", pp->hp->pid);
    if (ptrace(PTRACE_DETACH, pp->hp->pid, NULL, NULL) < 0) {
      int err = errno;
      LOG(LOG_ERR, "Ptrace detach failed with error %s", strerror(err));
    } else {
      rc = 0;
      LOG(LOG_INFO, "Detached from PID %d", pp->hp->pid);
    }
    pp->attached = FALSE;
  }
  return rc;
}

int ptrace_pp_set_eip(struct ptrace_pid *pp, uintptr_t ptr) {
  int rc = -1;
  if (ptr && pp && pp->attached && pp->hp) {
    struct user regs;
    memset(&regs, 0, sizeof(regs));
    if (ptrace(PTRACE_GETREGS, pp->hp->pid, NULL, &regs) < 0) {
      int err = errno;
      LOG(LOG_ERR, "Ptrace getregs failed with error %s", strerror(err));
    } else {
      LOG(LOG_ERR, "%s is %p", PTRACE_REG_IP_NAME, (void *)PTRACE_REG_IP(regs));
      if (ptr == pp->hp->exe_entry_point) ptr += sizeof(void *);
      PTRACE_REG_IP(regs) = ptr;
      if (ptrace(PTRACE_SETREGS, pp->hp->pid, NULL, &regs) < 0) {
        int err = errno;
        LOG(LOG_ERR, "Ptrace setregs failed with error %s", strerror(err));
      } else {
        LOG(LOG_INFO, "[%s:%d] Set %s to %p", PTRACE_REG_IP_NAME, ptr);
        rc = 0;
      }
    }
  } else {
    if (!ptr) {
      LOG(LOG_ERR, "The execution pointer is null.");
    }
    if (!pp || !pp->attached || !pp->hp) {
      LOG(LOG_ERR, "The process is not attached to.");
    }
  }
  return rc;
}

int ptrace_pp_read_data(struct ptrace_pid *pp, uintptr_t target,
                        unsigned char *outdata, size_t outdatalen) {
  int rc = 0;
  if (!pp || !pp->hp || !outdata || !outdatalen) {
    LOG(LOG_ERR, "Invalid arguments.");
    return -1;
  }
  do {
    /* Prepare the child for injection */
    LOG(LOG_DEBUG, "Attaching to PID %d", pp->hp->pid);
    if ((rc = ptrace_pid_attach(pp->hp->pid)) < 0) break;
    LOG(LOG_DEBUG, "Waiting...");
    if ((rc = ptrace_pid_wait(pp->hp->pid)) < 0) break;
    if (ptrace_pid_readarray(pp->hp->pid, target, outdata, outdatalen) < 0) {
      rc = -1;
      LOG(LOG_ERR, "PID %d read array from(%p) to(%p) size(%u) error : %s",
          pp->hp->pid, target, outdata, outdatalen, strerror(errno));
      break;
    }
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
      rc = -1;
      LOG(LOG_ERR, "PID %d will be unstable, continue error : %s", pp->hp->pid,
          strerror(errno));
      break;
    }
    LOG(LOG_DEBUG, "PID %d is running now.", pp->hp->pid);
  } while (0);
  if (rc < 0) {
    LOG(LOG_DEBUG, "Detaching from PID %d.", pp->hp->pid);
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
      LOG(LOG_ERR, "Error detaching from PID %d", pp->hp->pid);
      rc = -1;
    }
  }
  return rc;
}

int ptrace_pp_write_zero_data(struct ptrace_pid *pp, uintptr_t target,
                              size_t indatalen) {
  int rc = 0;
  if (!pp || !pp->hp || !indatalen) {
    LOG(LOG_ERR, "Invalid arguments.");
    return -1;
  }
  do {
    /* Prepare the child for injection */
    LOG(LOG_INFO, "Attaching to PID %d", pp->hp->pid);
    if ((rc = ptrace_pid_attach(pp->hp->pid)) < 0) break;
    LOG(LOG_INFO, "Waiting...");
    if ((rc = ptrace_pid_wait(pp->hp->pid)) < 0) break;
    if (ptrace_pid_writezero(pp->hp->pid, target, indatalen) < 0) {
      rc = -1;
      LOG(LOG_ERR, "PID %d write zero array to(%p)  size(%u) error : %s",
          pp->hp->pid, target, indatalen, strerror(errno));
      break;
    }
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
      rc = -1;
      LOG(LOG_ERR, "PID %d will be unstable, continue error : %s", pp->hp->pid,
          strerror(errno));
      break;
    }
    LOG(LOG_INFO, "PID %d is running now.", pp->hp->pid);
  } while (0);
  if (rc < 0) {
    LOG(LOG_INFO, "Detaching from PID %d.", pp->hp->pid);
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
      LOG(LOG_ERR, "Error detaching from PID %d", pp->hp->pid);
      rc = -1;
    }
  }
  return rc;
}

int ptrace_pp_write_data(struct ptrace_pid *pp, uintptr_t target,
                         const unsigned char *indata, size_t indatalen) {
  int rc = 0;
  if (!pp || !pp->hp || !indata || !indatalen) {
    LOG(LOG_ERR, "Invalid arguments.");
    return -1;
  }
  do {
    /* Prepare the child for injection */
    LOG(LOG_DEBUG, "Attaching to PID %d", pp->hp->pid);
    if ((rc = ptrace_pid_attach(pp->hp->pid)) < 0) break;
    LOG(LOG_DEBUG, "Waiting...");
    if ((rc = ptrace_pid_wait(pp->hp->pid)) < 0) break;
    if (ptrace_pid_writearray(pp->hp->pid, target, indata, indatalen) < 0) {
      rc = -1;
      LOG(LOG_ERR, "PID %d write array to(%p) from(%p) size(%u) error : %s",
          pp->hp->pid, target, indata, indatalen, strerror(errno));
      break;
    }
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
      rc = -1;
      LOG(LOG_ERR, "PID %d will be unstable, continue error : %s", pp->hp->pid,
          strerror(errno));
      break;
    }
    LOG(LOG_DEBUG, "PID %d is running now.", pp->hp->pid);
  } while (0);
  if (rc < 0) {
    LOG(LOG_DEBUG, "Detaching from PID %d.", pp->hp->pid);
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
      LOG(LOG_ERR, "Error detaching from PID %d", pp->hp->pid);
      rc = -1;
    }
  }
  return rc;
}

int ptrace_pp_call_library(struct ptrace_pid *pp, uintptr_t indlladdr,
                           const char *callsymbol,
                           const unsigned char *paradata, size_t paradatalen,
                           uintptr_t *outcallret, int needattach) {
  size_t symsz = 0;
  size_t datasz = 0;
  size_t tgtsz = 0;
  int rc = 0;
  unsigned char *mdata = NULL;

  /* The stack is read-write and not executable */
  struct user iregs; /* intermediate registers */
  struct user oregs; /* original registers */
  uintptr_t result = 0;
  uintptr_t stack[4] = {0, 0, 0,
                        0}; /* max arguments of the functions we are using */
  uintptr_t heapptr = 0;
  uintptr_t heapptr_need_free = 0;
  int idx = 0;

  if (!pp || !pp->hp || !callsymbol || !indlladdr) {
    LOG(LOG_ERR, "Invalid arguments.");
    return -1;
  }
  if (!pp->hp->fn_malloc || !pp->hp->fn_free) {
    LOG(LOG_ERR, "No malloc/fn_free found.");
    return -1;
  }
  /* calculate the size to allocate */
  symsz = callsymbol ? (strlen(callsymbol) + 1) : 0;
  if (!symsz) {
    LOG(LOG_ERR, "callsymbol %s invalid.", callsymbol);
    return -1;
  }
  datasz = paradata ? paradatalen : 0;
  tgtsz = symsz + datasz + 32; /* general buffer */
  tgtsz = (tgtsz > 1024) ? tgtsz : 1024;
  /* align the memory */
  tgtsz += (tgtsz % sizeof(void *) == 0)
               ? 0
               : (sizeof(void *) - (tgtsz % sizeof(void *)));

  /* LOG(LOG_INFO, "Allocating %u bytes in the target.", tgtsz); */
  mdata = calloc(sizeof(unsigned char), tgtsz);
  if (!mdata) {
    LOG(LOG_ERR, "malloc error: size %d, %s", tgtsz, strerror(errno));
    return -1;
  }
  memset(mdata, 0, tgtsz);
  memcpy(mdata, callsymbol, symsz);
  LOG(LOG_DEBUG, "Copy symbol [%s] to the target.", callsymbol);
  if (paradata) {
    memcpy(mdata + symsz, paradata, datasz);
    LOG(LOG_DEBUG, "Copy data len [%u] to the target.", datasz);
  }

  do {
    if (needattach == 1) {
      /* Prepare the child for injection */
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
    }

    LOG(LOG_DEBUG, "Getting original registers.");
    if ((rc = ptrace_pid_getregs(pp->hp->pid, &oregs)) < 0) break;
    memcpy(&iregs, &oregs, sizeof(oregs));
    LOG(LOG_DEBUG, "Copying stack out...");
    for (idx = 0; idx < sizeof(stack) / sizeof(uintptr_t); ++idx) {
      if ((rc = ptrace_pid_readlong(pp->hp->pid,
                                    PTRACE_REG_SP(iregs) + idx * sizeof(size_t),
                                    &stack[idx])) < 0)
        break;
      LOG(LOG_DEBUG, "CopyFrom idx[%u] SP[%p] V[%p].", idx,
          PTRACE_REG_SP(iregs) + idx * sizeof(size_t), stack[idx]);
    }
    if (rc < 0) {
      LOG(LOG_ERR, "Copy stack error %s.", strerror(errno));
      break;
    }
    LOG(LOG_DEBUG, "Copy stack out ok.");
    /* Call malloc */
    LOG(LOG_DEBUG, "Start call function [malloc]...");
    PTRACE_ASM_SET_BREAKPOINT(pp->hp->pid, iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
    PTRACE_ASM_PASS_ARGS2FUNC(pp->hp->pid, iregs, pp->hp->fn_malloc, tgtsz, 0,
                              rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2FUNC");
    PTRACE_ASM_SET_REGS(pp->hp->pid, "malloc", iregs, rc);
    PTRACE_ASM_CALL_FUNC(pp->hp->pid, "malloc", iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "CALL_FUNC [malloc]");
    result = PTRACE_REG_AX(iregs);
    heapptr = PTRACE_REG_AX(iregs); /* keep a copy of this pointer */
    PTRACE_ASM_RECOVER_REGS(pp->hp->pid, iregs, oregs, rc);
    LOG(LOG_DEBUG, "End call function [malloc]...");
    /* Copy data to the malloced area */
    LOG(LOG_DEBUG, "Copying %u bytes to %p.", tgtsz, heapptr);
    if (!heapptr) {
      LOG(LOG_ERR, "Malloced area point is %p.", heapptr);
      break;
    }
    heapptr_need_free = heapptr;
    if ((rc = ptrace_pid_writearray(pp->hp->pid, heapptr, mdata, tgtsz)) < 0) {
      LOG(LOG_DEBUG, "Copy mdata error %s.", strerror(errno));
      break;
    }

    /* Call dlsym */
    if (callsymbol && pp->hp->fn_dlsym && indlladdr != 0) {
      LOG(LOG_DEBUG, "Start call function [dlsym]...");
      PTRACE_ASM_SET_BREAKPOINT(pp->hp->pid, iregs, rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
      PTRACE_ASM_PASS_ARGS2FUNC(pp->hp->pid, iregs, pp->hp->fn_dlsym, indlladdr,
                                (heapptr), rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2FUNC");
      PTRACE_ASM_SET_REGS(pp->hp->pid, "dlsym", iregs, rc);
      PTRACE_ASM_CALL_FUNC(pp->hp->pid, "dlsym", iregs, rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "CALL_FUNC [dlsym]");
      result = PTRACE_REG_AX(iregs);
      PTRACE_ASM_RECOVER_REGS(pp->hp->pid, iregs, oregs, rc);
      LOG(LOG_DEBUG, "Start call function [dlsym].");
      LOG(LOG_DEBUG, "Symbol %s found at %p", callsymbol, result);
      if (result != 0) {
        LOG(LOG_DEBUG, "Start call function [%s]...", callsymbol);
        PTRACE_ASM_SET_BREAKPOINT(pp->hp->pid, iregs, rc);
        PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
        if (datasz > 0) {
          PTRACE_ASM_PASS_ARGS2FUNC(pp->hp->pid, iregs,
                                    result /* value from dlsym */,
                                    (heapptr + symsz), datasz, rc);
          PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2FUNC");
        } else {
          PTRACE_ASM_PASS_ARGS2FUNC(pp->hp->pid, iregs,
                                    result /* value from dlsym */, 0, 0, rc);
          PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2FUNC");
        }
        PTRACE_ASM_SET_REGS(pp->hp->pid, callsymbol, iregs, rc);
        PTRACE_ASM_CALL_FUNC(pp->hp->pid, callsymbol, iregs, rc);
        PTRACE_CHECK_RC_AND_BREAK(rc, "CALL_FUNC [in dll]");
        result = PTRACE_REG_AX(iregs);
        PTRACE_ASM_RECOVER_REGS(pp->hp->pid, iregs, oregs, rc);
        LOG(LOG_DEBUG, "End call function [%s].", callsymbol);
        LOG(LOG_DEBUG, "Return value from call %s(): %p", callsymbol,
            (void *)result);
        if (outcallret) *outcallret = result;
      } else {
        LOG(LOG_ERR,
            "Unable to find %s(). Dll might already have been injected "
            "earlier.",
            callsymbol);
        if (outcallret) *outcallret = 0;
      }
    } else {
      if (callsymbol) {
        LOG(LOG_ERR, "%s not invoked as dlsym() wasn't found.", callsymbol);
      } else {
        LOG(LOG_DEBUG, "No symbol was specified.");
      }
      if (outcallret) *outcallret = 0;
    }
  } while (0);

  do {
    /* free memory */
    if (heapptr_need_free) {
      LOG(LOG_DEBUG, "free heapptr_need_free<%p>...", heapptr_need_free);
      /* Call free */
      LOG(LOG_DEBUG, "Start call function [free]...");
      PTRACE_ASM_SET_BREAKPOINT(pp->hp->pid, iregs, rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
      PTRACE_ASM_PASS_ARGS2FUNC(pp->hp->pid, iregs, pp->hp->fn_free,
                                heapptr_need_free, 0, rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2FUNC");
      PTRACE_ASM_SET_REGS(pp->hp->pid, "free", iregs, rc);
      PTRACE_ASM_CALL_FUNC(pp->hp->pid, "free", iregs, rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "CALL_FUNC [free]");
      PTRACE_ASM_RECOVER_REGS(pp->hp->pid, iregs, oregs, rc);
      LOG(LOG_DEBUG, "End call function [free].");
      heapptr_need_free = 0;
      LOG(LOG_DEBUG, "free heapptr_need_free ok.");
    }
    /* Original reset */
    LOG(LOG_DEBUG, "Setting original registers...");
    if ((rc = ptrace_pid_setregs(pp->hp->pid, &oregs)) < 0) {
      LOG(LOG_ERR, "PID %d will be unstable, set original registers error : %s",
          pp->hp->pid, strerror(errno));
      break;
    }
    LOG(LOG_DEBUG, "Copying stack back...");
    for (idx = 0; idx < sizeof(stack) / sizeof(uintptr_t); ++idx) {
      if ((rc = ptrace_pid_writelong(
               pp->hp->pid, PTRACE_REG_SP(oregs) + idx * sizeof(size_t),
               stack[idx])) < 0)
        break;
      LOG(LOG_DEBUG, "CopyBack idx[%u] SP[%p] V[%p].", idx,
          PTRACE_REG_SP(oregs) + idx * sizeof(size_t), stack[idx]);
    }
    if (rc < 0) {
      LOG(LOG_ERR, "Copy stack back error %s.", strerror(errno));
      break;
    }
    LOG(LOG_DEBUG, "Copy stack back out ok.");
    LOG(LOG_DEBUG, "Continue PID %d...", pp->hp->pid);

    if (needattach == 1) {
      if (ptrace_pid_detach(pp->hp->pid) < 0) {
        LOG(LOG_ERR, "PID %d will be unstable, continue error : %s",
            pp->hp->pid, strerror(errno));
        rc = -1;
        break;
      }
      LOG(LOG_DEBUG, "PID %d is running now.", pp->hp->pid);
    }
  } while (0);

  if (rc < 0 && needattach == 1) {
    LOG(LOG_DEBUG, "Detaching from PID %d.", pp->hp->pid);
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
      LOG(LOG_ERR, "Error detaching from PID %d", pp->hp->pid);
      rc = -1;
    }
  }

  if (mdata) free(mdata);
  mdata = NULL;
  return rc;
}

struct hlink_map {
  /* These first few members are part of the protocol with the debugger.
     This is the same format used in SVR4.  */

  uintptr_t l_addr; /* Base address shared object is loaded at.  */
  char *l_name;     /* Absolute file name object was found in.  */
  uintptr_t *l_ld;  /* Dynamic section of the shared object.  */
  struct hlink_map *l_next, *l_prev; /* Chain of loaded objects.  */
};

int ptrace_pid_inject_libc(pid_t pid, int elang, const char *libcname,
                           const size_t libcsize) {
  int rc = 0;
  int idx = 0;
  /* The stack is read-write and not executable */
  struct user iregs; /* intermediate registers */
  struct user oregs; /* original registers */
  uintptr_t stack[4] = {0, 0, 0,
                        0}; /* max arguments of the functions we are using */

  uintptr_t inj_fd = 0;
  uintptr_t inj_libcname = 0;
  uintptr_t inj_libcbase = 0;
  size_t inj_libcsize = libcsize;

  do {
    inj_libcsize = (libcsize & 0xFFFFFFF0) + 0x10;

    /* Prepare the child for injection */
    LOG(LOG_DEBUG, "Attaching to PID %d", pid);
    if ((rc = ptrace_pid_attach(pid)) < 0) break;
    LOG(LOG_DEBUG, "Waiting attach request to complete...");
    if ((rc = ptrace_pid_wait(pid)) < 0) break;
    LOG(LOG_DEBUG, "Set trace syscall...");
    if ((rc = ptrace_pid_syscall(pid)) < 0) break;
    LOG(LOG_DEBUG, "Waiting an syscall ...");
    if ((rc = ptrace_pid_wait(pid)) < 0) break;
    LOG(LOG_DEBUG, "Getting original registers.");
    if ((rc = ptrace_pid_getregs(pid, &oregs)) < 0) break;
    memcpy(&iregs, &oregs, sizeof(oregs));
    LOG(LOG_DEBUG, "Copying stack out...");
    for (idx = 0; idx < sizeof(stack) / sizeof(uintptr_t); ++idx) {
      if ((rc = ptrace_pid_readlong(
               pid, PTRACE_REG_SP(iregs) + idx * sizeof(size_t), &stack[idx])) <
          0)
        break;
      LOG(LOG_DEBUG, "CopyFrom idx[%u] SP[%p] V[%p].", idx,
          PTRACE_REG_SP(iregs) + idx * sizeof(size_t), stack[idx]);
    }
    if (rc < 0) {
      LOG(LOG_ERR, "Copy stack error %s.", strerror(errno));
      break;
    }
    LOG(LOG_DEBUG, "Copy stack out ok.");

    // syscall open("xxx.so", O_RDONLY, 0)
    PTRACE_ASM_MEMCPY2STACK(pid, iregs, libcname, strlen(libcname) + 1,
                            inj_libcname, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "MEMCPY2STACK");
    PTRACE_ASM_SET_BREAKPOINT(pid, iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
    PTRACE_ASM_PASS_ARGS2SYSCALL6(pid, iregs, P_SYS_openat, (int32_t)P_AT_FDCWD,
                                  inj_libcname, P_O_RDONLY, 0, 0, 0, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2SYSCALL");
    PTRACE_ASM_SET_REGS(pid, "SET_REGS [P_SYS_openat]", iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "SET_REGS");
    PTRACE_ASM_RUN_SYSCALL6(pid, iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "CALL_SYSCALL [P_SYS_openat]");
    inj_fd = PTRACE_REG_AX(iregs);
    PTRACE_ASM_RECOVER_REGS(pid, iregs, oregs, rc);
    LOG(LOG_DEBUG, "Syscall result %p.", inj_fd);

    // wait another syscall
    LOG(LOG_DEBUG, "Set trace syscall...");
    if ((rc = ptrace_pid_syscall(pid)) < 0) break;
    LOG(LOG_DEBUG, "Waiting an syscall ...");
    if ((rc = ptrace_pid_wait(pid)) < 0) break;
    LOG(LOG_DEBUG, "Getting original registers.");
    if ((rc = ptrace_pid_getregs(pid, &oregs)) < 0) break;
    memcpy(&iregs, &oregs, sizeof(oregs));
    LOG(LOG_DEBUG, "Copying stack out...");

    // syscall soptr = mmap(0, inj_libcsize, PROT_EXEC | PROT_READ, MAP_PRIVATE,
    // inj_fd, 0);
    PTRACE_ASM_SET_BREAKPOINT(pid, iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
    PTRACE_ASM_PASS_ARGS2SYSCALL7(pid, iregs, P_SYS_mmap, 0, inj_libcsize,
                                  (P_PROT_EXEC | P_PROT_READ | P_PROT_WRITE),
                                  P_MAP_PRIVATE, inj_fd, 0, 0, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2SYSCALL");
    PTRACE_ASM_SET_REGS(pid, "SET_REGS [P_SYS_mmap]", iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "SET_REGS");
    PTRACE_ASM_RUN_SYSCALL7(pid, iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "CALL_SYSCALL [P_SYS_mmap]");
    inj_libcbase = PTRACE_REG_AX(iregs);
    PTRACE_ASM_RECOVER_REGS(pid, iregs, oregs, rc);
    LOG(LOG_DEBUG, "Syscall result %p.", inj_libcbase);
  } while (0);

  do {
    /* Original reset */
    LOG(LOG_DEBUG, "Setting original registers...");
    if ((rc = ptrace_pid_setregs(pid, &oregs)) < 0) {
      LOG(LOG_ERR, "PID %d will be unstable, set original registers error : %s",
          pid, strerror(errno));
      break;
    }
    LOG(LOG_DEBUG, "Copying stack back...");
    for (idx = 0; idx < sizeof(stack) / sizeof(uintptr_t); ++idx) {
      if ((rc = ptrace_pid_writelong(
               pid, PTRACE_REG_SP(oregs) + idx * sizeof(size_t), stack[idx])) <
          0)
        break;
      LOG(LOG_DEBUG, "CopyBack idx[%u] SP[%p] V[%p].", idx,
          PTRACE_REG_SP(oregs) + idx * sizeof(size_t), stack[idx]);
    }
    if (rc < 0) {
      LOG(LOG_ERR, "Copy stack back error %s.", strerror(errno));
      break;
    }
    LOG(LOG_DEBUG, "Copy stack back out ok.");
    // LOG(LOG_DEBUG, "Continue PID %d...", pid);
    // ptrace_pid_cont(pid);
    if (ptrace_pid_detach(pid) < 0) {
      rc = -1;
      LOG(LOG_ERR, "PID %d will be unstable, continue error : %s", pid,
          strerror(errno));
      break;
    }
    LOG(LOG_DEBUG, "PID %d is running now.", pid);
  } while (0);

  return rc;
}

int ptrace_pp_inject_library(struct ptrace_pid *pp, const char *dll,
                             const char *callsymbol,
                             const unsigned char *paradata, size_t paradatalen,
                             uintptr_t *outdlladdr, uintptr_t *outcallret) {
  size_t dllsz = 0;
  size_t symsz = 0;
  size_t datasz = 0;
  size_t tgtsz = 0;
  int rc = 0;
  unsigned char *mdata = NULL;

  /* The stack is read-write and not executable */
  struct user iregs; /* intermediate registers */
  struct user oregs; /* original registers */
  uintptr_t result = 0;
  uintptr_t stack[4] = {0, 0, 0,
                        0}; /* max arguments of the functions we are using */
  uintptr_t heapptr = 0;
  uintptr_t heapptr_need_free = 0;
  struct hlink_map dll_link_map; /* Force loading the .so file into memory
                                    (sometime it does not auto load) */
  unsigned char dll_link_map_len = sizeof(struct hlink_map);
  char dll_link_map_file[256] = {0};
  int idx = 0;

  if (!dll || !pp || !pp->hp) {
    LOG(LOG_ERR, "Invalid arguments dll<%p> pp<%p> pp->hp<%p>.", dll, pp,
        pp->hp);
    return -1;
  }
  if (!pp->hp->fn_malloc || !pp->hp->fn_dlopen || !pp->hp->fn_free) {
    LOG(LOG_ERR, "No malloc/dlopen found.");
    return -1;
  }
  /* calculate the size to allocate */
  dllsz = strlen(dll) + 1;
  symsz = callsymbol ? (strlen(callsymbol) + 1) : 0;
  datasz = paradata ? paradatalen : 0;
  tgtsz = dllsz + symsz + datasz + 32; /* general buffer */
  tgtsz = (tgtsz > 1024) ? tgtsz : 1024;
  /* align the memory */
  tgtsz += (tgtsz % sizeof(void *) == 0)
               ? 0
               : (sizeof(void *) - (tgtsz % sizeof(void *)));

  LOG(LOG_DEBUG, "Allocating %u bytes in the target.", tgtsz);
  mdata = calloc(sizeof(unsigned char), tgtsz);
  if (!mdata) {
    LOG(LOG_ERR, "malloc error: size %d, %s", tgtsz, strerror(errno));
    return -1;
  }
  memset(mdata, 0, tgtsz);
  memcpy(mdata, dll, dllsz);
  LOG(LOG_DEBUG, "Copy dll [%s] to the target.", dll);
  if (callsymbol) {
    memcpy(mdata + dllsz, callsymbol, symsz);
    LOG(LOG_DEBUG, "Copy symbol [%s] to the target.", callsymbol);
  }
  if (paradata) {
    memcpy(mdata + dllsz + symsz, paradata, datasz);
    LOG(LOG_DEBUG, "Copy data len [%u] to the target.", datasz);
  }

  do {
    /* Prepare the child for injection */
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
    LOG(LOG_DEBUG, "Getting original registers.");
    if ((rc = ptrace_pid_getregs(pp->hp->pid, &oregs)) < 0) break;
    memcpy(&iregs, &oregs, sizeof(oregs));
    LOG(LOG_DEBUG, "Copying stack out...");
    for (idx = 0; idx < sizeof(stack) / sizeof(uintptr_t); ++idx) {
      if ((rc = ptrace_pid_readlong(pp->hp->pid,
                                    PTRACE_REG_SP(iregs) + idx * sizeof(size_t),
                                    &stack[idx])) < 0)
        break;
      LOG(LOG_DEBUG, "CopyFrom idx[%u] SP[%p] V[%p].", idx,
          PTRACE_REG_SP(iregs) + idx * sizeof(size_t), stack[idx]);
    }
    if (rc < 0) {
      LOG(LOG_ERR, "Copy stack error %s.", strerror(errno));
      break;
    }
    LOG(LOG_DEBUG, "Copy stack out ok.");
    /* Call malloc */
    LOG(LOG_DEBUG, "Start call function [malloc]...");
    PTRACE_ASM_SET_BREAKPOINT(pp->hp->pid, iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
    PTRACE_ASM_PASS_ARGS2FUNC(pp->hp->pid, iregs, pp->hp->fn_malloc, tgtsz, 0,
                              rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2FUNC");
    PTRACE_ASM_SET_REGS(pp->hp->pid, "malloc", iregs, rc);
    PTRACE_ASM_CALL_FUNC(pp->hp->pid, "malloc", iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "CALL_FUNC [malloc]");
    result = PTRACE_REG_AX(iregs);
    heapptr = PTRACE_REG_AX(iregs); /* keep a copy of this pointer */
    PTRACE_ASM_RECOVER_REGS(pp->hp->pid, iregs, oregs, rc);
    LOG(LOG_DEBUG, "End call function [malloc] result.");
    /* Copy data to the malloced area */
    LOG(LOG_DEBUG, "Copying %u bytes to %p.", tgtsz, heapptr);
    if (!heapptr) {
      LOG(LOG_ERR, "Malloced area point is %p.", heapptr);
      break;
    }
    heapptr_need_free = heapptr;
    if ((rc = ptrace_pid_writearray(pp->hp->pid, heapptr, mdata, tgtsz)) < 0) {
      LOG(LOG_ERR, "Copy mdata error %s.", strerror(errno));
      break;
    }
    /* Call dlopen */
    LOG(LOG_DEBUG, "Start call function [dlopen]...");
    PTRACE_ASM_SET_BREAKPOINT(pp->hp->pid, iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
    PTRACE_ASM_PASS_ARGS2FUNC(pp->hp->pid, iregs, pp->hp->fn_dlopen, heapptr,
                              (RTLD_NOW | RTLD_LOCAL), rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2FUNC");
    PTRACE_ASM_SET_REGS(pp->hp->pid, "dlopen", iregs, rc);
    PTRACE_ASM_CALL_FUNC(pp->hp->pid, "dlopen", iregs, rc);
    PTRACE_CHECK_RC_AND_BREAK(rc, "CALL_FUNC [dlopen]");
    result = PTRACE_REG_AX(iregs);
    PTRACE_ASM_RECOVER_REGS(pp->hp->pid, iregs, oregs, rc);
    LOG(LOG_DEBUG, "End call function [dlopen].");
    LOG(LOG_DEBUG, "Dll opened at %p", result);
    if (outdlladdr) *outdlladdr = result;
    /* Call dlsym */
    if (callsymbol && pp->hp->fn_dlsym && *outdlladdr != 0) {
      if (0 /* TODO: not work for now */) {
        // Force loading the .so file into memory (sometime it does not auto
        // load)
        if (ptrace_pid_readarray(pp->hp->pid, *outdlladdr,
                                 (unsigned char *)&dll_link_map,
                                 dll_link_map_len) == 0) {
          if (ptrace_pid_readarray(pp->hp->pid, (uintptr_t)dll_link_map.l_name,
                                   (unsigned char *)dll_link_map_file,
                                   dllsz) == 0) {
            LOG(LOG_DEBUG, "Read dll_link_map.l_name(%p) = %s",
                (uintptr_t)dll_link_map.l_name, dll_link_map_file);
          }
        }
      }
      LOG(LOG_DEBUG, "Start call function [dlsym]...");
      PTRACE_ASM_SET_BREAKPOINT(pp->hp->pid, iregs, rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
      PTRACE_ASM_PASS_ARGS2FUNC(pp->hp->pid, iregs, pp->hp->fn_dlsym,
                                *outdlladdr, (heapptr + dllsz), rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2FUNC");
      PTRACE_ASM_SET_REGS(pp->hp->pid, "dlsym", iregs, rc);
      PTRACE_ASM_CALL_FUNC(pp->hp->pid, "dlsym", iregs, rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "CALL_FUNC [dlsym]");
      result = PTRACE_REG_AX(iregs);
      PTRACE_ASM_RECOVER_REGS(pp->hp->pid, iregs, oregs, rc);
      LOG(LOG_DEBUG, "Start call function [dlsym].");
      LOG(LOG_DEBUG, "Symbol %s found at %p", callsymbol, result);
      if (result != 0) {
        LOG(LOG_DEBUG, "Start call function [%s]...", callsymbol);
        PTRACE_ASM_SET_BREAKPOINT(pp->hp->pid, iregs, rc);
        PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
        if (datasz > 0) {
          PTRACE_ASM_PASS_ARGS2FUNC(pp->hp->pid, iregs,
                                    result /* value from dlsym */,
                                    (heapptr + dllsz + symsz), datasz, rc);
          PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2FUNC");
        } else {
          PTRACE_ASM_PASS_ARGS2FUNC(pp->hp->pid, iregs,
                                    result /* value from dlsym */, 0, 0, rc);
          PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2FUNC");
        }
        PTRACE_ASM_SET_REGS(pp->hp->pid, callsymbol, iregs, rc);
        PTRACE_ASM_CALL_FUNC(pp->hp->pid, callsymbol, iregs, rc);
        PTRACE_CHECK_RC_AND_BREAK(rc, "CALL_FUNC [in dll]");
        result = PTRACE_REG_AX(iregs);
        PTRACE_ASM_RECOVER_REGS(pp->hp->pid, iregs, oregs, rc);
        LOG(LOG_DEBUG, "End call function [%s].", callsymbol);
        LOG(LOG_DEBUG, "Return value from call %s(): %p", callsymbol,
            (void *)result);
        if (outcallret) *outcallret = result;
      } else {
        LOG(LOG_ERR,
            "Unable to find %s(). Dll might already have been injected "
            "earlier.",
            callsymbol);
        if (outcallret) *outcallret = 0;
      }
    } else {
      if (callsymbol) {
        LOG(LOG_ERR, "%s not invoked as dlsym() wasn't found.", callsymbol);
      } else {
        LOG(LOG_DEBUG,
            "No symbol was specified. _init() might have been invoked.");
      }
      if (outcallret) *outcallret = 0;
    }
  } while (0);

  do {
    /* free memory */
    if (heapptr_need_free) {
      LOG(LOG_DEBUG, "free heapptr_need_free<%p>...", heapptr_need_free);
      /* Call free */
      LOG(LOG_DEBUG, "Start call function [free]...");
      PTRACE_ASM_SET_BREAKPOINT(pp->hp->pid, iregs, rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "SET_BREAKPOINT");
      PTRACE_ASM_PASS_ARGS2FUNC(pp->hp->pid, iregs, pp->hp->fn_free,
                                heapptr_need_free, 0, rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "PASS_ARGS2FUNC");
      PTRACE_ASM_SET_REGS(pp->hp->pid, "free", iregs, rc);
      PTRACE_ASM_CALL_FUNC(pp->hp->pid, "free", iregs, rc);
      PTRACE_CHECK_RC_AND_BREAK(rc, "CALL_FUNC [free]");
      PTRACE_ASM_RECOVER_REGS(pp->hp->pid, iregs, oregs, rc);
      LOG(LOG_DEBUG, "End call function [free].");
      heapptr_need_free = 0;
      LOG(LOG_DEBUG, "free heapptr_need_free ok.");
    }
    /* Original reset */
    LOG(LOG_DEBUG, "Setting original registers...");
    if ((rc = ptrace_pid_setregs(pp->hp->pid, &oregs)) < 0) {
      LOG(LOG_ERR, "PID %d will be unstable, set original registers error : %s",
          pp->hp->pid, strerror(errno));
      break;
    }
    LOG(LOG_DEBUG, "Copying stack back...");
    for (idx = 0; idx < sizeof(stack) / sizeof(uintptr_t); ++idx) {
      if ((rc = ptrace_pid_writelong(
               pp->hp->pid, PTRACE_REG_SP(oregs) + idx * sizeof(size_t),
               stack[idx])) < 0)
        break;
      LOG(LOG_DEBUG, "CopyBack idx[%u] SP[%p] V[%p].", idx,
          PTRACE_REG_SP(oregs) + idx * sizeof(size_t), stack[idx]);
    }
    if (rc < 0) {
      LOG(LOG_ERR, "Copy stack back error %s.", strerror(errno));
      break;
    }
    LOG(LOG_DEBUG, "Copy stack back out ok.");
    LOG(LOG_DEBUG, "Continue PID %d...", pp->hp->pid);
    /* if ((rc = ptrace_pid_cont(pp->hp->pid)) < 0) */
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
      rc = -1;
      LOG(LOG_ERR, "PID %d will be unstable, continue error : %s", pp->hp->pid,
          strerror(errno));
      break;
    }
    LOG(LOG_DEBUG, "PID %d is running now.", pp->hp->pid);
  } while (0);

  if (rc < 0) {
    LOG(LOG_DEBUG, "Detaching from PID %d.", pp->hp->pid);
    if (ptrace_pid_detach(pp->hp->pid) < 0) {
      LOG(LOG_ERR, "Error detaching from PID %d", pp->hp->pid);
      rc = -1;
    }
  }

  if (mdata) free(mdata);
  mdata = NULL;
  return rc;
}

#ifdef TEST_SYMBOL
int main(int argc, char *argv[]) {
  if (argc < 3) {
    printf("usage: %s <pid> <dll>\n", argv[0]);
    exit(-1);
  }

  int pid = atoi(argv[1]);

  struct ptrace_pid *pp = ptrace_pp_create(pid);
  ptrace_pp_inject_library(pp, argv[2], NULL, NULL, 0, NULL, NULL);
  ptrace_pp_destroy(pp);

  return 0;
}
#endif
