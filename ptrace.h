//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#ifndef __HPATCH_PTRACE_H__
#define __HPATCH_PTRACE_H__

#include "define.h"
#include "symbol.h"

#if __WORDSIZE == 64
#define PTRACE_REG_IP_NAME "RIP"
#define PTRACE_REG_IP(A) (A).regs.rip
#define PTRACE_REG_SP(A) (A).regs.rsp
#define PTRACE_REG_BP(A) (A).regs.rbp
#define PTRACE_REG_AX(A) (A).regs.rax
#define PTRACE_REG_CX(A) (A).regs.rcx
#define PTRACE_REG_BX(A) (A).regs.rbx
#define PTRACE_REG_DX(A) (A).regs.rdx
#define PTRACE_REG_DI(A) (A).regs.rdi
#define PTRACE_REG_SI(A) (A).regs.rsi
#define PTRACE_REG_R8(A) (A).regs.r8
#define PTRACE_REG_R9(A) (A).regs.r9
#define PTRACE_REG_R10(A) (A).regs.r10
#define PTRACE_REG_R11(A) (A).regs.r11
#define PTRACE_REG_R14(A) (A).regs.r14

#define PTRACE_REG_CF_SET(A) ((A).regs.eflags |= 1UL << 0)
#define PTRACE_REG_CF_UNSET(A) ((A).regs.eflags &= ~(1UL << 0))
#define PTRACE_REG_ZF_SET(A) ((A).regs.eflags |= 1UL << 6)
#define PTRACE_REG_ZF_UNSET(A) ((A).regs.eflags &= ~(1UL << 6))

#else
#define PTRACE_REG_IP_NAME "EIP"
#define PTRACE_REG_IP(A) (A).regs.eip
#define PTRACE_REG_SP(A) (A).regs.esp
#define PTRACE_REG_AX(A) (A).regs.eax
#define PTRACE_REG_CX(A) (A).regs.ecx
#endif

#define PTRACE_CHECK_RC_AND_BREAK(rc,log) \
    if (rc < 0) \
    { \
        LOG(LOG_ERR, "ASM ERROR: %s, %s.", log, strerror(errno)); \
        break; \
    }

#define PTRACE_ASM_SET_REGS(pid,fn,iregs,rc) \
    do { \
        LOG(LOG_DEBUG,"Setting registers and invoking %s.", fn); \
        if ((rc = ptrace_pid_setregs(pid, &iregs)) < 0) \
            break; \
    } while (0)

#define PTRACE_ASM_CALL_FUNC(pid,fn,iregs,rc) \
    do { \
        if (rc < 0) \
            break; \
        LOG(LOG_DEBUG,"Executing..."); \
        if ((rc = ptrace_pid_cont(pid)) < 0) \
            break; \
        LOG(LOG_DEBUG,"Waiting..."); \
        if ((rc = ptrace_pid_wait(pid)) < 0) \
            break; \
        LOG(LOG_DEBUG,"Getting registers."); \
        if ((rc = ptrace_pid_getregs(pid, &iregs)) < 0) \
            break; \
        LOG(LOG_DEBUG,"Registers: IP:%p, SP:%p, AX:%p", PTRACE_REG_IP(iregs), PTRACE_REG_SP(iregs), PTRACE_REG_AX(iregs)); \
        if (PTRACE_REG_IP(iregs) == 0) { \
            LOG(LOG_DEBUG,"IP is at breakpoint, function call finished."); \
            break; \
        } \
        LOG(LOG_DEBUG,"IP is not at breakpoint, try wait again..."); \
    } while (0)

#define PTRACE_ASM_MEMCPY2STACK(pid,iregs,mem,memsize,retmem,rc) \
    do { \
        LOG(LOG_DEBUG,"MEMCPY2STACK : from SP[%p]", PTRACE_REG_SP(iregs)); \
        PTRACE_REG_SP(iregs) = PTRACE_REG_SP(iregs) - (((memsize) / 8 + 1) * 8); \
        LOG(LOG_DEBUG,"MEMCPY2STACK : to   SP[%p]", PTRACE_REG_SP(iregs)); \
        LOG(LOG_DEBUG,"Copy mem to stack..."); \
        if ((rc = ptrace_pid_writearray(pid, PTRACE_REG_SP(iregs), (unsigned char *)mem, (size_t)(memsize))) < 0) \
            break; \
        retmem = PTRACE_REG_SP(iregs);\
        LOG(LOG_DEBUG,"Copy mem to SP[%p] V[%p] Size[%d] done.", PTRACE_REG_SP(iregs), mem, memsize); \
    } while (0)

/* Alignment for gcc ABI: 16bypes align; (not work , need -8, dlopen bug?) */
#define PTRACE_ASM_SET_BREAKPOINT(pid,iregs,rc) \
    do { \
        uintptr_t nullcode = 0; \
        LOG(LOG_DEBUG,"Alignment for gcc ABI : from SP[%p]", PTRACE_REG_SP(iregs)); \
        PTRACE_REG_SP(iregs) = PTRACE_REG_SP(iregs) - 64; \
        PTRACE_REG_SP(iregs) = PTRACE_REG_SP(iregs) & (-15); \
        PTRACE_REG_SP(iregs) = PTRACE_REG_SP(iregs) - (8); \
        LOG(LOG_DEBUG,"Alignment for gcc ABI : to   SP[%p]", PTRACE_REG_SP(iregs)); \
        LOG(LOG_DEBUG,"Setting breakpoint to stack..."); \
        if ((rc = ptrace_pid_writelong(pid, PTRACE_REG_SP(iregs), nullcode)) < 0) \
            break; \
        LOG(LOG_DEBUG,"Set breakpoint SP[%p] V[%p] done.", PTRACE_REG_SP(iregs), nullcode); \
    } while (0)

#define PTRACE_ASM_RECOVER_REGS(pid,iregs,oregs,rc)\
    do { \
        LOG(LOG_DEBUG, "Setting original registers...");\
        memcpy(&iregs, &oregs, sizeof(oregs));\
        if ((rc = ptrace_pid_setregs(pid, &oregs)) < 0) { \
            LOG(LOG_ERR, "PID %d will be unstable, set original registers error : %s", pid, strerror(errno)); \
            break;\
        }\
    }while(0)\

#if __WORDSIZE == 64
#define P_SYS_openat    257
#define P_AT_FDCWD      -100
#define P_O_RDONLY      0
#define P_O_WRONLY      1
#define P_O_RDWR        2

#define P_SYS_mmap		9
#define P_PROT_READ		1
#define P_PROT_WRITE    2
#define P_PROT_EXEC		4
#define P_MAP_PRIVATE   2

#define PTRACE_ASM_PASS_ARGS2SYSCALL7(pid,A,SYSCALLNO,ARG1,ARG2,ARG3,ARG4,ARG5,ARG6,ARG7,rc) \
    do { \
        PTRACE_REG_SP(iregs) = PTRACE_REG_SP(iregs) - 16; \
        if ((rc = ptrace_pid_writelong(pid, PTRACE_REG_SP(iregs) + 8, ARG7)) < 0) { \
            PTRACE_REG_SP(iregs) = PTRACE_REG_SP(iregs) + 16; \
            break; \
        } \
        A.regs.r9  =  ARG6; \
        A.regs.r8  =  ARG5; \
        A.regs.r10 =  ARG4; \
        A.regs.rdx =  ARG3; \
        A.regs.rsi =  ARG2; \
        A.regs.rdi =  ARG1; \
        A.regs.orig_rax = SYSCALLNO; \
        LOG(LOG_DEBUG,"ARGS2SYSCALL[%p]: ARG1:%p, ARG2:%p, ARG3:%p, ARG4:%p, ARG5:%p, ARG6:%p, ARG7:%p", SYSCALLNO, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6, ARG7); \
        rc = 0; \
        pid = pid; \
    } while (0)

#define PTRACE_ASM_RUN_SYSCALL7(pid,iregs,rc) \
    do { \
        if (rc < 0) \
            break; \
        LOG(LOG_DEBUG,"Executing..."); \
        if ((rc = ptrace_pid_syscall(pid)) < 0) \
            break; \
        LOG(LOG_DEBUG,"Waiting..."); \
        if ((rc = ptrace_pid_wait(pid)) < 0) \
            break; \
        LOG(LOG_DEBUG,"Getting registers."); \
        if ((rc = ptrace_pid_getregs(pid, &iregs)) < 0) \
            break; \
        PTRACE_REG_SP(iregs) = PTRACE_REG_SP(iregs) + 16; \
        LOG(LOG_DEBUG,"Registers: IP:%p, SP:%p, AX:%p", PTRACE_REG_IP(iregs), PTRACE_REG_SP(iregs), PTRACE_REG_AX(iregs)); \
        if (!((int64_t)PTRACE_REG_AX(iregs) >= -4095 && (int64_t)PTRACE_REG_AX(iregs) <= -1)) { \
            LOG(LOG_DEBUG,"Syscall function call finished, return %p.", PTRACE_REG_AX(iregs)); \
            break; \
        } \
        rc = -1; \
        LOG(LOG_DEBUG,"Syscall return error : %p, try wait again...", PTRACE_REG_AX(iregs)); \
    } while (0)


#define PTRACE_ASM_PASS_ARGS2SYSCALL6(pid,A,SYSCALLNO,ARG1,ARG2,ARG3,ARG4,ARG5,ARG6,rc) \
    do { \
        A.regs.r9  =  ARG6; \
        A.regs.r8  =  ARG5; \
        A.regs.r10 =  ARG4; \
        A.regs.rdx =  ARG3; \
        A.regs.rsi =  ARG2; \
        A.regs.rdi =  ARG1; \
        A.regs.orig_rax = SYSCALLNO; \
        LOG(LOG_DEBUG,"ARGS2SYSCALL[%p]: ARG1:%p, ARG2:%p, ARG3:%p, ARG4:%p, ARG5:%p, ARG6:%p", SYSCALLNO, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6); \
        rc = 0; \
        pid = pid; \
    } while (0)

#define PTRACE_ASM_RUN_SYSCALL6(pid,iregs,rc) \
    do { \
        if (rc < 0) \
            break; \
        LOG(LOG_DEBUG,"Executing..."); \
        if ((rc = ptrace_pid_syscall(pid)) < 0) \
            break; \
        LOG(LOG_DEBUG,"Waiting..."); \
        if ((rc = ptrace_pid_wait(pid)) < 0) \
            break; \
        LOG(LOG_DEBUG,"Getting registers."); \
        if ((rc = ptrace_pid_getregs(pid, &iregs)) < 0) \
            break; \
        LOG(LOG_DEBUG,"Registers: IP:%p, SP:%p, AX:%p", PTRACE_REG_IP(iregs), PTRACE_REG_SP(iregs), PTRACE_REG_AX(iregs)); \
        if (!((int64_t)PTRACE_REG_AX(iregs) >= -4095 && (int64_t)PTRACE_REG_AX(iregs) <= -1)) { \
            LOG(LOG_DEBUG,"Syscall function call finished, return %p.", PTRACE_REG_AX(iregs)); \
            break; \
        } \
        rc = -1; \
        LOG(LOG_DEBUG,"Syscall return error : %p, try wait again...", PTRACE_REG_AX(iregs)); \
    } while (0)

#endif /* __WORDSIZE == 64 */

#if __WORDSIZE == 64
#define PTRACE_ASM_PASS_ARGS2FUNC(pid,A,FN,ARG1,ARG2,rc) \
    do { \
        A.regs.rsi = ARG2; \
        A.regs.rdi = ARG1; \
        A.regs.rip = FN; \
        A.regs.rax = 0; \
        LOG(LOG_DEBUG,"ARGS2FUNC: FN:[%p], ARG1:%p, ARG2:%p", FN, ARG1, ARG2); \
        rc = 0; \
        pid = pid; \
    } while (0)
#else /* __WORDSIZE == 32 */
#define PTRACE_ASM_PASS_ARGS2FUNC(pid,A,FN,ARG1,ARG2,rc) \
    do { \
        LOG(LOG_DEBUG,"Setting Arg 1 to stack..."); \
        if ((rc = ptrace_pid_writelong(pid, PTRACE_REG_SP(A) + sizeof(size_t), \
                                       ARG1)) < 0) \
            break; \
        LOG(LOG_DEBUG,"Set Arg 1 to stack ok."); \
        LOG(LOG_DEBUG,"Setting Arg 2 to stack..."); \
        if ((rc = ptrace_pid_writelong(pid, PTRACE_REG_SP(A) + 2 * sizeof(size_t), \
                                       ARG2)) < 0) \
            break; \
        LOG(LOG_DEBUG,"Set Arg 2 to stack ok."); \
        A.regs.eip = FN; \
        A.regs.eax = 0; \
    } while (0)
#endif /* __WORDSIZE == 64 */


struct ptrace_pid
{
    struct symbol_elf_pid* hp;
    pid_t pid;
    int attached;
};

struct ptrace_pid* ptrace_pp_create(pid_t pid, int symelang);
struct ptrace_pid * ptrace_pp_create_nolibc(pid_t pid, int symelang);
struct ptrace_pid * ptrace_pp_create_inner(pid_t pid, int symelang, int needlibc);

extern int ptrace_traceme();
extern int ptrace_pid_attach(pid_t pid);
extern int ptrace_pid_detach(pid_t pid);
extern int ptrace_pid_syscall(pid_t pid);
extern int ptrace_pid_cont(pid_t pid);
extern int ptrace_pid_cont_one(pid_t pid);
extern int ptrace_pid_wait(pid_t pid);
extern int ptrace_pid_wait_attach(pid_t pid, pid_t tid);
extern int ptrace_pid_wait_thread(pid_t pid, pid_t *childpid, pid_t *newpid);
extern int ptrace_pid_set_watchthread(pid_t pid);
extern int ptrace_pid_getregs(pid_t pid, struct user *regs);
extern int ptrace_pid_setregs(pid_t pid, const struct user *regs);
extern int ptrace_pid_readlong(pid_t pid, uintptr_t target, uintptr_t *outvalue);
extern int ptrace_pid_writelong(pid_t pid, uintptr_t target, uintptr_t invalue);
extern int ptrace_pid_readarray(pid_t pid, uintptr_t target,
                                unsigned char* data, size_t datasz);
extern int ptrace_pid_writearray(pid_t pid, uintptr_t target,
                                 const unsigned char* data, size_t datasz);
extern int ptrace_pid_call_func_noparam(pid_t pid, uintptr_t funcaddr, uintptr_t* outcallret);
extern int ptrace_pp_read_data(struct ptrace_pid* pp, uintptr_t target, unsigned char* outdata, size_t outdatalen);
extern int ptrace_pp_write_data(struct ptrace_pid* pp, uintptr_t target, const unsigned char* indata, size_t indatalen);
extern int ptrace_pp_call_library(struct ptrace_pid* pp, uintptr_t indlladdr, const char* callsymbol,
                                  const unsigned char* paradata, size_t paradatalen, uintptr_t* outcallret, int needattach);
extern int ptrace_pid_inject_libc(pid_t pid, int elang, const char *libcname, const size_t libcsize);
extern int ptrace_pp_inject_library(struct ptrace_pid* pp, const char* dll, const char* callsymbol,
                                    const unsigned char* paradata, size_t paradatalen,
                                    uintptr_t* outdlladdr, uintptr_t* outcallret);
void ptrace_pp_destroy(struct ptrace_pid* pp);

#endif /* __HPATCH_PTRACE_H__ */

