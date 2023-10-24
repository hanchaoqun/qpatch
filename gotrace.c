//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include "define.h"
#include "ptrace.h"
#include "symbol.h"
#include "hashmap.c/hashmap.h"
#include "linkable.h"

struct user_hashmap {
    uint64_t key;
    void * data;
};

int user_compare(const void *a, const void *b, void *udata) {
    const struct user_hashmap *ua = a;
    const struct user_hashmap *ub = b;

    if (ua->key > ub->key) {
        return 1;
    } else if (ua->key < ub->key) {
        return -1;
    }
    return 0;
}

uint64_t user_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const struct user_hashmap *user = item;
    return hashmap_sip(&(user->key), sizeof(user->key), seed0, seed1);
}

struct hashmap *user_hashmap_init(int size)
{
    return hashmap_new(sizeof(struct user_hashmap), size, 0, 0, user_hash, user_compare, NULL, NULL);
}

void *user_hashmap_get(struct hashmap *map, uint64_t key)
{
    const struct user_hashmap *user = hashmap_get(map, &(struct user_hashmap){ .key=key });
    if (user == NULL) {
        return NULL;
    }
    return user->data;
}
void *user_hashmap_set(struct hashmap *map, uint64_t key, void *data)
{
    const struct user_hashmap *user = hashmap_set(map, &(struct user_hashmap){ .key=key, .data=data });
	return (void *)user;
}

#define GOTRACE_MAX_PATH_LEN 256

// Go 1.16
//  <+0> : mov %fs:0xfffffffffffffff8,%rcx  => 0x64 0x48 0x8b 0x0c 0x25 0xf8 0xff 0xff 0xff
//  <+9> : cmp 0x10(%rcx),%rsp  => 0x48 0x3b 0x61 0x10
//  <+13>: jbe

// Go 1.17
// <+0>: cmp 0x10(%r14),%rsp => 0x49 0x3b 0x66 0x10
// <+4>: jbe

// C/C++
// <+0>: push %rbp       => 0x55
// <+1>: mov %rsp,%rbp   => 0x48 0x89 0xe5
// <+4>:

#define GOTRACE_GO_PRE_OPCODE_MAX 16

#define GOTRACE_GO_SHOW_ARG_NUM 9
#define GOTRACE_C_SHOW_ARG_NUM 5

#define GOTRACE_GO_PRE_CNT 3
#define GOTRACE_GO_116 1
#define GOTRACE_GO_117 2
#define GOTRACE_GO_CPP 3

struct tag_gotrace_go_pre {
    unsigned char opcodes[GOTRACE_GO_PRE_OPCODE_MAX];
    unsigned char bpcodes[GOTRACE_GO_PRE_OPCODE_MAX];
    int codesize;
    int bpoff;
} gotrace_go_pre[GOTRACE_GO_PRE_CNT] = {
        /* go 1.16 */
        {
            {0x64,0x48,0x8b,0x0c,0x25,0xf8,0xff,0xff,0xff,0x48,0x3b,0x61,0x10},
            {0x64,0x48,0x8b,0x0c,0x25,0xf8,0xff,0xff,0xff,0x90,0x90,0x90,0xcc},
            13,
            13
        },
        /* go 1.17 */
        {
            {0x49,0x3b,0x66,0x10},
            {0x90,0x90,0x90,0xcc},
            4,
            4
        },
        /* c/c++ */
        {
            {0x55,0x48,0x89,0xe5},
            {0xcc,0x48,0x89,0xe5},
            4,
            1
        },
};

int gotrace_wait_breakpoint(struct ptrace_pid * pp, int force);
int gotrace_set_breakpoint(struct ptrace_pid * pp, struct symbol_elf_sym* sym);
int gotrace_unset_breakpoint(struct ptrace_pid * pp, struct symbol_elf_sym* sym);
void gotrace_oncallin_116(struct ptrace_pid * pp, struct user* oregs, struct symbol_elf_sym* sym);
void gotrace_oncallin_117(struct ptrace_pid * pp, struct user* oregs, struct symbol_elf_sym* sym);
void gotrace_oncallin_cpp(struct ptrace_pid * pp, struct user* oregs, struct symbol_elf_sym* sym);
int gotrace_filter(struct symbol_elf_sym* sym);

extern UINT32 g_ucurLogLevel;
struct hashmap* g_add2sym_maps = NULL;
int g_stop = 0;
int g_enableCppfilt = 1;

struct hashmap* gotrace_get_hashmap()
{
    return g_add2sym_maps;
}

struct symbol_elf_sym* gotrace_getsymbyaddr(uintptr_t addr)
{
    struct symbol_elf_sym* sym = NULL;
    sym = (struct symbol_elf_sym*)user_hashmap_get(g_add2sym_maps, (uint64_t)addr);
    return sym;
}

struct symbol_elf_sym* gotrace_getelfsym(struct ptrace_pid * pp, const char * name)
{
    struct symbol_elf_sym* sym = NULL;
    for (int idx = 0; idx < pp->hp->exe_symbols_num; ++idx) {
        if (strcmp(pp->hp->exe_symbols[idx].name, name) == 0) {
            sym = &(pp->hp->exe_symbols[idx]);
            break;
        }
    }
    return sym;
}

char * __cxa_demangle(const char* mangled_name, char* buf, size_t* n, int* status);
char * gotrace_demangle(char * mangled_name)
{
    int status = 0;
    char *buf = __cxa_demangle(mangled_name, 0x0, 0x0, &status);
    if (status == 0) { /* return buf to output */
        return buf;
    }
    return mangled_name;
}

int gotrace_set_breakpoint_all(struct ptrace_pid * pp)
{
    int sum = 0;
    int cnt = 0;
    struct symbol_elf_sym* sym = NULL;
    struct symbol_elf_sym* symtmp = NULL;
    struct hashmap* map = user_hashmap_init(pp->hp->exe_symbols_num);
    g_add2sym_maps = map;
    for (int idx = 0; idx < pp->hp->exe_symbols_num; ++idx) {
        sym = &(pp->hp->exe_symbols[idx]);
        if (SYMBOL_IS_FUNCTION != sym->type || sym->address == 0 || gotrace_filter(sym) == -1) {
            continue;
        }
        symtmp = gotrace_getsymbyaddr(sym->address);
        if (symtmp != NULL) {
            LOG(LOG_ERR, "sym address <%p> with name <%s> already insterted by <%s>!", sym->address, sym->name, symtmp->name);
            continue;
        }
        sym->cppname = NULL;
        if (g_enableCppfilt == 1) {
            sym->cppname = gotrace_demangle(sym->name);
        }
        if (gotrace_set_breakpoint(pp, sym) < 0) {
            LOG(LOG_ERR, "sym <%s> set breakpoint error!", sym->name);
            continue;
        }
        cnt = hashmap_count(map);
        user_hashmap_set(map, (uint64_t)(sym->address), (void*)(sym));
        if (hashmap_count(map) != cnt + 1) {
            LOG(LOG_ERR, "sym <%s> user_hashmap_set insert error!", sym->name);
            continue;
        }
        sum = sum + 1;
    }

    return sum;
}

void gotrace_unset_breakpoint_all(struct ptrace_pid * pp)
{
    struct symbol_elf_sym* sym = NULL;
    struct hashmap* map = user_hashmap_init(pp->hp->exe_symbols_num);
    g_add2sym_maps = map;
    for (int idx = 0; idx < pp->hp->exe_symbols_num; ++idx) {
        sym = &(pp->hp->exe_symbols[idx]);
        if (SYMBOL_IS_FUNCTION != sym->type || sym->address == 0 || gotrace_filter(sym) == -1) {
            continue;
        }
        if (sym->setbp == 0 || sym->gopreidx == 0) {
            continue;
        }
        if (gotrace_unset_breakpoint(pp, sym) < 0) {
            continue;
        }
    }
}

int gotrace_set_breakpoint(struct ptrace_pid * pp, struct symbol_elf_sym* sym)
{
    int rc = -1;
    int idx = 0;
    pid_t pid = pp->pid;
    unsigned char tmpopcode[GOTRACE_GO_PRE_OPCODE_MAX];

    do{
        if ((rc = ptrace_pid_readarray(pid, sym->address, tmpopcode, GOTRACE_GO_PRE_OPCODE_MAX)) < 0){
            LOG(LOG_ERR, "Process <%s> can't read fun from(%p) len(%u).", sym->name, sym->address, GOTRACE_GO_PRE_OPCODE_MAX);
            break;
        }
        for (idx = 0; idx < GOTRACE_GO_PRE_CNT; idx++) {
            if (memcmp(tmpopcode, gotrace_go_pre[idx].opcodes, gotrace_go_pre[idx].codesize) == 0) {
                sym->gopreidx = idx + 1;
                break;
            }
        }
        if (sym->gopreidx == 0) {
            LOG(LOG_INFO, "Process <%s>(%p) go pre code is not expected!", sym->name, sym->address);
            break;
        }
        idx = sym->gopreidx - 1;
        if ((rc = ptrace_pid_writearray(pid, sym->address, (unsigned char *)gotrace_go_pre[idx].bpcodes, gotrace_go_pre[idx].codesize)) < 0){
            LOG(LOG_ERR, "Process <%s> can't write to(%p) len(%u).", sym->name, sym->address, gotrace_go_pre[idx].codesize);
            break;
        }
        LOG(LOG_INFO, "set breakpoint <%s>(%p) gopreidx<%d> ok!", sym->name, sym->address, sym->gopreidx);
        sym->setbp = 1;
        rc = 0;
    } while(0);

    return rc;
}


int gotrace_unset_breakpoint(struct ptrace_pid * pp, struct symbol_elf_sym* sym)
{
    int rc = -1;
    pid_t pid = pp->pid;
    unsigned char tmpopcode[GOTRACE_GO_PRE_OPCODE_MAX];
    int idx = sym->gopreidx - 1;

    do{
        if ((rc = ptrace_pid_readarray(pid, sym->address, tmpopcode, GOTRACE_GO_PRE_OPCODE_MAX)) < 0){
            LOG(LOG_ERR, "Process <%s> can't read fun from(%p) len(%u).", sym->name, sym->address, GOTRACE_GO_PRE_OPCODE_MAX);
            break;
        }
        if (memcmp(tmpopcode, gotrace_go_pre[idx].bpcodes, gotrace_go_pre[idx].codesize) != 0) {
            break;
        }
        if ((rc = ptrace_pid_writearray(pid, sym->address, (unsigned char *)gotrace_go_pre[idx].opcodes, gotrace_go_pre[idx].codesize)) < 0){
            LOG(LOG_ERR, "Process <%s> can't write to(%p) len(%u).", sym->name, sym->address, gotrace_go_pre[idx].codesize);
            break;
        }
        LOG(LOG_INFO, "unset breakpoint <%s>(%p) gopreidx<%d> ok!", sym->name, sym->address, sym->gopreidx);
        sym->setbp = 0;
        rc = 0;
    } while(0);

    return rc;
}

/* 48 3b 61 10 cmp    0x10(%rcx),%rsp */
int gotrace_sim_cmp_rcx_0x10_rsp(struct ptrace_pid * pp, struct user* oregs)
{
    pid_t pid = pp->pid;
    uintptr_t rcx = PTRACE_REG_CX(*oregs);
    uintptr_t rsp = PTRACE_REG_SP(*oregs);
    uintptr_t rcx_0x10_ptr = rcx + 0x10;
    uintptr_t rcx_0x10_var = 0;
    int rc = -1;
    do {
        if ((rc = ptrace_pid_readlong(pid, rcx_0x10_ptr, &rcx_0x10_var)) < 0) {
            break;
        }

        if (rcx_0x10_var == rsp) {
            PTRACE_REG_ZF_SET(*oregs);
        } else {
            PTRACE_REG_ZF_UNSET(*oregs);
        }

        if (rcx_0x10_var > rsp) {
            PTRACE_REG_CF_SET(*oregs);
        } else {
            PTRACE_REG_CF_UNSET(*oregs);
        }

        if ((rc = ptrace_pid_setregs(pid, oregs)) < 0) {
            break;
        }

        rc = 0;

    } while (0);

    return rc;
}

/* 49 3b 66 10 cmp    0x10(%r14),%rsp */
int gotrace_sim_cmp_r14_0x10_rsp(struct ptrace_pid * pp, struct user* oregs)
{
    pid_t pid = pp->pid;
    uintptr_t r14 = PTRACE_REG_R14(*oregs);
    uintptr_t rsp = PTRACE_REG_SP(*oregs);
    uintptr_t r14_0x10_ptr = r14 + 0x10;
    uintptr_t r14_0x10_var = 0;
    int rc = -1;
    do {
        if ((rc = ptrace_pid_readlong(pid, r14_0x10_ptr, &r14_0x10_var)) < 0) {
            break;
        }

        if (r14_0x10_var == rsp) {
            PTRACE_REG_ZF_SET(*oregs);
        } else {
            PTRACE_REG_ZF_UNSET(*oregs);
        }

        if (r14_0x10_var > rsp) {
            PTRACE_REG_CF_SET(*oregs);
        } else {
            PTRACE_REG_CF_UNSET(*oregs);
        }

        if ((rc = ptrace_pid_setregs(pid, oregs)) < 0) {
            break;
        }

        rc = 0;

    } while (0);

    return rc;
}


/* <+0>: 0x55 push %rbp */
int gotrace_sim_push_rbp(struct ptrace_pid * pp, struct user* oregs)
{
    pid_t pid = pp->pid;
    uintptr_t rspptr   = PTRACE_REG_SP(*oregs) - 8;
    uintptr_t rbpvalue = PTRACE_REG_BP(*oregs);
    int rc = -1;
    do {
        if ((rc = ptrace_pid_writelong(pid, rspptr, rbpvalue)) < 0) {
            break;
        }

        PTRACE_REG_SP(*oregs) = rspptr;

        if ((rc = ptrace_pid_setregs(pid, oregs)) < 0) {
            break;
        }

        rc = 0;

    } while (0);

    return rc;
}

int gotrace_on_breakpoint(struct ptrace_pid * pp, struct user* oregs, struct symbol_elf_sym* sym)
{
    int rc = -1;
    if (sym->gopreidx == GOTRACE_GO_116) {
        gotrace_oncallin_116(pp, oregs, sym);
        rc = gotrace_sim_cmp_rcx_0x10_rsp(pp, oregs);
    } else if (sym->gopreidx == GOTRACE_GO_117) {
        gotrace_oncallin_117(pp, oregs, sym);
        rc = gotrace_sim_cmp_r14_0x10_rsp(pp, oregs);
    } else if (sym->gopreidx == GOTRACE_GO_CPP) {
        gotrace_oncallin_cpp(pp, oregs, sym);
        rc = gotrace_sim_push_rbp(pp, oregs);
    }
    return rc;
}


int gotrace_wait_breakpoint(struct ptrace_pid * pp, int force)
{
    int rc = -1;
    int idx = 0;
    struct user oregs;
    uintptr_t keyaddr = 0;
    uintptr_t keyaddrtmp = 0;
    struct symbol_elf_sym* sym = NULL;
    pid_t pid = pp->pid;
    pid_t newpid = 0;
    pid_t childpid = 0;

    do {
        rc = -1;

        if (force == 0 && g_stop >= 1) {
            rc = 0;
            break;
        }

        if ((rc = ptrace_pid_cont(pid)) < 0) {
            break;
        }

        do {
            newpid = 0;
            if ((rc = ptrace_pid_wait_thread(pp->hp->pid, &childpid, &newpid)) < 0) {
                rc = -1;
                LOG(LOG_ERR, "Wait breakpoint error!");
                break;
            }

            pp->pid = childpid;
            pid = pp->pid;

            if (rc == 1 && newpid != 0) {
                LOG(LOG_INFO, "The New thread %d created.", newpid);
                ptrace_pid_set_watchthread(newpid);
                ptrace_pid_cont(newpid);
                /* start a new thread here ??*/
                ptrace_pid_cont(pid);
                rc = 0;
                break;
            }

            if ((rc = ptrace_pid_getregs(pid, &oregs)) < 0) {
                LOG(LOG_ERR, "Read regs error!");
                break;
            }
            keyaddr = PTRACE_REG_IP(oregs);
            if (keyaddr != 0) {
                sym = NULL;
                for (idx = 0; idx < GOTRACE_GO_PRE_CNT; idx++) {
                    keyaddrtmp = keyaddr - gotrace_go_pre[idx].bpoff;
                    sym = gotrace_getsymbyaddr(keyaddrtmp);
                    if (sym != NULL) {
                        break;
                    }
                }
                if (sym != NULL && (rc = gotrace_on_breakpoint(pp, &oregs, sym)) < 0) {
                    break;
                }
            }
            rc = 0;
        } while(0);

        if (rc < 0) {
            break;
        }

    } while(1);

    return rc;
}

int gotrace_attach_all(int pid)
{
    DIR *d = NULL;
    struct dirent *dp = NULL;
    struct stat st;
    char path[GOTRACE_MAX_PATH_LEN] = {0};
    int childpid = 0;

    snprintf(path, sizeof(path) - 1, "/proc/%d/task", pid);

    if(stat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
        return -1;
    }

    if(!(d = opendir(path))) {
        return -1;
    }

    while((dp = readdir(d)) != NULL) {
        if((!strncmp(dp->d_name, ".", 1)) || (!strncmp(dp->d_name, "..", 2))) {
            continue;
        }
        childpid = atoi(dp->d_name);
        if (childpid == 0) {
            return -1;
        }
        if (childpid == pid) {
            continue;
        }
        if (ptrace_pid_attach(childpid) < 0) {
            return -1;
        }
        if (ptrace_pid_wait_attach(pid, childpid) < 0) {
            return -1;
        }
        if (ptrace_pid_set_watchthread(childpid) < 0) {
            return -1;
        }
    }
    closedir(d);

    return 0;
}


int gotrace_dettach_all(int pid)
{
    DIR *d = NULL;
    struct dirent *dp = NULL;
    struct stat st;
    char path[GOTRACE_MAX_PATH_LEN] = {0};
    int childpid = 0;

    snprintf(path, sizeof(path) - 1, "/proc/%d/task", pid);

    if(stat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
        return -1;
    }

    if(!(d = opendir(path))) {
        return -1;
    }

    while((dp = readdir(d)) != NULL) {
        if((!strncmp(dp->d_name, ".", 1)) || (!strncmp(dp->d_name, "..", 2))) {
            continue;
        }
        childpid = atoi(dp->d_name);
        if (childpid == 0) {
            return -1;
        }
        if (ptrace_pid_detach(childpid) < 0) {
            continue;
        }
    }
    closedir(d);

    return 0;
}

int gotrace_start_all(int pid)
{
    DIR *d = NULL;
    struct dirent *dp = NULL;
    struct stat st;
    char path[GOTRACE_MAX_PATH_LEN] = {0};
    int childpid = 0;

    snprintf(path, sizeof(path) - 1, "/proc/%d/task", pid);

    if(stat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
        return -1;
    }

    if(!(d = opendir(path))) {
        return -1;
    }

    while((dp = readdir(d)) != NULL) {
        if((!strncmp(dp->d_name, ".", 1)) || (!strncmp(dp->d_name, "..", 2))) {
            continue;
        }
        childpid = atoi(dp->d_name);
        if (childpid == 0) {
            return -1;
        }
        if (pid == childpid) {
            continue;
        }
        if ((ptrace_pid_cont(childpid)) < 0) {
            continue;
        }
    }
    closedir(d);

    return 0;
}

void gotrace_sighander(int sign)
{
    g_stop++;
    if (g_stop == 1) {
        printf("Please press CTL+C again ...!\n");
    }
    if (g_stop == 2) {
        printf("Please press CTL+C again ...!\n");
        signal(SIGINT,SIG_DFL);
    }
    if (g_stop >= 3) {
        printf("END!\n");
        exit(-1);
    }
}


void gotrace_oncallin_116(struct ptrace_pid * pp, struct user* oregs, struct symbol_elf_sym* sym)
{
    pid_t pid = pp->pid;
    uintptr_t rsp = PTRACE_REG_SP(*oregs);
    uintptr_t gptr = PTRACE_REG_CX(*oregs);
    uintptr_t args[GOTRACE_GO_SHOW_ARG_NUM] = {0};
    uintptr_t goidptr = gptr + 8 * 19;
    uintptr_t goid;
    int i = 0;
    if (ptrace_pid_readlong(pid, goidptr, &goid) < 0) {
        goid = -1;
    }
    printf("mid[%08ld] goid[%06ld]: [%p] %s <-( ", (uintptr_t)pid, goid, (void *)sym->address, sym->name);
    ptrace_pid_readarray(pid, rsp + 8, (unsigned char *)args, sizeof(uintptr_t) * GOTRACE_GO_SHOW_ARG_NUM);
    for (i = 0; i < GOTRACE_GO_SHOW_ARG_NUM; i++) {
        printf("0x%lx, ", args[i]);
    }
    printf("... )\n");

    return;
}

void gotrace_oncallin_117(struct ptrace_pid * pp, struct user* oregs, struct symbol_elf_sym* sym)
{
    pid_t pid = pp->pid;
    uintptr_t gptr = PTRACE_REG_R14(*oregs);
    uintptr_t goidptr = gptr + 8 * 19;
    uintptr_t goid;
    if (ptrace_pid_readlong(pid, goidptr, &goid) < 0) {
        goid = -1;
    }

    printf("mid[%08ld] goid[%06ld]: [%p] %s <-( ", (uintptr_t)pid, goid, (void *)sym->address, sym->name);
    printf("0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, ",
           PTRACE_REG_AX(*oregs), PTRACE_REG_BX(*oregs), PTRACE_REG_CX(*oregs), PTRACE_REG_DI(*oregs), PTRACE_REG_SI(*oregs),
           PTRACE_REG_R8(*oregs), PTRACE_REG_R9(*oregs), PTRACE_REG_R10(*oregs), PTRACE_REG_R11(*oregs));
    printf("... )\n");

    return;
}

void gotrace_oncallin_cpp(struct ptrace_pid * pp, struct user* oregs, struct symbol_elf_sym* sym)
{
    int i = 0;
    pid_t pid = pp->pid;
    uintptr_t rsp = PTRACE_REG_SP(*oregs);
    uintptr_t args[GOTRACE_C_SHOW_ARG_NUM] = {0};
    ptrace_pid_readarray(pid, rsp + 8, (unsigned char *)args, sizeof(uintptr_t) * GOTRACE_C_SHOW_ARG_NUM);
    printf("tid[%08ld]: [%p] %s <-( ", (uintptr_t)pid, (void *)sym->address, (sym->cppname == NULL)?sym->name:sym->cppname);
    printf("0x%llx, 0x%llx, 0x%llx, 0x%llx, ",
           PTRACE_REG_CX(*oregs), PTRACE_REG_DX(*oregs), PTRACE_REG_R8(*oregs), PTRACE_REG_R9(*oregs));
    for (i = 0; i < GOTRACE_C_SHOW_ARG_NUM; i++) {
        printf("0x%lx, ", args[i]);
    }
    printf("... )\n");
    return;
}


int gotrace_filter(struct symbol_elf_sym* sym)
{
    if (strcmp("runtime.text", sym->name) == 0) {
        return -1;
    }
    return 0;
}

void usage_exit(char * binname)
{
    printf("gotrace "
           "Usage: \n"
           "        %s  -p <PID> \n" , binname);
    printf("          -p <PID>     the process pid\n");
    printf("or:\n"
           "        %s  <filename> \n" , binname);
    exit(-1);
}

int main(int argc, char *argv[])
{
    int rc = -1;
    int ch = 0;
    int pid = 0;
    int bpsum = 0;
    struct ptrace_pid * pp = NULL;
    g_ucurLogLevel = LOG_IMPORTENT; // 0

    signal(SIGINT, gotrace_sighander);

    g_enableCppfilt = 1;
    opterr = 0;
    while( (ch = getopt(argc, argv, "p:v:c")) != -1 ) {
          switch(ch) {
              case 'p':
                    pid = atoi(optarg); //pid 
                    break;
              case 'c':
                  g_enableCppfilt = 0;
                  break;
              case 'v':
                  g_ucurLogLevel = atoi(optarg); //loglevel
                  break;
          }
    }

    if(pid != 0) {
        pp = (struct ptrace_pid *)ptrace_pp_create_nolibc(pid, ELF_E_LANG_GO);
        if (ptrace_pid_attach(pid) < 0) {
            exit(-1);
        }
        if (ptrace_pid_wait_attach(pid, pid) < 0) {
            exit(-1);
        }
        if (ptrace_pid_set_watchthread(pid) < 0) {
            exit(-1);
        }
        gotrace_attach_all(pid);
    } else {
        if (argc <= 1) {
            printf("PARAM ERROR: too few arguments!\n");
            usage_exit(argv[0]);
        }
        pid_t pid = fork();
        switch (pid) {
            case -1: /* error */
                printf("%s", strerror(errno));
                exit(-1);
            case 0:  // child
                if (ptrace_traceme() == -1) {
                    exit(-1);
                }
                execvp(argv[optind], argv + optind);
                printf("%s", strerror(errno));
                exit(-1);
        }
        if (ptrace_pid_wait(pid) < 0) {
            exit(-1);
        }
        if (ptrace_pid_set_watchthread(pid) < 0) {
            exit(-1);
        }
        pp = (struct ptrace_pid *)ptrace_pp_create_nolibc(pid, ELF_E_LANG_GO);
    }

    bpsum = gotrace_set_breakpoint_all(pp);
    if (bpsum <= 0) {
        printf("No breakpoint set!\n");
        exit(-1);
    }

    if(pid != 0) {
        gotrace_start_all(pid);
    }

    rc = gotrace_wait_breakpoint(pp, 0);
    gotrace_unset_breakpoint_all(pp);

    if(pid != 0) {
        rc = gotrace_wait_breakpoint(pp, 1);
        gotrace_unset_breakpoint_all(pp);
        gotrace_dettach_all(pp->hp->pid);
    }

    if( rc < 0 ) {
        printf("-END!\n");
        exit(-1);
    }

    printf("END!\n");
    return 0;
}


