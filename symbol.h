//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#ifndef __HPATCH_SYMBOL_H__
#define __HPATCH_SYMBOL_H__

#include "define.h"

#define MAX_BUFFER 512

#if __WORDSIZE == 64
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym  Elf_Sym;
typedef Elf64_Rela Elf_Rela;
#define ELF_R_SYM  ELF64_R_SYM
#define ELF_R_SYM  ELF64_R_SYM
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_ST_BIND ELF64_ST_BIND
#define ELF_ST_TYPE ELF64_ST_TYPE
typedef Elf64_Addr Elf_Addr;
#else
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Sym  Elf_Sym;
typedef Elf32_Rela Elf_Rela;
#define ELF_R_SYM  ELF32_R_SYM
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_ST_BIND ELF32_ST_BIND
#define ELF_ST_TYPE ELF32_ST_TYPE
typedef Elf32_Addr Elf_Addr;
#endif

//#define ELF32_R_SYM(x) ((x) >> 8)
//#define ELF32_R_TYPE(x) ((x) & 0xff)

enum
{
    SYMBOL_IS_UNKNOWN,
    SYMBOL_IS_FUNCTION,
    SYMBOL_IS_FILENAME,
    SYMBOL_IS_SECTION,
    SYMBOL_IS_OBJECT
};

enum symbol_elf_bit
{
    ELF_IS_NEITHER,
    ELF_IS_32BIT,
    ELF_IS_64BIT
};


/* segment type
enum ELF_RELA_SEG_TYPE
{
    ELF_RELA_SEG_TEXT   = 0X1, // relocation applies to .text segment
    ELF_RELA_SEG_DATA   = 0X2, // relocation applies to .data segment
    ELF_RELA_SEG_BSS    = 0X3, // relocation applies to .bss segment
    ELF_RELA_SEG_DLL    = 0X4, // relocation applies to DLL
    ELF_RELA_SEG_ABS    = 0X5, // 32 bits long jump
    ELF_RELA_SEG_BUT    = 0xff
};
*/

enum symbol_elf_sec_type
{
    ELF_SECT_UNSUPPORT  = 0x0,
    ELF_SECT_TEXT       = 0X1,
    ELF_SECT_RODATA     = 0X2,
    ELF_SECT_DATA       = 0X3,
    ELF_SECT_BSS        = 0X4,
    ELF_SECT_GOT        = 0X5,
    ELF_SECT_GOT_PLT    = 0X6,
    ELF_SECT_END
};


////
//// uintptr_t ==  UINT64
//// off_t     ==  INT32  typedef long _off_t;
//// size_t    ==  UINT32 typedef unsigned int size_t;

struct symbol_elf_sym
{
    char* name; /* null terminated symbol name */
    char* cppname;
    uintptr_t address; /* address at which it is available */
    int type; /* type of symbol */
    size_t size; /* size of the symbol if available */
    Elf_Sym sym;
    int gopreidx;
    int setbp;
};

struct symbol_elf_interp
{
    char* name;
    size_t length;
    uintptr_t ph_addr;
};

struct symbol_elf_internals
{
    int fd;
    enum symbol_elf_bit is64;
    size_t type; /* ET_REL ? */
    size_t machine; /* EM_386 EM_X86_64 EM_MIPS ? */
    off_t proghdr_offset;
    void* proghdrs; /* program headers */
    size_t proghdr_num;
    size_t proghdr_size; /* total buffer size */
    off_t sechdr_offset; /* Object file must have section-header-table, EXE file has. */
    void* sechdrs; /* section headers, sechdrs[0..sechdr_num] */
    size_t sechdr_num;
    size_t sechdr_size; /* total buffer size, sechdr_num*sizeof(*sechdrs[0]) */
    size_t secnametbl_idx; /* Object file must have section-name-strings-table-sechr, strsectblhdr = &sechdrs[ei->secnametbl_idx]; strsectbl = malloc(strsectblhdr->sh_size) */
    char* strsectbl; /* string table for section names, strsectbl[sechdrs[0].sh_name] */
    size_t strsectbl_size;
    /*
     * Only valid for ET_REL type.
     */
    size_t*  sechdrs_types;
    size_t sechdr_idx_text;   /* .text   */
    size_t sechdr_idx_data;   /* .data   */
    size_t sechdr_idx_rodata; /* .rodata */
    size_t sechdr_idx_bss;    /* .bss    */
    size_t sechdr_idx_got;    /* .got    */
    size_t sechdr_idx_got_plt;/* .got.plt */

    /*
     * stored here temporarily, should not be freed unless on failure.
     */
    uintptr_t entry_point;
    uintptr_t base_adjust;
    struct symbol_elf_sym* symbols;
    size_t symbols_num;
    struct symbol_elf_interp interp;
};

enum
{
    PROCMAPS_PERMS_NONE		= 0x0,
    PROCMAPS_PERMS_READ		= 0x1,
    PROCMAPS_PERMS_EXEC		= 0x2,
    PROCMAPS_PERMS_WRITE	= 0x4,
    PROCMAPS_PERMS_PRIVATE  = 0x8,
    PROCMAPS_PERMS_SHARED   = 0x10
};

enum
{
    PROCMAPS_FILETYPE_UNKNOWN,
    PROCMAPS_FILETYPE_EXE,
    PROCMAPS_FILETYPE_LIB,
    PROCMAPS_FILETYPE_DATA,
    PROCMAPS_FILETYPE_VDSO,
    PROCMAPS_FILETYPE_HEAP,
    PROCMAPS_FILETYPE_STACK,
    PROCMAPS_FILETYPE_SYSCALL,
    PROCMAPS_FILETYPE_VVAR
};

struct symbol_ld_library
{
    int isfound;
    char* pathname;
    size_t length;
    ino_t inode;
    uintptr_t addr_begin;
    uintptr_t addr_end;
};

struct symbol_ld_procmaps
{
    uintptr_t addr_begin;
    uintptr_t addr_end;
    int addr_valid;
    int permissions;
    off_t offset;
    int device_major;
    int device_minor;
    ino_t inode;
    char* pathname;
    size_t pathname_sz;
    int filetype;
};

enum
{
    ELF_LIB_LD = 0,
    ELF_LIB_C,
    ELF_LIB_DL,
    ELF_LIB_PTHREAD,
    ELF_LIB_MAX
};

enum symbol_elf_elang
{
    ELF_E_LANG_C = 0,
    ELF_E_LANG_GO,
    ELF_E_LANG_MAX
};

#define LIB_LD "ld"
#define LIB_C "libc"
#define LIB_DL "libdl"
#define LIB_PTHREAD "libpthread"

struct symbol_elf_pid
{
    pid_t pid;
    enum symbol_elf_bit is64;
    enum symbol_elf_elang elang;
    struct symbol_elf_sym* exe_symbols;
    size_t exe_symbols_num;
    uintptr_t exe_entry_point;
    uintptr_t exe_base_adjust;
    struct symbol_elf_interp exe_interp; /* dynamic loader from .interp in the exe */

    struct symbol_ld_procmaps* ld_maps;
    size_t ld_maps_num;
    struct symbol_ld_library libs[ELF_LIB_MAX];
    /* addresses useful */
    uintptr_t fn_malloc;
    uintptr_t fn_realloc;
    uintptr_t fn_free;
    uintptr_t fn_dlopen;
    uintptr_t fn_dlclose;
    uintptr_t fn_dlsym;
    uintptr_t fn_pthread_create;
    uintptr_t fn_pthread_detach;
};

extern struct symbol_elf_pid* symbol_pid_create(pid_t pid, int symelang);
extern struct symbol_elf_pid* symbol_pid_create_nolibc(pid_t pid, int symelang);
extern struct symbol_elf_pid* symbol_pid_create_inner(pid_t pid, int symelang, int needlibc);
extern void symbol_pid_destroy(struct symbol_elf_pid* hp);
extern uintptr_t symbol_pid_find_func(struct symbol_elf_pid* hp, const char* symbol, size_t* sz);
extern uintptr_t symbol_pid_find_global(struct symbol_elf_pid* hp, const char* symbol, size_t* sz);
extern uintptr_t symbol_ld_find_func(struct symbol_elf_pid* hp, const char* symbol, size_t* sz);
extern uintptr_t symbol_ld_find_global(struct symbol_elf_pid* hp, const char* symbol, size_t* sz);
extern uintptr_t symbol_pid_find_entry_point(struct symbol_elf_pid* hp);
extern int symbol_open_filename(const char* filename);
extern int symbol_elf_ei_create_hdrs_symtabs(struct symbol_elf_internals* ei);
extern void symbol_elf_ei_destory(struct symbol_elf_internals* ei, int needfreesymbol);
extern void* symbol_elf_load_section_tables(struct symbol_elf_internals* ei, Elf_Shdr* sechdr, size_t* outnum);
extern void* symbol_elf_load_section_strings(struct symbol_elf_internals* ei, Elf_Shdr* strh, size_t* outtotalsize);
uintptr_t symbol_ld_find_func_repable(struct symbol_elf_pid* hp, const char* symbol, size_t* sz);
uintptr_t symbol_ld_find_global_repable(struct symbol_elf_pid* hp, const char* symbol, size_t* sz);

#endif /* __HPATCH_SYMBOL_H__ */

