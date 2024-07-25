//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
#include "symbol.h"

/* each of the exe_* functions have to be reentrant and thread-safe */
static int symbol_convert_type(int info) {
  int value = ELF_ST_TYPE(info);
  if (value == STT_FUNC) {
    return SYMBOL_IS_FUNCTION;
  } else if (value == STT_FILE) {
    return SYMBOL_IS_FILENAME;
  } else if (value == STT_SECTION) {
    return SYMBOL_IS_SECTION;
  } else if (value == STT_OBJECT) {
    return SYMBOL_IS_OBJECT;
  } else {
    return SYMBOL_IS_UNKNOWN;
  }
}

static long symbol_get_file_size(const char* filename) {
  long filesize = 0;
  struct stat statbuff;
  if (stat(filename, &statbuff) < 0) {
    return filesize;
  } else {
    filesize = statbuff.st_size;
  }
  return filesize;
}

int symbol_open_filename(const char* filename) {
  int fd = -1;
  fd = open(filename, O_RDONLY);
  if (fd < 0) {
    LOG(LOG_ERR, "open file(%s) : %s", filename, strerror(errno));
  }
  return fd;
}

static int symbol_elf_symbol_cmpqsort(const void* p1, const void* p2) {
  return strcmp(((const struct symbol_elf_sym*)p1)->name,
                ((const struct symbol_elf_sym*)p2)->name);
}

static int symbol_elf_identify(unsigned char* e_ident, size_t size) {
  if (e_ident && size > 0) {
    if ((e_ident[EI_MAG0] == ELFMAG0) && (e_ident[EI_MAG1] == ELFMAG1) &&
        (e_ident[EI_MAG2] == ELFMAG2) && (e_ident[EI_MAG3] == ELFMAG3)) {
      int is64 = ELF_IS_NEITHER;
      /* magic number says this is an ELF file */
      switch (e_ident[EI_CLASS]) {
        case ELFCLASS32:
          is64 = ELF_IS_32BIT;
          /* LOG(LOG_DEBUG, "File is 32-bit ELF."); */
          break;
        case ELFCLASS64:
          is64 = ELF_IS_64BIT;
          /* LOG(LOG_DEBUG, "File is 64-bit ELF."); */
          break;
        case ELFCLASSNONE:
        default:
          is64 = ELF_IS_NEITHER;
          /* LOG(LOG_DEBUG, "File is not ELF."); */
          break;
      }
      if (is64 != ELF_IS_NEITHER) {
        int isbigendian = -1;
        int iscurrent = 0;
        int islinux = 0;
        switch (e_ident[EI_DATA]) {
          case ELFDATA2LSB:
            isbigendian = 0;
            /* LOG(LOG_DEBUG, "File is Little endian format."); */
            break;
          case ELFDATA2MSB:
            isbigendian = 1;
            /* LOG(LOG_DEBUG, "File is Big endian format."); */
            break;
          case ELFDATANONE:
          default:
            isbigendian = -1;
            /* LOG(LOG_DEBUG, "File is Unknown endian format."); */
            break;
        }
        if (e_ident[EI_VERSION] == EV_CURRENT) {
          iscurrent = 1;
          /* LOG(LOG_DEBUG, "File is Current ELF format."); */
        }
        /* LOG(LOG_DEBUG, "File ELFOSABI: %d.", e_ident[EI_OSABI]); */
        if (e_ident[EI_OSABI] == ELFOSABI_LINUX ||
            e_ident[EI_OSABI] == ELFOSABI_SYSV) {
          islinux = 1;
          /* LOG(LOG_DEBUG, "File OS ABI is Linux."); */
        }
        if (islinux && isbigendian == 0 && iscurrent) {
          return is64;
        }
        LOG(LOG_ERR, "Not an acceptable header.");
      }
    } else {
      LOG(LOG_ERR, "This is not an ELF file format.");
    }
  }
  return ELF_IS_NEITHER;
}

void* symbol_elf_load_section_strings(struct symbol_elf_internals* ei,
                                      Elf_Shdr* strh, size_t* outtotalsize) {
  char* strsymtbl = NULL;
  size_t strsymtbl_size = 0;

  if (!ei || !strh || !outtotalsize) {
    return NULL;
  }
  if (strh->sh_size <= 0) {
    LOG(LOG_ERR, "Read strings section error totalsize<%d>", strh->sh_size);
    return NULL;
  }
  strsymtbl_size = strh->sh_size + 0;
  strsymtbl = malloc(strh->sh_size);
  if (!strsymtbl) {
    LOG(LOG_ERR, "malloc error: size %d, %s", strh->sh_size, strerror(errno));
    return NULL;
  }
  if (lseek(ei->fd, strh->sh_offset, SEEK_SET) < 0) {
    LOG(LOG_ERR, "lseek error: fd %d, %s", ei->fd, strerror(errno));
    free(strsymtbl);
    strsymtbl = NULL;
    return NULL;
  }
  if (read(ei->fd, strsymtbl, strh->sh_size) < 0) {
    LOG(LOG_ERR, "read error: fd %d, %s", ei->fd, strerror(errno));
    free(strsymtbl);
    strsymtbl = NULL;
    return NULL;
  }
  *outtotalsize = strsymtbl_size;
  return strsymtbl;
}

void* symbol_elf_load_section_tables(struct symbol_elf_internals* ei,
                                     Elf_Shdr* sechdr, size_t* outnum) {
  void* r_tabs = NULL;
  int rc = 0;

  if (!ei || !sechdr || !outnum) {
    return NULL;
  }
  if (sechdr->sh_entsize <= 0 || sechdr->sh_size <= 0) {
    LOG(LOG_ERR, "Read section tables error entsize<%d> totalsize<%d>",
        sechdr->sh_entsize, sechdr->sh_size);
    return NULL;
  }
  do {
    size_t sym_num = sechdr->sh_size / sechdr->sh_entsize;
    r_tabs = malloc(sechdr->sh_size);
    if (!r_tabs) {
      LOG(LOG_ERR, "malloc error: size %d, %s", sechdr->sh_size,
          strerror(errno));
      rc = -1;
      break;
    }
    if (lseek(ei->fd, sechdr->sh_offset, SEEK_SET) < 0) {
      LOG(LOG_ERR, "lseek error: fd %d, %s", ei->fd, strerror(errno));
      free(r_tabs);
      r_tabs = NULL;
      rc = -1;
      break;
    }
    if (read(ei->fd, r_tabs, sechdr->sh_size) < 0) {
      LOG(LOG_ERR, "read error: fd %d, %s", ei->fd, strerror(errno));
      free(r_tabs);
      r_tabs = NULL;
      rc = -1;
      break;
    }
    *outnum = sym_num;
  } while (0);
  if (rc < 0 || !r_tabs) {
    return NULL;
  }
  return r_tabs;
}

static int symbol_elf_load_sym_table(struct symbol_elf_internals* ei,
                                     Elf_Shdr* symh, Elf_Shdr* strh) {
  char* strsymtbl = NULL;
  while (ei && symh && strh) {
    /* LOG(LOG_DEBUG, "Retrieving symbol table."); */
    if (lseek(ei->fd, strh->sh_offset, SEEK_SET) < 0) {
      LOG(LOG_ERR, "lseek error: fd %d, %s", ei->fd, strerror(errno));
      break;
    }
    strsymtbl = malloc(strh->sh_size);
    if (!strsymtbl) {
      LOG(LOG_ERR, "malloc error: size %d, %s", strh->sh_size, strerror(errno));
      break;
    }
    if (read(ei->fd, strsymtbl, strh->sh_size) < 0) {
      LOG(LOG_ERR, "read error: fd %d, %s", ei->fd, strerror(errno));
      free(strsymtbl);
      strsymtbl = NULL;
      break;
    }
    if (symh->sh_entsize > 0 && symh->sh_size > 0) {
      size_t idx;
      size_t sym_num = symh->sh_size / symh->sh_entsize;
      Elf_Sym* syms = malloc(symh->sh_size);
      if (!syms) {
        LOG(LOG_ERR, "malloc error: size %d, %s", symh->sh_size,
            strerror(errno));
        break;
      }
      if (lseek(ei->fd, symh->sh_offset, SEEK_SET) < 0) {
        LOG(LOG_ERR, "lseek error: fd %d, %s", ei->fd, strerror(errno));
        free(syms);
        break;
      }
      if (read(ei->fd, syms, symh->sh_size) < 0) {
        LOG(LOG_ERR, "read error: fd %d, %s", ei->fd, strerror(errno));
        free(syms);
        break;
      }
      /* there might already exist symbols from another section.
       * hence using realloc() takes care of that.
       * */
      ei->symbols = realloc(ei->symbols,
                            (sym_num + ei->symbols_num) * sizeof(*ei->symbols));
      if (!ei->symbols) {
        LOG(LOG_ERR, "malloc error: size %d, %s", strh->sh_size,
            strerror(errno));
        break;
      }
      memset(&ei->symbols[ei->symbols_num], 0, sizeof(*ei->symbols) * sym_num);

      /* LOG(LOG_DEBUG, "Symbol-sechdr size<%d>, entsize<%d>, offset<%d>",
       * symh->sh_size, symh->sh_entsize, symh->sh_offset); */
      /* index 0 is always NULL */
      for (idx = 1; idx < sym_num; ++idx) {
        if (syms[idx].st_shndx == SHN_UNDEF) {
          continue;
        }
        /*
        LOG(LOG_DEBUG, "Symbol-info idx<%d> info<%d>, nameidx<%d> symb<%p>",
        idx, syms[idx].st_info, syms[idx].st_name, &syms[idx]);
        */
        const char* name =
            syms[idx].st_name > 0 ? &strsymtbl[syms[idx].st_name] : "";
        if (name) {
          char* name2;
          int symtype = symbol_convert_type(syms[idx].st_info);
          /*
          LOG(LOG_DEBUG,"Symbol %u is %s at %p type %d size %u",
                        idx, name, (void *)syms[idx].st_value, symtype,
          syms[idx].st_size);
           */
          name2 = strdup(name);
          if (!name2) {
            LOG(LOG_ERR, "malloc error: size %d, %s", strh->sh_size,
                strerror(errno));
            continue;
          }
          ei->symbols[ei->symbols_num].name = name2;
          ei->symbols[ei->symbols_num].address = (uintptr_t)syms[idx].st_value;
          ei->symbols[ei->symbols_num].size = (size_t)syms[idx].st_size;
          ei->symbols[ei->symbols_num].type = symtype;
          ei->symbols[ei->symbols_num].sym = syms[idx];
          ei->symbols_num++;
        }
      }
      free(syms);
      if (strsymtbl) {
        free(strsymtbl);
      }
      return 0;
    }
  }
  if (strsymtbl) {
    free(strsymtbl);
  }
  return -1;
}

static int symbol_elf_load_section_headers_and_symtabs(
    struct symbol_elf_internals* ei) {
  Elf_Shdr* strsectblhdr = NULL;
  Elf_Shdr* sechdrs = NULL;
  size_t idx = 0;
  ssize_t symtab = -1;
  ssize_t strtab = -1;

  if (!ei || ei->sechdr_offset == 0 || ei->sechdr_size == 0) {
    LOG(LOG_ERR, "param error!");
    return -1;
  }
  /* LOG(LOG_DEBUG, "Retrieving section headers."); */

  ei->sechdrs = malloc(ei->sechdr_size);
  if (!ei->sechdrs) {
    LOG(LOG_ERR, "malloc error: size %d, %s", ei->sechdr_size, strerror(errno));
    return -1;
  }
  memset(ei->sechdrs, 0, ei->sechdr_size);
  /* LOG(LOG_DEBUG, "Reading section header offset at %u",
   * (size_t)ei->sechdr_offset); */

  if (lseek(ei->fd, ei->sechdr_offset, SEEK_SET) < 0) {
    LOG(LOG_ERR, "lseek error: fd %d, %s", ei->fd, strerror(errno));
    return -1;
  }
  if (read(ei->fd, ei->sechdrs, ei->sechdr_size) < 0) {
    LOG(LOG_ERR, "read error: fd %d, %s", ei->fd, strerror(errno));
    return -1;
  }
  sechdrs = (Elf_Shdr*)ei->sechdrs;
  strsectblhdr = &sechdrs[ei->secnametbl_idx];
  if (lseek(ei->fd, strsectblhdr->sh_offset, SEEK_SET) < 0) {
    LOG(LOG_ERR, "lseek error: fd %d, %s", ei->fd, strerror(errno));
    return -1;
  }
  ei->strsectbl = malloc(strsectblhdr->sh_size);
  if (!ei->strsectbl) {
    LOG(LOG_ERR, "malloc error: size %d, %s", ei->sechdr_size, strerror(errno));
    return -1;
  }
  ei->strsectbl_size = strsectblhdr->sh_size + 0;
  if (read(ei->fd, ei->strsectbl, strsectblhdr->sh_size) < 0) {
    LOG(LOG_ERR, "read error: fd %d, %s", ei->fd, strerror(errno));
    return -1;
  }
  ei->sechdrs_types = malloc(sizeof(size_t) * ei->sechdr_num);
  if (!ei->sechdrs_types) {
    LOG(LOG_ERR, "malloc error: size %d, %s", sizeof(size_t) * ei->sechdr_num,
        strerror(errno));
    return -1;
  }
  memset(ei->sechdrs_types, 0, sizeof(size_t) * ei->sechdr_num);
  /* LOG(LOG_DEBUG, "Number of sections: %u", ei->sechdr_num); */
  for (idx = 0; idx < ei->sechdr_num; ++idx) {
    const char* name = &ei->strsectbl[sechdrs[idx].sh_name];
    /*
    if (name)
    {
            LOG(LOG_DEBUG, "Section name: %s Addr: %p Len: %u Idx: %u", name,
    (void *)sechdrs[idx].sh_offset, sechdrs[idx].sh_size, idx);
    }
    else
    {
            LOG(LOG_DEBUG, "Section name: %s Addr: %p Len: %u Idx: %u", "N/A",
    (void *)sechdrs[idx].sh_offset, sechdrs[idx].sh_size, idx);
    }
    */
    ei->sechdrs_types[idx] = ELF_SECT_UNSUPPORT;
    switch (sechdrs[idx].sh_type) {
      case SHT_SYMTAB:
      case SHT_DYNSYM:
        symtab = idx;
        /*
        LOG(LOG_DEBUG, "Symbol table offset: %u size: %u entsize: %u entries:
        %u", sechdrs[idx].sh_offset, sechdrs[idx].sh_size,
        sechdrs[idx].sh_entsize, (sechdrs[idx].sh_entsize > 0 ?
        sechdrs[idx].sh_size / sechdrs[idx].sh_entsize : 0));
        */
        break;
      case SHT_STRTAB:
        if (idx != ei->secnametbl_idx) {
          strtab = idx;
          /* LOG(LOG_DEBUG, "Reading symbol table from %s", name); */
          if (symtab >= 0 && symbol_elf_load_sym_table(ei, &sechdrs[symtab],
                                                       &sechdrs[strtab]) < 0) {
            LOG(LOG_ERR, "Failed to retrieve symbol table.", name);
          }
          symtab = -1;
        }
        break;
      case SHT_NOBITS:
        /* if(ei->type == ET_REL) { */
        if (!ei->sechdr_idx_bss) {
          ei->sechdr_idx_bss = idx; /* .bss    */
        }
        ei->sechdrs_types[idx] = ELF_SECT_BSS;
        /* } */
        break;
      case SHT_NUM: /* == SHT_COMDAT == 12*/
      case SHT_PROGBITS:
        /* if(ei->type == ET_REL) { */
        if ((sechdrs[idx].sh_flags & SHF_ALLOC) &&
            (sechdrs[idx].sh_flags & SHF_EXECINSTR)) {
          if (!ei->sechdr_idx_text) {
            ei->sechdr_idx_text = idx; /* .text   */
          }
          ei->sechdrs_types[idx] = ELF_SECT_TEXT;
        } else if ((sechdrs[idx].sh_flags & SHF_ALLOC) &&
                   (sechdrs[idx].sh_flags & SHF_WRITE)) {
          if (!strcmp(".got.plt", name)) {
            ei->sechdr_idx_got_plt = idx;
            ei->sechdrs_types[idx] = ELF_SECT_GOT_PLT;
          } else if (!strcmp(".got", name)) {
            ei->sechdr_idx_got = idx;
            ei->sechdrs_types[idx] = ELF_SECT_GOT;
          } else {
            if (!ei->sechdr_idx_data) {
              ei->sechdr_idx_data = idx; /* .data   */
            }
            ei->sechdrs_types[idx] = ELF_SECT_DATA;
          }
        } else if ((sechdrs[idx].sh_flags & SHF_ALLOC)) {
          if (!ei->sechdr_idx_rodata) {
            ei->sechdr_idx_rodata = idx; /* .rodata */
          }
          ei->sechdrs_types[idx] = ELF_SECT_RODATA;
        }
        /* } */
        break;
      default:
        break;
    }
  }
  if (ei->type == ET_REL) {
    LOG(LOG_DEBUG,
        "Find linkable sections bss_idx(%u) text_idx(%u) data_idx(%u) "
        "rodata_idx(%u) ",
        ei->sechdr_idx_bss, ei->sechdr_idx_text, ei->sechdr_idx_data,
        ei->sechdr_idx_rodata);
  }
  return 0;
}

static int symbol_elf_load_program_headers(struct symbol_elf_internals* ei) {
  Elf_Phdr* proghdrs = NULL;
  size_t idx = 0;
  int rc = 0;
  int cnt_LOAD = 0;
  if (!ei || ei->proghdr_offset == 0 || ei->proghdr_size == 0) {
    return -1;
  }
  ei->proghdrs = malloc(ei->proghdr_size);
  if (!ei->proghdrs) {
    LOG(LOG_ERR, "malloc error: size %d, %s", ei->sechdr_size, strerror(errno));
    return -1;
  }
  memset(ei->proghdrs, 0, ei->proghdr_size);
  if (lseek(ei->fd, ei->proghdr_offset, SEEK_SET) < 0) {
    LOG(LOG_ERR, "lseek error: fd %d, %s", ei->fd, strerror(errno));
    return -1;
  }
  if (read(ei->fd, ei->proghdrs, ei->proghdr_size) < 0) {
    LOG(LOG_ERR, "read error: fd %d, %s", ei->fd, strerror(errno));
    return -1;
  }

  /* LOG(LOG_DEBUG, "Number of segments: %u", ei->proghdr_num); */

  proghdrs = (Elf_Phdr*)ei->proghdrs;
  for (idx = 0; idx < ei->proghdr_num; ++idx) {
    rc = 0;

    /*
    LOG(LOG_DEBUG,"Prog-header %u: Type: %d VAddr: %p PAddr: %p FileSz: %u
    MemSz: %u", idx, proghdrs[idx].p_type, (void *)proghdrs[idx].p_vaddr, (void
    *)proghdrs[idx].p_paddr, proghdrs[idx].p_filesz, proghdrs[idx].p_memsz);
    */
    if (proghdrs[idx].p_type == PT_INTERP) {
      /* LOG(LOG_DEBUG, "PT_INTERP section found"); */
      if (proghdrs[idx].p_filesz == 0) {
        continue;
      }
      if (lseek(ei->fd, proghdrs[idx].p_offset, SEEK_SET) < 0) {
        LOG(LOG_ERR, "lseek error: fd %d, %s", ei->fd, strerror(errno));
        rc = -1;
        break;
      }
      if (ei->interp.name) {
        free(ei->interp.name);
        memset(&ei->interp, 0, sizeof(ei->interp));
      }
      ei->interp.name = malloc(proghdrs[idx].p_filesz);
      if (!ei->interp.name) {
        LOG(LOG_ERR, "malloc error: size %d, %s", ei->sechdr_size,
            strerror(errno));
        rc = -1;
        break;
      }
      if (read(ei->fd, ei->interp.name, proghdrs[idx].p_filesz) < 0) {
        LOG(LOG_ERR, "read error: fd %d, %s", ei->fd, strerror(errno));
        rc = -1;
        break;
      }
      ei->interp.length = proghdrs[idx].p_filesz;
      ei->interp.ph_addr = proghdrs[idx].p_vaddr;
      /* LOG(LOG_DEBUG, "Found %s at V-Addr %p", ei->interp.name,
       * ei->interp.ph_addr); */
    } else if (proghdrs[idx].p_type == PT_DYNAMIC) {
      /* LOG(LOG_DEBUG, "PT_DYNAMIC section found"); */
    } else if (proghdrs[idx].p_type == PT_LOAD) {
      /* LOG(LOG_DEBUG, "PT_LOAD section found"); */
      if (cnt_LOAD == 0) {
        if (ei->type == ET_EXEC) {
          ei->base_adjust = 0;
        } else if (ei->type == ET_DYN) {
          ei->base_adjust = -1;
          if (proghdrs[idx].p_offset != 0 || proghdrs[idx].p_vaddr != 0) {
            LOG(LOG_ERR,
                "ELF file is not support: ET_DYN with none zero PT_LOAD[0]");
            rc = -1;
            break;
          }
        }
      }
      cnt_LOAD++;
    }
  }
  return rc;
}

void symbol_elf_ei_destory(struct symbol_elf_internals* ei,
                           int needfreesymbol) {
  if (!ei) {
    return;
  }
  if (ei->fd >= 0) {
    close(ei->fd);
  }
  ei->fd = -1;
  ei->strsectbl_size = 0;
  if (ei->sechdrs_types) {
    free(ei->sechdrs_types);
    ei->sechdrs_types = NULL;
  }
  if (ei->strsectbl) {
    free(ei->strsectbl);
    ei->strsectbl = NULL;
  }
  if (ei->sechdrs) {
    free(ei->sechdrs);
    ei->sechdrs = NULL;
  }
  if (ei->proghdrs) {
    free(ei->proghdrs);
    ei->proghdrs = NULL;
  }
  if (needfreesymbol) {
    /* LOG(LOG_DEBUG, "Free symbols..."); */
    if (ei->interp.name) {
      free(ei->interp.name);
    }
    ei->interp.name = NULL;
    if (ei->symbols) {
      size_t idx;
      for (idx = 0; idx < ei->symbols_num; ++idx) {
        free(ei->symbols[idx].name);
        ei->symbols[idx].name = NULL;
      }
      free(ei->symbols);
    }
    ei->symbols = NULL;
    ei->symbols_num = 0;
  } else {
    /* LOG(LOG_DEBUG, "No need free symbols."); */
  }
  return;
}

int symbol_elf_ei_create_hdrs_symtabs(struct symbol_elf_internals* ei) {
  Elf_Ehdr hdr;
  int fd = -1;
  if (!ei) {
    return -1;
  }
  fd = ei->fd;
  memset(&hdr, 0, sizeof(hdr));
  if (lseek(fd, 0, SEEK_SET) < 0) {
    LOG(LOG_ERR, "lseek error: fd %d, %s", fd, strerror(errno));
    return -1;
  }
  if (read(fd, &hdr, sizeof(hdr)) < 0) {
    LOG(LOG_ERR, "read error: fd %d, %s", fd, strerror(errno));
    return -1;
  }

  /* LOG(LOG_DEBUG, "Reading Elf header."); */

  ei->is64 = symbol_elf_identify(hdr.e_ident, EI_NIDENT);
  switch (ei->is64) {
    case ELF_IS_64BIT:

#if __WORDSIZE != 64
      LOG(LOG_ERR, "64-bit valid exe, is not 32-bit.");
      return -1;
#endif

      break;
    case ELF_IS_32BIT:

#if __WORDSIZE == 64
      LOG(LOG_ERR, "32bit valid exe, is not 64-bit.");
      return -1;
#endif

      break;
    case ELF_IS_NEITHER:
    default:
      return -1;
  }

  /* LOG(LOG_DEBUG, "Object file type %d", hdr.e_type); */
  ei->type = hdr.e_type;

  /* LOG(LOG_DEBUG, "Entry point %p", (void *)hdr.e_entry); */
  ei->entry_point = (uintptr_t)hdr.e_entry;

  /* LOG(LOG_DEBUG, "Machine %d", hdr.e_machine); */
  ei->machine = hdr.e_machine;
  if (hdr.e_machine != EM_X86_64 && hdr.e_machine != EM_386) {
    LOG(LOG_ERR, "ERROR: unsupported processor!");
    return -1;
  }

  /*Object file has section-header-table.*/
  if (hdr.e_shoff > 0) {
    ei->sechdr_offset = 0 + hdr.e_shoff;
    ei->sechdr_num = 0 + hdr.e_shnum;
    ei->sechdr_size = 0 + hdr.e_shnum * hdr.e_shentsize;
    ei->secnametbl_idx = 0 + hdr.e_shstrndx;
  }
  /*Exe file has program-header-table.*/
  if (hdr.e_phoff > 0) {
    ei->proghdr_offset = 0 + hdr.e_phoff;
    ei->proghdr_num = 0 + hdr.e_phnum;
    ei->proghdr_size = 0 + hdr.e_phnum * hdr.e_phentsize;
  }
  if (hdr.e_shoff > 0) {
    /*Load section-header-table and symbol tables.*/
    if (symbol_elf_load_section_headers_and_symtabs(ei) < 0) {
      LOG(LOG_ERR, "ERROR in loading section headers");
      return -1;
    }
  }
  if (hdr.e_phoff > 0) {
    /*Load program-header-table.*/
    if (symbol_elf_load_program_headers(ei) < 0) {
      LOG(LOG_ERR, "ERROR in loading section headers");
      return -1;
    }
  }
  return 0;
}

static struct symbol_elf_sym* symbol_elf_load_file(
    const char* filename, size_t* symbols_num, uintptr_t* entry_point,
    uintptr_t* base_adjust, struct symbol_elf_interp* interp,
    enum symbol_elf_bit* is64) {
  int rc = 0;
  struct symbol_elf_sym* symbols = NULL;
  struct symbol_elf_internals ei;
  memset(&ei, 0, sizeof(ei));
  if (entry_point) {
    *entry_point = 0;
  }
  if (base_adjust) {
    *base_adjust = 0;
  }

  ei.fd = symbol_open_filename(filename);
  if (ei.fd < 0) {
    return NULL;
  }
  /* LOG(LOG_INFO, "Begin to load Elf details for %s", filename); */
  if ((rc = symbol_elf_ei_create_hdrs_symtabs(&ei)) < 0) {
    LOG(LOG_ERR, "Unable to load Elf details for %s", filename);
  }

  /* LOG(LOG_INFO, "Freeing internal structure for %s", filename); */
  if (rc < 0) {
    symbol_elf_ei_destory(&ei, TRUE);
  } else {
    /* LOG(LOG_DEBUG, "Readying return values."); */
    symbols = ei.symbols;
    if (symbols_num) {
      *symbols_num = ei.symbols_num;
    }
    if (interp) {
      interp->name = ei.interp.name;
      interp->length = ei.interp.length;
      interp->ph_addr = ei.interp.ph_addr;
    } else {
      if (ei.interp.name) {
        free(ei.interp.name);
      }
      ei.interp.name = NULL;
    }
    if (is64) {
      *is64 = ei.is64;
    }
    if (entry_point) {
      *entry_point = ei.entry_point;
    }
    if (base_adjust) {
      *base_adjust = ei.base_adjust;
    }
    symbol_elf_ei_destory(&ei, FALSE);
  }

  return symbols;
}

#if 0
static void symbol_ld_procmaps_dump(struct symbol_ld_procmaps* pm)
{
    if (!pm)
    { return; }
    LOG(LOG_DEBUG, "Pathname: %s", pm->pathname ? pm->pathname : "Unknown");
    LOG(LOG_DEBUG, "Address Start: %p End: %p Valid: %d Offset: %u", pm->addr_begin, pm->addr_end, pm->addr_valid, (size_t)pm->offset);
    LOG(LOG_DEBUG, "Device Major: %d Minor: %d", pm->device_major, pm->device_minor);
    LOG(LOG_DEBUG, "Inode: %u", (size_t)pm->inode);
    LOG(LOG_DEBUG, "Permissions: Read(%d) Write(%d) Execute(%d) Private(%d) Shared(%d)",
        (pm->permissions & PROCMAPS_PERMS_READ) ? 1 : 0,
        (pm->permissions & PROCMAPS_PERMS_WRITE) ? 1 : 0,
        (pm->permissions & PROCMAPS_PERMS_EXEC) ? 1 : 0,
        (pm->permissions & PROCMAPS_PERMS_PRIVATE) ? 1 : 0,
        (pm->permissions & PROCMAPS_PERMS_SHARED) ? 1 : 0
       );
    LOG(LOG_DEBUG, "Pathname length: %u", pm->pathname_sz);
    LOG(LOG_DEBUG, "Filetype: %d", pm->filetype);
}
#endif

static int symbol_ld_procmaps_parse(char* buf, size_t bufsz,
                                    struct symbol_ld_procmaps* pm,
                                    const char* appname) {
  if (!buf || !pm) {
    LOG(LOG_ERR, "Invalid arguments.");
    return -1;
  }
  /* this is hardcoded parsing of the maps file */
  do {
    char* token = NULL;
    char* save = NULL;
    int idx, err;
    memset(pm, 0, sizeof(*pm));
    token = strtok_r(buf, "-", &save);
    if (!token) {
      break;
    }
    errno = 0;
    pm->addr_begin = (uintptr_t)strtoul(token, NULL, 16);
    err = errno;
    pm->addr_valid = (err == ERANGE || err == EINVAL) ? FALSE : TRUE;
    if (!pm->addr_valid) {
      LOG(LOG_DEBUG, "Strtoul error(%s) in parsing %s", strerror(err), token);
    }
    token = strtok_r(NULL, " ", &save);
    if (!token) {
      break;
    }
    errno = 0;
    pm->addr_end = (intptr_t)strtoul(token, NULL, 16);
    err = errno;
    pm->addr_valid = (err == ERANGE || err == EINVAL) ? FALSE : TRUE;
    if (!pm->addr_valid) {
      LOG(LOG_DEBUG, "[%s:%d] Strtoul error(%s) in parsing %s", strerror(err),
          token);
    }
    token = strtok_r(NULL, " ", &save);
    if (!token) {
      break;
    }
    pm->permissions = PROCMAPS_PERMS_NONE;
    for (idx = strlen(token) - 1; idx >= 0; --idx) {
      switch (token[idx]) {
        case 'r':
          pm->permissions |= PROCMAPS_PERMS_READ;
          break;
        case 'w':
          pm->permissions |= PROCMAPS_PERMS_WRITE;
          break;
        case 'x':
          pm->permissions |= PROCMAPS_PERMS_EXEC;
          break;
        case 'p':
          pm->permissions |= PROCMAPS_PERMS_PRIVATE;
          break;
        case 's':
          pm->permissions |= PROCMAPS_PERMS_SHARED;
          break;
        case '-':
          break;
        default:
          LOG(LOG_DEBUG, "Unknown flag: %c", token[idx]);
          break;
      }
    }
    token = strtok_r(NULL, " ", &save);
    if (!token) {
      break;
    }
    errno = 0;
    pm->offset = (off_t)strtoul(token, NULL, 16);
    err = errno;
    if (err == ERANGE || err == EINVAL) {
      LOG(LOG_DEBUG, "Strtoul error(%s) in parsing %s", strerror(err), token);
    }
    token = strtok_r(NULL, ":", &save);
    if (!token) {
      break;
    }
    pm->device_major = (int)strtol(token, NULL, 10);
    token = strtok_r(NULL, " ", &save);
    if (!token) {
      break;
    }
    pm->device_minor = (int)strtol(token, NULL, 10);
    token = strtok_r(NULL, " ", &save);
    if (!token) {
      break;
    }
    pm->inode = (ino_t)strtoul(token, NULL, 10);
    token = strtok_r(NULL, "\n", &save);
    if (!token) {
      break;
    }
    pm->pathname_sz = strlen(token);
    pm->pathname = calloc(sizeof(char), pm->pathname_sz + 1);
    if (!pm->pathname) {
      LOG(LOG_ERR, "malloc error: size %d, %s", pm->pathname_sz + 1,
          strerror(errno));
      pm->pathname = NULL;
      pm->pathname_sz = 0;
      break;
    }
    /* trim the extra spaces out */
    save = token;
    /* find the real path names */
    if ((token = strchr(save, '/'))) {
      memcpy(pm->pathname, token, strlen(token));
      if (strstr(pm->pathname, ".so") || strstr(pm->pathname, ".so.")) {
        pm->filetype = PROCMAPS_FILETYPE_LIB;
      } else {
        struct stat statbuf;
        pm->filetype = PROCMAPS_FILETYPE_DATA;
        memset(&statbuf, 0, sizeof(statbuf));
        if (stat(pm->pathname, &statbuf) >= 0) {
          ino_t inode1 = statbuf.st_ino;
          memset(&statbuf, 0, sizeof(statbuf));
          if (stat(appname, &statbuf) >= 0) {
            if (statbuf.st_ino == inode1) {
              pm->filetype = PROCMAPS_FILETYPE_EXE;
            }
          }
        } else {
          int err = errno;
          LOG(LOG_DEBUG, "Unable to stat file %s. Error: %s", pm->pathname,
              strerror(err));
        }
      }
    } else if ((token = strchr(save, '['))) {
      memcpy(pm->pathname, token, strlen(token));
      if (strstr(pm->pathname, "[heap]")) {
        pm->filetype = PROCMAPS_FILETYPE_HEAP;
      } else if (strstr(pm->pathname, "[stack]")) {
        pm->filetype = PROCMAPS_FILETYPE_STACK;
      } else if (strstr(pm->pathname, "[vdso]")) {
        pm->filetype = PROCMAPS_FILETYPE_VDSO;
      } else if (strstr(pm->pathname, "[vsyscall]")) {
        pm->filetype = PROCMAPS_FILETYPE_SYSCALL;
      } else if (strstr(pm->pathname, "[vvar]")) {
        pm->filetype = PROCMAPS_FILETYPE_VVAR;
      } else {
        LOG(LOG_ERR, "Unknown memory map: %s", pm->pathname);
        pm->filetype = PROCMAPS_FILETYPE_UNKNOWN;
      }
    } else {
      memcpy(pm->pathname, token, strlen(token));
      pm->filetype = PROCMAPS_FILETYPE_UNKNOWN;
    }
  } while (0);
  return 0;
}

static struct symbol_ld_procmaps* symbol_ld_load_maps(pid_t pid, size_t* num,
                                                      uintptr_t* base_adjust) {
  char filename[MAX_BUFFER];
  char appname[MAX_BUFFER];
  FILE* ff = NULL;
  const size_t bufsz = 4096;
  char* buf = NULL;
  int need_adjust = 0;
  int cnt_LOAD = 0;

  size_t mapmax = 0;
  size_t mapnum = 0;
  struct symbol_ld_procmaps* maps = NULL;
  if (pid == 0) {
    LOG(LOG_ERR, "invalid pid %d.", pid);
    return NULL;
  }
  if (base_adjust && *base_adjust == -1) {
    need_adjust = 1;
  }

  snprintf(filename, MAX_BUFFER, "/proc/%d/maps", pid);
  snprintf(appname, MAX_BUFFER, "/proc/%d/exe", pid);
  LOG(LOG_DEBUG, "Using Proc Maps from %s", filename);
  LOG(LOG_DEBUG, "Using Proc Exe from %s", appname);

  do {
    buf = calloc(sizeof(char), bufsz);
    if (!buf) {
      LOG(LOG_ERR, "malloc error: size %d, %s", bufsz, strerror(errno));
      break;
    }
    ff = fopen(filename, "r");
    if (!ff) {
      LOG(LOG_ERR, "open file(%s) : %s", filename, strerror(errno));
      break;
    }
    while (fgets(buf, bufsz, ff)) {
      mapmax++;
    }

    LOG(LOG_DEBUG, "Max number of mappings present: %u", mapmax);
    fseek(ff, 0L, SEEK_SET);
    maps = calloc(sizeof(*maps), mapmax);
    if (!maps) {
      LOG(LOG_ERR, "malloc error: size %d, %s", mapmax * sizeof(*maps),
          strerror(errno));
      break;
    }

    LOG(LOG_DEBUG, "Allocated memory to load proc maps.");
    memset(buf, 0, bufsz);
    mapnum = 0;
    while (fgets(buf, bufsz, ff)) {
      struct symbol_ld_procmaps* pm = &maps[mapnum];
      trimstr(buf);
      /* LOG(LOG_DEBUG, "Parsing %s", buf); */
      if (symbol_ld_procmaps_parse(buf, bufsz, pm, appname) < 0) {
        LOG(LOG_INFO, "Parsing failure. Ignoring.");
        continue;
      }
      if (need_adjust == 1 && cnt_LOAD == 0) {
        if (pm->filetype == PROCMAPS_FILETYPE_EXE) {
          if (!pm->addr_valid) {
            LOG(LOG_ERR, "/proc/%d/maps addr invalid for %s", pid,
                pm->pathname);
            break;
          }
          *base_adjust = pm->addr_begin;
          cnt_LOAD++;
        }
      }
      /* symbol_ld_procmaps_dump(pm); */
      mapnum++;
    }
    if (num) {
      *num = mapnum;
    } else {
      LOG(LOG_ERR, "Cannot return size of maps object.");
    }

    if (need_adjust == 1 && *base_adjust == -1) {
      LOG(LOG_ERR, "can't find exe's first LOAD in /proc/%d/maps", pid);
      break;
    }
  } while (0);
  if (buf) {
    free(buf);
  }
  if (ff) {
    fclose(ff);
  }
  return maps;
}

static void symbol_ld_free_maps(struct symbol_ld_procmaps* maps, size_t num) {
  if (maps && num > 0) {
    size_t idx;
    for (idx = 0; idx < num; ++idx) {
      if (maps[idx].pathname) {
        free(maps[idx].pathname);
      }
      maps[idx].pathname = NULL;
    }
    free(maps);
    maps = NULL;
  }
}

static int symbol_ld_find_library(const struct symbol_ld_procmaps* maps,
                                  const size_t mapnum, const char* libpath,
                                  int inode_match,
                                  struct symbol_ld_library* lib) {
  if (!maps && !libpath) {
    LOG(LOG_ERR, "Invalid arguments.");
    return -1;
  } else {
    size_t idx;
    int found = FALSE;
    ino_t inode = 0;
    int nonlib_match = FALSE;
    int exact_match = FALSE;
    if (inode_match) {
      struct stat statbuf = {0};
      if (stat(libpath, &statbuf) < 0) {
        int err = errno;
        LOG(LOG_ERR, "Unable to get inode for %s. Error: %s", libpath,
            strerror(err));
        return -1;
      }
      inode = statbuf.st_ino;
    } else {
      LOG(LOG_DEBUG, "Not doing an inode match.");
      nonlib_match =
          (strchr(libpath, '[') || strchr(libpath, ']')) ? TRUE : FALSE;
      if (nonlib_match) {
        LOG(LOG_DEBUG, "Found '[' or ']' in %s", libpath);
      }
      exact_match = (strchr(libpath, '/')) ? TRUE : FALSE;
      if (exact_match) {
        LOG(LOG_DEBUG, "Found '/' in %s. Doing an exact match search", libpath);
      }
      if (!nonlib_match && !exact_match) {
        LOG(LOG_DEBUG, "Doing best substring search for %s.", libpath);
      }
    }
    for (idx = 0; idx < mapnum; ++idx) {
      const struct symbol_ld_procmaps* pm = &maps[idx];
      if (!pm->pathname) {
        continue;
      }
      /* first try inode match. the libraries can be symlinks and
       * all that
       */
      if (inode_match) {
        /* if it has no inode, we do not support it */
        if (pm->inode == 0) {
          continue;
        }
        found = (pm->inode == inode) ? TRUE : FALSE;
      } else {
        /* Now try string match.
         * 1. if the string contains a '[' or ']' then do a substring
         * match
         * 2. if the string contains a '/' then do an exact match
         * 3. else substring search all libs and return the first one
         * with a valid inode
         */
        if (nonlib_match) {
          /* we're looking for a non-library or a non-exe file or a
           * non-data file
           */
          if (pm->filetype == PROCMAPS_FILETYPE_VDSO ||
              pm->filetype == PROCMAPS_FILETYPE_HEAP ||
              pm->filetype == PROCMAPS_FILETYPE_STACK ||
              pm->filetype == PROCMAPS_FILETYPE_SYSCALL ||
              pm->filetype == PROCMAPS_FILETYPE_VVAR) {
            /* doing a substring match to be safe */
            found = strstr(pm->pathname, libpath) != NULL ? TRUE : FALSE;
          }
        } else {
          if (pm->filetype != PROCMAPS_FILETYPE_LIB) {
            continue;
          }
          if (pm->inode == 0) {
            continue;
          }
          /* we're doing an exact match */
          if (exact_match) {
            found = strcmp(libpath, pm->pathname) == 0 ? TRUE : FALSE;
          } else {
            /* do a substring match for best fit. If the string
             * matches then check if the next character is not an
             * alphabet and is a . or a -
             */
            char* sub = strstr(pm->pathname, libpath);
            found = FALSE;
            if (sub) {
              size_t alen = strlen(libpath);
              if (sub[alen] == '.' || sub[alen] == '-') {
                found = TRUE;
              }
            }
          }
        }
      }
      if (found) {
        LOG(LOG_DEBUG, "Found index %u matching.", idx);
        LOG(LOG_DEBUG, "Found entry %s matching %s", pm->pathname, libpath);
        break;
      }
    }
    if (!found) {
      LOG(LOG_INFO, "Library %s not found in procmaps", libpath);
      return -1;
    }
    if (found && lib) {
      const struct symbol_ld_procmaps* pm = &maps[idx];
      if (pm->addr_valid) {
        lib->addr_begin = pm->addr_begin;
        lib->addr_end = pm->addr_end;
      } else {
        LOG(LOG_ERR, "Addresses are invalid for %s", lib->pathname);
        return -1;
      }
      lib->inode = pm->inode;
      lib->pathname = strdup(pm->pathname);
      if (!lib->pathname) {
        LOG(LOG_ERR, "malloc for pm->pathname error", strerror(errno));
        lib->pathname = NULL;
        lib->length = 0;
        return -1;
      } else {
        lib->length = pm->pathname_sz;
      }
      lib->isfound = TRUE;
    }
  }
  return 0;
}

static uintptr_t symbol_ld_find_sym_a(const struct symbol_ld_library* lib,
                                      int intype, const char* symbol,
                                      size_t* sz) {
  uintptr_t ptr = 0;
  if (lib && symbol && lib->pathname) {
    size_t syms_num = 0;
    struct symbol_elf_sym* syms =
        symbol_elf_load_file(lib->pathname, &syms_num, NULL, NULL, NULL, NULL);
    if (syms && syms_num > 0) {
      size_t idx = 0;
      /* LOG(LOG_DEBUG, "%u symbols found in %s", syms_num, lib->pathname); */
      qsort(syms, syms_num, sizeof(*syms), symbol_elf_symbol_cmpqsort);
      for (idx = 0; idx < syms_num; ++idx) {
        if (strcmp(symbol, syms[idx].name) == 0) {
          LOG(LOG_DEBUG,
              "Found %s in symbol list at %u with address offset %p in %s",
              symbol, idx, syms[idx].address, lib->pathname);
          if (syms[idx].address > lib->addr_begin) {
            ptr = syms[idx].address;
          } else {
            ptr = syms[idx].address + lib->addr_begin;
          }

          if (ptr <= 0) {
            continue;
          }
          if (intype != syms[idx].type) {
            continue;
          }
          if (sz) {
            *sz = syms[idx].size;
          }
          break;
        } else {
          /*
          LOG(LOG_DEBUG, "Found symbol but not equal [%s != %s] lib %s ",
          syms[idx].name, symbol, lib->pathname);
          */
        }
      }
      /* free memory for all to avoid mem-leaks */
      for (idx = 0; idx < syms_num; ++idx) {
        if (syms[idx].name) {
          free(syms[idx].name);
        }
        syms[idx].name = NULL;
      }
      free(syms);
      syms_num = 0;
    } else {
      LOG(LOG_ERR, "No symbols found in %s", lib->pathname);
    }
  } else {
    LOG(LOG_ERR, "Invalid arguments.");
  }
  return ptr;
}

uintptr_t symbol_ld_find_sym_repable(struct symbol_elf_pid* hp, int intype,
                                     const char* symbol, size_t* sz) {
  uintptr_t ptr = 0;
  struct symbol_ld_library lib_s;
  struct symbol_ld_library* lib = &lib_s;

  /* find in default lib first??? */
  if (hp && hp->ld_maps_num && hp->ld_maps) {
    size_t ddx = 0;
    for (ddx = ELF_LIB_C; ddx < ELF_LIB_MAX; ddx++) {
      lib = &(hp->libs[ddx]);
      if (lib->isfound != TRUE) {
        continue;
      }
      ptr = symbol_ld_find_sym_a(lib, intype, symbol, sz);
      if (ptr) {
        LOG(LOG_DEBUG, "Find symbol<%s> ptr:%p in default lib:<%s>", symbol,
            ptr, lib->pathname);
        return ptr;
      }
    }
  }

  lib = &lib_s;
  if (hp && hp->ld_maps_num && hp->ld_maps) {
    size_t idx = 0;
    for (idx = 0; idx < hp->ld_maps_num; idx++) {
      memset(lib, 0, sizeof(lib_s));
      struct symbol_ld_procmaps* pm = &(hp->ld_maps[idx]);
      if (!pm->pathname) {
        continue;
      }
      if (pm->filetype != PROCMAPS_FILETYPE_LIB) {
        continue;
      }
      if (pm->inode == 0) {
        continue;
      }
      if (symbol_get_file_size(pm->pathname) <= 0) {
        continue;
      }

      if (pm->addr_valid) {
        lib->addr_begin = pm->addr_begin;
        lib->addr_end = pm->addr_end;
      } else {
        LOG(LOG_ERR, "Addresses are invalid for %s", lib->pathname);
        continue;
      }
      lib->inode = pm->inode;
      lib->pathname = strdup(pm->pathname);
      if (!lib->pathname) {
        LOG(LOG_ERR, "malloc for pm->pathname error", strerror(errno));
        lib->pathname = NULL;
        lib->length = 0;
        continue;
      } else {
        lib->length = pm->pathname_sz;
      }
      lib->isfound = TRUE;

      ptr = symbol_ld_find_sym_a(lib, intype, symbol, sz);

      if (ptr) {
        LOG(LOG_DEBUG, "Find symbol<%s> ptr:%p in lib:<%s>", symbol, ptr,
            lib->pathname);
        if (lib->pathname) {
          free(lib->pathname);
        }
        lib->pathname = NULL;
        break;
      }
      if (lib->pathname) {
        free(lib->pathname);
      }
      lib->pathname = NULL;
    }
  } else {
    LOG(LOG_ERR, "Invalid arguments.");
  }
  return ptr;
}

uintptr_t symbol_ld_find_sym(struct symbol_elf_pid* hp, int intype,
                             const char* symbol, size_t* sz) {
  uintptr_t ptr = 0;
  struct symbol_ld_library lib_s;
  struct symbol_ld_library* lib = &lib_s;

  /* find in default lib first??? */
  if (hp && hp->ld_maps_num && hp->ld_maps) {
    size_t ddx = 0;
    for (ddx = 0; ddx < ELF_LIB_MAX; ddx++) {
      lib = &(hp->libs[ddx]);
      if (lib->isfound != TRUE) {
        continue;
      }
      ptr = symbol_ld_find_sym_a(lib, intype, symbol, sz);
      if (ptr) {
        LOG(LOG_DEBUG, "Find symbol<%s> ptr:%p in default lib:<%s>", symbol,
            ptr, lib->pathname);
        return ptr;
      }
    }
  }

  lib = &lib_s;
  if (hp && hp->ld_maps_num && hp->ld_maps) {
    size_t idx = 0;
    for (idx = 0; idx < hp->ld_maps_num; idx++) {
      memset(lib, 0, sizeof(lib_s));
      struct symbol_ld_procmaps* pm = &(hp->ld_maps[idx]);
      if (!pm->pathname) {
        continue;
      }
      if (pm->filetype != PROCMAPS_FILETYPE_LIB) {
        continue;
      }
      if (pm->inode == 0) {
        continue;
      }
      if (symbol_get_file_size(pm->pathname) <= 0) {
        continue;
      }

      if (pm->addr_valid) {
        lib->addr_begin = pm->addr_begin;
        lib->addr_end = pm->addr_end;
      } else {
        LOG(LOG_ERR, "Addresses are invalid for %s", lib->pathname);
        continue;
      }
      lib->inode = pm->inode;
      lib->pathname = strdup(pm->pathname);
      if (!lib->pathname) {
        LOG(LOG_ERR, "malloc for pm->pathname error", strerror(errno));
        lib->pathname = NULL;
        lib->length = 0;
        continue;
      } else {
        lib->length = pm->pathname_sz;
      }
      lib->isfound = TRUE;

      ptr = symbol_ld_find_sym_a(lib, intype, symbol, sz);

      if (ptr) {
        LOG(LOG_DEBUG, "Find symbol<%s> ptr:%p in lib:<%s>", symbol, ptr,
            lib->pathname);
        if (lib->pathname) {
          free(lib->pathname);
        }
        lib->pathname = NULL;
        break;
      }
      if (lib->pathname) {
        free(lib->pathname);
      }
      lib->pathname = NULL;
    }
  } else {
    LOG(LOG_ERR, "Invalid arguments.");
  }
  return ptr;
}

uintptr_t symbol_ld_find_func_repable(struct symbol_elf_pid* hp,
                                      const char* symbol, size_t* sz) {
  uintptr_t ptr =
      symbol_ld_find_sym_repable(hp, SYMBOL_IS_FUNCTION, symbol, sz);
  return ptr;
}

uintptr_t symbol_ld_find_global_repable(struct symbol_elf_pid* hp,
                                        const char* symbol, size_t* sz) {
  uintptr_t ptr = symbol_ld_find_sym_repable(hp, SYMBOL_IS_OBJECT, symbol, sz);
  return ptr;
}

uintptr_t symbol_ld_find_func(struct symbol_elf_pid* hp, const char* symbol,
                              size_t* sz) {
  uintptr_t ptr = symbol_ld_find_sym(hp, SYMBOL_IS_FUNCTION, symbol, sz);
  return ptr;
}

uintptr_t symbol_ld_find_global(struct symbol_elf_pid* hp, const char* symbol,
                                size_t* sz) {
  uintptr_t ptr = symbol_ld_find_sym(hp, SYMBOL_IS_OBJECT, symbol, sz);
  return ptr;
}

static int symbol_ld_find_default_lib(struct symbol_elf_pid* hp) {
  int ld_found = FALSE;
  int c_found = FALSE;
  int dl_found = FALSE;
  int pthread_found = FALSE;
  if (!hp || !hp->libs) {
    return -1;
  }
  if (hp->ld_maps_num <= 0) {
    return -1;
  }
  memset(hp->libs, 0, sizeof(hp->libs));

#undef LD_PROCMAPS_FIND_LIB
#define LD_PROCMAPS_FIND_LIB(name, flag, index, retval)                      \
  do {                                                                       \
    LOG(LOG_DEBUG, "Checking if %s exists in procmaps.", name);              \
    memset(&hp->libs[index], 0, sizeof(hp->libs[index]));                    \
    if (symbol_ld_find_library(hp->ld_maps, hp->ld_maps_num, name, flag,     \
                               &hp->libs[index]) < 0) {                      \
      LOG(LOG_INFO, "%s not mapped.", name);                                 \
      retval = FALSE;                                                        \
    } else {                                                                 \
      retval = TRUE;                                                         \
      LOG(LOG_DEBUG, "Found %s libpath %s", name, hp->libs[index].pathname); \
    }                                                                        \
  } while (0)

  if (hp->exe_interp.name) {
    LD_PROCMAPS_FIND_LIB(hp->exe_interp.name, TRUE, ELF_LIB_LD, ld_found);
  }
  if (!ld_found) {
    LOG(LOG_INFO, "No interpreter found. Guessing.");
    LD_PROCMAPS_FIND_LIB(LIB_LD, FALSE, ELF_LIB_LD, ld_found);
  }
  LD_PROCMAPS_FIND_LIB(LIB_C, FALSE, ELF_LIB_C, c_found);
  LD_PROCMAPS_FIND_LIB(LIB_DL, FALSE, ELF_LIB_DL, dl_found);
  LD_PROCMAPS_FIND_LIB(LIB_PTHREAD, FALSE, ELF_LIB_PTHREAD, pthread_found);
  if (!pthread_found) {
    LOG(LOG_DEBUG, "No pthread_found found.");
  }

#undef LD_PROCMAPS_FIND_LIB

  return (ld_found || c_found || dl_found);
}

static int symbol_ld_find_default_func(struct symbol_elf_pid* hp) {
  size_t symbsize = 0;
  if (!hp || !hp->libs) {
    return -1;
  }
  if (hp->ld_maps_num <= 0) {
    return -1;
  }

  hp->fn_malloc = 0;
  hp->fn_realloc = 0;
  hp->fn_free = 0;
  hp->fn_dlopen = 0;
  hp->fn_dlclose = 0;
  hp->fn_dlsym = 0;
  hp->fn_pthread_create = 0;
  hp->fn_pthread_detach = 0;

#undef LD_LIB_FIND_FN_ADDR
#define LD_LIB_FIND_FN_ADDR(fn, outfn, index)                                \
  do {                                                                       \
    if (outfn) break;                                                        \
    outfn = symbol_ld_find_sym_a(&hp->libs[ELF_##index], SYMBOL_IS_FUNCTION, \
                                 fn, &symbsize);                             \
    if (outfn != 0) {                                                        \
      LOG(LOG_DEBUG, "Found %s at %p in %s", fn, outfn, index);              \
    } else {                                                                 \
      LOG(LOG_DEBUG, "%s not found in %s.", fn, index);                      \
    }                                                                        \
  } while (0)

  if (hp->libs[ELF_LIB_C].isfound) {
    LD_LIB_FIND_FN_ADDR("malloc", hp->fn_malloc, LIB_C);
    LD_LIB_FIND_FN_ADDR("realloc", hp->fn_realloc, LIB_C);
    LD_LIB_FIND_FN_ADDR("free", hp->fn_free, LIB_C);
  }
  if (hp->libs[ELF_LIB_LD].isfound) {
    LD_LIB_FIND_FN_ADDR("malloc", hp->fn_malloc, LIB_LD);
    LD_LIB_FIND_FN_ADDR("realloc", hp->fn_realloc, LIB_LD);
    LD_LIB_FIND_FN_ADDR("free", hp->fn_free, LIB_LD);
  }
  if (!hp->fn_malloc || !hp->fn_realloc || !hp->fn_free) {
    LOG(LOG_ERR,
        "Some memory allocation routines are unavailable. Cannot proceed.");
    return -1;
  }
  if (hp->libs[ELF_LIB_DL].isfound) {
    LD_LIB_FIND_FN_ADDR("dlopen", hp->fn_dlopen, LIB_DL);
    LD_LIB_FIND_FN_ADDR("dlclose", hp->fn_dlclose, LIB_DL);
    LD_LIB_FIND_FN_ADDR("dlsym", hp->fn_dlsym, LIB_DL);
  }
  if (!hp->fn_dlopen || !hp->fn_dlsym) {
    if (hp->libs[ELF_LIB_C].isfound) {
      LD_LIB_FIND_FN_ADDR("__libc_dlopen_mode", hp->fn_dlopen, LIB_C);
      LD_LIB_FIND_FN_ADDR("__libc_dlclose", hp->fn_dlclose, LIB_C);
      LD_LIB_FIND_FN_ADDR("__libc_dlsym", hp->fn_dlsym, LIB_C);

      if (!hp->fn_dlopen || !hp->fn_dlsym) {
        LD_LIB_FIND_FN_ADDR("dlopen", hp->fn_dlopen, LIB_C);
        LD_LIB_FIND_FN_ADDR("dlclose", hp->fn_dlclose, LIB_C);
        LD_LIB_FIND_FN_ADDR("dlsym", hp->fn_dlsym, LIB_C);
      }
    }
  }
  if (!hp->fn_dlopen || !hp->fn_dlsym) {
    LOG(LOG_ERR,
        "Dynamic Library loading routines were not found. Cannot proceed.");
    return -1;
  }
  if (hp->libs[ELF_LIB_PTHREAD].isfound) {
    LD_LIB_FIND_FN_ADDR("pthread_create", hp->fn_pthread_create, LIB_PTHREAD);
    LD_LIB_FIND_FN_ADDR("pthread_detach", hp->fn_pthread_detach, LIB_PTHREAD);
  } else {
    hp->fn_pthread_create = hp->fn_pthread_detach = 0;
  }

  if (hp->fn_pthread_create && hp->fn_pthread_detach) {
    LOG(LOG_DEBUG, "Pthread's symbol found. Do not need more magic.");
  } else {
    LOG(LOG_INFO,
        "Pthread's symbol not found. Will disable pthread usage in injection.");
  }

#undef LD_LIB_FIND_FN_ADDR
  return 0;
}

void symbol_pid_destroy(struct symbol_elf_pid* hp) {
  if (hp) {
    size_t idx;
    if (hp->exe_symbols) {
      for (idx = 0; idx < hp->exe_symbols_num; ++idx) {
        free(hp->exe_symbols[idx].name);
        hp->exe_symbols[idx].name = NULL;
      }
      free(hp->exe_symbols);
    }
    hp->exe_symbols = NULL;
    hp->exe_symbols_num = 0;
    if (hp->exe_interp.name) {
      free(hp->exe_interp.name);
      hp->exe_interp.name = NULL;
    }
    for (idx = 0; idx < ELF_LIB_MAX; ++idx) {
      if (hp->libs[idx].pathname) {
        free(hp->libs[idx].pathname);
      }
      hp->libs[idx].pathname = NULL;
    }
    memset(hp->libs, 0, sizeof(hp->libs));
    if (hp->ld_maps) {
      symbol_ld_free_maps(hp->ld_maps, hp->ld_maps_num);
      hp->ld_maps = NULL;
      hp->ld_maps_num = 0;
    }
    free(hp);
    hp = NULL;
  }
}

struct symbol_elf_pid* symbol_pid_create(pid_t pid, int symelang) {
  return symbol_pid_create_inner(pid, symelang, 1);
}

struct symbol_elf_pid* symbol_pid_create_nolibc(pid_t pid, int symelang) {
  return symbol_pid_create_inner(pid, symelang, 0);
}

struct symbol_elf_pid* symbol_pid_create_inner(pid_t pid, int symelang,
                                               int needlibc) {
  int rc = 0;
  int idx = 0;
  uintptr_t ptr = 0;
  struct symbol_elf_pid* hp = NULL;
  do {
    char exename[MAX_BUFFER];
    char filename[MAX_BUFFER];
    ssize_t len;
    if (pid <= 0) {
      LOG(LOG_ERR, "invalid pid %d.", pid);
      break;
    }
    memset(exename, 0, sizeof(exename));
    snprintf(exename, sizeof(exename), "/proc/%d/exe", pid);
    LOG(LOG_DEBUG, "Exe symlink for pid %d : %s", pid, exename);
    if ((len = readlink(exename, filename, MAX_BUFFER - 1)) != -1) {
      filename[len] = '\0';
    }
    LOG(LOG_DEBUG, "Exe file for pid %d : %s", pid, filename);

    hp = malloc(sizeof(*hp));
    if (!hp) {
      LOG(LOG_ERR, "malloc error: size %d, %s", sizeof(*hp), strerror(errno));
      rc = -1;
      break;
    }
    memset(hp, 0, sizeof(*hp));
    hp->pid = pid;
    hp->is64 = ELF_IS_NEITHER;
    hp->elang = symelang;
    hp->exe_symbols = symbol_elf_load_file(
        filename, &hp->exe_symbols_num, &hp->exe_entry_point,
        &hp->exe_base_adjust, &hp->exe_interp, &hp->is64);
    if (!hp->exe_symbols) {
      LOG(LOG_ERR, "Unable to find any symbols in exe.");
      rc = -1;
      break;
    }
    if (hp->exe_entry_point == 0) {
      LOG(LOG_ERR, "Entry point is 0. Invalid.");
      rc = -1;
      break;
    }

    LOG(LOG_DEBUG, "Exe headers loaded.");

    hp->ld_maps =
        symbol_ld_load_maps(hp->pid, &hp->ld_maps_num, &hp->exe_base_adjust);
    if (!hp->ld_maps) {
      LOG(LOG_ERR, "Unable to load data in /proc/%d/maps.", pid);
      rc = -1;
      break;
    }
    if (hp->exe_base_adjust == -1) {
      LOG(LOG_ERR, "Unable to find exe_base_adjust in /proc/%d/maps.", pid);
      rc = -1;
      break;
    }
    LOG(LOG_DEBUG, "Load data in /proc/%d/maps.", pid);
    if (hp->exe_symbols && hp->exe_symbols_num > 0) {
      qsort(hp->exe_symbols, hp->exe_symbols_num, sizeof(*hp->exe_symbols),
            symbol_elf_symbol_cmpqsort);

      for (idx = 0; idx < hp->exe_symbols_num; ++idx) {
        ptr = hp->exe_symbols[idx].address;
        if (!ptr) {
          continue;
        }
        hp->exe_symbols[idx].address = hp->exe_base_adjust + ptr;
      }
    }
    if (needlibc != 0 && symbol_ld_find_default_lib(hp) < 0) {
      LOG(LOG_ERR, "Unable to find all the libs needed. Cannot proceed.");
      rc = -1;
      break;
    }
    if (needlibc != 0 && symbol_ld_find_default_func(hp) < 0) {
      LOG(LOG_ERR, "Unable to find all the funcs needed. Cannot proceed.");
      rc = -1;
      break;
    }
    if (rc < 0) {
      symbol_pid_destroy(hp);
      hp = NULL;
      LOG(LOG_ERR, "Destory mem.");
    }
  } while (0);
  return hp;
}

static uintptr_t symbol_pid_find_sym_a(struct symbol_elf_pid* hp, int intype,
                                       const char* symbol, size_t* sz) {
  uintptr_t ptr = 0;
  size_t idx = 0;
  if (!hp || !symbol || !hp->exe_symbols) {
    LOG(LOG_ERR, "Invalid arguments.");
    return (uintptr_t)0;
  }
  for (idx = 0; idx < hp->exe_symbols_num; ++idx) {
    if (hp->exe_symbols[idx].sym.st_shndx == SHN_UNDEF) {
      continue;
    }
    const char* name = hp->exe_symbols[idx].name;
    if (strcmp(name, symbol) == 0) {
      LOG(LOG_DEBUG, "Found %s in symbol list at %u", symbol, idx);
      ptr = hp->exe_symbols[idx].address;
      if (!ptr) {
        continue;
      }
      if (intype != hp->exe_symbols[idx].type) {
        continue;
      }
      if (sz) {
        *sz = hp->exe_symbols[idx].size;
      }
      break;
    }
  }
  LOG(LOG_DEBUG, "Symbol %s has address %p", symbol, ptr);
  return ptr;
}

uintptr_t symbol_pid_find_func(struct symbol_elf_pid* hp, const char* symbol,
                               size_t* sz) {
  uintptr_t ptr = symbol_pid_find_sym_a(hp, SYMBOL_IS_FUNCTION, symbol, sz);
  return ptr;
}

uintptr_t symbol_pid_find_global(struct symbol_elf_pid* hp, const char* symbol,
                                 size_t* sz) {
  uintptr_t ptr = symbol_pid_find_sym_a(hp, SYMBOL_IS_OBJECT, symbol, sz);
  return ptr;
}

uintptr_t symbol_pid_find_entry_point(struct symbol_elf_pid* hp) {
  return hp ? hp->exe_entry_point : 0;
}

#ifdef TEST_SYMBOL
int main(int argc, char* argv[]) {
  if (argc < 2) {
    printf("usage: %s <pid>\n", argv[0]);
    exit(-1);
  }

  int pid = atoi(argv[1]);

  struct symbol_elf_pid* hp = symbol_pid_create(pid);
  uintptr_t uep = symbol_pid_find_entry_point(hp);
  symbol_pid_find_sym_a(hp, "MON_RebootSystem", NULL, NULL);

  LOG(LOG_DEBUG, "symbol_pid_find_entry_point %p", uep);

  return 0;
}
#endif
