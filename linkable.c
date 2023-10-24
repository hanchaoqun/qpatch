
//===----------------------------------------------------------------------===//
//
// Copyright 2023 hanssccv@gmail.com. All rights reserved.
// Use of this source code is governed by a Anti-996 style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//

#include "linkable.h"

static Elf_Addr linkable_elf_pat_repable(const char * symbolname, const char * pat_symbol_file,size_t *outsymbolsize, int type );

static int linkable_open_filename(const char *filename)
{
        int fd = -1;
        fd = open(filename, O_RDONLY);
        if(fd < 0){
                 LOG(LOG_ERR, "open file(%s) : %s", filename, strerror(errno));
        }
        return fd;
}

long linkable_get_file_size (const char *filename)
{
    long filesize = 0;
    struct stat statbuff;  
    if(stat(filename, &statbuff) < 0){
        return filesize;
    }else{
        filesize = statbuff.st_size;
    }
    return filesize; 
}

static void * linkable_file_read_to_buf(const char *filename, size_t *outlen,  long addlen)
{
    void * baseptr;
    unsigned char buf[MAX_BUFF_LEN];
    unsigned char * tbuf;
    int fd, i;
    long filelen = 0;
    long readlen = 0;
    size_t memlen = 0;

    if(!outlen){
        return NULL;
    }
    *outlen = 0;

    filelen = linkable_get_file_size(filename);
    if (filelen <= 0) {
        LOG(LOG_ERR,"Get linkable file size for %s err ret %d , %s", filename, filelen, strerror(errno));
        return NULL;
    }
    
    fd = linkable_open_filename(filename);
    if (fd < 0) {
        return NULL;
    }
    
    /*Mask the last 4 bits */
    memlen  = ( filelen & 0xFFFFFFF0 ) + 0x10;
    baseptr = ( unsigned char * )malloc(memlen + addlen);
    if (  NULL  == baseptr ){
        LOG(LOG_ERR, "malloc error: size %d, %s", memlen + addlen, strerror(errno));
        close(fd);
        return NULL;
    }
    memset(baseptr, 0, memlen + addlen);

    if (lseek(fd, 0, SEEK_SET) < 0) {
        LOG(LOG_ERR, "lseek error: fd %d, %s", fd, strerror(errno));
        return NULL;
    }
    tbuf = baseptr;
    /*start to read file to buffer*/
    while ( TRUE ) {
        readlen = read(fd,buf,sizeof(unsigned char)*MAX_BUFF_LEN);
        if (0 >= readlen) {
            break;
        }
        for (i=0;i<readlen;i++) {
            tbuf[i] = buf[i];
        }
        tbuf = ( unsigned char * )((size_t)tbuf + (size_t)readlen);
    }
    close(fd);         
    *outlen = memlen;
    LOG(LOG_DEBUG, "Read obj to buff<%p> len<%u>", baseptr, memlen);
    return baseptr;
}


static int linkable_elf_is_object_type(struct linkable_elf_internals *li)
{
    if (!li || li->ei.sechdr_offset == 0 || li->ei.sechdr_size == 0)
            return -1;
    
    if(li->ei.type != ET_REL){
        LOG(LOG_ERR, "Object file type error %d.(relocatable file expected)", li->ei.type);
        return -1;
    }

    if(li->ei.sechdrs == NULL || li->ei.strsectbl == NULL){
        LOG(LOG_ERR, "Object file type error (%p or %p).(section-header-table or section-name-string-table missing)", 
                      li->ei.sechdrs, li->ei.strsectbl);
        return -1;
    }

    if( !li->ei.sechdr_idx_bss && !li->ei.sechdr_idx_text && !li->ei.sechdr_idx_data && !li->ei.sechdr_idx_rodata )
    {
        LOG(LOG_ERR, "Object file type error missing sections bss_idx(%u) text_idx(%u) data_idx(%u) rodata_idx(%u) ",
                      li->ei.sechdr_idx_bss, li->ei.sechdr_idx_text, li->ei.sechdr_idx_data, li->ei.sechdr_idx_rodata);
        return -1;
    }
    
    return 0;
}


static Elf_Addr linkable_elf_rsv_symbol_repable(struct linkable_elf_internals *li, const char * symbolname, size_t *outsymbolsize, int st)
{
    Elf_Addr tptr = 0;
    int inexe = TRUE;
    size_t symbolsize = 0;
    if(!symbolname)
        return 0;
    do{
        if(!tptr){
            if(LNK_SH_TYPE_EITHER == st || LNK_SH_TYPE_FUN == st){
                if( (tptr = symbol_pid_find_func(li->hp, symbolname, &symbolsize)) > 0 ){
                    inexe = TRUE;
                    break;
                }
            }
            if(LNK_SH_TYPE_EITHER == st || LNK_SH_TYPE_OBJ == st){
                if( (tptr = symbol_pid_find_global(li->hp, symbolname, &symbolsize)) > 0 ){
                    inexe = TRUE;
                    break;
                }
            }
        }
        if(!tptr){
            if(LNK_SH_TYPE_EITHER == st || LNK_SH_TYPE_FUN == st){
                if( (tptr = symbol_ld_find_func_repable(li->hp, symbolname, &symbolsize)) > 0 ){
                    inexe = FALSE;
                    break;
                }
            }
            if(LNK_SH_TYPE_EITHER == st || LNK_SH_TYPE_OBJ == st){
                if( (tptr = symbol_ld_find_global_repable(li->hp, symbolname, &symbolsize)) > 0 ){
                    inexe = FALSE;
                    break;
                }
            }
        }
    }while(0);
    if(!tptr){
        LOG(LOG_DEBUG, "Symbol<%s> Un-Resolved!", symbolname);
        return 0;
    }
    if(outsymbolsize)
        *outsymbolsize = symbolsize;
    LOG(LOG_DEBUG, "Symbol<%s> Addr<%p> Size<%u> Exe<%u> resolved!", symbolname, tptr, symbolsize, inexe);
    return tptr;
}


static Elf_Addr linkable_elf_rsv_symbol(struct linkable_elf_internals *li, const char * symbolname, size_t *outsymbolsize, int st,  const char *pat_symbol)
{
    Elf_Addr tptr = 0;
    int inexe = TRUE;
    size_t symbolsize = 0;
    if(!symbolname)
        return 0;
    do{
        if(!tptr){
            if(LNK_SH_TYPE_EITHER == st || LNK_SH_TYPE_FUN == st){
                if( (tptr = symbol_pid_find_func(li->hp, symbolname, &symbolsize)) > 0 ){
                    inexe = TRUE;
                    break;
                }
            }
            if(LNK_SH_TYPE_EITHER == st || LNK_SH_TYPE_OBJ == st){
                if( (tptr = symbol_pid_find_global(li->hp, symbolname, &symbolsize)) > 0 ){
                    inexe = TRUE;
                    break;
                }
            }
        }
        if(!tptr){
            if(LNK_SH_TYPE_EITHER == st || LNK_SH_TYPE_FUN == st){
                if( (tptr = symbol_ld_find_func(li->hp, symbolname, &symbolsize)) > 0 ){
                    inexe = FALSE;
                    break;
                }
            }
            if(LNK_SH_TYPE_EITHER == st || LNK_SH_TYPE_OBJ == st){
                if( (tptr = symbol_ld_find_global(li->hp, symbolname, &symbolsize)) > 0 ){
                    inexe = FALSE;
                    break;
                }
            }
        }
    }while(0);
    if(!tptr){
    if ((tptr = linkable_elf_pat_repable(symbolname, pat_symbol, &symbolsize, 0)) <= 0){
           LOG(LOG_DEBUG, "Symbol<%s> Un-Resolved!", symbolname);
           return 0;
       }
    }
    if(outsymbolsize)
        *outsymbolsize = symbolsize;
    LOG(LOG_DEBUG, "Symbol<%s> Addr<%p> Size<%u> Exe<%u> resolved!", symbolname, tptr, symbolsize, inexe);
    return tptr;
}

/*
static void linkable_elf_rsv_upd_sym_addr(struct linkable_elf_internals *li, Elf_Sym *sym, uintptr_t newaddr)
{
    size_t idx = 0;
    Elf_Sym  *orsym     = NULL; 
    struct symbol_elf_sym * symbol = NULL;

    if (!li || !sym || !li->ei.symbols || !newaddr)
        return;
    
    for(idx = 0; idx < li->ei.symbols_num; idx++)
    {
        symbol = &(li->ei.symbols[idx]);
        orsym = &(symbol->sym);
        // same 
        if(orsym->st_name == sym->st_name){
            LOG(LOG_INFO, "Symbol<%s> Addr<%p> update to NewAddr<%p>!", symbol->name, symbol->address, newaddr);
            symbol->address = (uintptr_t)newaddr;
        }
    }
}
*/

static struct linkable_elf_hook_fun * linkable_elf_find_hookfun(struct linkable_elf_internals *li, const char *oldsymbolname)
{
    struct linkable_elf_hook_fun * find = NULL;
    struct linkable_elf_hook_fun *hf = NULL;
    size_t idx = 0;
    
    if(!oldsymbolname || !li){
        return NULL;
    }

    for(idx = 0; idx < li->rephdr.hookfuns_num; idx++)
    {
        hf = &(li->rephdr.hookfuns[idx]);
        if(strcmp(oldsymbolname, hf->oldname) == 0){
            find = hf;
            break;
        }
    }
    return find;
}


static int linkable_elf_rsv_rela(struct linkable_elf_internals *li, 
                                                      struct linkable_elf_rela_info *rela_info,
                                                       const char *pat_symbol)
{
    //int rc = 0;
    Elf_Shdr *sechdr_dest  = NULL;
    Elf_Shdr *sechdr_rela  = NULL;
    Elf_Shdr *sechdr_symb  = NULL;
    Elf_Shdr *sechdr_str   = NULL;
    void *sechdr_dest_offset = NULL;
    void *base_rel_hdr_addr   = NULL;
    void *base_rel_itm_addr   = NULL;
    void *from_rel_hdr_addr   = NULL;
    void *from_rel_itm_addr   = NULL;
    Elf_Addr base_symbol_addr = 0;
	Elf_Addr got_g_symbol_addr = 0;
	struct linkable_elf_pltgot_item * got_g_symbol_item = NULL;
    //size_t segtype_dest = 0; //SHT_SYMTAB;
    Elf_Rela *relas = NULL;
    Elf_Rela *rela  = NULL;
    size_t relas_num = 0;
    Elf_Sym *r_syms = NULL;
    Elf_Sym *r_sym  = NULL;
    size_t r_syms_num = 0;
	char *strsymtbl = NULL;
	size_t strsymtbl_size = 0;
    size_t relaidx = 0;
    size_t r_symbidx = 0;
    size_t r_reltype = 0;
    Elf_Addr P_FROM  = 0;
    Elf_Addr P    = 0;
    Elf_Addr A  = 0;
    Elf_Addr S  = 0;
    Elf_Addr RV = 0;
    int relacnt = 0;
    int sym_un_res_cnt = 0;
    int shtype = 0;
    size_t symbolsize = 0;
    void * inruntimebase = 0;
    void * inbssoffsetbase = 0;
    void * inbssoffsetend = 0;
    long * relaSymAddrs = 0;
    void * inpltgotoffsetbase = 0;
    void * inpltgotoffsetend = 0;
	long * relaSymAddrsPlt = 0;
    struct linkable_elf_hook_fun * hf = NULL;
    
    if (!li || !rela_info || !li->ei.sechdrs || !li->ei.sechdr_num)
        return -1;

    /*Only two types of relocation are found in a relocatable object file. So its enough 
      if we handle these two*/

    /* if(rela_info->sechdr_dst_idx > li->ei.sechdr_num){
        LOG(LOG_ERR, "Relocation dest section index is out of range %u/%u.", rela_info->sechdr_dst_idx, li->ei.sechdr_num);
        return -1;
    } */
    if(rela_info->sechdr_idx > li->ei.sechdr_num){
        LOG(LOG_ERR, "Relocation self section index is out of range %u/%u.", rela_info->sechdr_idx, li->ei.sechdr_num);
        return -1;
    }
    if(rela_info->sechdr_sym_idx > li->ei.sechdr_num){
        LOG(LOG_ERR, "Relocation symb section index is out of range %u/%u.", rela_info->sechdr_sym_idx, li->ei.sechdr_num);
        return -1;
    }
    
    if(rela_info->sechdr_str_idx > li->ei.sechdr_num){
        LOG(LOG_ERR, "Relocation symb-str section index is out of range %u/%u.", rela_info->sechdr_str_idx, li->ei.sechdr_num);
        return -1;
    }
    
    /* sechdr_dest = &((Elf_Shdr *)(li->ei.sechdrs))[rela_info->sechdr_dst_idx]; */
    sechdr_rela = &((Elf_Shdr *)(li->ei.sechdrs))[rela_info->sechdr_idx];
    /*
    if( (sechdr_rela->sh_info != li->ei.sechdr_idx_bss)
        && (sechdr_rela->sh_info != li->ei.sechdr_idx_text)
        && (sechdr_rela->sh_info != li->ei.sechdr_idx_data)
        && (sechdr_rela->sh_info != li->ei.sechdr_idx_rodata) )
    {
        LOG(LOG_INFO, "Relo-dest-section unsupport: idx<%d> not in .bss<%d> .text<%d> .data<%d> .rodata<%d>", 
                       sechdr_rela->sh_info, li->ei.sechdr_idx_bss, li->ei.sechdr_idx_text, li->ei.sechdr_idx_data, li->ei.sechdr_idx_rodata);
        return 0;
    }*/
    if(sechdr_rela->sh_info >= li->ei.sechdr_num){
        LOG(LOG_DEBUG, "Relo-dest-section unsupport: idx<%d> not in .bss<%d> .text<%d> .data<%d> .rodata<%d>", 
                       sechdr_rela->sh_info, li->ei.sechdr_idx_bss, li->ei.sechdr_idx_text, li->ei.sechdr_idx_data, li->ei.sechdr_idx_rodata);
        return 0;
    }
    if( (li->ei.sechdrs_types[sechdr_rela->sh_info] != ELF_SECT_BSS)
         && (li->ei.sechdrs_types[sechdr_rela->sh_info] != ELF_SECT_TEXT)
         && (li->ei.sechdrs_types[sechdr_rela->sh_info] != ELF_SECT_DATA)
         && (li->ei.sechdrs_types[sechdr_rela->sh_info] != ELF_SECT_RODATA) )
    {
        LOG(LOG_DEBUG, "Relo-dest-section unsupport: idx<%d> not in .bss<%d> .text<%d> .data<%d> .rodata<%d>", 
                       sechdr_rela->sh_info, li->ei.sechdr_idx_bss, li->ei.sechdr_idx_text, li->ei.sechdr_idx_data, li->ei.sechdr_idx_rodata);
        return 0;
    }
    if(sechdr_rela->sh_info == SHN_UNDEF){
        LOG(LOG_DEBUG, "Relo-dest-section unsupport: idx<%d> is SHN_UNDEF<%d>", 
                       sechdr_rela->sh_info, SHN_UNDEF);
        return 0;
    }
    inruntimebase = li->baseptr;
    inbssoffsetbase = li->bssptr;
    inbssoffsetend  = inbssoffsetbase + li->bsslen;
	inpltgotoffsetbase = li->pltgotptr;
	inpltgotoffsetend  = inpltgotoffsetbase + li->pltgotlen;
    sechdr_dest = &((Elf_Shdr *)(li->ei.sechdrs))[sechdr_rela->sh_info];
    sechdr_dest_offset = (void *)sechdr_dest->sh_offset;
    base_rel_hdr_addr = (void *)((Elf_Addr)inruntimebase + (Elf_Addr)sechdr_dest_offset);
    from_rel_hdr_addr   = (void *)((Elf_Addr)li->objptr + (Elf_Addr)sechdr_dest_offset);
        
    sechdr_symb = &((Elf_Shdr *)(li->ei.sechdrs))[rela_info->sechdr_sym_idx];
    sechdr_str  = &((Elf_Shdr *)(li->ei.sechdrs))[rela_info->sechdr_str_idx];

    const char *name = &li->ei.strsectbl[sechdr_dest->sh_name];
    if(name){
        LOG(LOG_DEBUG, "Relocating rt_base:%p from_obj:%p secname:%s sec_off:%p rt_hdr_addr:%p from_hdr_addr:%p", 
                       inruntimebase, li->objptr, name, sechdr_dest_offset, base_rel_hdr_addr, from_rel_hdr_addr);
    }else{
        LOG(LOG_DEBUG, "Relocating rt_base:%p from_obj:%p secname:%s sec_off:%p rt_hdr_addr:%p from_hdr_addr:%p", 
                       inruntimebase, li->objptr, "N/A", sechdr_dest_offset, base_rel_hdr_addr, from_rel_hdr_addr);
    }

    /* read rela section tables */
    relas = (Elf_Rela *)symbol_elf_load_section_tables(&(li->ei),sechdr_rela, &relas_num);
    if(!relas){
                return -1;
    }
    
    /* read symbol section tables for this rel */
    r_syms = (Elf_Sym *)symbol_elf_load_section_tables(&(li->ei),sechdr_symb, &r_syms_num);
    if(!r_syms){
        free(relas);
        relas = NULL;
        return -1;
    }

    /* read strings section tables tables for this symbol-sec */
    strsymtbl = (char *)symbol_elf_load_section_strings(&(li->ei),sechdr_str, &strsymtbl_size);
    if(!strsymtbl){
        free(relas);
        relas = NULL;
        free(r_syms);
        r_syms = NULL;
        return -1;
    }

    relaSymAddrs = (long *)malloc(r_syms_num * sizeof(long));
    if(!relaSymAddrs){
        free(relas);
        relas = NULL;
        free(r_syms);
        r_syms = NULL;
        free(strsymtbl);
        strsymtbl = NULL;
        return -1;
    }
    memset(relaSymAddrs, 0, r_syms_num * sizeof(long));

    relaSymAddrsPlt = (long *)malloc(r_syms_num * sizeof(long));
    if(!relaSymAddrsPlt){
        free(relas);
        relas = NULL;
        free(r_syms);
        r_syms = NULL;
        free(strsymtbl);
        strsymtbl = NULL;
        free(relaSymAddrsPlt);
        relaSymAddrsPlt = NULL;
        return -1;
    }
    memset(relaSymAddrsPlt, 0, r_syms_num * sizeof(long));

    LOG(LOG_DEBUG, "Relo-sechdr size<%d>, entsize<%d>, offset<%d>", sechdr_rela->sh_size, sechdr_rela->sh_entsize, sechdr_rela->sh_offset);
    for (relaidx=0; relaidx< (sechdr_rela->sh_size / sechdr_rela->sh_entsize); relaidx++)
    {
        rela = (Elf_Rela *)((unsigned long)relas + (relaidx*sechdr_rela->sh_entsize));
        base_rel_itm_addr = (void *)((Elf_Addr)rela->r_offset + (Elf_Addr)base_rel_hdr_addr); 
        from_rel_itm_addr = (void *)((Elf_Addr)rela->r_offset + (Elf_Addr)from_rel_hdr_addr); 
        r_symbidx = ELF_R_SYM(rela->r_info);
        r_reltype = ELF_R_TYPE(rela->r_info);
        r_sym = &(r_syms[r_symbidx]);
        const char *name2 = (r_sym->st_name > 0) ? &strsymtbl[r_sym->st_name] : "";
        name2 = (name2==0)? "" : name2;
        Elf_Addr sh_offset = 0;
        /* the symbols have been done with type SHN_COMMON */
        /*
        if( SHN_COMMON == r_sym->st_shndx) {
            LOG(LOG_ERR, "Relo-symbol symbol<%s> is in SHN_COMMON<%u>, i haven't find out how to solve it, so don't support!", name2, SHN_COMMON);
            LOG(LOG_ERR, "Relo-symbol symbol<%s> , please INIT IT WITH NONE ZERO VALUE!", name2);
            sym_un_res_cnt++;
            continue;
        }else if( li->ei.sechdr_idx_bss == r_sym->st_shndx) {
            LOG(LOG_ERR, "Relo-symbol symbol<%s> is in .bss<%u>, i haven't find out how to solve it, so don't support!", name2, li->ei.sechdr_idx_bss);
            LOG(LOG_ERR, "Relo-symbol symbol<%s> , please INIT IT WITH NONE ZERO VALUE!", name2);
            sym_un_res_cnt++;
            continue;
        }*/
        /* if( SHN_COMMON == r_sym->st_shndx ||  li->ei.sechdr_idx_bss == r_sym->st_shndx) */
        if( SHN_COMMON == r_sym->st_shndx || li->ei.sechdrs_types[r_sym->st_shndx] == ELF_SECT_BSS) {
            if(r_sym->st_size <= 0 ){
                LOG(LOG_INFO, "BSS-Relo-symbol symbol<%s> is in BSS<%u>, and size<%d> is less or equal zero, not support, ignore!", name2, r_sym->st_shndx, r_sym->st_size);
                //sym_un_res_cnt++;
                continue;
            }
            /* already allocate memory for bss value */
            if( relaSymAddrs[r_symbidx]  != 0 ){
                base_symbol_addr = relaSymAddrs[r_symbidx];
                LOG(LOG_DEBUG, "BSS-Relo-idx<%d>tp<%d>smbidx<%d>smbshidx<%d>oldsmb<%s>smbvl<%p> t_base<%p>rtsymadr<%p>rela<%p> symsize<%d> inbssoffsetbase<%p>", 
                                relaidx, r_reltype, r_symbidx, r_sym->st_shndx,name2, r_sym->st_value, inruntimebase, base_symbol_addr, rela, r_sym->st_size, inbssoffsetbase);
            } else {
               /* allocate memory for new find bss value */
                base_symbol_addr = (Elf_Addr)inbssoffsetbase;
                relaSymAddrs[r_symbidx] = base_symbol_addr;
                inbssoffsetbase = (void *)((Elf_Addr)inbssoffsetbase + (Elf_Addr)(r_sym->st_size));
                LOG(LOG_DEBUG, "BSS-Relo-idx<%d>tp<%d>smbidx<%d>smbshidx<%d>newsmb<%s>smbvl<%p> t_base<%p>rtsymadr<%p>rela<%p> symsize<%d> inbssoffsetbase<%p>", 
                                relaidx, r_reltype, r_symbidx, r_sym->st_shndx,name2, r_sym->st_value, inruntimebase, base_symbol_addr, rela, r_sym->st_size, inbssoffsetbase);
                if(inbssoffsetbase > inbssoffsetend) {
                    LOG(LOG_ERR, "BSS-Relo-symbol symbol<%s> is in BSS<%u>, and size<%d> exceed limit <%d>!", name2, r_sym->st_shndx, r_sym->st_size, li->bsslen);
                    sym_un_res_cnt++;
                    continue;
                }
            }
        } else{
            Elf_Shdr * r_sym_hdr = &((Elf_Shdr *)(li->ei.sechdrs))[r_sym->st_shndx];
            sh_offset = r_sym_hdr->sh_offset;
            base_symbol_addr = (Elf_Addr)inruntimebase + (Elf_Addr)r_sym->st_value + (Elf_Addr)sh_offset;
            LOG(LOG_DEBUG, "Relo-idx<%d>tp<%d>smbidx<%d>smbshidx<%d>smb<%s>smbvl<%p>smbhdroff<%p>rt_base<%p>rtsymadr<%p>rela<%p>", 
                            relaidx, r_reltype, r_symbidx, r_sym->st_shndx,name2, r_sym->st_value, sh_offset, inruntimebase, base_symbol_addr, rela);
        }

        /* undefine in obj file, find from outside */
        if(r_sym->st_shndx == SHN_UNDEF){
            if(r_sym->st_name <= 0){
                LOG(LOG_ERR, "Relo-symbol symbol<%s> unsupport: symbol name idx<%d>", name2, r_sym->st_name);
                sym_un_res_cnt++;
                continue;
            }
            if ((STB_GLOBAL != ELF_ST_BIND(r_sym->st_info))
                && (STB_WEAK != ELF_ST_BIND(r_sym->st_info)))
            {
                LOG(LOG_ERR, "Relo-symbol symbol<%s> unsupport: BIND<%u> not STB_GLOBAL<%d> STB_WEAK<%d>", name2, ELF_ST_BIND(r_sym->st_info), STB_GLOBAL, STB_WEAK);
                sym_un_res_cnt++;
                continue;
            }
            if ((ELF_ST_TYPE(r_sym->st_info) == STT_SECTION)
                || (ELF_ST_TYPE(r_sym->st_info) == STT_FILE))
            {
                /* section has been handled before */
                LOG(LOG_ERR, "Relo-symbol symbol<%s> has been handled before, TYPE<%u> is STT_SECTION<%d> STT_FILE<%d>", name2, ELF_ST_TYPE(r_sym->st_info), STT_SECTION, STT_FILE);
                relacnt++;
                continue;
            }
            shtype = LNK_SH_TYPE_EITHER;
            if (ELF_ST_TYPE(r_sym->st_info) == STT_FUNC) {
                shtype = LNK_SH_TYPE_FUN;
            }else if(ELF_ST_TYPE(r_sym->st_info) == STT_OBJECT){
                shtype = LNK_SH_TYPE_OBJ;
            }
            if( (base_symbol_addr = linkable_elf_rsv_symbol(li, name2, &symbolsize, shtype, pat_symbol) ) <= 0 ){
                LOG(LOG_ERR, "Relo-symbol-external symbol<%s> doesn't find, Un-Resolved!", name2);
                sym_un_res_cnt++;
                continue;
            }else{
                LOG(LOG_DEBUG, "Relo-symbol-external sym<%s> rt_sym_addr:S<%p> rt_rel_itm_addr:P<%p> from_rel_itm_addr:A<%p>", 
                    name2, base_symbol_addr, base_rel_itm_addr, from_rel_itm_addr);
            }
            if(base_symbol_addr <= 0){
                LOG(LOG_ERR, "Relo-symbol-external symbol<%s> need retry, but we don't support!", name2);
                sym_un_res_cnt++;
                continue;
            }
        }
        else 
        {
            if(base_symbol_addr <= 0){
                LOG(LOG_ERR, "Relo-symbol-internal symbol<%s> need retry, but we don't support!", name2);
                sym_un_res_cnt++;
                continue;
            }
            LOG(LOG_DEBUG, "Relo-symbol-internal sym<%s> rt_sym_addr:S<%p> rt_rel_itm_addr:P<%p> from_rel_itm_addr:A<%p>", 
                name2, base_symbol_addr, base_rel_itm_addr, from_rel_itm_addr);
        }
        /* NONEED!! linkable_elf_rsv_upd_sym_addr(li, r_sym, (uintptr_t)base_symbol_addr); */
        hf = (struct linkable_elf_hook_fun *)linkable_elf_find_hookfun(li, name2);
        if(hf != NULL){
            /* This function need be hooked, so we redirect the inner call jump to "origfunhead", set base_symbol_addr->"origfunhead"  */
            base_symbol_addr = LNK_HOOK_FUN_ORIGFUNHEAD_ENTRY((Elf_Addr)li->base_rephdr_ptr, hf->idx);
            LOG(LOG_DEBUG, "Relo-symbol-hooked sym<%s> base_rephdr_ptr:<%p> CHANGED_rt_sym_addr:S<%p> rt_rel_itm_addr:P<%p> from_rel_itm_addr:A<%p>", 
                name2, li->base_rephdr_ptr, base_symbol_addr, base_rel_itm_addr, from_rel_itm_addr);
        }
        switch(r_reltype)
        {
#if __WORDSIZE == 64
            case R_X86_64_GOTPCREL: //word32 0x9  (G+GOT) + A - P
                S      = (Elf_Addr)base_symbol_addr;
                P      = (Elf_Addr)base_rel_itm_addr;
                P_FROM = (Elf_Addr)from_rel_itm_addr;
                if (inruntimebase && li->objptr)
                {
					/* already allocate memory for GOT value */
		            if( relaSymAddrsPlt[r_symbidx]  != 0 ){
						got_g_symbol_addr = relaSymAddrsPlt[r_symbidx];
                        LOG(LOG_DEBUG, "GOT-Relo-idx<%d>tp<%d>smbidx<%d>smbshidx<%d>oldsmb<%s>smbvl<%p> t_base<%p>rtsymadr<%p>rela<%p> symsize<%d> inpltgotoffsetbase<%p>", 
                                relaidx, r_reltype, r_symbidx, r_sym->st_shndx,name2, r_sym->st_value, inruntimebase, base_symbol_addr, rela, r_sym->st_size, inpltgotoffsetbase);
		            }
					else
					{
		               /* allocate memory for new find GOT value */
					    got_g_symbol_item = (struct linkable_elf_pltgot_item *)((char *)li->objptr + (long)LNK_PLTGOT_BASE_OFFSET_IN_OBJ(li->objlen) + (long)inpltgotoffsetbase - (long)li->pltgotptr);
					    const char *g_pMac = "\xff\x25\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0";
						const int N_OFFSET2 = 6;
						memcpy((char *)got_g_symbol_item, g_pMac, N_OFFSET2);
						got_g_symbol_item->addrlong = S;
		                got_g_symbol_addr = (Elf_Addr)inpltgotoffsetbase + (Elf_Addr)LNK_ELF_PLTGOT_ADDRLONG_OFFSET;
		                relaSymAddrsPlt[r_symbidx] = got_g_symbol_addr;
		                inpltgotoffsetbase = (void *)((Elf_Addr)inpltgotoffsetbase + (Elf_Addr)(sizeof(struct linkable_elf_pltgot_item)));
		                LOG(LOG_DEBUG, "GOT-Relo-idx<%d>tp<%d>smbidx<%d>smbshidx<%d>newsmb<%s>smbvl<%p> t_base<%p>rtsymadr<%p>rela<%p> symsize<%d> inpltgotoffsetbase<%p>", 
		                                relaidx, r_reltype, r_symbidx, r_sym->st_shndx,name2, r_sym->st_value, inruntimebase, base_symbol_addr, rela, r_sym->st_size, inpltgotoffsetbase);
		                if(inpltgotoffsetbase > inpltgotoffsetend) {
		                    LOG(LOG_ERR, "GOT-Relo-symbol symbol<%s> is in GOT<%u>, value<%p> exceed limit <%p>!", name2, r_sym->st_shndx, inpltgotoffsetbase, inpltgotoffsetend);
		                    sym_un_res_cnt++;
		                    break;
		                }
					}
                    if (sechdr_rela->sh_entsize == sizeof(Elf_Rela))
                    {
                        A = rela->r_addend;
                    }
                    else
                    {
                        A  = *(Elf_Addr*)P_FROM;
                    }
					/*got_g_symbol_addr = G + GOT*/
                    RV = got_g_symbol_addr + A - P;
                    /* *(Elf_Addr *)P = RV; */
                    *(Elf32_Addr*)P_FROM = (Elf32_Addr)RV;
                }
                else
                {
                    A  = 0;
                    RV = 0;
                }
                relacnt++;
                LOG(LOG_DEBUG, "Relo-type R_X86_64_GOTPCREL:<%d>, smb<%s> G+GOT:%p S(sAd):%p P:%p A(*P):%p <(G+GOT)+A-P>(N*P):%p",
                    r_reltype, name2, got_g_symbol_addr, S, P, A, RV);
                break;
				
            case R_X86_64_PLT32: //word32 0x9  L + A - P
                S      = (Elf_Addr)base_symbol_addr;
                P      = (Elf_Addr)base_rel_itm_addr;
                P_FROM = (Elf_Addr)from_rel_itm_addr;
                if (inruntimebase && li->objptr)
                {
					/* already allocate memory for PLT value */
		            if( relaSymAddrsPlt[r_symbidx]  != 0 ){
						got_g_symbol_addr = relaSymAddrsPlt[r_symbidx];
                        LOG(LOG_DEBUG, "PLT-Relo-idx<%d>tp<%d>smbidx<%d>smbshidx<%d>oldsmb<%s>smbvl<%p> t_base<%p>rtsymadr<%p>rela<%p> symsize<%d> inpltgotoffsetbase<%p>", 
                                relaidx, r_reltype, r_symbidx, r_sym->st_shndx,name2, r_sym->st_value, inruntimebase, base_symbol_addr, rela, r_sym->st_size, inpltgotoffsetbase);
		            }
					else
					{
		               /* allocate memory for new find PLT value */
					    got_g_symbol_item = (struct linkable_elf_pltgot_item *)((char *)li->objptr + (long)LNK_PLTGOT_BASE_OFFSET_IN_OBJ(li->objlen) + (long)inpltgotoffsetbase - (long)li->pltgotptr);
					    const char *g_pMac = "\xff\x25\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0";
						const int N_OFFSET2 = 6;
						memcpy((char *)got_g_symbol_item, g_pMac, N_OFFSET2);
						got_g_symbol_item->addrlong = S;
		                got_g_symbol_addr = (Elf_Addr)inpltgotoffsetbase;
						relaSymAddrsPlt[r_symbidx] = got_g_symbol_addr;
		                inpltgotoffsetbase = (void *)((Elf_Addr)inpltgotoffsetbase + (Elf_Addr)(sizeof(struct linkable_elf_pltgot_item)));
		                LOG(LOG_DEBUG, "PLT-Relo-idx<%d>tp<%d>smbidx<%d>smbshidx<%d>newsmb<%s>smbvl<%p> t_base<%p>rtsymadr<%p>rela<%p> symsize<%d> inpltgotoffsetbase<%p>", 
		                                relaidx, r_reltype, r_symbidx, r_sym->st_shndx,name2, r_sym->st_value, inruntimebase, base_symbol_addr, rela, r_sym->st_size, inpltgotoffsetbase);
		                if(inpltgotoffsetbase > inpltgotoffsetend) {
		                    LOG(LOG_ERR, "PLT-Relo-symbol symbol<%s> is in GOT<%u>, value<%p> exceed limit <%p>!", name2, r_sym->st_shndx, inpltgotoffsetbase, inpltgotoffsetend);
		                    sym_un_res_cnt++;
		                    break;
		                }
					}
                    if (sechdr_rela->sh_entsize == sizeof(Elf_Rela))
                    {
                        A = rela->r_addend;
                    }
                    else
                    {
                        A  = *(Elf_Addr*)P_FROM;
                    }
					/*got_g_symbol_addr = L*/
                    RV = got_g_symbol_addr + A - P;
                    /* *(Elf_Addr *)P = RV; */
                    *(Elf32_Addr*)P_FROM = (Elf32_Addr)RV;
                }
                else
                {
                    A  = 0;
                    RV = 0;
                }
                relacnt++;
                LOG(LOG_DEBUG, "Relo-type R_X86_64_PLT32:<%d>, smb<%s> G+GOT:%p S(sAd):%p P:%p A(*P):%p <L+A-P>(N*P):%p",
                    r_reltype, name2, got_g_symbol_addr, S, P, A, RV);
                break;
				
            case R_X86_64_64: // word64 same with R_386_32 = 0x1
                S      = (Elf_Addr)base_symbol_addr;
                P      = (Elf_Addr)base_rel_itm_addr;
                P_FROM = (Elf_Addr)from_rel_itm_addr;
                if (inruntimebase && li->objptr)
                {
                    if (sechdr_rela->sh_entsize == sizeof(Elf_Rela))
                    {
                        A = rela->r_addend;
                    }
                    else
                    {
                        A  = *(Elf_Addr*)P_FROM;
                    }
                    RV = S + A;
                    /* *(Elf_Addr *)P = RV; */
                    *(Elf_Addr*)P_FROM = (Elf_Addr)RV;
                }
                else
                {
                    A  = 0;
                    RV = 0;
                }
                relacnt++;
                LOG(LOG_DEBUG, "Relo-type R_X86_64_64:<%d>, smb<%s> S(sAd):%p P:%p A(*P):%p <S+A>(N*P):%p",
                    r_reltype, name2, S, P, A, RV);
                break;
                
            case R_X86_64_32: //word32 0xa
                S      = (Elf_Addr)base_symbol_addr;
                P      = (Elf_Addr)base_rel_itm_addr;
                P_FROM = (Elf_Addr)from_rel_itm_addr;
                if (inruntimebase && li->objptr)
                {
                    if (sechdr_rela->sh_entsize == sizeof(Elf_Rela))
                    {
                        A = rela->r_addend;
                    }
                    else
                    {
                        A  = *(Elf_Addr*)P_FROM;
                    }
                    RV = S + A;
                    /* *(Elf_Addr *)P = RV; */
                    *(Elf32_Addr*)P_FROM = (Elf32_Addr)RV;
                }
                else
                {
                    A  = 0;
                    RV = 0;
                }
                relacnt++;
                LOG(LOG_DEBUG, "Relo-type R_X86_64_32:<%d>, smb<%s> S(sAd):%p P:%p A(*P):%p <S+A>(N*P):%p",
                    r_reltype, name2, S, P, A, RV);
                break;
#else
            case R_386_32: /* word32 *P = S + *P */  /* S + A */
                S      = (Elf_Addr)base_symbol_addr;
                P      = (Elf_Addr)base_rel_itm_addr;
                P_FROM = (Elf_Addr)from_rel_itm_addr;
                if (inruntimebase && li->objptr)
                {
                    if (sechdr_rela->sh_entsize == sizeof(Elf_Rela))
                    {
                        A = rela->r_addend;
                    }
                    else
                    {
                        A  = *(Elf_Addr*)P_FROM;
                    }
                    RV = S + A;
                    /* *(Elf_Addr *)P = RV; */
                    *(Elf32_Addr*)P_FROM =  (Elf32_Addr)RV;
                }
                else
                {
                    A  = 0;
                    RV = 0;
                }
                relacnt++;
                LOG(LOG_DEBUG, "Relo-type R_386_32:<%d>, smb<%s> S(sAd):%p P:%p A(*P):%p <S+A>(N*P):%p",
                    r_reltype, name2, S, P, A, RV);
                break;
 #endif
            //case R_X86_64_PC32: //word32 0x2
        case R_386_PC32: /* word32 *P = S + *P - P */  /* S + A - P */
                S      = (Elf_Addr)base_symbol_addr;
                P      = (Elf_Addr)base_rel_itm_addr;
                P_FROM = (Elf_Addr)from_rel_itm_addr;
                if(inruntimebase && li->objptr){
                    if(sechdr_rela->sh_entsize == sizeof(Elf_Rela)){
                        A = rela->r_addend;
                        LOG(LOG_DEBUG, "Relo-type R_386_PC32:<%d>, smb<%s> r_addend<%p> A<%p>", r_reltype, name2, rela->r_addend, A);
                    }
                    else
                    {
                        A  = *(Elf_Addr*)P_FROM;
                        LOG(LOG_DEBUG, "Relo-type R_386_PC32:<%d>, smb<%s> P_FROM<%p> A<%p>", r_reltype, name2, P_FROM, A);
                    }
                    RV = S + A - P;
                    /* *(Elf_Addr *)P = RV; */
                    *(Elf32_Addr*)P_FROM = (Elf32_Addr)RV;
                }
                else
                {
                    A  = 0;
                    RV = 0;
                }
                relacnt++;
                LOG(LOG_DEBUG, "Relo-type R_386_PC32:<%d>, smb<%s> S(sAd):%p P:%p A(*P):%p <S+A-P>(N*P):%p",
                    r_reltype, name2, S,  P, A, RV);
                break;
#if 0
            case R_386_GOT32:
                LOG(LOG_DEBUG, "Relo-type R_386_GOT32: <%d>", r_reltype);
                break;
            case R_386_PLT32:
                LOG(LOG_DEBUG, "Relo-type R_386_PLT32: <%d>", r_reltype);
                break;
            case R_386_COPY:
                LOG(LOG_DEBUG, "Relo-type R_386_COPY: <%d>", r_reltype);
                break;
            case R_386_GLOB_DAT:
                LOG(LOG_DEBUG, "Relo-type R_386_GLOB_DAT: <%d>", r_reltype);
                break;
            case R_386_JMP_SLOT:
                LOG(LOG_DEBUG, "Relo-type R_386_JMP_SLOT: <%d>", r_reltype);
                break;
            case R_386_RELATIVE:
                LOG(LOG_DEBUG, "Relo-type R_386_RELATIVE: <%d>", r_reltype);
                break;
            case R_386_GOTOFF:
                LOG(LOG_DEBUG, "Relo-type R_386_GOTOFF: <%d>", r_reltype);
                break;
                /*case R_386_GOT_PC:
                    LOG(LOG_DEBUG, "Relo-type R_386_GOT_PC: <%d>", r_reltype);
                    break; */
            default:
                LOG(LOG_ERR, "Relo-type unknown: <%d>", r_reltype);
#endif
            default:
                LOG(LOG_ERR, "Relo-type unknown: <%d>", r_reltype);
                sym_un_res_cnt++;
                break;
        }
    }
    free(relas);
    relas = NULL;
    free(r_syms);
    r_syms = NULL;
    free(strsymtbl);
    strsymtbl = NULL;
    free(relaSymAddrs);
    relaSymAddrs = NULL;
    if (relacnt == 0 || sym_un_res_cnt != 0)
    {
        LOG(LOG_ERR, "Relocate total count zero (%u) or has (%u) Un-Resolved symbols!!", relacnt, sym_un_res_cnt);
        return -1;
    }
    LOG(LOG_DEBUG, "Relocate total count %d.", relacnt);
    return 0;
}

static int linkable_elf_is_has_innersymbol(struct linkable_elf_internals *li, char *name)
{
    int find = FALSE;
    size_t idx = 0;
    Elf_Sym  *sym     = NULL; 
    struct symbol_elf_sym * symbol = NULL;
    
    for(idx = 0; idx < li->ei.symbols_num; idx++)
    {
        symbol = &(li->ei.symbols[idx]);
        sym = &(symbol->sym);
        if(sym->st_shndx == SHN_UNDEF)
        {
            continue;
        }
        /*
        if(sym->st_shndx != li->ei.sechdr_idx_text){
            continue;
        } */
        if(sym->st_shndx >= li->ei.sechdr_num) {
            continue;
        }
        if( li->ei.sechdrs_types[sym->st_shndx] != ELF_SECT_TEXT){
            continue;
        }
        if(ELF_ST_TYPE(sym->st_info) != STT_FUNC){
            continue;
        }
        if(strcmp(name, symbol->name) == 0){
            find = TRUE;
            break;
        }
    }
    return find;
}

static int linkable_elf_build_hookfuns(struct linkable_elf_internals *li, const char *pat_symbol)
{
    int rc = 0;
    size_t idx = 0;
    Elf_Sym  *sym     = NULL; 
    Elf_Shdr * sym_hdr = NULL;
    int shtype = 0;
    struct symbol_elf_sym * symbol = NULL;
    struct linkable_elf_hook_fun *hf = NULL;
    Elf_Addr symbol_addr = 0;
    Elf_Addr old_symbol_addr = 0;
    char *old_symbol_name = NULL;
    size_t old_symbol_size = 0;
    size_t old_name_len = 0;
    size_t name_len = 0;

    if(!li || !li->ei.symbols || !li->ei.sechdrs){
        rc = -1;
        return rc;
    }
    
    li->rephdr.hookfuns_num = 0;
    for(idx = 0; idx < li->ei.symbols_num; idx++)
    {
        symbol = &(li->ei.symbols[idx]);
        sym = &(symbol->sym);
        LOG(LOG_DEBUG, "Hook-Info-Find smb<%s> add<%p> size<%u> shndx<%u> type<%u> bind<%u>.", 
            symbol->name, symbol->address, symbol->size, sym->st_shndx, ELF_ST_TYPE(sym->st_info), ELF_ST_BIND(sym->st_info));
        if(sym->st_shndx == SHN_UNDEF)
        {
            LOG(LOG_DEBUG, "Hook-Info-Ignore smb<%s> shndx<%u> is SHN_UNDEF<%u>",
                symbol->name, sym->st_shndx, SHN_UNDEF);
            continue;
        }
        /*
        if(sym->st_shndx != li->ei.sechdr_idx_text){
            LOG(LOG_DEBUG, "Rep-Fun-Ignore smb<%s> shndx<%u> != .text<%u>",
                symbol->name, sym->st_shndx, li->ei.sechdr_idx_text);
            continue;
        }*/
        if( sym->st_shndx >= li->ei.sechdr_num  ||  li->ei.sechdrs_types[sym->st_shndx] != ELF_SECT_TEXT){
            LOG(LOG_DEBUG, "Rep-Fun-Ignore smb<%s> shndx<%u> != .text<%u>",
                symbol->name, sym->st_shndx, li->ei.sechdr_idx_text);
            continue;
        }
        if(ELF_ST_TYPE(sym->st_info) != STT_FUNC){
            LOG(LOG_DEBUG, "Hook-Info-Ignore smb<%s> type<%u> != STT_FUNC<%u>",
                symbol->name, ELF_ST_TYPE(sym->st_info), STT_FUNC);
            continue;
        }
        sym_hdr = &((Elf_Shdr *)(li->ei.sechdrs))[sym->st_shndx];
        if(!sym->st_size || !((Elf_Addr)sym->st_value + (Elf_Addr)sym_hdr->sh_offset) || !sym->st_name){
            LOG(LOG_DEBUG, "Hook-Info-Ignore smb<%s> nameidx<%u> value<%p> hdroff<%p> size<%u>, one of them is NULL.",
                symbol->name, sym->st_name, sym->st_value, sym_hdr->sh_offset, sym->st_size);
            continue;
        }
        if(strlen(symbol->name) <= strlen(LNK_HOOK_FUN_NAME_PREFIX)){
            LOG(LOG_DEBUG, "Hook-Info-Ignore smb<%s> doesn't match prefix <LNK_HOOK_FUN_NAME_PREFIX:%s>.", 
                           symbol->name, LNK_HOOK_FUN_NAME_PREFIX);
            continue;
        }
        if(strstr(symbol->name, LNK_HOOK_FUN_NAME_PREFIX) != symbol->name){
            LOG(LOG_DEBUG, "Hook-Info-Ignore smb<%s> doesn't match prefix <LNK_HOOK_FUN_NAME_PREFIX:%s>.", 
                           symbol->name, LNK_HOOK_FUN_NAME_PREFIX);
            continue;
        }
        old_symbol_name = symbol->name + strlen(LNK_HOOK_FUN_NAME_PREFIX);
        LOG(LOG_INFO, "Hook-Info-Find smb<%s> orgsmb<%s> match prefix <LNK_HOOK_FUN_NAME_PREFIX:%s>.", 
                       symbol->name, old_symbol_name, LNK_HOOK_FUN_NAME_PREFIX);
        if(TRUE == linkable_elf_is_has_innersymbol(li, old_symbol_name)){
            LOG(LOG_INFO, "Hook-Info-Ignore smb<%s> is find inner obj-file, that's doesn't support!", 
                           old_symbol_name);
            continue;
        }
        shtype = LNK_SH_TYPE_FUN;
        if( (old_symbol_addr = linkable_elf_rsv_symbol_repable(li, old_symbol_name, &old_symbol_size, shtype) ) <= 0 ){
            if ((old_symbol_addr = linkable_elf_pat_repable(old_symbol_name, pat_symbol, &old_symbol_size, 1)) <= 0){
                LOG(LOG_INFO, "Hook-Info-Ignore smb<%s> un-resolved.", old_symbol_name);
                continue;
            }
        }
        symbol_addr = (Elf_Addr)li->baseptr + (Elf_Addr)sym->st_value + (Elf_Addr)sym_hdr->sh_offset;
        LOG(LOG_INFO, "Hook-Info-NeedHook oldsmb<%s> oldaddr<%p> oldsize<%u> newsmb<%s> newaddr<%p> newsize<%u> baseptr<%p> stv<%p> shoff<%p>.", 
                       old_symbol_name, old_symbol_addr, old_symbol_size, symbol->name, symbol_addr, symbol->size,
                       li->baseptr, sym->st_value, sym_hdr->sh_offset);
        if(li->rephdr.hookfuns_num>= LNK_MAX_HOOK_FUNC_COUNT){
            LOG(LOG_DEBUG, "Hook-Info-Ignore smb<%s> hookfunum<%u> exceed MAX<%u>.", old_symbol_name, li->rephdr.hookfuns_num, LNK_MAX_HOOK_FUNC_COUNT);
            continue;
        }
        name_len     = strlen(symbol->name) + 1;
        old_name_len = strlen(old_symbol_name) + 1;
        hf = &(li->rephdr.hookfuns[li->rephdr.hookfuns_num]);
        strncpy(hf->newname, symbol->name, (name_len>LNK_MAX_NAME_LEN)?LNK_MAX_NAME_LEN:name_len);
        strncpy(hf->oldname, old_symbol_name, (old_name_len>LNK_MAX_NAME_LEN)?LNK_MAX_NAME_LEN:old_name_len);
        hf->newname[LNK_MAX_NAME_LEN-1] = '\0';
        hf->oldname[LNK_MAX_NAME_LEN-1] = '\0';
        hf->newaddr = (long)symbol_addr;
        hf->newsize = symbol->size;
        hf->oldaddr = (long)old_symbol_addr;
        hf->oldsize = old_symbol_size;
        hf->idx     = li->rephdr.hookfuns_num;
        li->rephdr.hookfuns_num++;
        /*
        LOG(LOG_INFO, "Hook-Info-Hook newsmb<%s> oldsmb<%s> idx<%u>.", hf->newname, hf->oldname, hf->idx);
        */
    }
    return rc;
}

static int linkable_elf_build_rela_info(struct linkable_elf_internals *li)
{
    int rc = 0;
    size_t idx = 0;
    size_t secidx = 0;
    size_t relahdr_num = 0;
    Elf_Shdr *sechdrs = NULL;

    if (!li || !li->ei.sechdrs || !li->ei.sechdr_num)
        return -1;
    
    sechdrs = (Elf_Shdr *)li->ei.sechdrs;
    
    for(secidx = 0 ; secidx < li->ei.sechdr_num; secidx++){
        if(SHT_RELA == sechdrs[secidx].sh_type){
            relahdr_num++;
        }
        if( (SHT_REL == sechdrs[secidx].sh_type) 
            /* && ((EM_386 == li->ei.machine) 
               || (EM_MIPS == li->ei.machine)
               || (EM_ARM == li->ei.machine))*/ ) {
            relahdr_num++;
        }
    }

    if(0 == relahdr_num){
        LOG(LOG_ERR, "Relocation section header not found.");
        return -1;
    }
    
        li->relahdr_infos = (struct linkable_elf_rela_info *)malloc(relahdr_num * sizeof(struct linkable_elf_rela_info));
        if (!li->relahdr_infos) {
                LOG(LOG_ERR, "malloc error: size %d, %s", relahdr_num * sizeof(struct linkable_elf_rela_info), strerror(errno));
                return -1;
        }
        memset(li->relahdr_infos, 0, relahdr_num * sizeof(struct linkable_elf_rela_info));

    idx = 0;
    for(secidx = 0, idx=0 ; (secidx < li->ei.sechdr_num) && (idx < relahdr_num); secidx++){
        if(SHT_RELA == sechdrs[secidx].sh_type){
            li->relahdr_infos[idx].sechdr_idx  = secidx;
            li->relahdr_infos[idx].sechdr_type = sechdrs[secidx].sh_type;
            /* li->relahdr_infos[idx].sechdr_dst_idx = sechdrs[secidx].sh_info; */
            li->relahdr_infos[idx].sechdr_sym_idx = sechdrs[secidx].sh_link;
            li->relahdr_infos[idx].sechdr_str_idx = sechdrs[sechdrs[secidx].sh_link].sh_link;
            idx++;
            const char *name = &li->ei.strsectbl[sechdrs[secidx].sh_name];
            if(name){
                LOG(LOG_DEBUG, "Find relocation section %s offset: %p [idx:%u,type:%u,info/dstidx:%u]",
                               name, sechdrs[secidx].sh_offset, secidx, sechdrs[secidx].sh_type, sechdrs[secidx].sh_info);
            }else{
                LOG(LOG_DEBUG, "Find relocation section %s offset: %p [idx:%u,type:%u,info/dstidx:%u]",
                               "N/A", sechdrs[secidx].sh_offset, secidx, sechdrs[secidx].sh_type, sechdrs[secidx].sh_info);
            }
        }
        if( (SHT_REL == sechdrs[secidx].sh_type) 
            /* && ((EM_386 == li->ei.machine) 
               || (EM_MIPS == li->ei.machine)
               || (EM_ARM == li->ei.machine))*/ )  {
            li->relahdr_infos[idx].sechdr_idx  = secidx;
            li->relahdr_infos[idx].sechdr_type = sechdrs[secidx].sh_type;
            /* li->relahdr_infos[idx].sechdr_dst_idx = sechdrs[secidx].sh_info; */
            li->relahdr_infos[idx].sechdr_sym_idx = sechdrs[secidx].sh_link;
            li->relahdr_infos[idx].sechdr_str_idx = sechdrs[sechdrs[secidx].sh_link].sh_link;
            idx++;
            const char *name = &li->ei.strsectbl[sechdrs[secidx].sh_name];
            if(name){
                LOG(LOG_DEBUG, "Find relocation section %s offset: %p [idx:%u,type:%u,info/dstidx:%u]",
                               name, sechdrs[secidx].sh_offset, secidx, sechdrs[secidx].sh_type, sechdrs[secidx].sh_info);
            }else{
                LOG(LOG_DEBUG, "Find relocation section %s offset: %p [idx:%u,type:%u,info/dstidx:%u]",
                               "N/A", sechdrs[secidx].sh_offset, secidx, sechdrs[secidx].sh_type, sechdrs[secidx].sh_info);
            }
        }
    }
    li->relahdr_info_num = relahdr_num;
    
    return rc;
}

static int linkable_elf_build_rela_tobuf(struct linkable_elf_internals *li,  const char *pat_symbol)
{
    int rc = 0;
    size_t idx = 0;
    Elf_Shdr *sechdrs = NULL;
    struct linkable_elf_rela_info *relahdr_info = NULL;
    int failnum = 0;

    if (!li || !li->ei.sechdrs || !li->ei.sechdr_num || !li->relahdr_infos || !li->relahdr_info_num)
        return -1;

    LOG(LOG_DEBUG, "Relocatable sections total num %d, start relo...", li->relahdr_info_num);
    sechdrs = (Elf_Shdr *)li->ei.sechdrs;
    for(idx = 0; idx < li->relahdr_info_num; idx++){
        relahdr_info = &(li->relahdr_infos[idx]);
        const char *name = &li->ei.strsectbl[sechdrs[relahdr_info->sechdr_idx].sh_name];
        if(name){
            LOG(LOG_DEBUG, "Processing %d relocatable sections %s offset: %p [idx:%u,type:%u,info/dstidx:%u]",
                           idx, name, sechdrs[relahdr_info->sechdr_idx].sh_offset, relahdr_info->sechdr_idx, 
                           sechdrs[relahdr_info->sechdr_idx].sh_type, sechdrs[relahdr_info->sechdr_idx].sh_info);
        }else{
            LOG(LOG_DEBUG, "Processing %d relocatable sections %s offset: %p [idx:%u,type:%u,info/dstidx:%u]",
                           idx, "N/A", sechdrs[relahdr_info->sechdr_idx].sh_offset, relahdr_info->sechdr_idx, 
                           sechdrs[relahdr_info->sechdr_idx].sh_type, sechdrs[relahdr_info->sechdr_idx].sh_info);
        }
        if( (rc = linkable_elf_rsv_rela(li, relahdr_info, pat_symbol)) < 0){
            LOG(LOG_ERR, "Relocatable sections process failed.");
            failnum++;
        }else{
            LOG(LOG_DEBUG, "Relocatable sections process succeed.");
        }
        LOG(LOG_DEBUG, "Relocatable sections stop relo.");
    }
    if(failnum){
        LOG(LOG_ERR, "Relocatable sections process %u/%u failed.", failnum, li->relahdr_info_num);
        return -1;
    }
    LOG(LOG_DEBUG, "Relocatable sections total num %u.", li->relahdr_info_num);
    return rc;
}

static int linkable_elf_build_repfuns(struct linkable_elf_internals *li, const char *pat_symbol)
{
    int rc = 0;
    size_t idx = 0;
    Elf_Sym  *sym     = NULL; 
    Elf_Shdr * sym_hdr = NULL;
    struct symbol_elf_sym * symbol = NULL;
    Elf_Addr old_symbol_addr = 0;
    Elf_Addr symbol_addr = 0;
    int shtype = 0;
    size_t old_symbol_size = 0;
    struct linkable_elf_rep_fun *rf = NULL; 
    size_t name_len = 0;

    if(!li || !li->ei.symbols || !li->ei.sechdrs){
        rc = -1;
        return rc;
    }
    
    li->rephdr.repfuns_num = 0;
    for(idx = 0; idx < li->ei.symbols_num; idx++)
    {
        symbol = &(li->ei.symbols[idx]);
        sym = &(symbol->sym);
        LOG(LOG_DEBUG, "Rep-Fun-Find smb<%s> add<%p> size<%u> shndx<%u> type<%u> bind<%u>.", 
            symbol->name, symbol->address, symbol->size, sym->st_shndx, ELF_ST_TYPE(sym->st_info), ELF_ST_BIND(sym->st_info));
        if(sym->st_shndx == SHN_UNDEF)
        {
            LOG(LOG_DEBUG, "Rep-Fun-Ignore smb<%s> shndx<%u> is SHN_UNDEF<%u>",
                symbol->name, sym->st_shndx, SHN_UNDEF);
            continue;
        }
        /*
        if(sym->st_shndx != li->ei.sechdr_idx_text){
            LOG(LOG_DEBUG, "Rep-Fun-Ignore smb<%s> shndx<%u> != .text<%u>",
                symbol->name, sym->st_shndx, li->ei.sechdr_idx_text);
            continue;
        }*/
        if( sym->st_shndx >= li->ei.sechdr_num || li->ei.sechdrs_types[sym->st_shndx] != ELF_SECT_TEXT){
            LOG(LOG_DEBUG, "Rep-Fun-Ignore smb<%s> shndx<%u> != .text<%u>",
                symbol->name, sym->st_shndx, li->ei.sechdr_idx_text);
            continue;
        }
        if(ELF_ST_TYPE(sym->st_info) != STT_FUNC){
            LOG(LOG_DEBUG, "Rep-Fun-Ignore smb<%s> type<%u> != STT_FUNC<%u>",
                symbol->name, ELF_ST_TYPE(sym->st_info), STT_FUNC);
            continue;
        }
        sym_hdr = &((Elf_Shdr *)(li->ei.sechdrs))[sym->st_shndx];
        if(!sym->st_size || !((Elf_Addr)sym->st_value + (Elf_Addr)sym_hdr->sh_offset) || !sym->st_name){
            LOG(LOG_DEBUG, "Rep-Fun-Ignore smb<%s> nameidx<%u> value<%p> hdroff<%p> size<%u>, one of them is NULL.",
                symbol->name, sym->st_name, sym->st_value, sym_hdr->sh_offset, sym->st_size);
            continue;
        }
        if(strcmp(PAT_ACT_BEFORE_FUN_NAME, symbol->name) == 0){
            symbol_addr = (Elf_Addr)li->baseptr + (Elf_Addr)sym->st_value + (Elf_Addr)sym_hdr->sh_offset;
            li->rephdr._pat_callback_active_before = symbol_addr;
            LOG(LOG_INFO, "Rep-Fun-Find-Fun smb<%s> addr<%p> ize<%u> baseptr<%p> stv<%p> shoff<%p>.", 
                           symbol->name, symbol_addr, symbol->size, li->baseptr, sym->st_value, sym_hdr->sh_offset);
            continue;
        }
        if(strcmp(PAT_ACT_AFTER_FUN_NAME, symbol->name) == 0){
            symbol_addr = (Elf_Addr)li->baseptr + (Elf_Addr)sym->st_value + (Elf_Addr)sym_hdr->sh_offset;
            li->rephdr._pat_callback_active_after = symbol_addr;
            LOG(LOG_INFO, "Rep-Fun-Find-Fun smb<%s> addr<%p> ize<%u> baseptr<%p> stv<%p> shoff<%p>.", 
                           symbol->name, symbol_addr, symbol->size, li->baseptr, sym->st_value, sym_hdr->sh_offset);
            continue;
        }
        if(strcmp(PAT_DEACT_BEFORE_FUN_NAME, symbol->name) == 0){
            symbol_addr = (Elf_Addr)li->baseptr + (Elf_Addr)sym->st_value + (Elf_Addr)sym_hdr->sh_offset;
            li->rephdr._pat_callback_deactive_before = symbol_addr;
            LOG(LOG_INFO, "Rep-Fun-Find-Fun smb<%s> addr<%p> ize<%u> baseptr<%p> stv<%p> shoff<%p>.", 
                           symbol->name, symbol_addr, symbol->size, li->baseptr, sym->st_value, sym_hdr->sh_offset);
            continue;
        }
        if(strcmp(PAT_DEACT_AFTER_FUN_NAME, symbol->name) == 0){
            symbol_addr = (Elf_Addr)li->baseptr + (Elf_Addr)sym->st_value + (Elf_Addr)sym_hdr->sh_offset;
            li->rephdr._pat_callback_deactive_after = symbol_addr;
            LOG(LOG_INFO, "Rep-Fun-Find-Fun smb<%s> addr<%p> ize<%u> baseptr<%p> stv<%p> shoff<%p>.", 
                           symbol->name, symbol_addr, symbol->size, li->baseptr, sym->st_value, sym_hdr->sh_offset);
            continue;
        }
        shtype = LNK_SH_TYPE_FUN;
        if( (old_symbol_addr = linkable_elf_rsv_symbol_repable(li, symbol->name, &old_symbol_size, shtype) ) <= 0 ){
            if ((old_symbol_addr = linkable_elf_pat_repable(symbol->name, pat_symbol, &old_symbol_size, 1)) <= 0){
            LOG(LOG_DEBUG, "Rep-Fun-Ignore smb<%s> un-resolved.", symbol->name);
            continue;
            }
        }
        symbol_addr = (Elf_Addr)li->baseptr + (Elf_Addr)sym->st_value + (Elf_Addr)sym_hdr->sh_offset;
        LOG(LOG_INFO, "Rep-Fun-NeedRep smb<%s> oldaddr<%p> oldsize<%u> newaddr<%p> newsize<%u> baseptr<%p> stv<%p> shoff<%p>.", 
                       symbol->name, old_symbol_addr, old_symbol_size, symbol_addr, symbol->size,
                       li->baseptr, sym->st_value, sym_hdr->sh_offset);
        if(li->rephdr.repfuns_num >= LNK_MAX_REP_FUNC_COUNT){
            LOG(LOG_ERR, "Rep-Fun-Ignore smb<%s> repfunum<%u> exceed MAX<%u>.", symbol->name, li->rephdr.repfuns_num, LNK_MAX_REP_FUNC_COUNT);
            continue;
        }
        rf = &(li->rephdr.repfuns[li->rephdr.repfuns_num]);
        rf->isreplaced = 0;
        rf->newaddr = (long)symbol_addr;
        rf->newsize = symbol->size;
        rf->oldaddr = (long)old_symbol_addr;
        rf->oldsize = old_symbol_size;
        name_len = strlen(symbol->name) + 1;
        strncpy(rf->name, symbol->name, (name_len>LNK_MAX_NAME_LEN)?LNK_MAX_NAME_LEN:name_len);
        rf->name[LNK_MAX_NAME_LEN-1] = '\0';
        li->rephdr.repfuns_num++;
    }
    return rc;
}

void linkable_elf_obj_destory(struct linkable_elf_internals * li)
{
        LOG(LOG_DEBUG, "Freeing internal structure hp&ei ...");
    if(!li){
        return;
    }
    
    symbol_pid_destroy(li->hp);
    li->hp = NULL;

    symbol_elf_ei_destory(&li->ei, TRUE);
}

struct linkable_elf_internals * linkable_elf_obj_create(pid_t pid, int elang, const char *filename, void * baseptr , void * base_rephdr_ptr, void * bssptr, long bsslen, void * pltgotptr, long pltgotlen, const char *pat_symbol)
{
    int rc = 0;
    struct symbol_elf_pid * hp = NULL;
    void * objptr = NULL;
    size_t objlen  = 0;
    struct linkable_elf_internals *li = NULL;
    do{
        if (pid <= 0) {
                LOG(LOG_ERR, "invalid pid %d.", pid);
                        rc = -1;
                        break;
        }
            
        if(!filename){
            LOG(LOG_ERR, "The file name invalid!");
                        rc = -1;
                        break;
        }

        /*
        if(!baseptr){
            LOG(LOG_ERR, "The baseptr invalid!");
                        rc = -1;
                        break;
        }*/
        
        li = malloc(sizeof(*li));
        if (!li) {
			LOG(LOG_ERR, "malloc error: size %d, %s", sizeof(*li), strerror(errno));
			rc = -1;
			break;
        }
        memset(li, 0, sizeof(*li));

        objptr = linkable_file_read_to_buf(filename, &objlen, pltgotlen + bsslen);
        if(!objptr || !objlen){
            LOG(LOG_ERR, "Unable to read Elf file %s", filename);
            rc = -1;
            break;
        }
        li->objptr = objptr;
        li->objlen = objlen;

        hp = symbol_pid_create(pid, elang);
        if(!hp){
            LOG(LOG_ERR, "Unable to processes PID %u", pid);
                        rc = -1;
                        break;
        }
        LOG(LOG_DEBUG, "Processes PID %u", pid);
        li->hp = hp;

        li->ei.fd = symbol_open_filename(filename);
        if (li->ei.fd < 0) {
            rc = -1;
            break;
        }

        LOG(LOG_DEBUG, "Begin to load Elf details for %s", filename);
        if ((rc = symbol_elf_ei_create_hdrs_symtabs(&(li->ei))) < 0) {
                LOG(LOG_ERR, "Unable to load Elf details for %s", filename);
                        rc = -1;
                        break;
        }
        if((rc = linkable_elf_is_object_type(li)) < 0) {
            LOG(LOG_ERR, "The file is not Elf-linkable format: %s", filename);
                        rc = -1;
                        break;
        }
        if((rc = linkable_elf_build_rela_info(li)) < 0) {
            LOG(LOG_ERR, "The file is not Elf-linkable format: %s", filename);
                        rc = -1;
                        break;
        }
        
        li->baseptr = baseptr;
        li->base_rephdr_ptr = base_rephdr_ptr;
        li->bssptr = bssptr;
        li->bsslen = bsslen;
        li->pltgotptr = pltgotptr;
        li->pltgotlen = pltgotlen;
        //#ifdef TEST_LINKABLE
           //li->baseptr = li->objptr;
           //LOG(LOG_ERR, "**********Set baseptr to objprt %p, for TEST ONLY!!!**********", li->baseptr);
        //#endif
        LOG(LOG_INFO, "The patch symbol filename is %s.", pat_symbol);

        if((rc = linkable_elf_build_hookfuns(li, pat_symbol)) < 0) {
            LOG(LOG_ERR, "The Elf-linkable %s, hook funtion(s) error.", filename);
                        rc = -1;
                        break;
        }
        
        if((rc = linkable_elf_build_rela_tobuf(li, pat_symbol)) < 0) {
            LOG(LOG_ERR, "The Elf-linkable %s, has some symbol(s) can't be resolved.", filename);
                        rc = -1;
                        break;
        }

        if((rc = linkable_elf_build_repfuns(li,pat_symbol)) < 0) {
            LOG(LOG_ERR, "The Elf-linkable %s, build replace funtion list error.", filename);
                        rc = -1;
                        break;
        }
    }while(0);
    if(rc < 0)
    {
        linkable_elf_obj_destory(li);
        li = NULL;
    }
    return li;
}

/*
static int linkable_elf_load_obj_to_pid(pid_t pid, const char *filename, void * baseptr, void * base_rephdr_ptr, void * bssptr,  long bsslen, const char *pat_symbol)
{
    int rc = 0;
        struct linkable_elf_internals *li = NULL;
    li = linkable_elf_obj_create(pid, filename, baseptr, base_rephdr_ptr, bssptr, bsslen, pat_symbol);
    if(li){
        LOG(LOG_INFO, "Load obj to pid done.");
        LOG(LOG_INFO, "Start processing...");
        // TODO: processing
        LOG(LOG_DEBUG, "Freeing internal structure li...");
        linkable_elf_obj_destory(li);
    }else{
        LOG(LOG_ERR, "Error to load obj to pid!");
        rc = -1;
    }
    return rc;
}
*/

static Elf_Addr linkable_elf_pat_repable(const char * symbolname, const char * pat_symbol_file,size_t *outsymbolsize, int type )
{
    Elf_Addr tptr = 0;
    FILE *fp = 0;
    char symbol_para[256] = {0};
    char pat_func_name[256] = {0};
    char pat_func_addr[256] = {0};
    char pat_func_size[256] = {0};
    char *psubstr  = 0;
	int fun_or_obj = 1; 

    //LOG(LOG_DEBUG, "enter func linkable_elf_pat_repable!(%s)", pat_symbol_file);
        
    if((!symbolname) || (!pat_symbol_file))
    {
        LOG(LOG_INFO, "file ptr is null(%s)", pat_symbol_file);  
        return 0; 
    }

    if (0 == strlen(pat_symbol_file))
    {
        LOG(LOG_INFO, "file is not exist(%s)", pat_symbol_file);  
        return 0;
    }

    fp = fopen(pat_symbol_file, "rb");
    if(0 == fp){
         LOG(LOG_ERR, "open file(%s) : %s", pat_symbol_file, strerror(errno));
         return 0;
    }

    while (VOS_NULL_PTR != fgets(symbol_para, 256, fp))
    {   
        if (1 == type)
        {
            if (0!=strstr(symbol_para,"Function name")) 
            {
				/*IS FUNC*/
				fun_or_obj = 1;
            }
			else
			{
				continue;
			}
        }
        else
        {
			fun_or_obj = -1;
            if( 0!=strstr(symbol_para,"Function name") )
            {
				fun_or_obj = 1;
            }

			if( 0!=strstr(symbol_para,"Data name") )
            {
				fun_or_obj = 0;
            }
			if( 0!=fun_or_obj && 1!=fun_or_obj )
			{
				continue;
			}
        }

        psubstr = strstr(symbol_para,":");
        strcpy(pat_func_name,(psubstr+2));
        trimstr(pat_func_name);

        LOG(LOG_DEBUG, "symbol_para (%s). pat_func_name (%s)", symbolname, pat_func_name);

        if(0==(strcmp(symbolname,pat_func_name)))
        {
            /*��ȡ���ŵ�ַ*/
            memset(symbol_para,0,256);
            fgets(symbol_para, 256, fp);
            psubstr = strstr(symbol_para,":");
            strcpy(pat_func_addr,(psubstr+2));
            trimstr(pat_func_addr);

            if( 1 == fun_or_obj ) /*IS FUNC*/
            {
	            /*��ȡ����size*/
	            memset(symbol_para,0,256);
	            fgets(symbol_para, 256, fp);

	            memset(symbol_para,0,256);
	            fgets(symbol_para, 256, fp);
	            psubstr = strstr(symbol_para,":");
	            strcpy(pat_func_size,(psubstr+2));
	            trimstr(pat_func_size);

	            tptr = (Elf_Addr)strtol(pat_func_addr,NULL,16);
	            *outsymbolsize = strtol(pat_func_size,NULL,16);
            }
			else
			{
				tptr = (Elf_Addr)strtol(pat_func_addr,NULL,16);
				*outsymbolsize = 1; /*���ݣ����дһ���������*/
			}
            
            LOG(LOG_DEBUG, "find patch func. name (%s), addr (%p), size (%u)", pat_func_name,tptr,*outsymbolsize);
            
            break;
        }
    }

    fclose(fp);
    return tptr;
    
}

#ifdef TEST_LINKABLE
int main(int argc, char *argv[])
{
        if (argc < 3) {
                printf("usage: %s <pid> <obj>\n" , argv[0]);
                exit(-1);
        }
        
        int pid = atoi(argv[1]);
    char * filename = argv[2];
        
        linkable_elf_load_obj_to_pid(pid, filename, 0, 0, 0, 0, 0);

        return 0;
}
#endif

