/*
 * Copyright (c) 2011, 2012 The University of Utah
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <assert.h>
#include <sysexits.h>
#include <err.h>

#include <dwarf.h>
#include <gelf.h>
#include <elfutils/libebl.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libeblP.h>
#include <elfutils/memory-access.h>

#include "offset.h"

char conf_sysmap[PATH_MAX];
char conf_debuginfo[PATH_MAX];

/* this avoid searching for "base.c" repeatedly */
static Dwarf_Off base_from, base_to;

enum {
    DW_REQ_scope = 0x1,
    DW_REQ_level = 0x2,
    DW_REQ_offset = 0x4,
    DW_REQ_sibling = 0x8,
    DW_REQ_tag = 0x10,
    DW_REQ_name = 0x20,
    DW_REQ_block = 0x40,
};

typedef struct {
    unsigned int match; // match only the fields specified here

    unsigned int level;
    Dwarf_Off offset;
    Dwarf_Off sibling;
    unsigned int tag;
    char *name;
    int name_dir;
    unsigned int block;
    
    Dwarf_Off scope_from;
    Dwarf_Off scope_to;     
} Dwarf_Request;

struct attrcb_args
{
    Dwfl_Module *dwflmod;
    Dwarf *dbg;
    int level;
    unsigned int addrsize;
    Dwarf_Off cu_offset;

    /* added to match request with attributes */
    Dwarf_Request *req;
    int matched;
};

static int get_ops(unsigned int *ops, 
                   unsigned int addrsize, 
                   Dwarf_Word len, 
                   const unsigned char *data)
{
    Dwarf_Word offset = 0;
    while (len-- > 0)
    {
        size_t op = *data++;

        switch (op)
        {
        case DW_OP_call_ref:
        case DW_OP_addr:;
            data += addrsize;
            len -= addrsize;
            offset += 1 + addrsize;
            break;

        case DW_OP_deref_size:
        case DW_OP_xderef_size:
        case DW_OP_pick:
        case DW_OP_const1u:
            ++data;
            --len;
            offset += 2;
            break;

        case DW_OP_const2u:
            len -= 2;
            data += 2;
            offset += 3;
            break;

        case DW_OP_const4u:
            len -= 4;
            data += 4;
            offset += 5;
            break;

        case DW_OP_const8u:
            len -= 8;
            data += 8;
            offset += 9;
            break;

        case DW_OP_const1s:
            ++data;
            --len;
            offset += 2;
            break;

        case DW_OP_const2s:
            len -= 2;
            data += 2;
            offset += 3;
            break;

        case DW_OP_const4s:
            len -= 4;
            data += 4;
            offset += 5;
            break;

        case DW_OP_const8s:
            len -= 8;
            data += 8;
            offset += 9;
            break;

        case DW_OP_piece:
        case DW_OP_regx:
        case DW_OP_plus_uconst:
        case DW_OP_constu:;
            const unsigned char *start = data;
            unsigned int uleb;
            get_uleb128(uleb, data);
            *ops = uleb;
            len -= data - start;
            offset += 1 + (data - start);
            return 0;
            //break;

        case DW_OP_bit_piece:
            start = data;
            unsigned int uleb2;
            get_uleb128 (uleb, data);
            get_uleb128 (uleb2, data);
            len -= data - start;
            offset += 1 + (data - start);
            break;

        case DW_OP_fbreg:
        case DW_OP_breg0 ... DW_OP_breg31:
        case DW_OP_consts:
            start = data;
            unsigned int sleb;
            get_sleb128 (sleb, data);
            len -= data - start;
            offset += 1 + (data - start);
            break;

        case DW_OP_bregx:
            start = data;
            get_uleb128 (uleb, data);
            get_sleb128 (sleb, data);
            len -= data - start;
            offset += 1 + (data - start);
            break;

        case DW_OP_call2:
        case DW_OP_call4:
        case DW_OP_skip:
        case DW_OP_bra:
            len -= 2;
            data += 2;
            offset += 3;
            break;

        default:
            ++offset;
            break;
        }
    }
    
    return -1;
}

static int process_attrs(Dwarf_Attribute *attrp, void *arg)
{
    struct attrcb_args *cbargs = (struct attrcb_args *)arg;
    //const int level = cbargs->level;
    Dwarf_Request *req = cbargs->req;
    
    unsigned int attr = dwarf_whatattr(attrp);
    if (attr == 0)
    {
        err(EX_DATAERR, "cannot get attribute code: %s", dwarf_errmsg(-1));
        return DWARF_CB_ABORT;
    }

    unsigned int form = dwarf_whatform(attrp);
    if (form == 0)
    {
        err(EX_DATAERR, "cannot get attribute form: %s", dwarf_errmsg(-1));
        return DWARF_CB_ABORT;
    }

    switch (form)
    {
    case DW_FORM_indirect:
    case DW_FORM_strp:
    case DW_FORM_string:;
        const char *str = dwarf_formstring(attrp);
        if (str == NULL)
            goto attrval_out;
        if (attr == DW_AT_name)
        {
            //printf("string: %s\n", str);
            if (req->match & DW_REQ_name)
            {
                if (req->name_dir)
                {
                    const char *fname = strrchr(str, '/');
                    if (fname != NULL) str = fname + 1;
                }
                if (strcmp(req->name, str) == 0)
                {
                    cbargs->matched = 1;
                    //return DWARF_CB_ABORT;
                }
            }
            else
                req->name = strdup(str);
        }
        break;
    case DW_FORM_block4:
    case DW_FORM_block2:
    case DW_FORM_block1:
    case DW_FORM_block:;
        Dwarf_Block block;
        if (dwarf_formblock(attrp, &block) != 0)
            goto attrval_out;
        switch (attr)
        {
        case DW_AT_location:
        case DW_AT_data_member_location:
        case DW_AT_vtable_elem_location:
        case DW_AT_string_length:
        case DW_AT_use_location:
        case DW_AT_frame_base:
        case DW_AT_return_addr:
        case DW_AT_static_link:;
            unsigned int ops;
            if (get_ops(&ops, cbargs->addrsize, block.length, block.data) == 0)
            {
            //    printf("ops: %x\n", ops);
                if (req->match & DW_REQ_block)
                {
                    if (req->block != ops)
                    {
                        cbargs->matched = 0;
                        return DWARF_CB_ABORT;
                    }
                }
                else
                    req->block = ops;
            }
            break;
        }
        break;
    }
    
    return DWARF_CB_OK;

attrval_out:
    err(EX_DATAERR, "cannot get attribute value: %s", dwarf_errmsg(-1));
    return DWARF_CB_ABORT;
}

static int process_debug_info(Dwfl_Module *dwflmod,
                              Ebl *ebl __attribute__ ((unused)),
                              GElf_Ehdr *ehdr __attribute__ ((unused)),
                              Elf_Scn *scn __attribute__ ((unused)),
                              GElf_Shdr *shdr, 
                              Dwarf *dbg, 
                              Dwarf_Request *req)
{
    int ret = EX_OK;
        
    if (shdr->sh_size == 0)
    {
        err(EX_DATAERR, "section is empty");
        return -EX_DATAERR;
    }
    
    int maxdies = 20;
    Dwarf_Die *dies = (Dwarf_Die *)malloc(maxdies * sizeof (Dwarf_Die));
    if (dies == NULL)
    {
        err(EX_SOFTWARE, "memory exhausted");
        return -EX_SOFTWARE;
    }    

    Dwarf_Off offset = 0;
    int sibling_ret = 0;
    int sibling_level = 0;

    /* new compilation unit.  */
    size_t cuhl;
    Dwarf_Off abbroffset;
    uint8_t addrsize;
    uint8_t offsize;
    Dwarf_Off nextcu;

next_cu:
    if (dwarf_nextcu(dbg, offset, &nextcu, &cuhl, &abbroffset, &addrsize,
        &offsize) != 0)
    {
        ret = -EX_DATAERR;
        err(EX_DATAERR, "cannot find the requested DIE");
        goto do_return;
    }
    
    struct attrcb_args args;
    args.dwflmod = dwflmod;
    args.dbg = dbg;
    args.addrsize = addrsize;
    args.cu_offset = offset;
    args.req = req;

    offset += cuhl;

    int level = 0;

    // get a DIE
    if (dwarf_offdie(dbg, offset, &dies[level]) == NULL)
    {
        ret = -EX_DATAERR;
        err(EX_DATAERR, "cannot get DIE at offset %llx in section '%s': %s",
            (uint64_t)offset, ".debug_info", dwarf_errmsg(-1));
        goto do_return;
    }

    do
    {
        //printf("level: %d\n", level);
    
        // get DIE offset
        offset = dwarf_dieoffset(&dies[level]);
        if (offset == ~0ul)
        {
            ret = -EX_DATAERR;
            err(EX_DATAERR, "cannot get DIE offset: %s", dwarf_errmsg (-1));
            goto do_return;
        }
        //printf("offset: 0x%06llx\n", offset);

        // TEST
        if (sibling_ret && sibling_level == level)
        {
            req->sibling = offset;
        //    printf("sibling return!: offset (0x%06llx)\n", offset);
            goto do_return;
        }

        // get tag
        int tag = dwarf_tag(&dies[level]);
        if (tag == DW_TAG_invalid)
        {
            ret = -EX_DATAERR;
            err(EX_DATAERR, "cannot get tag of DIE at offset %llu in "
                "section '%s': %s", (uint64_t)offset, ".debug_info", 
                dwarf_errmsg(-1));
            goto do_return;
        }
        //printf("tag: 0x%02x\n", tag);

        // get the attribute values
        args.level = level;
        args.matched = 0;
        dwarf_getattrs(&dies[level], process_attrs, &args, 0);

        if (!(req->match & DW_REQ_scope) || 
            (offset >= req->scope_from && offset < req->scope_to))
        {
        //    printf("offset: 0x%06llx\n", offset);
            int matched = 1;

            if (req->match & DW_REQ_level && req->level != level)
                matched = 0;
            if (req->match & DW_REQ_offset && req->offset != offset)
                matched = 0;
            if (req->match & DW_REQ_tag && req->tag != tag)
                matched = 0;
            if (!args.matched)
                matched = 0;

            if (matched)
            {
                if (!(req->match & DW_REQ_level)) req->level = level;
                if (!(req->match & DW_REQ_offset)) req->offset = offset;
                if (!(req->match & DW_REQ_tag)) req->tag = tag;
                if (!(req->match & DW_REQ_sibling))
                {
                    sibling_ret = 1;
                    sibling_level = level;
                //    printf("sibling return mode on: level (%d)\n", level);
                }
                else
                    goto do_return;
            }
        }

        // make room for the next level's DIE
        if (level + 1 == maxdies)
        {
            dies = (Dwarf_Die *)realloc(dies, (maxdies += 10) 
                    * sizeof (Dwarf_Die));
            if (dies == NULL)
            {
                ret = -EX_SOFTWARE;
                err(EX_SOFTWARE, "memory exhausted");
                goto do_return;
            }
        }    

        // get a next level's DIE
        int res = dwarf_child(&dies[level], &dies[level + 1]);
        if (res > 0)
        {
            // get another DIE at the same level
            while ((res = dwarf_siblingof(&dies[level], &dies[level])) == 1)
                if (level-- == 0)
                    break;

            if (res == -1)
            {
                res = -EX_DATAERR;
                err(EX_DATAERR, "cannot get next sibling DIE: %s\n", 
                    dwarf_errmsg(-1));
                goto do_return;
            }
        }
        else if (res < 0)
        {
            ret = -EX_DATAERR;
            err(EX_DATAERR, "cannot get next child DIE: %s", dwarf_errmsg(-1));
            goto do_return;
        }
        else
            ++level;
    } while (level >= 0);

    offset = nextcu;
    if (offset != 0)
        goto next_cu;

do_return:
    free(dies);

    return ret;
}

static int process_debug(Dwfl_Module *dwflmod, 
                         Ebl *ebl, 
                         GElf_Ehdr *ehdr, 
                         Dwarf_Request *req)
{
    Dwarf_Addr dwbias;
    Dwarf *dbg = dwfl_module_getdwarf(dwflmod, &dwbias);
    if (dbg == NULL)
    {
        err(EX_DATAERR, "cannot get debug context descriptor: %s",
            dwfl_errmsg(-1));
        return -EX_DATAERR;
    }

    /* Get the section header string table index.  */
    size_t shstrndx;
    if (elf_getshstrndx(ebl->elf, &shstrndx) < 0)
    {
        err(EX_DATAERR, "cannot get section header string table index");
        return -EX_DATAERR;
    }

    // look through all the sections for the debugging sections to print
    Elf_Scn *scn = NULL;
    int ret;
    while ((scn = elf_nextscn(ebl->elf, scn)) != NULL)
    {
        GElf_Shdr shdr_mem;
        GElf_Shdr *shdr = gelf_getshdr (scn, &shdr_mem);

        if (shdr != NULL && shdr->sh_type == SHT_PROGBITS)
        {
            const char *name = elf_strptr(ebl->elf, shstrndx,
                            shdr->sh_name);
            if (strcmp(name, ".debug_info") == 0)
            {
                if ((ret = process_debug_info(dwflmod, ebl, ehdr, scn, shdr, 
                    dbg, req)) != EX_OK)
                    return ret;
                break;
            }
        }
    }
    
    return EX_OK;
}

static int process_elf_request(Dwfl_Module *dwflmod, Dwarf_Request *req)
{
    GElf_Addr dwflbias;
    Elf *elf = dwfl_module_getelf(dwflmod, &dwflbias);

    GElf_Ehdr ehdr_mem;
    GElf_Ehdr *ehdr = gelf_getehdr(elf, &ehdr_mem);
    if (ehdr == NULL)
    {
        err(EX_DATAERR, "cannot read ELF header: %s", elf_errmsg(-1));
        return -EX_DATAERR;
    }

    Ebl *ebl = ebl_openbackend(elf);
    if (ebl == NULL)
    {
        err(EX_SOFTWARE, "cannot create EBL handle");
        return -EX_SOFTWARE;
    }

    // determine the number of sections
    size_t shnum = 0;
    if (elf_getshnum(ebl->elf, &shnum) < 0)
    {
        err(EX_SOFTWARE, "cannot determine number of sections: %s", 
            elf_errmsg(-1));
        return -EX_SOFTWARE;
    }        

    int ret;
    if ((ret = process_debug(dwflmod, ebl, ehdr, req)) != EX_OK)
        return ret;

    ebl_closebackend(ebl);

    return EX_OK;
}

static int process_dwflmod(Dwfl_Module *dwflmod,
                           void **userdata __attribute__ ((unused)), 
                           const char *name __attribute__ ((unused)),
                           Dwarf_Addr base __attribute__ ((unused)),
                           void *arg)
{
    if (process_elf_request(dwflmod, (Dwarf_Request *)arg) != EX_OK)
        return DWARF_CB_ABORT;
    return DWARF_CB_OK;
}

static int find_no_debuginfo(Dwfl_Module *mod __attribute__ ((unused)),
                             void **userdata __attribute__ ((unused)),
                             const char *modname __attribute__ ((unused)),
                             Dwarf_Addr base __attribute__ ((unused)),
                             const char *file_name __attribute__ ((unused)),
                             const char *debuglink_file __attribute__ ((unused)),
                             GElf_Word debuglink_crc __attribute__ ((unused)),
                             char **debuginfo_file_name __attribute__ ((unused)))
{
    return -1;
}

static int process_request(int fd, const char *fname, Dwarf_Request *req)
{
    static const Dwfl_Callbacks callbacks = {
        .section_address = dwfl_offline_section_address,
        .find_debuginfo = find_no_debuginfo
    };
    Dwfl *dwfl = dwfl_begin(&callbacks);
    if (dwfl_report_offline(dwfl, fname, fname, fd) == NULL)
    {
        err(EX_DATAERR, "failed reading '%s': %s", fname, dwfl_errmsg(-1));
        return -EX_DATAERR;
    }
    else
    {
        dwfl_report_end(dwfl, NULL, NULL);
        
        // process the one or more modules gleaned from this file
        if (dwfl_getmodules(dwfl, &process_dwflmod, req, 0) != 0)
            return -EX_SOFTWARE;
    }

    dwfl_end(dwfl);

    return EX_OK;
}

static int find_comp_unit(Dwarf_Off *from,
                          Dwarf_Off *to,
                          const char *name,
                          const char *fname)
{
    int fd, ret;
    Dwarf_Request req;

    if ((fd = open(fname, O_RDONLY, 0)) < 0)
    {
        err(EX_NOINPUT, "open \"%s\" failed", fname);
        return -EX_NOINPUT;
    }

    memset(&req, 0, sizeof(req));
    req.match = DW_REQ_level | DW_REQ_tag | DW_REQ_name;
    req.level = 0;
    req.tag = DW_TAG_compile_unit;
    req.name = (char *)name;
    req.name_dir = 1;
    if ((ret = process_request(fd, fname, &req)) != EX_OK)
        return ret;
        
    *from = req.offset;
    *to = req.sibling;

    close(fd);

    return EX_OK;
}

static int find_struct(Dwarf_Off *from, 
                       Dwarf_Off *to,
                       const char *name,
                       const Dwarf_Off scope_from, 
                       const Dwarf_Off scope_to, 
                       const char *fname)
{
    int fd, ret;
    Dwarf_Request req;

    if ((fd = open(fname, O_RDONLY, 0)) < 0)
    {
        err(EX_NOINPUT, "open \"%s\" failed", fname);
        return -EX_NOINPUT;
    }
    
    memset(&req, 0, sizeof(req));
    req.match = DW_REQ_level | DW_REQ_tag | DW_REQ_name | DW_REQ_scope;
    req.level = 1;
    req.tag = DW_TAG_structure_type;
    req.name = (char *)name;
    req.name_dir = 0;
    req.scope_from = scope_from;
    req.scope_to = scope_to;
    if ((ret = process_request(fd, fname, &req)) != EX_OK)
        return ret;
    
    *from = req.offset;
    *to = req.sibling;
    
    close(fd);

    return EX_OK;
}

static int find_struct_member(unsigned int *offset,
                              char *name, 
                              const Dwarf_Off struct_from, 
                              const Dwarf_Off struct_to, 
                              const char *fname)
{
    int fd, ret;
    Dwarf_Request req;

    if ((fd = open(fname, O_RDONLY, 0)) < 0)
    {
        err(EX_NOINPUT, "open \"%s\" failed", fname);
        return -EX_NOINPUT;
    }
    
    memset(&req, 0, sizeof(req));
    req.match = DW_REQ_level | DW_REQ_tag | DW_REQ_name | DW_REQ_scope;
    req.level = 2;
    req.tag = DW_TAG_member;
    req.name = name;
    req.name_dir = 0;
    req.scope_from = struct_from;
    req.scope_to = struct_to;
    if ((ret = process_request(fd, fname, &req)) != EX_OK)
        return ret;
    
    *offset = req.block;
    
    close(fd);

    return EX_OK;
}

int offset_task_struct(int *tasks_offset,
                       int *name_offset,
                       int *pid_offset,
                       int *files_offset,
                       const char *fsym)
{
    char *fields[] = {
        "tasks",
        "pid",
        "comm",    // name
        "files",
    };
    int *offsets[4];
    offsets[0] = tasks_offset;
    offsets[1] = pid_offset;
    offsets[2] = name_offset;
    offsets[3] = files_offset;
    uint32_t i;
    int ret = 0;
    
    Dwarf_Off sched_from, sched_to;
    if ((ret = find_comp_unit(&sched_from, &sched_to, "sched.c", fsym)) 
        != EX_OK)
    {
        errx(-ret, "cannot find sched.c in %s", fsym);
        return ret;
    }
    //printf("sched.c found: 0x%06llx - 0x%06llx\n", sched_from, sched_to);    

    Dwarf_Off task_from, task_to = 0;
    if ((ret = find_struct(&task_from, &task_to, "task_struct", sched_from, 
        sched_to, fsym)) != EX_OK)
    {
        errx(-ret, "cannot find task_struct in %s", fsym);
        return ret;
    }
    //printf("task_struct found: 0x%06llx - 0x%06llx\n", task_from, task_to);

    unsigned int offset;
    for (i = 0; i < 4; i++)
    {
        if ((ret = find_struct_member(&offset, fields[i], task_from, task_to, 
            fsym)) != EX_OK)
        {
            errx(-ret, "cannot find task_struct->%s", fields[i]);
            return ret;
        }
        //printf("%s: 0x%x\n", fields[i], offset);
        *(offsets[i]) = offset;
    }
        
    return ret;
}

int offset_files_struct(int *fdt_offset, const char *fsym)
{
    unsigned int offset = 0;
    char *field = NULL;
    int ret = 0;

    if (base_from == 0 || base_to == 0)
    {
        if ((ret = find_comp_unit(&base_from, &base_to, "base.c", fsym)) 
            != EX_OK)
        {
            errx(-ret, "cannot find base.c in %s", fsym);
            return ret;
           }
        //printf("base.c found: 0x%06llx - 0x%06llx\n", base_from, base_to);    
    }

    Dwarf_Off files_from, files_to = 0;
    if ((ret = find_struct(&files_from, &files_to, "files_struct", base_from, 
        base_to, fsym)) != EX_OK)
    {
        errx(-ret, "cannot find files_struct in %s", fsym);
        return ret;
    }
    //printf("files_struct found: 0x%06llx - 0x%06llx\n", files_from, files_to);

    field = "fdt";
    if ((ret = find_struct_member(&offset, field, files_from, files_to, 
                    fsym)) != EX_OK)
    {
        errx(-ret, "cannot fine files_struct->%s", field);
        return ret;
    }
    //printf("%s: 0x%x\n", field, offset);
    *fdt_offset = offset;

    return ret;
}

int offset_fdtable(int *max_fds_offset, int *fd_offset, const char *fsym)
{
    unsigned int offset = 0;
    char *field = NULL;
    int ret = 0;

    if (base_from == 0 || base_to == 0)
    {
        if ((ret = find_comp_unit(&base_from, &base_to, "base.c", fsym)) 
            != EX_OK)
        {
            errx(-ret, "cannot find base.c in %s", fsym);
            return ret;
           }
        //printf("base.c found: 0x%06llx - 0x%06llx\n", base_from, base_to);    
    }

    Dwarf_Off fdt_from, fdt_to = 0;
    if ((ret = find_struct(&fdt_from, &fdt_to, "fdtable", base_from, 
        base_to, fsym)) != EX_OK)
    {
        errx(-ret, "cannot find fdtable in %s", fsym);
        return ret;
    }
    //printf("fdtable found: 0x%06llx - 0x%06llx\n", fdt_from, fdt_to);

    field = "max_fds";
    if ((ret = find_struct_member(&offset, field, fdt_from, fdt_to, fsym)) 
        != EX_OK)
    {
        errx(-ret, "cannot find fdtable->%s", field);
        return ret;
    }
    //printf("%s: 0x%x\n", field, offset);
    *max_fds_offset = offset;

    field = "fd";
    if ((ret = find_struct_member(&offset, field, fdt_from, fdt_to, fsym)) 
        != EX_OK)
    {
        errx(-ret, "cannot find fdtable->%s", field);
        return ret;
    }
    //printf("%s: 0x%x\n", field, offset);
    *fd_offset = offset;

    return ret;
}

int offset_file(int *f_dentry_offset, int *f_vfsmnt_offset, const char *fsym)
{
    unsigned int offset = 0;
    char *field = NULL;
    int ret = 0;

    if (base_from == 0 || base_to == 0)
    {
        if ((ret = find_comp_unit(&base_from, &base_to, "base.c", fsym)) 
            != EX_OK)
        {
            errx(-ret, "cannot find base.c in %s", fsym);
            return ret;
           }
        //printf("base.c found: 0x%06llx - 0x%06llx\n", base_from, base_to);    
    }

    Dwarf_Off fd_from, fd_to = 0;
    if ((ret = find_struct(&fd_from, &fd_to, "file", base_from, base_to, 
        fsym)) != EX_OK)
    {
        errx(-ret, "cannot find file in %s", fsym);
        return ret;
    }
    //printf("file found: 0x%06llx - 0x%06llx\n", fd_from, fd_to);

    field = "f_dentry";
    if ((ret = find_struct_member(&offset, field, fd_from, fd_to, fsym)) 
        != EX_OK)
    {
        errx(-ret, "cannot find file->%s", field);
        return ret;
    }
    //printf("%s: 0x%x\n", field, offset);
    *f_dentry_offset = offset;

    field = "f_vfsmnt";
    if ((ret = find_struct_member(&offset, field, fd_from, fd_to, fsym)) 
        != EX_OK)
    {
        errx(-ret, "cannot find file->%s", field);
        return ret;
    }
    //printf("%s: 0x%x\n", field, offset);
    *f_vfsmnt_offset = offset;

    return ret;
}

int offset_dentry(int *d_parent_offset, int *d_name_offset, const char *fsym)
{
    unsigned int offset = 0;
    char *field = NULL;
    int ret = 0;

    if (base_from == 0 || base_to == 0)
    {
        if ((ret = find_comp_unit(&base_from, &base_to, "base.c", fsym)) 
            != EX_OK)
        {
            errx(-ret, "cannot find base.c in %s", fsym);
            return ret;
           }
        //printf("base.c found: 0x%06llx - 0x%06llx\n", base_from, base_to);    
    }

    Dwarf_Off dentry_from, dentry_to = 0;
    if ((ret = find_struct(&dentry_from, &dentry_to, "dentry", base_from, 
        base_to, fsym)) != EX_OK)
    {
        errx(-ret, "cannot find dentry in %s", fsym);
        return ret;
    }
    //printf("dentry found: 0x%06llx - 0x%06llx\n", dentry_from, dentry_to);
    
    field = "d_parent";
    if ((ret = find_struct_member(&offset, field, dentry_from, dentry_to, 
        fsym)) != EX_OK)
    {
        errx(-ret, "cannot find dentry->%s", field);
        return ret;
    }
    //printf("%s: 0x%x\n", field, offset);
    *d_parent_offset = offset;

    field = "d_name";
    if ((ret = find_struct_member(&offset, field, dentry_from, dentry_to, 
        fsym)) != EX_OK)
    {
        errx(-ret, "cannot find dentry->%s", field);
        return ret;
    }
    //printf("%s: 0x%x\n", field, offset);
    *d_name_offset = offset;

    return ret;
}

int offset_vfsmount(int *mnt_devname_offset, const char *fsym)
{
    unsigned int offset = 0;
    char *field = NULL;
    int ret = 0;

    if (base_from == 0 || base_to == 0)
    {
        if ((ret = find_comp_unit(&base_from, &base_to, "base.c", fsym)) 
            != EX_OK)
        {
            errx(-ret, "cannot find base.c in %s", fsym);
            return ret;
           }
        //printf("base.c found: 0x%06llx - 0x%06llx\n", base_from, base_to);    
    }

    Dwarf_Off vfsmount_from, vfsmount_to = 0;
    if ((ret = find_struct(&vfsmount_from, &vfsmount_to, "vfsmount", base_from, 
        base_to, fsym)) != EX_OK)
    {
        errx(-ret, "cannot find vfsmount in %s", fsym);
        return ret;
    }
    //printf("vfsmount found: 0x%06llx - 0x%06llx\n", vfsmount_from, vfsmount_to);
    
    field = "mnt_devname";
    if ((ret = find_struct_member(&offset, field, vfsmount_from, vfsmount_to, 
        fsym)) != EX_OK)
    {
        errx(-ret, "cannot find vfsmount->%s", field);
        return ret;
    }
    //printf("%s: 0x%x\n", field, offset);
    *mnt_devname_offset = offset;
    
    return ret;
}

int offset_qstr(int *len_offset, int *name_offset, const char *fsym)
{
    unsigned int offset = 0;
    char *field = NULL;
    int ret = 0;

    if (base_from == 0 || base_to == 0)
    {
        if ((ret = find_comp_unit(&base_from, &base_to, "base.c", fsym)) 
            != EX_OK)
        {
            errx(-ret, "cannot find base.c in %s", fsym);
            return ret;
           }
        //printf("base.c found: 0x%06llx - 0x%06llx\n", base_from, base_to);    
    }

    Dwarf_Off qstr_from, qstr_to = 0;
    if ((ret = find_struct(&qstr_from, &qstr_to, "qstr", base_from, 
        base_to, fsym)) != EX_OK)
    {
        errx(-ret, "cannot find qstr in %s", fsym);
        return ret;
    }
    //printf("qstr found: 0x%06llx - 0x%06llx\n", qstr_from, qstr_to);

    field = "len";
    if ((ret = find_struct_member(&offset, field, qstr_from, qstr_to, 
        fsym)) != EX_OK)
    {
        errx(-ret, "cannot find qstr->%s", field);
        return ret;
    }
    //printf("%s: 0x%x\n", field, offset);
    *len_offset = offset;

    field = "name";
    if ((ret = find_struct_member(&offset, field, qstr_from, qstr_to, 
        fsym)) != EX_OK)
    {
        errx(-ret, "cannot find qstr->%s", field);
        return ret;
    }
    //printf("%s: 0x%x\n", field, offset);
    *name_offset = offset;

    return ret;
}
