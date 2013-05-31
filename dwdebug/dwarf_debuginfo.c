/*
 * Copyright (c) 2011, 2012, 2013 The University of Utah
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

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <regex.h>

#include "config.h"
#include "common.h"
#include "log.h"
#include "output.h"
#include "list.h"
#include "alist.h"
#include "dwdebug.h"

#include <dwarf.h>
#include <gelf.h>
#include <elfutils/libebl.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>

#include "memory-access.h"

/*
 * Prototypes.
 */

struct attrcb_args {
    Dwfl_Module *dwflmod;
    Dwarf *dbg;
    struct dwarf_cu_meta *meta;

    int level;
    Dwarf_Off cu_offset;
    Dwarf_Off die_offset;
    Dwarf_Addr cu_base;
    bool have_stmt_list_offset;
    Dwarf_Word stmt_list_offset;

    struct debugfile *debugfile;
    struct debugfile_load_opts *opts;
    struct symtab *cu_symtab;
    struct symtab *symtab;
    struct symbol *symbol;
    struct symbol *parentsymbol;
    struct symbol *voidsymbol;
    GHashTable *reftab;
    GHashTable *cu_abstract_origins;

    ADDR lowpc;
    ADDR highpc;
    uint8_t lowpc_set:1,
	highpc_is_offset:1,
	reloading:1;
};

/* Declare these now; they are used in attr_callback. */
static int  get_rangelist(Dwfl_Module *dwflmod,Dwarf *dbg,unsigned int vers,
			  unsigned int addrsize,unsigned int offsetsize,
			  unsigned int attr,Dwarf_Word offset,
			  struct debugfile *debugfile,ADDR cu_base,
			  struct range_list *list);
static int    get_loclist(Dwfl_Module *dwflmod,Dwarf *dbg,unsigned int vers,
			  unsigned int addrsize,unsigned int offsetsize,
			  unsigned int attr,Dwarf_Word offset,
			  struct debugfile *debugfile,ADDR cu_base,
			  struct loc_list *list);
static int get_static_ops(Dwfl_Module *dwflmod,Dwarf *dbg,unsigned int vers,
			  unsigned int addrsize,unsigned int offset_size,
			  Dwarf_Word len,const unsigned char *data,
			  unsigned int attr,struct location *retval);
static inline void set_language(struct dwarf_cu_meta *meta,int language);

static int attr_callback(Dwarf_Attribute *attrp,void *arg) {
    struct attrcb_args *cbargs = (struct attrcb_args *)arg;
    const int level = cbargs->level;
    struct debugfile *debugfile = cbargs->debugfile;

    if (unlikely(attrp == NULL)) {
	verror("cannot get attribute: %s",dwarf_errmsg (-1));
	return DWARF_CB_ABORT;
    }

    unsigned int attr = attrp->code;
    unsigned int form = attrp->form;

    if (unlikely(attr == 0)) {
	verror("attr code was 0, aborting!\n");
	goto errout;
    }
    if (unlikely(form == 0)) {
	verror("form code was 0, aborting!\n");
	goto errout;
    }

    vdebug(4,LA_DEBUG,LF_DWARFATTR,"%d 0x%x %s (%s) (as=%d,os=%d)\n",
	   (int)level,cbargs->die_offset,dwarf_attr_string(attr),
	   dwarf_form_string(form),cbargs->meta->addrsize,cbargs->meta->offsize);

    /* if form is a string */
    char *str = NULL;

    Dwarf_Word num;
    Dwarf_Addr addr;
    Dwarf_Block block;
    bool flag;
    SMOFFSET ref = 0;
    Dwarf_Die rref;

    uint8_t str_set = 0;
    uint8_t str_copy = 0;
    uint8_t num_set = 0;
    uint8_t addr_set = 0;
    uint8_t flag_set = 0;
    uint8_t ref_set = 0;
    uint8_t block_set = 0;

    struct array_list *iilist;

    switch(form) {
    case DW_FORM_string:
	// XXX: do we need to strcpy this one?  It's not in our dbg_strtab...
	str = (char *)attrp->valp;
	str_set = 1;
	str_copy = 1;
	break;
    case DW_FORM_strp:
    case DW_FORM_indirect:
	//str = dwarf_formstring(attrp);
	//str_set = 1;
	//break;
	if (*(attrp->valp) > (debugfile->dbg_strtablen - 1)) {
	    vwarn("[DIE %" PRIx64 "] dwarf str at 0x%lx not in dbg_strtab for attr %s; copying!\n",
		   cbargs->die_offset,(unsigned long int)*(attrp->valp),
		   dwarf_attr_string(attr));
	    str_copy = 1;
	}
	// XXX relocation...
	if (cbargs->meta->offsize == 4)
	    str = &debugfile->dbg_strtab[*((uint32_t *)attrp->valp)];
	else 
	    str = &debugfile->dbg_strtab[*((uint64_t *)attrp->valp)];
#ifdef DWDEBUG_NOUSE_STRTAB
	str_copy = 1;
#else
	str_copy = 0;
#endif
	str_set = 1;
	break;
    case DW_FORM_addr:
	if (unlikely(dwarf_formaddr(attrp,&addr) != 0)) {
	    verror("[DIE %" PRIx64 "] could not get dwarf addr for attr %s\n",
		   cbargs->die_offset,dwarf_attr_string(attr));
	    goto errout;
	}
	addr_set = 1;
	break;
    case DW_FORM_ref_addr:
    case DW_FORM_ref_udata:
    case DW_FORM_ref8:
    case DW_FORM_ref4:
    case DW_FORM_ref2:
    case DW_FORM_ref1:
	if (unlikely(dwarf_formref_die(attrp,&rref) == NULL)) {
	    verror("[DIE %" PRIx64 "] could not get dwarf die ref for attr %s\n",
		   cbargs->die_offset,dwarf_attr_string(attr));
	    goto errout;
	}
	ref = dwarf_dieoffset(&rref);
	ref_set = 1;
	break;
    case DW_FORM_sec_offset:
      attrp->form = cbargs->meta->offsize == 8 ? DW_FORM_data8 : DW_FORM_data4;
      /* Fall through.  */
    case DW_FORM_udata:
    case DW_FORM_sdata:
    case DW_FORM_data8:
    case DW_FORM_data4:
    case DW_FORM_data2:
    case DW_FORM_data1:
	if (unlikely(dwarf_formudata(attrp,&num) != 0)) {
	    verror("[DIE %" PRIx64 "] could not load dwarf num for attr %s",
		   cbargs->die_offset,dwarf_attr_string(attr));
	    goto errout;
	}
	num_set = 1;
	break;
/* not sure if 137 is the right number! */
#if _INT_ELFUTILS_VERSION > 137
    case DW_FORM_exprloc:
#endif
    case DW_FORM_block4:
    case DW_FORM_block2:
    case DW_FORM_block1:
    case DW_FORM_block:
	if (unlikely(dwarf_formblock(attrp,&block) != 0)) {
	    verror("[DIE %" PRIx64 "] could not load dwarf block for attr %s",
		   cbargs->die_offset,dwarf_attr_string(attr));
	    goto errout;
	}
	block_set = 1;
	break;
    case DW_FORM_flag:
/* not sure if 137 is the right number! */
#if _INT_ELFUTILS_VERSION > 137
    case DW_FORM_flag_present:
#endif
	if (unlikely(dwarf_formflag(attrp,&flag) != 0)) {
	    verror("[DIE %" PRIx64 "] could not load dwarf flag for attr %s",
		   cbargs->die_offset,dwarf_attr_string(attr));
	    goto errout;
	}
	flag_set = 1;
	break;
    default:
	vwarnopt(2,LA_DEBUG,LF_DWARFATTR,
		 "[DIE %" PRIx64 "] unrecognized form %s (0x%x) for attr %s\n",
		 cbargs->die_offset,dwarf_form_string(form),form,
		 dwarf_attr_string(attr));
	goto errout;
    }

    /*
     * If this is a partial symbol, only process some attributes!
     */
    if (cbargs->symbol && SYMBOL_IS_PARTIAL(cbargs->symbol)) {
	switch(attr) {
	case DW_AT_name:
	case DW_AT_decl_line:
	case DW_AT_type:
	case DW_AT_external:
	case DW_AT_declaration:
	case DW_AT_prototyped:
	case DW_AT_low_pc:
	case DW_AT_high_pc:
	case DW_AT_entry_pc:
	case DW_AT_location:
	case DW_AT_abstract_origin:
	    /* These we always do because if we're mostly loading a
	     * symtab, or a CU, we still need them; they don't touch the
	     * current symbol, if there is one.
	     */
	case DW_AT_stmt_list:
	case DW_AT_producer:
	case DW_AT_comp_dir:
	case DW_AT_language:
	    break;
	default:
	    return 0;
	}
    }

    switch (attr) {
    case DW_AT_name:
	vdebug(4,LA_DEBUG,LF_DWARFATTR,"\t\t\tvalue = %s\n",str);

	if (cbargs->reloading) 
	    break;

	if (level == 0) {
	    symtab_set_name(cbargs->cu_symtab,str,str_copy);
	}
	else if (cbargs->symbol) {
	    symbol_set_name(cbargs->symbol,str,str_copy);
	    /* Only full functions have a symtab! */
	    if (SYMBOL_IS_FULL_FUNCTION(cbargs->symbol))
		symtab_set_name(cbargs->symtab,str,str_copy);
	}
	else {
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval %s for attr %s in bad context\n",
		     cbargs->die_offset,str,dwarf_attr_string(attr));
	}
	break;
    case DW_AT_stmt_list:
	/* XXX: don't do line numbers yet. */
	if (num_set) {
	    cbargs->stmt_list_offset = num;
	    cbargs->have_stmt_list_offset = true;
	    vdebug(4,LA_DEBUG,LF_DWARFATTR,"\t\t\tvalue = %d\n",num);
	}
	else {
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attr %s in bad context\n",
		     cbargs->die_offset,dwarf_attr_string(attr));
	}
	break;
    case DW_AT_producer:
	vdebug(4,LA_DEBUG,LF_DWARFATTR,"\t\t\tvalue = %s\n",str);
	if (level == 0) {
	    if (str_copy) {
		cbargs->meta->producer = strdup(str);
		cbargs->meta->producer_nofree = 0;
	    }
	    else {
		cbargs->meta->producer = str;
		cbargs->meta->producer_nofree = 1;
	    }
	}
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval %s for attr %s in bad context\n",
		     cbargs->die_offset,str,dwarf_attr_string(attr));
	break;
    case DW_AT_comp_dir:
	vdebug(4,LA_DEBUG,LF_DWARFATTR,"\t\t\tvalue = %s\n",str);
	if (level == 0) {
	    if (str_copy) {
		cbargs->meta->compdirname = strdup(str);
		cbargs->meta->compdirname_nofree = 0;
	    }
	    else {
		cbargs->meta->compdirname = str;
		cbargs->meta->compdirname_nofree = 1;
	    }
	}
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval %s for attr %s in bad context\n",
		     cbargs->die_offset,str,dwarf_attr_string(attr));
	break;
    case DW_AT_language:
	vdebug(4,LA_DEBUG,LF_DWARFATTR,"\t\t\tvalue = %d\n",num);
	if (level == 0) 
	    set_language(cbargs->cu_symtab->meta,num);
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval %d for attr %s in bad context\n",
		     cbargs->die_offset,(int)num,dwarf_attr_string(attr));
	break;
    case DW_AT_low_pc:
	vdebug(4,LA_DEBUG,LF_DWARFATTR,"\t\t\tvalue = 0x%p\n",addr);

	/* If we see a new compilation unit, save its low pc separately
	 * for use in loclist calculations.  CUs can have both a low pc
	 * and range list, so we can't just use the symtab's range
	 * struct to hold this special low_pc.
	 */
	if (level == 0) {
	    cbargs->cu_base = addr;
	}

	cbargs->lowpc = addr;
	cbargs->lowpc_set = 1;

	if (cbargs->symbol && addr < cbargs->symbol->base_addr) {
	    cbargs->symbol->base_addr = addr;
	    cbargs->symbol->has_base_addr = 1;
	}

	if (SYMBOL_IS_FULL_LABEL(cbargs->symbol)) {
	    if (RANGE_IS_LIST(&cbargs->symbol->s.ii->d.l.range)) {
		verror("cannot update lowpc; already saw AT_ranges for %s symbol %s!\n",
		       SYMBOL_TYPE(cbargs->symbol->type),symbol_get_name_orig(cbargs->symbol));
	    }
	    else {
		cbargs->symbol->s.ii->d.l.range.rtype = RANGE_TYPE_PC;
		cbargs->symbol->s.ii->d.l.range.r.a.lowpc = addr;
	    }
	}
	else if (SYMBOL_IS_FUNCTION(cbargs->symbol)) {
	    ;
	}
	else if (!cbargs->symbol && cbargs->symtab) {
	    ;
	}
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval %" PRIx64 " for attr %s in bad context (symbol)\n",
		     cbargs->die_offset,addr,dwarf_attr_string(attr));
	break;
    case DW_AT_high_pc:
	if (num_set) {
	    vdebug(4,LA_DEBUG,LF_DWARFATTR,"\t\t\tvalue = " PRIu64 "\n",num);

	    /* it's a relative offset from low_pc; if we haven't seen
	     * low_pc yet, just bail.
	     */
	    cbargs->highpc = num;
	    cbargs->highpc_is_offset = 1;

	    if (SYMBOL_IS_FULL_LABEL(cbargs->symbol)) {
		if (RANGE_IS_LIST(&cbargs->symbol->s.ii->d.l.range)) {
		    verror("cannot update highpc; already saw AT_ranges for %s symbol %s!\n",
			   SYMBOL_TYPE(cbargs->symbol->type),symbol_get_name_orig(cbargs->symbol));
		}
		/* This is not exactly good, but... */
		else if (cbargs->symbol->s.ii->d.l.range.r.a.lowpc) {
		    cbargs->symbol->s.ii->d.l.range.rtype = RANGE_TYPE_PC;
		    cbargs->symbol->s.ii->d.l.range.r.a.highpc = cbargs->symbol->s.ii->d.l.range.r.a.lowpc + num;
		}
		else {
		    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
			     "[DIE %" PRIx64 "] attrval %" PRIu64 " (num) for"
			     " attr %s in bad context (%s %s -- no lowpc yet)!\n",
			     cbargs->die_offset,num,dwarf_attr_string(attr),
			     SYMBOL_TYPE(cbargs->symbol->type),
			     symbol_get_name_orig(cbargs->symbol));
		}
	    }
	}
	else if (addr_set) {
	    vdebug(4,LA_DEBUG,LF_DWARFATTR,"\t\t\tvalue = 0x%p\n",addr);

	    cbargs->highpc = addr;
	    cbargs->highpc_is_offset = 0;

	    /* On the off chance that high_pc is the lowest address for
	     * this symbol, check it!
	     */
	    if (cbargs->symbol && addr < cbargs->symbol->base_addr) {
		cbargs->symbol->base_addr = addr;
		cbargs->symbol->has_base_addr = 1;
	    }

	    if (SYMBOL_IS_FULL_LABEL(cbargs->symbol)) {
		if (RANGE_IS_LIST(&cbargs->symbol->s.ii->d.l.range)) {
		    verror("cannot update highpc; already saw AT_ranges for %s symbol %s!\n",
			   SYMBOL_TYPE(cbargs->symbol->type),symbol_get_name_orig(cbargs->symbol));
		}
		else {
		    cbargs->symbol->s.ii->d.l.range.rtype = RANGE_TYPE_PC;
		    cbargs->symbol->s.ii->d.l.range.r.a.highpc = addr;
		}
	    }
	}
	else {
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] bad attr type for attr %s\n",
		     cbargs->die_offset,dwarf_attr_string(attr));
	}
	break;
    case DW_AT_entry_pc:
	if (addr_set) {
	    vdebug(4,LA_DEBUG,LF_DWARFATTR,"\t\t\tvalue = 0x%p\n",addr);

	    if (level == 0) {
		/* Don't bother recording this for CUs. */
		break;
	    }

	    if (SYMBOL_IS_FUNCTION(cbargs->symbol)) {
		if (addr < cbargs->symbol->base_addr) { 
		    cbargs->symbol->base_addr = addr;
		    cbargs->symbol->has_base_addr = 1;
		}

		if (SYMBOL_IS_FULL(cbargs->symbol)) {
		    cbargs->symbol->s.ii->d.f.entry_pc = addr;
		    cbargs->symbol->s.ii->d.f.hasentrypc = 1;
		}
	    }
	    else 
		vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
			 "[DIE %" PRIx64 "] attrval 0x%" PRIx64 " for"
			 " attr %s in bad context (symbol)\n",
			 cbargs->die_offset,addr,dwarf_attr_string(attr));
	}
	else {
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] bad attr form for attr %s // form %s\n",
		     cbargs->die_offset,dwarf_attr_string(attr),
		     dwarf_form_string(form));
	}
	break;
    case DW_AT_decl_file:
	if (cbargs->symbol) {
	    ; // XXX
	}
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval %d for attr %s in bad context\n",
		     cbargs->die_offset,(int)num,dwarf_attr_string(attr));
	break;
    case DW_AT_decl_line:
	if (cbargs->symbol) {
	    symbol_set_srcline(cbargs->symbol,(int)num);
	}
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval %d for attr %s in bad context\n",
		     cbargs->die_offset,(int)num,dwarf_attr_string(attr));
	break;
    /* Don't bother with these yet. */
    case DW_AT_decl_column:
    case DW_AT_call_file:
    case DW_AT_call_line:
    case DW_AT_call_column:
	break;
    case DW_AT_encoding:
	if (cbargs->symbol && cbargs->symbol->type == SYMBOL_TYPE_TYPE) {
	    /* our encoding_t is 1<->1 map to the DWARF encoding codes. */
	    cbargs->symbol->s.ti->d.t.encoding = (encoding_t)num;
	}
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval %d for attr %s in bad context\n",
		     cbargs->die_offset,(int)num,dwarf_attr_string(attr));
	break;
    case DW_AT_declaration:
	if (cbargs->symbol) {
	    cbargs->symbol->isdeclaration = flag;
	}
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval %d for attr %s in bad context\n",
		     cbargs->die_offset,flag,dwarf_attr_string(attr));
	break;
    case DW_AT_external:
	if (cbargs->symbol 
	    && (cbargs->symbol->type == SYMBOL_TYPE_FUNCTION
		|| cbargs->symbol->type == SYMBOL_TYPE_VAR)) {
	    cbargs->symbol->isexternal = flag;
	}
	else if (cbargs->symbol && cbargs->symbol->type == SYMBOL_TYPE_TYPE
		 && cbargs->symbol->datatype_code == DATATYPE_FUNCTION) {
	    cbargs->symbol->isexternal = flag;
	}
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval %d for attr %s in bad context\n",
		     cbargs->die_offset,flag,dwarf_attr_string(attr));
	break;
    case DW_AT_prototyped:
	if (cbargs->symbol && cbargs->symbol->type == SYMBOL_TYPE_FUNCTION) {
	    cbargs->symbol->isprototyped = flag;
	}
	else if (cbargs->symbol && cbargs->symbol->type == SYMBOL_TYPE_TYPE
		 && cbargs->symbol->datatype_code == DATATYPE_FUNCTION) {
	    cbargs->symbol->isprototyped = flag;
	}
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval %d for attr %s in bad context\n",
		     cbargs->die_offset,flag,dwarf_attr_string(attr));
	break;
    case DW_AT_inline:
	if (num_set && cbargs->symbol 
	    && cbargs->symbol->type == SYMBOL_TYPE_FUNCTION) {
	    if (num == 1)
		cbargs->symbol->s.ii->isinlined = 1;
	    else if (num == 2)
		cbargs->symbol->s.ii->isdeclinline = 1;
	    else if (num == 3) {
		cbargs->symbol->s.ii->isinlined = 1;
		cbargs->symbol->s.ii->isdeclinline = 1;
	    }
	}
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval 0x%" PRIu64 " for attr %s in bad context\n",
		     cbargs->die_offset,num,dwarf_attr_string(attr));
	break;
    case DW_AT_abstract_origin:
	if (ref_set && SYMBOL_IS_INSTANCE(cbargs->symbol)) {
	    cbargs->symbol->isinlineinstance = 1;
	    if (SYMBOL_IS_FULL(cbargs->symbol)) {
		/*
		 * Do this in the CU post-pass; it copies additional
		 * stuff into cbargs->symbol (like datatype).
		 */
		//cbargs->symbol->s.ii->origin = (struct symbol *)	
		//    g_hash_table_lookup(cbargs->reftab,(gpointer)(uintptr_t)ref);
		/* Always set the ref so we can generate a unique name for 
		 * the symbol; see finalize_die_symbol!!
		 */
		cbargs->symbol->s.ii->origin_ref = ref;
	    }

	    iilist = g_hash_table_lookup(cbargs->cu_abstract_origins,
					 (gpointer)(uintptr_t)ref);
	    if (!iilist) {
		iilist = array_list_create(1);
		g_hash_table_insert(cbargs->cu_abstract_origins,
				    (gpointer)(uintptr_t)ref,iilist);
	    }
	    array_list_add(iilist,(void *)cbargs->symbol);
	}
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval %" PRIxSMOFFSET " for attr %s"
		     " in bad context\n",
		     cbargs->die_offset,ref,dwarf_attr_string(attr));
	break;
    case DW_AT_type:
	if (cbargs->reloading) 
	    break;

	if (ref_set && cbargs->symbol) {
	    /*
	     * Disable the datatype lookup here; there's no point; it
	     * saves us no time, and for implementing type compression
	     * (see end of CU load function) and code simplicity with
	     * that, we just do all datatype lookups there, in one
	     * place.
	     */
	    /* struct symbol *datatype = (struct symbol *)		
	           g_hash_table_lookup(cbargs->reftab,(gpointer)(uintptr_t)ref); */
	    if (cbargs->symbol->type == SYMBOL_TYPE_TYPE) {
		if (cbargs->symbol->datatype_code == DATATYPE_PTR
		    || cbargs->symbol->datatype_code == DATATYPE_TYPEDEF
		    || cbargs->symbol->datatype_code == DATATYPE_ARRAY
		    || cbargs->symbol->datatype_code == DATATYPE_CONST
		    || cbargs->symbol->datatype_code == DATATYPE_VOL
		    || cbargs->symbol->datatype_code == DATATYPE_FUNCTION) {
		    cbargs->symbol->datatype_ref = (uint64_t)ref;
		    /* if (datatype)
		           cbargs->symbol->datatype = datatype; */
		}
		else 
		    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
			     "[DIE %" PRIx64 "] bogus: type ref for unknown"
			     " type symbol\n",
			     cbargs->die_offset);
	    }
	    else {
		cbargs->symbol->datatype_ref = ref;
		/* if (datatype)
		       cbargs->symbol->datatype = datatype; */
	    }
	}
	else if (ref_set && !cbargs->symbol && cbargs->parentsymbol 
		 && cbargs->parentsymbol->type == SYMBOL_TYPE_TYPE 
		 && cbargs->parentsymbol->datatype_code == DATATYPE_ARRAY) {
	    /* If the parent was an array_type, don't worry about typing its
	     * array subranges.
	     */
	    ;
	}
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attrval %" PRIxSMOFFSET " for attr %s"
		     " in bad context\n",
		     cbargs->die_offset,ref,dwarf_attr_string(attr));
	break;
    case DW_AT_const_value:
	if (num_set
	    && cbargs->symbol 
	    && SYMBOL_IS_VAR(cbargs->symbol)
	    && cbargs->parentsymbol
	    && SYMBOL_IS_FULL_TYPE(cbargs->parentsymbol)
	    && cbargs->parentsymbol->datatype_code == DATATYPE_ENUM
	    && cbargs->parentsymbol->size_is_bytes
	    && cbargs->parentsymbol->size.bytes > 0) {
	    cbargs->symbol->s.ii->constval = \
		malloc(symbol_bytesize(cbargs->parentsymbol));
	    memcpy(cbargs->symbol->s.ii->constval,&num,
		   symbol_bytesize(cbargs->parentsymbol));
	    cbargs->symbol->isenumval = 1;
	}
	else if (num_set && SYMBOL_IS_FULL_INSTANCE(cbargs->symbol)) {
	    /* XXX: just use a 64 bit unsigned for now, since we may not
	     * have seen the type for this symbol yet.  We can always
	     * deal with it later.
	     */
	    cbargs->symbol->s.ii->constval = malloc(sizeof(Dwarf_Word));
	    memcpy(cbargs->symbol->s.ii->constval,&num,sizeof(Dwarf_Word));
	}
	else if (str_set && SYMBOL_IS_FULL_INSTANCE(cbargs->symbol)) {
	    /* Don't malloc; use our copy of the string table. */
	    if (str_copy) {
		int slen = strlen(str);
		cbargs->symbol->s.ii->constval = malloc(slen+1);
		strncpy(cbargs->symbol->s.ii->constval,str,slen+1);
		cbargs->symbol->s.ii->constval_nofree = 0;
	    }
	    else {
		cbargs->symbol->s.ii->constval = str;
		cbargs->symbol->s.ii->constval_nofree = 1;
	    }
	}
	else if (block_set && SYMBOL_IS_FULL_INSTANCE(cbargs->symbol)) {
	    cbargs->symbol->s.ii->constval = malloc(block.length);
	    memcpy(cbargs->symbol->s.ii->constval,block.data,block.length);
	}
	else 
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] attr %s form %s in bad context\n",
		     cbargs->die_offset,dwarf_attr_string(attr),
		     dwarf_form_string(form));
	break;
    /* XXX: byte/bit sizes/offsets can technically be a reference
     * to another DIE, or an exprloc... but they should always be
     * consts for C!
     */
    case DW_AT_byte_size:
	if (num_set) {
	    if (cbargs->symbol->size_is_bits) {
		vwarnopt(5,LA_DEBUG,LF_DWARFATTR,
			 "[DIE %" PRIx64 "] attr %s: already saw bit_size;"
			 " setting ctbytes.\n",
			 cbargs->die_offset,dwarf_attr_string(attr));

		if (num > (1 << SIZE_CTBYTES_SIZE)) 
		    verror("[DIE %" PRIx64 "] attr %s: ctbytes too large,"
			   " truncating!\n",
			   cbargs->die_offset,dwarf_attr_string(attr));

		cbargs->symbol->size.ctbytes = num;
	    }
	    else {
		cbargs->symbol->size.bytes = num;
		cbargs->symbol->size_is_bytes = 1;
	    }
	}
	else {
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] unrecognized attr %s // form %s mix!\n",
		     cbargs->die_offset,dwarf_attr_string(attr),
		     dwarf_form_string(form));
	}
	break;
    case DW_AT_bit_size:
	if (num_set) {
	    /*
	     * If a type or variable has both a byte_size and a bit_size
	     * (gcc does this for bitfields -- in its DWARF output,
	     * byte_size is the size of the type containing the
	     * bitfield; bit_size is the actual size of the bitfield),
	     * and byte_size is moved into ctbytes (size of containing
	     * integral type).
	     */
	    if (cbargs->symbol->size_is_bytes) {
		uint32_t tmpbytes = cbargs->symbol->size.bytes;
		/* Clear old bytes. */
		cbargs->symbol->size.bytes = 0;
		cbargs->symbol->size_is_bytes = 0;

		if (tmpbytes * 8 > ((1 << SIZE_CTBYTES_SIZE) - 1)) 
		    verror("[DIE %" PRIx64 "] byte_size does not fit into"
			   " ctbytes (triggered by bit_offset); truncating!\n",
			   cbargs->die_offset);
		
		/* Set new (containing) bytes. */
		cbargs->symbol->size.ctbytes = tmpbytes;
	    }

	    if (num > ((1 << SIZE_BITS_SIZE) - 1)) 
		verror("[DIE %" PRIx64 "] bit_size does not fit into"
		       " uint16_t; truncating!\n",
		       cbargs->die_offset);

	    cbargs->symbol->size.bits = num;
	    cbargs->symbol->size_is_bits = 1;
	}
	else {
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] unrecognized attr %s // form %s mix!\n",
		     cbargs->die_offset,dwarf_attr_string(attr),
		     dwarf_form_string(form));
	}
	break;
    case DW_AT_bit_offset:
	if (num_set) {
	    /*
	     * If a type or variable has both a byte_size and a bit_size
	     * (gcc does this for bitfields -- in its DWARF output,
	     * byte_size is the size of the type containing the
	     * bitfield; bit_size is the actual size of the bitfield),
	     * and byte_size is moved into ctbytes (size of containing
	     * integral type).
	     */
	    if (cbargs->symbol->size_is_bytes) {
		uint32_t tmpbytes = cbargs->symbol->size.bytes;
		/* Clear old bytes. */
		cbargs->symbol->size.bytes = 0;
		cbargs->symbol->size_is_bytes = 0;

		if (tmpbytes * 8 > ((1 << SIZE_CTBYTES_SIZE) - 1)) 
		    verror("[DIE %" PRIx64 "] byte_size does not fit into"
			   " ctbytes (triggered by bit_offset); truncating!\n",
			   cbargs->die_offset);
		
		/* Set new (containing) bytes. */
		cbargs->symbol->size.ctbytes = tmpbytes;
	    }

	    if (num > ((1 << SIZE_OFFSET_SIZE) - 1)) 
		verror("[DIE %" PRIx64 "] bit_offset does not fit into"
		       " offset; truncating!\n",
		       cbargs->die_offset);

	    cbargs->symbol->size.offset = num;
	    cbargs->symbol->size_is_bits = 1;
	}
	else {
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] unrecognized attr %s // form %s mix!\n",
		     cbargs->die_offset,dwarf_attr_string(attr),
		     dwarf_form_string(form));
	}
	break;
    case DW_AT_sibling:
	/* we process all DIEs, so no need to skip any child content. */
	break;
    case DW_AT_data_member_location:
	/* can be either an exprloc, loclistptr, or a constant. */
	if (block_set) {
	    if (SYMBOL_IS_VAR(cbargs->symbol)
		&& cbargs->symbol->ismember) {
		if (SYMBOL_IS_FULL(cbargs->symbol)) {
		    if (get_static_ops(cbargs->dwflmod,cbargs->dbg,
				       cbargs->meta->version,
				       cbargs->meta->addrsize,
				       cbargs->meta->offsize,
				       block.length,block.data,attr,
				       &cbargs->symbol->s.ii->d.v.l)) {
			verror("[DIE %" PRIx64 "] failed get_static_ops at"
			       " attrval %" PRIx64 " for attr %s // form %s\n",
			       cbargs->die_offset,num,dwarf_attr_string(attr),
			       dwarf_form_string(form));
		    }
		}
	    }
	    else {
		vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
			 "[DIE %" PRIx64 "] no/bad symbol for attr %s // form %s\n",
			 cbargs->die_offset,dwarf_attr_string(attr),
			 dwarf_form_string(form));
	    }
	}
	else if (num_set && (form == DW_FORM_data4 
			     || form == DW_FORM_data8)) {
	    if (SYMBOL_IS_VAR(cbargs->symbol)
		&& cbargs->symbol->ismember) {
		if (SYMBOL_IS_FULL(cbargs->symbol)) {
		    cbargs->symbol->s.ii->d.v.l.loctype = LOCTYPE_LOCLIST;

		    cbargs->symbol->s.ii->d.v.l.l.loclist = loc_list_create(0);

		    if (get_loclist(cbargs->dwflmod,cbargs->dbg,
				    cbargs->meta->version,
				    cbargs->meta->addrsize,
				    cbargs->meta->offsize,
				    attr,num,cbargs->debugfile,cbargs->cu_base,
				    cbargs->symbol->s.ii->d.v.l.l.loclist)) {
			verror("[DIE %" PRIx64 "] failed get_loclist at"
			       " attrval %" PRIx64 " for attr %s // form %s\n",
			       cbargs->die_offset,num,dwarf_attr_string(attr),
			       dwarf_form_string(form));
		    }
		}
	    }
	    else {
		vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
			 "[DIE %" PRIx64 "] no/bad symbol for attr %s // form %s\n",
			 cbargs->die_offset,dwarf_attr_string(attr),
			 dwarf_form_string(form));
	    }
	}
	else if (num_set
/* not sure if 137 is the right number! */
#if _INT_ELFUTILS_VERSION > 137
	    && form != DW_FORM_sec_offset
#endif
	    && (cbargs->meta->version >= 4
		|| (form != DW_FORM_data4 
		    && form != DW_FORM_data8))) {
	    /* it's a constant */
	    if (SYMBOL_IS_VAR(cbargs->symbol)) {
		if (SYMBOL_IS_FULL(cbargs->symbol)) {
		    cbargs->symbol->s.ii->d.v.l.loctype = LOCTYPE_MEMBER_OFFSET;
		    cbargs->symbol->s.ii->d.v.l.l.member_offset = (int32_t)num;
		}
	    }
	    else {
		vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
			 "[DIE %" PRIx64 "] attrval %" PRIx64 " for attr %s in bad context\n",
			 cbargs->die_offset,num,dwarf_attr_string(attr));
	    }
	}
	break;
    case DW_AT_frame_base:
	/* if it's a loclist */
	if (num_set && (form == DW_FORM_data4 
			|| form == DW_FORM_data8)) {
	    if (SYMBOL_IS_FUNCTION(cbargs->symbol)) {
		cbargs->symbol->s.ii->d.f.fbisloclist = 1;

		cbargs->symbol->s.ii->d.f.fb.list = loc_list_create(0);

		if (get_loclist(cbargs->dwflmod,cbargs->dbg,cbargs->meta->version,
				cbargs->meta->addrsize,cbargs->meta->offsize,
				attr,num,
				cbargs->debugfile,
				cbargs->cu_base,
				cbargs->symbol->s.ii->d.f.fb.list)) {
		    verror("[DIE %" PRIx64 "] failed to get loclist attrval %" PRIx64 " for attr %s in function symbol %s\n",
			   cbargs->die_offset,num,dwarf_attr_string(attr),
			   symbol_get_name_orig(cbargs->symbol));
		}
	    }
	    else {
		vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
			 "[DIE %" PRIx64 "] no/bad symbol for loclist for attr %s\n",
			 cbargs->die_offset,dwarf_attr_string(attr));
	    }
	}
	/* if it's an exprloc in a block */
	else if (block_set) {
	    if (SYMBOL_IS_FUNCTION(cbargs->symbol)) {
		cbargs->symbol->s.ii->d.f.fbissingleloc = 1;

		cbargs->symbol->s.ii->d.f.fb.loc = \
		    (struct location *)malloc(sizeof(struct location));
		memset(cbargs->symbol->s.ii->d.f.fb.loc,0,sizeof(struct location));

		if (get_static_ops(cbargs->dwflmod,cbargs->dbg,cbargs->meta->version,
				   cbargs->meta->addrsize,cbargs->meta->offsize,
				   block.length,block.data,attr,
				   cbargs->symbol->s.ii->d.f.fb.loc)) {
		    verror("[DIE %" PRIx64 "] failed to get single loc attrval %" PRIx64 " for attr %s in function symbol %s\n",
			   cbargs->die_offset,num,dwarf_attr_string(attr),
			   symbol_get_name_orig(cbargs->symbol));
		}
	    }
	    else {
		vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
			 "[DIE %" PRIx64 "] no/bad symbol for single loc for"
			 " attr %s\n",
			 cbargs->die_offset,dwarf_attr_string(attr));
	    }
	}
	else {
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] frame_base not num/block; attr %s //"
		     " form %s mix!\n",
		     cbargs->die_offset,dwarf_attr_string(attr),
		     dwarf_form_string(form));
	}
	break;
    case DW_AT_ranges:
	/* always a rangelistptr */
	if (num_set && (form == DW_FORM_sec_offset 
			|| form == DW_FORM_data4 
			|| form == DW_FORM_data8)) {
	    if (cbargs->symtab) {
		/* Just in case the symtab already has range info, we
		 * have to get the list, then "update" the entries in
		 * the real symtab list -- which will add them if they
		 * don't exist, or update any conflicting entries.
		 */
		struct range_list rl;
		int i;
		memset(&rl,0,sizeof(rl));

		if (get_rangelist(cbargs->dwflmod,cbargs->dbg,cbargs->meta->version,
				  cbargs->meta->addrsize,cbargs->meta->offsize,
				  attr,num,
				  cbargs->debugfile,cbargs->cu_base,
				  &rl)) {
		    verror("[DIE %" PRIx64 "] failed to get rangelist attrval %" PRIx64 " for attr %s in symtab\n",
			   cbargs->die_offset,num,dwarf_attr_string(attr));
		}
		else {
		    for (i = 0; i < rl.len; ++i) {
			symtab_update_range(cbargs->symtab,
					    rl.list[i]->start,rl.list[i]->end,
					    RANGE_TYPE_LIST);
		    }
		}

		range_list_internal_free(&rl);
	    }

	    if (cbargs->symbol && SYMBOL_IS_FULL_LABEL(cbargs->symbol)
		&& cbargs->symbol->s.ii->d.l.range.rtype == RANGE_TYPE_NONE) {
		if (get_rangelist(cbargs->dwflmod,cbargs->dbg,cbargs->meta->version,
				  cbargs->meta->addrsize,cbargs->meta->offsize,
				  attr,num,
				  cbargs->debugfile,cbargs->cu_base,
				  &cbargs->symbol->s.ii->d.l.range.r.rlist)) {
		    verror("[DIE %" PRIx64 "] failed to get rangelist attrval %" PRIx64 " for attr %s in label symbol %s\n",
			   cbargs->die_offset,num,dwarf_attr_string(attr),
			   symbol_get_name_orig(cbargs->symbol));
		}
	    }
	}
	else {
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] bad rangelist attr %s // form %s!\n",
		     cbargs->die_offset,dwarf_attr_string(attr),
		     dwarf_form_string(form));
	}
	break;
    case DW_AT_location:
	/* We only accept this for params and variables */
	if (SYMBOL_IS_VAR(cbargs->symbol)) {
	    if (num_set && (form == DW_FORM_sec_offset 
			    || form == DW_FORM_data4 
			    || form == DW_FORM_data8)) {
		struct loc_list *loclist;
		if (SYMBOL_IS_FULL(cbargs->symbol)) {
		    cbargs->symbol->s.ii->d.v.l.loctype = LOCTYPE_LOCLIST;
		    cbargs->symbol->s.ii->d.v.l.l.loclist = loc_list_create(0);
		    loclist = cbargs->symbol->s.ii->d.v.l.l.loclist;
		}
		else {
		    loclist = loc_list_create(0);
		}

		if (get_loclist(cbargs->dwflmod,cbargs->dbg,cbargs->meta->version,
				cbargs->meta->addrsize,cbargs->meta->offsize,
				attr,num,
				cbargs->debugfile,
				cbargs->cu_base,
				loclist)) {
		    vwarnopt(9,LA_DEBUG,LF_DWARFATTR,
			     "[DIE %" PRIx64 "] failed to get loclist"
			     " attrval %" PRIx64 " for attr %s in var symbol %s\n",
			     cbargs->die_offset,num,dwarf_attr_string(attr),
			     symbol_get_name_orig(cbargs->symbol));
		    loc_list_free(loclist);
		    if (SYMBOL_IS_FULL(cbargs->symbol)) {
			cbargs->symbol->s.ii->d.v.l.loctype = LOCTYPE_UNKNOWN;
			cbargs->symbol->s.ii->d.v.l.l.loclist = NULL;
		    }
		}

		if (SYMBOL_IS_FUNCTION(cbargs->symbol)
		    || SYMBOL_IS_LABEL(cbargs->symbol)) {
		    int i;
		    for (i = 0; i < loclist->len; ++i) {
			if (loclist->list[i]->start < cbargs->symbol->base_addr) {
			    cbargs->symbol->base_addr = loclist->list[i]->start;
			    cbargs->symbol->has_base_addr = 1;
			}
		    }
		}

		if (SYMBOL_IS_PARTIAL(cbargs->symbol)) {
		    loc_list_free(loclist);
		}
	    }
	    else if (block_set) {
		struct location *loc;
		if (SYMBOL_IS_FULL(cbargs->symbol)) {
		    loc = &cbargs->symbol->s.ii->d.v.l;
		}
		else {
		    loc = (struct location *)malloc(sizeof(struct location));
		    memset(loc,0,sizeof(*loc));
		}
		get_static_ops(cbargs->dwflmod,cbargs->dbg,
			       cbargs->meta->version,cbargs->meta->addrsize,
			       cbargs->meta->offsize,
			       block.length,block.data,attr,
			       loc);

		if (loc->loctype == LOCTYPE_ADDR 
		    && loc->l.addr < cbargs->symbol->base_addr) {
		    cbargs->symbol->base_addr = loc->l.addr;
		    cbargs->symbol->has_base_addr = 1;
		}

		if (SYMBOL_IS_PARTIAL(cbargs->symbol)) 
		    free(loc);
	    }
	    else {
		vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
			 "[DIE %" PRIx64 "] loclist: bad attr %s // form %s!\n",
			 cbargs->die_offset,dwarf_attr_string(attr),
			 dwarf_form_string(form));
	    }
	}
	else {
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] bad attr %s // form %s!\n",
		     cbargs->die_offset,dwarf_attr_string(attr),
		     dwarf_form_string(form));
	}
	break;
    case DW_AT_lower_bound:
	if (num_set && num) {
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] we only support lower_bound attrs"
		     " of 0 (%" PRIu64 ")!\n",
		     cbargs->die_offset,num);
	}
	else {
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] unsupported attr %s // form %s!\n",
		     cbargs->die_offset,dwarf_attr_string(attr),
		     dwarf_form_string(form));
	}
	break;
    case DW_AT_count:
	vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		 "[DIE %" PRIx64 "] interpreting AT_count as AT_upper_bound!\n",
		 cbargs->die_offset);
    case DW_AT_upper_bound:
	/* it's a constant, not a block op */
	if (num_set && form != DW_FORM_sec_offset) {
	    if (!cbargs->symbol && cbargs->parentsymbol
		&& cbargs->parentsymbol->type == SYMBOL_TYPE_TYPE
		&& cbargs->parentsymbol->datatype_code == DATATYPE_ARRAY) {
		if (cbargs->parentsymbol->s.ti->d.a.count == \
		    cbargs->parentsymbol->s.ti->d.a.alloc) {
		    if (!realloc(cbargs->parentsymbol->s.ti->d.a.subranges,
				 sizeof(int)*(cbargs->parentsymbol->s.ti->d.a.alloc + 4))) {
			verror("realloc: %s",strerror(errno));
			return DWARF_CB_ABORT;
		    }
		    cbargs->parentsymbol->s.ti->d.a.alloc += 4;
		}

		cbargs->parentsymbol->s.ti->d.a.subranges[cbargs->parentsymbol->s.ti->d.a.count] = (int)num;
		++cbargs->parentsymbol->s.ti->d.a.count;
	    }
	    else {
		vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
			 "[DIE %" PRIx64 "] attrval %" PRIx64 " for"
			 " attr %s in bad context\n",
			 cbargs->die_offset,num,dwarf_attr_string(attr));
	    }
	    break;
	}
	else {
	    vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		     "[DIE %" PRIx64 "] unsupported attr %s // form %s!\n",
		     cbargs->die_offset,dwarf_attr_string(attr),
		     dwarf_form_string(form));
	}
	break;

    /* Skip these things. */
    case DW_AT_MIPS_linkage_name:
    case DW_AT_artificial:
	break;
    /* Skip DW_AT_GNU_vector, which not all elfutils versions know about. */
    case 8455:
	break;

    default:
	vwarnopt(3,LA_DEBUG,LF_DWARFATTR,
		 "[DIE %" PRIx64 "] unrecognized attr %s (%d)\n",
		 cbargs->die_offset,dwarf_attr_string(attr),attr);
	//goto errout;
	break;
    }

    goto out;

 errout:
    return DWARF_CB_ABORT;
 out:
    return 0;
}

static inline void set_language(struct dwarf_cu_meta *meta,int language) {
    switch (language) {
    case DW_LANG_C89:
	meta->language = "C89";
	break;
    case DW_LANG_C:
	meta->language = "C";
	break;
    case DW_LANG_Ada83:
	meta->language = "Ada83";
	break;
    case DW_LANG_C_plus_plus:
	meta->language = "C++";
	break;
    case DW_LANG_Cobol74:
	meta->language = "Cobol74";
	break;
    case DW_LANG_Cobol85:
	meta->language = "Cobol85";
	break;
    case DW_LANG_Fortran77:
	meta->language = "Fortran77";
	break;
    case DW_LANG_Fortran90:
	meta->language = "Fortran90";
	break;
    case DW_LANG_Pascal83:
	meta->language = "Pascal83";
	break;
    case DW_LANG_Modula2:
	meta->language = "Modula2";
	break;
    case DW_LANG_Java:
	meta->language = "Java";
	break;
    case DW_LANG_C99:
	meta->language = "C99";
	break;
    case DW_LANG_Ada95:
	meta->language = "Ada95";
	break;
    case DW_LANG_Fortran95:
	meta->language = "Fortran95";
	break;
    case DW_LANG_PL1:
	meta->language = "PL/1";
	break;
    case DW_LANG_Objc:
	meta->language = "ObjectiveC";
	break;
    case DW_LANG_ObjC_plus_plus:
	meta->language = "ObjectiveC++";
	break;
    case DW_LANG_UPC:
	meta->language = "UnifiedParallelC";
	break;
    case DW_LANG_D:
	meta->language = "D";
	break;
    case DW_LANG_Python:
	meta->language = "Python";
	break;
    case DW_LANG_Go:
	meta->language = "Go";
	break;
    default:
	meta->language = NULL;
	break;
    }

    meta->lang_code = language;
}

static int get_rangelist(Dwfl_Module *dwflmod,Dwarf *dbg,unsigned int vers,
			 unsigned int addrsize,unsigned int offsetsize,
			 unsigned int attr,Dwarf_Word offset,
			 struct debugfile *debugfile,ADDR cu_base,
			 struct range_list *list) {
    char *readp;
    char *endp;
    ptrdiff_t loffset;
    Dwarf_Addr begin;
    Dwarf_Addr end;
    int len = 0;
    int have_base = 0;
    Dwarf_Addr base = 0;

    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;

    if (!debugfile->rangetab
	|| offset > debugfile->rangetablen) {
	errno = EFAULT;
	return -1;
    }

    readp = debugfile->rangetab + offset;
    endp = debugfile->rangetab + debugfile->rangetablen;

    vdebug(5,LA_DEBUG,LF_DLOC,"starting (rangetab len %d, offset %d)\n",
	   debugfile->rangetablen,offset);

    while (readp < endp) {
	loffset = readp - debugfile->rangetab;

	if (unlikely((debugfile->rangetablen - loffset) < addrsize * 2)) {
	    verror("[%6tx] invalid loclist entry\n",loffset);
	    break;
	}

	if (addrsize == 8) {
	    begin = read_8ubyte_unaligned_inc(obo,readp);
	    end = read_8ubyte_unaligned_inc(obo,readp);
	}
	else {
	    begin = read_4ubyte_unaligned_inc(obo,readp);
	    end = read_4ubyte_unaligned_inc(obo,readp);
	    if (begin == (Dwarf_Addr)(uint32_t)-1)
		begin = (Dwarf_Addr)-1l;
	}

	if (begin == (Dwarf_Addr)-1l) {
	    /* Base address entry.  */
	    vdebug(5,LA_DEBUG,LF_DLOC,"[%6tx] base address 0x%" PRIxADDR "\n",
		   loffset,end);
	    have_base = 1;
	    base = end;
	}
	else if (begin == 0 && end == 0) {
	    /* End of list entry.  */
	    if (len == 0)
		vwarn("[%6tx] empty list\n",loffset);
	    else 
		vdebug(5,LA_DEBUG,LF_DLOC,"[%6tx] end of list\n");
	    break;
	}
	else {
	    ++len;

	    /* We have a range entry.  */
	    range_list_add(list,
			   (have_base) ? begin + base : begin + cu_base,
			   (have_base) ? end + base : end + cu_base);
	}
    }

    return 0;
}

static int get_loclist(Dwfl_Module *dwflmod,Dwarf *dbg,unsigned int vers,
		       unsigned int addrsize,unsigned int offsetsize,
		       unsigned int attr,Dwarf_Word offset,
		       struct debugfile *debugfile,ADDR cu_base,
		       struct loc_list *list) {
    char *readp;
    char *endp;
    ptrdiff_t loffset;
    Dwarf_Addr begin;
    Dwarf_Addr end;
    int len = 0;
    uint16_t exprlen;
    int have_base = 0;
    Dwarf_Addr base = 0;
    struct location *tmploc;

    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;

    if (!debugfile->loctab
	|| offset > debugfile->loctablen) {
	errno = EFAULT;
	return -1;
    }

    readp = debugfile->loctab + offset;
    endp = debugfile->loctab + debugfile->loctablen;

    vdebug(5,LA_DEBUG,LF_DLOC,"starting (loctab len %d, offset %d)\n",
	   debugfile->loctablen,offset);

    while (readp < endp) {
	loffset = readp - debugfile->loctab;

	if (unlikely((debugfile->loctablen - loffset) < addrsize * 2)) {
	    verror("[%6tx] invalid loclist entry\n",loffset);
	    break;
	}

	if (addrsize == 8) {
	    begin = read_8ubyte_unaligned_inc(obo,readp);
	    end = read_8ubyte_unaligned_inc(obo,readp);
	}
	else {
	    begin = read_4ubyte_unaligned_inc(obo,readp);
	    end = read_4ubyte_unaligned_inc(obo,readp);
	    if (begin == (Dwarf_Addr)(uint32_t)-1)
		begin = (Dwarf_Addr)-1l;
	}

	if (begin == (Dwarf_Addr)-1l) {
	    /* Base address entry.  */
	    vdebug(5,LA_DEBUG,LF_DLOC,"[%6tx] base address 0x%" PRIxADDR "\n",
		   loffset,end);
	    have_base = 1;
	    base = end;
	}
	else if (begin == 0 && end == 0) {
	    /* End of list entry.  */
	    if (len == 0)
		vwarnopt(4,LA_DEBUG,LF_DWARF | LF_DLOC,
			 "[%6tx] empty list\n",loffset);
	    else 
		vdebug(5,LA_DEBUG,LF_DLOC,"[%6tx] end of list\n");
	    break;
	}
	else {
	    ++len;

	    /* We have a location expression entry.  */
	    exprlen = read_2ubyte_unaligned_inc(obo,readp);

	    vdebug(5,LA_DEBUG,LF_DLOC,"[%6tx] loc expr range 0x%" PRIxADDR ",0x%" PRIxADDR ", len %hd\n",
		   loffset,begin,end,exprlen);

	    if (endp - readp <= (ptrdiff_t) exprlen) {
		verror("[%6tx] invalid exprlen (%hd) in entry\n",loffset,exprlen);
		break;
	    }
	    else {
		vdebug(5,LA_DEBUG,LF_DLOC,"[%6tx] loc expr len (%hd) in entry\n",
		       loffset,exprlen);
	    }

	    tmploc = location_create();

	    if (get_static_ops(dwflmod,dbg,3,addrsize,offsetsize,
			       exprlen,(unsigned char *)readp,attr,
			       tmploc)) {
		vwarnopt(9,LA_DEBUG,LF_DLOC,
			 "get_static_ops (%d) failed!\n",exprlen);
		location_free(tmploc);
		return -1;
	    }
	    else {
		vdebug(5,LA_DEBUG,LF_DLOC,
		       "get_static_ops (%d) succeeded!\n",exprlen);
	    }

	    if (loc_list_add(list,
			     (have_base) ? begin + base : begin + cu_base,
			     (have_base) ? end + base : end + cu_base,
			     tmploc)) {
		verror("loc_list_add failed!\n");
		location_free(tmploc);
	    }

	    readp += exprlen;
	}
    }

    return 0;
}


/*
 * This originally came from readelf.c, but I rewrote much of it.  Some
 * operations can be evaluated statically to produce a fixed location
 * that never changes, except for a simple offset.  Others actually need
 * runtime information.  So, we evaluate everything that is simple to
 * do, and punt the rest for runtime evaluation against actual machine
 * data.
 */
static int get_static_ops(Dwfl_Module *dwflmod,Dwarf *dbg,unsigned int vers,
			  unsigned int addrsize,unsigned int offset_size,
			  Dwarf_Word len,const unsigned char *data,
			  unsigned int attr,struct location *retval) {

    /* const unsigned int ref_size = vers < 3 ? addrsize : offset_size; */

    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;

    /* save the originals for later for runtime computation if we need */
    const unsigned char *origdata = data;
    Dwarf_Word origlen = len;

    static const char *const known[] = {
	[DW_OP_addr] = "addr",
	[DW_OP_deref] = "deref",
	[DW_OP_const1u] = "const1u",
	[DW_OP_const1s] = "const1s",
	[DW_OP_const2u] = "const2u",
	[DW_OP_const2s] = "const2s",
	[DW_OP_const4u] = "const4u",
	[DW_OP_const4s] = "const4s",
	[DW_OP_const8u] = "const8u",
	[DW_OP_const8s] = "const8s",
	[DW_OP_constu] = "constu",
	[DW_OP_consts] = "consts",
	[DW_OP_dup] = "dup",
	[DW_OP_drop] = "drop",
	[DW_OP_over] = "over",
	[DW_OP_pick] = "pick",
	[DW_OP_swap] = "swap",
	[DW_OP_rot] = "rot",
	[DW_OP_xderef] = "xderef",
	[DW_OP_abs] = "abs",
	[DW_OP_and] = "and",
	[DW_OP_div] = "div",
	[DW_OP_minus] = "minus",
	[DW_OP_mod] = "mod",
	[DW_OP_mul] = "mul",
	[DW_OP_neg] = "neg",
	[DW_OP_not] = "not",
	[DW_OP_or] = "or",
	[DW_OP_plus] = "plus",
	[DW_OP_plus_uconst] = "plus_uconst",
	[DW_OP_shl] = "shl",
	[DW_OP_shr] = "shr",
	[DW_OP_shra] = "shra",
	[DW_OP_xor] = "xor",
	[DW_OP_bra] = "bra",
	[DW_OP_eq] = "eq",
	[DW_OP_ge] = "ge",
	[DW_OP_gt] = "gt",
	[DW_OP_le] = "le",
	[DW_OP_lt] = "lt",
	[DW_OP_ne] = "ne",
	[DW_OP_skip] = "skip",
	[DW_OP_lit0] = "lit0",
	[DW_OP_lit1] = "lit1",
	[DW_OP_lit2] = "lit2",
	[DW_OP_lit3] = "lit3",
	[DW_OP_lit4] = "lit4",
	[DW_OP_lit5] = "lit5",
	[DW_OP_lit6] = "lit6",
	[DW_OP_lit7] = "lit7",
	[DW_OP_lit8] = "lit8",
	[DW_OP_lit9] = "lit9",
	[DW_OP_lit10] = "lit10",
	[DW_OP_lit11] = "lit11",
	[DW_OP_lit12] = "lit12",
	[DW_OP_lit13] = "lit13",
	[DW_OP_lit14] = "lit14",
	[DW_OP_lit15] = "lit15",
	[DW_OP_lit16] = "lit16",
	[DW_OP_lit17] = "lit17",
	[DW_OP_lit18] = "lit18",
	[DW_OP_lit19] = "lit19",
	[DW_OP_lit20] = "lit20",
	[DW_OP_lit21] = "lit21",
	[DW_OP_lit22] = "lit22",
	[DW_OP_lit23] = "lit23",
	[DW_OP_lit24] = "lit24",
	[DW_OP_lit25] = "lit25",
	[DW_OP_lit26] = "lit26",
	[DW_OP_lit27] = "lit27",
	[DW_OP_lit28] = "lit28",
	[DW_OP_lit29] = "lit29",
	[DW_OP_lit30] = "lit30",
	[DW_OP_lit31] = "lit31",
	[DW_OP_reg0] = "reg0",
	[DW_OP_reg1] = "reg1",
	[DW_OP_reg2] = "reg2",
	[DW_OP_reg3] = "reg3",
	[DW_OP_reg4] = "reg4",
	[DW_OP_reg5] = "reg5",
	[DW_OP_reg6] = "reg6",
	[DW_OP_reg7] = "reg7",
	[DW_OP_reg8] = "reg8",
	[DW_OP_reg9] = "reg9",
	[DW_OP_reg10] = "reg10",
	[DW_OP_reg11] = "reg11",
	[DW_OP_reg12] = "reg12",
	[DW_OP_reg13] = "reg13",
	[DW_OP_reg14] = "reg14",
	[DW_OP_reg15] = "reg15",
	[DW_OP_reg16] = "reg16",
	[DW_OP_reg17] = "reg17",
	[DW_OP_reg18] = "reg18",
	[DW_OP_reg19] = "reg19",
	[DW_OP_reg20] = "reg20",
	[DW_OP_reg21] = "reg21",
	[DW_OP_reg22] = "reg22",
	[DW_OP_reg23] = "reg23",
	[DW_OP_reg24] = "reg24",
	[DW_OP_reg25] = "reg25",
	[DW_OP_reg26] = "reg26",
	[DW_OP_reg27] = "reg27",
	[DW_OP_reg28] = "reg28",
	[DW_OP_reg29] = "reg29",
	[DW_OP_reg30] = "reg30",
	[DW_OP_reg31] = "reg31",
	[DW_OP_breg0] = "breg0",
	[DW_OP_breg1] = "breg1",
	[DW_OP_breg2] = "breg2",
	[DW_OP_breg3] = "breg3",
	[DW_OP_breg4] = "breg4",
	[DW_OP_breg5] = "breg5",
	[DW_OP_breg6] = "breg6",
	[DW_OP_breg7] = "breg7",
	[DW_OP_breg8] = "breg8",
	[DW_OP_breg9] = "breg9",
	[DW_OP_breg10] = "breg10",
	[DW_OP_breg11] = "breg11",
	[DW_OP_breg12] = "breg12",
	[DW_OP_breg13] = "breg13",
	[DW_OP_breg14] = "breg14",
	[DW_OP_breg15] = "breg15",
	[DW_OP_breg16] = "breg16",
	[DW_OP_breg17] = "breg17",
	[DW_OP_breg18] = "breg18",
	[DW_OP_breg19] = "breg19",
	[DW_OP_breg20] = "breg20",
	[DW_OP_breg21] = "breg21",
	[DW_OP_breg22] = "breg22",
	[DW_OP_breg23] = "breg23",
	[DW_OP_breg24] = "breg24",
	[DW_OP_breg25] = "breg25",
	[DW_OP_breg26] = "breg26",
	[DW_OP_breg27] = "breg27",
	[DW_OP_breg28] = "breg28",
	[DW_OP_breg29] = "breg29",
	[DW_OP_breg30] = "breg30",
	[DW_OP_breg31] = "breg31",
	[DW_OP_regx] = "regx",
	[DW_OP_fbreg] = "fbreg",
	[DW_OP_bregx] = "bregx",
	[DW_OP_piece] = "piece",
	[DW_OP_deref_size] = "deref_size",
	[DW_OP_xderef_size] = "xderef_size",
	[DW_OP_nop] = "nop",
	[DW_OP_push_object_address] = "push_object_address",
	[DW_OP_call2] = "call2",
	[DW_OP_call4] = "call4",
	[DW_OP_call_ref] = "call_ref",
	[DW_OP_form_tls_address] = "form_tls_address",
	[DW_OP_call_frame_cfa] = "call_frame_cfa",
	[DW_OP_bit_piece] = "bit_piece",
/* not sure if 137 is the right number! */
#if _INT_ELFUTILS_VERSION > 137
	[DW_OP_implicit_value] = "implicit_value",
	[DW_OP_stack_value] = "stack_value",
#endif
/* not sure if 142 is the right number! */
#if _INT_ELFUTILS_VERSION > 142
	[DW_OP_GNU_implicit_pointer] = "GNU_implicit_pointer",
#endif
    };

    if (len == 0) {
	vwarn("empty dwarf block num!\n");
	goto errout;
    }

#define NEED(n)		if (len < (Dwarf_Word) (n)) goto errout
#define CONSUME(n)	NEED (n); else len -= (n)

/* If this is the only thing in this op list, be done now. */
#define ONLYOP(location,type,field,value) \
    if (start == (origdata + 1) && len == 0) {	\
	location->loctype = (type);	  \
	location->l.field = (value);	  \
	goto out;			  \
    }					  \
    else {				  \
	vwarnopt(3,LA_DEBUG,LF_DWARFOPS,					\
		 "unsupported %s op with other ops!\n",known[op]);	\
    }

#define OPCONSTU(size,tt)			\
    NEED(size);						\
    u64 = (uint64_t)*((tt *)data);			\
    data += size;					\
    CONSUME(size);					\
    vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s -> 0x%" PRIuMAX "\n",known[op],u64);	\
    if (attr == DW_AT_data_member_location) {		\
	ONLYOP(retval,LOCTYPE_MEMBER_OFFSET,		\
	       member_offset,(int32_t)u64);		\
    }							\
    else {					       	\
	vwarnopt(3,LA_DEBUG,LF_DWARFOPS,				\
		 "assuming constXu is for loctype_addr!\n");	\
	ONLYOP(retval,LOCTYPE_ADDR,addr,u64);		\
    }

#define OPCONSTS(size,tt)			\
    NEED(size);						\
    s64 = (int64_t)*((tt *)data);			\
    data += size;					\
    CONSUME(size);					\
    vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s -> 0x%" PRIxMAX "\n",known[op],s64);	\
    if (attr == DW_AT_data_member_location) {		\
	ONLYOP(retval,LOCTYPE_MEMBER_OFFSET,		\
	       member_offset,(int32_t)s64);		\
    }							\
    else {					       	\
	vwarnopt(3,LA_DEBUG,LF_DWARFOPS,			\
		 "assuming constXs is for loctype_addr!\n");	\
	ONLYOP(retval,LOCTYPE_ADDR,addr,(uint64_t)s64);		\
    }

    while (len-- > 0) {
	uint_fast8_t op = *data++;
	const unsigned char *start = data;

	if (op < sizeof known / sizeof known[0] && known[op] != NULL) 
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s with len = %d\n",known[op],len);
	else
	    vwarnopt(2,LA_DEBUG,LF_DWARF | LF_DWARFOPS,
		     "unknown op 0x%hhx with len = %d\n",op,len);

	Dwarf_Word addr;
	uint8_t reg;
	uint64_t u64;
	int64_t s64;

	switch (op) {
	case DW_OP_addr:
	    NEED(addrsize);
	    if (addrsize == 4)
		addr = read_4ubyte_unaligned(obo,data);
	    else {
		assert(addrsize == 8);
		addr = read_8ubyte_unaligned(obo,data);
	    }
	    data += addrsize;
	    CONSUME(addrsize);
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s -> 0x%" PRIx64 "\n",known[op],addr);
	    if (start == (origdata + 1) && len == 0) {
		retval->loctype = LOCTYPE_ADDR;
		retval->l.addr = addr;
		goto out;
	    }
	    else {
		vwarnopt(3,LA_DEBUG,LF_DWARFOPS,
			 "unsupported %s op with other ops!\n",known[op]);
	    }
	    //ONLYOP(retval,LOCTYPE_ADDR,addr,((uint64_t)addr));
	    break;

	case DW_OP_reg0...DW_OP_reg31:
	    reg = op - (uint8_t)DW_OP_reg0;

	    vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s -> 0x%" PRIu8 "\n",known[op],reg);
	    ONLYOP(retval,LOCTYPE_REG,reg,reg);
	    break;
	//case DW_OP_piece:
	case DW_OP_regx:
	    NEED(1);
	    get_uleb128(u64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s -> 0x%" PRIuMAX "\n",known[op],u64);
	    ONLYOP(retval,LOCTYPE_REG,reg,(uint8_t)u64);
	    break;

	case DW_OP_plus_uconst:
	case DW_OP_constu:
	    NEED(1);
	    get_uleb128(u64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s -> 0x%" PRIuMAX "\n",known[op],u64);
	    if (attr == DW_AT_data_member_location) {
		ONLYOP(retval,LOCTYPE_MEMBER_OFFSET,
		       member_offset,(int32_t)u64);
	    }
	    else {
		vwarnopt(3,LA_DEBUG,LF_DWARFOPS,
			 "assuming uconst/constu is for loctype_addr!\n");
		ONLYOP(retval,LOCTYPE_ADDR,
		       addr,(uint64_t)u64);
	    }
	    break;
	case DW_OP_consts:
	    NEED(1);
	    get_sleb128(s64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s -> 0x%" PRIxMAX "\n",known[op],s64);
	    if (attr == DW_AT_data_member_location) {
		ONLYOP(retval,LOCTYPE_MEMBER_OFFSET,
		       member_offset,(int32_t)s64);
	    }
	    else {
		vwarnopt(3,LA_DEBUG,LF_DWARFOPS,
			 "assuming consts is for loctype_addr!\n");
		ONLYOP(retval,LOCTYPE_ADDR,
		       addr,(uint64_t)s64);
	    }
	    break;
	case DW_OP_const1u:
	    OPCONSTU(1,uint8_t);
	    break;
	case DW_OP_const2u:
	    OPCONSTU(2,uint16_t);
	    break;
	case DW_OP_const4u:
	    OPCONSTU(4,uint32_t);
	    break;
	case DW_OP_const8u:
	    OPCONSTU(8,uint64_t);
	    break;
	case DW_OP_const1s:
	    OPCONSTS(1,int8_t);
	    break;
	case DW_OP_const2s:
	    OPCONSTS(2,int16_t);
	    break;
	case DW_OP_const4s:
	    OPCONSTS(4,int32_t);
	    break;
	case DW_OP_const8s:
	    OPCONSTS(8,int64_t);
	    break;
	/*
	case DW_OP_bit_piece:
	  start = data;
	  uint64_t uleb2;
	  NEED (2);
	  get_uleb128 (uleb, data); // XXX check overrun
	  get_uleb128 (uleb2, data); // XXX check overrun 
	  //printf ("%*s[%4" PRIuMAX "] %s %" PRIu64 ", %" PRIu64 "\n",
	  //indent, "", (uintmax_t) offset, known[op], uleb, uleb2);
	  CONSUME (data - start);
	  break;
	*/
	case DW_OP_fbreg:
	  NEED(1);
	  get_sleb128(s64,data); /* XXX check overrun */
	  CONSUME(data - start);
	  vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s -> fbreg offset %ld\n",known[op],s64);
	  ONLYOP(retval,LOCTYPE_FBREG_OFFSET,fboffset,s64);
	  break;
	case DW_OP_breg0 ... DW_OP_breg31:
	    NEED(1);
	    get_sleb128(s64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s -> reg (%d) offset %ld\n",known[op],
		   (uint8_t)(op - DW_OP_breg0),s64);
	    retval->l.regoffset.offset = s64;
	    ONLYOP(retval,LOCTYPE_REG_OFFSET,regoffset.reg,
		   (uint8_t)(op - DW_OP_breg0));
	    break;
	case DW_OP_bregx:
	    NEED(2);
	    get_uleb128(u64,data); /* XXX check overrun */
	    get_sleb128(s64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LA_DEBUG,LF_DWARFOPS,"%s -> reg%" PRId8 ", offset %ld\n",known[op],
		   (uint8_t)u64,s64);
	    retval->l.regoffset.offset = s64;
	    ONLYOP(retval,LOCTYPE_REG_OFFSET,regoffset.reg,(uint8_t)u64);
	    break;
	default:
	  /* No Operand.  */
	    if (op < sizeof known / sizeof known[0] && known[op] != NULL) {
		; /*printf ("%*s[%4" PRIuMAX "] %s\n",
		    indent, "", (uintmax_t) offset, known[op]);*/
	    }
	    else {
		; /*printf ("%*s[%4" PRIuMAX "] %#x\n",
		    indent, "", (uintmax_t) offset, op);*/
	    }
	    break;
	}

	continue;
    }

    vwarnopt(3,LA_DEBUG,LF_DWARFOPS,"had to save dwarf ops for runtime!\n");
    retval->loctype = LOCTYPE_RUNTIME;
    retval->l.runtime.data = malloc(origlen);
    memcpy(retval->l.runtime.data,origdata,origlen);

 out:
    return 0;

 errout:
    return -1;
}

/* Used in fill_debuginfo; defined right afer it for ease of
 * understanding the code.
 */

void finalize_die_symbol_name(struct symbol *symbol);
int finalize_die_symbol(struct debugfile *debugfile,int level,
			struct symbol *symbol,
			struct symbol *parentsymbol,
			struct symbol *voidsymbol,
			GHashTable *reftab,struct array_list *die_offsets,
			SMOFFSET cu_offset);
void resolve_refs(gpointer key,gpointer value,gpointer data);

struct symbol *do_void_symbol(struct debugfile *debugfile,
			       struct symtab *symtab) {
    /* symbol_create dups the name, so we just pass a static buf */
    struct symbol *symbol;

    if ((symbol = (struct symbol *)g_hash_table_lookup(symtab->tab,
						       (gpointer)"void")))
	return symbol;

    symbol = symbol_create(symtab,0,"void",0,SYMBOL_TYPE_TYPE,SYMBOL_SOURCE_DWARF,1);
    symbol->datatype_code = DATATYPE_VOID;

    /* RHOLD; this debugfile owns symbol. */
    RHOLD(symbol,debugfile);

    /* Always put it in its primary symtab, of course -- probably the CU's. */
    symtab_insert(symbol->symtab,symbol,0);

    /* And also always put it in the debugfile's global types table. */
    if (!(debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES))
	debugfile_add_type_name(debugfile,symbol_get_name(symbol),symbol);

    return symbol;
}

/*
 * You can call this in two main ways.  First, if you are loading a CU
 * for the first time, you *must* supply @meta, and it must be filled
 * in.  Second, if you have already loaded some or part of the CU, you
 * need not specify @meta, since it will be reachable from 
 * debugfile->cu_offsets{@cu_offset}->meta (the cu_symtab's struct) --
 * if you supply a valid offset.  If you specify @die_offsets, you can
 * specify that those DIEs should be expanded if they've already been
 * partially loaded, by setting @expand_dies nonzero.
 *
 * XXX: a major bad thing we do is reduce the Dwarf_Off offset to a
 * 32-bit value, instead of a (potential) 64-bit value.  However, doing
 * this saves us lots of struct bytes, and if anybody supplies a
 * debuginfo file > 4GB in size, we're just not going to support it.
 */
static int debuginfo_load_cu(struct debugfile *debugfile,
			     struct dwarf_cu_meta *meta,
			     Dwarf_Off *cu_offset,
			     struct array_list *init_die_offsets,
			     int expand_dies) {
    Dwfl_Module *dwflmod;
    Dwarf *dbg;
    struct debugfile_load_opts *opts = debugfile->opts;
    int retval = 0;
    Dwarf_Off offset = *cu_offset;
    struct attrcb_args args;
    int maxdies = 8;
    int level = 0;
    Dwarf_Die *dies = (Dwarf_Die *)malloc(maxdies*sizeof(Dwarf_Die));
    GHashTable *reftab = g_hash_table_new(g_direct_hash,g_direct_equal);
    GHashTableIter iter;
    GHashTable *cu_abstract_origins = g_hash_table_new(g_direct_hash,
						       g_direct_equal);
    struct array_list *iilist;

    struct symtab *cu_symtab;
    struct symbol **symbols = (struct symbol **) \
	malloc(maxdies*sizeof(struct symbol *));
    struct symtab **symtabs = (struct symtab **) \
	malloc(maxdies*sizeof(struct symtab *));

    struct symbol *voidsymbol;
    struct symbol *rsymbol;
    int quick = opts->flags & DEBUGFILE_LOAD_FLAG_PARTIALSYM;
    /*
     * XXX: what if we are using a CU symtab created in get_aranges or
     * get_pubnames, and we don't end up hashing the symtab in
     * debugfiles->srcfiles because it doesn't have a name?  What about
     * symtabs from aranges or pubnames that aren't in debuginfo?  Those
     * will be leaked.  Ack, don't worry about it for now; that would be
     * a DWARF bug :).
     */
    int cu_symtab_added = 0;
    int cu_symtab_preexisting = 0;

    struct array_list *die_offsets = NULL;
    int i;
    struct symbol *tsymbol;
    char *sname;
    int accept;
    gpointer key;
    gpointer value;
    struct array_list *duplist;
    int trefcnt;

    /*
     * If we only want to load specific die offsets, clone the incoming
     * list so we can append to it as we discover necessary!
     */
    if (init_die_offsets) 
	die_offsets = array_list_clone(init_die_offsets,0);

    /*
     * Set up the cu_symtab variable.  CU symtabs go in two places in
     * the debugfile struct: in ->cuoffsets (with the CU offset as key),
     * and in ->srcfiles (with the CU name as the key).  When they are
     * created in get_aranges, we don't yet know their name, so they are
     * only in ->cuoffsets.  If we see one of these, we know this is the
     * initial load of the CU, and we have to process the CU DIE.
     * Otherwise, we can skip *processing* the CU die -- we still have
     * to load it in dies[].
     */

    if (!(cu_symtab = (struct symtab *) \
	  g_hash_table_lookup(debugfile->cuoffsets,
			      (gpointer)(uintptr_t)offset))) {
	if (!meta) {
	    verror("Could not find a previous CU symtab at offset"
		   " 0x%"PRIx64", and no DWARF metadata supplied;"
		   " aborting!\n",offset);
	    goto errout;
	}

	vdebug(5,LA_DEBUG,LF_DWARF,
	       "creating new CU symtab at offset 0x%"PRIx64"!\n",offset);

	/* attr_callback has to fill cu_symtab, and *MUST* fill at least
	 * the name field; otherwise we can't add the symtab to our hash table.
	 */
	cu_symtab = symtab_create(NULL,debugfile,offset,NULL,0,NULL);
	g_hash_table_insert(debugfile->cuoffsets,(gpointer)(uintptr_t)offset,
			    (gpointer)cu_symtab);
	cu_symtab->meta = meta;
    }
    else {
	vdebug(5,LA_DEBUG,LF_DWARF,
	       "using existing CU symtab %s (offset 0x%"PRIx64")!\n",
	       cu_symtab->name,offset);

	if (!cu_symtab->meta) {
	    if (!meta) {
		verror("No DWARF metadata supplied for CU symtab load at offset"
		       " 0x%"PRIx64"; aborting!\n",offset);
		goto errout;
	    }
	    cu_symtab->meta = meta;
	}

	cu_symtab_preexisting = 1;

	/* 
	 * Create a reftab of the existing symbols, so we can skip
	 * loading them if they're already done.
	 */
	if (1 || cu_symtab->meta->loadtag == LOADTYPE_PARTIAL) {
	    g_hash_table_iter_init(&iter,cu_symtab->anontab);
	    while (g_hash_table_iter_next(&iter,
					  (gpointer *)&key,(gpointer *)&value)) {
		tsymbol = (struct symbol *)value;
		g_hash_table_insert(reftab,key,(gpointer *)tsymbol);
		vdebug(6,LA_DEBUG,LF_DWARF,
		       "inserted %s into reuse reftab\n",tsymbol->name);
	    }
	    g_hash_table_iter_init(&iter,cu_symtab->tab);
	    while (g_hash_table_iter_next(&iter,
					  (gpointer *)&key,(gpointer *)&value))  {
		tsymbol = (struct symbol *)value;
		g_hash_table_insert(reftab,(gpointer)(uintptr_t)tsymbol->ref,
				    (gpointer)tsymbol);
		vdebug(6,LA_DEBUG,LF_DWARF,
		       "inserted %s (0x%"PRIxSMOFFSET") into reuse reftab\n",
		       tsymbol->name,tsymbol->ref);
	    }
	    g_hash_table_iter_init(&iter,cu_symtab->duptab);
	    while (g_hash_table_iter_next(&iter,
					  (gpointer *)&key,(gpointer *)&value))  {
		duplist = (struct array_list *)value;
		for (i = 0; i < array_list_len(duplist); ++i) {
		    tsymbol = (struct symbol *)array_list_item(duplist,i);
		    g_hash_table_insert(reftab,(gpointer)(uintptr_t)tsymbol->ref,
					(gpointer)tsymbol);
		    vdebug(6,LA_DEBUG,LF_DWARF,
			   "inserted dup %s (0x%"PRIxSMOFFSET") into reuse reftab\n",
			   tsymbol->name,tsymbol->ref);
		}
	    }
	}
    }

    /* Make sure, if we're loading this CU again, to take its metadata! */
    if (!meta)
	meta = cu_symtab->meta;

    dwflmod = meta->dwflmod;
    dbg = meta->dbg;

    /* Set the load type -- the expected, no-errors state :)! */
    if (meta->loadtag == LOADTYPE_UNLOADED 
	&& (die_offsets || debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_PARTIALSYM))
	meta->loadtag = LOADTYPE_PARTIAL;
    else if (meta->loadtag == LOADTYPE_PARTIAL 
	     && (die_offsets || debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_PARTIALSYM))
	meta->loadtag = LOADTYPE_PARTIAL;
    else if (meta->loadtag == LOADTYPE_FULL && die_offsets) {
	verror("CU %s (offset 0x%"PRIxSMOFFSET") already fully loaded!\n",
	       cu_symtab->name,cu_symtab->ref);
	goto errout;
    }
    else
	meta->loadtag = LOADTYPE_FULL;

    /* If we've loaded this one before, we don't want to add it again
     * (which we can only do after processing its DIE attrs, the first
     * time); so say here, don't add it again!
     */
    if (cu_symtab->name 
	&& (g_hash_table_lookup(debugfile->srcfiles,cu_symtab->name)
	    || g_hash_table_lookup(debugfile->srcfiles_multiuse,cu_symtab->name))) {
	cu_symtab_added = 1;
    }

    /* Set the top-level symtab. */
    symtabs[0] = cu_symtab;

    /* Either create the void symbol for this CU, or grab it from
     * elsewhere.
     */
    voidsymbol = do_void_symbol(debugfile,cu_symtab);

    /* Setup our args for attr_callback! */
    args.dwflmod = dwflmod;
    args.dbg = dbg;
    args.meta = meta;

    args.level = level;
    args.cu_offset = offset;
    args.cu_base = 0;
    args.have_stmt_list_offset = 0;
    args.stmt_list_offset = 0;

    args.debugfile = debugfile;
    args.opts = opts;
    args.cu_symtab = cu_symtab;
    args.symtab = cu_symtab;
    args.symbol = NULL;
    args.parentsymbol = NULL;
    args.voidsymbol = voidsymbol;
    args.reftab = reftab;
    args.cu_abstract_origins = cu_abstract_origins;

    /* Skip the CU header. */
    offset += meta->cuhl;

    /* If we are doing a partial CU load, we still have to parse the CU
     * DIE's attributes!  So, we have to hold the skip to the first
     * offset in die_offsets until we've done that.
     */

    if (dwarf_offdie(dbg,offset,&dies[level]) == NULL) {
	verror("cannot get DIE at offset %" PRIx64 ": %s\n",
	       offset,dwarf_errmsg(-1));
	goto errout;
    }

    /*
     * This is the main DIE-processing loop.  Each iteration requires
     * that dies[level] be set to the next DIE to process.
     */

    do {
	struct symtab *newscope = NULL;
	struct symbol *ts;
	int nofinalize = 0;
	int rc;

	offset = dwarf_dieoffset(&dies[level]);
	if (offset == ~0ul) {
	    verror("cannot get DIE offset: %s",dwarf_errmsg(-1));
	    goto errout;
	}

	/* We need the tag even if we don't process it at first. */
	int tag = dwarf_tag(&dies[level]);

	args.reloading = 0;
	symbols[level] = NULL;

	/*
	 * If the offset is already in reftab, AND if it's a FULL
	 * symbol, skip to its sibling; don't process either its
	 * attributes nor its children.
	 */
	ts = (struct symbol *) \
	    g_hash_table_lookup(reftab,(gpointer)(uintptr_t)offset);
	if (ts && ts->loadtag == LOADTYPE_FULL) {
	    /*
	     * This is tricky.  Set up its "parent" if it had one, just
	     * in case the sibling (if we process one) needs it.  WAIT
	     * -- you might think you need to do that, but you don't
	     * because the only way you process a sibling of something
	     * that was already processed is to get to it is to have
	     * already processed its parent in this loop (or loaded
	     * symbols/symtabs[level] at level - 1 from reftab in an
	     * earlier iteration of this loop).
	     */
	    symbols[level] = ts;
	    symtabs[level] = ts->symtab;
	    vdebug(6,LA_DEBUG,LF_DWARF,
		   "existing reftab symbol (full) %s 0x%"PRIxSMOFFSET" on"
		   " symtab %s 0x%"PRIxSMOFFSET"; skip to sibling\n",
		   symbol_get_name(ts),ts->ref,ts->symtab->name,ts->symtab->ref);
	    goto do_sibling;
	}
	/* 
	 * If it's a partial symbol:
	 *   If @expand_dies, we need to fully load it, which means we
	 *   need to malloc its type/instance struct, AND then
	 *   re-process its attributes, BUT not finalize it.
	 *
	 *   If not @expand_dies, we don't want to do anything to this,
	 *   nor load its children; skip to its sibling.
	 */
	else if (ts && ts->loadtag == LOADTYPE_PARTIAL) {
	    if (expand_dies) {
		//if (!(debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_CUHEADERS
		//	  || debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_PUBNAMES)
		//	|| expand_dies) {
		nofinalize = 1;
		symbols[level] = ts;
		symtabs[level] = ts->symtab;

		vdebug(6,LA_DEBUG,LF_DWARF,
		       "existing reftab symbol (partial) %s 0x%"PRIxSMOFFSET
		       " on symtab %s 0x%"PRIxSMOFFSET"; expanding"
		       " attrs and children\n",
		       symbol_get_name(ts),ts->ref,
		       ts->symtab->name,ts->symtab->ref);

		/*
		 * malloc more mem so that tag/attr processing has the
		 * memory to initialize, but don't change the symbol's
		 * loadtag to LOADTYPE_FULL until *after* we re-process
		 * the tag and attrs.
		 */
		if (SYMBOL_IS_TYPE(ts)) {
		    ts->s.ti = (struct symbol_type *) \
			malloc(sizeof(struct symbol_type));
		    memset(ts->s.ti,0,sizeof(struct symbol_type));
		}
		else {
		    ts->s.ii = (struct symbol_instance *) \
			malloc(sizeof(struct symbol_instance));
		    memset(ts->s.ii,0,sizeof(struct symbol_instance));
		}

		args.reloading = 1;
	    }
	    else {
		symbols[level] = NULL;
		symtabs[level] = ts->symtab;

		vdebug(6,LA_DEBUG,LF_DWARF,
		       "existing reftab symbol (partial) %s 0x%"PRIxSMOFFSET
		       " on symtab %s 0x%"PRIxSMOFFSET"; skip to sibling\n",
		       symbol_get_name(ts),ts->ref,
		       ts->symtab->name,ts->symtab->ref);

		goto do_sibling;
	    }
	}

	/* We may create a new scope (i.e., for a function or lexical
	 * scope if we're fully loading symbols); or we may NULL this
	 * out for those cases if we're loading partial symbols; BUT in
	 * the default case we want it to be our current level.
	 */
	args.symtab = symtabs[level];

	/*
	 * Otherwise, start processing the DIE.
	 */

	if (tag == DW_TAG_invalid) {
	    verror("cannot get tag of DIE at offset %" PRIx64 ": %s\n",
		   offset,dwarf_errmsg(-1));
	    goto errout;
	}

	vdebug(4,LA_DEBUG,LF_DWARF," [%6Lx] %d %s\n",(uint64_t)offset,(int)level,
	       dwarf_tag_string(tag));

	/* Figure out what type of symbol (or symtab?) to create! */
	if (tag == DW_TAG_variable
	    || tag == DW_TAG_formal_parameter
	    || tag == DW_TAG_enumerator) {
	    if (!symbols[level]) {
		symbols[level] = symbol_create(symtabs[level],offset,NULL,0,
					       SYMBOL_TYPE_VAR,SYMBOL_SOURCE_DWARF,
					       (!quick || expand_dies));
		/* RHOLD; this debugfile owns symbol. */
		RHOLD(symbols[level],debugfile);
		if (tag == DW_TAG_formal_parameter) {
		    symbols[level]->isparam = 1;
		}
		if (tag == DW_TAG_enumerator) {
		    symbols[level]->isenumval = 1;
		}
	    }
	}
	else if (tag == DW_TAG_member) {
	    /* Members are special IF the parent is a type, because if
	     * that type got shared in a previous pass, we have to share
	     * these symbols too.
	     */
	    if (!symbols[level]) {
		if (symbols[level-1] && SYMBOL_IS_TYPE(symbols[level-1])
		    && symbols[level-1]->isshared)
		    symbols[level] = symbol_create(symbols[level-1]->symtab,offset,
						   NULL,0,SYMBOL_TYPE_VAR,
						   SYMBOL_SOURCE_DWARF,
						   (!quick || expand_dies));
		else 
		    symbols[level] = symbol_create(symtabs[level],offset,NULL,0,
						   SYMBOL_TYPE_VAR,
						   SYMBOL_SOURCE_DWARF,
						   (!quick || expand_dies));
		/* RHOLD; this debugfile owns symbol. */
		RHOLD(symbols[level],debugfile);
		symbols[level]->ismember = 1;
	    }
	}
	else if (tag == DW_TAG_label) {
	    if (!symbols[level]) {
		symbols[level] = symbol_create(symtabs[level],offset,NULL,0,
					       SYMBOL_TYPE_LABEL,
					       SYMBOL_SOURCE_DWARF,
					       (!quick || expand_dies));
		/* RHOLD; this debugfile owns symbol. */
		RHOLD(symbols[level],debugfile);
	    }
	}
	else if (tag == DW_TAG_unspecified_parameters) {
	    if (!symbols[level-1])
		vwarn("cannot handle unspecified_parameters without parent DIE!\n");
	    else if (SYMBOL_IS_FULL_TYPE(symbols[level-1])
		     && symbols[level-1]->datatype_code == DATATYPE_FUNCTION) {
		symbols[level-1]->s.ti->d.f.hasunspec = 1;
	    }
	    else if (SYMBOL_IS_FULL_FUNCTION(symbols[level-1])) {
		symbols[level-1]->s.ii->d.f.hasunspec = 1;
	    }
	}
	else if (tag == DW_TAG_base_type
		 || tag == DW_TAG_typedef
		 || tag == DW_TAG_pointer_type
		 || tag == DW_TAG_array_type
		 || tag == DW_TAG_structure_type
		 || tag == DW_TAG_enumeration_type
		 || tag == DW_TAG_union_type
		 || tag == DW_TAG_const_type
		 || tag == DW_TAG_volatile_type
		 || tag == DW_TAG_subroutine_type) {
	    if (!symbols[level])
		symbols[level] = symbol_create(symtabs[level],offset,
					       NULL,0,SYMBOL_TYPE_TYPE,
					       SYMBOL_SOURCE_DWARF,
					       (!quick || expand_dies));
		/* RHOLD; this debugfile owns symbol. */
		RHOLD(symbols[level],debugfile);
	    switch (tag) {
	    case DW_TAG_base_type:
		symbols[level]->datatype_code = DATATYPE_BASE; break;
	    case DW_TAG_typedef:
		symbols[level]->datatype_code = DATATYPE_TYPEDEF; break;
	    case DW_TAG_pointer_type:
		symbols[level]->datatype_code = DATATYPE_PTR; break;
	    case DW_TAG_array_type:
		symbols[level]->datatype_code = DATATYPE_ARRAY;
		if (((!quick || expand_dies) && !ts) 
		    || (expand_dies && ts && ts->loadtag == LOADTYPE_PARTIAL)) {
		    symbols[level]->s.ti->d.a.subranges = malloc(sizeof(int)*4);
		    symbols[level]->s.ti->d.a.count = 0;
		    symbols[level]->s.ti->d.a.alloc = 4;
		}
		break;
	    case DW_TAG_structure_type:
		symbols[level]->datatype_code = DATATYPE_STRUCT;
		if (((!quick || expand_dies) && !ts) 
		    || (expand_dies && ts && ts->loadtag == LOADTYPE_PARTIAL)) 
		    INIT_LIST_HEAD(&(symbols[level]->s.ti->d.su.members));
		break;
	    case DW_TAG_enumeration_type:
		symbols[level]->datatype_code = DATATYPE_ENUM; 
		if (((!quick || expand_dies) && !ts) 
		    || (expand_dies && ts && ts->loadtag == LOADTYPE_PARTIAL)) 
		    INIT_LIST_HEAD(&(symbols[level]->s.ti->d.e.members));
		break;
	    case DW_TAG_union_type:
		symbols[level]->datatype_code = DATATYPE_UNION;
		if (((!quick || expand_dies) && !ts) 
		    || (expand_dies && ts && ts->loadtag == LOADTYPE_PARTIAL)) 
		    INIT_LIST_HEAD(&(symbols[level]->s.ti->d.su.members));
		break;
	    case DW_TAG_const_type:
		symbols[level]->datatype_code = DATATYPE_CONST; break;
	    case DW_TAG_volatile_type:
		symbols[level]->datatype_code = DATATYPE_VOL; break;
	    case DW_TAG_subroutine_type:
		symbols[level]->datatype_code = DATATYPE_FUNCTION;
		if (((!quick || expand_dies) && !ts) 
		    || (expand_dies && ts && ts->loadtag == LOADTYPE_PARTIAL)) 
		    INIT_LIST_HEAD(&(symbols[level]->s.ti->d.f.args));
		break;
	    default:
		break;
	    }
	}
	else if (tag == DW_TAG_subrange_type) {
	    /* We cheat and don't actually type subranges... we're C
	     * hackers, after all :).
	    */
	    ;
	}
	else if (tag == DW_TAG_subprogram) {
		 //|| tag == DW_TAG_inlined_subroutine) {
	    if (!symbols[level]) {
		symbols[level] = symbol_create(symtabs[level],offset,NULL,0,
					       SYMBOL_TYPE_FUNCTION,
					       SYMBOL_SOURCE_DWARF,
					       (!quick || expand_dies));
		/* RHOLD; this debugfile owns symbol. */
		RHOLD(symbols[level],debugfile);
		/* Build a new symtab and use it until we finish this
		 * subprogram, or until we need another child scope.
		 */
		if (!quick || expand_dies) {
		    newscope = symtab_create(NULL,debugfile,offset,NULL,0,symbols[level]);
		    newscope->parent = symtabs[level];
		    // XXX: should we wait to do this until we level up after
		    // successfully completing this new child scope?
		    list_add_tail(&newscope->member,&symtabs[level]->subtabs);
		}
		else 
		    args.symtab = NULL;
	    }
	    else if (SYMBOL_IS_FULL_FUNCTION(symbols[level])
		     && !symbols[level]->s.ii->d.f.symtab) {
		/* This happens when we are expanding a func symbol. */
		newscope = symtab_create(NULL,debugfile,offset,NULL,0,symbols[level]);
		newscope->parent = symtabs[level];
		// XXX: should we wait to do this until we level up after
		// successfully completing this new child scope?
		list_add_tail(&newscope->member,&symtabs[level]->subtabs);
	    }
	    else {
		newscope = symbols[level]->s.ii->d.f.symtab;
	    }

	    if (((!quick || expand_dies) && !ts) 
		|| (expand_dies && ts && ts->loadtag == LOADTYPE_PARTIAL)) {
		symbols[level]->s.ii->d.f.symtab = newscope;
		INIT_LIST_HEAD(&(symbols[level]->s.ii->d.f.args));
	    }
	}
	else if (tag == DW_TAG_inlined_subroutine) {
	    if (!symbols[level]) {
		symbols[level] = symbol_create(symtabs[level],offset,NULL,0,
					       SYMBOL_TYPE_FUNCTION,
					       SYMBOL_SOURCE_DWARF,
					       (!quick || expand_dies));
		/* RHOLD; this debugfile owns symbol. */
		RHOLD(symbols[level],debugfile);
		/* Build a new symtab and use it until we finish this
		 * subprogram, or until we need another child scope.
		 */
		if (!quick || expand_dies) {
		    newscope = symtab_create(NULL,debugfile,offset,NULL,0,symbols[level]);
		    newscope->parent = symtabs[level];
		    // XXX: should we wait to do this until we level up after
		    // successfully completing this new child scope?
		    list_add_tail(&newscope->member,&symtabs[level]->subtabs);
		}
		else 
		    args.symtab = NULL;
	    }
	    else if (SYMBOL_IS_FULL_FUNCTION(symbols[level])
		     && !symbols[level]->s.ii->d.f.symtab) {
		/* This happens when we are expanding a func symbol. */
		newscope = symtab_create(NULL,debugfile,offset,NULL,0,symbols[level]);
		newscope->parent = symtabs[level];
		// XXX: should we wait to do this until we level up after
		// successfully completing this new child scope?
		list_add_tail(&newscope->member,&symtabs[level]->subtabs);
	    }
	    else {
		newscope = symbols[level]->s.ii->d.f.symtab;
	    }

	    if (((!quick || expand_dies) && !ts) 
		|| (expand_dies && ts && ts->loadtag == LOADTYPE_PARTIAL)) {
		symbols[level]->s.ii->d.f.symtab = newscope;
		INIT_LIST_HEAD(&(symbols[level]->s.ii->d.f.args));
	    }
	}
	else if (tag == DW_TAG_lexical_block) {
	    /* Build a new symtab and use it until we finish this
	     * block, or until we need another child scope.
	     */
	    if (!quick || expand_dies) {
		newscope = symtab_create(NULL,debugfile,offset,NULL,0,NULL);
		newscope->parent = symtabs[level];
		// XXX: should we wait to do this until we level up after
		// successfully completing this new child scope?
		list_add_tail(&newscope->member,&symtabs[level]->subtabs);
	    }
	    else 
		args.symtab = NULL;
	}
	else {
	    if (tag != DW_TAG_compile_unit)
		vwarnopt(3,LA_DEBUG,LF_DWARF,
			 "unknown dwarf tag %s!\n",dwarf_tag_string(tag));
	    symbols[level] = NULL;
	    if (tag != DW_TAG_compile_unit) 
		goto do_sibling;
	}

	/* Get the attribute values.  */
	args.level = level;
	if (level > 1)
	    args.parentsymbol = symbols[level-1];
	else
	    args.parentsymbol = NULL;
	args.symbol = symbols[level];
	if (newscope) {
	    /* Make sure attrs are processed for the new scope! i.e.,
	     * high_pc and low_pc.
	     */
	    args.symtab = newscope;
	}

	args.lowpc = args.highpc = 0;
	args.lowpc_set = 0;
	args.highpc_is_offset = 0;

	args.die_offset = offset;
	(void)dwarf_getattrs(&dies[level],attr_callback,&args,0);

	/* Handle updating the symtab with low_pc and high_pc attrs, if
	 * we have a symtab, now that we have processed both attrs (if
	 * they existed).
	 */
	if (args.symtab && args.symtab->ref == offset && args.lowpc_set) {
	    if (args.highpc_is_offset
		|| args.highpc >= args.lowpc) {
		if (!args.highpc_is_offset) 
		    symtab_update_range(args.symtab,args.lowpc,
					args.highpc,RANGE_TYPE_NONE);
		else
		    symtab_update_range(args.symtab,args.lowpc,
					args.lowpc + args.highpc,
					RANGE_TYPE_NONE);
	    }
	    else {
		verror("bad lowpc/highpc (0x%"PRIxADDR",0x%"PRIxADDR
		       ") for symtab at 0x%"PRIxSMOFFSET"\n",
		       args.lowpc,args.highpc,args.symtab->ref);
	    }
	}

	/* The first time we are not level 0 (i.e., at the CU's DIE),
	 * check that we found a src filename attr; we must have it to
	 * hash the symtab.
	 */
	if (tag == DW_TAG_compile_unit && unlikely(!cu_symtab_added)) {
	    if (!symtab_get_name(cu_symtab)) {
		verror("CU did not have a src filename; aborting processing!\n");
		/* Don't free preexisting ones! */
		if (!cu_symtab_preexisting) 
		    symtab_free(cu_symtab);
		cu_symtab = NULL;
		goto out;
	    }
	    else {
		if (cu_symtab_preexisting) {
		    if (debugfile_update_cu_symtab(debugfile,cu_symtab)) {
			vwarnopt(2,LA_DEBUG,LF_DWARF,
				 "could not update CU symtab %s to debugfile;"
				 " aborting processing!\n",
				 symtab_get_name(cu_symtab));
			/* Don't free preexisting ones! */
			//symtab_free(cu_symtab);
			cu_symtab = NULL;
			goto out;
		    }
		}
		else if (debugfile_add_cu_symtab(debugfile,cu_symtab)) {
		    vwarnopt(2,LA_DEBUG,LF_DWARF,
			     "could not add CU symtab %s to debugfile;"
			     " aborting processing!\n",
			     symtab_get_name(cu_symtab));
		    symtab_free(cu_symtab);
		    cu_symtab = NULL;
		    goto out;
		}
		cu_symtab_added = 1;
	    }

	    /*
	     * Only check CU load options on the initial load, because
	     * if we have to expand it later, it is because a symbol or
	     * address search required it... and the initial load opts
	     * are meaningless.
	     */
	    if (debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_CUHEADERS)
		goto out;
	    if (debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_PUBNAMES
		&& (!die_offsets || array_list_len(die_offsets) == 0))
		goto out;
	    /*
	     * If we have regexes for symtabs and this one doesn't
	     * match, skip it!
	     */
	    else if (opts->srcfile_filter) {
		rfilter_check(opts->srcfile_filter,
			      symtab_get_name(cu_symtab),
			      &accept,NULL);
		if (accept == RF_REJECT) {
		    vdebug(3,LA_DEBUG,LF_DWARF,"skipping CU '%s'\n",
			   symtab_get_name(cu_symtab));
		    goto out;
		}
	    }
	}

	/* If we have die_offsets to load, and we're not just going to
	 * load the full CU, AND if we have now processed the CU
	 * symtab's attributes, we need to skip to the first DIE in our
	 * list.
	 */
	if (tag == DW_TAG_compile_unit && die_offsets) {
	    if (array_list_len(die_offsets)) {
		i = 0;
		offset = (SMOFFSET)(uintptr_t)array_list_item(die_offsets,i);
		++i;

		/* So many things key off level == 0 that we set it to 1
		 * deliberately.
		 */
		level = 1;
		if (dwarf_offdie(dbg,offset,&dies[level]) == NULL) {
		    verror("cannot get first DIE at offset 0x%"PRIx64
			   " during partial CU load: %s\n",offset,dwarf_errmsg(-1));
		    goto errout;
		}
		vdebug(5,LA_DEBUG,LF_DWARF,"skipping to first DIE 0x%x\n",offset);
		symtabs[level] = symtabs[level-1];
		continue;
	    }
	    else {
		/* We're done -- we just wanted to load the CU header. */
		goto out;
	    }
	}

	if (expand_dies && ts && ts->loadtag == LOADTYPE_PARTIAL)
	    ts->loadtag = LOADTYPE_FULL;

	/* If we're actually handling this CU, then... */

	/* THIS MUST HAPPEN FIRST:
	 *
	 * If we are going to give the symbol an extname, we must do it
	 * now, before it goes onto any hashtables.  We cannot rename in
	 * finalize_die_symbol; that is too late and will cause memory
	 * corruption because the symbol will have already been inserted
	 * into hashtables.
	 */
	if (symbols[level] && !nofinalize)
	    finalize_die_symbol_name(symbols[level]);

	/*
	 * Type compression, part 1:
	 *
	 * If we've loaded the attrs for a non-enumerated type, and it
	 * is already present in our global type table, AND if the user
	 * hasn't specified that we must *fully* check the type
	 * equivalence (DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV), and
	 * if the looked up symbol is not in our CU, AND if we're at
	 * level 1 (we only consider types that are at the top level),
	 * we can 
	 *   free this symbol, use the looked-up value right away, and
	 *   skip any of our children!
	 *
	 * Type compression, part 2 continues below (needed if
	 * DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV is set because we
	 * can't fully check type equivalence until we've loaded this
	 * type and all its children, if any).
	 */
	if (level == 1 && symbols[level] 
	    && SYMBOL_IS_TYPE(symbols[level]) && !SYMBOL_IST_ENUM(symbols[level])
	    && opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES
	    && !(opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV)
	    && symbol_get_name(symbols[level])) {
	    if ((tsymbol = symtab_get_sym(debugfile->shared_types,
					  symbol_get_name(symbols[level])))) {
		if (SYMBOL_IS_TYPE(tsymbol) && !SYMBOL_IST_ENUM(tsymbol)
		    ) {//&& symbols[level]->symtab != tsymbol->symtab) {
		    /* Insert the looked up symbol into our CU's temp
		     * reftab so that any of our DIEs that tries to use
		     * it gets the "global" one instead.
		     */
		    g_hash_table_insert(reftab,
					(gpointer)(uintptr_t)symbols[level]->ref,
					tsymbol);

		    vdebug(4,LA_DEBUG,LF_SYMBOL,
			   "inserting shared symbol (quick check) %s (%s"
			   " 0x%"PRIxSMOFFSET") of type %s at offset 0x%"
			   PRIxSMOFFSET" into reftab\n",
			   symbol_get_name(tsymbol),
			   symbol_get_name_orig(tsymbol),
			   tsymbol->ref,
			   SYMBOL_TYPE(tsymbol->type),symbols[level]->ref);

		    /* Since we're moving across the CU boundary, we
		     * have to hold a ref to this symbol *now*!
		     *
		     * There is a slight possibility that we might end
		     * up "wasting" this reference -- i.e., if our CU
		     * had listed it, but then did not reference it in
		     * any of its DIEs.
		     *
		     * NOTE: no longer hold a ref here; we have to hold
		     * a ref each time we actually use it; see below in
		     * the datatype_ref resolution code!
		     */
		    /* RHOLD(tsymbol); */
		    /* Free ourself! */
		    /* (and release the ref we took after symbol_create) */
		    RPUT(symbols[level],symbol,debugfile,trefcnt);
		    symbols[level] = NULL;
		    /* Skip to the next sibling, or to the next DIE if
		     * we're doing a partial CU load.
		     */
		    goto do_sibling;
		}
	    }
	    else {
		vdebug(4,LA_DEBUG,LF_SYMBOL,
		       "sharing symbol (quick check) %s (%s) of type %s\n",
		       symbol_get_name(symbols[level]),
		       symbol_get_name_orig(symbols[level]),
		       SYMBOL_TYPE(symbols[level]->type));
		symbols[level]->isshared = 1;
		/*
		 * NOTE: no longer hold a ref here; we have to hold a
		 * ref each time we actually use it; see below in the
		 * datatype_ref resolution code!
		 */
		//RHOLD(symbols[level],debugfile);
		//symtab_insert(debugfile->shared_types,symbols[level],0);
		/* We have to change its symtab, AND later on (after
		 * we've processed any symbols it or its members (i.e.,
		 * STUN types) reference, we have to mark those symbols
		 * as shared, too, even if they are anon (putting them
		 * into the anontab in shared types if they are -- and
		 * must use the CU+DIE offset, not just CU-relative
		 * offset!), and change *their* symtabs.
		 */
		/* For now, don't set the recurse-on-type bit.  Also,
		 * don't insert it, since finalize_die_symbol will!
		 */
		symbol_change_symtab(symbols[level],debugfile->shared_types,1,0);
		//symbols[level]->symtab = debugfile->shared_types;
	    }
	}

	if (SYMBOL_IS_INSTANCE(symbols[level]) 
	    && !symbol_get_name_orig(symbols[level])) {
		/* This is actually ok because function type params can
		 * be unnamed, and so can inlined functions.
		 */
		if (!((SYMBOL_IS_FUNCTION(symbols[level]) 
		       && symbols[level]->isinlineinstance)
		      || (SYMBOL_IS_LABEL(symbols[level]) 
			  && (symbols[level]->isinlineinstance))
		      || (SYMBOL_IS_VAR(symbols[level]) 
			  && (symbols[level]->isinlineinstance
			      || (level > 0 
				  && SYMBOL_IST_FUNCTION(symbols[level-1])
				  && symbols[level]->isparam)
			      || (level > 0 && SYMBOL_IST_STUN(symbols[level-1])
				  && symbols[level]->ismember)))))
		    vwarnopt(4,LA_DEBUG,LF_DWARF,
			     "anonymous symbol of type %s at DIE 0x%"PRIx64"!\n",
			     SYMBOL_TYPE(symbols[level]->type),offset);
	}

	/*
	 * Add to this CU's reference offset table.  We originally only
	 * did this for types, but since inlined func/param instances
	 * can refer to funcs/vars, we have to do it for every symbol.
	 */
	if (!ts)
	    g_hash_table_insert(reftab,(gpointer)(uintptr_t)offset,symbols[level]);

	/* Handle adding child symbols to parents!
	 *
	 * Only do this if we're doing a full symbol load.  The reason
	 * we don't need to check if the parents are full symbols is
	 * because we can never load a child symbol unless we fully load
	 * a parent, in which case we also fully load the child.
	 *
	 * XXX: Don't have the parent hold a ref to the child.  This
	 * could cause problems, but the idea is that a user looking up
	 * a symbol should never take a ref only to a member.  Hm, this
	 * probably isn't exactly true; we do support member-only
	 * lookup.  Hm, probably have to take a ref.  The problem is
	 * that if the parent gets released and the child doesn't,
	 * things will break.  But we have this problem going all the
	 * way up to the symtab hierarchy of parents.
	 */
	if ((!quick || expand_dies) && level > 1 && symbols[level-1]) {
	    if (tag == DW_TAG_member) {
		symbols[level]->s.ii->d.v.member_symbol = symbols[level];
		symbols[level]->s.ii->d.v.parent_symbol = symbols[level-1];
		list_add_tail(&(symbols[level]->s.ii->d.v.member),
			      &(symbols[level-1]->s.ti->d.su.members));
		++(symbols[level-1]->s.ti->d.su.count);
	    }
	    else if (tag == DW_TAG_formal_parameter) {
		if (symbols[level-1]->type == SYMBOL_TYPE_FUNCTION) {
		    symbols[level]->s.ii->d.v.member_symbol = symbols[level];
		    symbols[level]->s.ii->d.v.parent_symbol = symbols[level-1];
		    list_add_tail(&(symbols[level]->s.ii->d.v.member),
				  &(symbols[level-1]->s.ii->d.f.args));
		    ++(symbols[level-1]->s.ii->d.f.count);
		}
		else if (symbols[level-1]->type == SYMBOL_TYPE_TYPE
			 && symbols[level-1]->datatype_code == DATATYPE_FUNCTION) {
		    symbols[level]->s.ii->d.v.member_symbol = symbols[level];
		    symbols[level]->s.ii->d.v.parent_symbol = symbols[level-1];
		    list_add_tail(&(symbols[level]->s.ii->d.v.member),
				  &(symbols[level-1]->s.ti->d.f.args));
		    ++(symbols[level-1]->s.ti->d.f.count);
		}
	    }
	    else if (tag == DW_TAG_enumerator) {
		if (symbols[level-1]->type == SYMBOL_TYPE_TYPE 
		    && symbols[level-1]->datatype_code == DATATYPE_ENUM) {
		    symbols[level]->s.ii->d.v.member_symbol = symbols[level];
		    symbols[level]->s.ii->d.v.parent_symbol = symbols[level-1];
		    /* Yes, this means we don't do type compression for
		     * enumerated types!  See comments near datatype_ref
		     * resolution near the bottom of this function.
		     */
		    symbols[level]->datatype = symbols[level-1];
		    symbols[level]->datatype_ref = symbols[level-1]->ref;
		    list_add_tail(&(symbols[level]->s.ii->d.v.member),
				  &(symbols[level-1]->s.ti->d.e.members));
		    ++(symbols[level-1]->s.ti->d.e.count);
		}
		else
		    verror("invalid parent for enumerator %s!\n",
			   symbol_get_name_orig(symbols[level]));
	    }
	    else {
		// XXX maybe array types too?  what else can have
		// children?
	    }
	}

	/* The last thing to do is finalize the symbol (which we can do
	 * before processing its children.
	 */
	if (symbols[level] && !nofinalize) {
	    rc = finalize_die_symbol(debugfile,level,symbols[level],
				     symbols[level-1],voidsymbol,
				     reftab,die_offsets,(SMOFFSET)*cu_offset);
	    /*
	     * XXX: don't try to do this in the future, because 1) the
	     * symbol is already on our reftab (see above), and 2) the
	     * symbol may have been put on a parent list (see above
	     * block).
	     */
	    if (rc == 2) {
		/*
		 * This symbol was actually freed; don't try to
		 * reference it anymore!  See finalize_die_symbol.
		 */
		symbols[level] = NULL;
	    }
	}

	inline int setup_skip_to_next_die(void) {
	    int alen = array_list_len(die_offsets);

	    /* Maybe skip to the next offset if we haven't already
	     * processed this DIE.
	     */
	    if (i >= alen) {
		vdebug(5,LA_DEBUG,LF_DWARF,"end of partial load DIE list!\n");
		return 0;
	    }
	    offset = (SMOFFSET)(uintptr_t)array_list_item(die_offsets,i);
	    ++i;

	    /* So many things key off level == 0 that we set
	     * it to 1 deliberately.
	     */
	    level = 1;
	    symtabs[level] = cu_symtab;
	    if (dwarf_offdie(dbg,offset,&dies[level]) == NULL) {
		verror("cannot get DIE %d at offset 0x%"PRIx64
		       " during partial CU (0x%"PRIx64") load: %s\n",
		       i - 1,offset,*cu_offset,dwarf_errmsg(-1));
		return -1;
	    }
	    vdebug(5,LA_DEBUG,LF_DWARF,"skipping to DIE %d at 0x%x in CU 0x%"PRIx64"\n",
		   i,offset,*cu_offset);
	    return 1;
	}

	/* Make room for the next level's DIE.  */
	if (level + 1 == maxdies) {
	    dies = (Dwarf_Die *)realloc(dies,(maxdies += 8)*sizeof(Dwarf_Die));
	    symbols = (struct symbol **) \
		realloc(symbols,maxdies*sizeof(struct symbol *));
	    symtabs = (struct symtab **) \
		realloc(symtabs,maxdies*sizeof(struct symtab *));
	}

	int res = dwarf_child(&dies[level],&dies[level + 1]);
	int res2;
	if (res > 0) {
	do_sibling:
	    /* If we were teleported here, set res just in case somebody
	     * expects it to be valid in this block, if the block ever
	     * gets code that needs it!
	     */
	    res = 1;

	    /* No new child, but possibly a new sibling, so nuke this
	     * level's symbol.
	     */
	    symbols[level] = NULL;

	    if (die_offsets && level == 1) {
		res2 = setup_skip_to_next_die();
		/* error; bail */
		if (res2 == -1) goto errout;
		/* no DIEs left to load in CU */
		else if (res2 == 0) { level = -1; }
		/* next die offset is setup; continue */
		else if (res2 == 1) continue;
	    }
	    else {
		while ((res = dwarf_siblingof(&dies[level],&dies[level])) == 1) {
		    int oldlevel = level--;
		    /* If we're loading a partial CU, if there are more DIEs
		     * we need to load, do them!  We don't process any
		     * siblings at level 1, since that's the level we start
		     * each DIE load in a partial CU load at.
		     */
		    if (die_offsets && oldlevel == 1) {
			res2 = setup_skip_to_next_die();
			/* error; bail */
			if (res2 == -1) goto errout;
			/* no DIEs left to load in CU */
			else if (res2 == 0) { level = -1; break; }
			/* next die offset is setup; continue */
			else if (res2 == 1) continue;
		    }
		    /* Otherwise, we stop when the level was zero! */
		    else if (oldlevel == 0)
			break;

		    /* Now that a DIE's children have all been parsed, and
		     * we're leveling up, NULL out this symbol.
		     */
		    symbols[level] = NULL;
		    /*if (symbols[level-1] 
		      && symbols[level-1]->type == SYMBOL_TYPE_FUNCTION 
		      && symtab->parent)
		      symtab = symtab->parent;*/
		}

		if (res == -1) {
		    verror("cannot get next DIE: %s\n",dwarf_errmsg(-1));
		    goto errout;
		}
		else if (res == 0 && die_offsets && level == 1) {
		    /* If there IS a sibling, but we don't want to
		     * process it, because we finished the DIE we wanted
		     * to do, skip to the next DIE.
		     */
		    res2 = setup_skip_to_next_die();
		    /* error; bail */
		    if (res2 == -1) goto errout;
		    /* no DIEs left to load in CU */
		    else if (res2 == 0) { level = -1; }
		    /* next die offset is setup; continue */
		    else if (res2 == 1) continue;
		}
	    }
	}
	else if (res < 0) {
	    verror("cannot get next DIE: %s",dwarf_errmsg(-1));
	    goto errout;
	}
	else {
	    /* 
	     * New child DIE.  If we're loading partial symbols, only
	     * process it given some conditions.
	     */
	    if ((!quick || expand_dies) || level < 1) {
		++level;
		symbols[level] = NULL;
		if (!newscope)
		    symtabs[level] = symtabs[level-1];
		else
		    symtabs[level] = newscope;
	    }
	    else {
		/* Skip to the next sibling. */
		goto do_sibling;
	    }
	}
    }
    while (level >= 0);

    /*
     * Since we may not have been able to resolve all the dwarf type refs for
     * our symbols during our single pass (since a type can follow its
     * use in dwarf debug info), we have to postpass all the symbols :(.
     *
     * The only other alternative is to use libelf/libdw to resolve them
     * during the single pass, which seems less good...
     */
    
    /* g_hash_table_foreach(cu_symtab->tab,resolve_refs,reftab); */

    /*
     * resolve_refs was too badly broken for nested struct/union types,
     * so we have moved to the very straightforward (and possibly
     * wasteful) approach below.  All symbols are in the reftab, and we
     * just postpass them all.  So, we might end up resolving some
     * symbols we don't care about, but it's easy and simple.
     *
     * Also, we now don't set the ->datatype field at all during
     * attr_callback because of type compression; we do all that here
     * for code simplicity.
     */

    g_hash_table_iter_init(&iter,reftab);
    while (g_hash_table_iter_next(&iter,
				  (gpointer *)&key,(gpointer *)&value)) {
	offset = (uintptr_t)key;
	rsymbol = (struct symbol *)value;
	if (!rsymbol)
	    continue;

	/* If we didn't yet resolve the symbol's datatype (or if we're
	 * doing quick type compression, the value for the datatype_ref
	 * key in reftab might have changed as we compressed above, in
	 * which case we need to re-resolve), and if we have a
	 * datatype_ref, resolve it!
	 */
	if ((!rsymbol->datatype 
	     || (opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES
		 && !(opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV)))
	    && rsymbol->datatype_ref
	    && !rsymbol->isshared) {
	    rsymbol->datatype = (struct symbol *) \
		g_hash_table_lookup(reftab,
				    (gpointer)(uintptr_t)rsymbol->datatype_ref);
	    /* Type compression: if this type is in another CU, hold a
	     * ref to it! 
	     */
	    if (/* *opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES
		&& !(opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV) */
		rsymbol->datatype
		&& rsymbol->datatype->isshared) {
		/*
		&& SYMTAB_IS_ROOT(rsymbol->datatype->symtab)
		&& rsymbol->datatype->symtab != cu_symtab)
		*/
		RHOLD(rsymbol->datatype,rsymbol);
		rsymbol->usesshareddatatype = 1;

		vdebug(4,LA_DEBUG,LF_SYMBOL,
		       "using shared symbol (quick check) %s (%s 0x%"PRIxSMOFFSET
		       ") of type %s at offset 0x%"PRIxSMOFFSET"\n",
		       symbol_get_name(rsymbol->datatype),
		       symbol_get_name_orig(rsymbol->datatype),
		       rsymbol->datatype->ref,
		       SYMBOL_TYPE(rsymbol->datatype->type),
		       rsymbol->datatype_ref);
	    }
	}

	/*
	 * Technically, we don't need to RHOLD refs to any of these
	 * things, since they are all within a single CU -- but for
	 * completeness (and thus easier optimization later), RHOLD
	 * anyway.
	 */
	if (SYMBOL_IS_FULL_INSTANCE(rsymbol)) {
	    if (rsymbol->isinlineinstance) {
		if (!rsymbol->s.ii->origin && rsymbol->s.ii->origin_ref) {
		    rsymbol->s.ii->origin = (struct symbol *)	\
			g_hash_table_lookup(reftab,
			    (gpointer)(uintptr_t)rsymbol->s.ii->origin_ref);

		    /*
		     * NB NB NB: we cannot have objects referencing each other;
		     * such objects might not get deleted.
		     *
		     * (See comments in common.h about ref usage.)
		     */
		    /*if (rsymbol->s.ii->origin) {
		     *    RHOLD(rsymbol->s.ii->origin,rsymbol);
		     *}
		     */
		}

		if (rsymbol->s.ii->origin) {
		    /* Autoset the instance's datatype attrs! */
		    rsymbol->datatype = rsymbol->s.ii->origin->datatype;
		    rsymbol->datatype_ref = rsymbol->s.ii->origin->datatype_ref;
		    //memcpy(&rsymbol->s.ii->l,&rsymbol->s.ii->origin->s.ii->l,
		    //	   sizeof(struct location));

		    if (rsymbol->datatype)
			RHOLD(rsymbol->datatype,rsymbol);

		    vdebug(4,LA_DEBUG,LF_SYMBOL,
			   "copied datatype %s//%s (0x%"PRIxSMOFFSET")"
			   " for inline instance %s//%s"
			   " (0x%"PRIxSMOFFSET"\n",
			   rsymbol->datatype ? DATATYPE(rsymbol->datatype->datatype_code) : NULL,
			   rsymbol->datatype ? symbol_get_name(rsymbol->datatype) : NULL,
			   rsymbol->datatype ? rsymbol->datatype->ref : 0,
			   SYMBOL_TYPE(rsymbol->type),symbol_get_name(rsymbol),
			   rsymbol->ref);
		}
		else {
		    vwarn("could not find abstract origin for inline instance"
			  " %s//%s (0x%"PRIxSMOFFSET"\n",
			   SYMBOL_TYPE(rsymbol->type),symbol_get_name(rsymbol),
			   rsymbol->ref);
		}
	    }

	    iilist = (struct array_list *)g_hash_table_lookup(cu_abstract_origins,
							      (gpointer)(uintptr_t)offset);
	    if (iilist) {
		int iii;
		struct symbol *iisymbol;
		g_hash_table_remove(cu_abstract_origins,(gpointer)(uintptr_t)offset);
		rsymbol->s.ii->inline_instances = iilist;

		/*
		 * Need to take a ref to each symbol.
		 */
		array_list_foreach(iilist,iii,iisymbol) {
		    RHOLD(iisymbol,rsymbol);
		}
	    }
	}
    }

    /* Type compression part 2a:
     *
     * We go through our entire reftab, again, now that all refs have
     * been resolved and we can do full type equivalence checks (if
     * we're doing DEBUGFILE_LOAD_FLAG_REDUCETYPES and opts->flags &
     * DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV (if we didn't need to
     * check for full equiv, that check has already been done in
     * debuginfo_load_cu as a shortcut), check full type equivalence).
     *
     * Unfortunately, full equivalence requires us to check *here*, once
     * we've post-passed all our datatype refs.  Why?  For the same
     * reason that the post-pass is there -- we may not have fully
     * resolved the type refs for the type we are examining (i.e., for a
     * struct type, some of the members' types may still be
     * unresolved until after the post-pass).
     *
     * Basically, for each symbol with a valid name, we look it up in
     * the debugfile->types hashtable.  If we find it there already, we
     * change reftab so that the DIE offset for that symbol points to
     * the one we find.  (This means, that to be useful, we have to
     * construct names for pointer/const/vol/array types so that we can
     * look them up too... but we can try the base type thing first and
     * see if it works good enough.)  If we find it, we free it.
     *
     * XXX: but how do we know if we can free what it points to?  Should
     * we maintain a counter of who points to what refs, and any that
     * have zero, remove?  Should we do this with symbol refcnt
     * mechanism?  WAIT -- the principle is that any type we find that
     * matches a type at one of our refs *fully* matches, including all
     * of the types it references, so when we rewrite reftab to use the
     * global type we found, we can safely free the type from this CU
     * AND any types it references.  Suppose we free a pointer to a
     * struct type because we matched it against a global type.  Ok,
     * that means we free the struct type and anything it references.
     * Later, when we process the reftab entry for the struct type
     * itself, we will also find a match in the globals table, and reuse
     * *that* global entry in reftab.  What this means, though, is that
     * we can't free any symbols that did match until after the loop!
     * So we keep a free list.
     *
     * We also need to build fake names for some kinds of types once
     * they've been resolved -- pointers are the big one, because if we
     * can save pointer/const/vol/types, 
     *
     * Of course, this may be temporarily very wasteful; we may have
     * created lots of type symbols we will now remove, and this is
     * essentially our third pass through the CU (and we still have a
     * 4th one to rewrite all our ->datatype fields.  But it should
     * result in less memory usage if there are lots of CUs that have
     * identical types.
     *
     */
    if (opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV) {
	GHashTable *updated = g_hash_table_new(g_direct_hash,g_direct_equal);
	vdebug(3,LA_DEBUG,LF_SYMBOL | LF_DWARF,"type compression 2a\n");
	g_hash_table_iter_init(&iter,reftab);
	while (g_hash_table_iter_next(&iter,
				      (gpointer *)&key,(gpointer *)&value)) {
	    offset = (uintptr_t)key;
	    rsymbol = (struct symbol *)value;
	    if (!rsymbol || !SYMBOL_IS_TYPE(rsymbol) || SYMBOL_IST_ENUM(rsymbol))
		continue;

	    if (rsymbol->freenextpass) {
		rsymbol->freenextpass = 0;
		RPUT(rsymbol,symbol,debugfile,trefcnt);
		g_hash_table_iter_replace(&iter,NULL);
		continue;
	    }

	    if (!(sname = symbol_get_name(rsymbol)))
		continue;

	    if (sname 
		&& (tsymbol = symtab_get_sym(debugfile->shared_types,sname))
		&& rsymbol != tsymbol && tsymbol->isshared) {
		if (symbol_type_equal(rsymbol,tsymbol,updated) == 0) {
		    /* Insert the looked up symbol into our CU's temp
		     * reftab so that any of our DIEs that tries to use
		     * it gets the "global" one instead.
		     */
		    g_hash_table_iter_replace(&iter,tsymbol);

		    g_hash_table_insert(updated,(gpointer)(uintptr_t)offset,
					(gpointer)tsymbol);

		    vdebug(4,LA_DEBUG,LF_SYMBOL,
			   "inserting shared symbol (slow check) %s (%s"
			   " 0x%"PRIxSMOFFSET") of type %s at offset 0x%"
			   PRIxSMOFFSET" into reftab\n",
			   symbol_get_name(tsymbol),
			   symbol_get_name_orig(tsymbol),
			   tsymbol->ref,
			   SYMBOL_TYPE(tsymbol->type),offset);

		    /* Since we're moving across the CU boundary, we
		     * have to hold a ref to this symbol *now*!
		     *
		     * There is a slight possibility that we might end
		     * up "wasting" this reference -- i.e., if our CU
		     * had listed it, but then did not reference it in
		     * any of its DIEs.
		     *
		     * NOTE: no longer hold a ref here; we have to hold
		     * a ref each time we actually use it; see below in
		     * the datatype_ref resolution code!
		     */
		    /* RHOLD(tsymbol); */
		    /* Mark all the symbols that symbol_free would
		     * free as "free next pass" symbols, so that we just
		     * free them and don't process them anymore in our
		     * reftab passes.
		     */
		    /* Free ourself, but not our members! */
		    symbol_type_mark_members_free_next_pass(rsymbol,0);
		    /* Remove ourself from our symtab. */
		    symtab_remove_symbol(rsymbol->symtab,rsymbol);
		    /* Free ourself. */
		    RPUT(rsymbol,symbol,debugfile,trefcnt);
		    continue;
		}
	    }
	    else if (rsymbol != tsymbol) {
		/* XXX: must also change its members' symtabs,
		 * recursively -- all of them!!
		 *
		 * Well, see the comment about members above.  We don't
		 * RHOLD on members right now either.  If we ever do, we
		 * have to do this (^^) too!
		 */
		rsymbol->isshared = 1;
		/* For now, don't set the recurse-on-type bit.  Don't
		 * set the noinsert bit, since we need to stick the
		 * symbol into the new symbol and remove it from the
		 * old.
		 */
		/*
		 * NOTE: no longer hold a ref here; we have to hold
		 * a ref each time we actually use it; see below in
		 * the datatype_ref resolution code!
		 */
		/* RHOLD(rsymbol,debugfile); */
		symbol_change_symtab(rsymbol,debugfile->shared_types,0,0);
		continue;
	    }
	}
	g_hash_table_destroy(updated);
    }

    /* Type compression 2b:
     *
     * Once we've done this first compression pass, we need to go back,
     * again, and resolve all the datatype refs again!  Argh!  But at
     * least it's only the datatype pointers.
     */
    if (opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV) {
	vdebug(3,LA_DEBUG,LF_SYMBOL | LF_DWARF,"type compression 2b\n");
	g_hash_table_iter_init(&iter,reftab);
	while (g_hash_table_iter_next(&iter,
				      (gpointer *)&key,(gpointer *)&value)) {
	    offset = (uintptr_t)key;
	    rsymbol = (struct symbol *)value;
	    if (!rsymbol)
		continue;

	    if (rsymbol->freenextpass) {
		rsymbol->freenextpass = 0;
		RPUT(rsymbol,symbol,debugfile,trefcnt);
		g_hash_table_iter_replace(&iter,NULL);
		continue;
	    }

	    if (rsymbol->datatype_ref) {
		tsymbol = (struct symbol *)	\
		    g_hash_table_lookup(reftab,
					(gpointer)(uintptr_t)rsymbol->datatype_ref);
		/* Type compression: if this type is in another CU, hold
		 * a ref to it!
		 */
		if (tsymbol != rsymbol && tsymbol && tsymbol->isshared) {
		    rsymbol->datatype = tsymbol;
		    RHOLD(tsymbol,rsymbol);
		    rsymbol->usesshareddatatype = 1;

		    //if (tsymbol->datatype && tsymbol->datatype->isshared)
		    //	RHOLD(tsymbol->datatype);

		    vdebug(4,LA_DEBUG,LF_SYMBOL,
			   "using shared symbol (slow check) %s (%s 0x%"PRIxSMOFFSET
			   ") of type %s instead of 0x%"PRIxSMOFFSET
			   " at offset 0x%"PRIxSMOFFSET"\n",
			   symbol_get_name(rsymbol->datatype),
			   symbol_get_name_orig(rsymbol->datatype),
			   rsymbol->datatype->ref,
			   SYMBOL_TYPE(rsymbol->datatype->type),
			   rsymbol->datatype_ref,offset);
		}
	    }
	}

	/* Clean up anybody else who still needs to be freed; also,
	 * check for shared symbols that were unused by this CU (i.e.,
	 * needless types like double or whatever that even if the code
	 * didn't use, the user could still want.
	 */
	vdebug(3,LA_DEBUG,LF_SYMBOL | LF_DWARF,"type compression 2c\n");
	g_hash_table_iter_init(&iter,reftab);
	while (g_hash_table_iter_next(&iter,
				      (gpointer *)&key,(gpointer *)&value)) {
	    offset = (uintptr_t)key;
	    rsymbol = (struct symbol *)value;
	    if (!rsymbol)
		continue;

	    /* If we shared this symbol, but nothing in our CU held a
	     * ref to it, hold an extra ref to it, since it is now on 1)
	     * the shared types symtab, and 2) our symtab.  We cannot do
	     * this in the previous pass; if our reftab's symbols take
	     * more than one ref to this symbol, we need all those
	     * refs.  If we don't take any refs to it, though, we still
	     * need one ref to release when it is freed from this CU's
	     * symtab.
	     */
	    if (rsymbol->symtab != cu_symtab 
		&& rsymbol->isshared && rsymbol->refcnt == 1)
		//RHOLD(rsymbol);

	    if (rsymbol->freenextpass) {
		rsymbol->freenextpass = 0;
		RPUT(rsymbol,symbol,debugfile,trefcnt);
		g_hash_table_iter_replace(&iter,NULL);
		continue;
	    }
	}
    }

    /* Try to find prologue info from line table for this CU. */
    if (args.have_stmt_list_offset) {
	get_lines(debugfile,cu_symtab,args.stmt_list_offset,meta->addrsize);
    }
    else {
	vwarnopt(4,LA_DEBUG,LF_DWARF,"not doing get_lines for offset 0x%"PRIx64"\n",
	      args.stmt_list_offset);
    }

    /* Clear out inline instances table! */
    g_hash_table_iter_init(&iter,cu_abstract_origins);
    while (g_hash_table_iter_next(&iter,
				      (gpointer *)&key,(gpointer *)&value)) {
	offset = (uintptr_t)key;
	iilist = (struct array_list *)value;
	vwarnopt(4,LA_DEBUG,LF_DWARF,
		 "did not use abstract origins list (%d) for offset 0x%"PRIx64"!\n",
		 array_list_len(iilist),offset);
	/* GHashTable thankfully does not depend on the value pointer
	 * being valid in order to remove items from the hashtable!
	 */
	array_list_free(iilist);
    }

    /* Save off whatever offset we got to! */
    *cu_offset = offset;

    goto out;

 errout:
    retval = -1;

 out:
    if (die_offsets) 
	array_list_free(die_offsets);
    free(dies);
    g_hash_table_destroy(reftab);
    g_hash_table_destroy(cu_abstract_origins);
    free(symbols);
    free(symtabs);

    return retval;
}

int debugfile_expand_symbol(struct debugfile *debugfile,struct symbol *symbol) {
    Dwarf_Off die_offset;
    struct array_list *sal = array_list_create(1);
    struct symtab *cu_symtab = symbol->symtab;
    int retval;

    /* Find the top-level symtab. */
    while (cu_symtab->parent)
	cu_symtab = cu_symtab->parent;
    die_offset = cu_symtab->ref;

    if (cu_symtab->meta && cu_symtab->meta->loadtag == LOADTYPE_FULL) {
	vwarnopt(4,LA_DEBUG,LF_DWARF,"cu %s already fully loaded!\n",cu_symtab->name);
	return 0;
    }

    array_list_append(sal,(void *)(uintptr_t)symbol->ref);

    vdebug(5,LA_DEBUG,LF_DWARF,
	   "expanding symbol %s at offset 0x%"PRIxOFFSET"\n",
	   symbol_get_name(symbol),die_offset);

    retval = debuginfo_load_cu(debugfile,NULL,&die_offset,sal,1);

    array_list_free(sal);

    return retval;
}

int debugfile_expand_cu(struct debugfile *debugfile,struct symtab *cu_symtab,
			struct array_list *die_offsets,int expand_dies) {
    Dwarf_Off cu_offset = cu_symtab->ref;

    if (cu_symtab->meta && cu_symtab->meta->loadtag == LOADTYPE_FULL) {
	vwarnopt(4,LA_DEBUG,LF_DWARF,"cu %s already fully loaded!\n",cu_symtab->name);
	return 0;
    }

    if (die_offsets) {
	vdebug(5,LA_DEBUG,LF_DWARF,
	       "loading %d DIEs from CU symtab %s (offset 0x%"PRIxOFFSET")!\n",
	       array_list_len(die_offsets),cu_symtab->name,cu_offset);
    }
    else {
	vdebug(5,LA_DEBUG,LF_DWARF,
	       "loading entire CU symtab %s (offset 0x%"PRIxOFFSET")!\n",
	       cu_symtab->name,cu_offset);
    }
    return debuginfo_load_cu(debugfile,NULL,&cu_offset,die_offsets,expand_dies);
}

/*
 * Traverses the entire debuginfo section in order, one pass.  For each
 * CU, parse it according to constraints in @srcfile_regex_list,
 * @symbol_regex_list, and @quick; then does a post-pass after each CU
 * to resolve references (necessary since we do a strict one-pass
 * traversal).
 *
 * If @srcfile_regex_list, and the CU srcfile name doesn't match
 * anything, skip the CU.
 *
 * Then, if we're processing the CU, and if @symbol_regex_list is set,
 * load all type symbols and inlined origins, and any other symbols that
 * match our regex list; but once we finish the CU, and have resolved
 * references, remove any symbols that have refcnt zero.
 *
 * Finally, if @quick, do not load any detailed information for symbols,
 * including children (i.e., params, members) -- EXCEPT for enumerated
 * vars.  They are technically children, but they are in the namespace
 * of the parent.
 *
 * If the user supplies cu_die_offsets, we only do the CUs specified
 * (and debuginfo_load_cu might only do the DIEs requested too!).  That
 * works like this:
 *
 * Traverses the debuginfo section by hopping around as needed, with a
 * post-pass to resolve accumulated references.  We start with an
 * initial set of symbol names that map to struct dwarf_cu_die_ref
 * offset pairs.  If the DEBUGFILE_LOAD_FLAG_FULL_CU flag is set, we
 * load the full CU for any offset.  Otherwise, we load only the
 * specified DIE, save off any other DIEs it references, and add those
 * offsets to a list to load.  If we don't load full CUs, we have to do
 * the post-pass on the reftab/abs origin stuff ourselves still, because
 * we're not going to handle the DIE's refs recursively.
 */
static int debuginfo_load(struct debugfile *debugfile,
			  Dwfl_Module *dwflmod,Dwarf *dbg) {
    int rc;
    int retval = 0;
    GHashTable *cu_die_offsets = NULL;
    Dwarf_Off offset = 0;
    struct dwarf_cu_meta *meta;
    gpointer cu_offset;
    struct array_list *die_offsets = NULL;
    GHashTableIter iter;
    struct dwarf_cu_die_ref *dcd;
    struct array_list *tmpal;
    int i;
    gpointer key;
    gpointer value;
    struct rfilter_entry *rfe;
    int accept = RF_ACCEPT;

    vdebug(1,LA_DEBUG,LF_DWARF,"starting on %s \n",debugfile->filename);

    if (debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_PUBNAMES) {
	offset = OFFSETMAX;
	cu_die_offsets = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					       NULL,
					       (GDestroyNotify)array_list_free);
	g_hash_table_iter_init(&iter,debugfile->pubnames);
	while (g_hash_table_iter_next(&iter,&key,(gpointer)&value)) {
	    dcd = (struct dwarf_cu_die_ref *)value;
	    if (!(tmpal = (struct array_list *) \
		  g_hash_table_lookup(cu_die_offsets,
				      (gpointer)(uintptr_t)dcd->cu_offset))) {
		tmpal = array_list_create(1);
		g_hash_table_insert(cu_die_offsets,
				    (gpointer)(uintptr_t)dcd->cu_offset,
				    (gpointer *)tmpal);
	    }

	    /* Check the pubname against our rfilter of symbol names, if
	     * any, and skip or include it as the rfilter dictates.
	     *
	     * NOTE that we insert an empty list for the CU to make sure
	     * its header gets loaded.  This way (since each CU in a
	     * sane C program will have at least one thing in
	     * debug_pubnames -- otherwise what's the point?), we force
	     * each CU header to be parsed.  If this turns out to not
	     * work well enough, we'll have to force it another way.
	     */
	    if (debugfile->opts->symbol_filter) {
		rfilter_check(debugfile->opts->symbol_filter,(char *)key,
			      &accept,&rfe);
		if (accept == RF_REJECT) 
		    continue;
	    }

	    array_list_append(tmpal,(void *)(uintptr_t)(dcd->die_offset \
							+ dcd->cu_offset));
	    if ((Dwarf_Off)dcd->cu_offset < offset)
		offset = (Dwarf_Off)dcd->cu_offset;
	}

	g_hash_table_iter_init(&iter,cu_die_offsets);
	while (g_hash_table_iter_next(&iter,&cu_offset,&value)) {
	    tmpal = (struct array_list *)value;
	    vdebug(5,LA_DEBUG,LF_DWARF,"preloading offsets for CU 0x%"PRIxSMOFFSET": ",
		   (SMOFFSET)(uintptr_t)cu_offset);
	    for (i = 0; i < array_list_len(tmpal); ++i) {
		vdebugc(5,LA_DEBUG,LF_DWARF,"0x%"PRIxSMOFFSET" ",
			(SMOFFSET)(uintptr_t)array_list_item(tmpal,i));
	    }
	    vdebugc(5,LA_DEBUG,LF_DWARF,"\n");
	}

	/* Get the first one to seed the loop below. */
	g_hash_table_iter_init(&iter,cu_die_offsets);
	if (!g_hash_table_iter_next(&iter,&cu_offset,&value)) 
	    goto out;
	die_offsets = (struct array_list *)value;
	offset = (Dwarf_Off)(uintptr_t)cu_offset;
    }

    while (1) {
	meta = (struct dwarf_cu_meta *)malloc(sizeof(*meta));
	memset(meta,0,sizeof(*meta));
	meta->dwflmod = dwflmod;
	meta->dbg = dbg;
	meta->addrsize = 0;
	meta->offsize = 0;
#if defined(LIBDW_HAVE_NEXT_UNIT) && LIBDW_HAVE_NEXT_UNIT == 1
	if ((rc = dwarf_next_unit(dbg,offset,&meta->nextcu,&meta->cuhl,
				  &meta->version,&meta->abbroffset,&meta->addrsize,
				  &meta->offsize,NULL,NULL)) < 0) {
	    verror("dwarf_next_unit: %s (%d)\n",dwarf_errmsg(dwarf_errno()),rc);
	    free(meta);
	    goto errout;
	}
	else if (rc > 0) {
	    vdebug(2,LA_DEBUG,LF_DWARF,
		   "dwarf_next_unit returned (%d), aborting successfully.\n",rc);
	    free(meta);
	    goto out;
	}
#else
	if ((rc = dwarf_nextcu(dbg,offset,&meta->nextcu,&meta->cuhl,
			       &meta->abbroffset,&meta->addrsize,
			       &meta->offsize)) < 0) {
	    verror("dwarf_nextcu: %s (%d)\n",dwarf_errmsg(dwarf_errno()),rc);
	    free(meta);
	    goto errout;
	}
	else if (rc > 0) {
	    vdebug(2,LA_DEBUG,LF_DWARF,
		   "dwarf_nextcu returned (%d), aborting successfully.\n",rc);
	    free(meta);
	    goto out;
	}

	vwarnopt(4,LA_DEBUG,LF_DWARF,"assuming DWARF version 4; old elfutils!\n");
	meta->version = 4;
#endif

	if (debuginfo_load_cu(debugfile,meta,&offset,die_offsets,0)) {
	    retval = -1;
	    goto errout;
	}

	if (cu_die_offsets) {
	    if (!g_hash_table_iter_next(&iter,&cu_offset,
					&value)) 
		break;
	    die_offsets = (struct array_list *)value;
	    offset = (Dwarf_Off)(uintptr_t)cu_offset;
	}
	else {
	    offset = meta->nextcu;
	    if (offset == 0) 
		break;
	}
    }
    goto out;

 errout:
    retval = -1;

 out:
    if (debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_PUBNAMES) 
	g_hash_table_destroy(cu_die_offsets);
    return retval;
}

/*
 * If we have to change the name of the symbol, we do it IMMEDIATELY
 * after parsing DIE attrs so that naming is consistent for all the
 * hashtable insertions we do!
 */
void finalize_die_symbol_name(struct symbol *symbol) {
    if (symbol_get_name_orig(symbol)
	&& (SYMBOL_IST_STUN(symbol) || SYMBOL_IST_ENUM(symbol))) {
	/*
	 * NOTE!!!  If this is a struct, union, or enum type, we
	 * *have* to place the struct/union/enum type in front of
	 * the alphanumeric name, since you can have typedefs that
	 * are named the same name as a struct/union/enum.  So we
	 * have to use the full type name as the hashtable key;
	 * otherwise we'll see collisions with typedefs.
	 *
	 * This means the user has to lookup those types with the
	 * fully-qualified type names (i.e., 'struct task_struct'),
	 * not just 'task_struct'.
	 */
	symbol_build_extname(symbol);
    }
}

/*
 * Returns 0 if the symbol was successfully inserted into symbol tables, 
 * and 1 if not (which may not be an error).
 */
int finalize_die_symbol(struct debugfile *debugfile,int level,
			struct symbol *symbol,
			struct symbol *parentsymbol,
			struct symbol *voidsymbol,
			GHashTable *reftab,struct array_list *die_offsets,
			SMOFFSET cu_offset) {
    int retval = 0;
    int *new_subranges;

    if (!symbol) {
	verror("null symbol!\n");
	return -1;
    }

    Dwarf_Off die_offset = symbol->ref;

    /*
     * First, handle void types and array subrange allocation resizing.
     */

    if (SYMBOL_IS_TYPE(symbol)) {
	/* If it's a valid symbol, and it's not a base type, but doesn't
	 * have a type, make it void!
	 */
	if (!SYMBOL_IST_BASE(symbol)
	    && symbol->datatype == NULL
	    && symbol->datatype_ref == 0
	    && (symbol->datatype_code == DATATYPE_PTR
		|| symbol->datatype_code == DATATYPE_TYPEDEF
		/* Not sure if C lets these cases through, but whatever */
		|| symbol->datatype_code == DATATYPE_CONST
		|| symbol->datatype_code == DATATYPE_VOL
		|| symbol->datatype_code == DATATYPE_FUNCTION)) {
	    vdebug(3,LA_DEBUG,LF_DWARF,
		   "[DIE %" PRIx64 "] assuming %s type %s without type is void\n",
		   die_offset,DATATYPE(symbol->datatype_code),
		   symbol_get_name_orig(symbol));
	    symbol->datatype = voidsymbol;
	}
	else if (symbol->datatype_code == DATATYPE_ARRAY
		 && SYMBOL_IS_FULL(symbol)
		 && symbol->s.ti->d.a.count) {
	    /* Reduce the allocation to exactly the length we used! */
	    if (symbol->s.ti->d.a.alloc > symbol->s.ti->d.a.count) {
		if (!(new_subranges = realloc(symbol->s.ti->d.a.subranges,
					      sizeof(int)*symbol->s.ti->d.a.count))) 
		    vwarnopt(4,LA_DEBUG,LF_DWARF,
			     "harmless subrange realloc failure: %s\n",
			     strerror(errno));
		else 
		    symbol->s.ti->d.a.subranges = new_subranges;
	    }
	}
    }

    if (SYMBOL_IS_FULL_VAR(symbol)
	&& SYMBOL_IS_FULL_TYPE(parentsymbol)
	&& parentsymbol->datatype_code == DATATYPE_UNION) {
	/*
	 * Set a member offset of 0 for each union's member.
	 */
	symbol->s.ii->d.v.l.loctype = LOCTYPE_MEMBER_OFFSET;
	symbol->s.ii->d.v.l.l.member_offset = 0;
    }

    /*
     * If we have a base_addr for the symbol, insert it into the
     * addresses table.
     */
    if (SYMBOL_IS_INSTANCE(symbol) && symbol_get_name_orig(symbol)) {
	ADDR fminaddr = symbol->base_addr;
	struct symtab *symtab;
	int i;

	/* We don't need this anymore because we track the minimum
	 * address during attribute parsing.
	 */
	if (0 && SYMBOL_IS_FULL(symbol)) {
	    if (symbol->s.ii->d.f.hasentrypc)
		fminaddr = symbol->s.ii->d.f.entry_pc;
	    else if ((symtab = symbol->s.ii->d.f.symtab)) {
		if (RANGE_IS_PC(&symtab->range)) 
		    fminaddr = symtab->range.r.a.lowpc;
		else if (RANGE_IS_LIST(&symtab->range)) {
		    /* Find the lowest addr! */
		    for (i = 0; i < symtab->range.r.rlist.len; ++i) {
			if (symtab->range.r.rlist.list[i]->start < fminaddr)
			    fminaddr = symtab->range.r.rlist.list[i]->start;
		    }
		    vwarnopt(4,LA_DEBUG,LF_DWARF,
			     "assuming function %s entry is lowest address"
			     " in list 0x%"PRIxADDR"!\n",
			     symbol_get_name_orig(symbol),fminaddr);
		}
		else if (!symbol->s.ii->isinlined) {
		    vwarnopt(4,LA_DEBUG,LF_DWARF,
			     "function %s range is not PC/list!\n",
			     symbol_get_name_orig(symbol));
		}
	    }
	}

	if (fminaddr != 0 && fminaddr != ADDRMAX) {
	    g_hash_table_insert(debugfile->addresses,(gpointer)fminaddr,symbol);
	    vdebug(4,LA_DEBUG,LF_DWARF,
		   "inserted %s %s with minaddr 0x%"PRIxADDR" into debugfile addresses table\n",
		   SYMBOL_TYPE(symbol->type),symbol_get_name_orig(symbol),fminaddr);
	}
    }

    /*
     * If we're doing a partial CU load (i.e., loading specific DIE
     * offset within this CU), any other symbols referenced by this
     * symbol need to get appended to our DIE load list if we haven't
     * already loaded them!
     */
    if (die_offsets) {
	if (!symbol->datatype
	    && symbol->datatype_ref
	    && !(symbol->datatype = (struct symbol *)	\
		 g_hash_table_lookup(reftab,
				     (gpointer)(uintptr_t)symbol->datatype_ref))) {
	    array_list_append(die_offsets,
			      (void *)(uintptr_t)symbol->datatype_ref);
	}

	/* We can't do this for inlined formal params, vars, or labels,
	 * because we will jump into the middle of a subprogram, without
	 * knowing we are in that subprogram DIE -- so our symtab
	 * hierarchy will be screwed up!
	 *
	 * XXX: I still think that this might be insufficient, and
	 * might end up putting inlined subroutines onto the wrong
	 * symtabs.  BUT, for now it seems reasonable because even if
	 * there are nested subroutines, as long as we fully process the
	 * outermost one (i.e., add it to die_offsets first) first,
	 * we'll process the children ones first (well, at least as long
	 * as they are loading without PARTIALSYM).  If they load with
	 * PARTIALSYM, then we won't process nested subroutines and
	 * we're screwed?  Worried.  But there's also little
	 * alternative, other than to back up to the CU start and skim
	 * over stacks of DIE children until we hit this origin_ref, and
	 * then process the top-most "parent" DIE of the origin_ref
	 * child DIE.  That is more expensive and more complicated :).
	 *
	 * TODO: but I suppose we'll have to do it...
	 */
	if (SYMBOL_IS_FULL_FUNCTION(symbol)) {
	    if (symbol->isinlineinstance
		&& !symbol->s.ii->origin && symbol->s.ii->origin_ref
		&& !(symbol->s.ii->origin = (struct symbol *)	\
		     g_hash_table_lookup(reftab,
					 (gpointer)(uintptr_t)symbol->s.ii->origin_ref))) {
		array_list_append(die_offsets,
				  (void *)(uintptr_t)symbol->s.ii->origin_ref);
	    }
	}
    }

    /*
     * Actually do the symtab inserts and generate names for symbols if
     * we need to.
     */

    if (SYMBOL_IS_TYPE(symbol)) {
	if (!symbol_get_name_orig(symbol)) {
	    symtab_insert(symbol->symtab,symbol,die_offset);

	    /* We inserted it, but into the anon table, not the primary
	     * table!  Don't give anonymous symbols names.
	     */
	    retval = 1;
	}
	else {
	    if (symtab_insert(symbol->symtab,symbol,0)) {
		/* The symbol already was in this symtab's primary
		 * table; put it in the anontable so it can get freed
		 * later!
		 */
		if (!strcmp("unsigned int",symbol_get_name(symbol)) == 0)
		    vwarnopt(3,LA_DEBUG,LF_DWARF,
			     "duplicate symbol %s (orig %s) at offset %"PRIx64
			     " (symtab %s)\n",
			     symbol_get_name(symbol),
			     symbol_get_name_orig(symbol),
			     die_offset,symbol->symtab->name);

		if (symtab_insert(symbol->symtab,symbol,die_offset)) {
		    verror("could not insert duplicate symbol %s (%s) at offset %"PRIx64" into anontab!\n",
			   symbol_get_name(symbol),symbol_get_name_orig(symbol),
			   die_offset);
		}
	    }

	    if (!(debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES))
		debugfile_add_type_name(debugfile,symbol_get_name(symbol),symbol);
	}
    }
    else if (SYMBOL_IS_VAR(symbol) 
	     && symbol->isparam 
	     && parentsymbol && SYMBOL_IST_FUNCTION(parentsymbol)) {
	/* Argh, catch function params that are part of function types
	 * -- DO NOT put these in the symbol table!
	 */
	retval = 1;
    }
    else if (symbol_get_name_orig(symbol) && SYMBOL_IS_INSTANCE(symbol)) {
	if (symbol->type == SYMBOL_TYPE_FUNCTION) {
	    if (symbol->datatype == NULL
		&& symbol->datatype_ref == 0) {
		vdebug(3,LA_DEBUG,LF_DWARF,
		       "[DIE %" PRIx64 "] assuming function %s without type is void\n",
		       die_offset,symbol_get_name_orig(symbol));
		symbol->datatype = voidsymbol;
	    }

	    if (symtab_insert(symbol->symtab,symbol,0)) {
		/* The symbol already was in this symtab's primary
		 * table; put it in the anontable so it can get freed
		 * later!
		 */
		vwarnopt(3,LA_DEBUG,LF_DWARF,
			 "duplicate symbol %s at offset %"PRIx64" (symtab %s)\n",
			 symbol_get_name_orig(symbol),die_offset,
			 symbol->symtab->name);
		if (symtab_insert(symbol->symtab,symbol,die_offset)) {
		    verror("could not insert duplicate symbol %s at offset %"PRIx64" into anontab!\n",
			   symbol_get_name_orig(symbol),die_offset);
		}
	    }

	    if (symbol->isexternal && !symbol->isdeclaration) 
		debugfile_add_global(debugfile,symbol);
	}
	else if (symbol->type == SYMBOL_TYPE_VAR) {
	    if (symbol->datatype == NULL
		&& symbol->datatype_ref == 0) {
		vdebug(3,LA_DEBUG,LF_DWARF,
		       "assuming var %s without type is void at %"PRIx64"\n",
		       symbol_get_name_orig(symbol),die_offset);
		symbol->datatype = voidsymbol;
	    }

	    /* Don't insert members into the symbol table! */
	    if (!symbol->ismember) {
		if (symtab_insert(symbol->symtab,symbol,0)) {
		    /* The symbol already was in this symtab's primary
		     * table; put it in the anontable so it can get freed
		     * later!
		     */
		    vwarnopt(3,LA_DEBUG,LF_DWARF,
			     "duplicate symbol %s at offset %"PRIx64" (symtab %s)\n",
			     symbol_get_name_orig(symbol),die_offset,
			     symbol->symtab->name);
		    if (symtab_insert(symbol->symtab,symbol,die_offset)) {
			verror("could not insert duplicate symbol %s at offset %"PRIx64" into anontab!\n",
			       symbol_get_name_orig(symbol),die_offset);
		    }
		}
	    }

	    if (symbol->isexternal && !symbol->isdeclaration) 
		debugfile_add_global(debugfile,symbol);
	}
	else if (symbol->type == SYMBOL_TYPE_LABEL) {
	    if (symtab_insert(symbol->symtab,symbol,0)) {
		/* The symbol already was in this symtab's primary
		 * table; put it in the anontable so it can get freed
		 * later!
		 */
		vwarnopt(4,LA_DEBUG,LF_DWARF,
			 "duplicate symbol %s at offset %"PRIx64" (symtab %s)\n",
			 symbol_get_name_orig(symbol),die_offset,
			 symbol->symtab->name);
		if (symtab_insert(symbol->symtab,symbol,die_offset)) {
		    verror("could not insert duplicate symbol %s at offset %"PRIx64" into anontab!\n",
			   symbol_get_name_orig(symbol),die_offset);
		}
	    }
	}
    }
    else if (SYMBOL_IS_INSTANCE(symbol)
	     && symbol->isinlineinstance) {
	/* An inlined instance; definitely need it in the symbol
	 * tables.  But we have to give it a name.  And the name *has*
	 * to be unique... so we do our best: 
	 *  __INLINED(<symbol_mem_addr>:(iref<src_sym_dwarf_addr>
         *                               |<src_sym_name))
	 * (we really should use the DWARF DIE addr for easier debug,
	 * but that would cost us 8 bytes more in the symbol struct.)
	 */
	if (SYMBOL_IS_FULL(symbol) && !symbol_get_name(symbol)) {
	    char *inname;
	    int inlen;
	    if (symbol->s.ii->origin) {
		inlen = 9 + 1 + 18 + 1 + strlen(symbol_get_name_orig(symbol->s.ii->origin)) + 1 + 1;
		inname = malloc(sizeof(char)*inlen);
		sprintf(inname,"__INLINED(ref%"PRIxSMOFFSET":%s)",
			symbol->ref,
			symbol_get_name_orig(symbol->s.ii->origin));
	    }
	    else {
		inlen = 9 + 1 + 18 + 1 + 4 + 16 + 1 + 1;
		inname = malloc(sizeof(char)*inlen);
		sprintf(inname,"__INLINED(ref%"PRIxSMOFFSET":iref%"PRIxSMOFFSET")",
			symbol->ref,
			symbol->s.ii->origin_ref);
	    }

	    symbol_set_name(symbol,inname,1);
	    free(inname);
	}

	/* Stick it in the anontab. */
	if (symtab_insert(symbol->symtab,symbol,die_offset)) {
	    verror("could not insert inlineinstance symbol %s at offset %"PRIx64" into anontab!\n",
			   symbol_get_name_orig(symbol),die_offset);
	}
	retval = 1;
    }
    else if (symbol->type == SYMBOL_TYPE_VAR 
	     && symbol->isparam
	     && SYMBOL_IS_FULL_FUNCTION(parentsymbol) 
	     && parentsymbol->isinlineinstance) {
	/* Sometimes it seems we see unnamed function params that are
	 * not marked as inline instances, BUT have a subprogram parent
	 * that is an inline instance.
	 *
	 * Stick it in the anontab; otherwise it won't get freed.
	 */
	if (symtab_insert(symbol->symtab,symbol,die_offset)) {
	    verror("could not insert anon param at offset %"PRIx64" into anontab!\n",
		   die_offset);
	}
	retval = 1;
    }
    else if (symbol->type == SYMBOL_TYPE_VAR
	     && (symbol->isparam || symbol->ismember)) {
	/* We allow unnamed params, of course, BUT we don't put them
	 * into the symbol table.  We leave them on the function
	 * symbol/function type to be freed in symbol_free!
	 *
	 * XXX: we only need this for subroutine type formal parameters;
	 * should we make the check above more robust?
	 */
	retval = 1;
    }
    else {
	vwarnoptc(9,LA_DEBUG,LF_DWARF,
		  "non-anonymous symbol of type %s without a name at %"PRIx64"!\n",
		  SYMBOL_TYPE(symbol->type),die_offset);
	if (vwarn_is_on(9,LA_DEBUG,LF_DWARF)) {
	    struct dump_info udn = {
		.stream = stderr,
		.prefix = "  ",
		.detail = 1,
		.meta = 1
	    };
	    symbol_var_dump(symbol,&udn);
	    fprintf(stderr,"\n");
	}

	/*
	 * XXX: we cannot free any symbols in this function; they are
	 * already on the reftab and might have been attached to the
	 * parent.  Just stick it in the anontab.
	 */
	///* Don't need to force; nobody holds refs to us yet! */
	//symbol_free(symbol,0);
	//retval = 2;
	//return retval;
	if (symtab_insert(symbol->symtab,symbol,die_offset)) {
	    verror("could not insert non-anon symbol with no name at offset %"PRIx64" into anontab!\n",
		   die_offset);
	}
	retval = 1;
    }

    vdebug(5,LA_DEBUG,LF_SYMBOL,"finalized symbol at %lx %s//%s %p\n",
	   die_offset,SYMBOL_TYPE(symbol->type),symbol_get_name_orig(symbol),
	   symbol);

    return retval;
}

/*
 * Currently broken for nested struct/union resolution, if one of the
 * nested members has the same type as a parent higher up in the nest.
 *
 * So, we don't use it anymore and have moved to a much more
 * straightforward approach.
 */
void resolve_refs(gpointer key __attribute__ ((unused)),
		  gpointer value,gpointer data) {
    struct symbol *symbol = (struct symbol *)value;
    GHashTable *reftab = (GHashTable *)data;
    struct symbol *member;
    struct symbol_instance *member_instance;

    if (SYMBOL_IS_TYPE(symbol)) {
	if (symbol->datatype_code == DATATYPE_BASE)
	    return;
	if (symbol->datatype_code == DATATYPE_PTR
	    || symbol->datatype_code == DATATYPE_TYPEDEF
	    || symbol->datatype_code == DATATYPE_ARRAY
	    || symbol->datatype_code == DATATYPE_CONST
	    || symbol->datatype_code == DATATYPE_VOL
	    || symbol->datatype_code == DATATYPE_FUNCTION) {
	    if (!symbol->datatype) {
		symbol->datatype = \
		    g_hash_table_lookup(reftab,
					(gpointer)(uintptr_t)symbol->datatype_ref);
		if (!symbol->datatype) 
		    verror("could not resolve ref %"PRIxSMOFFSET" for %s type symbol %s\n",
			   symbol->datatype_ref,
			   DATATYPE(symbol->datatype_code),
			   symbol_get_name(symbol));
		else {
		    vdebug(3,LA_DEBUG,LF_DWARF,
			   "resolved ref 0x%"PRIxSMOFFSET" %s type symbol %s\n",
			   symbol->datatype_ref,
			   DATATYPE(symbol->datatype_code),symbol_get_name(symbol));

		    vdebug(3,LA_DEBUG,LF_DWARF,
			   "rresolving just-resolved %s type symbol %s\n",
			   DATATYPE(symbol->datatype->datatype_code),
			   symbol_get_name(symbol->datatype),
			   symbol->datatype->datatype_ref);
		    resolve_refs(NULL,symbol->datatype,reftab);
		}
	    }
	    else {
		/* Even if this symbol has been resolved, anon types
		 * further down the type chain may not have been
		 * resolved!
		 */
		vdebug(3,LA_DEBUG,LF_DWARF,
		       "rresolving known %s type symbol %s ref 0x%"PRIxSMOFFSET"\n",
		       DATATYPE(symbol->datatype->datatype_code),
		       symbol_get_name(symbol->datatype),
		       symbol->datatype->datatype_ref);

		resolve_refs(NULL,symbol->datatype,data);
	    }

	    if (SYMBOL_IS_FULL(symbol)
		&& symbol->datatype_code == DATATYPE_FUNCTION
		&& symbol->s.ti->d.f.count) {
		/* do it for the function type args! */
		list_for_each_entry(member_instance,&(symbol->s.ti->d.f.args),
				    d.v.member) {
		    member = member_instance->d.v.member_symbol;
		    vdebug(3,LA_DEBUG,LF_DWARF,
			   "rresolving function type %s arg %s ref 0x%"PRIxSMOFFSET"\n",
			   symbol_get_name(symbol),symbol_get_name(member),member->datatype_ref);
		    resolve_refs(NULL,member,reftab);
		}
	    }
	}
	else if (SYMBOL_IS_FULL(symbol)
		 && (symbol->datatype_code == DATATYPE_STRUCT
		     || symbol->datatype_code == DATATYPE_UNION)) {
	    /* 
	     * We need to recurse for each of the struct members too,
	     * BUT we have to take special care with members because
	     * the type of a member (or a member of a member, etc)
	     * could be the same type we're trying to resolve
	     * currently.  That would send us into a bad loop and blow
	     * out the stack... so we can't do that.
	     *
	     * XXX: this is currently broken -- even if the member's
	     * datatype is resolved, if that member has members, we
	     * don't handle those.  We've moved to not using this
	     * function anymore as a result.
	     */
	    list_for_each_entry(member_instance,&(symbol->s.ti->d.su.members),
				d.v.member) {
		member = member_instance->d.v.member_symbol;
		if (member->datatype)
		    continue;
		vdebug(3,LA_DEBUG,LF_DWARF,
		       "rresolving s/u %s member %s ref 0x%"PRIxSMOFFSET"\n",
		       symbol_get_name(symbol),symbol_get_name(member),member->datatype_ref);
		resolve_refs(NULL,member,reftab);
	    }
	}
    }
    else {
	/* do it for the variable or function's main type */
	if (!symbol->datatype && symbol->datatype_ref) {
	    if (!(symbol->datatype = \
		  g_hash_table_lookup(reftab,
				      (gpointer)(uintptr_t)symbol->datatype_ref)))
		verror("could not resolve ref %"PRIxSMOFFSET" for var/func symbol %s\n",
		       symbol->datatype_ref,symbol_get_name(symbol));
	    else {
		vdebug(3,LA_DEBUG,LF_DWARF,
		       "resolved ref %"PRIxSMOFFSET" non-type symbol %s\n",
		       symbol->datatype_ref,symbol_get_name(symbol));
	    }
	}

	/* Always recurse in case there are anon symbols down the chain
	 * that need resolution.
	 */
	if (symbol->datatype) {
	    vdebug(3,LA_DEBUG,LF_DWARF,
		   "rresolving ref 0x%"PRIxSMOFFSET" %s type symbol %s\n",
		   symbol->datatype->datatype_ref,
		   DATATYPE(symbol->datatype->datatype_code),
		   symbol_get_name(symbol->datatype));
	    resolve_refs(NULL,symbol->datatype,reftab);
	}

	/* then, if this is a function, do the args */
	if (SYMBOL_IS_FULL_FUNCTION(symbol)) 
	    list_for_each_entry(member_instance,&(symbol->s.ii->d.f.args),
				d.v.member) {
		member = member_instance->d.v.member_symbol;
		if (member->datatype) {
		    vdebug(3,LA_DEBUG,LF_DWARF,
			   "rresolving ref 0x%"PRIxSMOFFSET" function %s arg %s\n",
			   member->datatype_ref,symbol_get_name(symbol),symbol_get_name(member));
		    resolve_refs(NULL,member,reftab);
		}
	    }
    }

    /*
     * If this is an inlined instance of a function or variable
     * (probably only a param variable?), resolve the origin ref if it
     * exists.
     *
     * XXX: do we need to recurse on the resolved ref?  I hope not!
     */
    if (symbol->isinlineinstance
	&& SYMBOL_IS_FULL(symbol)
	&& !symbol->s.ii->origin 
	&& symbol->s.ii->origin_ref) {
	if (!(symbol->s.ii->origin = \
	      g_hash_table_lookup(reftab,
				  (gpointer)(uintptr_t)symbol->s.ii->origin_ref))) {
	    verror("could not resolve ref 0x%"PRIxSMOFFSET" for inlined %s\n",
		   symbol->s.ii->origin_ref,SYMBOL_TYPE(symbol->type));
	}
	else {
	    vdebug(3,LA_DEBUG,LF_DWARF,
		   "resolved ref 0x%"PRIxSMOFFSET" inlined %s to %s\n",
		   symbol->s.ii->origin_ref,
		   SYMBOL_TYPE(symbol->type),
		   symbol_get_name(symbol->s.ii->origin));
	}

	if (symbol->s.ii->origin)
	    resolve_refs(NULL,symbol->s.ii->origin,reftab);
    }
}

int get_pubnames(struct debugfile *debugfile,unsigned char *buf,unsigned int len,
		 Dwarf *dbg) {
    const unsigned char *readp = buf;
    const unsigned char *readendp = buf + len;
    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;

    while (readp < readendp) {
	/* Each entry starts with a header:

	   1. A 4-byte or 12-byte length containing the length of the
	   set of entries for this compilation unit, not including the
	   length field itself. [...]

	   2. A 2-byte version identifier containing the value 2 for
	   DWARF Version 2.1.

	   3. A 4-byte or 8-byte offset into the .debug_info section. [...]

	   4. A 4-byte or 8-byte length of the CU in the .debug_info section.
	*/

	Dwarf_Word length = read_4ubyte_unaligned_inc(obo,readp);
	int is64 = 0;

	if (length == DWARF3_LENGTH_64_BIT) {
	    vwarnopt(4,LA_DEBUG,LF_DWARF,
		     "64-bit DWARF length %"PRIu64"; continuing.\n",length);
	    length = read_8ubyte_unaligned_inc(obo,readp);
	    is64 = 1;
	}
	else if (unlikely(length >= DWARF3_LENGTH_MIN_ESCAPE_CODE
			  && length <= DWARF3_LENGTH_MAX_ESCAPE_CODE))
	    vwarnopt(2,LA_DEBUG,LF_DWARF,
		     "bad DWARF length %"PRIu64"; continuing anyway!\n",length);

	unsigned int version = read_2ubyte_unaligned_inc(obo,readp);
	if (version != 2) 
	    vwarnopt(2,LA_DEBUG,LF_DWARF,
		     "bad DWARF arange version %u; continuing anyway!\n",
		     version);

	Dwarf_Word offset = read_4ubyte_unaligned_inc(obo,readp);

	/* Dwarf_Word cu_length = */ read_4ubyte_unaligned_inc(obo,readp);

	while (1) {
	    Dwarf_Word die_offset;

	    if (is64) 
		die_offset = read_8ubyte_unaligned_inc(obo,readp);
	    else
		die_offset = read_4ubyte_unaligned_inc(obo,readp);

	    /* A zero value marks the end. */
	    if (die_offset == 0)
		break;

	    /* Use a global offset, not a per-CU offset. */
	    /* die_offset += offset; */

	    /* XXX: this is wasteful for 64-bit hosts; we could save all
	     * these mallocs by just using a u64 and giving half the
	     * bits to the cuoffset and half to the dieoffset.
	     */
	    struct dwarf_cu_die_ref *dcd = (struct dwarf_cu_die_ref *)	\
		malloc(sizeof(*dcd));
	    dcd->cu_offset = offset;
	    dcd->die_offset = die_offset;

	    g_hash_table_insert(debugfile->pubnames,strdup((const char *)readp),
				(gpointer)dcd);
	    readp += strlen((const char *)readp) + 1;
	}
    }

    return 0;
}

int get_aranges(struct debugfile *debugfile,unsigned char *buf,unsigned int len,
		Dwarf *dbg) {
    struct symtab *cu_symtab;
    const unsigned char *readp = buf;
    const unsigned char *readendp = buf + len;
    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;

    while (readp < readendp) {
	const unsigned char *hdrstart = readp;

	/* Each entry starts with a header:

	   1. A 4-byte or 12-byte length containing the length of the
	   set of entries for this compilation unit, not including the
	   length field itself. [...]

	   2. A 2-byte version identifier containing the value 2 for
	   DWARF Version 2.1.

	   3. A 4-byte or 8-byte offset into the .debug_info section. [...]

	   4. A 1-byte unsigned integer containing the size in bytes of
	   an address (or the offset portion of an address for segmented
	   addressing) on the target system.

	   5. A 1-byte unsigned integer containing the size in bytes of
	   a segment descriptor on the target system.
	*/

	Dwarf_Word length = read_4ubyte_unaligned_inc(obo,readp);

	if (length == DWARF3_LENGTH_64_BIT) {
	    vwarnopt(4,LA_DEBUG,LF_DWARF,
		     "64-bit DWARF length %"PRIu64"; continuing.\n",length);
	    length = read_8ubyte_unaligned_inc(obo,readp);
	}
	else if (unlikely(length >= DWARF3_LENGTH_MIN_ESCAPE_CODE
			  && length <= DWARF3_LENGTH_MAX_ESCAPE_CODE))
	    vwarnopt(2,LA_DEBUG,LF_DWARF,
		     "bad DWARF length %"PRIu64"; continuing anyway!\n",length);

	unsigned int version = read_2ubyte_unaligned_inc(obo,readp);
	if (version != 2) 
	    vwarnopt(2,LA_DEBUG,LF_DWARF,
		     "bad DWARF arange version %u; continuing anyway!\n",
		     version);

	Dwarf_Word offset = read_4ubyte_unaligned_inc(obo,readp);

	unsigned int address_size = *readp++;
	if (address_size != 4 && address_size != 8)
	    vwarnopt(4,LA_DEBUG,LF_DWARF,
		     "bad DWARF address size %u; continuing anyway!\n",
		     address_size);

	/* unsigned int segment_size = * */ readp++;

	/* Round the address to the next multiple of 2*address_size.  */
	readp += ((2 * address_size - ((readp - hdrstart) % (2 * address_size)))
		  % (2 * address_size));

	/*
	 * Lookup the symtab at this offset, or create one if it doesn't
	 * exist yet.
	 */
	if (!(cu_symtab = (struct symtab *)\
	      g_hash_table_lookup(debugfile->cuoffsets,(gpointer)(uintptr_t)offset))) {
	    cu_symtab = symtab_create(NULL,debugfile,(SMOFFSET)offset,NULL,0,NULL);
	    debugfile_add_cu_symtab(debugfile,cu_symtab);
	}

	while (1) {
	    Dwarf_Word range_address;
	    Dwarf_Word range_length;

	    if (address_size == 8) {
		range_address = read_8ubyte_unaligned_inc(obo,readp);
		range_length = read_8ubyte_unaligned_inc(obo,readp);
	    }
	    else {
		range_address = read_4ubyte_unaligned_inc(obo,readp);
		range_length = read_4ubyte_unaligned_inc(obo,readp);
	    }

	    /* Two zero values mark the end.  */
	    if (range_address == 0 && range_length == 0)
		break;
	    

	    symtab_update_range(cu_symtab,range_address,
				range_address + range_length,
				RANGE_TYPE_NONE);
	}
    }

    return 0;
}

static int process_dwflmod (Dwfl_Module *dwflmod,
			    void **userdata __attribute__ ((unused)),
			    const char *uname __attribute__ ((unused)),
			    Dwarf_Addr base __attribute__ ((unused)),
			    void *arg) {
    struct debugfile *debugfile = (struct debugfile *)arg;
    struct binfile *binfile = debugfile->binfile;
    struct binfile_elf *bfelf = (struct binfile_elf *)binfile->priv;
    GElf_Addr dwflbias;
    Dwarf_Addr dwbias;
    Dwarf *dbg;
    GElf_Shdr *shdr;
    Elf_Scn *scn;
    int i;
    char *name;
    char **saveptr;
    unsigned int *saveptrlen;
    Elf_Data *edata;

    dwfl_module_getelf(dwflmod,&dwflbias);

    /*
     * Last setup before parsing DWARF stuff!
     */
    dbg = dwfl_module_getdwarf(dwflmod,&dwbias);
    if (!dbg) {
	vwarnopt(2,LA_DEBUG,LF_DWARF,
		 "could not get dwarf module in debugfile %s!\n",
		 debugfile->filename);
	goto errout;
    }

    for (i = 0; i < bfelf->ehdr.e_shnum; ++i) {
	shdr = &bfelf->shdrs[i];
	scn = elf_getscn(bfelf->elf,i);

	if (shdr && shdr->sh_size > 0) { // &&shdr->sh_type != SHT_PROGBITS) {
	    //shdr_mem.sh_flags & SHF_STRINGS) {
	    name = elf_strptr(bfelf->elf,bfelf->shstrndx,shdr->sh_name);

	    if (strcmp(name,".debug_str") == 0) {
		saveptr = &debugfile->dbg_strtab;
		saveptrlen = &debugfile->dbg_strtablen;
	    }
	    else if (strcmp(name,".debug_loc") == 0) {
		saveptr = &debugfile->loctab;
		saveptrlen = &debugfile->loctablen;
	    }
	    else if (strcmp(name,".debug_ranges") == 0) {
		saveptr = &debugfile->rangetab;
		saveptrlen = &debugfile->rangetablen;
	    }
	    else if (strcmp(name,".debug_line") == 0) {
		saveptr = &debugfile->linetab;
		saveptrlen = &debugfile->linetablen;
	    }
	    else if (strcmp(name,".debug_aranges") == 0
		     || strcmp(name,".debug_pubnames") == 0) {
		/* Skip to the !saveptr checks below and load these
		 * sections immediately.
		 */
		saveptr = NULL;
		saveptrlen = NULL;
	    }
	    else {
		continue;
	    }

	    vdebug(2,LA_DEBUG,LF_DWARF,
		   "found %s section (%d) (%p) in debugfile %s\n",
		   name,shdr->sh_size,scn,debugfile->filename);

	    edata = elf_rawdata(scn,NULL);
	    if (!edata) {
		verror("cannot get data for valid section '%s': %s\n",
		       name,elf_errmsg(-1));
		continue;
	    }

	    /*
	     * aranges and pubnames are special.  We parse them
	     * *immediately*, using them to setup our CU symtabs, which
	     * are then validated and filled in as we parse debuginfo.
	     */
	    if (!saveptr) {
		if (strcmp(name,".debug_aranges") == 0) {
		    get_aranges(debugfile,edata->d_buf,edata->d_size,dbg);
		    continue;
		}
		else if (strcmp(name,".debug_pubnames") == 0) {
		    get_pubnames(debugfile,edata->d_buf,edata->d_size,dbg);
		    continue;
		}
	    }
	    else {
		/*
		 * We just malloc a big buf now, and then we don't free
		 * anything in symtabs or syms that is present in here!
		 */
		*saveptrlen = edata->d_size;
		*saveptr = malloc(edata->d_size);
		memcpy(*saveptr,edata->d_buf,edata->d_size);
	    }
	}
	else if (shdr && shdr->sh_size == 0) {
	    vdebug(2,LA_DEBUG,LF_DWARF,"section empty, which is fine!\n");
	}
    }
    if (!debugfile->dbg_strtab) {
	vwarn("no debug string table found for debugfile %s; things may break!\n",
	      debugfile->filename);
    }

    /* now rescan for debug_info sections */
    for (i = 0; i < bfelf->ehdr.e_shnum; ++i) {
	shdr = &bfelf->shdrs[i];
	scn = elf_getscn(bfelf->elf,i);

	if (shdr && shdr->sh_size > 0 && shdr->sh_type == SHT_PROGBITS) {
	    name = elf_strptr(bfelf->elf,bfelf->shstrndx,shdr->sh_name);

	    if (strcmp(name,".debug_info") == 0) {
		vdebug(2,LA_DEBUG,LF_DWARF,
		       "found .debug_info section in debugfile %s\n",
		       debugfile->filename);
		debuginfo_load(debugfile,dwflmod,dbg);
		//break;
	    }
	}
    }

    /* Don't free any of the copied ELF data structs if we're partially
     * loading the debuginfo!
     */
    if (debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_PARTIALSYM
	|| debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_CUHEADERS
	|| debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_PUBNAMES) 
	goto out;

    /* Now free up the temp loc/range tables. */
    if (debugfile->loctab) {
	free(debugfile->loctab);
	debugfile->loctablen = 0;
	debugfile->loctab = NULL;
    }
    if (debugfile->rangetab) {
	free(debugfile->rangetab);
	debugfile->rangetablen = 0;
	debugfile->rangetab = NULL;
    }
    if (debugfile->linetab) {
	free(debugfile->linetab);
	debugfile->linetablen = 0;
	debugfile->linetab = NULL;
    }
    /*
     * Only save dbg_strtab if we're gonna use it.
     */
#ifdef DWDEBUG_NOUSE_STRTAB
    if (debugfile->dbg_strtab) {
	free(debugfile->dbg_strtab);
	debugfile->dbg_strtablen = 0;
	debugfile->dbg_strtab = NULL;
    }
#endif

 out:
    /* Let caller (or debugfile free) free ebl later. */
    return DWARF_CB_OK;

 errout:
    /* Let caller (or debugfile free) free ebl later. */
    return DWARF_CB_ABORT;
}


/*
 * Stub callback telling 
 */
static int find_no_debuginfo(Dwfl_Module *mod __attribute__ ((unused)),
			     void **userdata __attribute__ ((unused)),
			     const char *modname __attribute__ ((unused)),
			     Dwarf_Addr base __attribute__ ((unused)),
			     const char *file_name __attribute__ ((unused)),
			     const char *debuglink_file __attribute__ ((unused)),
			     GElf_Word debuglink_crc __attribute__ ((unused)),
			     char **debuginfo_file_name __attribute__ ((unused))) {
    return -1;
}

static int bfi_find_elf(Dwfl_Module *mod __attribute__ ((unused)),
			void **userdata,
			const char *modname __attribute__ ((unused)),
			Dwarf_Addr base __attribute__ ((unused)),
			char **file_name __attribute__ ((unused)),
			Elf **elfp) {
    struct binfile *binfile;
    struct binfile_instance *bfi;
    struct binfile_elf *bfelf;

    if (!(binfile = (struct binfile *)*userdata)) {
	verror("no binfile; bug!?\n");
	return -1;
    }

    if (!(bfi = binfile->instance)) {
	verror("no instance info for binfile %s!\n",binfile->filename);
	return -1;
    }

    if (!(bfelf = (struct binfile_elf *)binfile->priv)) {
	verror("no ELF info for binfile %s!\n",binfile->filename);
	return -1;
    }

    if (elfp)
	*elfp = bfelf->elf;
    
    return -1;
}

static int bfi_find_section_address(Dwfl_Module *mod,void **userdata,
				    const char *modname,Dwarf_Addr base,
				    const char *secname,GElf_Word shndx,
				    const GElf_Shdr *shdr,Dwarf_Addr *addr) {
    struct binfile *binfile;
    struct binfile_instance *bfi;
    struct binfile_instance_elf *bfielf;
    ADDR tmp;

    if (!(binfile = (struct binfile *)*userdata)) {
	verror("no binfile; bug!?\n");
	return -1;
    }

    if (!(bfi = binfile->instance)) {
	verror("no instance info for binfile %s!\n",binfile->filename);
	return -1;
    }

    if (!(bfielf = (struct binfile_instance_elf *)(bfi->priv))) {
	verror("no ELF instance info for binfile %s!\n",binfile->filename);
	return -1;
    }

    if (addr) {
	if (shndx >= bfielf->num_sections) {
	    verror("section index %d out of range (%d) in binfile instance %s!\n",
		   shndx,bfielf->num_sections,bfi->filename);
	    return -1;
	}

	tmp = ((struct binfile_instance_elf *)(bfi->priv))->section_tab[shndx];

	vdebug(8,LA_DEBUG,LF_ELF,
	       "shndx = %d addr = %"PRIxADDR" base = %x\n",
	       shndx,tmp,base);

	if (tmp == 0)
	    /*
	     * If the section was not mapped, this is how we tell
	     * elfutils.
	     */
	    *addr = (Dwarf_Addr)-1L;
	else
	    *addr = (Dwarf_Addr)tmp;
    }

    return DWARF_CB_OK;
}

/*
 * Primary debuginfo interface.  Given an ELF filename, load all its
 * debuginfo into the supplied debugfile using elfutils libs.
 */
int debugfile_load_debuginfo(struct debugfile *debugfile) {
    struct debugfile_load_opts *opts = debugfile->opts;
    struct binfile *binfile = debugfile->binfile;
    struct binfile_elf *bfelf = (struct binfile_elf *)binfile->priv;
    struct binfile_instance *bfi = binfile->instance;
    struct binfile_instance_elf *bfielf = NULL;
    void **userdata = NULL;
    Dwfl_Module *mod;

    if (bfi)
	bfielf = (struct binfile_instance_elf *)bfi->priv;

    Dwfl_Callbacks callbacks = {
	.find_debuginfo = find_no_debuginfo,
    };

    bfelf->dwfl = dwfl_begin(&callbacks);
    if (bfelf->dwfl == NULL) {
	verror("could not init libdwfl: %s\n",dwfl_errmsg(dwfl_errno()));
	return -1;
    }

    /*
     * For relocatable files that are in binfile->image, binfile->elf is
     * already open on them.  But, we can't exactly dup or clone ->image
     * (at least I'm not sure it's safe), so when dwfl_close gets
     * called, elf_end will get called too.  Catch that and set
     * bfelf->elf = NULL in those cases...
     */

    if (bfi && bfielf && binfile->image) {
	callbacks.section_address = bfi_find_section_address;
	callbacks.find_elf = bfi_find_elf;

	/*
	 * Handle via relocation; must do this specially and manually.
	 */
	dwfl_report_begin(bfelf->dwfl);
	mod = dwfl_report_module(bfelf->dwfl,bfi->filename,bfi->start,bfi->end);
	if (!mod) {
	    verror("could not report relocatable module in binfile instance %s!\n",
		   bfi->filename);
	    dwfl_end(bfelf->dwfl);
	    bfelf->dwfl = NULL;
	    bfelf->dwfl_fd = -1;
	    bfelf->elf = NULL;
	    return -1;
	}
	dwfl_module_info(mod,&userdata,NULL,NULL,NULL,NULL,NULL,NULL);
	*userdata = binfile;
    }
    else if (binfile->fd > -1) {
	callbacks.section_address = dwfl_offline_section_address;

	if (bfelf->dwfl_fd < 0) {
	    bfelf->dwfl_fd = dup(binfile->fd);
	    if (bfelf->dwfl_fd == -1) {
		verror("dup(%d): %s\n",binfile->fd,strerror(errno));
		return -1;
	    }
	}

	// XXX do we really need this?  Can't have it without libdwflP.h
	//dwfl->offline_next_address = 0;
	if (!dwfl_report_offline(bfelf->dwfl,debugfile->filename,
				 debugfile->filename,bfelf->dwfl_fd)) {
	    verror("dwfl_report_offline: %s\n",dwfl_errmsg(dwfl_errno()));
	    dwfl_end(bfelf->dwfl);
	    bfelf->dwfl = NULL;
	    bfelf->dwfl_fd = -1;
	    return -1;
	}
    }
    else {
	verror("binfile %s had no fd nor memory image!\n",binfile->filename);
	dwfl_end(bfelf->dwfl);
	bfelf->dwfl = NULL;
	bfelf->dwfl_fd = -1;
	return -1;
    }

    dwfl_report_end(bfelf->dwfl,NULL,NULL);

    /*
     * This is where the guts of the work happen -- and that stuff all
     * happens in the callback.
     */
    if (dwfl_getmodules(bfelf->dwfl,&process_dwflmod,debugfile,0) < 0) {
	verror("getting dwarf modules: %s\n",dwfl_errmsg(dwfl_errno()));
	dwfl_end(bfelf->dwfl);
	bfelf->dwfl = NULL;
	if (bfi && bfielf && binfile->image) 
	    bfelf->elf = NULL;
	return -1;
    }

    /* Don't save any of this stuff if we did a full load. */
    if (!(opts->flags & DEBUGFILE_LOAD_FLAG_PARTIALSYM
	  || opts->flags & DEBUGFILE_LOAD_FLAG_CUHEADERS
	  || opts->flags & DEBUGFILE_LOAD_FLAG_PUBNAMES)) {
	dwfl_end(bfelf->dwfl);
	bfelf->dwfl = NULL;
	if (bfi && bfielf && binfile->image) 
	    bfelf->elf = NULL;
    }

    return 0;
}




/*
* Report the open ELF file as a module.  Always consumes ELF and FD.  *
static Dwfl_Module *
process_elf (Dwfl *dwfl, const char *name, const char *file_name, int fd,
	     Elf *elf)
{
  Dwfl_Module *mod = __libdwfl_report_elf (dwfl, name, file_name, fd, elf,
					   dwfl->offline_next_address, false);
  if (mod != NULL)
    {
      * If this is an ET_EXEC file with fixed addresses, the address range
	 it consumed may or may not intersect with the arbitrary range we
	 will use for relocatable modules.  Make sure we always use a free
	 range for the offline allocations.  If this module did use
	 offline_next_address, it may have rounded it up for the module's
	 alignment requirements.  *
      if ((dwfl->offline_next_address >= mod->low_addr
	   || mod->low_addr - dwfl->offline_next_address < OFFLINE_REDZONE)
	  && dwfl->offline_next_address < mod->high_addr + OFFLINE_REDZONE)
	dwfl->offline_next_address = mod->high_addr + OFFLINE_REDZONE;

      * Don't keep the file descriptor around.  *
      if (mod->main.fd != -1 && elf_cntl (mod->main.elf, ELF_C_FDREAD) == 0)
	{
	  close (mod->main.fd);
	  mod->main.fd = -1;
	}
    }

  return mod;
}

Dwfl_Module *
libdwfl_report_offline_custom (Dwfl *dwfl, const char *name,
			       const char *file_name, int fd, bool closefd)
{
  Elf *elf;
  *
  Dwfl_Error error = __libdw_open_file (&fd, &elf, closefd, true);
  if (error != DWFL_E_NOERROR)
    {
      __libdwfl_seterrno (error);
      return NULL;
    }
  *
  Dwfl_Module *mod = process_elf (dwfl, name, file_name, fd, elf);
  if (mod == NULL)
    {
      elf_end (elf);
      if (closefd)
	close (fd);
    }
  return mod;
}
*/
