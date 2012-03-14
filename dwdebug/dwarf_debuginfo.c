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
 * Foundation, 51 Franklin St, Suite 500, Boston, MA 02110-1335, USA.
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
    int level;
    unsigned int addrsize;
    unsigned int offset_size;
    Dwarf_Off cu_offset;
    Dwarf_Off die_offset;
    Dwarf_Half version;
    Dwarf_Addr cu_base;
    bool have_stmt_list_offset;
    Dwarf_Word stmt_list_offset;

    struct debugfile *debugfile;
    struct symtab *cu_symtab;
    struct symtab *symtab;
    struct symbol *symbol;
    struct symbol *parentsymbol;
    struct symbol *voidsymbol;
    GHashTable *reftab;
    int quick;
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

    vdebug(4,LOG_D_DWARF,"\t\t[DIE %" PRIx64 "] %d %s (%s) (as=%d,os=%d)\n",
	   (int)level,cbargs->die_offset,dwarf_attr_string(attr),
	   dwarf_form_string(form),cbargs->addrsize,cbargs->offset_size);

    /* if form is a string */
    char *str = NULL;

    Dwarf_Word num;
    Dwarf_Addr addr;
    Dwarf_Block block;
    bool flag;
    SMOFFSET ref = 0;
    Dwarf_Die rref;

    uint8_t str_set = 0;
    uint8_t num_set = 0;
    uint8_t addr_set = 0;
    uint8_t flag_set = 0;
    uint8_t ref_set = 0;
    uint8_t block_set = 0;

    switch(form) {
    case DW_FORM_string:
	// XXX: do we need to strcpy this one?  It's not in our strtab...
	str = (char *)attrp->valp;
	str_set = 1;
	break;
    case DW_FORM_strp:
    case DW_FORM_indirect:
	//str = dwarf_formstring(attrp);
	//str_set = 1;
	//break;
	if (*(attrp->valp) > (debugfile->strtablen - 1)) {
	    verror("[DIE %" PRIx64 "] dwarf str at 0x%lx not in strtab for attr %s!\n",
		   cbargs->die_offset,(unsigned long int)*(attrp->valp),
		   dwarf_attr_string(attr));
	    goto errout;
	}
	// XXX relocation...
	// XXX: make sure to only use this pointer if DWDEBUG_USE_STRTAB!
	if (cbargs->offset_size == 4)
	    str = &debugfile->strtab[*((uint32_t *)attrp->valp)];
	else 
	    str = &debugfile->strtab[*((uint64_t *)attrp->valp)];
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
      attrp->form = cbargs->offset_size == 8 ? DW_FORM_data8 : DW_FORM_data4;
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
	if (unlikely(dwarf_formflag(attrp,&flag) != 0)) {
	    verror("[DIE %" PRIx64 "] could not load dwarf flag for attr %s",
		   cbargs->die_offset,dwarf_attr_string(attr));
	    goto errout;
	}
	flag_set = 1;
	break;
    default:
	vwarn("[DIE %" PRIx64 "] unrecognized form %s for attr %s\n",
	      cbargs->die_offset,dwarf_form_string(form),dwarf_attr_string(attr));
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
	vdebug(4,LOG_D_DWARF,"\t\t\tvalue = %s\n",str);
	if (level == 0) {
	    symtab_set_name(cbargs->cu_symtab,str);
	}
	else if (cbargs->symbol) {
	    symbol_set_name(cbargs->symbol,str);
	    if (cbargs->symbol->type == SYMBOL_TYPE_FUNCTION)
		symtab_set_name(cbargs->symtab,str);
	}
	else {
	    vwarn("[DIE %" PRIx64 "] attrval %s for attr %s in bad context\n",
		  cbargs->die_offset,str,dwarf_attr_string(attr));
	}
	break;
    case DW_AT_stmt_list:
	/* XXX: don't do line numbers yet. */
	if (num_set) {
	    cbargs->stmt_list_offset = num;
	    cbargs->have_stmt_list_offset = true;
	    vdebug(4,LOG_D_DWARF,"\t\t\tvalue = %d\n",num);
	}
	else {
	    vwarn("[DIE %" PRIx64 "] attr %s in bad context\n",
		  cbargs->die_offset,dwarf_attr_string(attr));
	}
	break;
    case DW_AT_producer:
	vdebug(4,LOG_D_DWARF,"\t\t\tvalue = %s\n",str);
	if (level == 0) 
	    symtab_set_producer(cbargs->cu_symtab,str);
	else 
	    vwarn("[DIE %" PRIx64 "] attrval %s for attr %s in bad context\n",
		  cbargs->die_offset,str,dwarf_attr_string(attr));
	break;
    case DW_AT_comp_dir:
	vdebug(4,LOG_D_DWARF,"\t\t\tvalue = %s\n",str);
	if (level == 0) 
	    symtab_set_compdirname(cbargs->cu_symtab,str);
	else 
	    vwarn("[DIE %" PRIx64 "] attrval %s for attr %s in bad context\n",
		  cbargs->die_offset,str,dwarf_attr_string(attr));
	break;
    case DW_AT_language:
	vdebug(4,LOG_D_DWARF,"\t\t\tvalue = %d\n",num);
	if (level == 0) 
	    cbargs->cu_symtab->language = num;
	else 
	    vwarn("[DIE %" PRIx64 "] attrval %d for attr %s in bad context\n",
		  cbargs->die_offset,(int)num,dwarf_attr_string(attr));
	break;
    case DW_AT_low_pc:
	vdebug(4,LOG_D_DWARF,"\t\t\tvalue = 0x%p\n",addr);

	/* If we see a new compilation unit, save its low pc separately
	 * for use in loclist calculations.  CUs can have both a low pc
	 * and range list, so we can't just use the symtab's range
	 * struct to hold this special low_pc.
	 */
	if (level == 0) {
	    cbargs->cu_base = addr;
	}

	/* Handle the symtab lowpc/highpc values first; function
	 * instances are part of the symtab.  Labels are not, so we do them
	 * separately below.
	 *
	 * NOTE: also, only set the symtab's low_pc/high_pc values if
	 * this is the CU symtab, OR if this is a function symtab!
	 * Other things may have a low_pc; we don't want to overwrite
	 * the current symtab's lowpc/highpc values in that case!
	 */
	if (cbargs->symtab && (SYMBOL_IS_FUNCTION(cbargs->symbol) 
			       || level == 0)) {
	    if (cbargs->symtab->range.rtype == RANGE_TYPE_NONE) {
		cbargs->symtab->range.rtype = RANGE_TYPE_PC;
		cbargs->symtab->range.r.a.lowpc = addr;
	    }
	    else if (cbargs->symtab->range.rtype == RANGE_TYPE_PC) {
		/* Already decoded it in get_aranges; just check here! */
		if (cbargs->symtab->range.r.a.lowpc != addr) {
		    vwarn("inconsistent %s (aranges?) 0x%"PRIx64" (was 0x%"PRIx64") at %"PRIx64"\n",
			  dwarf_attr_string(attr),addr,
			  cbargs->symtab->range.r.a.lowpc,cbargs->die_offset);
		}
	    }
	    else if (cbargs->symtab->range.rtype == RANGE_TYPE_LIST) {
		/*
		vwarn("inconsistent %s (aranges?) 0x%"PRIx64" (was 0x%"PRIx64") at %"PRIx64" (already was a RANGE_LIST!)\n",
		      dwarf_attr_string(attr),addr,
		      cbargs->symtab->range.r.a.lowpc,cbargs->die_offset);
		*/ ;
	    }
	}
	else if (!cbargs->symtab)
	    vwarn("[DIE %" PRIx64 "] attrval %" PRIx64 " for attr %s in bad context (symtab)\n",
		  cbargs->die_offset,addr,dwarf_attr_string(attr));

	if (cbargs->symbol && addr < cbargs->symbol->base_addr)
	    cbargs->symbol->base_addr = addr;

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
	    vwarn("[DIE %" PRIx64 "] attrval %" PRIx64 " for attr %s in bad context (symbol)\n",
		  cbargs->die_offset,addr,dwarf_attr_string(attr));
	break;
    case DW_AT_high_pc:
	if (num_set) {
	    vdebug(4,LOG_D_DWARF,"\t\t\tvalue = " PRIu64 "\n",num);

	    /* it's a relative offset from low_pc; if we haven't seen
	     * low_pc yet, just bail.
	     */

	    if (cbargs->symtab && (SYMBOL_IS_FUNCTION(cbargs->symbol) 
				   || level == 0)) {
		if (cbargs->symtab->range.rtype == RANGE_TYPE_PC) {
		    /* Might have already decoded it in get_aranges;
		     * just check here!
		     */
		    if (cbargs->symtab->range.r.a.highpc 
			&& cbargs->symtab->range.r.a.highpc != \
			     (cbargs->symtab->range.r.a.lowpc + num)) {
			vwarn("inconsistent %s (aranges?) 0x%"PRIx64" at %"PRIx64"\n",
			      dwarf_attr_string(attr),addr,cbargs->die_offset);
		    }
		    else if (cbargs->symtab->range.r.a.lowpc) {
			cbargs->symtab->range.rtype = RANGE_TYPE_PC;
			cbargs->symtab->range.r.a.highpc = cbargs->symtab->range.r.a.lowpc + num;
		    }
		    else 
			vwarn("[DIE %" PRIx64 "] attrval %" PRIu64 " (num) for attr %s in bad context (no lowpc yet)!\n",
			      cbargs->die_offset,num,dwarf_attr_string(attr));
		}
	    }

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
		    vwarn("[DIE %" PRIx64 "] attrval %" PRIu64 " (num) for attr %s in bad context (%s %s -- no lowpc yet)!\n",
			  cbargs->die_offset,num,dwarf_attr_string(attr),
			  SYMBOL_TYPE(cbargs->symbol->type),symbol_get_name_orig(cbargs->symbol));
		}
	    }
	}
	else if (addr_set) {
	    vdebug(4,LOG_D_DWARF,"\t\t\tvalue = 0x%p\n",addr);

	    if (cbargs->symtab) {
		cbargs->symtab->range.rtype = RANGE_TYPE_PC;
		cbargs->symtab->range.r.a.highpc = addr;
	    }

	    /* On the off chance that high_pc is the lowest address for
	     * this symbol, check it!
	     */
	    if (cbargs->symbol && addr < cbargs->symbol->base_addr)
		cbargs->symbol->base_addr = addr;

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
	    vwarn("[DIE %" PRIx64 "] bad attr type for attr %s\n",
		      cbargs->die_offset,dwarf_attr_string(attr));
	}
	break;
    case DW_AT_entry_pc:
	if (addr_set) {
	    vdebug(4,LOG_D_DWARF,"\t\t\tvalue = 0x%p\n",addr);

	    if (level == 0) {
		/* Don't bother recording this for CUs. */
		break;
	    }

	    if (SYMBOL_IS_FUNCTION(cbargs->symbol)) {
		if (addr < cbargs->symbol->base_addr) 
		    cbargs->symbol->base_addr = addr;

		if (SYMBOL_IS_FULL(cbargs->symbol)) {
		    cbargs->symbol->s.ii->d.f.entry_pc = addr;
		    cbargs->symbol->s.ii->d.f.hasentrypc = 1;
		}
	    }
	    else 
		vwarn("[DIE %" PRIx64 "] attrval 0x%" PRIx64 " for attr %s in bad context (symbol)\n",
		      cbargs->die_offset,addr,dwarf_attr_string(attr));
	}
	else {
	    vwarn("[DIE %" PRIx64 "] bad attr form for attr %s // form %s\n",
		  cbargs->die_offset,dwarf_attr_string(attr),
		  dwarf_form_string(form));
	}
	break;
    case DW_AT_decl_file:
	if (cbargs->symbol) {
	    ; // XXX
	}
	else 
	    vwarn("[DIE %" PRIx64 "] attrval %d for attr %s in bad context\n",
		  cbargs->die_offset,(int)num,dwarf_attr_string(attr));
	break;
    case DW_AT_decl_line:
	if (cbargs->symbol) {
	    cbargs->symbol->srcline = (int)num;
	}
	else 
	    vwarn("[DIE %" PRIx64 "] attrval %d for attr %s in bad context\n",
		  cbargs->die_offset,(int)num,dwarf_attr_string(attr));
	break;
    /* Don't bother with these yet. */
    case DW_AT_decl_column:
    case DW_AT_call_file:
    case DW_AT_call_line:
    case DW_AT_call_column:
	break;
    case DW_AT_declaration:
	/* XXX: hopefully this is mostly necessary to handle weird
	 * scoping cases, so ignore for now.
	 */
	break;
    case DW_AT_encoding:
	if (cbargs->symbol && cbargs->symbol->type == SYMBOL_TYPE_TYPE) {
	    /* our encoding_t is 1<->1 map to the DWARF encoding codes. */
	    cbargs->symbol->s.ti->d.v.encoding = (encoding_t)num;
	}
	else 
	    vwarn("[DIE %" PRIx64 "] attrval %d for attr %s in bad context\n",
		  cbargs->die_offset,(int)num,dwarf_attr_string(attr));
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
	    vwarn("[DIE %" PRIx64 "] attrval %d for attr %s in bad context\n",
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
	    vwarn("[DIE %" PRIx64 "] attrval %d for attr %s in bad context\n",
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
	    vwarn("[DIE %" PRIx64 "] attrval 0x%" PRIu64 " for attr %s in bad context\n",
		  cbargs->die_offset,num,dwarf_attr_string(attr));
	break;
    case DW_AT_abstract_origin:
	if (ref_set && SYMBOL_IS_INSTANCE(cbargs->symbol)) {
	    cbargs->symbol->isinlineinstance = 1;
	    if (SYMBOL_IS_FULL(cbargs->symbol)) {
		cbargs->symbol->s.ii->origin = (struct symbol *)	\
		    g_hash_table_lookup(cbargs->reftab,(gpointer)(OFFSET)ref);
		/* Always set the ref so we can generate a unique name for 
		 * the symbol; see finalize_die_symbol!!
		 */
		cbargs->symbol->s.ii->origin_ref = ref;
	    }
	}
	else 
	    vwarn("[DIE %" PRIx64 "] attrval %" PRIxSMOFFSET " for attr %s in bad context\n",
		  cbargs->die_offset,ref,dwarf_attr_string(attr));
	break;
    case DW_AT_type:
	if (ref_set && cbargs->symbol) {
	    struct symbol *datatype = (struct symbol *) \
		g_hash_table_lookup(cbargs->reftab,(gpointer)(OFFSET)ref);
	    if (cbargs->symbol->type == SYMBOL_TYPE_TYPE) {
		if (cbargs->symbol->datatype_code == DATATYPE_PTR
		    || cbargs->symbol->datatype_code == DATATYPE_TYPEDEF
		    || cbargs->symbol->datatype_code == DATATYPE_ARRAY
		    || cbargs->symbol->datatype_code == DATATYPE_CONST
		    || cbargs->symbol->datatype_code == DATATYPE_VOL
		    || cbargs->symbol->datatype_code == DATATYPE_FUNCTION) {
		    cbargs->symbol->datatype_ref = (uint64_t)ref;
		    if (datatype)
			cbargs->symbol->datatype = datatype;
		}
		else 
		    vwarn("[DIE %" PRIx64 "] bogus: type ref for unknown type symbol\n",
			  cbargs->die_offset);
	    }
	    else {
		cbargs->symbol->datatype_ref = ref;
		if (datatype)
		    cbargs->symbol->datatype = datatype;
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
	    vwarn("[DIE %" PRIx64 "] attrval %" PRIxSMOFFSET " for attr %s in bad context\n",
		  cbargs->die_offset,ref,dwarf_attr_string(attr));
	break;
    case DW_AT_const_value:
	if (num_set
	    && cbargs->symbol 
	    && SYMBOL_IS_VAR(cbargs->symbol)
	    && cbargs->parentsymbol
	    && SYMBOL_IS_FULL_TYPE(cbargs->parentsymbol)
	    && cbargs->parentsymbol->datatype_code == DATATYPE_ENUM
	    && cbargs->parentsymbol->s.ti->byte_size > 0) {
	    cbargs->symbol->s.ii->constval = \
		malloc(cbargs->parentsymbol->s.ti->byte_size);
	    memcpy(cbargs->symbol->s.ii->constval,&num,
		   cbargs->parentsymbol->s.ti->byte_size);
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
#ifdef DWDEBUG_USE_STRTAB
	    cbargs->symbol->s.ii->constval = str;
#else
	    int slen = strlen(str);
	    cbargs->symbol->s.ii->constval = malloc(slen+1);
	    strcpy(cbargs->symbol->s.ii->constval,str,slen+1);
#endif
	}
	else if (block_set && SYMBOL_IS_FULL_INSTANCE(cbargs->symbol)) {
	    cbargs->symbol->s.ii->constval = malloc(block.length);
	    memcpy(cbargs->symbol->s.ii->constval,block.data,block.length);
	}
	else 
	    vwarn("[DIE %" PRIx64 "] attr %s form %s in bad context\n",
		  cbargs->die_offset,dwarf_attr_string(attr),
		  dwarf_form_string(form));
	break;
    /* XXX: byte/bit sizes/offsets can technically be a reference
     * to another DIE, or an exprloc... but they should always be
     * consts for C!
     */
    case DW_AT_byte_size:
	if (num_set && SYMBOL_IS_TYPE(cbargs->symbol)) {
	    cbargs->symbol->s.ti->byte_size = num;
	}
	else if (num_set && SYMBOL_IS_VAR(cbargs->symbol)) {
	    cbargs->symbol->s.ii->d.v.byte_size = num;
	}
	else {
	    vwarn("[DIE %" PRIx64 "] unrecognized attr %s // form %s mix!\n",
		  cbargs->die_offset,dwarf_attr_string(attr),
		  dwarf_form_string(form));
	}
	break;
    case DW_AT_bit_size:
	if (num_set && SYMBOL_IS_VAR(cbargs->symbol)) {
	    cbargs->symbol->s.ii->d.v.bit_size = num;
	}
	else {
	    vwarn("[DIE %" PRIx64 "] unrecognized attr %s // form %s mix!\n",
		  cbargs->die_offset,dwarf_attr_string(attr),
		  dwarf_form_string(form));
	}
	break;
    case DW_AT_bit_offset:
	if (num_set && SYMBOL_IS_VAR(cbargs->symbol)) {
	    cbargs->symbol->s.ii->d.v.bit_offset = num;
	}
	else {
	    vwarn("[DIE %" PRIx64 "] unrecognized attr %s // form %s mix!\n",
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
		if (get_static_ops(cbargs->dwflmod,cbargs->dbg,cbargs->version,
				   cbargs->addrsize,cbargs->offset_size,
				   block.length,block.data,attr,
				   &cbargs->symbol->s.ii->l)) {
		    verror("[DIE %" PRIx64 "] failed get_static_ops at attrval %" PRIx64 " for attr %s // form %s\n",
			   cbargs->die_offset,num,dwarf_attr_string(attr),
			   dwarf_form_string(form));
		}
	    }
	    else {
		vwarn("[DIE %" PRIx64 "] no/bad symbol for attr %s // form %s\n",
		      cbargs->die_offset,dwarf_attr_string(attr),
		      dwarf_form_string(form));
	    }
	}
	else if (num_set && (form == DW_FORM_data4 
			     || form == DW_FORM_data8)) {
	    if (SYMBOL_IS_VAR(cbargs->symbol)
		&& cbargs->symbol->ismember) {
		cbargs->symbol->s.ii->l.loctype = LOCTYPE_LOCLIST;

		cbargs->symbol->s.ii->l.l.loclist = loc_list_create(0);

		if (get_loclist(cbargs->dwflmod,cbargs->dbg,cbargs->version,
				cbargs->addrsize,cbargs->offset_size,
				attr,num,cbargs->debugfile,cbargs->cu_base,
				cbargs->symbol->s.ii->l.l.loclist)) {
		    verror("[DIE %" PRIx64 "] failed get_static_ops at attrval %" PRIx64 " for attr %s // form %s\n",
			   cbargs->die_offset,num,dwarf_attr_string(attr),
			   dwarf_form_string(form));
		}
	    }
	    else {
		vwarn("[DIE %" PRIx64 "] no/bad symbol for attr %s // form %s\n",
		      cbargs->die_offset,dwarf_attr_string(attr),
		      dwarf_form_string(form));
	    }
	}
	else if (num_set
/* not sure if 137 is the right number! */
#if _INT_ELFUTILS_VERSION > 137
	    && form != DW_FORM_sec_offset
#endif
	    && (cbargs->version >= 4
		|| (form != DW_FORM_data4 
		    && form != DW_FORM_data8))) {
	    /* it's a constant */
	    if (cbargs->symbol) {
		cbargs->symbol->s.ii->l.loctype = LOCTYPE_MEMBER_OFFSET;
		cbargs->symbol->s.ii->l.l.member_offset = (int32_t)num;
	    }
	    else {
		vwarn("[DIE %" PRIx64 "] attrval %" PRIx64 " for attr %s in bad context\n",
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

		if (get_loclist(cbargs->dwflmod,cbargs->dbg,cbargs->version,
				cbargs->addrsize,cbargs->offset_size,
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
		vwarn("[DIE %" PRIx64 "] no/bad symbol for loclist for attr %s\n",
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

		if (get_static_ops(cbargs->dwflmod,cbargs->dbg,cbargs->version,
				   cbargs->addrsize,cbargs->offset_size,
				   block.length,block.data,attr,
				   cbargs->symbol->s.ii->d.f.fb.loc)) {
		    verror("[DIE %" PRIx64 "] failed to get single loc attrval %" PRIx64 " for attr %s in function symbol %s\n",
			   cbargs->die_offset,num,dwarf_attr_string(attr),
			   symbol_get_name_orig(cbargs->symbol));
		}
	    }
	    else {
		vwarn("[DIE %" PRIx64 "] no/bad symbol for single loc for attr %s\n",
		      cbargs->die_offset,dwarf_attr_string(attr));
	    }
	}
	else {
	    vwarn("[DIE %" PRIx64 "] frame_base not num/block; attr %s // form %s mix!\n",
		  cbargs->die_offset,dwarf_attr_string(attr),
		  dwarf_form_string(form));
	}
	break;
    case DW_AT_ranges:
	/* always a rangelistptr */
	if (num_set && (form == DW_FORM_data4 
			|| form == DW_FORM_data8)) {
	    if (cbargs->symtab) {
		if (cbargs->symtab->range.rtype == RANGE_TYPE_NONE
		    /* DWARF allows the symtab to have its own low_pc, as
		     * well as a range.
		     */
		    || level == 0) {
		    /* If we already had set a range list in
		     * get_aranges, just clear it and reset it here --
		     * don't bother checking for consistency!!
		     */
		    if (cbargs->symtab->range.rtype == RANGE_TYPE_LIST) {
			range_list_internal_free(&cbargs->symtab->range.r.rlist);
			memset(&cbargs->symtab->range.r.rlist,0,
			       sizeof(struct range_list));
		    }
		    else if (cbargs->symtab->range.rtype == RANGE_TYPE_PC) {
			/*
			 * Convert it to a list first, and ignore
			 * whatever was set before!
			 */
			/* ADDR olowpc = cbargs->symtab->range.r.a.lowpc; */
			/* ADDR ohighpc = cbargs->symtab->range.r.a.highpc; */

			memset(&cbargs->symtab->range.r.rlist,0,
			       sizeof(struct range_list));

			/*
			cbargs->symtab->range.rtype = RANGE_TYPE_LIST;

			range_list_add(&cbargs->symtab->range.r.rlist,olowpc,
				       ohighpc);
			*/
		    }

		    cbargs->symtab->range.rtype = RANGE_TYPE_LIST;
		    if (get_rangelist(cbargs->dwflmod,cbargs->dbg,cbargs->version,
				      cbargs->addrsize,cbargs->offset_size,
				      attr,num,
				      cbargs->debugfile,cbargs->cu_base,
				      &cbargs->symtab->range.r.rlist)) {
			verror("[DIE %" PRIx64 "] failed to get rangelist attrval %" PRIx64 " for attr %s in symtab\n",
			       cbargs->die_offset,num,dwarf_attr_string(attr));
		    }
		}
		else {
		    verror("[DIE %" PRIx64 "] cannot set symtab rangelist; already set a range!\n",cbargs->die_offset);
		}
	    }

	    if (cbargs->symbol && SYMBOL_IS_FULL_LABEL(cbargs->symbol)
		&& cbargs->symbol->s.ii->d.l.range.rtype == RANGE_TYPE_NONE) {
		if (get_rangelist(cbargs->dwflmod,cbargs->dbg,cbargs->version,
				  cbargs->addrsize,cbargs->offset_size,
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
	    vwarn("[DIE %" PRIx64 "] bad rangelist attr %s // form %s!\n",
		  cbargs->die_offset,dwarf_attr_string(attr),
		  dwarf_form_string(form));
	}
	break;
    case DW_AT_location:
	/* We only accept this for params and variables */
	if (SYMBOL_IS_VAR(cbargs->symbol)) {
	    if (num_set && (form == DW_FORM_data4 
			    || form == DW_FORM_data8)) {
		struct loc_list *loclist;
		if (SYMBOL_IS_FULL(cbargs->symbol)) {
		    cbargs->symbol->s.ii->l.loctype = LOCTYPE_LOCLIST;
		    cbargs->symbol->s.ii->l.l.loclist = loc_list_create(0);
		    loclist = cbargs->symbol->s.ii->l.l.loclist;
		}
		else {
		    loclist = loc_list_create(0);
		}

		if (get_loclist(cbargs->dwflmod,cbargs->dbg,cbargs->version,
				cbargs->addrsize,cbargs->offset_size,
				attr,num,
				cbargs->debugfile,
				cbargs->cu_base,
				loclist)) {
		    verror("[DIE %" PRIx64 "] failed to get loclist attrval %" PRIx64 " for attr %s in var symbol %s\n",
			   cbargs->die_offset,num,dwarf_attr_string(attr),
			   symbol_get_name_orig(cbargs->symbol));
		    loc_list_free(loclist);
		    if (SYMBOL_IS_FULL(cbargs->symbol)) {
			cbargs->symbol->s.ii->l.loctype = LOCTYPE_UNKNOWN;
			cbargs->symbol->s.ii->l.l.loclist = NULL;
		    }
		}

		if (SYMBOL_IS_PARTIAL(cbargs->symbol)) {
		    int i;
		    for (i = 0; i < loclist->len; ++i) {
			if (loclist->list[i]->start < cbargs->symbol->base_addr)
			    cbargs->symbol->base_addr = loclist->list[i]->start;
		    }
		}
	    }
	    else if (block_set) {
		struct location *loc;
		if (SYMBOL_IS_FULL(cbargs->symbol)) {
		    loc = &cbargs->symbol->s.ii->l;
		}
		else {
		    loc = (struct location *)malloc(sizeof(struct location));
		    memset(loc,0,sizeof(*loc));
		}
		get_static_ops(cbargs->dwflmod,cbargs->dbg,
			       cbargs->version,cbargs->addrsize,cbargs->offset_size,
			       block.length,block.data,attr,
			       loc);
		if (SYMBOL_IS_PARTIAL(cbargs->symbol)) {
		    if (loc->loctype == LOCTYPE_ADDR 
			&& loc->l.addr < cbargs->symbol->base_addr)
			cbargs->symbol->base_addr = loc->l.addr;
		    free(loc);
		}
	    }
	    else {
		vwarn("[DIE %" PRIx64 "] loclist: bad attr %s // form %s!\n",
		      cbargs->die_offset,dwarf_attr_string(attr),
		      dwarf_form_string(form));
	    }
	}
	else {
	    vwarn("[DIE %" PRIx64 "] bad attr %s // form %s!\n",
		  cbargs->die_offset,dwarf_attr_string(attr),
		  dwarf_form_string(form));
	}
	break;
    case DW_AT_lower_bound:
	if (num_set && num) {
	    vwarn("[DIE %" PRIx64 "] we only support lower_bound attrs of 0 (%" PRIu64 ")!\n",
		  cbargs->die_offset,num);
	}
	else {
	    vwarn("[DIE %" PRIx64 "] unsupported attr %s // form %s!\n",
		  cbargs->die_offset,dwarf_attr_string(attr),
		  dwarf_form_string(form));
	}
	break;
    case DW_AT_count:
	vwarn("[DIE %" PRIx64 "] interpreting AT_count as AT_upper_bound!\n",
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
		vwarn("[DIE %" PRIx64 "] attrval %" PRIx64 " for attr %s in bad context\n",
		      cbargs->die_offset,num,dwarf_attr_string(attr));
	    }
	    break;
	}
	else {
	    vwarn("[DIE %" PRIx64 "] unsupported attr %s // form %s!\n",
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
	vwarn("[DIE %" PRIx64 "] unrecognized attr %s (%d)\n",
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

    vdebug(5,LOG_D_DWARF,"starting (rangetab len %d, offset %d)\n",
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
	    vdebug(5,LOG_D_DWARF,"[%6tx] base address 0x%" PRIxADDR "\n",
		   loffset,end);
	    have_base = 1;
	    base = end;
	}
	else if (begin == 0 && end == 0) {
	    /* End of list entry.  */
	    if (len == 0)
		vwarn("[%6tx] empty list\n",loffset);
	    else 
		vdebug(5,LOG_D_DWARF,"[%6tx] end of list\n");
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

    vdebug(5,LOG_D_DWARF,"starting (loctab len %d, offset %d)\n",
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
	    vdebug(5,LOG_D_DWARF,"[%6tx] base address 0x%" PRIxADDR "\n",
		   loffset,end);
	    have_base = 1;
	    base = end;
	}
	else if (begin == 0 && end == 0) {
	    /* End of list entry.  */
	    if (len == 0)
		vwarn("[%6tx] empty list\n",loffset);
	    else 
		vdebug(5,LOG_D_DWARF,"[%6tx] end of list\n");
	    break;
	}
	else {
	    ++len;

	    /* We have a location expression entry.  */
	    exprlen = read_2ubyte_unaligned_inc(obo,readp);

	    vdebug(5,LOG_D_DWARF,"[%6tx] loc expr range 0x%" PRIxADDR ",0x%" PRIxADDR ", len %hd\n",
		   loffset,begin,end,exprlen);

	    if (endp - readp <= (ptrdiff_t) exprlen) {
		verror("[%6tx] invalid exprlen (%hd) in entry\n",loffset,exprlen);
		break;
	    }
	    else {
		vdebug(5,LOG_D_DWARF,"[%6tx] loc expr len (%hd) in entry\n",
		       loffset,exprlen);
	    }

	    tmploc = location_create();

	    if (get_static_ops(dwflmod,dbg,3,addrsize,offsetsize,
			       exprlen,(unsigned char *)readp,attr,
			       tmploc)) {
		verror("get_static_ops (%d) failed!\n",exprlen);
		location_free(tmploc);
		return -1;
	    }
	    else {
		vdebug(5,LOG_D_DWARF,"get_static_ops (%d) succeeded!\n",exprlen);
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
	vwarn("unsupported %s op with other ops!\n",known[op]); \
    }

#define OPCONSTU(size,tt)			\
    NEED(size);						\
    u64 = (uint64_t)*((tt *)data);			\
    data += size;					\
    CONSUME(size);					\
    vdebug(6,LOG_D_DWARF,"%s -> 0x%" PRIuMAX "\n",known[op],u64);	\
    if (attr == DW_AT_data_member_location) {		\
	ONLYOP(retval,LOCTYPE_MEMBER_OFFSET,		\
	       member_offset,(int32_t)u64);		\
    }							\
    else {					       	\
	vwarn("assuming constXu is for loctype_addr!\n");	\
	ONLYOP(retval,LOCTYPE_ADDR,addr,u64);		\
    }

#define OPCONSTS(size,tt)			\
    NEED(size);						\
    s64 = (int64_t)*((tt *)data);			\
    data += size;					\
    CONSUME(size);					\
    vdebug(6,LOG_D_DWARF,"%s -> 0x%" PRIxMAX "\n",known[op],s64);	\
    if (attr == DW_AT_data_member_location) {		\
	ONLYOP(retval,LOCTYPE_MEMBER_OFFSET,		\
	       member_offset,(int32_t)s64);		\
    }							\
    else {					       	\
	vwarn("assuming constXs is for loctype_addr!\n");	\
	ONLYOP(retval,LOCTYPE_ADDR,addr,(uint64_t)s64);		\
    }

    while (len-- > 0) {
	uint_fast8_t op = *data++;
	const unsigned char *start = data;

	vdebug(6,LOG_D_DWARF,"%s with len = %d\n",known[op],len);

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
	    vdebug(6,LOG_D_DWARF,"%s -> 0x%" PRIx64 "\n",known[op],addr);
	    if (start == (origdata + 1) && len == 0) {
		retval->loctype = LOCTYPE_ADDR;
		retval->l.addr = addr;
		goto out;
	    }
	    else {
		vwarn("unsupported %s op with other ops!\n",known[op]);
	    }
	    //ONLYOP(retval,LOCTYPE_ADDR,addr,((uint64_t)addr));
	    break;

	case DW_OP_reg0...DW_OP_reg31:
	    reg = op - (uint8_t)DW_OP_reg0;

	    vdebug(6,LOG_D_DWARF,"%s -> 0x%" PRIu8 "\n",known[op],reg);
	    ONLYOP(retval,LOCTYPE_REG,reg,reg);
	    break;
	//case DW_OP_piece:
	case DW_OP_regx:
	    NEED(1);
	    get_uleb128(u64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LOG_D_DWARF,"%s -> 0x%" PRIuMAX "\n",known[op],u64);
	    ONLYOP(retval,LOCTYPE_REG,reg,(uint8_t)u64);
	    break;

	case DW_OP_plus_uconst:
	case DW_OP_constu:
	    NEED(1);
	    get_uleb128(u64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LOG_D_DWARF,"%s -> 0x%" PRIuMAX "\n",known[op],u64);
	    if (attr == DW_AT_data_member_location) {
		ONLYOP(retval,LOCTYPE_MEMBER_OFFSET,
		       member_offset,(int32_t)u64);
	    }
	    else {
		vwarn("assuming uconst/constu is for loctype_addr!\n");
		ONLYOP(retval,LOCTYPE_ADDR,
		       addr,(uint64_t)u64);
	    }
	    break;
	case DW_OP_consts:
	    NEED(1);
	    get_sleb128(s64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LOG_D_DWARF,"%s -> 0x%" PRIxMAX "\n",known[op],s64);
	    if (attr == DW_AT_data_member_location) {
		ONLYOP(retval,LOCTYPE_MEMBER_OFFSET,
		       member_offset,(int32_t)s64);
	    }
	    else {
		vwarn("assuming consts is for loctype_addr!\n");
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
	  vdebug(6,LOG_D_DWARF,"%s -> fbreg offset %ld\n",known[op],s64);
	  ONLYOP(retval,LOCTYPE_FBREG_OFFSET,fboffset,s64);
	  break;
	case DW_OP_breg0 ... DW_OP_breg31:
	    NEED(1);
	    get_sleb128(s64,data); /* XXX check overrun */
	    CONSUME(data - start);
	    vdebug(6,LOG_D_DWARF,"%s -> reg (%d) offset %ld\n",known[op],
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
	    vdebug(6,LOG_D_DWARF,"%s -> reg%" PRId8 ", offset %ld\n",known[op],
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

    vwarn("had to save dwarf ops for runtime!\n");
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
int finalize_die_symbol(struct debugfile *debugfile,int level,
			Dwarf_Off die_offset,
			struct symbol *symbol,
			struct symbol *parentsymbol,
			struct symbol *voidsymbol);
void resolve_refs(gpointer key,gpointer value,gpointer data);

struct symbol *add_void_symbol(struct debugfile *debugfile,
			       struct symtab *symtab) {
    /* symbol_create dups the name, so we just pass a static buf */
    struct symbol *symbol = symbol_create(symtab,0,"void",
					  SYMBOL_TYPE_TYPE,1);
    symbol->datatype_code = DATATYPE_VOID;

    /* Always put it in its primary symtab, of course -- probably the CU's. */
    symtab_insert(symbol->symtab,symbol,0);

    /* And also always put it in the debugfile's global types table. */
    debugfile_add_type(debugfile,symbol);

    return symbol;
}

/*
 * Traverses the debuginfo section by hopping around as needed, with a
 * post-pass to resolve accumulated references.  We start with an
 * initial g
 */
static int debuginfo_unordered_traversal(struct debugfile *debugfile,
					 GHashTable *names_to_cu_offsets,
					 regex_t **srcfile_regex_list,
					 regex_t **symbol_regex_list,
					 int quick,
					 Dwfl_Module *dwflmod,Dwarf *dbg) {
    return -1;
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
 */
static int debuginfo_ordered_traversal(struct debugfile *debugfile,
				       struct debugfile_load_opts *opts,
				       Dwfl_Module *dwflmod,Dwarf *dbg) {
    int rc;
    int retval = 0;

    vdebug(1,LOG_D_DWARF,"starting on %s \n",debugfile->filename);

    int maxdies = 8;
    int level;
    Dwarf_Die *dies = (Dwarf_Die *)malloc(maxdies*sizeof(Dwarf_Die));
    Dwarf_Off offset = 0;

    /* New compilation unit.  */
    size_t cuhl;
    Dwarf_Off abbroffset;
    uint8_t addrsize;
    uint8_t offsize;
    Dwarf_Off nextcu;
    Dwarf_Half version;

    struct symtab *cu_symtab;
    struct symbol **symbols = (struct symbol **)malloc(maxdies*sizeof(struct symbol *));
    struct symtab **symtabs = (struct symtab **)malloc(maxdies*sizeof(struct symtab *));

    GHashTable *reftab = g_hash_table_new(g_direct_hash,g_direct_equal);
    struct symbol *voidsymbol;
    GHashTableIter iter;
    struct symbol *rsymbol;

    int quick = 0;

    if (opts && opts->quick)
	quick = 1;

 next_cu:
#if defined(LIBDW_HAVE_NEXT_UNIT) && LIBDW_HAVE_NEXT_UNIT == 1
    if ((rc = dwarf_next_unit(dbg,offset,&nextcu,&cuhl,&version,
			      &abbroffset,&addrsize,&offsize,NULL,NULL)) < 0) {
	verror("dwarf_next_unit: %s (%d)\n",dwarf_errmsg(dwarf_errno()),rc);
	goto errout;
    }
    else if (rc > 0) {
	vdebug(2,LOG_D_DWARF,
	       "dwarf_next_unit returned (%d), aborting successfully.\n",rc);
	goto out;
    }
#else
    if ((rc = dwarf_nextcu(dbg,offset,&nextcu,&cuhl,
			   &abbroffset,&addrsize,&offsize)) < 0) {
	verror("dwarf_nextcu: %s (%d)\n",dwarf_errmsg(dwarf_errno()),rc);
	goto errout;
    }
    else if (rc > 0) {
	vdebug(2,LOG_D_DWARF,
	       "dwarf_nextcu returned (%d), aborting successfully.\n",rc);
	goto out;
    }

    vwarn("assuming DWARF version 4; old elfutils!\n");
    version = 4;
#endif

    /*
     * Clean up our refs table; it contains per-CU offsets
     * that map to types and sources of inlined functions/variables
     * we've built symbols for.  We need this in case one type/inlined instance
     * symbol references a type that has not yet appeared in the debug info.
     */
    g_hash_table_remove_all(reftab);

    /* attr_callback has to fill this, and *MUST* fill at least
     * name; otherwise we can't add the symtab to our hash table.
     */
    if (!(cu_symtab = (struct symtab *)\
	  g_hash_table_lookup(debugfile->cuoffsets,(gpointer)offset))) {
	cu_symtab = symtab_create(debugfile,offset,NULL,NULL,0,NULL);
	g_hash_table_insert(debugfile->cuoffsets,(gpointer)offset,
			    (gpointer)cu_symtab);
    }
    else {
	vdebug(5,LOG_D_DWARF,"using existing CU symtab!\n");
    }
    /*
     * XXX: what if we are using a CU symtab created in get_aranges or
     * get_pubnames, and we don't end up hashing the symtab in
     * debugfiles->srcfiles because it doesn't have a name?  What about
     * symtabs from aranges or pubnames that aren't in debuginfo?  Those
     * will be leaked.  Ack, don't worry about it for now; that would be
     * a DWARF bug :).
     */
    int cu_symtab_added = 0;

    symtabs[0] = cu_symtab;

    /* Add the void symbol, always. */
    voidsymbol = add_void_symbol(debugfile,cu_symtab);

    struct attrcb_args args = {
	.dwflmod = dwflmod,
	.dbg = dbg,
	.addrsize = addrsize,
	.offset_size = offsize,
	.cu_offset = offset,
	.version = version,
	.cu_base = version,
	.have_stmt_list_offset = 0,

	.debugfile = debugfile,
	.cu_symtab = cu_symtab,
	.symtab = cu_symtab,
	.symbol = NULL,
	.parentsymbol = NULL,
	.voidsymbol = voidsymbol,
	.reftab = reftab,
	.quick = quick,
    };

    offset += cuhl;
    level = 0;

    if (dwarf_offdie(dbg,offset,&dies[level]) == NULL) {
	verror("cannot get DIE at offset %" PRIx64 ": %s\n",
	       offset,dwarf_errmsg(-1));
	goto errout;
    }

    do {
	struct symtab *newscope = NULL;

	offset = dwarf_dieoffset(&dies[level]);
	if (offset == ~0ul) {
	    verror("cannot get DIE offset: %s",dwarf_errmsg(-1));
	    goto errout;
	}

	int tag = dwarf_tag(&dies[level]);
	if (tag == DW_TAG_invalid) {
	    verror("cannot get tag of DIE at offset %" PRIx64 ": %s\n",
		   offset,dwarf_errmsg(-1));
	    goto errout;
	}

	vdebug(4,LOG_D_DWARF," [%6Lx] %d %s\n",(uint64_t)offset,(int)level,
	       dwarf_tag_string(tag));

	/* Figure out what type of symbol (or symtab?) to create! */
	if (tag == DW_TAG_variable
	    || tag == DW_TAG_formal_parameter
	    || tag == DW_TAG_member
	    || tag == DW_TAG_enumerator) {
	    symbols[level] = symbol_create(symtabs[level],offset,NULL,
					   SYMBOL_TYPE_VAR,!quick);
	    if (tag == DW_TAG_formal_parameter) {
		symbols[level]->isparam = 1;
	    }
	    if (tag == DW_TAG_member) {
		symbols[level]->ismember = 1;
	    }
	    if (tag == DW_TAG_enumerator) {
		symbols[level]->isenumval = 1;
	    }
	}
	else if (tag == DW_TAG_label) {
	    symbols[level] = symbol_create(symtabs[level],offset,NULL,
					   SYMBOL_TYPE_LABEL,!quick);
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
	    symbols[level] = symbol_create(symtabs[level],offset,
					   NULL,SYMBOL_TYPE_TYPE,!quick);
	    switch (tag) {
	    case DW_TAG_base_type:
		symbols[level]->datatype_code = DATATYPE_BASE; break;
	    case DW_TAG_typedef:
		symbols[level]->datatype_code = DATATYPE_TYPEDEF; break;
	    case DW_TAG_pointer_type:
		symbols[level]->datatype_code = DATATYPE_PTR; break;
	    case DW_TAG_array_type:
		symbols[level]->datatype_code = DATATYPE_ARRAY;
		if (!quick) {
		    symbols[level]->s.ti->d.a.subranges = malloc(sizeof(int)*4);
		    symbols[level]->s.ti->d.a.count = 0;
		    symbols[level]->s.ti->d.a.alloc = 4;
		}
		break;
	    case DW_TAG_structure_type:
		symbols[level]->datatype_code = DATATYPE_STRUCT;
		if (!quick) 
		    INIT_LIST_HEAD(&(symbols[level]->s.ti->d.su.members));
		break;
	    case DW_TAG_enumeration_type:
		symbols[level]->datatype_code = DATATYPE_ENUM; 
		if (!quick) 
		    INIT_LIST_HEAD(&(symbols[level]->s.ti->d.e.members));
		break;
	    case DW_TAG_union_type:
		symbols[level]->datatype_code = DATATYPE_UNION;
		if (!quick) 
		    INIT_LIST_HEAD(&(symbols[level]->s.ti->d.su.members));
		break;
	    case DW_TAG_const_type:
		symbols[level]->datatype_code = DATATYPE_CONST; break;
	    case DW_TAG_volatile_type:
		symbols[level]->datatype_code = DATATYPE_VOL; break;
	    case DW_TAG_subroutine_type:
		symbols[level]->datatype_code = DATATYPE_FUNCTION;
		if (!quick) 
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
	    symbols[level] = symbol_create(symtabs[level],offset,NULL,
					   SYMBOL_TYPE_FUNCTION,!quick);
	    /* Build a new symtab and use it until we finish this
	     * subprogram, or until we need another child scope.
	     */
	    newscope = symtab_create(debugfile,offset,NULL,NULL,0,NULL);
	    newscope->parent = symtabs[level];
	    // XXX: should we wait to do this until we level up after
	    // successfully completing this new child scope?
	    list_add_tail(&newscope->member,&symtabs[level]->subtabs);

	    if (!quick) {
		symbols[level]->s.ii->d.f.symtab = newscope;
		INIT_LIST_HEAD(&(symbols[level]->s.ii->d.f.args));
	    }
	}
	else if (tag == DW_TAG_inlined_subroutine) {
	    symbols[level] = symbol_create(symtabs[level],offset,
					   NULL,SYMBOL_TYPE_FUNCTION,!quick);
	    /* Build a new symtab and use it until we finish this
	     * subprogram, or until we need another child scope.
	     */
	    newscope = symtab_create(debugfile,offset,NULL,NULL,0,NULL);
	    newscope->parent = symtabs[level];
	    // XXX: should we wait to do this until we level up after
	    // successfully completing this new child scope?
	    list_add_tail(&newscope->member,&symtabs[level]->subtabs);

	    symbols[level]->isinlineinstance = 1;

	    if (!quick) {
		symbols[level]->s.ii->d.f.symtab = newscope;
		INIT_LIST_HEAD(&(symbols[level]->s.ii->d.f.args));
	    }
	}
	else if (tag == DW_TAG_lexical_block) {
	    /* Build a new symtab and use it until we finish this
	     * block, or until we need another child scope.
	     */
	    newscope = symtab_create(debugfile,offset,NULL,NULL,0,NULL);
	    newscope->parent = symtabs[level];
	    // XXX: should we wait to do this until we level up after
	    // successfully completing this new child scope?
	    list_add_tail(&newscope->member,&symtabs[level]->subtabs);
	}
	else {
	    if (tag != DW_TAG_compile_unit)
		vwarn("unknown dwarf tag %s!\n",dwarf_tag_string(tag));
	    symbols[level] = NULL;
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
	else 
	    args.symtab = symtabs[level];

	args.die_offset = offset;
	(void)dwarf_getattrs(&dies[level],attr_callback,&args,0);

	/* The first time we are not level 0 (i.e., at the CU's DIE),
	 * check that we found a src filename attr; we must have it to
	 * hash the symtab.
	 */
	if (unlikely(!cu_symtab_added) && level == 0) {
	    if (!symtab_get_name(cu_symtab)) {
		verror("CU did not have a src filename; aborting processing!\n");
		symtab_free(cu_symtab);
		goto nextcuiter;
	    }
	    else {
		if (debugfile_add_symtab(debugfile,cu_symtab)) {
		    verror("could not add CU symtab %s to debugfile; aborting processing!\n",
			   symtab_get_name(cu_symtab));
		    symtab_free(cu_symtab);
		    goto nextcuiter;
		}
		cu_symtab_added = 1;
	    }

	    /*
	     * If we have regexes for symtabs and this one doesn't
	     * match, skip it!
	     */
	    if (opts && opts->srcfile_regex_list) {
		regex_t **rp = opts->srcfile_regex_list;
		int match = 0;
		while (*rp) {
		    if (regexec(*rp,symtab_get_name(cu_symtab),0,NULL,0) == 0) {
			match = 1;
			break;
		    }
		    ++rp;
		}
		if (!match) {
		    vdebug(3,LOG_D_DWARF,"skipping CU '%s'\n",symtab_get_name(cu_symtab));
		    goto nextcuiter;
		}
	    }
	}

	/* Make room for the next level's DIE.  */
	if (level + 1 == maxdies) {
	    dies = (Dwarf_Die *)realloc(dies,(maxdies += 8)*sizeof(Dwarf_Die));
	    symbols = (struct symbol **)realloc(symbols,maxdies*sizeof(struct symbol *));
	    symtabs = (struct symtab **)realloc(symtabs,maxdies*sizeof(struct symtab *));
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
		    vwarn("anonymous symbol of type %s at DIE 0x%" PRIx64 "!\n",
			  SYMBOL_TYPE(symbols[level]->type),offset);
	}

	/*
	 * Add to this CU's reference offset table.  We originally only
	 * did this for types, but since inlined func/param instances
	 * can refer to funcs/vars, we have to do it for every symbol.
	 */
	g_hash_table_insert(reftab,(gpointer)(OFFSET)offset,symbols[level]);

	/* Handle adding child symbols to parents!
	 *
	 * Only do this if we're doing a full symbol load.  The reason
	 * we don't need to check if the parents are full symbols is
	 * because we can never load a child symbol unless we fully load
	 * a parent, in which case we also fully load the child.
	 */
	if (!quick && level > 1 && symbols[level-1]) {
	    if (tag == DW_TAG_member) {
		symbols[level]->s.ii->d.v.member_symbol = symbols[level];
		list_add_tail(&(symbols[level]->s.ii->d.v.member),
			      &(symbols[level-1]->s.ti->d.su.members));
		++(symbols[level-1]->s.ti->d.su.count);
	    }
	    else if (tag == DW_TAG_formal_parameter) {
		if (symbols[level-1]->type == SYMBOL_TYPE_FUNCTION) {
		    symbols[level]->s.ii->d.v.member_symbol = symbols[level];
		    list_add_tail(&(symbols[level]->s.ii->d.v.member),
				  &(symbols[level-1]->s.ii->d.f.args));
		    ++(symbols[level-1]->s.ii->d.f.count);
		}
		else if (symbols[level-1]->type == SYMBOL_TYPE_TYPE
			 && symbols[level-1]->datatype_code == DATATYPE_FUNCTION) {
		    symbols[level]->s.ii->d.v.member_symbol = symbols[level];
		    list_add_tail(&(symbols[level]->s.ii->d.v.member),
				  &(symbols[level-1]->s.ti->d.f.args));
		    ++(symbols[level-1]->s.ti->d.f.count);
		}
	    }
	    else if (tag == DW_TAG_enumerator) {
		if (symbols[level-1]->type == SYMBOL_TYPE_TYPE 
		    && symbols[level-1]->datatype_code == DATATYPE_ENUM) {
		    symbols[level]->s.ii->d.v.member_symbol = symbols[level];
		    symbols[level]->datatype = symbols[level-1];
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

	int res = dwarf_child(&dies[level],&dies[level + 1]);
	if (res > 0) {
	do_sibling:
	    /* No new child, but possibly a new sibling, so finalize the
	     * current sibling if it exists!
	     */
	    if (symbols[level]) {
		finalize_die_symbol(debugfile,level,offset,symbols[level],
				    symbols[level-1],voidsymbol);
		symbols[level] = NULL;
		//symtabs[level] = NULL;
	    }

	    while ((res = dwarf_siblingof(&dies[level],&dies[level])) == 1) {

		if (level-- == 0)
		    break;

		/* Now that a DIE's children have all been parsed, and
		 * we're leveling up, finalize the "parent" DIE's symbol.
		 */
		if (symbols[level]) {
		    finalize_die_symbol(debugfile,level,offset,symbols[level],
					symbols[level-1],voidsymbol);
		    symbols[level] = NULL;
		    /*if (symbols[level-1] 
			&& symbols[level-1]->type == SYMBOL_TYPE_FUNCTION 
			&& symtab->parent)
			symtab = symtab->parent;*/
		    //symtabs[level] = NULL;
		}
	    }

	    if (res == -1) {
		verror("cannot get next DIE: %s\n",dwarf_errmsg(-1));
		goto errout;
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
	    if (!quick || level < 1) {
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
     */

    g_hash_table_iter_init(&iter,reftab);
    while (g_hash_table_iter_next(&iter,
				  (gpointer)&offset,(gpointer)&rsymbol)) {
	if (!rsymbol)
	    continue;

	if (!rsymbol->datatype
	    && rsymbol->datatype_ref) {
	    rsymbol->datatype = (struct symbol *) \
		g_hash_table_lookup(reftab,
				    (gpointer)(OFFSET)rsymbol->datatype_ref);
	}

	if (SYMBOL_IS_FULL_INSTANCE(rsymbol)
	    && rsymbol->isinlineinstance
	    && !rsymbol->s.ii->origin && rsymbol->s.ii->origin_ref) {
	    rsymbol->s.ii->origin = (struct symbol *) \
		g_hash_table_lookup(reftab,
				    (gpointer)(OFFSET)rsymbol->s.ii->origin_ref);
	}
    }

    /* Try to find prologue info from line table for this CU. */
    if (args.have_stmt_list_offset) {
	get_lines(debugfile,args.stmt_list_offset,addrsize);
    }
    else {
	vwarn("not doing offset %lx\n",args.stmt_list_offset);
    }

 nextcuiter:
    offset = nextcu;
    if (offset != 0) {
	goto next_cu;
    }

    goto out;

 errout:
    if (dies)
	free(dies);
    g_hash_table_destroy(reftab);
    free(symbols);
    free(symtabs);
    return -1;
 out:
    if (dies)
	free(dies);
    g_hash_table_destroy(reftab);
    free(symbols);
    free(symtabs);
    return retval;
}

/*
 * Returns 0 if the symbol was successfully inserted into symbol tables, 
 * and 1 if not (which may not be an error).
 */
int finalize_die_symbol(struct debugfile *debugfile,int level,
			Dwarf_Off die_offset,
			struct symbol *symbol,
			struct symbol *parentsymbol,
			struct symbol *voidsymbol) {
    int retval = 0;
    int *new_subranges;

    if (!symbol) {
	vwarn("[DIE %" PRIx64 "] null symbol!\n",die_offset);
	return -1;
    }

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
	    vdebug(3,LOG_D_DWARF,
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
		    vwarn("harmless subrange realloc failure: %s\n",
			   strerror(errno));
		else 
		    symbol->s.ti->d.a.subranges = new_subranges;
	    }
	}
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
		    vwarn("assuming function %s entry is lowest address in list 0x%"PRIxADDR"!\n",
			  symbol_get_name_orig(symbol),fminaddr);
		}
		else if (!symbol->s.ii->isinlined) {
		    vwarn("function %s range is not PC/list!\n",symbol_get_name_orig(symbol));
		}
	    }
	}

	if (fminaddr != 0) {
	    g_hash_table_insert(debugfile->addresses,(gpointer)fminaddr,symbol);
	    vdebug(4,LOG_D_DWARF,
		   "inserted function %s with minaddr 0x%"PRIxADDR" into debugfile addresses table\n",
		   symbol_get_name_orig(symbol),fminaddr);
	}
    }

    /*
     * Actually do the symtab inserts and generate names for symbols if
     * we need to.
     */

    if (SYMBOL_IS_TYPE(symbol)) {
	/* If it doesn't have a type, make it void. */
	if (symbol->datatype == NULL
	    && symbol->datatype_ref == 0) {
	    //&& symbol->datatype_code == DATATYPE_PTR) {
	    vdebug(3,LOG_D_DWARF,
		   "[DIE %" PRIx64 "] assuming anon %s type %s without type is void\n",
		   die_offset,DATATYPE(symbol->datatype_code),
		   symbol_get_name_orig(symbol));
	    symbol->datatype = voidsymbol;
	}

	if (!symbol_get_name_orig(symbol)) {
	    symtab_insert(symbol->symtab,symbol,die_offset);

	    /* We inserted it, but into the anon table, not the primary
	     * table!  Don't give anonymous symbols names.
	     */
	    retval = 1;
	}
	else if (SYMBOL_IST_STUN(symbol) || SYMBOL_IST_ENUM(symbol)) {
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
	    char *insertname;
	    symbol_build_extname(symbol);
	    insertname = symbol_get_name(symbol);

	    if (symtab_insert_fakename(symbol->symtab,insertname,symbol,0)) {
		/* The symbol already was in this symtab's primary
		 * table; put it in the anontable so it can get freed
		 * later!
		 */
		vwarn("duplicate symbol %s at offset %"PRIx64"\n",
		      insertname,die_offset);
		if (symtab_insert_fakename(symbol->symtab,insertname,symbol,
					   die_offset)) {
		    verror("could not insert duplicate symbol %s at offset %"PRIx64" into anontab!\n",
			   insertname,die_offset);
		}
	    }

	    if (!debugfile_find_type(debugfile,insertname))
		debugfile_add_type_fakename(debugfile,insertname,symbol);
	}
	else {
	    if (symtab_insert(symbol->symtab,symbol,0)) {
		/* The symbol already was in this symtab's primary
		 * table; put it in the anontable so it can get freed
		 * later!
		 */
		vwarn("duplicate symbol %s at offset %"PRIx64"\n",
		      symbol_get_name_orig(symbol),die_offset);
		if (symtab_insert(symbol->symtab,symbol,die_offset)) {
		    verror("could not insert duplicate symbol %s at offset %"PRIx64" into anontab!\n",
			   symbol_get_name_orig(symbol),die_offset);
		}
	    }

	    if (!debugfile_find_type(debugfile,symbol_get_name_orig(symbol)))
		debugfile_add_type(debugfile,symbol);
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
		vdebug(3,LOG_D_DWARF,
		       "[DIE %" PRIx64 "] assuming function %s without type is void\n",
		       die_offset,symbol_get_name_orig(symbol));
		symbol->datatype = voidsymbol;
	    }

	    if (symtab_insert(symbol->symtab,symbol,0)) {
		/* The symbol already was in this symtab's primary
		 * table; put it in the anontable so it can get freed
		 * later!
		 */
		vwarn("duplicate symbol %s at offset %"PRIx64"\n",
		      symbol_get_name_orig(symbol),die_offset);
		if (symtab_insert(symbol->symtab,symbol,die_offset)) {
		    verror("could not insert duplicate symbol %s at offset %"PRIx64" into anontab!\n",
			   symbol_get_name_orig(symbol),die_offset);
		}
	    }

	    if (symbol->isexternal) 
		debugfile_add_global(debugfile,symbol);
	}
	else if (symbol->type == SYMBOL_TYPE_VAR) {
	    if (symbol->datatype == NULL
		&& symbol->datatype_ref == 0) {
		vdebug(3,LOG_D_DWARF,
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
		    vwarn("duplicate symbol %s at offset %"PRIx64"\n",
		    	  symbol_get_name_orig(symbol),die_offset);
		    if (symtab_insert(symbol->symtab,symbol,die_offset)) {
			verror("could not insert duplicate symbol %s at offset %"PRIx64" into anontab!\n",
			       symbol_get_name_orig(symbol),die_offset);
		    }
		}
	    }

	    if (symbol->isexternal) 
		debugfile_add_global(debugfile,symbol);
	}
	else if (symbol->type == SYMBOL_TYPE_LABEL) {
	    if (symtab_insert(symbol->symtab,symbol,0)) {
		/* The symbol already was in this symtab's primary
		 * table; put it in the anontable so it can get freed
		 * later!
		 */
		vwarn("duplicate symbol %s at offset %"PRIx64"\n",
		      symbol_get_name_orig(symbol),die_offset);
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
	if (SYMBOL_IS_FULL(symbol)) {
	    char *inname;
	    int inlen;
	    if (symbol->s.ii->origin) {
		inlen = 9 + 1 + 18 + 1 + strlen(symbol_get_name_orig(symbol->s.ii->origin)) + 1 + 1;
		inname = malloc(sizeof(char)*inlen);
		sprintf(inname,"__INLINED(%p:%s)",
			(void *)symbol,
			symbol_get_name_orig(symbol->s.ii->origin));
	    }
	    else {
		inlen = 9 + 1 + 18 + 1 + 4 + 16 + 1 + 1;
		inname = malloc(sizeof(char)*inlen);
		sprintf(inname,"__INLINED(%p:iref%"PRIxSMOFFSET")",
			(void *)symbol,
			symbol->s.ii->origin_ref);
	    }

	    symbol_set_name(symbol,inname);
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
	verror("non-anonymous symbol of type %s without a name at %"PRIx64"!\n",
	       SYMBOL_TYPE(symbol->type),die_offset);
	struct dump_info udn = {
	    .stream = stderr,
	    .prefix = "  ",
	    .detail = 1,
	    .meta = 1
	};
	symbol_var_dump(symbol,&udn);
	fprintf(stderr,"\n");
	symbol_free(symbol);
	retval = 1;
    }

    vdebug(5,LOG_D_SYMBOL,"finalized symbol at %lx %s//%s \n",
	   die_offset,SYMBOL_TYPE(symbol->type),symbol_get_name_orig(symbol));

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
					(gpointer)(OFFSET)symbol->datatype_ref);
		if (!symbol->datatype) 
		    verror("could not resolve ref %"PRIxSMOFFSET" for %s type symbol %s\n",
			   symbol->datatype_ref,
			   DATATYPE(symbol->datatype_code),
			   symbol_get_name(symbol));
		else {
		    vdebug(3,LOG_D_DWARF,
			   "resolved ref 0x%"PRIxSMOFFSET" %s type symbol %s\n",
			   symbol->datatype_ref,
			   DATATYPE(symbol->datatype_code),symbol_get_name(symbol));

		    vdebug(3,LOG_D_DWARF,
			   "rresolving just-resolved %s type symbol %s\n",
			   SYMBOL_TYPE(symbol->datatype->datatype_code),
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
		vdebug(3,LOG_D_DWARF,
		       "rresolving known %s type symbol %s ref 0x%"PRIxSMOFFSET"\n",
		       SYMBOL_TYPE(symbol->datatype->datatype_code),
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
		    vdebug(3,LOG_D_DWARF,
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
		vdebug(3,LOG_D_DWARF,
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
				      (gpointer)(OFFSET)symbol->datatype_ref)))
		verror("could not resolve ref %"PRIxSMOFFSET" for var/func symbol %s\n",
		       symbol->datatype_ref,symbol_get_name(symbol));
	    else {
		vdebug(3,LOG_D_DWARF,
		       "resolved ref %"PRIxSMOFFSET" non-type symbol %s\n",
		       symbol->datatype_ref,symbol_get_name(symbol));
	    }
	}

	/* Always recurse in case there are anon symbols down the chain
	 * that need resolution.
	 */
	if (symbol->datatype) {
	    vdebug(3,LOG_D_DWARF,
		   "rresolving ref 0x%"PRIxSMOFFSET" %s type symbol %s\n",
		   symbol->datatype->datatype_ref,
		   SYMBOL_TYPE(symbol->datatype->datatype_code),
		   symbol_get_name(symbol->datatype));
	    resolve_refs(NULL,symbol->datatype,reftab);
	}

	/* then, if this is a function, do the args */
	if (SYMBOL_IS_FULL_FUNCTION(symbol)) 
	    list_for_each_entry(member_instance,&(symbol->s.ii->d.f.args),
				d.v.member) {
		member = member_instance->d.v.member_symbol;
		if (member->datatype) {
		    vdebug(3,LOG_D_DWARF,
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
				  (gpointer)(OFFSET)symbol->s.ii->origin_ref))) {
	    verror("could not resolve ref 0x%"PRIxSMOFFSET" for inlined %s\n",
		   symbol->s.ii->origin_ref,SYMBOL_TYPE(symbol->type));
	}
	else {
	    vdebug(3,LOG_D_DWARF,
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
	    vwarn("64-bit DWARF length %ld; continuing.\n",length);
	    length = read_8ubyte_unaligned_inc(obo,readp);
	    is64 = 1;
	}
	else if (unlikely(length >= DWARF3_LENGTH_MIN_ESCAPE_CODE
			  && length <= DWARF3_LENGTH_MAX_ESCAPE_CODE))
	    vwarn("bad DWARF length %ld; continuing anyway!\n",length);

	unsigned int version = read_2ubyte_unaligned_inc(obo,readp);
	if (version != 2) 
	    vwarn("bad DWARF arange version %u; continuing anyway!\n",version);

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
	    die_offset += offset;

	    g_hash_table_insert(debugfile->pubnames,strdup((const char *)readp),
				(gpointer)die_offset);
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
	    vwarn("64-bit DWARF length %ld; continuing.\n",length);
	    length = read_8ubyte_unaligned_inc(obo,readp);
	}
	else if (unlikely(length >= DWARF3_LENGTH_MIN_ESCAPE_CODE
			  && length <= DWARF3_LENGTH_MAX_ESCAPE_CODE))
	    vwarn("bad DWARF length %ld; continuing anyway!\n",length);

	unsigned int version = read_2ubyte_unaligned_inc(obo,readp);
	if (version != 2) 
	    vwarn("bad DWARF arange version %u; continuing anyway!\n",version);

	Dwarf_Word offset = read_4ubyte_unaligned_inc(obo,readp);

	unsigned int address_size = *readp++;
	if (address_size != 4 && address_size != 8)
	    vwarn("bad DWARF address size %u; continuing anyway!\n",address_size);

	/* unsigned int segment_size = * */ readp++;

	/* Round the address to the next multiple of 2*address_size.  */
	readp += ((2 * address_size - ((readp - hdrstart) % (2 * address_size)))
		  % (2 * address_size));

	/*
	 * Lookup the symtab at this offset, or create one if it doesn't
	 * exist yet.
	 */
	if (!(cu_symtab = (struct symtab *)\
	      g_hash_table_lookup(debugfile->cuoffsets,(gpointer)offset))) {
	    cu_symtab = symtab_create(debugfile,(SMOFFSET)offset,NULL,NULL,0,
				      NULL);
	    g_hash_table_insert(debugfile->cuoffsets,(gpointer)offset,cu_symtab);
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

	    /* If it's the first tuple, leave it as RANGE_PC; else, change
	     * type to RANGE_LIST and build the list!
	     */
	    struct range *r = &cu_symtab->range;
	    if (r->rtype == RANGE_TYPE_NONE) {
		r->rtype = RANGE_TYPE_PC;
		r->r.a.lowpc = range_address;
		r->r.a.highpc = range_address + range_length;
		vdebug(5,LOG_D_DWARF,
		       "added RANGE_TYPE_PC(0x%"PRIxADDR",0x%"PRIxADDR")\n",
		       r->r.a.lowpc,r->r.a.highpc);
	    }
	    else if (r->rtype == RANGE_TYPE_PC) {
		ADDR olowpc = r->r.a.lowpc;
		ADDR ohighpc = r->r.a.highpc;
		r->rtype = RANGE_TYPE_LIST;
		/* reset it; it's a union? */
		memset(&r->r.rlist,0,sizeof(struct range_list));
		range_list_add(&r->r.rlist,olowpc,ohighpc);
		range_list_add(&r->r.rlist,range_address,
			       range_address + range_length);
		vdebug(5,LOG_D_DWARF,
		       "converted PC to LIST with new entry (0x%"PRIxADDR",0x%"PRIxADDR")\n",
		       range_address,range_address + range_length);
	    }
	    else if (r->rtype == RANGE_TYPE_LIST) {
		range_list_add(&r->r.rlist,range_address,
			       range_address + range_length);
		vdebug(5,LOG_D_DWARF,
		       "added RANGE_TYPE_LIST entry (0x%"PRIxADDR",0x%"PRIxADDR")\n",
		       range_address,range_address + range_length);
	    }
	}
    }

    return 0;
}

struct process_dwflmod_argdata {
    struct debugfile *debugfile;
    struct debugfile_load_opts *debugfile_load_opts;
    int fd;
};

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

static int process_dwflmod (Dwfl_Module *dwflmod,
			    void **userdata __attribute__ ((unused)),
			    const char *name __attribute__ ((unused)),
			    Dwarf_Addr base __attribute__ ((unused)),
			    void *arg) {
    struct process_dwflmod_argdata *data = \
	(struct process_dwflmod_argdata *)arg;

    GElf_Addr dwflbias;
    Elf *elf = dwfl_module_getelf(dwflmod,&dwflbias);

    GElf_Ehdr ehdr_mem;
    GElf_Ehdr *ehdr = gelf_getehdr(elf,&ehdr_mem);

    if (ehdr == NULL) {
	verror("cannot read ELF header: %s",elf_errmsg(-1));
	return DWARF_CB_ABORT;
    }

    Ebl *ebl = ebl_openbackend(elf);
    if (ebl == NULL) {
	verror("cannot create EBL handle: %s",strerror(errno));
	return DWARF_CB_ABORT;
    }

    /*
     * Last setup before parsing DWARF stuff!
     */
    Dwarf_Addr dwbias;
    Dwarf *dbg = dwfl_module_getdwarf(dwflmod,&dwbias);
    if (!dbg) {
	verror("could not get dwarf module!\n");
	goto errout;
    }

    size_t shstrndx;
#if _INT_ELFUTILS_VERSION >= 152
    if (elf_getshdrstrndx(elf,&shstrndx) < 0) {
#else 
    if (elf_getshstrndx(elf,&shstrndx) < 0) {
#endif
	verror("cannot get section header string table index\n");
	goto errout;
    }

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf,scn)) != NULL) {
	GElf_Shdr shdr_mem;
	GElf_Shdr *shdr = gelf_getshdr(scn,&shdr_mem);


	if (shdr && shdr->sh_size > 0) { // &&shdr->sh_type != SHT_PROGBITS) {
	    //shdr_mem.sh_flags & SHF_STRINGS) {
	    const char *name = elf_strptr(elf,shstrndx,shdr->sh_name);
	    char **saveptr;
	    unsigned int *saveptrlen;

	    if (strcmp(name,".debug_str") == 0) {
		saveptr = &data->debugfile->strtab;
		saveptrlen = &data->debugfile->strtablen;
	    }
	    else if (strcmp(name,".debug_loc") == 0) {
		saveptr = &data->debugfile->loctab;
		saveptrlen = &data->debugfile->loctablen;
	    }
	    else if (strcmp(name,".debug_ranges") == 0) {
		saveptr = &data->debugfile->rangetab;
		saveptrlen = &data->debugfile->rangetablen;
	    }
	    else if (strcmp(name,".debug_line") == 0) {
		saveptr = &data->debugfile->linetab;
		saveptrlen = &data->debugfile->linetablen;
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

	    vdebug(2,LOG_D_DWARF,"found %s section (%d) in debugfile %s\n",name,
		   shdr->sh_size,data->debugfile->idstr);

	    Elf_Data *edata = elf_rawdata(scn,NULL);
	    if (!edata) {
		verror("cannot get data for valid section '%s': %s",
		       name,elf_errmsg(-1));
		goto errout;
	    }

	    /*
	     * aranges and pubnames are special.  We parse them
	     * *immediately*, using them to setup our CU symtabs, which
	     * are then validated and filled in as we parse debuginfo.
	     */
	    if (!saveptr) {
		if (strcmp(name,".debug_aranges") == 0) {
		    get_aranges(data->debugfile,edata->d_buf,edata->d_size,dbg);
		    continue;
		}
		else if (strcmp(name,".debug_pubnames") == 0) {
		    get_pubnames(data->debugfile,edata->d_buf,edata->d_size,dbg);
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
	    vdebug(2,LOG_D_DWARF,"section empty, which is fine!\n");
	}
    }
    if (!data->debugfile->strtab) {
	vwarn("no string table found for debugfile %s; things may break!\n",
	      data->debugfile->filename);
    }

    /* now rescan for debug_info sections */
    scn = NULL;
    while ((scn = elf_nextscn(elf,scn)) != NULL) {
	GElf_Shdr shdr_mem;
	GElf_Shdr *shdr = gelf_getshdr(scn,&shdr_mem);

	if (shdr && shdr->sh_size > 0 && shdr->sh_type == SHT_PROGBITS) {
	    const char *name = elf_strptr(elf,shstrndx,shdr->sh_name);

	    if (strcmp(name,".debug_info") == 0) {
		vdebug(2,LOG_D_DWARF,
		       "found .debug_info section in debugfile %s\n",
		       data->debugfile->idstr);
		debuginfo_ordered_traversal(data->debugfile,
					    data->debugfile_load_opts,
					    dwflmod,dbg);
		//break;
	    }
	}
    }

    /* Now free up the temp loc/range tables. */
    if (data->debugfile->loctab) {
	free(data->debugfile->loctab);
	data->debugfile->loctablen = 0;
	data->debugfile->loctab = NULL;
    }
    if (data->debugfile->rangetab) {
	free(data->debugfile->rangetab);
	data->debugfile->rangetablen = 0;
	data->debugfile->rangetab = NULL;
    }
    if (data->debugfile->linetab) {
	free(data->debugfile->linetab);
	data->debugfile->linetablen = 0;
	data->debugfile->linetab = NULL;
    }
    /*
     * Only save strtab if we're gonna use it.
     */
#ifndef DWDEBUG_USE_STRTAB
    if (data->debugfile->strtab) {
	free(data->debugfile->strtab);
	data->debugfile->strtablen = 0;
	data->debugfile->strtab = NULL;
    }
#endif

    ebl_closebackend(ebl);

    return DWARF_CB_OK;

 errout:
    ebl_closebackend(ebl);

    return DWARF_CB_ABORT;
}

/*
 * Primary debuginfo interface.  Given an ELF filename, load all its
 * debuginfo into the supplied debugfile using elfutils libs.
 */
int debugfile_load(struct debugfile *debugfile,struct debugfile_load_opts *opts) {
    int fd;
    Dwfl *dwfl;
    Dwfl_Module *mod;
    char *filename = debugfile->filename;

    if ((fd = open(filename,0,O_RDONLY)) < 0) {
	verror("open %s: %s\n",filename,strerror(errno));
	return -1;
    }

    /* 
     * Don't try to find any extra debuginfo; we'll handle that elsewhere.
     *
     * XXX This takes care of applying relocations to DWARF data in
     * ET_REL files.  Do we want this???
     *
     * I think not -- what I'd rather have is a post-pass to apply
     * section relocation information when we decode, so that we can
     * share debuginfo-loaded data structs.
     */
    static const Dwfl_Callbacks callbacks = {
	.section_address = dwfl_offline_section_address,
	.find_debuginfo  = find_no_debuginfo,
    };

    dwfl = dwfl_begin(&callbacks);
    if (dwfl == NULL) {
	verror("could not init libdwfl: %s\n",dwfl_errmsg(dwfl_errno()));
	close(fd);
	return -1;
    }

    // XXX do we really need this?  Can't have it without libdwflP.h
    //dwfl->offline_next_address = 0;

    if (!(mod = dwfl_report_offline(dwfl,filename,filename,fd))) {
	verror("dwfl_report_offline: %s\n",dwfl_errmsg(dwfl_errno()));
	dwfl_end(dwfl);
	close(fd);
	return -1;
    }

    dwfl_report_end(dwfl,NULL,NULL);

    /*
     * This is where the guts of the work happen -- and that stuff all
     * happens in the callback.
     */
    struct process_dwflmod_argdata data = { 
	.debugfile = debugfile,
	.debugfile_load_opts = opts,
	.fd = fd,
    };
    if (dwfl_getmodules(dwfl,&process_dwflmod,&data,0) < 0) {
	verror("getting dwarf modules: %s\n",dwfl_errmsg(dwfl_errno()));
	return -1;
    }

    dwfl_end(dwfl);
    close(fd);

    return 0;
}


