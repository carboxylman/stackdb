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
#include "binfile.h"
#include "dwdebug.h"
#include "dwdebug_priv.h"

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
    struct symbol_root_dwarf *srd;

    int level;
    Dwarf_Off cu_offset;
    Dwarf_Off die_offset;

    struct symbol *symbol;
    struct symbol *parentsymbol;
    struct symbol *voidsymbol;

    Dwarf_Off specification_ref;

    ADDR lowpc;
    ADDR highpc;
    Dwarf_Word stmt_list_offset;
    struct range *ranges;
    uint8_t lowpc_set:1,
	    highpc_set:1,
  	    highpc_is_offset:1,
	    reloading:1,
	    have_stmt_list_offset:1,
	    specification_set:1;
};

extern int dwarf_load_cfa(struct debugfile *debugfile,
			  char *buf,unsigned int len,Dwarf *dbg);
extern int dwarf_unload_cfa(struct debugfile *debugfile);
/* Declare these now; they are used in attr_callback. */
static struct range *dwarf_get_ranges(struct symbol_root_dwarf *srd,
				      unsigned int attr,Dwarf_Word offset);

static struct location *dwarf_get_loclistloc(struct symbol_root_dwarf *srd,
					     unsigned int attr,
					     Dwarf_Word offset);
int dwarf_get_lines(struct symbol_root_dwarf *srd,Dwarf_Off offset);
static inline char *dwarf_language_string(int language);

const char *dwarf_tag_string(unsigned int tag);
const char *dwarf_attr_string(unsigned int attrnum);
const char *dwarf_form_string(unsigned int form);
const char *dwarf_lang_string(unsigned int lang);
const char *dwarf_inline_string(unsigned int code);
const char *dwarf_encoding_string(unsigned int code);
const char *dwarf_access_string(unsigned int code);
const char *dwarf_visibility_string(unsigned int code);
const char *dwarf_virtuality_string(unsigned int code);
const char *dwarf_identifier_case_string(unsigned int code);
const char *dwarf_calling_convention_string(unsigned int code);
const char *dwarf_ordering_string(unsigned int code);
const char *dwarf_discr_list_string(unsigned int code);

static int attr_callback(Dwarf_Attribute *attrp,void *arg) {
    struct attrcb_args *cbargs = (struct attrcb_args *)arg;

    Dwarf_Off die_offset = cbargs->die_offset;
    const int level = cbargs->level;
    struct symbol *symbol = cbargs->symbol;
    struct symbol_root_dwarf *srd = cbargs->srd;
    struct debugfile *debugfile = srd->debugfile;
    Dwarf_Half version = srd->version;
    uint8_t offsize = srd->offsize;

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
    uint8_t sec_offset_set = 0;

    GSList *iilist;
    struct location *loc;

#define DFE(msg)						\
    verror(" <%d><%"PRIx64">  %s: %s\n",				\
	   level,die_offset,dwarf_attr_string(attr),msg);

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
	    vwarnopt(5,LA_DEBUG,LF_DWARF,
		     " <%d><%"PRIx64">  %s: dwarf str at 0x%lx not in dbg_strtab;"
		     " copying!\n",
		     level,die_offset,dwarf_attr_string(attr),
		     (unsigned long int)*(attrp->valp));
	    str_copy = 1;
	}
	// XXX relocation...
	if (offsize == 4)
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
	    DFE("could not get dwarf addr!");
	    goto errout;
	}
	addr_set = 1;
	break;
    case DW_FORM_ref_addr:
	vdebug(12,LA_DEBUG,LF_DWARFATTR,
	       " <%d><%"PRIx64">  %s: cross-CU ref %"PRIxADDR"\n",
	       level,die_offset,dwarf_attr_string(attr),ref);
    case DW_FORM_ref_udata:
    case DW_FORM_ref8:
    case DW_FORM_ref4:
    case DW_FORM_ref2:
    case DW_FORM_ref1:
	if (unlikely(dwarf_formref_die(attrp,&rref) == NULL)) {
	    DFE("could not get dwarf die ref!");
	    goto errout;
	}
	ref = dwarf_dieoffset(&rref);
	ref_set = 1;
	break;
#if _INT_ELFUTILS_VERSION > 141
    case DW_FORM_sec_offset:
	/*
	 * Util .153, dwarf_forudata could not handle DW_FORM_sec_offset.
	 */
#if _INT_ELFUTILS_VERSION < 153
	attrp->form = 
	    offsize == 8 ? DW_FORM_data8 : DW_FORM_data4;
#endif
	sec_offset_set = 1;
      /* Fall through.  */
#endif
    case DW_FORM_udata:
    case DW_FORM_sdata:
    case DW_FORM_data8:
    case DW_FORM_data4:
    case DW_FORM_data2:
    case DW_FORM_data1:
	if (unlikely(dwarf_formudata(attrp,&num) != 0)) {
	    DFE("could not load dwarf num!");
	    goto errout;
	}
	num_set = 1;
	break;
#if _INT_ELFUTILS_VERSION > 141
    case DW_FORM_exprloc:
#endif
    case DW_FORM_block4:
    case DW_FORM_block2:
    case DW_FORM_block1:
    case DW_FORM_block:
	if (unlikely(dwarf_formblock(attrp,&block) != 0)) {
	    DFE("could not load dwarf block!");
	    goto errout;
	}
	block_set = 1;
	break;
    case DW_FORM_flag:
#if _INT_ELFUTILS_VERSION > 141
    case DW_FORM_flag_present:
#endif
	if (unlikely(dwarf_formflag(attrp,&flag) != 0)) {
	    DFE("could not load dwarf flag!");
	    goto errout;
	}
	flag_set = 1;
	break;
    default:
	vwarnopt(2,LA_DEBUG,LF_DWARFATTR,
		 " <%d><"PRIx64">  %s: unrecognized form %s (0x%x)!\n",
		 level,die_offset,dwarf_attr_string(attr),
		 dwarf_form_string(form),form);
	goto errout;
    }

    /* Quick debugging. */
    if (vdebug_is_on(9,LA_DEBUG,LF_DWARFATTR)) {
	if (str_set)
	    vdebug(9,LA_DEBUG,LF_DWARFATTR,
		   " <%d><%x>  %s = '%s'\n",
		   (int)level,die_offset,dwarf_attr_string(attr),str);
	else if (addr_set)
	    vdebug(9,LA_DEBUG,LF_DWARFATTR,
		   " <%d><%x>  %s = 0x%"PRIxADDR"\n",
		   (int)level,die_offset,dwarf_attr_string(attr),addr);
	else if (num_set)
	    vdebug(9,LA_DEBUG,LF_DWARFATTR,
		   " <%d><%x>  %s = %d\n",
		   (int)level,die_offset,dwarf_attr_string(attr),num);
	else if (block_set)
	    vdebug(9,LA_DEBUG,LF_DWARFATTR,
		   " <%d><%x>  %s = 0x%"PRIxADDR"\n",
		   (int)level,die_offset,dwarf_attr_string(attr),block);
	else if (ref_set)
	    vdebug(9,LA_DEBUG,LF_DWARFATTR,
		   " <%d><%x>  %s = 0x%"PRIxSMOFFSET"\n",
		   (int)level,die_offset,dwarf_attr_string(attr),ref);
	else if (flag_set)
	    vdebug(9,LA_DEBUG,LF_DWARFATTR,
		   " <%d><%x>  %s = %d\n",
		   (int)level,die_offset,dwarf_attr_string(attr),flag);
	else 
	    vdebug(9,LA_DEBUG,LF_DWARFATTR,
		   " <%d><%x>  %s\n",
		   (int)level,die_offset,dwarf_attr_string(attr));
    }

#define DAW_STR(msg)							\
    { vwarnopt(6,LA_DEBUG,LF_DWARFATTR,					\
	       " <%d><%"PRIx64">  %s (%s): %s\n",			\
	       level,die_offset,dwarf_attr_string(attr),str,msg); }
#define DAW_ADDR(msg)							\
    { vwarnopt(6,LA_DEBUG,LF_DWARFATTR,					\
	       " <%d><%"PRIx64">  %s (0x%"PRIxADDR"): %s\n",		\
	       level,die_offset,dwarf_attr_string(attr),addr,msg); }
#define DAW_NUM(msg)							\
    { vwarnopt(6,LA_DEBUG,LF_DWARFATTR,					\
	       " <%d><%"PRIx64">  %s (%d): %s\n",			\
	       level,die_offset,dwarf_attr_string(attr),num,msg); }
#define DAW_BLOCK(msg)							\
    { vwarnopt(6,LA_DEBUG,LF_DWARFATTR,					\
	       " <%d><%"PRIx64">  %s (0x%"PRIxADDR"): %s\n",		\
	       level,die_offset,dwarf_attr_string(attr),block,msg); }
#define DAW_REF(msg)							\
    { vwarnopt(6,LA_DEBUG,LF_DWARFATTR,					\
	       " <%d><%"PRIx64">  %s (0x%"PRIxSMOFFSET"): %s\n",		\
	       level,die_offset,dwarf_attr_string(attr),ref,msg); }
#define DAW_FLAG(msg)							\
    { vwarnopt(6,LA_DEBUG,LF_DWARFATTR,					\
	       " <%d><%"PRIx64">  %s (%d): %s\n",			\
	       level,die_offset,dwarf_attr_string(attr),flag,msg); }
#define DAW(msg)						\
    { vwarnopt(6,LA_DEBUG,LF_DWARFATTR,				\
	       " <%d><%"PRIx64">  %s: %s\n",			\
	       level,die_offset,dwarf_attr_string(attr),msg); }
#define DAWL(msg)						\
    { vwarnopt(16,LA_DEBUG,LF_DWARFATTR,			\
	       " <%d><%"PRIx64">  %s: %s\n",			\
	       level,die_offset,dwarf_attr_string(attr),msg); }

    /*
     * Ok, finally process them!!
     */
    switch (attr) {
    case DW_AT_name:
	if (cbargs->reloading) 
	    break;

	if (symbol) 
	    symbol_set_name(symbol,str,str_copy);
	else 
	    DAW_STR("bad context");
	break;
    case DW_AT_stmt_list:
	/* XXX: don't do line numbers yet. */
	if (num_set) {
	    cbargs->stmt_list_offset = num;
	    cbargs->have_stmt_list_offset = 1;
	}
	else 
	    DAW("bad form");
	break;
    case DW_AT_producer:
	if (level == 0) 
	    symbol_set_root_producer(symbol,str,str_copy);
	else 
	    DAW_STR("bad context");
	break;
    case DW_AT_comp_dir:
	if (level == 0) 
	    symbol_set_root_compdir(symbol,str,str_copy);
	else 
	    DAW_STR("bad context");
	break;
    case DW_AT_language:
	if (level == 0) 
	    symbol_set_root_language(symbol,dwarf_language_string(num),0,num);
	else 
	    DAW_NUM("bad context");
	break;
    case DW_AT_low_pc:
	/* Just stash it here; do the updating in attr postprocessing. */
	cbargs->lowpc = addr;
	cbargs->lowpc_set = 1;
	break;
    case DW_AT_high_pc:
	if (num_set) {
	    /* Just stash it and postprocess after all attrs processed. */
	    cbargs->highpc = num;
	    cbargs->highpc_set = 1;
	    cbargs->highpc_is_offset = 1;
	}
	else if (addr_set) {
	    /* Just stash it and postprocess after all attrs processed. */
	    cbargs->highpc = addr;
	    cbargs->highpc_set = 1;
	    cbargs->highpc_is_offset = 0;
	}
	else 
	    DAW("bad form");
	break;
    case DW_AT_entry_pc:
	if (addr_set) {
	    if (SYMBOL_IS_FUNC(symbol) || SYMBOL_IS_ROOT(symbol)) 
		symbol_set_entry_pc(symbol,addr);
	    else 
		DAW_ADDR("bad context");
	}
	else 
	    DAW("bad form");
	break;
    case DW_AT_decl_file:
	if (symbol) {
	    ; // XXX
	}
	else 
	    DAW("bad context");
	break;
    case DW_AT_decl_line:
	if (symbol) 
	    symbol_set_srcline(symbol,(int)num);
	else 
	    DAW("bad context");
	break;
    /* Don't bother with these yet. */
    case DW_AT_decl_column:
    case DW_AT_call_file:
    case DW_AT_call_line:
    case DW_AT_call_column:
	break;
    case DW_AT_encoding:
	if (symbol && SYMBOL_IST_BASE(symbol)) {
	    /* our encoding_t is 1<->1 map to the DWARF encoding codes. */
	    symbol_set_encoding(symbol,(encoding_t)num);
	}
	else 
	    DAW("bad context");
	break;
    case DW_AT_declaration:
	if (symbol) 
	    symbol->isdeclaration = flag;
	else 
	    DAW("bad context");
	break;
    case DW_AT_external:
	if (symbol 
	    && (SYMBOL_IS_FUNC(symbol) || SYMBOL_IS_VAR(symbol))) {
	    /*
	     * C++ struct/class members marked with AT_external are
	     * really static data members; do not mark them external.
	     */
	    if (SYMBOL_IS_VAR(symbol)
		&& cbargs->parentsymbol
		&& SYMBOL_IST_STUNC(cbargs->parentsymbol))
		symbol->isexternal = 0;
	    else
		symbol->isexternal = flag;
	}
	else if (symbol && SYMBOL_IST_FUNC(symbol)) {
	    symbol->isexternal = flag;
	}
	else 
	    DAW("bad context");
	break;
    case DW_AT_linkage_name:
    case DW_AT_MIPS_linkage_name:
	if (symbol) {
	    /*
	     * We need to record this so that we don't mark AT_external
	     * vars as globals, if they have external linkage.  We just
	     * ignore AT_external for stuff that has external linkage
	     * names; we don't try to put an alias in for the linkage
	     * symbol -- we're not a linker and users won't care!
	     */
	    symbol->has_linkage_name = 1;
	}
	else 
	    DAW("bad context");
	break;
    case DW_AT_prototyped:
	if (symbol && (SYMBOL_IS_FUNC(symbol) || SYMBOL_IST_FUNC(symbol)))
	    symbol->isprototyped = flag;
	else 
	    DAW("bad context");
	break;
    case DW_AT_inline:
	if (num_set && symbol && SYMBOL_IS_FUNC(symbol)) {
	    if (num == 1)
		symbol_set_inline_info(symbol,1,0);
	    else if (num == 2)
		symbol_set_inline_info(symbol,0,1);
	    else if (num == 3) 
		symbol_set_inline_info(symbol,1,1);
	    else if (num == 0) 
		; /* Ignore; same as not decl nor inlined; spec v4 p. 59 */
	    else
		DAW_NUM("bad inline number");
	}
	else 
	    DAW("bad context");
	break;
    case DW_AT_abstract_origin:
	if (ref_set && SYMBOL_IS_INLINEABLE(symbol)) {
		/*
		 * Do this in the CU post-pass; it copies additional
		 * stuff into symbol (like datatype).
		 */
		//symbol->s.ii->origin = (struct symbol *)	
		//   g_hash_table_lookup(cbargs->reftab,(gpointer)(uintptr_t)ref);
		/* Always set the ref so we can generate a unique name for 
		 * the symbol; see finalize_die_symbol!!
		 */
	    if (symbol_set_inline_origin(symbol,ref,NULL)) {
		DAW_REF("failed to set inline origin");
		break;
	    }

	    /* Record it as needing resolution in our CU table. */
	    iilist = g_hash_table_lookup(srd->abstract_origins,
					 (gpointer)(uintptr_t)ref);
	    iilist = g_slist_append(iilist,symbol);
	    g_hash_table_insert(srd->abstract_origins,
				(gpointer)(uintptr_t)ref,iilist);
	}
	else 
	    DAW("bad context");
	break;
    case DW_AT_type:
	if (cbargs->reloading) 
	    break;

	if (ref_set && symbol) {
	    /*
	     * Disable the datatype lookup here; there's no point; it
	     * saves us no time, and for implementing type compression
	     * (see end of CU load function) and code simplicity with
	     * that, we just do all datatype lookups there, in one
	     * place.
	     */
	    /* struct symbol *datatype = (struct symbol *)		
	           g_hash_table_lookup(cbargs->reftab,(gpointer)(uintptr_t)ref); */
	    if (SYMBOL_IS_TYPE(symbol)) {
		if (SYMBOL_IST_PTR(symbol) || SYMBOL_IST_TYPEDEF(symbol)
		    || SYMBOL_IST_ARRAY(symbol) || SYMBOL_IST_CONST(symbol)
		    || SYMBOL_IST_VOL(symbol) || SYMBOL_IST_FUNC(symbol)) {
		    symbol->datatype_ref = (uint64_t)ref;
		    /* if (datatype)
		           symbol->datatype = datatype; */
		}
		else 
		    DAW_REF("bogus: type ref for unknown type symbol");
	    }
	    else {
		symbol->datatype_ref = ref;
		/* if (datatype)
		       symbol->datatype = datatype; */
	    }
	}
	else if (ref_set && !symbol && cbargs->parentsymbol 
		 && SYMBOL_IST_ARRAY(cbargs->parentsymbol)) {
	    /*
	     * If the parent was an array_type, don't worry about typing
	     * its array subranges.
	     */
	    ;
	}
	else 
	    DAW("bad context");
	break;
    case DW_AT_const_value:
	if (!symbol || !SYMBOL_IS_VAR(symbol)) {
	    DAW("bad context");
	    break;
	}
	else if (num_set && symbol_get_datatype(symbol) 
		 && symbol_get_bytesize(symbol_get_datatype(symbol)) > 0) {
	    symbol_set_constval(symbol,(void *)&num,
				symbol_get_bytesize(symbol_get_datatype(symbol)),
				1);
	}
	else if (num_set && SYMBOL_IS_VAR(symbol)) {
	    /*
	     * XXX: just use a 64 bit unsigned for now, since we may not
	     * have seen the type for this symbol yet.  We can always
	     * deal with it later.
	     */
	    symbol_set_constval(symbol,(void *)&num,sizeof(Dwarf_Word),1);
	}
	else if (str_set) {
	    if (str_copy)
		symbol_set_constval(symbol,str,strlen(str) + 1,1);
	    else
		symbol_set_constval(symbol,str,-1,0);
	}
	else if (block_set) 
	    symbol_set_constval(symbol,block.data,block.length,1);
	else 
	    DAW("bad context");
	break;
    /*
     * XXX: byte/bit sizes/offsets can technically be a reference
     * to another DIE, or an exprloc... but they should always be
     * consts for C!
     */
    case DW_AT_byte_size:
	if (!symbol) {
	    DAW("bad context");
	    break;
	}
	else if (num_set) 
	    symbol_set_bytesize(symbol,num);
	else 
	    DAW("bad form");
	break;
    case DW_AT_bit_size:
	if (!symbol) {
	    DAW("bad context");
	    break;
	}
	else if (num_set) 
	    symbol_set_bitsize(symbol,num);
	else 
	    DAW("bad form");
	break;
    case DW_AT_bit_offset:
	if (!symbol) {
	    DAW("bad context");
	    break;
	}
	else if (num_set) 
	    symbol_set_bitoffset(symbol,num);
	else 
	    DAW("bad form");
	break;
    case DW_AT_sibling:
	/* we process all DIEs, so no need to skip any child content. */
	break;
    case DW_AT_data_member_location:
	if (!symbol || !SYMBOL_IS_VAR(symbol)) {
	    DAW("bad context");
	    break;
	}

	/* In V3 or V4, this can be either an exprloc, loclistptr, or a
	 * constant.  In V2, it can only be an exprloc (block) or a
	 * loclistptr (reference).
	 *
	 * We know if block_set, it is an exprloc (see above in form
	 * processing), regardless of V2, V3, or V4.
	 *
	 * However, if the version is DWARF3, we cannot tell the
	 * difference between a constant and loclistptr if the form is
	 * FORM_data4 or FORM_data8 (the comment in V3 spec, p. 140 is:
	 *    Because classes lineptr, loclistptr, macptr and
	 *    rangelistptr share a common representation, it is not
	 *    possible for an attribute to allow more than one of these
	 *    classes. If an attribute allows both class constant and
	 *    one of lineptr, loclistptr, macptr or rangelistptr, then
	 *    DW_FORM_data4 and DW_FORM_data8 are interpreted as members
	 *    of the latter as appropriate (not class constant).
	 * ).  This rule seems awfully bad to me, but we follow it!
	 *
	 * Then, if the version is 4 and we see a FORM_data4 or
	 * FORM_data8, we take it as a constant.  This seems to be the
	 * correct behavior, because the V4 spec does not include the
	 * above caveat.  For V4, we only consider it a loclistptr if
	 * FORM_sec_offset was used.
	 *
	 * NB: This *also means that if you use this library on a DWARF4
	 * file, but your elfutils does not support FORM_sec_offset,
	 * things will break!!!
	 */
	loc = NULL;
	if (block_set) {
	    if (symbol->ismember) {
		loc = dwarf_get_static_ops(srd,block.data,block.length,attr);
		if (!loc) {
		    DAW_BLOCK("failed get_static_ops");
		}
		else if (symbol_set_location(symbol,loc)) {
		    DAW_BLOCK("failed symbol_set_location");
		    location_free(loc);
		}
	    }
	    else 
		DAW_BLOCK("nonmember symbol");
	}
	else if (num_set) {
	    if ((version == 3 && (form == DW_FORM_data4 
				  || form == DW_FORM_data8))
		|| (version >= 4 && sec_offset_set)) {
		if (symbol->ismember) {
		    loc = dwarf_get_loclistloc(srd,attr,num);
		    if (!loc) 
			DAW_NUM("failed get_loclistloc");
		}
		else 
		    DAW_BLOCK("nonmember symbol");
	    }
	    else {
		/* it's a constant */
		loc = location_create();
		location_set_member_offset(loc,(int32_t)num);
	    }

	    if (loc && symbol_set_location(symbol,loc)) {
		DAW_NUM("failed symbol_set_location");
		location_free(loc);
	    }
	}
	else 
	    DAW("bad form");
	break;
    case DW_AT_frame_base:
	if (!symbol || !SYMBOL_IS_FUNC(symbol)) {
	    DAW("bad context");
	    break;
	}

	loc = NULL;
	/* if it's a loclist */
	if (num_set && (form == DW_FORM_data4 || form == DW_FORM_data8)) {
	    loc = dwarf_get_loclistloc(srd,attr,num);
	    if (!loc) {
		DAW_NUM("failed get_loclistloc");
		break;
	    }
	    SYMBOL_WX_FUNC(symbol,sf,-1);
	    sf->fbloc = loc;
	}
	/* if it's an exprloc in a block */
	else if (block_set) {
	    loc = dwarf_get_static_ops(srd,block.data,block.length,attr);
	    if (!loc) {
		DAW_BLOCK("failed to get_static_ops");
		break;
	    }
	    SYMBOL_WX_FUNC(symbol,sf,-1);
	    sf->fbloc = loc;
	}
	else 
	    DAW("frame_base not num/block");
	break;
    case DW_AT_ranges:
	/* always a rangelistptr */
	if (num_set && (sec_offset_set
			|| form == DW_FORM_data4 
			|| form == DW_FORM_data8)) {
	    cbargs->ranges = dwarf_get_ranges(srd,attr,num);
	    if (!cbargs->ranges) {
		DAW_NUM("failed to get_ranges");
		break;
	    }
	}
	else 
	    DAW("bad form");
	break;
    case DW_AT_location:
	/* We only accept this for params and variables */
	if (!symbol || !SYMBOL_IS_VAR(symbol)) {
	    DAW("bad context");
	    break;
	}

	if (num_set && (sec_offset_set
			|| form == DW_FORM_data4 
			|| form == DW_FORM_data8)) {
	    loc = dwarf_get_loclistloc(srd,attr,num);
	    if (!loc) {
		DAW_NUM("failed to get_loclistloc");
		break;
	    }
	    else if (symbol_set_location(symbol,loc)) {
		DAW_NUM("failed to set_location!");
		location_free(loc);
		break;
	    }
	}
	else if (block_set) {
	    loc = dwarf_get_static_ops(srd,block.data,block.length,attr);
	    if (!loc) {
		DAW("failed to get_static_ops");
		break;
	    }
	    else if (symbol_set_location(symbol,loc)) {
		DAW_NUM("failed to set_location!");
		location_free(loc);
		break;
	    }
	}
	else 
	    DAW("bad form");
	break;
    case DW_AT_lower_bound:
	if (num_set && num) {
	    DAW_NUM("we only support lower_bound attrs of 0");
	}
	else 
	    DAW("bad attr/form");
	break;
    case DW_AT_count:
	//DAW("interpreting AT_count as AT_upper_bound");
    case DW_AT_upper_bound:
	/* it's a constant, not a block op */
	if (num_set && !sec_offset_set) {
	    if (!symbol && cbargs->parentsymbol
		&& SYMBOL_IST_ARRAY(cbargs->parentsymbol)) {
		symbol_add_subrange(cbargs->parentsymbol,(int)num);
	    }
	    else 
		DAW_NUM("non array-type parent or bad context");
	    break;
	}
	else
	    DAW("bad attr/form");
	break;
    case DW_AT_specification:
	if (ref_set && symbol) {
	    cbargs->specification_ref = ref;
	    cbargs->specification_set = 1;
	}
	else
	    DAW("bad context/form");
	break;
    /* Skip these things. */
    case DW_AT_artificial:
	break;
    /* Skip DW_AT_GNU_vector, which not all elfutils versions know about. */
    case 8455:
	break;

    /* Skip a few that we might add support for later. */
    case DW_AT_object_pointer:
    case DW_AT_accessibility:
    case DW_AT_containing_type:
    case DW_AT_virtuality:
    case DW_AT_vtable_elem_location:
    case DW_AT_explicit:
	DAWL("known unhandled");
	break;

    default:
	DAW("unrecognized");
	//goto errout;
	break;
    }

    goto out;

 errout:
    return DWARF_CB_ABORT;
 out:
    return 0;
}

static inline char *dwarf_language_string(int language) {
    switch (language) {
    case DW_LANG_C89:			return "C89";
    case DW_LANG_C:			return "C";
    case DW_LANG_Ada83:			return "Ada83";
    case DW_LANG_C_plus_plus:		return "C++";
    case DW_LANG_Cobol74:		return "Cobol74";
    case DW_LANG_Cobol85:		return "Cobol85";
    case DW_LANG_Fortran77:		return "Fortran77";
    case DW_LANG_Fortran90:		return "Fortran90";
    case DW_LANG_Pascal83:		return "Pascal83";
    case DW_LANG_Modula2:		return "Modula2";
    case DW_LANG_Java:			return "Java";
    case DW_LANG_C99:			return "C99";
    case DW_LANG_Ada95:			return "Ada95";
    case DW_LANG_Fortran95:		return "Fortran95";
    case DW_LANG_PL1:			return "PL/1";
    case DW_LANG_Objc:			return "ObjectiveC";
    case DW_LANG_ObjC_plus_plus:	return "ObjectiveC++";
    case DW_LANG_UPC:			return "UnifiedParallelC";
    case DW_LANG_D:			return "D";
#if _INT_ELFUTILS_VERSION > 147
    case DW_LANG_Python:		return "Python";
#endif
#if _INT_ELFUTILS_VERSION > 149
    case DW_LANG_Go:			return "Go";
#endif
    case DW_LANG_Mips_Assembler:	return "Assembler";
    default:				return NULL;
    }
}

static struct range *dwarf_get_ranges(struct symbol_root_dwarf *srd,
				      unsigned int attr,Dwarf_Word offset) {
    struct debugfile *debugfile = srd->debugfile;
    unsigned int addrsize = srd->addrsize;
    char *readp;
    char *endp;
    ptrdiff_t loffset;
    Dwarf_Addr begin;
    Dwarf_Addr end;
    int len = 0;
    int have_base = 0;
    Dwarf_Addr base = 0;
    struct range *retval = NULL, *lastr = NULL;
    ADDR cu_base;

    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;

    if (!debugfile->rangetab || offset > debugfile->rangetablen) {
	errno = EFAULT;
	return NULL;
    }

    cu_base = symbol_get_addr(srd->root);

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
		vdebug(5,LA_DEBUG,LF_DLOC,"[%6tx] end of list\n",loffset);
	    break;
	}
	else {
	    ++len;

	    /* We have a range entry.  */
	    if (!retval) {
		retval = calloc(1,sizeof(*retval));
		retval->start = (have_base) ? begin + base : begin + cu_base;
		retval->end = (have_base) ? end + base : end + cu_base;
		lastr = retval;
	    }
	    else {
		lastr->next = calloc(1,sizeof(*lastr));
		lastr->next->start = (have_base) ? begin + base : begin + cu_base;
		lastr->next->end = (have_base) ? end + base : end + cu_base;
		lastr = lastr->next;
	    }
	}
    }

    return retval;
}

static struct location *dwarf_get_loclistloc(struct symbol_root_dwarf *srd,
					     unsigned int attr,
					     Dwarf_Word offset) {
    struct debugfile *debugfile = srd->debugfile;
    unsigned int addrsize = srd->addrsize;
    ADDR cu_base;
    char *readp;
    char *endp;
    ptrdiff_t loffset;
    Dwarf_Addr begin;
    Dwarf_Addr end;
    int len = 0;
    uint16_t exprlen;
    int have_base = 0;
    Dwarf_Addr base = 0;
    struct location *tmploc = NULL;
    struct location *retval = NULL;
    ADDR rbegin,rend;

    /* XXX: we can't get other_byte_order from dbg since we don't have
     * the struct def for it... so we assume it's not a diff byte order
     * than the phys host for now.
     */
    int obo = 0;

    if (!debugfile->loctab
	|| offset > debugfile->loctablen) {
	errno = EFAULT;
	return NULL;
    }

    cu_base = symbol_get_addr(srd->root);

    readp = debugfile->loctab + offset;
    endp = debugfile->loctab + debugfile->loctablen;

    vdebug(5,LA_DEBUG,LF_DLOC,"starting (loctab len %d, offset %d)\n",
	   debugfile->loctablen,offset);

    retval = location_create();

    while (readp < endp) {
	loffset = readp - debugfile->loctab;

	if (unlikely((debugfile->loctablen - loffset) < addrsize * 2)) {
	    verror("[%6tx] invalid loclist entry\n",loffset);
	    goto errout;
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

	    if (endp - readp <= (ptrdiff_t) exprlen) {
		verror("[%6tx] invalid exprlen (%hd) in entry\n",loffset,exprlen);
		goto errout;
	    }

	    /* GCC apparently produces these meaningless entries; ignore them! */
	    if (begin == end) {
		vwarnopt(4,LA_DEBUG,LF_DWARF | LF_DLOC,
			 "[%6tx] begin (0x%"PRIxADDR") == end (0x%"PRIxADDR")\n",
			 loffset,begin,end);
		goto cont;
	    }

	    vdebug(5,LA_DEBUG,LF_DLOC,
		   "[%6tx] loc expr range(0x%"PRIxADDR",0x%"PRIxADDR") len %hd\n",
		   loffset,begin,end,exprlen);

	    tmploc = dwarf_get_static_ops(srd,(const unsigned char *)readp,
					  exprlen,attr);

	    if (!tmploc) {
		vwarnopt(9,LA_DEBUG,LF_DLOC,
			 "get_static_ops (%d) failed!\n",exprlen);
		goto errout;
	    }
	    else {
		vdebug(5,LA_DEBUG,LF_DLOC,
		       "get_static_ops (%d) succeeded!\n",exprlen);
	    }

	    rbegin = (have_base) ? begin + base : begin + cu_base;
	    rend = (have_base) ? end + base : end + cu_base;
	    if (location_update_loclist(retval,rbegin,rend,tmploc,NULL)) {
		verror("location_update_loclist failed!\n");
		goto errout;
	    }

	cont:
	    readp += exprlen;
	}
    }

    return retval;

 errout:
    if (tmploc)
	location_free(tmploc);
    if (retval)
	location_free(retval);
    return NULL;
}

/* Used in fill_debuginfo; defined right afer it for ease of
 * understanding the code.
 */

void finalize_die_symbol_name(struct symbol *symbol);
void finalize_die_symbol(struct debugfile *debugfile,int level,
			 struct symbol *symbol,
			 struct symbol *parentsymbol,
			 struct symbol *voidsymbol,
			 GHashTable *reftab,struct array_list *die_offsets,
			 SMOFFSET cu_offset);
void resolve_refs(gpointer key,gpointer value,gpointer data);

struct symbol *do_void_symbol(struct debugfile *debugfile,
			      struct symbol *root) {
    /* symbol_create dups the name, so we just pass a static buf */
    struct symbol *symbol;

    symbol = symbol_get_sym(root,"void",SYMBOL_TYPE_FLAG_TYPE);
    if (symbol)
	return symbol;

    symbol = symbol_create(SYMBOL_TYPE_TYPE,SYMBOL_SOURCE_DWARF,"void",0,0,
			   LOADTYPE_FULL,symbol_read_owned_scope(root));
    symbol->datatype_code = DATATYPE_VOID;

    /* Always put it in its primary symtab, of course -- probably the CU's. */
    symbol_insert_symbol(root,symbol);

    /* And also always put it in the debugfile's global types table. */
    if (!(debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES))
	debugfile_add_type_name(debugfile,symbol_get_name(symbol),symbol);

    return symbol;
}

struct symbol *do_word_symbol(struct debugfile *debugfile,
			      struct symbol *root) {
    struct symbol_root_dwarf *srd = SYMBOLX_ROOT(root)->priv;
    /* symbol_create dups the name, so we just pass a static buf */
    struct symbol *symbol;

    symbol = symbol_get_sym(root,"long unsigned int",SYMBOL_TYPE_FLAG_TYPE);
    if (symbol)
	return symbol;

    symbol = symbol_create(SYMBOL_TYPE_TYPE,SYMBOL_SOURCE_DWARF,
			   "long unsigned int",0,0,LOADTYPE_FULL,
			   symbol_read_owned_scope(root));
    symbol->datatype_code = DATATYPE_BASE;
    symbol_set_bytesize(symbol,srd->addrsize);
    symbol_set_encoding(symbol,ENCODING_UNSIGNED);

    /* RHOLD; this debugfile owns symbol. */
    RHOLD(symbol,debugfile);

    /* Always put it in its primary symtab, of course -- probably the CU's. */
    symbol_insert_symbol(root,symbol);

    /* And also always put it in the debugfile's global types table. */
    if (!(debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES))
	debugfile_add_type_name(debugfile,symbol_get_name(symbol),symbol);

    return symbol;
}

/*
 * If you specify @die_offsets, you can specify that those DIEs should
 * be expanded if they've already been partially loaded, by setting
 * @expand_dies nonzero.
 *
 * XXX: a major bad thing we do is reduce the Dwarf_Off offset to a
 * 32-bit value, instead of a (potential) 64-bit value.  However, doing
 * this saves us lots of struct bytes, and if anybody supplies a
 * debuginfo file > 4GB in size, we're just not going to support it.
 */
static int dwarf_load_cu(struct symbol_root_dwarf *srd,
			 Dwarf_Off *cu_offset,
			 struct array_list *init_die_offsets,int expand_dies) {
    Dwarf *dbg = srd->dbg;
    struct debugfile *debugfile = srd->debugfile;
    struct debugfile_load_opts *dopts = debugfile->opts;
    int retval = 0;
    Dwarf_Off offset = *cu_offset;
    struct attrcb_args args;
    int maxdies = 8;
    int level = 0;
    Dwarf_Die *dies = (Dwarf_Die *)malloc(maxdies*sizeof(Dwarf_Die));
    /*
     * NB: anything we put in the reftab, we place a temporary hold
     * on.  We clean these up before we exit.  We have to do this to
     * do type compression -- so we know which symbols are really
     * unheld and can really be freed, by the end of this function.
     */
    GHashTable *reftab = srd->reftab;
    GHashTableIter iter;
    GSList *iilist;

    struct symbol *root;
    struct scope *root_scope;
    struct symbol **symbols = (struct symbol **) \
	malloc(maxdies*sizeof(struct symbol *));
    struct scope **scopes = (struct scope **) \
	malloc(maxdies*sizeof(struct scope *));

    struct symbol *voidsymbol;
    struct symbol *rsymbol;
    int quick = dopts->flags & DEBUGFILE_LOAD_FLAG_PARTIALSYM;
    load_type_t loadtype = 
	(!quick || expand_dies) ? LOADTYPE_FULL : LOADTYPE_PARTIAL;
    /*
     * XXX: what if we are using a CU symbol created in get_aranges or
     * get_pubnames, and we don't end up hashing the symbol in
     * debugfiles->srcfiles because it doesn't have a name?  What about
     * symbols from aranges or pubnames that aren't in debuginfo?  Those
     * will be leaked.  Ack, don't worry about it for now; that would be
     * a DWARF bug :).
     */
    int root_added = 0;
    int root_preexisting = 0;

    struct array_list *die_offsets = NULL;
    int i;
    struct symbol *tsymbol;
    char *sname;
    int accept;
    gpointer key;
    gpointer value;
    int trefcnt;
    struct scope *specification_scope;
    struct symbol *specification_symbol;
    struct symbol *specification_symbol_parent;

    /*
     * If we only want to load specific die offsets, clone the incoming
     * list so we can append to it as we discover necessary!
     */
    if (init_die_offsets) 
	die_offsets = array_list_clone(init_die_offsets,0);

    /*
     * Set up the root variable.  CU symbols go in two places in
     * the debugfile struct: in ->cuoffsets (with the CU offset as key),
     * and in ->srcfiles (with the CU name as the key).  When they are
     * created in get_aranges, we don't yet know their name, so they are
     * only in ->cuoffsets.  If we see one of these, we know this is the
     * initial load of the CU, and we have to process the CU DIE.
     * Otherwise, we can skip *processing* the CU die -- we still have
     * to load it in dies[].
     */

    root = (struct symbol *)debugfile_lookup_root(debugfile,offset);
    if (!root) {
	vdebug(5,LA_DEBUG,LF_DWARF,
	       "creating new CU symbol at 0x%"PRIx64"!\n",offset);

	/* attr_callback has to fill root, and *MUST* fill at least
	 * the name field; otherwise we can't add the symbol to our hash table.
	 */
	symbols[0] = root = symbol_create(SYMBOL_TYPE_ROOT,SYMBOL_SOURCE_DWARF,
					  NULL,0,(SMOFFSET)offset,loadtype,NULL);
	symbol_set_root_priv(root,srd);
	srd->root = root;
	debugfile_insert_root(debugfile,root);

	/* Set the top-level scope. */
	scopes[0] = root_scope = symbol_write_owned_scope(root);
    }
    else {
	vdebug(5,LA_DEBUG,LF_DWARF,
	       "using existing CU symbol %s (offset 0x%"PRIx64")!\n",
	       symbol_get_name(root),offset);

	/*
	 * Make sure, if we got a root symbol from dwarf_load_aranges,
	 * that it has our metadata recorded, and vice versa.
	 */
	if (!srd->root)
	    srd->root = root;
	if (!SYMBOLX_ROOT(root)->priv)
	    symbol_set_root_priv(root,srd);

	root_preexisting = 1;

	symbols[0] = root;
	/* Get the top-level scope. */
	scopes[0] = root_scope = symbol_write_owned_scope(root);
    }

    /* Set the load type -- the expected, no-errors state :)! */
    if (root->loadtag == LOADTYPE_UNLOADED 
	&& (die_offsets || dopts->flags & DEBUGFILE_LOAD_FLAG_PARTIALSYM))
	root->loadtag = LOADTYPE_PARTIAL;
    else if (root->loadtag == LOADTYPE_PARTIAL 
	     && (die_offsets || dopts->flags & DEBUGFILE_LOAD_FLAG_PARTIALSYM))
	root->loadtag = LOADTYPE_PARTIAL;
    else if (root->loadtag == LOADTYPE_FULL && die_offsets) {
	verror("CU %s (offset 0x%"PRIxSMOFFSET") already fully loaded!\n",
	       root->name,root->ref);
	goto errout;
    }
    else
	root->loadtag = LOADTYPE_FULL;

    /* If we've loaded this one before, we don't want to add it again
     * (which we can only do after processing its DIE attrs, the first
     * time); so say here, don't add it again!
     */
    if (root->name 
	&& (g_hash_table_lookup(debugfile->srcfiles,root->name)
	    || g_hash_table_lookup(debugfile->srcfiles_multiuse,root->name))) {
	root_added = 1;
    }

    /* Either create the void symbol for this CU, or grab it from
     * elsewhere.
     */
    voidsymbol = do_void_symbol(debugfile,root);

    /* Setup our args for attr_callback! */
    args.srd = srd;

    args.level = level;
    args.cu_offset = offset;
    args.have_stmt_list_offset = 0;
    args.stmt_list_offset = 0;

    args.symbol = NULL;
    args.parentsymbol = NULL;
    args.voidsymbol = voidsymbol;

    /* Skip the CU header. */
    offset += srd->cuhl;

    /* If we are doing a partial CU load, we still have to parse the CU
     * DIE's attributes!  So, we have to hold the skip to the first
     * offset in die_offsets until we've done that.
     */

    if (dwarf_offdie(dbg,offset,&dies[level]) == NULL) {
	verror("cannot get DIE at offset %" PRIx64 ": %s\n",
	       offset,dwarf_errmsg(-1));
	goto errout;
    }

    /**
     ** This is the main DIE-processing loop.  Each iteration requires
     ** that dies[level] be set to the next DIE to process.
     **
     ** The steps are:
     **
     **   1) If there was a partial symbol already loaded at this DIE,
     **      we expand its data structure so it is a full symbol.
     **
     **   2) Process the DWARF TAG, and get set up for handling the
     **      TAG's ATs (attributes).  We also make sure to setup scope
     **      hierarchies correctly.
     **
     **   3) Process the attributes.
     **
     **   4) Post-process the TAG and attrs (this must wait until the
     **      attributes have been processed; primarily so that we can
     **      insert symbols into scopes once we know their name).
     **
     **/

    do {
	struct scope *newscope;
	struct symbol *ts;
	int nofinalize;
	int action;
	ADDR highpc;
	int tag;

	offset = dwarf_dieoffset(&dies[level]);
	if (offset == ~0ul) {
	    verror("cannot get DIE offset: %s",dwarf_errmsg(-1));
	    goto errout;
	}

	/* Initialize some defaults for this iteration. */
	args.reloading = 0;
	symbols[level] = NULL;
	newscope = NULL;
	nofinalize = 0;

	/*
	 * If the offset is already in reftab, AND if it's a FULL
	 * symbol, skip to its sibling; don't process either its
	 * attributes nor its children.
	 */
	ts = (struct symbol *) \
	    g_hash_table_lookup(reftab,(gpointer)(uintptr_t)offset);
	if (ts && SYMBOL_IS_FULL(ts)) {
	    /*
	     * This is tricky.  Set up its "parent" if it had one, just
	     * in case the sibling (if we process one) needs it.  WAIT
	     * -- you might think you need to do that, but you don't
	     * because the only way you process a sibling of something
	     * that was already processed is to get to it is to have
	     * already processed its parent in this loop (or loaded
	     * symbols/scopes[level] at level - 1 from reftab in an
	     * earlier iteration of this loop).
	     */
	    symbols[level] = ts;
	    scopes[level] = symbol_containing_scope(ts);
	    vdebug(6,LA_DEBUG,LF_DWARF,
		   "existing reftab symbol (full) %s 0x%"PRIxSMOFFSET";"
		   " skipping to sibling\n",
		   symbol_get_name(ts),ts->ref);
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
	else if (ts && SYMBOL_IS_PARTIAL(ts)) {
	    if (expand_dies) {
		//if (!(dopts->flags & DEBUGFILE_LOAD_FLAG_CUHEADERS
		//	  || dopts->flags & DEBUGFILE_LOAD_FLAG_PUBNAMES)
		//	|| expand_dies) {
		nofinalize = 1;
		symbols[level] = ts;
		scopes[level] = symbol_containing_scope(ts);

		vdebug(6,LA_DEBUG,LF_DWARF,
		       "existing reftab symbol (partial) %s 0x%"PRIxSMOFFSET
		       " on symtab; expanding attrs and children\n",
		       symbol_get_name(ts),ts->ref);

		args.reloading = 1;
	    }
	    else {
		symbols[level] = NULL;
		scopes[level] = symbol_containing_scope(ts);

		vdebug(6,LA_DEBUG,LF_DWARF,
		       "existing reftab symbol (partial) %s 0x%"PRIxSMOFFSET";"
		       " skipping to sibling\n",
		       symbol_get_name(ts),ts->ref);

		goto do_sibling;
	    }
	}

	/*
	 * Otherwise, start processing the DIE.
	 */

	/* We need the tag even if we don't process it at first. */
	tag = dwarf_tag(&dies[level]);

	if (tag == DW_TAG_invalid) {
	    verror("cannot get tag of DIE at offset %" PRIx64 ": %s\n",
		   offset,dwarf_errmsg(-1));
	    goto errout;
	}

	vdebug(4,LA_DEBUG,LF_DWARF,"<%d><%"PRIx64"> %s\n",
	       (int)level,(uint64_t)offset,dwarf_tag_string(tag));

	/**
	 ** NB: any symbols created in TAG processing are placed in the
	 ** reftab, and we take hold a tmp ref on them.  We don't do
	 ** this at symbol_create; we do it after TAG processing.
	 ** Remember, some symbols may already be in the reftab if they
	 ** had already been partially or fully loaded.
	 **
	 ** Also NB: we cannot insert the symbols into their parent
	 ** symbol/scope right away; we have to wait until we process
	 ** their names so they can get inserted by name into symdicts.
	 **
	 ** Also NB: we deliberately do not create a new scope yet even
	 ** if we will create one; we wait to see if we have attributes
	 ** that are attached to the scope first (i.e., range info).
	 ** This avoids creating scopes needlessly for declaration
	 ** symbols!
	 **/

	/**
	 ** TAG processing: Figure out what type of symbol (or scope?)
	 ** to create!
	 **/
	if (tag == DW_TAG_variable
	    || tag == DW_TAG_formal_parameter
	    || tag == DW_TAG_enumerator) {
	    if (!symbols[level]) {
		symbols[level] = 
		    symbol_create(SYMBOL_TYPE_VAR,SYMBOL_SOURCE_DWARF,
				  NULL,0,offset,loadtype,scopes[level]);
		if (tag == DW_TAG_formal_parameter) 
		    symbol_set_parameter(symbols[level]);
		if (tag == DW_TAG_enumerator) {
		    symbol_set_enumval(symbols[level]);
		    
		    /*
		     * Assume the parent for this symbol is the
		     * enumerated datatype... for C/C++ that is the only
		     * way it could be.  So don't even check.
		     *
		     * Yes, this means we don't do type compression for
		     * enumerated types!  See comments near datatype_ref
		     * resolution near the bottom of this function.
		     *
		     * It's important that the datatype get set before
		     * attr processing, because const vals for
		     * enumerators should/must be loaded according to
		     * their datatype.
		     */
		    symbols[level]->datatype = symbols[level-1];
		    symbols[level]->datatype_ref = symbols[level-1]->ref;
		}
	    }
	}
	else if (tag == DW_TAG_member) {
	    if (!symbols[level]) {
		symbols[level] = 
		    symbol_create(SYMBOL_TYPE_VAR,SYMBOL_SOURCE_DWARF,
				  NULL,0,offset,loadtype,scopes[level]);
	    }
	    symbol_set_member(symbols[level]);
	}
	else if (tag == DW_TAG_label) {
	    if (!symbols[level]) {
		symbols[level] = 
		    symbol_create(SYMBOL_TYPE_LABEL,SYMBOL_SOURCE_DWARF,
				  NULL,0,offset,loadtype,scopes[level]);
	    }
	}
	else if (tag == DW_TAG_unspecified_parameters) {
	    if (!symbols[level-1])
		vwarn("cannot handle unspecified_parameters without parent!\n");
	    else if (SYMBOL_IST_FUNC(symbols[level-1])
		     || SYMBOL_IS_FUNC(symbols[level-1])) 
		symbol_set_unspec_params(symbols[level-1]);
	}
	else if (tag == DW_TAG_base_type
		 || tag == DW_TAG_typedef
		 || tag == DW_TAG_pointer_type
		 || tag == DW_TAG_reference_type
		 || tag == DW_TAG_array_type
		 || tag == DW_TAG_structure_type
		 || tag == DW_TAG_enumeration_type
		 || tag == DW_TAG_union_type
		 || tag == DW_TAG_const_type
		 || tag == DW_TAG_volatile_type
		 || tag == DW_TAG_subroutine_type
		 || tag == DW_TAG_class_type
		 || tag == DW_TAG_namespace
		 ) {
	    if (!symbols[level]) {
		symbols[level] = 
		    symbol_create(SYMBOL_TYPE_TYPE,SYMBOL_SOURCE_DWARF,
				  NULL,0,offset,loadtype,scopes[level]);

		switch (tag) {
		case DW_TAG_base_type:
		    symbols[level]->datatype_code = DATATYPE_BASE;     break;
		case DW_TAG_typedef:
		    symbols[level]->datatype_code = DATATYPE_TYPEDEF;  break;
		case DW_TAG_pointer_type:
		    symbols[level]->datatype_code = DATATYPE_PTR;      break;
		case DW_TAG_reference_type:
		    symbols[level]->datatype_code = DATATYPE_REF;      break;
		case DW_TAG_array_type:
		    symbols[level]->datatype_code = DATATYPE_ARRAY;    break;
		case DW_TAG_structure_type:
		    symbols[level]->datatype_code = DATATYPE_STRUCT;   break;
		case DW_TAG_enumeration_type:
		    symbols[level]->datatype_code = DATATYPE_ENUM;     break;
		case DW_TAG_union_type:
		    symbols[level]->datatype_code = DATATYPE_UNION;    break;
		case DW_TAG_const_type:
		    symbols[level]->datatype_code = DATATYPE_CONST;    break;
		case DW_TAG_volatile_type:
		    symbols[level]->datatype_code = DATATYPE_VOL;      break;
		case DW_TAG_subroutine_type:
		    symbols[level]->datatype_code = DATATYPE_FUNC;     break;
		case DW_TAG_class_type:
		    symbols[level]->datatype_code = DATATYPE_CLASS;    break;
		case DW_TAG_namespace:
		    symbols[level]->datatype_code = DATATYPE_NAMESPACE;break;
		default:
		    break;
		}
	    }
	    else if (SYMBOL_IST_CONTAINER(symbols[level])) {
		/*
		 * Make sure we've got it if it exists.  It might exist
		 * even if we did a partial load before, if attributes
		 * required it to be created.
		 */
		newscope = symbol_read_owned_scope(symbols[level]);
	    }
	}
	else if (tag == DW_TAG_subrange_type) {
	    /*
	     * We cheat and don't actually type subranges... we're C
	     * hackers, after all :).
	     */
	    ;
	}
	else if (tag == DW_TAG_subprogram || tag == DW_TAG_inlined_subroutine) {
	    if (!symbols[level]) {
		symbols[level] = 
		    symbol_create(SYMBOL_TYPE_FUNC,SYMBOL_SOURCE_DWARF,
				  NULL,0,offset,loadtype,scopes[level]);
	    }
	    else 
		/*
		 * Make sure we've got it if it exists.  It might exist
		 * even if we did a partial load before, if attributes
		 * required it to be created.
		 */
		newscope = symbol_read_owned_scope(symbols[level]);
	}
	else if (tag == DW_TAG_lexical_block) {
	    /* 
	     * Always build the scope for these things, even if not
	     * fully loading.  Good to get their range attributes.
	     */
	    newscope = scope_create(NULL);
	}
	else if (tag == DW_TAG_compile_unit) {
	    symbols[level] = root;
	}
	else if (tag == DW_TAG_imported_declaration
		 || tag == DW_TAG_template_type_parameter
		 || tag == DW_TAG_template_value_parameter
		 || tag == DW_TAG_imported_module
		 || tag == DW_TAG_inheritance) {
	    vwarnopt(16,LA_DEBUG,LF_DWARF,
		     "known unhandled dwarf tag %s!\n",dwarf_tag_string(tag));
	    symbols[level] = NULL;
	    goto do_sibling;
	}
	else {
	    vwarnopt(3,LA_DEBUG,LF_DWARF,
		     "unknown dwarf tag %s!\n",dwarf_tag_string(tag));
	    symbols[level] = NULL;
	    goto do_sibling;
	}

	/**
	 ** Attribute processing.
	 **/
	args.level = level;
	if (level > 1)
	    args.parentsymbol = symbols[level-1];
	else
	    args.parentsymbol = NULL;
	args.symbol = symbols[level];

	args.lowpc = args.highpc = 0;
	args.lowpc_set = 0;
	args.highpc_set = 0;
	args.highpc_is_offset = 0;
	args.specification_set = 0;
	args.specification_ref = 0;
	args.ranges = NULL;

	args.die_offset = offset;
	(void)dwarf_getattrs(&dies[level],attr_callback,&args,0);

	/**
	 ** Post-attribute processing.
	 **/

	/*
	 * Unmark member 'declaration' flag if the symbol is not also
	 * external.  We do this to avoid marking C++ struct/class
	 * members as declarations if they are not also marked external
	 * (external signals they are static members, and static members
	 * probably will have definitions, so we can leave them as
	 * declarations) -- because a non-static data member of a C/C++
	 * struct/class is, for all practical purposes, a definition
	 * (DWARF Spec v4, p 85).
	 */
	if (symbols[level] && SYMBOL_IS_VAR(symbols[level])
	    && symbols[level]->ismember 
	    && symbols[level]->isdeclaration 
	    && !symbols[level]->isexternal) {
	    vdebug(8,LA_DEBUG,LF_DWARF,
		   "unmarking declaration flag for non-static member!\n");
	    symbols[level]->isdeclaration = 0;
	}

	/*
	 * Figure out if we have a specification declaration we should
	 * try to leverage.
	 *
	 * NB: if we *do* have one, when we link the scope in below, we
	 * need to use specification_scope as the "new_parent" argument
	 * to symbol_link_owned_scope!!!
	 */
	specification_scope = NULL;
	specification_symbol = NULL;
	specification_symbol_parent = NULL;
	if (args.specification_set && symbols[level]) {
	    // XXXX: fix up for partial loads!
	    specification_symbol = (struct symbol *) \
		g_hash_table_lookup(reftab,
				    (gpointer)(uintptr_t)args.specification_ref);
	    if (specification_symbol) {
		specification_scope = 
		    symbol_containing_scope(specification_symbol);
		/*
		 * Change the child's scope.
		 */
		symbols[level]->scope = specification_scope;

		/*
		 * If we're going to shift it for the scope, we have to
		 * change the parent too.
		 */
		specification_symbol_parent = specification_scope->symbol;

		/*
		 * Update the definition with the info from the
		 * declaration insofar as it makes sense.
		 */
		debugfile_define_by_specification(debugfile,
						  specification_symbol,
						  symbols[level]);
	    }
	}

	/*
	 * Handle low_pc/high_pc attrs together.  If we have a scope,
	 * try to update the scope's range(s).  If we have a symbol,
	 * update its base address.
	 */
	if (symbols[level] && args.lowpc_set) 
	    symbol_set_addr(symbols[level],args.lowpc);

	/*
	 * Be careful.  Only try to set a range if the symbol can have
	 * one, or if one was just created (i.e. for a block).
	 */
	if (((symbols[level] && SYMBOL_CAN_OWN_SCOPE(symbols[level]))
	     || newscope)
	    && args.lowpc_set && args.highpc_set) {
	    if (!newscope) 
		newscope = symbol_link_owned_scope(symbols[level],
						   specification_scope);

	    if (args.highpc_is_offset || args.highpc >= args.lowpc) {
		if (!args.highpc_is_offset) 
		    highpc = args.highpc;
		else
		    highpc = args.lowpc + args.highpc;

		action = 0;
		scope_update_range(newscope,args.lowpc,highpc,&action);

		/*
		 * Only update the fast range lookup struct if this is a
		 * CU range or if the user asked for it via the
		 * ALLRANGES flag.
		 */
		if (level == 0 || dopts->flags & DEBUGFILE_LOAD_FLAG_ALLRANGES) {
		    if (action == 1)
			clrange_add(&debugfile->ranges,args.lowpc,highpc,
				    newscope);
		    else if (action == 2)
			clrange_update_end(&debugfile->ranges,args.lowpc,highpc,
					   newscope);
		}
	    }
	    else {
		verror("bad lowpc/highpc (0x%"PRIxADDR",0x%"PRIxADDR")"
		       " at 0x%"PRIxOFFSET"\n",
		       args.lowpc,args.highpc,offset);
	    }
	}
	else if (args.lowpc_set && args.highpc_set) {
	    vwarn("bad context for lowpc/highpc at offset 0x%"PRIxOFFSET"\n",
		  offset);
	}

	/*
	 * Handle AT_ranges, if there was any.  Build and link in the
	 * scope if we need.
	 */
	if (args.ranges
	    && ((symbols[level] && SYMBOL_CAN_OWN_SCOPE(symbols[level]))
		|| newscope)) {
	    struct range *range, *lastr;
	    int action;

	    if (!newscope)
		newscope = symbol_link_owned_scope(symbols[level],
						   specification_scope);

	    range = args.ranges;
	    while (range) {
		action = 0;
		scope_update_range(newscope,range->start,range->end,&action);

		/*
		 * Only update the fast range lookup struct if this is a
		 * CU range or if the user asked for it via the
		 * ALLRANGES flag.
		 */
		if (level == 0 || dopts->flags & DEBUGFILE_LOAD_FLAG_ALLRANGES) {
		    if (action == 1)
			clrange_add(&debugfile->ranges,range->start,range->end,
				    newscope);
		    else if (action == 2)
			clrange_update_end(&debugfile->ranges,
					   range->start,range->end,newscope);
		}
		lastr = range;
		range = range->next;
		free(lastr);
	    }
	    args.ranges = NULL;
	}

	/*
	 * The first time we are not level 0 (i.e., at the CU's DIE),
	 * check that we found a src filename attr; we must have it to
	 * hash the symtab.
	 */
	if (tag == DW_TAG_compile_unit && unlikely(!root_added)) {
	    if (!symbol_get_name(root)) {
		verror("CU did not have a src filename; aborting processing!\n");
		/* Don't free preexisting ones! */
		if (!root_preexisting) 
		    /* This will free the symbol! */
		    debugfile_remove_root(debugfile,root);
		root = NULL;
		goto out;
	    }
	    else {
		if (root_preexisting) {
		    if (debugfile_update_root(debugfile,root)) {
			vwarnopt(2,LA_DEBUG,LF_DWARF,
				 "could not update CU symbol %s to debugfile;"
				 " aborting processing!\n",
				 symbol_get_name(root));
			/* Don't free preexisting ones! */
			//symbol_free(root);
			root = NULL;
			goto out;
		    }
		}
		else if (debugfile_insert_root(debugfile,root)) {
		    vwarnopt(2,LA_DEBUG,LF_DWARF,
			     "could not add CU symbol %s to debugfile;"
			     " aborting processing!\n",
			     symbol_get_name(root));
		    /* This will free the symbol! */
		    debugfile_remove_root(debugfile,root);
		    root = NULL;
		    goto out;
		}
		root_added = 1;
	    }

	    /*
	     * Only check CU load options on the initial load, because
	     * if we have to expand it later, it is because a symbol or
	     * address search required it... and the initial load opts
	     * are meaningless.
	     */
	    if (dopts->flags & DEBUGFILE_LOAD_FLAG_CUHEADERS)
		goto out;
	    if (dopts->flags & DEBUGFILE_LOAD_FLAG_PUBNAMES
		&& (!die_offsets || array_list_len(die_offsets) == 0))
		goto out;
	    /*
	     * If we have regexes for root symbols and this one doesn't
	     * match, skip it!
	     */
	    else if (dopts->srcfile_filter) {
		rfilter_check(dopts->srcfile_filter,symbol_get_name(root),
			      &accept,NULL);
		if (accept == RF_REJECT) {
		    vdebug(3,LA_DEBUG,LF_DWARF,"skipping CU '%s'\n",
			   symbol_get_name(root));
		    goto out;
		}
	    }
	}

	/*
	 * If we have die_offsets to load, and we're not just going to
	 * load the full CU, AND if we have now processed the CU
	 * symbol's attributes, we need to skip to the first DIE in our
	 * list.
	 */
	if (tag == DW_TAG_compile_unit && die_offsets) {
	    if (array_list_len(die_offsets)) {
		i = 0;
		offset = (SMOFFSET)(uintptr_t)array_list_item(die_offsets,i);
		++i;

		/*
		 * So many things key off level == 0 that we set it to 1
		 * deliberately.  Abstractly, we don't know what depth
		 * we're heading for anyway!
		 */
		level = 1;
		if (dwarf_offdie(dbg,offset,&dies[level]) == NULL) {
		    verror("cannot get first DIE at offset 0x%"PRIx64
			   " during partial CU load: %s\n",
			   offset,dwarf_errmsg(-1));
		    goto errout;
		}
		vdebug(5,LA_DEBUG,LF_DWARF,"skipping to first DIE 0x%x\n",offset);
		scopes[level] = scopes[level-1];
		continue;
	    }
	    else {
		/* We're done -- we just wanted to load the CU header. */
		goto out;
	    }
	}

	if (expand_dies && ts && SYMBOL_IS_PARTIAL(ts))
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
	 * We can only do this stuff for C; we cannot for C++ because we
	 * don't check namespaces.  We could only technically share
	 * types within namespaces -- not globally.
	 *
	 * Type compression, part 2 continues below (needed if
	 * DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV is set because we
	 * can't fully check type equivalence until we've loaded this
	 * type and all its children, if any).
	 */
	if (level == 1 && symbols[level] 
	    && SYMBOLX_ROOT(root) 
	    && (SYMBOLX_ROOT(root)->lang_code == DW_LANG_C
		|| SYMBOLX_ROOT(root)->lang_code == DW_LANG_C89
		|| SYMBOLX_ROOT(root)->lang_code == DW_LANG_C99)
	    && SYMBOL_IS_TYPE(symbols[level]) && !SYMBOL_IST_ENUM(symbols[level])
	    && dopts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES
	    && !(dopts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV)
	    && symbol_get_name(symbols[level])) {
	    if ((tsymbol = (struct symbol *) \
		     g_hash_table_lookup(debugfile->shared_types,
					 symbol_get_name(symbols[level])))) {
		if (SYMBOL_IS_TYPE(tsymbol) && !SYMBOL_IST_ENUM(tsymbol)) {
		    /* Insert the looked up symbol into our CU's temp
		     * reftab so that any of our DIEs that tries to use
		     * it gets the "global" one instead.
		     */
		    g_hash_table_insert(reftab,
					(gpointer)(uintptr_t)symbols[level]->ref,
					tsymbol);
		    /*
		     * Anything that goes into our reftab we must RHOLD
		     * on; do that.
		     *
		     * NOTE: hold a ref each time we actually use it;
		     * see below in the datatype_ref resolution code!
		     */
		    RHOLD(tsymbol,reftab);

		    vdebug(4,LA_DEBUG,LF_SYMBOL,
			   "inserted shared symbol (quick check) %s (%s"
			   " 0x%"PRIxSMOFFSET") of type %s at offset 0x%"
			   PRIxSMOFFSET" into reftab\n",
			   symbol_get_name(tsymbol),
			   symbol_get_name_orig(tsymbol),
			   tsymbol->ref,
			   SYMBOL_TYPE(tsymbol->type),symbols[level]->ref);

		    /* Free ourself! */
		    symbol_free(symbols[level],1);
		    symbols[level] = NULL;
		    /* Skip to the next sibling, or to the next DIE if
		     * we're doing a partial CU load.
		     */
		    goto do_sibling;
		}
	    }
	    else if (!symbols[level]->isdeclaration) {
		vdebug(4,LA_DEBUG,LF_SYMBOL,
		       "sharing symbol (quick check) %s (%s) of type %s\n",
		       symbol_get_name(symbols[level]),
		       symbol_get_name_orig(symbols[level]),
		       SYMBOL_TYPE(symbols[level]->type));
		symbols[level]->isshared = 1;
		g_hash_table_insert(debugfile->shared_types,
				    symbol_get_name(symbols[level]),
				    symbols[level]);
		/*
		 * NOTE: hold a ref here for clarity.
		 */
		RHOLD(symbols[level],debugfile);
	    }
	}

	if (symbols[level] 
	    && SYMBOL_IS_INSTANCE(symbols[level]) 
	    && !symbol_get_name_orig(symbols[level])) {
		/* This is actually ok because function type params can
		 * be unnamed, and so can inlined functions.
		 */
		if (!((SYMBOL_IS_FUNC(symbols[level]) 
		       && symbols[level]->isinlineinstance)
		      || (SYMBOL_IS_LABEL(symbols[level]) 
			  && (symbols[level]->isinlineinstance))
		      || (SYMBOL_IS_VAR(symbols[level]) 
			  && (symbols[level]->isinlineinstance
			      || (level > 0 
				  && symbols[level]->isparam
				  && symbols[level-1] 
				  && (SYMBOL_IS_FUNC(symbols[level-1])
				      || SYMBOL_IST_FUNC(symbols[level-1])))
			      || (level > 0 
				  && symbols[level]->ismember
				  && symbols[level-1] 
				  && SYMBOL_IST_CONTAINER(symbols[level-1]))))))
		    vwarnopt(4,LA_DEBUG,LF_DWARF,
			     "anonymous symbol of type %s at DIE 0x%"PRIx64"!\n",
			     SYMBOL_TYPE(symbols[level]->type),offset);
	}

	/*
	 * Add to this CU's reference offset table.  We originally only
	 * did this for types, but since inlined func/param instances
	 * can refer to funcs/vars, we have to do it for every symbol.
	 */
	if (!ts && symbols[level]) {
	    g_hash_table_insert(reftab,
				(gpointer)(uintptr_t)offset,symbols[level]);
	    RHOLD(symbols[level],reftab);
	}

	/*
	 * See if we have a child to process so we can create a scope
	 * for the current symbol if we tried to optimize by not
	 * creating it yet (i.e., if it's a function or
	 * struct/union/classdecl, and has no children, it won't need a
	 * scope, so we save mem).
	 *
	 * Ok, this is knarly.  We need to know if we're going to have a
	 * child.  If so (even if we're not fully loading the DIE this
	 * pass), create the scope and link it in.
	 *
	 * We also do it in this out-of-order way so that we can change
	 * a symbol's scope appropriately if we're going to need to.
	 */

	/* Make room for the next level's DIE.  */
	if (level + 1 == maxdies) {
	    dies = (Dwarf_Die *)realloc(dies,(maxdies += 8)*sizeof(Dwarf_Die));
	    symbols = (struct symbol **) \
		realloc(symbols,maxdies*sizeof(struct symbol *));
	    scopes = (struct scope **) \
		realloc(scopes,maxdies*sizeof(struct scope *));
	}

	int res = dwarf_child(&dies[level],&dies[level + 1]);

	/*
	 * NB: but! first, very important.  If our current symbol
	 * can own a scope, but we didn't have to create it yet, we
	 * must create and link it in now!  We cannot wait for
	 * later.
	 * And, remember from above, to use specification_scope to
	 * handle the case where we're moving this symbol into its
	 * specifier's scope.
	 */
	if (res == 0
	    && symbols[level] && SYMBOL_CAN_OWN_SCOPE(symbols[level])
	    && !newscope) {
	    newscope = 
		symbol_link_owned_scope(symbols[level],specification_scope);
	}

	/*
	 * Make sure we link the newscope into the scope struct.  If we
	 * need to move the symbol onto a different scope (i.e., the one
	 * that contained our specifying declaration), we will do it by
	 * setting teh second arg to symbol_link_owned_scope.
	 *
	 * We might not have a newscope yet, if we didn't need one.  So
	 * -- we also have to check this again if we are going to load
	 * children.  If we are going to load children, we *must* have
	 * setup our owned scope before we process the child.
	 * Otherwise, if we had multiple levels (i.e., function, block,
	 * var, and called tried to insert...
	 */
	//if (newscope && symbols[level]) 
	//    symbol_link_owned_scope(symbols[level],specification_scope);

	/*
	 * Handle adding child symbols/scopes to parents!
	 */
	if (level > 0) {
	    /*
	     * Be careful.  If you have symbol/symbol, must call
	     * symbol_insert_symbol; else you can call
	     * scope_insert_symbol; or scope_insert_scope.
	     * symbol_insert_symbol takes care of allocating
	     * symbol-owned scopes for you.
	     */
	    if (symbols[level]) {
		if (args.specification_set && specification_symbol_parent) 
		    symbol_insert_symbol(specification_symbol_parent,
					 symbols[level]);
		else if (symbols[level-1]) 
		    symbol_insert_symbol(symbols[level-1],symbols[level]);
		else if (scopes[level])
		    scope_insert_symbol(scopes[level],symbols[level]);
		else {
		    verror("symbol(%s:0x%"PRIxSMOFFSET") but no parent to add to!\n",
			   symbol_get_name(symbols[level]),symbols[level]->ref);
		    goto errout;
		}
	    }
	    else if (newscope) {
		if (scopes[level])
		    scope_insert_scope(scopes[level],newscope);
		else {
		    verror("scope at 0x%"PRIx64" has no parent!\n",
			   offset);
		    goto errout;
		}
	    }
	}

	/* The last thing to do is finalize the symbol (which we can do
	 * before processing its children.
	 *
	 * Make sure to pass the new specification_symbol_parent if
	 * there is one!!
	 */
	if (symbols[level] && !nofinalize) {
	    finalize_die_symbol(debugfile,level,symbols[level],
				(specification_symbol_parent) ?: symbols[level-1],
				voidsymbol,
				reftab,die_offsets,(SMOFFSET)*cu_offset);
	    /*
	     * NB: we cannot free the symbol once we are here, because 1) the
	     * symbol is already on our reftab (see above), and 2) the
	     * symbol may have been put on a parent list (see above
	     * block).
	     */
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
	    scopes[level] = root_scope;
	    if (dwarf_offdie(dbg,offset,&dies[level]) == NULL) {
		verror("cannot get DIE %d at offset 0x%"PRIx64
		       " during partial CU (0x%"PRIx64") load: %s\n",
		       i - 1,offset,*cu_offset,dwarf_errmsg(-1));
		return -1;
	    }
	    vdebug(5,LA_DEBUG,LF_DWARF,
		   "skipping to DIE %d at 0x%x in CU 0x%"PRIx64"\n",
		   i,offset,*cu_offset);
	    return 1;
	}

	int res2;
	if (res > 0) {
	    /*
	     * If there are no children, this symbol was fully loaded
	     * even if we didn't try to do that.  So mark it as fully
	     * loaded.
	     */
	    if (symbols[level])
		symbols[level]->loadtag = LOADTYPE_FULL;

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
		    scopes[level] = scopes[level-1];
		else
		    scopes[level] = newscope;
	    }
	    else {
		/* Skip to the next sibling. */
		goto do_sibling;
	    }
	}
    }
    while (level >= 0);

    do_word_symbol(debugfile,root);

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
	     || (dopts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES
		 && !(dopts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV)))
	    && rsymbol->datatype_ref
	    && !rsymbol->isshared) {
	    rsymbol->datatype = (struct symbol *) \
		g_hash_table_lookup(reftab,
				    (gpointer)(uintptr_t)rsymbol->datatype_ref);
	    /* Type compression: if this type is in another CU, hold a
	     * ref to it! 
	     */
	    if (/* *dopts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES
		&& !(dopts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV) */
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
	if (SYMBOL_IS_INLINEABLE(rsymbol)) {
	    SYMBOL_RX_INLINE(rsymbol,sii);

	    if (sii && rsymbol->isinlineinstance) {
		if (!sii->origin && sii->origin_ref) {
		    sii->origin = (struct symbol *)	\
			g_hash_table_lookup(reftab,
					    (gpointer)(uintptr_t)sii->origin_ref);

		    /*
		     * NB NB NB: we cannot have objects referencing each other;
		     * such objects might not get deleted.
		     *
		     * (See comments in common.h about ref usage.)
		     */
		    /*if (sii->origin) {
		     *    RHOLD(sii->origin,rsymbol);
		     *}
		     */
		}

		if (sii->origin) {
		    /* Autoset the instance's datatype attrs! */
		    rsymbol->datatype = sii->origin->datatype;
		    rsymbol->datatype_ref = sii->origin->datatype_ref;
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

	    iilist = (GSList *)g_hash_table_lookup(srd->abstract_origins,
						   (gpointer)(uintptr_t)offset);
	    if (iilist) {
		g_hash_table_remove(srd->abstract_origins,
				    (gpointer)(uintptr_t)offset);
		symbol_set_inline_instances(rsymbol,iilist);
	    }
	}
    }

    /* Type compression part 2a:
     *
     * We go through our entire reftab, again, now that all refs have
     * been resolved and we can do full type equivalence checks (if
     * we're doing DEBUGFILE_LOAD_FLAG_REDUCETYPES and dopts->flags &
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
    if (SYMBOLX_ROOT(root) 
	&& (SYMBOLX_ROOT(root)->lang_code == DW_LANG_C
	    || SYMBOLX_ROOT(root)->lang_code == DW_LANG_C89
	    || SYMBOLX_ROOT(root)->lang_code == DW_LANG_C99)
	&& dopts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV) {
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
                RPUT(rsymbol,symbol,reftab,trefcnt);
                g_hash_table_iter_replace(&iter,NULL);
                continue;
            }

	    if (!(sname = symbol_get_name(rsymbol)))
		continue;

	    if (sname 
		&& (tsymbol = (struct symbol *)				\
		        g_hash_table_lookup(debugfile->shared_types,sname))
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
		    /*
		     * Mark all the symbols that symbol_free would
                     * free as "free next pass" symbols, so that we just
                     * free them and don't process them anymore in our
                     * reftab passes.
                     */
                    symbol_type_mark_members_free_next_pass(rsymbol,0);
		    /*
		     * RPUT() once on rsymbol to remove it from reftab;
		     * and once to remove it from its scope.
		     */
		    scope_remove_symbol(symbol_containing_scope(rsymbol),rsymbol);
		    RPUT(rsymbol,symbol,reftab,trefcnt);
		    continue;
		}
	    }
	    else if (rsymbol != tsymbol && !rsymbol->isdeclaration) {
		/*
		 * Mark it as a shared symbol; then insert it into the
		 * shared_types table.
		 */
		rsymbol->isshared = 1;
		g_hash_table_insert(debugfile->shared_types,sname,rsymbol);
		/*
		 * Hold a ref just because it's in our table.
		 */
		RHOLD(rsymbol,debugfile);
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
    if (SYMBOLX_ROOT(root) 
	&& (SYMBOLX_ROOT(root)->lang_code == DW_LANG_C
	    || SYMBOLX_ROOT(root)->lang_code == DW_LANG_C89
	    || SYMBOLX_ROOT(root)->lang_code == DW_LANG_C99)
	&& dopts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV) {
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
		RPUT(rsymbol,symbol,reftab,trefcnt);
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
	dwarf_get_lines(srd,args.stmt_list_offset);
    }
    else {
	vwarnopt(4,LA_DEBUG,LF_DWARF,
		 "not doing get_lines for offset 0x%"PRIx64"\n",
		 args.stmt_list_offset);
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
    free(symbols);
    free(scopes);

    /*
     * If the CU has been fully loaded or if there was an error, clear
     * out the reftab and abstract_origins tables!
     */
    if (SYMBOL_IS_FULL(root) || retval) {
	g_hash_table_iter_init(&iter,srd->abstract_origins);
	while (g_hash_table_iter_next(&iter,
				      (gpointer *)&key,(gpointer *)&value)) {
	    offset = (uintptr_t)key;
	    iilist = (GSList *)value;
	    vwarnopt(8,LA_DEBUG,LF_DWARF,
		     "did not use abstract_origins for offset 0x%"PRIx64"!\n",
		     offset);
	    /* GHashTable thankfully does not depend on the value pointer
	     * being valid in order to remove items from the hashtable!
	     */
	    g_slist_free(iilist);
	}
	/* Let caller destroy it. */
	g_hash_table_remove_all(srd->abstract_origins);

	/*
	 * Put all the tmp refs we took on reftab symbols.  Some might
	 * be NULL if we employed type compression.
	 */
	g_hash_table_iter_init(&iter,srd->reftab);
	while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&tsymbol)) {
	    if (tsymbol)
		RPUT(tsymbol,symbol,srd->reftab,trefcnt);
	}
	g_hash_table_remove_all(reftab);
    }

    return retval;
}

int dwarf_symbol_expand(struct debugfile *debugfile,
			struct symbol *root,struct symbol *symbol) {
    Dwarf_Off die_offset;
    struct array_list *sal;
    int retval;
    struct symbol_root_dwarf *srd = SYMBOLX_ROOT(root)->priv;

    /* Caller should protect against this, but let's be sure. */
    if (SYMBOL_IS_FULL(symbol) || SYMBOL_IS_FULL(root))
	return 0;

    sal = array_list_create(1);
    die_offset = root->ref;

    array_list_append(sal,(void *)(uintptr_t)symbol->ref);

    vdebug(5,LA_DEBUG,LF_DWARF,
	   "expanding symbol(%s:0x%"PRIxOFFSET") in CU %s\n",
	   symbol_get_name(symbol),die_offset,symbol_get_name(root));

    retval = dwarf_load_cu(srd,&die_offset,sal,1);

    array_list_free(sal);

    /*
     * XXX: NB: we have to do this at the very end, since it is not
     * per-CU.  We can't always guarantee it happened when we unearthed
     * new globals or type definitions, because the datatypes of those
     * symbols may not have been resolved yet.  So, we have to retry
     * this each time we load more content for the debugfile.
     */
    if (!retval)
	debugfile_resolve_declarations(srd->debugfile);

    return retval;
}

int dwarf_symbol_root_expand(struct debugfile *debugfile,struct symbol *root) {
    Dwarf_Off cu_offset = root->ref;
    int rc;
    struct symbol_root_dwarf *srd = SYMBOLX_ROOT(root)->priv;

    if (SYMBOL_IS_FULL(root)) {
	vwarnopt(4,LA_DEBUG,LF_DWARF,
		 "CU %s already fully loaded!\n",symbol_get_name(root));
	return 0;
    }

    vdebug(5,LA_DEBUG,LF_DWARF,
	   "loading entire CU %s (offset 0x%"PRIxOFFSET")!\n",
	   symbol_get_name(root),cu_offset);

    rc = dwarf_load_cu(srd,&cu_offset,NULL,1);

    /*
     * XXX: NB: we have to do this at the very end, since it is not
     * per-CU.  We can't always guarantee it happened when we unearthed
     * new globals or type definitions, because the datatypes of those
     * symbols may not have been resolved yet.  So, we have to retry
     * this each time we load more content for the debugfile.
     */
    if (!rc)
	debugfile_resolve_declarations(srd->debugfile);

    return rc;
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
    struct debugfile_load_opts *dopts = debugfile->opts;
    int rc;
    int retval = 0;
    GHashTable *cu_die_offsets = NULL;
    Dwarf_Off offset = 0;
    struct symbol_root_dwarf *srd;
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

    if (dopts->flags & DEBUGFILE_LOAD_FLAG_PUBNAMES) {
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
	    if (dopts->symbol_filter) {
		rfilter_check(dopts->symbol_filter,(char *)key,
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
	srd = (struct symbol_root_dwarf *)calloc(1,sizeof(*srd));
	srd->debugfile = debugfile;
	srd->dwflmod = dwflmod;
	srd->dbg = dbg;
	srd->addrsize = 0;
	srd->offsize = 0;

#if defined(LIBDW_HAVE_NEXT_UNIT) && LIBDW_HAVE_NEXT_UNIT == 1
	if ((rc = dwarf_next_unit(dbg,offset,&srd->nextcu,&srd->cuhl,
				  &srd->version,&srd->abbroffset,&srd->addrsize,
				  &srd->offsize,NULL,NULL)) < 0) {
	    verror("dwarf_next_unit: %s (%d)\n",dwarf_errmsg(dwarf_errno()),rc);
	    free(srd);
	    goto errout;
	}
	else if (rc > 0) {
	    vdebug(2,LA_DEBUG,LF_DWARF,
		   "dwarf_next_unit returned (%d), aborting successfully.\n",rc);
	    free(srd);
	    goto out;
	}
#else
	if ((rc = dwarf_nextcu(dbg,offset,&srd->nextcu,&srd->cuhl,
			       &srd->abbroffset,&srd->addrsize,&
			       srd->offsize)) < 0) {
	    verror("dwarf_nextcu: %s (%d)\n",dwarf_errmsg(dwarf_errno()),rc);
	    free(srd);
	    goto errout;
	}
	else if (rc > 0) {
	    vdebug(2,LA_DEBUG,LF_DWARF,
		   "dwarf_nextcu returned (%d), aborting successfully.\n",rc);
	    free(srd);
	    goto out;
	}

	vwarnopt(4,LA_DEBUG,LF_DWARF,"assuming DWARF version 4; old elfutils!\n");
	srd->version = 4;
#endif

	/*
	 * Make a reftab for loading the CU.  This is alive until the CU
	 * is fully loaded.  Also, all symbols in it have refs held on
	 * them by the srd->reftab (itself).
	 */
	srd->reftab = g_hash_table_new(g_direct_hash,g_direct_equal);
	srd->abstract_origins = g_hash_table_new(g_direct_hash,g_direct_equal);

	rc = dwarf_load_cu(srd,&offset,die_offsets,0);
	if (rc || SYMBOL_IS_FULL(srd->root)) {
	    /* free the reftab and abstract_origins. */
	    g_hash_table_destroy(srd->reftab);
	    srd->reftab = NULL;
	    g_hash_table_destroy(srd->abstract_origins);
	    srd->abstract_origins = NULL;
	}

	if (rc) {
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
	    offset = srd->nextcu;
	    if (offset == 0) 
		break;
	}
    }

    /*
     * XXX: NB: we have to do this at the very end, since it is not
     * per-CU.  We can't always guarantee it happened when we unearthed
     * new globals or type definitions, because the datatypes of those
     * symbols may not have been resolved yet.  So, we have to retry
     * this each time we load more content for the debugfile.
     */
    debugfile_resolve_declarations(debugfile);

    goto out;

 errout:
    retval = -1;

 out:
    if (dopts->flags & DEBUGFILE_LOAD_FLAG_PUBNAMES) 
	g_hash_table_destroy(cu_die_offsets);
    return retval;
}

/*
 * If we have to change the name of the symbol, we do it IMMEDIATELY
 * after parsing DIE attrs so that naming is consistent for all the
 * hashtable insertions we do!
 */
void finalize_die_symbol_name(struct symbol *symbol) {
    if (symbol->name && !symbol->orig_name_offset
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
void finalize_die_symbol(struct debugfile *debugfile,int level,
			 struct symbol *symbol,
			 struct symbol *parentsymbol,
			 struct symbol *voidsymbol,
			 GHashTable *reftab,struct array_list *die_offsets,
			 SMOFFSET cu_offset) {
    Dwarf_Off die_offset = symbol->ref;
    struct location *loc;

    if (!symbol) {
	verror("null symbol!\n");
	return;
    }

    /*
     * First, handle symbols that need a type.  Declarations don't get a
     * type if they don't have one!
     */
    if (!symbol->isdeclaration 
	&& symbol->datatype == NULL && symbol->datatype_ref == 0) {
	if (SYMBOL_IS_TYPE(symbol)) {
	    /* If it's a valid symbol, and it's not a base type, but doesn't
	     * have a type, make it void!
	     */
	    if (!SYMBOL_IST_BASE(symbol)
		&& (SYMBOL_IST_PTR(symbol)
		    || SYMBOL_IST_TYPEDEF(symbol)
		    /* Not sure if C lets these cases through, but whatever */
		    || SYMBOL_IST_CONST(symbol)
		    || SYMBOL_IST_VOL(symbol)
		    || SYMBOL_IST_FUNC(symbol))) {
		vdebug(3,LA_DEBUG,LF_DWARF,
		       "setting symbol(%s:0x%"PRIxSMOFFSET") type %s"
		       " without type to void\n",
		       symbol->name,symbol->ref,DATATYPE(symbol->datatype_code));
		symbol->datatype = voidsymbol;
	    }
	}
	else if (SYMBOL_IS_FUNC(symbol) || SYMBOL_IS_VAR(symbol)) {
	    vdebug(3,LA_DEBUG,LF_DWARF,
		   "setting symbol(%s:0x%"PRIxSMOFFSET") type %s"
		   " without type to void\n",
		   symbol->name,symbol->ref,DATATYPE(symbol->datatype_code));
	    symbol->datatype = voidsymbol;
	}
    }

    /*
     * Set a member offset of 0 for each union's member.
     */
    if (SYMBOL_IS_VAR(symbol)
	&& parentsymbol && SYMBOL_IST_UNION(parentsymbol)) {
	loc = location_create();
	location_set_member_offset(loc,0);
	symbol_set_location(symbol,loc);
    }

    /*
     * If we have a base_addr for the symbol, insert it into the
     * addresses table.
     */
    if (SYMBOL_IS_INSTANCE(symbol) && symbol_get_name_orig(symbol)) {
	if (symbol_has_addr(symbol)) {
	    g_hash_table_insert(debugfile->addresses,
				(gpointer)(uintptr_t)symbol_get_addr(symbol),
				symbol);
	    vdebug(4,LA_DEBUG,LF_DWARF,
		   "inserted %s %s(0x%"PRIxSMOFFSET") with base_addr 0x%"PRIxADDR
		   " into debugfile addresses table\n",
		   SYMBOL_TYPE(symbol->type),symbol_get_name(symbol),symbol->ref,
		   symbol_get_addr(symbol));
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
	 * scopes.  BUT, for now it seems reasonable because even if
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
	if (SYMBOL_IS_FUNC(symbol)) {
	    SYMBOL_RX_INLINE(symbol,sii);

	    if (symbol->isinlineinstance
		&& sii && !sii->origin && sii->origin_ref
		&& !(sii->origin = (struct symbol *)	\
		         g_hash_table_lookup(reftab,
					     (gpointer)(uintptr_t)sii->origin_ref))) {
		array_list_append(die_offsets,
				  (void *)(uintptr_t)sii->origin_ref);
	    }
	}
    }

    /*
     * Generate names for symbols if we need to; handle declarations; ...
     */
    if (SYMBOL_IS_TYPE(symbol) && symbol_get_name_orig(symbol)) {
	if (parentsymbol && SYMBOL_IS_ROOT(parentsymbol)) {
	    if (!(debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES)
		&& !symbol->isdeclaration)
		debugfile_add_type_name(debugfile,symbol_get_name(symbol),symbol);

	    if (symbol->isdeclaration) 
		debugfile_handle_declaration(debugfile,symbol);
	}
    }
    else if (SYMBOL_IS_INSTANCE(symbol) && symbol_get_name_orig(symbol)) {
	if (parentsymbol && SYMBOL_IS_ROOT(parentsymbol)) {
	    if (!symbol->has_linkage_name 
		&& symbol->isexternal 
		&& !symbol->isdeclaration) 
		debugfile_add_global(debugfile,symbol);
	    else if (symbol->isdeclaration) 
		debugfile_handle_declaration(debugfile,symbol);
	}
    }
    else if (SYMBOL_IS_INSTANCE(symbol) && symbol->isinlineinstance) {
	/* An inlined instance; definitely need it in the symbol
	 * tables.  But we have to give it a name.  And the name *has*
	 * to be unique... so we do our best: 
	 *  __INLINED(<symbol_mem_addr>:(iref<src_sym_dwarf_addr>
         *                               |<src_sym_name))
	 * (we really should use the DWARF DIE addr for easier debug,
	 * but that would cost us 8 bytes more in the symbol struct.)
	 */
	SYMBOL_RX_INLINE(symbol,sii);

	/* XXX: don't give inline instances names?? */

	if (0 && sii) {
	    char *inname;
	    int inlen;
	    if (sii->origin) {
		inlen = 9 + 1 + 18 + 1 + strlen(symbol_get_name_orig(sii->origin)) + 1 + 1;
		inname = malloc(sizeof(char)*inlen);
		sprintf(inname,"__INLINED(ref%"PRIxSMOFFSET":%s)",
			symbol->ref,symbol_get_name_orig(sii->origin));
	    }
	    else {
		inlen = 9 + 1 + 18 + 1 + 4 + 16 + 1 + 1;
		inname = malloc(sizeof(char)*inlen);
		sprintf(inname,"__INLINED(ref%"PRIxSMOFFSET":iref%"PRIxSMOFFSET")",
			symbol->ref,sii->origin_ref);
	    }

	    symbol_set_name(symbol,inname,1);
	    free(inname);
	}
    }
    else if (SYMBOL_IS_VAR(symbol) && symbol->isparam
	     && parentsymbol && SYMBOL_IS_FUNC(parentsymbol) 
	     && parentsymbol->isinlineinstance) {
	/* Sometimes it seems we see unnamed function params that are
	 * not marked as inline instances, BUT have a subprogram parent
	 * that is an inline instance.
	 */
	;
    }
    else if (SYMBOL_IS_VAR(symbol) && (symbol->isparam || symbol->ismember)) {
	/* We allow unnamed params, of course, BUT we don't put them
	 * into the symbol table.  We leave them on the function
	 * symbol/function type to be freed in symbol_free!
	 *
	 * XXX: we only need this for subroutine type formal parameters;
	 * should we make the check above more robust?
	 */
	;
    }

    vdebug(5,LA_DEBUG,LF_SYMBOL,"finalized %s symbol(%s:0x%"PRIxSMOFFSET") %p\n",
	   SYMBOL_TYPE(symbol->type),symbol->name,symbol->ref,symbol);
}

/*
 * Currently broken for nested struct/union resolution, if one of the
 * nested members has the same type as a parent higher up in the nest.
 *
 * So, we don't use it anymore and have moved to a much more
 * straightforward approach.
 */
#if 0
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
#endif

int dwarf_load_pubnames(struct debugfile *debugfile,
			unsigned char *buf,unsigned int len,Dwarf *dbg) {
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

int dwarf_load_aranges(struct debugfile *debugfile,
		       unsigned char *buf,unsigned int len,Dwarf *dbg) {
    struct symbol *root;
    struct scope *cu_scope;
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
	 * Lookup the scope at this offset, or create one if it doesn't
	 * exist yet.
	 */
	root = debugfile_lookup_root(debugfile,offset);
	if (!root) {
	    root = symbol_create(SYMBOL_TYPE_ROOT,SYMBOL_SOURCE_DWARF,NULL,0,
				 (SMOFFSET)offset,LOADTYPE_PARTIAL,NULL);
	    debugfile_insert_root(debugfile,root);
	}
	cu_scope = symbol_write_owned_scope(root);

	while (1) {
	    Dwarf_Word range_address;
	    Dwarf_Word range_length;
	    int action = 0;

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
	    
	    scope_update_range(cu_scope,range_address,
				range_address + range_length,&action);

	    /*
	     * We always populate the debugfile->ranges struct with CU
	     * range info, no matter what the ALLRANGES flag is set to.
	     */
	    if (action == 1)
		clrange_add(&debugfile->ranges,range_address,
			    range_address + range_length,cu_scope);
	    else if (action == 2)
		clrange_update_end(&debugfile->ranges,range_address,
				   range_address + range_length,cu_scope);
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
    struct dwarf_debugfile_info *ddi =
	(struct dwarf_debugfile_info *)debugfile->priv;
    struct debugfile_load_opts *dopts = debugfile->opts;
    struct binfile *binfile = debugfile->binfile;
    struct binfile *binfile_pointing = NULL;
    struct binfile_elf *bfelf = (struct binfile_elf *)binfile->priv;
    struct binfile_elf *bfelf_pointing = NULL;
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

    /*
     * Grab the pointing binfile in case it has section contents that
     * binfile does not.
     */
    binfile_pointing = debugfile->binfile_pointing;
    if (binfile_pointing)
	bfelf_pointing = (struct binfile_elf *)binfile_pointing->priv;

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
	    else if (strcmp(name,".eh_frame") == 0) {
		if (debugfile->frametab) {
		    vwarn("already saw frame section; not processing"
			  " .eh_frame!\n");
		    continue;
		}
		ddi->is_eh_frame = 1;
		ddi->frame_sec_offset = shdr->sh_offset;
		ddi->frame_sec_addr = shdr->sh_addr;
		saveptr = &debugfile->frametab;
		saveptrlen = &debugfile->frametablen;
	    }
	    else if (strcmp(name,".debug_frame") == 0) {
		if (debugfile->frametab) {
		    vwarn("already saw frame section; not processing"
			  " .debug_frame!\n");
		    continue;
		}
		ddi->frame_sec_offset = shdr->sh_offset;
		ddi->frame_sec_addr = shdr->sh_addr;
		saveptr = &debugfile->frametab;
		saveptrlen = &debugfile->frametablen;
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
		verror("cannot get raw data for valid section '%s': %s\n",
		       name,elf_errmsg(-1));
		continue;
	    }
	    else if (!edata->d_buf && edata->d_size) {
		if (bfelf_pointing && bfelf_pointing->elf) {
		    vwarnopt(8,LA_DEBUG,LF_DWARF,
			     "cannot get raw data for valid section '%s': %s;"
			     " trying getdata on the pointing binfile\n",
			     name,elf_errmsg(-1));

		    scn = elf_getscn(bfelf_pointing->elf,i);
		    edata = elf_getdata(scn,NULL);
		    if (!edata) {
			verror("still cannot get data for valid section '%s': %s\n",
			       name,elf_errmsg(-1));
			continue;
		    }
		    else if (!edata->d_buf) {
			vwarn("still cannot get data for valid section '%s' (%d); skipping!\n",
			      name,(int)edata->d_size);
			continue;
		    }
		}
		else {
		    verror("cannot get raw data for valid section '%s': %s;"
			   " could not try getdata on the pointing binfile\n",
			   name,elf_errmsg(-1));
		    continue;
		}
	    }

	    /*
	     * aranges and pubnames are special.  We parse them
	     * *immediately*, using them to setup our CU scopes, which
	     * are then validated and filled in as we parse debuginfo.
	     */
	    if (!saveptr) {
		if (strcmp(name,".debug_aranges") == 0) {
		    dwarf_load_aranges(debugfile,edata->d_buf,edata->d_size,dbg);
		    continue;
		}
		else if (strcmp(name,".debug_pubnames") == 0) {
		    dwarf_load_pubnames(debugfile,edata->d_buf,edata->d_size,dbg);
		    continue;
		}
	    }
	    else {
		/*
		 * We just malloc a big buf now, and then we don't free
		 * anything in scopes or syms that is present in here!
		 */
		*saveptrlen = edata->d_size;
		*saveptr = malloc(edata->d_size);
		memcpy(*saveptr,edata->d_buf,edata->d_size);

		/*
		 * frames is also special, but we need the persistent
		 * copy to stay in memory for on-demand evaluation as we
		 * use debuginfo to load symbols and examine memory.  We
		 * also pre-process it just to create an in-memory index
		 * of DWARF FDEs that can be decoded later, on-demand.
		 */
		if (strcmp(name,".debug_frame") == 0
		    || strcmp(name,".eh_frame") == 0) {
		    dwarf_load_cfa(debugfile,*saveptr,*saveptrlen,dbg);
		}
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
    if (dopts->flags & DEBUGFILE_LOAD_FLAG_PARTIALSYM
	|| dopts->flags & DEBUGFILE_LOAD_FLAG_CUHEADERS
	|| dopts->flags & DEBUGFILE_LOAD_FLAG_PUBNAMES) 
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
int dwarf_load_debuginfo(struct debugfile *debugfile) {
    struct debugfile_load_opts *dopts = debugfile->opts;
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
    if (!(dopts->flags & DEBUGFILE_LOAD_FLAG_PARTIALSYM
	  || dopts->flags & DEBUGFILE_LOAD_FLAG_CUHEADERS
	  || dopts->flags & DEBUGFILE_LOAD_FLAG_PUBNAMES)) {
	dwfl_end(bfelf->dwfl);
	bfelf->dwfl = NULL;
	if (bfi && bfielf && binfile->image) 
	    bfelf->elf = NULL;
    }

    return 0;
}

int dwarf_init(struct debugfile *debugfile) {
    struct dwarf_debugfile_info *ddi;

    if (debugfile->priv)
	return -1;

    ddi = calloc(1,sizeof(*ddi));
    debugfile->priv = ddi;

    return 0;
}

int dwarf_fini(struct debugfile *debugfile) {
    struct dwarf_debugfile_info *ddi;

    if (!debugfile->priv)
	return 0;

    ddi = (struct dwarf_debugfile_info *)debugfile->priv;

    dwarf_unload_cfa(debugfile);

    free(ddi);
    debugfile->priv = NULL;

    return 0;
}

/*
 * Our debugfile ops.
 */
struct debugfile_ops dwarf_debugfile_ops = {
    .init = dwarf_init,
    .load = dwarf_load_debuginfo,
    .symbol_expand = dwarf_symbol_expand,
    .symbol_root_expand = dwarf_symbol_root_expand,
    .fini = dwarf_fini,
};


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
