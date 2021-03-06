/*
 * Copyright (c) 2011, 2012, 2013, 2014 The University of Utah
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
#include "glib_wrapper.h"
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
    Dwarf_Off sibling;

    struct symbol *symbol;
    struct symbol *parentsymbol;
    struct symbol *voidsymbol;

    Dwarf_Off ref;
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
	    specification_set:1,
	    ref_set:1;
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

int dwarf_refuselist_hold(struct symbol_root_dwarf *srd,
			  struct symbol *symbol,SMOFFSET ref) {
    GSList *reflist;

    reflist = (GSList *)g_hash_table_lookup(srd->refuselist,
					    (gpointer)(uintptr_t)ref);
    reflist = g_slist_prepend(reflist,(gpointer)symbol);
    RHOLD(symbol,srd->refuselist);
    g_hash_table_insert(srd->refuselist,(gpointer)(uintptr_t)ref,reflist);

    return 0;
}

int dwarf_refuselist_release(struct symbol_root_dwarf *srd,
			     struct symbol *symbol,SMOFFSET ref) {
    GSList *reflist;
    REFCNT trefcnt;

    reflist = (GSList *)g_hash_table_lookup(srd->refuselist,
					    (gpointer)(uintptr_t)ref);
    if (reflist) {
	reflist = g_slist_remove(reflist,(gpointer)symbol);
	RPUT(symbol,symbol,srd->refuselist,trefcnt);
	g_hash_table_insert(srd->refuselist,(gpointer)(uintptr_t)ref,reflist);
    }

    return 0;
}

GSList *dwarf_refuselist_get(struct symbol_root_dwarf *srd,SMOFFSET ref) {
    return (GSList *)g_hash_table_lookup(srd->refuselist,
					 (gpointer)(uintptr_t)ref);
}

/* Should be called before symbol_free!! */
int dwarf_symbol_refuselist_release_all(struct symbol_root_dwarf *srd,
					struct symbol *symbol) {
    if (symbol->datatype_ref) {
	dwarf_refuselist_release(srd,symbol,symbol->datatype_ref);
	symbol->datatype_ref = 0;
    }

    SYMBOL_RX_INLINE(symbol,sii);
    if (sii && sii->origin_ref) {
	dwarf_refuselist_release(srd,symbol,sii->origin_ref);
	sii->origin_ref = 0;
    }

    return 0;
}

/*
 * This function handles the case when the @refsym at offset @ref has
 * been set for the first time, or changed, for @symbol that was using
 * @ref.  This gives us a chance to update any held pointers for
 * @symbol.
 */
int dwarf_symbol_ref_symbol_changed(struct symbol_root_dwarf *srd,
				    struct symbol *symbol,
				    SMOFFSET ref,struct symbol *refsym) {
    REFCNT trefcnt;

    /*
     * The ref is either a datatype_ref; an origin_ref; or else the ref
     * is on our inline instances list.  If it's the final case, we
     * have to go through the list looking for symbols with @ref, and
     * replacing them in the list with @refsym.
     */
    if (symbol->datatype_ref == ref) {
	vdebug(6,LA_DEBUG,LF_DWARF,"changing datatype for ");
	LOGDUMPSYMBOL(6,LA_DEBUG,LF_DWARF,symbol);
	vdebugc(6,LA_DEBUG,LF_DWARF," from ");
	if (symbol->datatype) {
	    LOGDUMPSYMBOL(6,LA_DEBUG,LF_DWARF,symbol->datatype);
	}
	else {
	    vdebugc(6,LA_DEBUG,LF_DWARF,"NULL");
	}
	vdebugc(6,LA_DEBUG,LF_DWARF," to ");
	LOGDUMPSYMBOL_NL(6,LA_DEBUG,LF_DWARF,refsym);

	/*
	 * Dump the old one; grab the new one.  Be careful to drop refs
	 * if the datatype was a shared one, or if the symbol was
	 * synthetic.  Neither should happen, but just in case...
	 */
	if (symbol->datatype && (symbol->usesshareddatatype 
				 || symbol->issynthetic)) {
	    RPUT(symbol->datatype,symbol,symbol,trefcnt);
	}

	if (refsym->isshared || symbol->issynthetic) {
	    if (refsym->isshared)
		symbol->usesshareddatatype = 1;
	    RHOLD(refsym,symbol);
	}

	symbol->datatype = refsym;
    }
    else {
	SYMBOL_RX_INLINE(symbol,sii);
	if (sii && sii->origin_ref == ref) {
	    vdebug(6,LA_DEBUG,LF_DWARF,"changing origin for ");
	    LOGDUMPSYMBOL(6,LA_DEBUG,LF_DWARF,symbol);
	    vdebugc(6,LA_DEBUG,LF_DWARF," from ");
	    if (sii->origin) {
		LOGDUMPSYMBOL(6,LA_DEBUG,LF_DWARF,sii->origin);
	    }
	    else {
		vdebugc(6,LA_DEBUG,LF_DWARF,"NULL");
	    }
	    vdebugc(6,LA_DEBUG,LF_DWARF," to ");
	    LOGDUMPSYMBOL_NL(6,LA_DEBUG,LF_DWARF,refsym);

	    sii->origin = refsym;

	    vdebug(6,LA_DEBUG,LF_DWARF,
		   "adding instance ");
	    LOGDUMPSYMBOL(6,LA_DEBUG,LF_DWARF,symbol);
	    vdebugc(6,LA_DEBUG,LF_DWARF," to ");
	    LOGDUMPSYMBOL_NL(6,LA_DEBUG,LF_DWARF,refsym);

	    symbol_add_inline_instance(refsym,symbol);

	    /*
	     * NB: don't copy anything from the origin to the instance
	     * anymore; the symbol_* functions do this following
	     * automatically as needed.
	     */
	    /*
	    symbol->datatype = sii->origin->datatype;
	    symbol->datatype_ref = sii->origin->datatype_ref;
	    //memcpy(&symbol->s.ii->l,&symbol->s.ii->origin->s.ii->l,
	    //	   sizeof(struct location));

	    if (symbol->datatype)
		RHOLD(symbol->datatype,sii->origin->dataype);

	    vdebug(4,LA_DEBUG,LF_SYMBOL,
		   "copied datatype %s//%s (0x%"PRIxSMOFFSET")"
		   " for inline instance %s//%s"
		   " (0x%"PRIxSMOFFSET"\n",
		   symbol->datatype ? DATATYPE(symbol->datatype->datatype_code) : NULL,
		   symbol->datatype ? symbol_get_name(symbol->datatype) : NULL,
		   symbol->datatype ? symbol->datatype->ref : 0,
		   SYMBOL_TYPE(symbol->type),symbol_get_name(symbol),
		   symbol->ref);
	    */
	}
    }

    return 0;
}

/*
 * Handle changes to the reftab -- either new symbols, or symbol
 * replacements!  This means that any symbol that had (or would)
 * reference the new/changed symbol needs to adjust its pointer(s).
 */
int dwarf_refuselist_notify_reftab_changed(struct symbol_root_dwarf *srd,
					   SMOFFSET ref,struct symbol *refsym) {
    GSList *uselist;
    GSList *gsltmp;
    struct symbol *symbol;

    uselist = (GSList *) \
	g_hash_table_lookup(srd->refuselist,(gpointer)(uintptr_t)ref);
    if (!uselist)
	return 0;

    v_g_slist_foreach(uselist,gsltmp,symbol) {
	dwarf_symbol_ref_symbol_changed(srd,symbol,ref,refsym);
    }

    return 0;
}

/*
 * Record in the refuselist that we want this datatype_ref; resolve it
 * if possible.
 */
int dwarf_symbol_set_datatype_ref(struct symbol_root_dwarf *srd,
				  struct symbol *symbol,SMOFFSET ref) {
    dwarf_refuselist_hold(srd,symbol,ref);

    symbol->datatype_ref = ref;
    /*
     * Set the datatype symbol if the reftab has it; otherwise, it will
     * get set later!
     */
    symbol->datatype = (struct symbol *) \
	g_hash_table_lookup(srd->reftab,(gpointer)(uintptr_t)ref);

    return 0;
}

/*
 * Record in the refuselist that we want this origin_ref; resolve it
 * if possible.
 */
int dwarf_symbol_set_origin_ref(struct symbol_root_dwarf *srd,
				struct symbol *symbol,SMOFFSET ref) {
    SYMBOL_WX_INLINE(symbol,sii,-1);

    dwarf_refuselist_hold(srd,symbol,ref);

    /*
     * First, setup stuff for the referencing symbol.  Set the origin
     * symbol if the reftab has it; otherwise, it will get set later!
     */
    sii->origin_ref = ref;
    sii->origin = (struct symbol *) \
	g_hash_table_lookup(srd->reftab,(gpointer)(uintptr_t)ref);

    /*
     * Second, setup stuff for the *referenced* symbol.  If the
     * referenced symbol exists, add this symbol as an inline instance
     * now.  If it doesn't exist, we place it on the refuselist too;
     * dwarf_refuselist_notify_reftab_changed() will handle that case
     * when the symbol ref actually is set.
     *
     * Note, then, that we support changing the origin, technically, but
     * it should not ever happen -- origins and instances are pretty
     * firmly linked and should not ever be replaced.  We don't even try
     * to support this case for the inline instances lists.
     */
    if (sii->origin)
	symbol_add_inline_instance(sii->origin,symbol);

    return 0;
}

/*
 * Insert a symbol into the reftab.  This takes care of safely removing
 * whatever symbol is already in it; and notifies any users of the
 * symbol in the refuselist hashtable once the change has been made.
 */
int dwarf_reftab_insert(struct symbol_root_dwarf *srd,
			struct symbol *symbol,SMOFFSET ref) {
    struct symbol *existing;
    REFCNT trefcnt;

    existing = (struct symbol *) \
	g_hash_table_lookup(srd->reftab,(gpointer)(uintptr_t)ref);

    if (existing) {
	if (existing == symbol)
	    return 0;

	RPUT(existing,symbol,srd->reftab,trefcnt);
    }

    g_hash_table_insert(srd->reftab,(gpointer)(uintptr_t)ref,symbol);
    RHOLD(symbol,srd->reftab);

    dwarf_refuselist_notify_reftab_changed(srd,ref,symbol);

    return 0;
}

int dwarf_reftab_replace(struct symbol_root_dwarf *srd,
			 struct symbol *existing,
			 struct symbol *new,SMOFFSET ref,GHashTableIter *iter) {

    REFCNT trefcnt;

    if (existing) {
	if (existing == new)
	    return 0;

	RPUT(existing,symbol,srd->reftab,trefcnt);
    }

    g_hash_table_iter_replace(iter,new);
    RHOLD(new,srd->reftab);

    dwarf_refuselist_notify_reftab_changed(srd,ref,new);

    return 0;
}

static void dwarf_reftab_clean(struct symbol *root,int force) {
    struct symbol_root_dwarf *srd = SYMBOLX_ROOT(root)->priv;
    GHashTableIter iter;
    struct symbol *tsymbol;
    REFCNT trefcnt;

    if (!(SYMBOL_IS_FULL(root) || force))
	return;

    if (!srd->reftab)
	return;

    /*
     * Put all the tmp refs we took on reftab symbols.  Some might
     * be NULL if we employed type compression.
     *
     * If a symbol is still in the refuselist, leave it in the reftab
     * too.  We might still need it!
     */
    g_hash_table_iter_init(&iter,srd->reftab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&tsymbol)) {
	if (!tsymbol)
	    continue;
	else if (force) {
	    ;
	}
	else if (srd->refuselist 
		 && g_hash_table_lookup_extended(srd->refuselist,
						 (gpointer)(uintptr_t)tsymbol->ref,
						 NULL,NULL) == TRUE)
	    continue;

	RPUT(tsymbol,symbol,srd->reftab,trefcnt);
	g_hash_table_iter_remove(&iter);
    }
}

static void dwarf_refuselist_clean(struct symbol *root,int force) {
    struct symbol_root_dwarf *srd = SYMBOLX_ROOT(root)->priv;
    GHashTableIter iter;
    gpointer key,value;
    struct symbol *tsymbol;
    GSList *gsltmp;
    REFCNT trefcnt;

    if (!(SYMBOL_IS_FULL(root) || force))
	return;

    if (!srd->refuselist)
	return;

    /*
     * If the CU has been fully loaded or if there was an error, clear
     * out the reftab and refuselist tables!
     *
     * However, there are a few exceptions.  Any symbol that might have
     * to get replaced with a symbol in another CU we have to leave in
     * place for now!  For now, that's only undefined declarations.  So,
     * go through the refuselist, check for decl key symbols; save
     * those.  Then, however, we can clean out the whole reftab -- we
     * don't need any of that because there are symbols on the
     * refuselist, not refs.
     */
    g_hash_table_iter_init(&iter,srd->refuselist);
    while (g_hash_table_iter_next(&iter,&key,&value)) {
	tsymbol = NULL;
	if (!force) {
	    if (srd->reftab)
		tsymbol = (struct symbol *)				\
		    g_hash_table_lookup(srd->reftab,(gpointer)(uintptr_t)key);
	    if (!(tsymbol && tsymbol->isdeclaration && !tsymbol->decldefined))
		tsymbol = NULL;
	}
	if (force || !tsymbol) {
	    v_g_slist_foreach((GSList *)value,gsltmp,tsymbol) {
		RPUT(tsymbol,symbol,srd->refuselist,trefcnt);
	    }
	    g_slist_free((GSList *)value);
	    g_hash_table_iter_remove(&iter);
	}
    }
}

/*
 * If we get a definition that specifies a declaration, we need to move
 * the @specification into the scope containing @declaration.
 * Basically, we want the definition symbol to actually move into the
 * declaration's scope, from wherever scope it is currently on.
 *
 * But then, it gets even worse.  We basically want anything useful from
 * the declaration to be incorporated into the definition (we won't
 * worry about the other way around for now -- in fact one useful thing
 * to do might be to get rid of the declaration symbol entirely!).  This
 * is tricky.  Here's an example:
 *
 *  <3><28e>: Abbrev Number: 34 (DW_TAG_subprogram)
 *     <28f>   DW_AT_external    : 1
 *     <290>   DW_AT_name        : (indirect string, offset: 0xcf): exception
 *     <294>   DW_AT_artificial  : 1
 *     <295>   DW_AT_declaration : 1
 *     <296>   DW_AT_object_pointer: <0x29a>
 *  <4><29a>: Abbrev Number: 8 (DW_TAG_formal_parameter)
 *     <29b>   DW_AT_type        : <0x2a8>
 *     <29f>   DW_AT_artificial  : 1
 *  <4><2a0>: Abbrev Number: 9 (DW_TAG_formal_parameter)
 *     <2a1>   DW_AT_type        : <0x2f6>
 *
 *
 *  <1><301>: Abbrev Number: 39 (DW_TAG_subprogram)
 *     <302>   DW_AT_specification: <0x28e>
 *     <306>   DW_AT_decl_file   : 1
 *     <307>   DW_AT_decl_line   : 61
 *     <308>   DW_AT_inline      : 2       (declared as inline but ignored)
 *     <309>   DW_AT_object_pointer: <0x311>
 *     <30d>   DW_AT_sibling     : <0x321>
 *  <2><311>: Abbrev Number: 36 (DW_TAG_formal_parameter)
 *     <312>   DW_AT_name        : (indirect string, offset: 0x72): this
 *     <316>   DW_AT_type        : <0x2c7>
 *     <31a>   DW_AT_artificial  : 1
 *  <2><31b>: Abbrev Number: 9 (DW_TAG_formal_parameter)
 *     <31c>   DW_AT_type        : <0x321>
 *
 * and another:
 *
 *  <3><368>: Abbrev Number: 41 (DW_TAG_subprogram)
 *     <369>   DW_AT_external    : 1
 *     <36a>   DW_AT_name        : (indirect string, offset: 0x18d): pushIt
 *     <36e>   DW_AT_decl_file   : 2
 *     <36f>   DW_AT_decl_line   : 10
 *     <370>   DW_AT_MIPS_linkage_name: (indirect string, offset: 0xd9): _ZN2N12N26pushItEi
 *     <374>   DW_AT_type        : <0x1e2>
 *     <378>   DW_AT_declaration : 1
 *  <4><379>: Abbrev Number: 9 (DW_TAG_formal_parameter)
 *     <37a>   DW_AT_type        : <0x1e2>
 *  <1><381>: Abbrev Number: 42 (DW_TAG_subprogram)
 *     <382>   DW_AT_specification: <0x368>
 *     <386>   DW_AT_low_pc      : 0x4009e4
 *     <38e>   DW_AT_high_pc     : 0x400a2e
 *     <396>   DW_AT_frame_base  : 0xc0    (location list)
 *     <39a>   DW_AT_sibling     : <0x3ab>
 *  <2><39e>: Abbrev Number: 43 (DW_TAG_formal_parameter)
 *     <39f>   DW_AT_name        : x
 *     <3a1>   DW_AT_decl_file   : 2
 *     <3a2>   DW_AT_decl_line   : 10
 *     <3a3>   DW_AT_type        : <0x1e2>
 *     <3a7>   DW_AT_location    : 2 byte block: 91 5c     (DW_OP_fbreg: -36)
 *
 *
 * So we can see we need to pull external, name, potentially datatype,
 * ... but that's about it.  What we should really try to do is pull all
 * the settings we don't have set already.
 */
static int dwarf_specify_definition(struct symbol *spec,struct symbol *def) {

    /* Cursory check. */
    if (spec->type != def->type || spec->datatype_code != def->datatype_code)
	return -1;

    /* @name */
    if (spec->name && !def->name) {
	if (spec->name_nofree) {
	    def->name = spec->name;
	    def->name_nofree = spec->name_nofree;
	}
	else {
	    def->name = strdup(spec->name);
	    def->name_nofree = 0;
	}
	def->orig_name_offset = spec->orig_name_offset;
    }
    /* @srcline -- XXX: need to handle this better??? srcfile could be diff. */
    if (!def->srcline)
	def->srcline = spec->srcline;

    /*
     * Various flags.  Basically, we need to handle
     * ismember/isparam/isenumval/isexternal/has_linkage_name/; don't
     * need to handle isshared (because a specified decl will never be
     * defined by a spec ref).
     */
    def->ismember = spec->ismember;
    def->isparam = spec->isparam;
    def->isenumval = spec->isenumval;
    def->isexternal = spec->isexternal;
    def->has_linkage_name = spec->has_linkage_name;

    /* @datatype */
    if (!def->datatype && spec->datatype) {
	def->datatype = spec->datatype;
	if (spec->usesshareddatatype) {
	    def->usesshareddatatype = 1;
	    RHOLD(def->datatype,def);
	}
    }
    if (!def->datatype_ref)
	def->datatype_ref = spec->datatype_ref;
    /* @isexternal */
    if (spec->isexternal)
	def->isexternal = 1;
    /*
     * XXX: hm, don't worry about inline stuff right now.  Instances
     * would be problematic because if they ref the decl, we might not
     * have them all by the time we get here.
     *
     * XXX: constval stuff?
     */
    /* @addr */
    if (spec->has_addr && !def->has_addr) {
	def->has_addr = 1;
	def->addr = spec->addr;
    }
    /* @size */
    if ((spec->size_is_bits || spec->size_is_bytes) 
	&& !def->size_is_bits && !def->size_is_bytes) {
	def->size_is_bits = spec->size_is_bits;
	def->size_is_bytes = spec->size_is_bytes;
	memcpy(&def->size,&spec->size,sizeof(spec->size));
    }

    /*
     * That's it for the core stuff.  Now, don't copy any member info,
     * BUT do check the per-symbol extra info.
     */
    if (SYMBOL_HAS_EXTRA(spec)) {
	if (SYMBOL_IS_FUNC(spec)) {
	    SYMBOL_RX_FUNC(spec,sfr);
	    SYMBOL_WX_FUNC(def,sfw,-1);

	    if (sfr->fbloc && !sfw->fbloc) 
		sfw->fbloc = location_copy(sfr->fbloc);
	    if (sfr->has_entry_pc && !sfw->has_entry_pc) {
		sfw->has_entry_pc = 1;
		sfw->entry_pc = sfr->entry_pc;
	    }
	    if ((sfr->prologue_known || sfr->prologue_guessed) 
		&& !sfw->prologue_known && !sfw->prologue_guessed) {
		sfw->prologue_known = 1;
		sfw->prologue_end = sfr->prologue_end;
	    }
	    if (sfr->epilogue_known && !sfw->epilogue_known) {
		sfw->epilogue_known = 1;
		sfw->epilogue_begin = sfr->epilogue_begin;
	    }
	}
	else if (SYMBOL_IS_VAR(spec)) {
	    SYMBOL_RX_VAR(spec,svr);
	    SYMBOL_WX_VAR(def,svw,-1);

	    if (svr->loc && !svw->loc) 
		svw->loc = location_copy(svr->loc);
	    /*
	     * We should never have to worry about constval copying; if
	     * the specifying "declaration" has a constval, how can
	     * there ever be a "definition" of it?  :)  Hopefully DWARF
	     * generators will honor my reasoning here.
	     */
	}
	else if (SYMBOL_IST_ARRAY(spec)) {
	    if (SYMBOLX_SUBRANGES(spec) && !SYMBOLX_SUBRANGES(def)) {
		SYMBOLX_SUBRANGES(def) = g_slist_copy(SYMBOLX_SUBRANGES(spec));
	    }
	}
	/*
	 * Should not have to worry about any other type information.
	 */
    }

    return 0;
}

int dwarf_specify_definition_attrs(struct symbol_root_dwarf *srd,
				   struct symbol *specification,
				   struct symbol *definition) {
    int rc;

    rc = dwarf_specify_definition(specification,definition);

    vdebug(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,
	   "used specification ");
    LOGDUMPSYMBOL(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,specification);
    vdebugc(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,
	    " to complete definition ");
    LOGDUMPSYMBOL_NL(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,definition);

    return rc;
}

int dwarf_specify_definition_members(struct symbol_root_dwarf *srd,
				     struct symbol *specification,
				     struct symbol *definition) {
    int rc;
    GSList *mlist;
    GSList *nmlist = NULL;
    GSList *tomove = NULL;
    GSList *gsl;
    struct symbol *m,*l;
    int moved = 0;
    int updated = 0;
    struct scope *scope;

    /*
     * If this is a definition that is replacing an earlier declaration,
     * we need to harvest any remaining members in the declaration that
     * need to get moved into the definition.  If any members were
     * specification decls for definition members, they have already
     * been removed.  So we just go through the members remaining in the
     * declaration; check if they already match a member in the
     * definition; and if they don't, move them in.  Otherwise delete
     * them?  Is that safe???
     */

    /*
     * First, we need to process members in order!
     */
    mlist = SYMBOLX_MEMBERS(specification);
    gsl = NULL;
    v_g_slist_foreach(mlist,gsl,m) {
	if (!m->name)
	    continue;

	l = symbol_get_sym(definition,m->name,symbol_to_type_flag_t(m));
	if (!l)
	    tomove = g_slist_append(tomove,m);
	else {
	    dwarf_specify_definition_attrs(srd,m,l);
	    ++updated;
	}
    }

    /*
     * Second, we need to process non-member contained symbols (types
     * are the big things; but even a namespace decl could contain other
     * var/func symbols).
     */
    scope = symbol_read_owned_scope(specification);
    if (scope) 
	nmlist = scope_match_syms(scope,NULL,SYMBOL_TYPE_FLAG_NONE);
    gsl = NULL;
    v_g_slist_foreach(nmlist,gsl,m) {
	if (!m->name)
	    continue;

	l = symbol_get_sym(definition,m->name,symbol_to_type_flag_t(m));
	if (!l)
	    tomove = g_slist_append(tomove,m);
	else {
	    dwarf_specify_definition_attrs(srd,m,l);
	    ++updated;
	}
    }
    if (nmlist)
	g_slist_free(nmlist);

    gsl = NULL;
    v_g_slist_foreach(tomove,gsl,m) {
	symbol_change_parent(specification,m,definition);
	++moved;
    }
    if (tomove)
	g_slist_free(tomove);

    vdebug(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,
	   "used specification ");
    LOGDUMPSYMBOL(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,specification);
    vdebugc(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,
	    " to complete definition (moved %d; updated %d) ",moved,updated);
    LOGDUMPSYMBOL_NL(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,definition);

    return 0;
}

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
	    if (symbol_set_inline_origin(symbol,ref,NULL)) {
		DAW_REF("failed to set inline origin");
		break;
	    }

	    /* Record it as needing resolution in our CU table. */
	    dwarf_symbol_set_origin_ref(srd,symbol,ref);
	}
	else 
	    DAW("bad context");
	break;
    case DW_AT_type:
	if (cbargs->reloading) 
	    break;

	if (ref_set && symbol) {
	    if (SYMBOL_IS_TYPE(symbol)) {
		if (SYMBOL_IST_PTR(symbol) || SYMBOL_IST_TYPEDEF(symbol)
		    || SYMBOL_IST_ARRAY(symbol) || SYMBOL_IST_CONST(symbol)
		    || SYMBOL_IST_VOL(symbol) || SYMBOL_IST_FUNC(symbol)) {
		    dwarf_symbol_set_datatype_ref(srd,symbol,ref);
		}
		else 
		    DAW_REF("bogus: type ref for unknown type symbol");
	    }
	    else {
		dwarf_symbol_set_datatype_ref(srd,symbol,ref);
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
	else if (num_set && symbol->datatype 
		 && symbol_get_bytesize(symbol->datatype) > 0) {
	    symbol_set_constval(symbol,(void *)&num,
				symbol_get_bytesize(symbol->datatype),
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
	if (ref_set)
	    cbargs->sibling = ref;
	else
	    DAW("bad form; expected ref");
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
    case DW_AT_import:
	if (ref_set && !symbol) {
	    cbargs->ref = ref;
	    cbargs->ref_set = 1;
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
#if _INT_ELFUTILS_VERSION >= 155
    case DW_LANG_ObjC:			return "ObjectiveC";
#else
    case DW_LANG_Objc:			return "ObjectiveC";
#endif
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

    vdebug(25,LA_DEBUG,LF_DLOC,"starting (rangetab len %d, offset %d)\n",
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
	    vdebug(25,LA_DEBUG,LF_DLOC,"[%6tx] base address 0x%" PRIxADDR "\n",
		   loffset,end);
	    have_base = 1;
	    base = end;
	}
	else if (begin == 0 && end == 0) {
	    /* End of list entry.  */
	    if (len == 0)
		vwarnopt(25,LA_DEBUG,LF_DLOC,"[%6tx] empty list\n",loffset);
	    else 
		vdebug(25,LA_DEBUG,LF_DLOC,"[%6tx] end of list\n",loffset);
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

    vdebug(25,LA_DEBUG,LF_DLOC,"starting (loctab len %d, offset %d)\n",
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
	    vdebug(25,LA_DEBUG,LF_DLOC,"[%6tx] base address 0x%" PRIxADDR "\n",
		   loffset,end);
	    have_base = 1;
	    base = end;
	}
	else if (begin == 0 && end == 0) {
	    /* End of list entry.  */
	    if (len == 0)
		vwarnopt(24,LA_DEBUG,LF_DWARF | LF_DLOC,
			 "[%6tx] empty list\n",loffset);
	    else 
		vdebug(25,LA_DEBUG,LF_DLOC,"[%6tx] end of list\n");
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
		vwarnopt(24,LA_DEBUG,LF_DWARF | LF_DLOC,
			 "[%6tx] begin (0x%"PRIxADDR") == end (0x%"PRIxADDR")\n",
			 loffset,begin,end);
		goto cont;
	    }

	    vdebug(25,LA_DEBUG,LF_DLOC,
		   "[%6tx] loc expr range(0x%"PRIxADDR",0x%"PRIxADDR") len %hd\n",
		   loffset,begin,end,exprlen);

	    tmploc = dwarf_get_static_ops(srd,(const unsigned char *)readp,
					  exprlen,attr);

	    if (!tmploc) {
		vwarnopt(29,LA_DEBUG,LF_DLOC,
			 "get_static_ops (%d) failed!\n",exprlen);
		goto errout;
	    }
	    else {
		vdebug(25,LA_DEBUG,LF_DLOC,
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
	debugfile_add_type(debugfile,symbol);

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

    /* Always put it in its primary symtab, of course -- probably the CU's. */
    symbol_insert_symbol(root,symbol);

    /* And also always put it in the debugfile's global types table. */
    if (!(debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES))
	debugfile_add_type(debugfile,symbol);

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

    struct symbol *root;
    struct scope *root_scope;
    struct symbol **symbols = (struct symbol **) \
	calloc(maxdies,sizeof(struct symbol *));
    struct scope **scopes = (struct scope **) \
	calloc(maxdies,sizeof(struct scope *));
    struct symbol **imported_modules = (struct symbol **) \
	calloc(maxdies,sizeof(struct symbol *));

    struct symbol *voidsymbol;
    struct symbol *rsymbol;
    int quick = dopts->flags & DEBUGFILE_LOAD_FLAG_PARTIALSYM;
    load_type_t loadtype = 
	(!quick || expand_dies) ? LOADTYPE_FULL : LOADTYPE_PARTIAL;
    Dwarf_Off until_die_offset = 0;
    Dwarf_Die top_level_first_die;
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

    int have_stmt_list_offset = 0;
    Dwarf_Word cu_stmt_list_offset = 0;

    struct array_list *die_offsets = NULL;
    int i;
    int tmplpc;
    struct symbol *tsymbol;
    char *sname;
    int accept;
    gpointer key;
    int trefcnt;
    struct scope *reparent_scope;
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
	srd->debugfile = debugfile;
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
	if (!srd->root) {
	    srd->root = root;
	    srd->debugfile = debugfile;
	}
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

	/* Add to the top_level_dies_offset range list. */
	if (dopts->flags & DEBUGFILE_LOAD_FLAG_PARTIALSYM && level == 1) {
	    /* And don't worry if it's already in the list. */
	    clmatchone_add(&srd->top_level_die_offsets,offset,
			   (void *)(uintptr_t)offset);
	    vdebug(6,LA_DEBUG,LF_DWARF,"added top level DIE 0x%x\n",offset);
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
	    g_hash_table_lookup(srd->reftab,(gpointer)(uintptr_t)offset);
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
	    newscope = scope_create(NULL,offset);
	}
	else if (tag == DW_TAG_compile_unit) {
	    symbols[level] = root;
	}
	else if (tag == DW_TAG_imported_module) {
	    /*
	     * The main work here is to parse the attrs and find the
	     * referenced "module" (C++ namespace, in our case).
	     */
	    ;
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

	args.sibling = 0;
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

	reparent_scope = NULL;

	/*
	 * See if this was an imported module (for our case, a C++ using
	 * directive).  If so, find that module symbol and start using
	 * it as the current scope parent!
	 *
	 * If we haven't seen the imported module ref yet, and we're in
	 * partial symbol mode, go get it first, then do this one.
	 * Otherwise, error -- we do not jump forwards in time for
	 * these.  If we ever see imported modules in advance of their
	 * declarations/definitions, we can try to fix this, but it is
	 * hard because we never jump forward in a non-partial (full)
	 * load; we only linearly traverse and patch up forward refs
	 * later.
	 */
	if (tag == DW_TAG_imported_module) {
	    if (!args.ref_set) {
		verror("no AT_import ref for TAG_imported_module"
		       " at 0x%"PRIxOFFSET"; skipping!\n",offset);
		goto do_sibling;
	    }
	    else if (!(imported_modules[level] = (struct symbol *) \
		       g_hash_table_lookup(srd->reftab,(gpointer)(uintptr_t)args.ref))) {
		if (die_offsets) {
		    vdebug(8,LA_DEBUG,LF_DWARF,
			   "forward ref 0x%"PRIxOFFSET" for TAG_imported_module;"
			   " pushing that in front of us and redoing after\n",
			   offset);
		    /* NB: see setup_skip_to_next_die() for why --i ! */
		    --i;
		    array_list_add_item_at(die_offsets,
					   (void *)(uintptr_t)args.ref,i);
		    /*
		     * This sends us to setup the "next" DIE (the one we
		     * just inserted into the list :)).
		     */
		    goto do_sibling;
		}
		else {
		    vwarn("cannot resolve forward ref 0x%"PRIxOFFSET" for"
			  " TAG_imported_module at 0x%"PRIxOFFSET"; skipping;"
			  " scope hier might be wrong!\n",args.ref,offset);
		    goto do_sibling;
		}
	    }
	    else {
		/*
		 * Ok, imported_modules[level] has our temporary
		 * "parent" namespace; just keep going (or wherever).
		 */
		reparent_scope = symbol_link_owned_scope(imported_modules[level],
							 NULL);
		goto do_sibling;
	    }
	}
	else if (imported_modules[level]) {
	    reparent_scope = symbol_read_owned_scope(imported_modules[level]);

	    /*
	     * Change the child's scope.
	     */
	    if (symbols[level])
		symbols[level]->scope = reparent_scope;

	    vdebug(8,LA_DEBUG,LF_DWARF,
		   "continuing to use imported module scope 0x%"PRIxSMOFFSET
		   " (%s) for new DIE 0x%"PRIxOFFSET"\n",
		   reparent_scope->ref,
		   reparent_scope->symbol ? symbol_get_name(reparent_scope->symbol) : NULL,
		   offset);
	}

	/*
	 * Check if this symbol links back to an earlier declaration via
	 * a specification reference.  If it does, make sure the
	 * declaration is fully loaded, and merge the declaration's
	 * contents into this definition symbol *once it is fully loaded*!
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
		g_hash_table_lookup(srd->reftab,
				    (gpointer)(uintptr_t)args.specification_ref);
	    if (!specification_symbol) {
		/*
		 * XXX: force a load, now!  Load will be partial or
		 * full; but we have to load it now so that attr
		 * processing happens for the decl first, then the
		 * current symbol (the definition).  We could relax
		 * this...
		 */
		;
	    }
	    else {
		specification_scope = 
		    symbol_containing_scope(specification_symbol);

		reparent_scope = specification_scope;

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
		dwarf_specify_definition_attrs(srd,specification_symbol,
					       symbols[level]);

		g_hash_table_insert(srd->spec_reftab,symbols[level],
				    specification_symbol);
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
						   reparent_scope);

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
						   reparent_scope);

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
	    /* Try to find prologue info from line table for this CU. */
	    if (args.have_stmt_list_offset) {
		have_stmt_list_offset = 1;
		cu_stmt_list_offset = args.stmt_list_offset;
	    }

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

	    /* Find the offset of the first top-level (level 1) DIE */
	    if (dwarf_child(&dies[level],&top_level_first_die) == 0)
		srd->first_top_level_die_offset =
		    dwarf_dieoffset(&top_level_first_die);
	    else
		srd->first_top_level_die_offset = 0;
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
		 * Now, if the requested DIE is not one of the
		 * top_level_die_offsets, we have to load the previous
		 * top_level_die_offset instead of the requested DIE.
		 * But if there are *no* top_level_die_offsets, we have
		 * to just keep loading the entire CU if it's not
		 * already loaded.  In this case, we need to clear the
		 * flags that we had setup for the partial load, or
		 * whatever, and load all the DIEs.  I think this can
		 * only happen if PUBNAMES and there are no
		 * AT_siblings.
		 *
		 * Do we fully load the top-level DIE?  Shoot, even if
		 * init_die_offsets, we might still only be partially
		 * loading them.  The flags are not setup to help us
		 * here.  Basically, we have to temporarily change them
		 * to say "load full until you see until_die_offset is
		 * loaded (either partially or fully), then revert to
		 * partial until you finish the DIE".  Crap.
		 */
		until_die_offset = offset;

		ADDR tstart = 0;
		if (srd->top_level_die_offsets
		    && clmatchone_find(&srd->top_level_die_offsets,offset,
				       &tstart) != NULL) {
		    offset = (Dwarf_Off)tstart;

		    vdebug(6,LA_DEBUG,LF_DWARF,
			   "skipping to top level DIE 0x%x to load DIE 0x%x\n",
			   offset,until_die_offset);
		}
		else {
		    /*
		     * All we can do is load the CU until we find the
		     * desired offset.
		     */
		    offset = srd->first_top_level_die_offset;

		    vdebug(6,LA_DEBUG,LF_DWARF,
			   "skipping to first CU top level DIE 0x%x to load DIE 0x%x\n",
			   offset,until_die_offset);
		}

		/*
		 * So many things key off level == 0 that we set it to 1
		 * deliberately.  Abstractly, we don't know what depth
		 * we're heading for anyway!
		 *
		 * Ok, now we know we're going to level 1, always, for
		 * partial symbol loads.
		 */
		level = 1;
		if (dwarf_offdie(dbg,offset,&dies[level]) == NULL) {
		    verror("cannot get first DIE at offset 0x%"PRIx64
			   " during partial CU load: %s\n",
			   offset,dwarf_errmsg(-1));
		    goto errout;
		}
		vdebug(5,LA_DEBUG,LF_DWARF,
		       "skipping to first DIE 0x%x\n",offset);
		scopes[level] = scopes[level-1];
		continue;
	    }
	    else {
		/* We're done -- we just wanted to load the CU header. */
		goto out;
	    }
	}

	/*
	 * Later on, when we decide whether to descend into this
	 * symbol's children or not, we may re-mark this as partial, if
	 * we are looking for a DIE that is not inside this DIE.  But we
	 * don't check that until later -- because it's related to
	 * whether we descend or not -- and we want the check in one
	 * place.  This is the default -- expand to LOADTYPE_FULL.
	 */
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
		    vdebug(4,LA_DEBUG,LF_SYMBOL,
			   "inserting shared symbol (quick check) %s (%s"
			   " 0x%"PRIxSMOFFSET") of type %s at offset 0x%"
			   PRIxSMOFFSET" into reftab\n",
			   symbol_get_name(tsymbol),
			   symbol_get_name_orig(tsymbol),
			   tsymbol->ref,
			   SYMBOL_TYPE(tsymbol->type),symbols[level]->ref);

		    /*
		     * It's not on a scope yet; so no need to remove
		     * it.  Then insert it into the reftab.
		     */
		    //scope_remove_symbol(symbol_containing_scope(symbols[level]),
		    //			symbols[level]);
		    dwarf_reftab_insert(srd,tsymbol,
					(SMOFFSET)symbols[level]->ref);

		    /*
		     * Nobody holds a ref to it yet, except possibly it
		     * referenced another symbol -- so must free it from
		     * refuselists!
		     *
		     * BUT, since reftab had not held on this symbol
		     * yet, only the refuselist had, potentially!  So
		     * hold it quickly; then release; then RPUT.  This
		     * protects us from not freeing if this symbol had
		     * not referenced anyone else (and thus the
		     * refuselist had not held it).
		     */
		    RHOLD(symbols[level],srd);
		    dwarf_symbol_refuselist_release_all(srd,symbols[level]);
		    RPUT(symbols[level],symbol,srd,trefcnt);
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
		/*
		 * Place it in debugfile->types too.
		 */
		debugfile_replace_type(debugfile,symbols[level]);
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
	 *
	 * Don't add the root symbol!  This causes chicken and egg
	 * problems when we remove symbols from the reftab.
	 */
	if (!ts && symbols[level] && level > 0)
	    dwarf_reftab_insert(srd,symbols[level],(SMOFFSET)offset);

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

	/*
	 * Make room for the next level's DIE.
	 *
	 * Also, make sure to NULL out the new values!  This is
	 * important for imported_modules; we don't NULL those out like
	 * we do symbols[] and scopes[]!
	 */
	if (level + 1 == maxdies) {
	    maxdies += 8;
	    dies = (Dwarf_Die *)realloc(dies,maxdies*sizeof(Dwarf_Die));
	    symbols = (struct symbol **) \
		realloc(symbols,maxdies*sizeof(struct symbol *));
	    scopes = (struct scope **) \
		realloc(scopes,maxdies*sizeof(struct scope *));
	    imported_modules = (struct symbol **) \
		realloc(imported_modules,maxdies*sizeof(struct symbol *));

	    for (tmplpc = level + 1; tmplpc < maxdies; ++tmplpc) {
		symbols[tmplpc] = NULL;
		imported_modules[tmplpc] = NULL;
	    }
	}

	int res = dwarf_child(&dies[level],&dies[level + 1]);

	/*
	 * NB: but! first, very important.  If our current symbol
	 * can own a scope, but we didn't have to create it yet, we
	 * must create and link it in now!  We cannot wait for
	 * later.
	 * And, remember from above, to use reparent_scope to
	 * handle the case where we're moving this symbol into its
	 * specifier's or imported module's scope.
	 */
	if (res == 0
	    && symbols[level] && SYMBOL_CAN_OWN_SCOPE(symbols[level])
	    && !newscope) {
	    newscope = 
		symbol_link_owned_scope(symbols[level],reparent_scope);
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
	//    symbol_link_owned_scope(symbols[level],reparent_scope);

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
		if (args.specification_set && specification_symbol_parent) {
		    symbol_insert_symbol(specification_symbol_parent,
					 symbols[level]);
		}
		else if (imported_modules[level]) {
		    symbol_insert_symbol(imported_modules[level],symbols[level]);
		}
		else if (ts) {
		    /*
		     * The symbol already existed, and we're not
		     * changing it, so it's already on the parent.
		     */
		    ;
		}
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
	 * Make sure to pass the new specification_symbol_parent or
	 * imported_modules[level] parent if there is one!!
	 */
	if (symbols[level] && !nofinalize) {
	    struct symbol *finalize_parent;
	    if (specification_symbol_parent)
		finalize_parent = specification_symbol_parent;
	    else if (imported_modules[level]) 
		finalize_parent = imported_modules[level];
	    else if (level > 0 && symbols[level - 1])
		finalize_parent = symbols[level - 1];
	    else
		finalize_parent = NULL;

	    finalize_die_symbol(debugfile,level,symbols[level],
				finalize_parent,
				voidsymbol,
				srd->reftab,die_offsets,(SMOFFSET)*cu_offset);
	    /*
	     * NB: we cannot free the symbol once we are here, because 1) the
	     * symbol is already on our reftab (see above), and 2) the
	     * symbol may have been put on a parent list (see above
	     * block).
	     */
	}

	inline int setup_skip_to_next_die(void) {
	    int alen = array_list_len(die_offsets);
	    struct symbol *sss;

	    /* Maybe skip to the next offset if we haven't already
	     * processed this DIE.
	     */
	    while (1) {
		if (i >= alen) {
		    vdebug(5,LA_DEBUG,LF_DWARF,"end of partial load DIE list!\n");
		    return 0;
		}
		offset = (SMOFFSET)(uintptr_t)array_list_item(die_offsets,i);
		++i;

		sss = (struct symbol *) \
		    g_hash_table_lookup(srd->reftab,(gpointer)(uintptr_t)offset);
		if (!sss || sss->loadtag != LOADTYPE_FULL)
		    break;
		else
		    continue;
	    }

	    /*
	     * Need to do the same as above; skip to the next top-level
	     * DIE and load/expand that.
	     */
	    until_die_offset = offset;

	    ADDR tstart = 0;
	    if (srd->top_level_die_offsets
		&& clmatchone_find(&srd->top_level_die_offsets,offset,
				   &tstart) != NULL) {
		offset = (Dwarf_Off)tstart;

		vdebug(6,LA_DEBUG,LF_DWARF,
		       "skipping to top level DIE 0x%x to load DIE 0x%x\n",
		       offset,until_die_offset);
	    }
	    else {
		offset = srd->first_top_level_die_offset;

		vdebug(6,LA_DEBUG,LF_DWARF,
		       "skipping to first CU top level DIE 0x%x to load DIE 0x%x\n",
		       offset,until_die_offset);
	    }

	    /* So many things key off level == 0 that we set
	     * it to 1 deliberately.
	     *
	     * Ok, now we know we're going to level 1, always, for
	     * partial symbol loads.
	     */
	    level = 1;
	    scopes[level] = root_scope;
	    if (dwarf_offdie(dbg,offset,&dies[level]) == NULL) {
		verror("cannot get DIE %d at offset 0x%"PRIx64
		       " during partial CU (0x%"PRIx64") load: %s\n",
		       i - 1,offset,*cu_offset,dwarf_errmsg(-1));
		return -1;
	    }
	    /*
	     * Clear out all the imported_module statements we might
	     * have seen; we don't want to add any symbols to these
	     * imported scopes erroneously!
	     *
	     * (NB: in general, imported modules are problematic for
	     * partial loads -- yet one more thing that forces us to
	     * parse the full level == 1 of each CU, at the very least.)
	     */
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

	    if (level >= 0 && symbols[level] 
		&& symbols[level]->isdeclaration)
		debugfile_save_declaration(debugfile,symbols[level]);

	do_sibling:
	    /* If we were teleported here, set res just in case somebody
	     * expects it to be valid in this block, if the block ever
	     * gets code that needs it!
	     */
	    res = 1;

	    /*
	     * Complete the symbol.
	     */
	    if (level >= 0 
		&& symbols[level] 
		&& symbols[level]->loadtag == LOADTYPE_FULL) {
		struct symbol *specsym;

		specsym = (struct symbol *)				\
		    g_hash_table_lookup(srd->spec_reftab,symbols[level]);
		if (specsym) {
		    dwarf_specify_definition_members(srd,specsym,symbols[level]);
		    g_hash_table_remove(srd->spec_reftab,symbols[level]);

		    /*
		     * Also, if we're going to replace the declaration
		     * (specification) symbol with its definition, do it.
		     */
		    if (!(dopts->flags & DEBUGFILE_LOAD_FLAG_KEEPDECLS)) {
			struct scope *tscope;
			tscope = symbol_containing_scope(specsym);
			if (tscope && tscope->symbol)
			    symbol_remove_symbol(tscope->symbol,specsym);
			else if (tscope)
			    scope_remove_symbol(tscope,specsym);
			dwarf_symbol_refuselist_release_all(srd,specsym);
		    }
		    dwarf_reftab_insert(srd,symbols[level],specsym->ref);
		}
	    }

	    if (die_offsets && level == 1 && offset > until_die_offset) {
		/* No new child, but possibly a new sibling, so nuke this
		 * level's symbol.  If it was a declaration, let the
		 * library maybe replace it with a definition symbol, or
		 * maybe just copy the info.
		 */
		if (die_offsets && symbols[level] && symbols[level]->name 
		    && symbols[level]->isdeclaration)
		    debugfile_resolve_one_declaration(debugfile,
						      symbols[level]->name);
		symbols[level] = NULL;

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

		    /*
		     * Complete the symbol if it has been fully loaded.
		     */
		    if (level >= 0 
			&& symbols[level] 
			&& symbols[level]->loadtag == LOADTYPE_FULL) {
			struct symbol *specsym;

			specsym = (struct symbol *)			\
			    g_hash_table_lookup(srd->spec_reftab,symbols[level]);
			if (specsym) {
			    dwarf_specify_definition_members(srd,specsym,
							     symbols[level]);
			    g_hash_table_remove(srd->spec_reftab,symbols[level]);

			    /*
			     * Also, if we're going to replace the declaration
			     * (specification) symbol with its definition, do it.
			     */
			    if (!(dopts->flags & DEBUGFILE_LOAD_FLAG_KEEPDECLS)) {
				struct scope *tscope;
				tscope = symbol_containing_scope(specsym);
				if (tscope && tscope->symbol)
				    symbol_remove_symbol(tscope->symbol,specsym);
				else if (tscope)
				    scope_remove_symbol(tscope,specsym);
			    }
			    dwarf_symbol_refuselist_release_all(srd,specsym);
			    dwarf_reftab_insert(srd,symbols[level],specsym->ref);
			}
		    }

		    /* If we're loading a partial CU, if there are more DIEs
		     * we need to load, do them!  We don't process any
		     * siblings at level 1, since that's the level we start
		     * each DIE load in a partial CU load at.
		     */
		    if (die_offsets && oldlevel == 1 && offset > until_die_offset) {
			/* Now that a DIE's children have all been parsed, and
			 * we're leveling up, NULL out this symbol.  If
			 * it was a declaration, let the library maybe
			 * replace it with a definition symbol, or maybe
			 * just copy the info.
			 */
			if (die_offsets && symbols[level] && symbols[level]->name 
			    && symbols[level]->isdeclaration)
			    debugfile_resolve_one_declaration(debugfile,
							      symbols[level]->name);
			symbols[level] = NULL;

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

		    /* Now that a DIE's children have all been parsed,
		     * and we're leveling up, NULL out this symbol.  If
		     * it was a declaration, let the library maybe
		     * replace it with a definition symbol, or maybe
		     * just copy the info.
		     */
		    if (die_offsets && symbols[level] && symbols[level]->name 
			&& symbols[level]->isdeclaration)
			debugfile_resolve_one_declaration(debugfile,
							  symbols[level]->name);
		    symbols[level] = NULL;
		    /*if (symbols[level-1] 
		      && symbols[level-1]->type == SYMBOL_TYPE_FUNCTION 
		      && symtab->parent)
		      symtab = symtab->parent;*/

		    /*
		     * Get rid of the old level's imported_module, if
		     * any; but obviously don't clear
		     * imported_modules[level]; that might still be
		     * relevant to any other DIEs we're still going to
		     * parse in level!
		     */
		    imported_modules[oldlevel] = NULL;
		}

		if (res == -1) {
		    verror("cannot get next DIE: %s\n",dwarf_errmsg(-1));
		    goto errout;
		}
		else if (res == 0 && die_offsets && level == 1 && offset > until_die_offset) {
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
	     *
	     * NB: if this was an enumerated type, we *have* to process
	     * the enumerators now -- because otherwise we'll never load
	     * them unless the user/library later loads the type they
	     * were contained in!
	     */

	    if ((!quick || expand_dies || tag == DW_TAG_enumeration_type) || level < 1 
		|| (until_die_offset && args.sibling && until_die_offset < args.sibling)) {
		++level;
		symbols[level] = NULL;
		if (!newscope)
		    scopes[level] = scopes[level-1];
		else
		    scopes[level] = newscope;
	    }
	    else {
		/* Skip to the next sibling. */
		if (until_die_offset && args.sibling && until_die_offset >= args.sibling) {
		    /*
		     * But first, if there were children we didn't
		     * process because the current DIE's range (to its
		     * sibling) does not contain the until_die_offset we
		     * are looking for, we can mark this as only
		     * partially loaded!
		     */
		    symbols[level]->loadtag = LOADTYPE_PARTIAL;
		}
		goto do_sibling;
	    }
	}
    }
    while (level >= 0);

    do_word_symbol(debugfile,root);

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
	//GHashTable *updated = g_hash_table_new(g_direct_hash,g_direct_equal);
	GSList *klist = g_hash_table_get_keys_slist(srd->reftab);
	GSList *gsltmp;
	GHashTable *eqcache = g_hash_table_new(g_direct_hash,g_direct_equal);

	v_g_slist_foreach(klist,gsltmp,key) {
	    offset = (uintptr_t)key;
	    rsymbol = (struct symbol *) \
		g_hash_table_lookup(srd->reftab,(gpointer)(uintptr_t)offset);
	    if (!rsymbol || !SYMBOL_IS_TYPE(rsymbol) || SYMBOL_IST_ENUM(rsymbol))
		continue;

	    if (!(sname = symbol_get_name(rsymbol)))
		continue;

	    if ((tsymbol = (struct symbol *)				\
		     g_hash_table_lookup(debugfile->shared_types,sname))
		&& rsymbol != tsymbol 
		&& tsymbol->isshared) {
		if (symbol_type_equal(rsymbol,tsymbol,eqcache,NULL) == 0) {
		    vdebug(4,LA_DEBUG,LF_SYMBOL,
			   "inserting shared symbol (slow check) %s (%s"
			   " 0x%"PRIxSMOFFSET") of type %s at offset 0x%"
			   PRIxSMOFFSET" into reftab\n",
			   symbol_get_name(tsymbol),
			   symbol_get_name_orig(tsymbol),
			   tsymbol->ref,SYMBOL_TYPE(tsymbol->type),offset);

		    /*
		     * Insert the looked up symbol into our CU's temp
		     * reftab so that any of our DIEs that tries to use
		     * it gets the "global" one instead.
		     */
		    //g_hash_table_iter_replace(&iter,tsymbol);

		    //g_hash_table_insert(updated,(gpointer)(uintptr_t)offset,
		    //			(gpointer)tsymbol);
		    /*
		     * RPUT() once on rsymbol to remove it from reftab;
		     * and once to remove it from its scope.
		     */
		    dwarf_reftab_insert(srd,tsymbol,offset);
		    dwarf_symbol_refuselist_release_all(srd,rsymbol);
		    scope_remove_symbol(symbol_containing_scope(rsymbol),rsymbol);
		    //RPUT(rsymbol,symbol,srd->reftab,trefcnt);
		}
		else {
		    vdebug(4,LA_DEBUG,LF_SYMBOL,
			   "no shared match for symbol (slow check) %s (%s"
			   " 0x%"PRIxSMOFFSET") of type %s at offset 0x%"
			   PRIxSMOFFSET" into reftab\n",
			   symbol_get_name(rsymbol),
			   symbol_get_name_orig(rsymbol),
			   rsymbol->ref,SYMBOL_TYPE(rsymbol->type),offset);
		}
	    }
	    else if (rsymbol != tsymbol && !rsymbol->isdeclaration) {
		vdebug(4,LA_DEBUG,LF_SYMBOL,
		       "sharing symbol (slow check) %s (%s"
		       " 0x%"PRIxSMOFFSET") of type %s at offset 0x%"
		       PRIxSMOFFSET" into reftab\n",
		       symbol_get_name(rsymbol),symbol_get_name_orig(rsymbol),
		       rsymbol->ref,SYMBOL_TYPE(rsymbol->type),offset);

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
		/*
		 * Place it in debugfile->types too.
		 */
		debugfile_replace_type(debugfile,rsymbol);
	    }
	}
	g_slist_free(klist);
	g_hash_table_destroy(eqcache);
	//g_hash_table_destroy(updated);
    }

    /* Try to find prologue info from line table for this CU. */
    if (have_stmt_list_offset) {
	dwarf_get_lines(srd,cu_stmt_list_offset);
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
    free(imported_modules);

    /*
     * Clean up whatever we can!
     */
    dwarf_refuselist_clean(root,retval ? 1 : 0);
    dwarf_reftab_clean(root,retval ? 1 : 0);

    return retval;
}

int dwarf_symbol_replace(struct debugfile *debugfile,
			 struct symbol *old,struct symbol *new) {
    struct symbol *root;
    struct symbol_root_dwarf *srd;
    struct scope *scope;

    /*
     * Just like for type compression, where we replace one symbol with
     * another symbol from a (likely) different CU, we have to get the
     * root symbol associated with the one we're replacing (the old
     * one), and insert the new symbol into the old symbol's reftab --
     * and then let dwarf_reftab_insert work its magic of replacing any
     * refs and deleting the old symbol.
     */
    root = symbol_find_root(old);
    if (!root) {
	verror("could not find root symbol for old ");
	ERRORDUMPSYMBOL(old);
	verrorc(" replacing with new ");
	ERRORDUMPSYMBOL_NL(new);
	return -1;
    }
    srd = SYMBOLX_ROOT(root)->priv;

    dwarf_reftab_insert(srd,new,old->ref);
    dwarf_symbol_refuselist_release_all(srd,old);
    scope = symbol_containing_scope(old);
    if (scope)
	scope_remove_symbol(scope,old);
    else {
	vwarn("no scope for old ");
	WARNDUMPSYMBOL_NL(old);
    }

    return 0;
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
     * (Ok, the following text is no longer true; we handle resolving
     * declarations dynamically if we're expanding symbols now.)
     *
     * NB: we have to do this at the very end, since it is not
     * per-CU.  We can't always guarantee it happened when we unearthed
     * new globals or type definitions, because the datatypes of those
     * symbols may not have been resolved yet.  So, we have to retry
     * this each time we load more content for the debugfile.
     */
#if 0
    if (!retval)
	debugfile_resolve_declarations(srd->debugfile);
#endif

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
     * (Ok, the following text is no longer true; we handle resolving
     * declarations dynamically if we're expanding symbols now.)
     *
     * NB: we have to do this at the very end, since it is not
     * per-CU.  We can't always guarantee it happened when we unearthed
     * new globals or type definitions, because the datatypes of those
     * symbols may not have been resolved yet.  So, we have to retry
     * this each time we load more content for the debugfile.
     */
#if 0
    if (!rc)
	debugfile_resolve_declarations(srd->debugfile);
#endif

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
	/*
	 * Make a range-searchable list of the top-level die offsets in
	 * this CU.  We have to do this because if we load DIEs out of
	 * order, one DIE may reference another DIE that is in a
	 * different parent hierarchy -- and we might not have loaded
	 * that parent hierarchy!  We could throw in all kinds of
	 * optimizations to try to figure out exactly how many DIEs in
	 * that hierarchy we have to load, but since dwarf_load_cu isn't
	 * well-ordered towards loading individual DIEs and reconciling
	 * their parent hierarchy *after* loading, what we will do is,
	 * when loading a particular referenced DIE, we will fully load
	 * the top-level die containing it.  Again, this is a balance
	 * between simplicity of implementation and runtime speed for
	 * the PARTIALSYM case.
	 *
	 * We create this list like this.  If PARTIALSYM, we build it up
	 * as we come across new top-level DIEs during our in-order
	 * traversal.  If not PARTIALSYM, and (CUHEADERS || PUBNAMES),
	 * we pre-scan the top-level DIEs IFF they have sibling
	 * attributes (but if there are no sibling attributes, we will
	 * just have to expand the whole CU to the one DIE we need!).
	 *
	 * Then, when we want to load a partial symbol at DIE offset X,
	 * we just find the previous top-level DIE to load!
	 */
	srd->top_level_die_offsets = clrangesimple_create();
	srd->refuselist = g_hash_table_new(g_direct_hash,g_direct_equal);
	srd->spec_reftab = g_hash_table_new(g_direct_hash,g_direct_equal);

	rc = dwarf_load_cu(srd,&offset,die_offsets,0);

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

    goto out;

 errout:
    retval = -1;

 out:

    /*
     * This is now dynamically handled for symbol expansion, but we're
     * not doing that here, so do it one final time.
     *
     * XXX: NB: we have to do this at the very end, since it is not
     * per-CU.  We can't always guarantee it happened when we unearthed
     * new globals or type definitions, because the datatypes of those
     * symbols may not have been resolved yet.  So, we have to retry
     * this each time we load more content for the debugfile.
     */
    if (retval == 0) {
	debugfile_resolve_declarations(debugfile);
    }
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
    struct location *loc;

    if (!symbol) {
	verror("null symbol!\n");
	return;
    }

    /*
     * First, handle symbols that need a type.  Declarations don't get a
     * type if they don't have one!
     */
    if (!symbol->isdeclaration && !symbol->isinlineinstance
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
	 * Ok, now we *can* do this, because our symbol expander will
	 * load the containing top-level symbol even if the symbol is a
	 * param, var, or label that is not at level 1!
	 */
	SYMBOL_RX_INLINE(symbol,sii);
	if (symbol->isinlineinstance && sii && sii->origin_ref) {
	    array_list_append(die_offsets,
			      (void *)(uintptr_t)sii->origin_ref);
	}
    }

    /*
     * Generate names for symbols if we need to; handle declarations; ...
     */
    if (SYMBOL_IS_TYPE(symbol) && symbol_get_name_orig(symbol)) {
	if (parentsymbol && SYMBOL_IS_ROOT(parentsymbol)) {
	    if (!(debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_REDUCETYPES)
		&& !symbol->isdeclaration)
		debugfile_add_type(debugfile,symbol);

	    if (0 && symbol->isdeclaration) 
		debugfile_handle_declaration(debugfile,symbol);
	}
    }
    else if (SYMBOL_IS_INSTANCE(symbol) && symbol_get_name_orig(symbol)) {
	if (parentsymbol && SYMBOL_IS_ROOT(parentsymbol)) {
	    if (!symbol->has_linkage_name 
		&& symbol->isexternal 
		&& !symbol->isdeclaration) 
		debugfile_add_global(debugfile,symbol);
	    else if (0 && symbol->isdeclaration) 
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
    int i,ii;
    char *name,*name2;
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
		scn = NULL;
		if (bfelf_pointing && bfelf_pointing->elf) {
		    vwarnopt(8,LA_DEBUG,LF_DWARF,
			     "cannot get raw data for valid section '%s': %s;"
			     " trying getdata on the pointing binfile\n",
			     name,elf_errmsg(-1));

		    for (ii = 0; ii < bfelf_pointing->ehdr.e_shnum; ++ii) {
			shdr = &bfelf_pointing->shdrs[ii];
			scn = elf_getscn(bfelf_pointing->elf,ii);

			if (shdr && shdr->sh_size > 0) { // &&shdr->sh_type != SHT_PROGBITS) {
			    //shdr_mem.sh_flags & SHF_STRINGS) {
			    name2 = elf_strptr(bfelf_pointing->elf,
					       bfelf_pointing->shstrndx,shdr->sh_name);

			    if (strcmp(name,name2) == 0) {
				edata = elf_getdata(scn,NULL);
				if (!edata) {
				    verror("still cannot get data for valid section '%s': %s\n",
					   name,elf_errmsg(-1));
				    scn = NULL;
				    break;
				}
				else if (!edata->d_buf) {
				    vwarn("still cannot get data for valid section '%s' (%d);"
					  " skipping!\n",
					  name,(int)edata->d_size);
				    scn = NULL;
				    break;
				}

				break;
			    }
			}
			scn = NULL;
		    }

		    if (!scn) {
			verror("cannot get raw data for valid section '%s': %s;"
			       " could not getdata on the pointing binfile\n",
			       name,elf_errmsg(-1));
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
    //struct binfile_instance *bfi;
    struct binfile_elf *bfelf;

    if (!(binfile = (struct binfile *)*userdata)) {
	verror("no binfile; bug!?\n");
	return -1;
    }

    //if (!(bfi = binfile->instance)) {
    //	verror("no instance info for binfile %s!\n",binfile->filename);
    //	return -1;
    //}

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
	    /*
	     * XXX: we probably were using a binfile instance that
	     * doesn't correspond exactly to the binfile; but in this
	     * case, we can just pretend that the section didn't get
	     * mapped :).
	     */
	    vwarnopt(12,LA_DEBUG,LF_DWARF,
		     "section %d out of range (%d) in binfile instance %s!\n",
		     shndx,bfielf->num_sections,bfi->filename);
	    tmp = 0;
	    //return -1;
	}
	else
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


int dwarf_symbol_root_priv_free(struct debugfile *debugfile,struct symbol *root) {
    struct symbol_root_dwarf *srd;

    SYMBOL_RX_ROOT(root,sr);
    if (!sr)
	return -1;

    srd = (struct symbol_root_dwarf *)sr->priv;
    if (!srd)
	return -1;

    /*
     * Clean up whatever we can!
     */
    dwarf_refuselist_clean(root,1);
    dwarf_reftab_clean(root,1);

    if (srd->reftab)
	g_hash_table_destroy(srd->reftab);
    if (srd->refuselist)
	g_hash_table_destroy(srd->refuselist);
    if (srd->spec_reftab)
	g_hash_table_destroy(srd->spec_reftab);

    free(srd);
    sr->priv = NULL;

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

extern int dwarf_cfa_read_saved_reg(struct debugfile *debugfile,
				    struct location_ctxt *lctxt,
				    REG reg,REGVAL *o_regval);
extern int dwarf_cfa_read_retaddr(struct debugfile *debugfile,
				  struct location_ctxt *lctxt,
				  ADDR *o_retaddr);

/*
 * Our debugfile ops.
 */
struct debugfile_ops dwarf_debugfile_ops = {
    .init = dwarf_init,
    .load = dwarf_load_debuginfo,
    .symbol_replace = dwarf_symbol_replace,
    .symbol_expand = dwarf_symbol_expand,
    .symbol_root_expand = dwarf_symbol_root_expand,
    .frame_read_saved_reg = dwarf_cfa_read_saved_reg,
    .frame_read_retaddr = dwarf_cfa_read_retaddr,
    .symbol_root_priv_free = dwarf_symbol_root_priv_free,
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
