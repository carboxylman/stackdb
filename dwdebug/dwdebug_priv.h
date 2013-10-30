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

#ifndef __DWDEBUG_PRIV_H__
#define __DWDEBUG_PRIV_H__

#include "dwdebug.h"

#define LOGDUMPSYMBOL(dl,lt,lf,s)					\
    vdebugc((dl),(lt),(lf),						\
	    "symbol(%s,%s,0x%"PRIxSMOFFSET",refcnt=%"PRIiREFCNT")",	\
	    symbol_get_name((s)),SYMBOL_TYPE((s)->type),(s)->ref,(s)->refcnt);

#define LOGDUMPSYMBOL_NL(dl,lt,lf,s)   \
    LOGDUMPSYMBOL((dl),(lt),(lf),(s)); \
    vdebugc((dl),(lt),(lf),"\n");

#define WARNDUMPSYMBOL(s)						\
    vwarnc("symbol(%s,%s,0x%"PRIxSMOFFSET",refcnt=%"PRIiREFCNT")",	\
	    symbol_get_name((s)),SYMBOL_TYPE((s)->type),(s)->ref,(s)->refcnt);

#define WARNDUMPSYMBOL_NL(s) \
    WARNDUMPSYMBOL((s)); \
    vwarnc("\n");

#define WARNOPTDUMPSYMBOL(wl,lt,lf,s)					\
    vwarnoptc(wl,lt,lf,"symbol(%s,%s,0x%"PRIxSMOFFSET",refcnt=%"PRIiREFCNT")", \
	      symbol_get_name((s)),SYMBOL_TYPE((s)->type),(s)->ref,(s)->refcnt);

#define WARNOPTDUMPSYMBOL_NL(wl,lt,lf,s)	\
    WARNOPTDUMPSYMBOL(wl,lt,lf,(s)); \
    vwarnoptc(wl,lt,lf,"\n");

#define ERRORDUMPSYMBOL(s)						\
    verrorc("symbol(%s,%s,0x%"PRIxSMOFFSET",refcnt=%"PRIiREFCNT")",	\
	    symbol_get_name((s)),SYMBOL_TYPE((s)->type),(s)->ref,(s)->refcnt);

#define ERRORDUMPSYMBOL_NL(s) \
    ERRORDUMPSYMBOL((s)); \
    verrorc("\n");


#define LOGDUMPSCOPE(dl,lt,lf,s)					\
    vdebugc((dl),(lt),(lf),						\
	    "scope(%s:0x%"PRIxSMOFFSET",[0x%"PRIxADDR",0x%"PRIxADDR"%s]," \
	    " refcnt=%"PRIiREFCNT")", \
	    ((s)->symbol) ? symbol_get_name((s)->symbol) : "NULL",	\
	    ((s)->symbol) ? (s)->symbol->ref : 0,			\
	    ((s)->range) ? (s)->range->start : 0,			\
	    ((s)->range) ? (s)->range->end : 0,				\
	    ((s)->range && (s)->range->next) ? ",..." : "",(s)->refcnt);

#define LOGDUMPSCOPE_NL(dl,lt,lf,s) \
    LOGDUMPSCOPE((dl),(lt),(lf),(s)); \
    vdebugc((dl),(lt),(lf),"\n");

#define ERRORDUMPSCOPE(s)						\
    verrorc("scope(%s:0x%"PRIxSMOFFSET",[0x%"PRIxADDR",0x%"PRIxADDR"%s]," \
	    " refcnt=%"PRIiREFCNT")", \
	    ((s)->symbol) ? symbol_get_name((s)->symbol) : "NULL",	\
	    ((s)->symbol) ? (s)->symbol->ref : 0,			\
	    ((s)->range) ? (s)->range->start : 0,			\
	    ((s)->range) ? (s)->range->end : 0,				\
	    ((s)->range && (s)->range->next) ? ",..." : "",(s)->refcnt);
 
#define ERRORDUMPSCOPE_NL(s) \
    ERRORDUMPSCOPE((s)); \
    verrorc("\n");

#define WARNDUMPSCOPE(s)						\
    vwarnc( "scope(%s:0x%"PRIxSMOFFSET",[0x%"PRIxADDR",0x%"PRIxADDR"%s]," \
	    " refcnt=%"PRIiREFCNT")", \
	    ((s)->symbol) ? symbol_get_name((s)->symbol) : "NULL",	\
	    ((s)->symbol) ? (s)->symbol->ref : 0,			\
	    ((s)->range) ? (s)->range->start : 0,			\
	    ((s)->range) ? (s)->range->end : 0,				\
	    ((s)->range && (s)->range->next) ? ",..." : "",(s)->refcnt);

#define WARNDUMPSCOPE_NL(s) \
    WARNDUMPSCOPE((s)); \
    verrorc("\n");


#define LOGDUMPLSYMBOL(dl,lt,lf,s) \
    vdebugc((dl),(lt),(lf),						\
	    "lsymbol(%s,%s,0x%"PRIxSMOFFSET";chainlen=%d)",		\
	    symbol_get_name((s)->symbol),SYMBOL_TYPE((s)->symbol->type), \
	    (s)->symbol->ref,array_list_len((s)->chain));

#define LOGDUMPLSYMBOL_NL(dl,lt,lf,s) \
    LOGDUMPLSYMBOL((dl),(lt),(lf),(s)); \
    vdebugc((dl),(lt),(lf),"\n");

#define ERRORDUMPLSYMBOL(s) \
    verrorc("lsymbol(%s,%s,0x%"PRIxSMOFFSET";chainlen=%d)", \
	    symbol_get_name((s)->symbol),SYMBOL_TYPE((s)->symbol->type), \
	    (s)->symbol->ref,array_list_len((s)->chain));

#define ERRORDUMPLSYMBOL_NL(s) \
    ERRORDUMPLSYMBOL((s)); \
    verrorc("\n");

/**
 ** Prototypes.
 **/
struct symbol_root_dwarf;
struct location_ctxt;

/**
 ** Debugfiles.
 **/
/*
 * Each kind of debugfile (i.e., DWARF, ELF) should supply one of these.
 */
struct debugfile_ops {
    int (*init)(struct debugfile *debugfile);
    int (*load)(struct debugfile *debugfile);
    int (*symbol_root_expand)(struct debugfile *debugfile,struct symbol *root);
    int (*symbol_expand)(struct debugfile *debugfile,
			 struct symbol *root,struct symbol *symbol);

    /*
     * Unwinders should basically call location_ctxt_read_retaddr() and
     * location_ctxt_read_cfa() in the current frame; then create the
     * previous frame using the first value as the IP and the second as
     * the stack pointer.  Then it can either call frame_read_all_saved,
     * which will read all saved registers in the current frame -- then
     * it can fill in current_frame + 1.  Alternatively, it can just
     * create the previous frame with IP and SP, and let it be loaded on
     * demand via location_resolve (which calls location_ctxt_read_reg).
     */

    /*
     * Tries to find the saved value of @reg in @lctxt->current_frame by
     * using the current frame's CFA data to get the callee-saved value.
     * If the register was saved in @lctxt->current_frame - N, this
     * function must retrieve that value recursively.
     */
    int (*frame_read_saved_reg)(struct debugfile *debugfile,
				struct location_ctxt *lctxt,
				REG reg,REGVAL *o_regval);
    /*
     * Tries to load all saved values of registers in
     * @lctxt->current_frame by using the current frame's CFA data to
     * get the callee-saved values.  If the register was saved in
     * @lctxt->current_frame - N, this function must retrieve that value
     * recursively.  It places the values directly into @regcache.
     */
    int (*frame_read_all_saved_reg)(struct debugfile *debugfile,
				    struct location_ctxt *lctxt,
				    GHashTable *regcache);
    /*
     * This gets the IP the current_frame will jump to when it returns
     * (the return address).
     */
    int (*frame_read_retaddr)(struct debugfile *debugfile,
			      struct location_ctxt *lctxt,ADDR *o_retaddr);
    /*
     * This gets the frame pointer address of the current_frame (which
     * is also the value of the stack pointer at the call site in the
     * previous frame -- the CFA (call frame address)).
     */
    int (*frame_read_cfa)(struct debugfile *debugfile,
			  struct location_ctxt *lctxt,ADDR *o_cfaaddr);

    int (*fini)(struct debugfile *debugfile);
};

struct debugfile *debugfile_create(debugfile_type_flags_t dtflags,
				   struct binfile *binfile,
				   struct debugfile_load_opts *opts,
				   struct binfile *binfile_pointing);
/* Load DWARF debuginfo into a debugfile. */
int debugfile_load_debuginfo(struct debugfile *debugfile);
/* Load ELF symtab info into a debugfile. */
int debugfile_load_elfsymtab(struct debugfile *debugfile,Elf *elf,
			     char *elf_filename);
loctype_t dwarf_location_resolve(const unsigned char *data,unsigned int len,
				 struct location_ctxt *lctxt,
				 struct symbol *symbol,struct location *o_loc);
struct location *dwarf_get_static_ops(struct symbol_root_dwarf *srd,
				      const unsigned char *data,Dwarf_Word len,
				      unsigned int attr);
struct symbol *debugfile_lookup_root(struct debugfile *debugfile,
				     SMOFFSET offset);
int debugfile_insert_root(struct debugfile *debugfile,struct symbol *symbol);
int debugfile_remove_root(struct debugfile *debugfile,struct symbol *symbol);
int debugfile_update_root(struct debugfile *debugfile,struct symbol *symbol);
int debugfile_add_global(struct debugfile *debugfile,struct symbol *symbol);
struct symbol *debugfile_find_type(struct debugfile *debugfile,
				   char *typename);
int debugfile_add_type_name(struct debugfile *debugfile,
			    char *name,struct symbol *symbol);
void debugfile_handle_declaration(struct debugfile *debugfile,
				  struct symbol *symbol);
void debugfile_resolve_declarations(struct debugfile *debugfile);
int debugfile_define_by_specification(struct debugfile *debugfile,
				      struct symbol *specification,
				      struct symbol *definition);
struct lsymbol *debugfile_lookup_addr__int(struct debugfile *debugfile,ADDR addr);
struct lsymbol *debugfile_lookup_sym__int(struct debugfile *debugfile,
					  char *name,const char *delim,
					  struct rfilter *srcfile_filter,
					  symbol_type_flag_t flags);
struct lsymbol *debugfile_lookup_sym_line__int(struct debugfile *debugfile,
					       char *filename,int line,
					       SMOFFSET *offset,ADDR *addr);
REFCNT debugfile_free(struct debugfile *debugfile,int force);

/**
 ** DWARF debugfile backend API stuff.
 **/
extern struct debugfile_ops dwarf_debugfile_ops;

struct dwarf_debugfile_info {
    /*
     * If this debugfile's DWARF CFA was plain old DWARF CFA, then
     * is_eh_frame is not set; if it was the special eh_frame encoding,
     * then it is set.
     */
    uint8_t is_eh_frame:1;

    /*
     * Easier to stash this here.
     */
    uint64_t frame_sec_offset;
    uint64_t frame_sec_addr;

    /*
     * Our CFA strategy is designed to support caching a scan of the
     * frame information; storing pointers to per-segment CFA info
     * (cached in @frametab above) starting at certain addresses;
     * and later decoding those bytes and placing them in another hash.
     *
     * The DWARF functions pre-scan all the CIEs and FDEs in the
     * .(debug|eh)_frame section; fully decoding each CIE and placing
     * its offset/decoding in @cfa_cie; and placing the FDE's start addr
     * and a pointer to the FDE data within @frametab in
     * @frame_pointers; when we need to decode, the DWARF functions
     * place decodings of the pointed-to FDEs in @frame_fde.
     *
     * NB: Well, it turns out we cannot just read the start addr out of
     * each FDE; gcc liberally uses augmentations and thus we must
     * sometimes use CIE info to compute the FDE.  So -- we just go
     * ahead and parse the whole FDE for now, EXCEPT for the CFA
     * program.
     */
    GHashTable *cfa_cie;
    GHashTable *cfa_fde;
};

/**
 ** Lookup symbols (lsymbols).
 **/
/*
 * Creates an lsymbol data structure and takes references to all its
 * symbols.  Users should never call this function.
 *
 * This function takes a ref to each symbol in @chain, BUT NOT to
 * @return.
 */
struct lsymbol *lsymbol_create(struct symbol *symbol,struct array_list *chain);
/*
 * Add another symbol to the end of our lookup chain and make it the
 * primary symbol (i.e, @lsymbol->symbol = symbol), and hold a ref on
 * @symbol.  Users should not need to call this.
 */
void lsymbol_append(struct lsymbol *lsymbol,struct symbol *symbol);
/*
 * Add a symbol to the start of our lookup chain and hold a ref on
 * @symbol.  Users should not need to call this.
 */
void lsymbol_prepend(struct lsymbol *lsymbol,struct symbol *symbol);
/*
 * Takes references to the symbols on the lsymbol chain!.  Users should
 * never call this function unless they call lsymbol_create*(); the
 * lookup functions return lsymbols that have been held.  The user
 * should only call lsymbol_release on them.
 */
void lsymbol_hold_int(struct lsymbol *lsymbol);
/*
 * These functions take refs to each symbol in the lsymbol they create,
 * BUT NOT to @return (call lsymbol_hold() to get that ref).
 */

struct lsymbol *lsymbol_lookup_sym__int(struct lsymbol *lsymbol,
					const char *name,const char *delim);
struct lsymbol *lsymbol_create_from_member__int(struct lsymbol *parent,
						struct symbol *member);
struct lsymbol *lsymbol_create_from_symbol__int(struct symbol *symbol);
struct lsymbol *lsymbol_create_noninline__int(struct lsymbol *lsymbol);

static inline int lsymbol_len(struct lsymbol *lsymbol) {
    return array_list_len(lsymbol->chain);
}
static inline struct symbol *lsymbol_last_symbol(struct lsymbol *lsymbol) {
    if (array_list_len(lsymbol->chain) > 0)
	return (struct symbol *) \
	    array_list_item(lsymbol->chain,array_list_len(lsymbol->chain) - 1);
    else
	return NULL;
}
static inline struct symbol *lsymbol_symbol(struct lsymbol *lsymbol,int i) {
    return (struct symbol *)array_list_item(lsymbol->chain,i);
}

/*
 * Releases references to the symbols on the chain and tries to free the
 * lsymbol (not the underlying symbols!).
 */
REFCNT lsymbol_free(struct lsymbol *lsymbol,int force);


/**
 ** Symbol dictionaries (symdicts).
 **/
/*
 * Symdicts are unfortunate.  Some languages allow for different kinds
 * of symbols with the same name in the same scope/block/whatever.  Some
 * languages allow for unnamed symbols too!  So, symdicts have to
 * account for all these possibilities because they are designed to be
 * symbol containers for scopes, or for symbols containing nested
 * symbols (but not necessarily in a scope).  Maybe we could improve
 * this later...
 */
struct symdict {
    /* 
     * This hashtable stores only *named* symbols that existed in this
     * scope.  If the symbol exists multiple times in this symdict, then
     * it is not in this table, but rather in duptab below.  If we have
     * to insert a symbol already present in this table, we create a
     * list and move it to the duptab.
     *
     * h(sym) -> struct symbol *
     */
    GHashTable *tab;

    /* 
     * This hashtable stores lists of duplicate symbols in this symdict.
     *
     * h(sym) -> struct array_list * (struct symbol *)
     */
    GHashTable *duptab;

    /* 
     * This hashtable stores only *unnamed* symbols that existed in this
     * scope.  These are probably mostly types.
     *
     * h(addr) -> struct symbol * 
     */
    GHashTable *anontab;
};

/**
 ** Refcnt rules for debugfiles, binfiles, scopes, and symbols:
 **
 ** 1) debugfiles/binfiles only hold on their root symbol;
 ** 2) scopes hold symbols inserted into them;
 ** 3) scopes hold scopes inserted into them (including for symbols
 **    inserted into them);
 ** 4) symbols hold on scopes they own;
 ** 5) symbols DO NOT hold on their datatype unless it is shared; and NOT the
 **    symbols in their scope (the scope holds those).
 ** 6) definitions/inlines...
 **/

struct symdict *symdict_create(void);
int symdict_get_size_simple(struct symdict *symdict);
int symdict_get_size(struct symdict *symdict);
int symdict_get_size_named(struct symdict *symdict);
int symdict_get_sizes(struct symdict *symdict,int *named,int *duplicated,int *anon);
int symdict_insert_symbol(struct symdict *symdict,struct symbol *symbol);
int symdict_insert_symbol_anon(struct symdict *symdict,struct symbol *symbol);
struct symbol *symdict_get_sym(struct symdict *symdict,const char *name,
			       symbol_type_flag_t flags);
GSList *symdict_match_syms(struct symdict *symdict,struct rfilter *symbol_filter,
			   symbol_type_flag_t flags);
/*
 * Removes @symbol from @symdict.  Returns 0 if success; -1 if error.
 */
int symdict_remove_symbol(struct symdict *symdict,struct symbol *symbol);
void symdict_dump(struct symdict *symdict,struct dump_info *ud);
typedef void (*symdict_symbol_dtor_t)(struct symbol *symbol);
extern symdict_symbol_dtor_t default_symdict_symbol_dtor;
void symdict_free(struct symdict *symdict,symdict_symbol_dtor_t ssd);


/**
 ** Scopes.
 **/

/*
 * In general, ranges can be either a single range or a list.  After
 * experience, we elect to encode both in a single struct.  We do waste
 * the @next pointer if the range is a singleton; but it simplifies the
 * code significantly and save us from keeping an array list, or from
 * using a heavyweight GSList.  Since users never should see these
 * things, we don't really care how they're implemented inside.
 */
struct range {
    ADDR start;
    ADDR end;
    struct range *next;
};

/*
 * A symbol's scope may be only a name scope, or it may be a name scope
 * PLUS a block (code) scope.  Block scopes can have anonymous children;
 * this is how unnamed blocks are represented.  A scope may have been
 * created for a symbol, or for a block of code.  This is the right
 * abstraction to support lots of languages.  It was tricky to get it
 * right.  Sometimes we need a block scope hierarchy to search; and
 * sometimes we need a symbol name scope hierarchy to search.  If we are
 * searching through a scope hierarchy, we need to know what symbol is
 * associated with the scope, sometimes.
 */
struct scope {
    /* Our refcnt. */
    REFCNT refcnt;
    /* Our weak reference count. */
    //REFCNT refcntw;

    /* If this scope is owned by a symbol, @symbol is that owner. */
    struct symbol *symbol;

    /* If this scope has members, this is the symdict containing them. */
    struct symdict *symdict;

    /*
     * Any block scope should have at least one range associated with it.
     */
    struct range *range;

    /*
     * If this scope is a child, this is its parent.
     */
    struct scope *parent;

    /*
     * If this scope has subscopes, this list is the scopes for each
     * subscope.  Of course, each subscope could have more children.  We
     * use a GSList because deletes are rare; they only happen if we
     * change which parent a subscope is on).
     */
    GSList *subscopes;
};

struct scope *scope_create(struct symbol *owner);
int scope_insert_symbol(struct scope *scope,struct symbol *symbol);
int scope_remove_symbol(struct scope *scope,struct symbol *symbol);
int scope_insert_scope(struct scope *parent,struct scope *child);
int scope_remove_scope(struct scope *parent,struct scope *child);
/*
 * Since we can get scope info from multiple places (i.e.,
 * .debug_aranges, and from .debug_info), we need to be able to update
 * 1) the scope's ranges, and 2) the debugfile's ranges lookup data
 * struct.  This function handles adding a new range, or updating an old
 * one whose end address may have changed (i.e., dwarf inconsistencies).
 *
 * If you supply @action, we set it to 1 if the range was newly added; 2
 * if the start matched but the end did not; 0 if nothing was changed.
 */
void scope_update_range(struct scope *scope,ADDR start,ADDR end,int *action);

static inline struct symbol *scope_get_symbol(struct scope *scope) {
    return scope->symbol;
}
struct symbol *scope_get_sym(struct scope *scope,const char *name,
			     symbol_type_flag_t flags);
int scope_contains_addr(struct scope *scope,ADDR addr);
struct lsymbol *scope_lookup_sym(struct scope *scope,
				 const char *name,const char *delim,
				 symbol_type_flag_t flags);
void scope_dump(struct scope *scope,struct dump_info *ud);
int scope_get_sizes(struct scope *scope,int *named,int *duplicated,int *anon,
		    int *numscopes);
/*
 * For a scope, returns 0 and sets @low_addr_saveptr and
 * @high_addr_saveptr appropriately.  If @scope has multiple ranges, and
 * if those ranges are noncontiguous, and @is_noncontiguous is not NULL,
 * we set it to 1.
 */
int scope_get_overall_range(struct scope *scope,ADDR *low_addr_saveptr,
			    ADDR *high_addr_saveptr,int *is_noncontiguous);
REFCNT scope_free(struct scope *scope,int force);
GSList *scope_match_syms(struct scope *scope,
			 struct rfilter *symbol_filter,
			 symbol_type_flag_t flags);


/**
 ** Locations.
 **/

#define LOCTYPE_BITS      4
static inline const char *LOCTYPE(int n) {
    switch (n) {
    case LOCTYPE_UNKNOWN:       return "unknown";
    case LOCTYPE_ADDR:          return "addr";
    case LOCTYPE_REG:           return "reg";
    case LOCTYPE_REG_ADDR:      return "regaddr";
    case LOCTYPE_REG_OFFSET:    return "regoffset";
    case LOCTYPE_MEMBER_OFFSET: return "memberoffset";
    case LOCTYPE_FBREG_OFFSET:  return "fbregoffset";
    case LOCTYPE_LOCLIST:       return "loclist";
    case LOCTYPE_IMPLICIT_WORD: return "implicit_word";
    case LOCTYPE_IMPLICIT_DATA: return "implicit_data";
    case LOCTYPE_RUNTIME:       return "runtime";
    default:                    return NULL;
    }
}
/*
 * Sometimes locations change depending on EIP; this struct can form a
 * list of such locations for a single symbol's location.  DWARF uses
 * these; other languages/debug info sources might as well.
 */
struct loclistloc {
    ADDR start;
    ADDR end;
    struct location *loc;
    struct loclistloc *next;
};

/*
 * We pack loctype plus any data length/register number fields, and
 * reserve a single bit that specifies if contents (like runtime data,
 * implicit data, loclist) should not be freed.
 */
#define LOCATION_REMAINING_BITS (__WORDSIZE - LOCTYPE_BITS - 1)

struct location {
    /*
     * This is basically a tagged union.
     *
     * NB: since the tag wastes a lot of space, we optimize by moving
     * @regoffset.reg and @runtime.len (and now implicit value data len)
     * out of the union.  Then we just have to limit the
     * runtime/implicit value data len; and ensure we limit the
     * sizeof(REG) in the future; right now it's int8_t .
     *
     * If users ever had to see this, it would stink for them.
     */

    loctype_t loctype:LOCTYPE_BITS;

    /*
     * Only controls freeing of @l.data -- not l.loclist -- that is
     * always freed!
     */
    int nofree:1;

    /* Encodes regoffset reg number, or the length of runtime data. */
#if LOCATION_REMAINING_BITS > 32
    long int extra:LOCATION_REMAINING_BITS;
#else
    int extra:LOCATION_REMAINING_BITS;
#endif

    union {
	ADDR addr;
	REG reg;
	OFFSET offset; /* fboffset, regoffset, member_offset */
	ADDR word;
	char *data;    /* runtime data or implicit value data */
	struct loclistloc *loclist;
    } l;
};

#define LOCATION_IS_UNKNOWN(loc) ((loc)->loctype == LOCTYPE_UNKNOWN)
#define LOCATION_IS_ADDR(loc) ((loc)->loctype == LOCTYPE_ADDR)
#define LOCATION_IS_REG(loc) ((loc)->loctype == LOCTYPE_REG)
#define LOCATION_IS_REG_ADDR(loc) ((loc)->loctype == LOCTYPE_REG_ADDR)
#define LOCATION_IS_REG_OFFSET(loc) ((loc)->loctype == LOCTYPE_REG_OFFSET)
#define LOCATION_IS_M_OFFSET(loc) ((loc)->loctype == LOCTYPE_MEMBER_OFFSET)
#define LOCATION_IS_FB_OFFSET(loc) ((loc)->loctype == LOCTYPE_FBREG_OFFSET)
#define LOCATION_IS_LOCLIST(loc) ((loc)->loctype == LOCTYPE_LOCLIST)
#define LOCATION_IS_IMPLICIT_WORD(loc) ((loc)->loctype == LOCTYPE_IMPLICIT_WORD)
#define LOCATION_IS_IMPLICIT_DATA(loc) ((loc)->loctype == LOCTYPE_IMPLICIT_DATA)
#define LOCATION_IS_RUNTIME(loc) ((loc)->loctype == LOCTYPE_RUNTIME)

#define LOCATION_ADDR(loc) (loc)->l.addr
#define LOCATION_REG(loc) (loc)->l.reg
#define LOCATION_OFFSET(loc) (loc)->l.offset
#define LOCATION_LOCLIST(loc) (loc)->l.loclist
#define LOCATION_WORD(loc) (loc)->l.word

#define LOCATION_GET_REGOFFSET(loc,reg,offset)			\
    do {							\
        reg = (REG)(loc)->extra;				\
	offset = (loc)->l.offset;				\
    } while (0);
#define LOCATION_GET_DATA(loc,buf,buflen)			\
    do {							\
        buflen = (int)(loc)->extra;				\
	buf = (loc)->l.data;					\
    } while (0);

int location_set_addr(struct location *l,ADDR addr);
int location_set_reg(struct location *l,REG reg);
int location_set_reg_addr(struct location *l,REG reg);
int location_set_reg_offset(struct location *l,REG reg,OFFSET offset);
int location_set_member_offset(struct location *l,OFFSET offset);
int location_set_fbreg_offset(struct location *l,OFFSET offset);
int location_set_loclist(struct location *l,struct loclistloc *list);
int location_update_loclist(struct location *loc,
			    ADDR start,ADDR end,struct location *rloc,
			    int *action);
int location_set_implicit_word(struct location *loc,ADDR word);
int location_set_implicit_data(struct location *loc,char *data,int len,
			       int nocopy);
int location_set_runtime(struct location *l,char *data,int len,int nocopy);

loctype_t location_resolve(struct location *loc,struct location_ctxt *lctxt,
			   struct symbol *symbol,struct location *o_loc);

struct location *location_copy(struct location *location);
void location_dump(struct location *location,struct dump_info *ud);
void location_internal_free(struct location *location);

/*
 * Targets must supply this interface.
 */
struct location_ops {
    /*
     * Change the current frame to something else.  This is useful for
     * obtaining saved register values in caller-saved frames.
     *
     * This library only uses it temporarily -- if it calls
     * setcurrentframe, it will undo that so that current_frame is the
     * same as it was when it was called.
     */
    int (*setcurrentframe)(struct location_ctxt *lctxt,int frame);
    /*
     * Gets the symbol associated with lctxt->current_frame.
     */
    struct symbol *(*getsymbol)(struct location_ctxt *lctxt);
    /*
     * Reads the value of @regno in @lctxt->current_frame.  This
     * function must NOT call location_ctxt_read_reg; that function will
     * read CFA data to compute it if it's not available in the cache.
     */
    int (*readreg)(struct location_ctxt *lctxt,REG regno,REGVAL *regval);
    int (*writereg)(struct location_ctxt *lctxt,REG regno,REGVAL regval);
    /*
     * If location_ctxt_read_reg reads a value, it will try to cache it
     * in lctxt->current_frame via this function.
     */
    int (*cachereg)(struct location_ctxt *lctxt,REG regno,REGVAL regval);
    /*
     * This is just syntactic sugar for getregno(CREG_IP) + readreg().
     */
    int (*readipreg)(struct location_ctxt *lctxt,REGVAL *regval);

    /*
     * Straightforward memory operations.
     */
    int (*readword)(struct location_ctxt *lctxt,ADDR real_addr,ADDR *pval);
    int (*writeword)(struct location_ctxt *lctxt,ADDR real_addr,ADDR pval);
    int (*relocate)(struct location_ctxt *lctxt,ADDR obj_addr,ADDR *real_addr);
    int (*unrelocate)(struct location_ctxt *lctxt,ADDR real_addr,ADDR *obj_addr);
    /*
     * Gets the target-specific regno for the common_reg_t reg.
     */
    int (*getregno)(struct location_ctxt *lctxt,common_reg_t reg,REG *o_reg);
    int (*getaddrsize)(struct location_ctxt *lctxt);
};

/*
 * location_ctxt couples a location_ops struct for reading machine state
 * to a notion of a stack of activations (frames) in that machine.
 * Basically, things that can resolve locations (debuginfo backends)
 * must provide debugfile_ops to virtually restore saved registers in
 * frame N-1 to frame N (where 0 is the most recent frame).  These
 * operations use location_ctxt_read_reg|read_addr to read registers
 * from the machine's state (and frame cache).  They can also cache
 * pseudo register values if desireable.  Then every time a dwdebug user
 * calls location_resolve()
 *
 * The @current_frame member indicates which frame the location_ops
 * should use for their current operation.  We expect that the
 * @lops_priv member is per-frame anyway -- so this is a convenient
 * multi-arg wrapper.
 *
 * So, the sequence:
 *
 *   * location_resolve(loc,ctxt) is called.  It uses
 *     ctxt->current_frame as the argument to calling
 *     location_ops->readreg/cache/readipreg as necessary.
 *   * These ops either read a machine value from frame 0; read a cached
 *     value from frame N; or use location_ctxt_read_reg to read the
 *     saved value for frame N in frame N - 1.
 *   * The unwinder uses location_ctxt_read_retaddr and
 *     location_ctxt_read_cfa to determine the value of IP to be
 *     returned to when done with current_frame; and the stack pointer
 *     of the start of the current_frame (CFA).  It then places these
 *     values into current_frame + 1 as it creates that frame.
 */
struct location_ctxt {
    struct location_ops *ops;
    void *priv;
    int current_frame;
};

struct location_ctxt *location_ctxt_create(struct location_ops *ops,void *priv);
int location_ctxt_read_retaddr(struct location_ctxt *lctxt,ADDR *o_retaddr);
/*
 * Attempts to load the value of @reg in @lctxt->current_frame.
 */
int location_ctxt_read_reg(struct location_ctxt *lctxt,REG reg,REGVAL *o_regval);
//int location_ctxt_read_all_registers(struct location_ctxt *lctxt,
int location_ctxt_write_reg(REG reg,struct location_ctxt *lctxt,REGVAL regval);
int location_ctxt_get_lops(struct location_ctxt *lctxt,
			   struct location_ops **ops,void **priv);
void location_ctxt_free(struct location_ctxt *lctxt);

/**
 ** Symbols.
 **/

struct symbol_root;
struct symbol_root_dwarf;
struct symbol_root_elf;
struct symbol_type_members;
struct symbol_function;
struct symbol_variable;
struct symbol_label;
struct symbol_block;
struct symbol_inline;

/*
 * Symbols are always attached to a containing scope, unless they are a
 * SYMBOL_TYPE_ROOT symbol.  That scope may have arisen due to a
 * hierarchy of names; or due to a hierarchy of code blocks.
 */
struct symbol {
    /*
     * Our name, if any.
     *
     * BUT, see comments about 'extname' below!!!  Do not free .name if
     * extname is set!  Right now it can only be set for type symbols;
     * hence, it is in the type section of the primary union below.
     */
    char *name;

    /*
     * Our containing scope or symbol.  Every symbol (except a root
     * symbol) is in a scope.  This is the best way to abstract this for
     * different languages.  When you think about it, some languages
     * have symbols nested directly in other symbols and scope is de
     * facto (i.e., a C struct member); but in other languages, a
     * directly nested symbol might still be part of a new scope (i.e.,
     * a C++ member var/function).
     *
     * One word of warning: although all symbols have parents, except
     * SYMBOL_TYPE_ROOT symbols, the parent might not be the *scope*
     * parent.  For instance, a local var in an anonymous lexical scope
     * in a C function would have the function as its parent (found via
     * symbol->scope->...->scope->symbol); but its scope would *not* be
     * the function's directly owned scope.
     */
    struct scope *scope;

    /*
     * If we copy the string table from the ELF binary
     * brute-force to save on lots of mallocs per symbol name,
     * we don't malloc each symbol's .name .  This means that
     * for type names that must be prepended to (i.e., the DWARF
     * name for a struct is just 'X', but we have to put it into
     * the symtab as 'struct X' to avoid typedef collisions
     * (i.e., typedef struct X X).  This means we have to drum
     * up a fake name. 
     * 
     * But, the fake name always contains the real name as a substring.
     * So, this is the offset of that string.
     */
    unsigned int orig_name_offset:8;

    /* Where we exist. */
    unsigned int srcline:SRCLINE_BITS;

    /* If this is a type symbol, which type. */
    datatype_code_t datatype_code:DATATYPE_CODE_BITS;

    /* Are we full or partial? */
    load_type_t loadtag:LOAD_TYPE_BITS;

    /* The kind of symbol we are. */
    symbol_type_t type:SYMBOL_TYPE_BITS;

    /* The symbol source. */
    symbol_source_t source:SYMBOL_SOURCE_BITS;

    unsigned int 
	issynthetic:1,
	isshared:1,
	usesshareddatatype:1,
	freenextpass:1,
	isexternal:1,
	has_linkage_name:1,
	isdeclaration:1,
	decldefined:1,
	decltypedefined:1,
	isprototyped:1,
	isparam:1,
	ismember:1,
	isenumval:1,
	isinlineinstance:1,
        isdeclinline:1,
	isinlined:1,
	has_addr:1,
	size_is_bytes:1,
	size_is_bits:1,
	guessed_size:1,
	name_nofree:1,
	has_unspec_params:1,
	constval_nofree:1;

    /* Our refcnt. */
    REFCNT refcnt;
    /* Our weak reference count. */
    //REFCNT refcntw;

    /* Our offset location in the debugfile. */
    SMOFFSET ref;

    /*
     * If this is a type symbol, datatype_ref and datatype are used as
     * part of its type definition when the definition references
     * another type (i.e., typedefs).
     *
     * If this is an instance symbol, datatype_ref and datatype are the
     * instance's type.
     *
     * If we see the use of the type before the type, or we're doing
     * partial loads, we can only fill in the ref and fill the datatype
     * in a postpass.
     */
    SMOFFSET datatype_ref;

    /*
     * If this is a type or var debug symbol, or an ELF symbol, it may
     * be nonzero.
     *
     * If @size.bytes is set, @size_is_bytes will be set above.
     * If @size.bits and/or @size.offset is set, @size_is_bits will be
     * set above (and if both a byte_size and bit_size are present,
     * ctbytes will inherit the byte_size).
     *
     * If a type or variable has both a byte_size and a bit_size (gcc
     * does this for bitfields -- in its DWARF output, byte_size is the
     * size of the type containing the bitfield; bit_size is the actual
     * size of the bitfield), bit_size is given precedence, and
     * byte_size is "lost" -- which is what we care about.  WHOOPS --
     * actually we do care about it for printing values at least.
     */
    union {
	uint32_t bytes;
	struct {
#define SIZE_BITS_SIZE     10
#define SIZE_OFFSET_SIZE   10
#define SIZE_CTBYTES_SIZE   12
	    uint32_t bits:SIZE_BITS_SIZE,
		     offset:SIZE_OFFSET_SIZE,
		     ctbytes:SIZE_CTBYTES_SIZE;
	};
    } size;

    /*
     * If this symbol has an address (or multiple addresses, or a range
     * of addresses, this is the smallest one.
     */
    ADDR addr;

    /*
     * If this symbol has a datatype, this is it.  These symbols have datatypes:
     * DATATYPE_FUNC DATATYPE_PTR DATATYPE_REF DATATYPE_TYPEDEF 
     *   DATATYPE_CONST DATATYPE_VOL
     * SYMBOL_TYPE_FUNC SYMBOL_TYPE_VAR
     * (DATATYPE_ENUM *could* have a type, but we don't bother).
     */
    struct symbol *datatype;

    /*
     * The meaning of these fields is conditional based on @type and
     * @datatype_code.
     *
     * Note, however, that just because a field is valid does not mean
     * it is set!  Fields spring into existence as needed; backends and
     * users should only touch them through accessor macros/functions.
     *
     *  type == SYMBOL_TYPE_ROOT 
     *    @extra.root is valid
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_BASE
     *    @extra.encoding is valid.
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_ARRAY
     *    @extra.subranges valid
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_ENUM
     *    @extra.members valid
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_FUNC
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_STRUCT
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_UNION
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_CLASS
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_NAMESPACE
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_TEMPLATE
     *    @extra.container valid
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_VOID
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_PTR
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_REF
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_TYPEDEF
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_CONST
     *  type == SYMBOL_TYPE_TYPE && datatype_code == DATATYPE_VOL
     *    @extra invalid
     *  type == SYMBOL_TYPE_FUNC
     *    @extra.function is valid
     *  type == SYMBOL_TYPE_VAR
     *    @extra.variable is valid
     *  type == SYMBOL_TYPE_LABEL
     *    @extra.label is valid
     *  type == SYMBOL_TYPE_BLOCK
     *    @extra.block is valid
     */
    union {
	/*
	 * Do we have content, period?  Sometimes useful to check in
	 * type-agnostic manner.
	 */
	void *exists;

	struct symbol_root *root;
	encoding_t encoding;
	GSList *subranges;
	GSList *members;
	struct symbol_type_container *container;
	struct symbol_function *function;
	struct symbol_variable *variable;
	struct symbol_label *label;
	struct symbol_block *block;
    } extra;
};

struct symbol_root {
    /*
     * One of these will be set, depending on if it's a debugfile symbol
     * or a binfile symbol.
     */
    struct debugfile *debugfile;
    struct binfile *binfile;

    char *compdirname;
    char *producer;
    char *language;
    short int lang_code;

    uint8_t compdirname_nofree:1,
            producer_nofree:1,
	    language_nofree:1,
	    has_entry_pc:1;

    struct scope *scope;
    ADDR entry_pc;

    void *priv;
};

struct symbol_root_dwarf {
    struct symbol *root;
    struct debugfile *debugfile;
    Dwfl_Module *dwflmod;
    Dwarf *dbg;
    size_t cuhl;
    Dwarf_Half version;
    uint8_t addrsize;
    uint8_t offsize;
    Dwarf_Off abbroffset;
    Dwarf_Off nextcu;

    /* Kept until the whole CU is loaded. */
    GHashTable *reftab;
    GHashTable *abstract_origins;
};

struct symbol_root_elf {
    struct binfile *binfile;
};

/*
 * Notes.  struct/union/enum/function/class types, and function
 * instances all have members.  In C, only function instances have
 * symtabs associated with them.  In C++, struct/union/class types may
 * also have type members (such as typedefs, or more struct/union/class
 * types).  In both languages, function instances have symtabs, of
 * course.  Any time a construct can both have ordered members, and
 * symtab entries, we store both the symtab and the order of the
 * members.
 *
 * So, to support C++, we always eat extra bytes for an unnecessary
 * symtab pointer for C (or for C++ struct/union/class types that don't
 * really need the symbol table for extra type info!).
 */
struct symbol_type_container {
    /*
     * An ordering over the members.
     */
    GSList *members;
    /*
     * The scope created by this container.  Note that type symbols
     * don't have block scope associated with them; they are about name
     * scope.  Again, it is struct scope here instead of struct symdict
     * because sometimes a symbol's parent is a scope; sometimes it's a
     * symbol -- but we only wanted to spend one pointer on that.  So
     * scope is kind of a unifying concept.
     */
    struct scope *scope;
};

struct symbol_function {
    GSList *members;
    /*
     * The scope created by this function.
     */
    struct scope *scope;
    /* The frame base location. */
    struct location *fbloc;
    uint8_t has_entry_pc:1,
	prologue_guessed:1,
	prologue_known:1,
	epilogue_known:1;
    ADDR entry_pc;
    ADDR prologue_end;
    ADDR epilogue_begin;
    struct symbol_inline *ii;
};

typedef char * dwarf_cfa_info_t;

struct symbol_variable {
    struct location *loc;
    /* If this instance already has a value, this is it! */
    void *constval;
    struct symbol_inline *ii;
};

struct symbol_label {
    struct symbol_inline *ii;
};

struct symbol_block {
    GSList *members;
    struct scope *scope;
    struct symbol_inline *ii;
};

struct symbol_inline {
    /* If this instance is inlined, these point back to the
     * source for the inlined instance.  If it was a forward ref
     * in the DWARF info, origin_ref is set and origin has to be
     * filled in a postpass.
     */
    SMOFFSET origin_ref;
    struct symbol *origin;

    /* If this symbol was declared or is inlined (is an abstract
     * origin), this is a list of the inline instance symbols
     * corresponding to this abstract origin.
     */
    GSList *inline_instances;
};

#define SYMBOL_IS_DWARF(sym) ((sym) && (sym)->source == SYMBOL_SOURCE_DWARF)
#define SYMBOL_IS_ELF(sym)  ((sym) && (sym)->source == SYMBOL_SOURCE_ELF)

#define SYMBOL_IS_FULL(sym) ((sym)->loadtag == LOADTYPE_FULL)
#define SYMBOL_IS_PARTIAL(sym) ((sym)->loadtag == LOADTYPE_PARTIAL)

#define SYMBOL_IS_ROOT(sym) ((sym)->type == SYMBOL_TYPE_ROOT)
#define SYMBOL_IS_TYPE(sym) ((sym)->type == SYMBOL_TYPE_TYPE)
#define SYMBOL_IS_VAR(sym) ((sym)->type == SYMBOL_TYPE_VAR)
#define SYMBOL_IS_FUNC(sym) ((sym)->type == SYMBOL_TYPE_FUNC)
#define SYMBOL_IS_LABEL(sym) ((sym)->type == SYMBOL_TYPE_LABEL)
#define SYMBOL_IS_BLOCK(sym) ((sym)->type == SYMBOL_TYPE_BLOCK)
#define SYMBOL_IS_INSTANCE(sym) ((sym)->type != SYMBOL_TYPE_TYPE \
				 && (sym)->type != SYMBOL_TYPE_ROOT \
				 && (sym)->type != SYMBOL_TYPE_NONE)

#define SYMBOL_IS_FULL_ROOT(sym) ((sym)->type == SYMBOL_TYPE_ROOT	\
				  && (sym)->extra.exists)
#define SYMBOL_IS_FULL_VAR(sym) ((sym)->type == SYMBOL_TYPE_VAR		\
				  && (sym)->extra.exists)
#define SYMBOL_IS_FULL_FUNC(sym) ((sym)->type == SYMBOL_TYPE_FUNC	\
	                          && (sym)->extra.exists)
#define SYMBOL_IS_FULL_LABEL(sym) ((sym)->type == SYMBOL_TYPE_LABEL	\
				   && (sym)->extra.exists)
#define SYMBOL_IS_FULL_BLOCK(sym) ((sym)->type == SYMBOL_TYPE_BLOCK	\
				   && (sym)->extra.exists)

#define SYMBOL_IST_VOID(sym)     (SYMBOL_IS_TYPE(sym) \
			          && (sym)->datatype_code == DATATYPE_VOID)
#define SYMBOL_IST_ARRAY(sym)    (SYMBOL_IS_TYPE(sym) \
			          && (sym)->datatype_code == DATATYPE_ARRAY)
#define SYMBOL_IST_STRUCT(sym)   (SYMBOL_IS_TYPE(sym) \
				  && (sym)->datatype_code == DATATYPE_STRUCT)
#define SYMBOL_IST_ENUM(sym)     (SYMBOL_IS_TYPE(sym) \
			          && (sym)->datatype_code == DATATYPE_ENUM)
#define SYMBOL_IST_PTR(sym)      (SYMBOL_IS_TYPE(sym) \
                                  && ((sym)->datatype_code == DATATYPE_PTR \
				      || (sym)->datatype_code == DATATYPE_REF))
#define SYMBOL_IST_FUNC(sym)     (SYMBOL_IS_TYPE(sym) \
				  && (sym)->datatype_code == DATATYPE_FUNC)
#define SYMBOL_IST_TYPEDEF(sym)  (SYMBOL_IS_TYPE(sym) \
				  && (sym)->datatype_code \
				                == DATATYPE_TYPEDEF)
#define SYMBOL_IST_UNION(sym)    (SYMBOL_IS_TYPE(sym) \
			          && (sym)->datatype_code == DATATYPE_UNION)
#define SYMBOL_IST_BASE(sym)     (SYMBOL_IS_TYPE(sym) \
			          && (sym)->datatype_code == DATATYPE_BASE)
#define SYMBOL_IST_CONST(sym)    (SYMBOL_IS_TYPE(sym) \
			          && (sym)->datatype_code == DATATYPE_CONST)
#define SYMBOL_IST_VOL(sym)      (SYMBOL_IS_TYPE(sym) \
			          && (sym)->datatype_code == DATATYPE_VOL)
#define SYMBOL_IST_NAMESPACE(sym)(SYMBOL_IS_TYPE(sym) \
			          && (sym)->datatype_code == DATATYPE_NAMESPACE)
#define SYMBOL_IST_CLASS(sym)    (SYMBOL_IS_TYPE(sym) \
			          && (sym)->datatype_code == DATATYPE_CLASS)
#define SYMBOL_IST_TEMPLATE(sym) (SYMBOL_IS_TYPE(sym)			\
			          && (sym)->datatype_code == DATATYPE_TEMPLATE)
/* convenient! */
#define SYMBOL_IST_STUN(sym)     (SYMBOL_IS_TYPE(sym) \
	                          && ((sym)->datatype_code == DATATYPE_STRUCT \
	                              || (sym)->datatype_code == DATATYPE_UNION))
#define SYMBOL_IST_STUNC(sym)    (SYMBOL_IS_TYPE(sym) \
	                          && ((sym)->datatype_code == DATATYPE_STRUCT \
	                              || (sym)->datatype_code  == DATATYPE_UNION \
				      || (sym)->datatype_code  == DATATYPE_CLASS))

#define SYMBOL_TYPE_FLAG_MATCHES(sym,flags)				\
    (flags == SYMBOL_TYPE_FLAG_NONE					\
     || ((flags & SYMBOL_TYPE_FLAG_TYPE && SYMBOL_IS_TYPE(sym))		\
	 || (flags & SYMBOL_TYPE_FLAG_VAR && SYMBOL_IS_VAR(sym))	\
	 || (flags & SYMBOL_TYPE_FLAG_VAR_ARG && SYMBOL_IS_VAR(sym)	\
	     && (sym)->isparam)						\
	 || (flags & SYMBOL_TYPE_FLAG_VAR_MEMBER && SYMBOL_IS_VAR(sym)	\
	     && (sym)->ismember)					\
	 || (flags & SYMBOL_TYPE_FLAG_VAR_GLOBAL && SYMBOL_IS_VAR(sym)	\
	     && (sym)->isexternal)					\
	 || (flags & SYMBOL_TYPE_FLAG_VAR_LOCAL && SYMBOL_IS_VAR(sym)	\
	     && !((sym)->isparam || (sym)->isexternal || (sym)->ismember \
		  || (sym)->isenumval))					\
	 || (flags & SYMBOL_TYPE_FLAG_FUNC && SYMBOL_IS_FUNC(sym))	\
	 || (flags & SYMBOL_TYPE_FLAG_LABEL && SYMBOL_IS_LABEL(sym))	\
	 || (flags & SYMBOL_TYPE_FLAG_ROOT && SYMBOL_IS_ROOT(sym))	\
	 || (flags & SYMBOL_TYPE_FLAG_BLOCK && SYMBOL_IS_BLOCK(sym))))

#define SYMBOL_IST_CONTAINER(sym) (SYMBOL_IS_TYPE(sym)	\
    && ((sym)->datatype_code == DATATYPE_FUNC		\
        || (sym)->datatype_code == DATATYPE_STRUCT	\
	|| (sym)->datatype_code == DATATYPE_UNION	\
	|| (sym)->datatype_code == DATATYPE_NAMESPACE	\
	|| (sym)->datatype_code == DATATYPE_CLASS	\
	|| (sym)->datatype_code == DATATYPE_TEMPLATE))
#define SYMBOL_HAS_MEMBERS(sym)						\
    (SYMBOL_IST_CONTAINER(sym) || SYMBOL_IST_ENUM(sym)			\
     || SYMBOL_IS_ROOT(sym) || SYMBOL_IS_FUNC(sym) || SYMBOL_IS_BLOCK(sym))
#define SYMBOL_CAN_OWN_SCOPE(sym)					\
    (SYMBOL_IST_CONTAINER(sym)						\
     || SYMBOL_IS_ROOT(sym) || SYMBOL_IS_FUNC(sym) || SYMBOL_IS_BLOCK(sym))
#define SYMBOL_IS_OWN_DATATYPE(sym) \
    (SYMBOL_IST_VOID(sym) || SYMBOL_IST_STUN(sym) || SYMBOL_IST_BASE(sym) \
     || SYMBOL_IST_NAMESPACE(sym) || SYMBOL_IST_CLASS(sym) \
     || SYMBOL_IST_TEMPLATE(sym))

#define SYMBOL_IS_INLINEABLE(sym)			\
    (SYMBOL_IS_FUNC(sym) || SYMBOL_IS_VAR(sym)		\
     || SYMBOL_IS_LABEL(sym) || SYMBOL_IS_BLOCK(sym))

#define SYMBOL_IS_CONTAINER(sym)					\
    (SYMBOL_IST_CONTAINER(sym)						\
     || SYMBOL_IS_ROOT(sym) || SYMBOL_IS_FUNC(sym) || SYMBOL_IS_BLOCK(sym))
#define SYMBOL_HAS_EXTRA(sym) ((sym)->extra.exists != NULL)
#define SYMBOL_HAS_INLINE(sym)					\
    (SYMBOL_HAS_EXTRA(sym)					\
     && ((SYMBOL_IS_VAR(sym) && SYMBOLX_VAR(sym)->ii)		\
	 || (SYMBOL_IS_FUNC(sym) && SYMBOLX_FUNC(sym)->ii)	\
	 || (SYMBOL_IS_LABEL(sym) && SYMBOLX_LABEL(sym)->ii)	\
	 || (SYMBOL_IS_BLOCK(sym) && SYMBOLX_BLOCK(sym)->ii)))

#define SYMBOLX_ROOT(sym) (sym)->extra.root
#define SYMBOL_RX_ROOT(sym,rvar) struct symbol_root *rvar = SYMBOLX_ROOT(sym)
#define SYMBOL_WX_ROOT(sym,wvar,reterr)			  \
    struct symbol_root *wvar;				  \
    if (!SYMBOL_IS_ROOT(sym)) return reterr;		  \
    if ((sym)->extra.root)				  \
	wvar = (sym)->extra.root;			  \
    else						  \
	wvar = (sym)->extra.root = (struct symbol_root *) \
	    calloc(1,sizeof(*(sym)->extra.root));
#define SYMBOLX_ENCODING_V(sym) (sym)->extra.encoding
#define SYMBOLX_SUBRANGES(sym) (sym)->extra.subranges
#define SYMBOLX_CONTAINER(sym) (sym)->extra.container
#define SYMBOL_RX_CONTAINER(sym,rvar)				\
    struct symbol_type_container *rvar = SYMBOLX_CONTAINER(sym)
#define SYMBOL_WX_CONTAINER(sym,wvar,reterr)				\
    struct symbol_type_container *wvar;					\
    if (!SYMBOL_IST_CONTAINER(sym)) return reterr;			\
    if ((sym)->extra.container)						\
	wvar = (sym)->extra.container;					\
    else								\
	wvar = (sym)->extra.container = (struct symbol_type_container *) \
	    calloc(1,sizeof(*(sym)->extra.container));
#define SYMBOLX_FUNC(sym) (sym)->extra.function
#define SYMBOL_RX_FUNC(sym,rvar) struct symbol_function *rvar = SYMBOLX_FUNC(sym)
#define SYMBOL_WX_FUNC(sym,wvar,reterr)				  \
    struct symbol_function *wvar;				  \
    if (!SYMBOL_IS_FUNC(sym)) return reterr;			  \
    if ((sym)->extra.function)					  \
	wvar = (sym)->extra.function;				  \
    else							  \
	wvar = (sym)->extra.function = (struct symbol_function *) \
	    calloc(1,sizeof(*(sym)->extra.function));

#define SYMBOLX_VAR(sym) (sym)->extra.variable
#define SYMBOL_RX_VAR(sym,rvar) struct symbol_variable *rvar = SYMBOLX_VAR(sym)
#define SYMBOL_WX_VAR(sym,wvar,reterr)					\
    struct symbol_variable *wvar;					\
    if (!SYMBOL_IS_VAR(sym)) return reterr;				\
    if ((sym)->extra.variable)						\
	wvar = (sym)->extra.variable;					\
    else								\
	wvar = (sym)->extra.variable = (struct symbol_variable *)	\
	    calloc(1,sizeof(*(sym)->extra.variable));
#define SYMBOLX_LABEL(sym) (sym)->extra.label
#define SYMBOL_RX_LABEL(sym,rvar) struct symbol_label *rvar = SYMBOLX_LABEL(sym)
#define SYMBOL_WX_LABEL(sym,wvar,reterr)			\
    struct symbol_label *wvar;					\
    if (!SYMBOL_IS_LABEL(sym)) return reterr;			\
    if ((sym)->extra.label)					\
	wvar = (sym)->extra.label;				\
    else							\
	wvar = (sym)->extra.label = (struct symbol_label *)	\
	    calloc(1,sizeof(*(sym)->extra.label));
#define SYMBOLX_BLOCK(sym) (sym)->extra.block
#define SYMBOL_RX_BLOCK(sym,rvar) struct symbol_block *rvar = SYMBOLX_BLOCK(sym)
#define SYMBOL_WX_BLOCK(sym,wvar,reterr)			\
    struct symbol_block *wvar;					\
    if (!SYMBOL_IS_BLOCK(sym)) return reterr;			\
    if ((sym)->extra.block)					\
	wvar = (sym)->extra.block;				\
    else							\
	wvar = (sym)->extra.block = (struct symbol_block *)	\
	    calloc(1,sizeof(*(sym)->extra.block));
#define SYMBOLX_INLINE(sym)					\
    (!SYMBOL_HAS_EXTRA(sym) ? NULL :				\
       (SYMBOL_IS_VAR(sym) ? SYMBOLX_VAR(sym)->ii :             \
	  (SYMBOL_IS_FUNC(sym) ? SYMBOLX_FUNC(sym)->ii :        \
             (SYMBOL_IS_LABEL(sym) ? SYMBOLX_LABEL(sym)->ii :   \
	      (SYMBOL_IS_BLOCK(sym) ? SYMBOLX_BLOCK(sym)->ii : NULL)))))
#define SYMBOL_RX_INLINE(sym,rvar)			\
    struct symbol_inline *rvar = SYMBOLX_INLINE(sym)
#define SYMBOL_WX_INLINE(sym,wvar,reterr)			  \
    struct symbol_inline *wvar;					  \
    if (SYMBOL_IS_FUNC(sym)) {					  \
        SYMBOL_WX_FUNC(sym,sf,reterr);				  \
	if (!sf->ii) sf->ii = calloc(1,sizeof(*(sf->ii)));	  \
	wvar = sf->ii;						  \
    }								  \
    else if (SYMBOL_IS_VAR(sym)) {				  \
        SYMBOL_WX_VAR(sym,sv,reterr);				  \
	if (!sv->ii) sv->ii = calloc(1,sizeof(*(sv->ii)));	  \
	wvar = sv->ii;						  \
    }								  \
    else if (SYMBOL_IS_LABEL(sym)) {				  \
        SYMBOL_WX_LABEL(sym,sl,reterr);				  \
	if (!sl->ii) sl->ii = calloc(1,sizeof(*(sl->ii)));	  \
	wvar = sl->ii;						  \
    }								  \
    else if (SYMBOL_IS_BLOCK(sym)) {				  \
        SYMBOL_WX_BLOCK(sym,sb,reterr);				  \
	if (!sb->ii) sb->ii = calloc(1,sizeof(*(sb->ii)));	  \
	wvar = sb->ii;						  \
    }								  \
    else							  \
	return reterr;
#define SYMBOLX_MEMBERS(sym)						\
    (!SYMBOL_HAS_EXTRA(sym) ? NULL :					\
      (SYMBOL_IS_FUNC(sym) ? SYMBOLX_FUNC(sym)->members :		\
        (SYMBOL_IS_FUNC(sym) ? SYMBOLX_FUNC(sym)->members :		\
          (SYMBOL_IST_ENUM(sym) ? (sym)->extra.members : 	 		\
	    (SYMBOL_IST_CONTAINER(sym) ? SYMBOLX_CONTAINER(sym)->members : NULL)))))
#define SYMBOLX_SCOPE(sym)						\
    (!SYMBOL_HAS_EXTRA(sym) ? NULL :					\
      (SYMBOL_IS_FUNC(sym) ? SYMBOLX_FUNC(sym)->scope :			\
	(SYMBOL_IST_CONTAINER(sym) ? SYMBOLX_CONTAINER(sym)->scope :	\
	  (SYMBOL_IS_ROOT(sym) ? SYMBOLX_ROOT(sym)->scope :		\
	    (SYMBOL_IS_BLOCK(sym) ? SYMBOLX_BLOCK(sym)->scope : NULL)))))
#define SYMBOLX_VAR_LOC(sym)						\
    (!SYMBOL_HAS_EXTRA(sym) ? NULL :					\
     (SYMBOL_IS_VAR(sym) ? SYMBOLX_VAR(sym)->loc : NULL))
#define SYMBOLX_VAR_CONSTVAL(sym)					\
    (!SYMBOL_HAS_EXTRA(sym) ? NULL :					\
     (SYMBOL_IS_VAR(sym) ? SYMBOLX_VAR(sym)->constval : NULL))

#define SYMBOL_EXPAND_WARN(symbol)				 	\
    do {								\
        if (!SYMBOL_IS_FULL(symbol)) {					\
	    if (symbol_expand(symbol))					\
	        vwarn("could not expand datatype symbol %s; continuing!\n", \
		      symbol_get_name(symbol));				\
	}								\
    } while(0);
#define SYMBOL_EXPAND_ERROR_RET(symbol,retval)				\
    do {								\
        if (!SYMBOL_IS_FULL(symbol)) {					\
	    if (symbol_expand(symbol)) {				\
	        verror("could not expand datatype symbol %s; continuing!\n", \
		      symbol_get_name(symbol));				\
		return retval;						\
	    }								\
	}								\
    } while(0);
#define SYMBOL_EXPAND_ERROR_OUT(symbol,label)				\
    do {								\
        if (!SYMBOL_IS_FULL(symbol)) {					\
	    if (symbol_expand(symbol)) {				\
	        verror("could not expand datatype symbol %s; continuing!\n", \
		      symbol_get_name(symbol));				\
		goto label;						\
	    }								\
	}								\
    } while(0);

/*
 * Internal lookup prototypes.
 */
struct lsymbol *scope_lookup_sym__int(struct scope *scope,
				      const char *name,const char *delim,
				      symbol_type_flag_t flags);
struct lsymbol *symbol_lookup_sym__int(struct symbol *symbol,
				       const char *name,const char *delim);

/*
 * Returns 0 if the symbol is already LOADTYPE_FULL, or if the full load
 * succeeds.  Returns nonzero if failure.
 *
 * Use the macros above, not this function.
 */
int symbol_expand(struct symbol *symbol);

/*
 * This function simplifies the process of adding a child symbol to a
 * parent.
 */
int symbol_insert_symbol(struct symbol *parent,struct symbol *child);
/*
 * If this symbol's name was modified by symbol_build_extname (i.e., if
 * it is an enum/struct/union type), this returns the base name.
 */
char *symbol_get_name_orig(struct symbol *symbol);
void symbol_set_name(struct symbol *symbol,char *name,int name_copy);
void symbol_build_extname(struct symbol *symbol);
int symbol_has_ext_name(struct symbol *symbol);

/*
 * Users should not have to deal directly with scopes.  These functions
 * do *not* hold on the returned scope.
 */
struct scope *symbol_containing_scope(struct symbol *symbol);
struct scope *symbol_read_owned_scope(struct symbol *symbol);
struct scope *symbol_write_owned_scope(struct symbol *symbol);
struct scope *symbol_link_owned_scope(struct symbol *symbol,
				      struct scope *new_parent);

#define symbol_set_external(s) (s)->isexternal = 1
#define symbol_set_parameter(s) (s)->isparam = 1
#define symbol_set_enumval(s) (s)->isenumval = 1
#define symbol_set_member(s) (s)->ismember = 1
#define symbol_set_unspec_params(s) (s)->has_unspec_params = 1
void symbol_set_srcline(struct symbol *s,int sl);
void symbol_set_bytesize(struct symbol *s,uint32_t b);
void symbol_set_bitsize(struct symbol *s,uint32_t b);
void symbol_set_bitoffset(struct symbol *s,uint32_t bo);
void symbol_set_bitsize_all(struct symbol *s,uint32_t b,uint32_t bo,uint32_t ctb);
void symbol_set_addr(struct symbol *s,ADDR a);
int symbol_set_root_priv(struct symbol *symbol,void *priv);
int symbol_set_root_compdir(struct symbol *symbol,char *compdirname,int copy);
int symbol_set_root_producer(struct symbol *symbol,char *producer,int copy);
int symbol_set_root_language(struct symbol *symbol,char *language,int copy,
			     short int lang_code);
int symbol_set_encoding(struct symbol *symbol,encoding_t num);

int symbol_add_subrange(struct symbol *symbol,int subrange);
int symbol_set_entry_pc(struct symbol *symbol,ADDR entry_pc);
int symbol_set_location(struct symbol *symbol,struct location *loc);
int symbol_set_inline_info(struct symbol *symbol,int isinlined,int isdeclinline);
int symbol_set_inline_origin(struct symbol *symbol,
			     SMOFFSET ref,struct symbol *origin);
int symbol_set_inline_instances(struct symbol *symbol,GSList *instances);
int symbol_add_inline_instance(struct symbol *symbol,struct symbol *instance);
int symbol_set_constval(struct symbol *symbol,void *value,int len,int copy);

void symbol_type_mark_members_free_next_pass(struct symbol *symbol,int force);

struct symbol *__symbol_get_one_member__int(struct symbol *symbol,char *member,
					    struct array_list **chainptr);
struct symbol *symbol_get_one_member__int(struct symbol *symbol,char *member);

void symbol_free_extra(struct symbol *symbol);
/* 
 * Frees a symbol.  Users should never call this; call symbol_release
 * instead.
 */
REFCNT symbol_free(struct symbol *symbol,int force);

/**
 ** Miscellaneous.
 **/
void g_hash_foreach_dump_symbol_list(gpointer key __attribute__((unused)),
				     gpointer value,gpointer userdata);
void g_hash_foreach_dump_symbol(gpointer key __attribute__((unused)),
				gpointer value,gpointer userdata);

#endif
