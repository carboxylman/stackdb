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

#ifndef __LIBDWDEBUG_H__
#define __LIBDWDEBUG_H__

#include <stdint.h>
#include <stdio.h>
#include <glib.h>
#include <wchar.h>
#include <sys/types.h>
#include <regex.h>

#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libebl.h>

#include "debugpred.h"
#include "list.h"
#include "alist.h"
#include "rfilter.h"
#include "config.h"
#include "log.h"
#include "output.h"
#include "common.h"
#include "clfit.h"

#if ELFUTILS_NO_VERSION_H
#define _INT_ELFUTILS_VERSION ELFUTILS_BIN_VERSION
#else
#include "elfutils/version.h"
#define _INT_ELFUTILS_VERSION _ELFUTILS_VERSION
#endif

#define DWDEBUG_DEF_DELIM "."

#define LOGDUMPSYMBOL(dl,lt,s) \
    vdebugc((dl),(lt),"symbol(%s,%s,0x%"PRIxSMOFFSET")", \
	    symbol_get_name((s)),SYMBOL_TYPE((s)->type),(s)->ref);

#define LOGDUMPSYMBOL_NL(dl,lt,s) \
    LOGDUMPSYMBOL((dl),(lt),(s)); \
    vdebugc((dl),(lt),"\n");

#define ERRORDUMPSYMBOL(s) \
    verrorc("symbol(%s,%s,0x%"PRIxSMOFFSET")", \
	    symbol_get_name((s)),SYMBOL_TYPE((s)->type),(s)->ref);

#define ERRORDUMPSYMBOL_NL(s) \
    ERRORDUMPSYMBOL((s)); \
    verrorc("\n");


#define LOGDUMPLSYMBOL(dl,lt,s) \
    vdebugc((dl),(lt),"lsymbol(%s,%s,0x%"PRIxSMOFFSET";chainlen=%d)", \
	    symbol_get_name((s)->symbol),SYMBOL_TYPE((s)->symbol->type), \
	    (s)->symbol->ref,array_list_len((s)->chain));

#define LOGDUMPLSYMBOL_NL(dl,lt,s) \
    LOGDUMPLSYMBOL((dl),(lt),(s)); \
    vdebugc((dl),(lt),"\n");

#define ERRORDUMPLSYMBOL(s) \
    verrorc("lsymbol(%s,%s,0x%"PRIxSMOFFSET";chainlen=%d)", \
	    symbol_get_name((s)->symbol),SYMBOL_TYPE((s)->symbol->type), \
	    (s)->symbol->ref,array_list_len((s)->chain));

#define ERRORDUMPLSYMBOL_NL(s) \
    ERRORDUMPLSYMBOL((s)); \
    verrorc("\n");

/*
 * Any library users must call these to initialize global library state.
 */
void dwdebug_init(void);
void dwdebug_fini(void);

/**
 ** Some forward declarations.
 **/
struct debugfile;
struct debugfile_load_opts;
struct symtab;
struct symbol;
struct lsymbol;
struct location;
struct range_list;
struct range_list_entry;
struct range;
struct loc_list_entry;
struct loc_list;
struct dwarf_cu_die;

/*
 * Our default load strategy is to always load the basic info for each
 * CU; to load all aranges info (address range info for each CU); to
 * load all pubnames info (gives per-CU offsets for pubnames); and to
 * load full CUs.  The flags below restrict what portions of the CUs we
 * try to load, and can be combined with debugfile_load_opts rfilters on
 * per-CU filenames (and on per-symbol names if PUBNAMES is set --
 * although only the pubnames will be filtered; any of their dependent
 * symbols will not be filtered).
 */
typedef enum {
    DEBUGFILE_LOAD_FLAG_NONE = 0,
    /* These control which CUs/DIEs are loaded.
     * _CUHEADERS says to load only the CU headers.
     * _PUBNAMES says to load all CU headers, but after that, only load
     *   any of the symbols in the debug_pubnames section, and their
     *   dependencies.
     */
    DEBUGFILE_LOAD_FLAG_CUHEADERS = 1 << 0,
    DEBUGFILE_LOAD_FLAG_PUBNAMES = 1 << 1,
    /* This forces partial symbol loading, instead of the default full. */
    DEBUGFILE_LOAD_FLAG_PARTIALSYM = 1 << 8,
    /* This flag specifies that we will try to promote all per-CU types
     * to be pubtypes, and then check if each symbol's type (if it has
     * one) is already a "pubtype" and is equivalent to our type (well,
     * the equivalence check is controlled by the next flag!).  If we
     * find a match, we set the symbol's datatype_ref field to the
     * per-CU offset (so we can load the real thing if we ever *want*
     * to), but we set the datatype field to point to the "pubtype" type
     * symbol AND take a reference to it.
     */
    DEBUGFILE_LOAD_FLAG_REDUCETYPES = 1 << 17,
    /* If the previous flag was set, if this is NOT set, we only check
     * name/datacode_type matches; if it IS set, we check all type
     * fields (including members and their types, recursively) for
     * equivalence).
     */
    DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV = 1 << 18,
} debugfile_load_flags_t;

typedef enum {
    DEBUGFILE_TYPE_KERNEL      = 0,
    DEBUGFILE_TYPE_KMOD        = 1,
    DEBUGFILE_TYPE_MAIN        = 2,
    DEBUGFILE_TYPE_SHAREDLIB   = 3,
    __DEBUGFILE_TYPE_MAX,
} debugfile_type_t;
extern char *DEBUGFILE_TYPE_STRINGS[];
#define DEBUGFILE_TYPE(n) (((n) < __DEBUGFILE_TYPE_MAX) ? DEBUGFILE_TYPE_STRINGS[(n)] : NULL)

typedef enum {
    SYMBOL_TYPE_NONE      = 0,
    SYMBOL_TYPE_TYPE      = 1,
    SYMBOL_TYPE_VAR       = 2,
    SYMBOL_TYPE_FUNCTION  = 3,
    SYMBOL_TYPE_LABEL     = 4,
    __SYMBOL_TYPE_MAX,
} symbol_type_t;
extern char *SYMBOL_TYPE_STRINGS[];
#define SYMBOL_TYPE(n) (((n) < __SYMBOL_TYPE_MAX) ? SYMBOL_TYPE_STRINGS[(n)] : NULL)
#define SYMBOL_IS_TYPE(sym) (sym && (sym)->type == SYMBOL_TYPE_TYPE)
#define SYMBOL_IS_VAR(sym) (sym && (sym)->type == SYMBOL_TYPE_VAR)
#define SYMBOL_IS_FUNCTION(sym) (sym && (sym)->type == SYMBOL_TYPE_FUNCTION)
#define SYMBOL_IS_LABEL(sym) (sym && (sym)->type == SYMBOL_TYPE_LABEL)
#define SYMBOL_IS_INSTANCE(sym) (sym && (sym)->type != SYMBOL_TYPE_TYPE)

#define SYMBOL_IS_FULL_TYPE(sym) (sym && (sym)->type == SYMBOL_TYPE_TYPE \
				  && (sym)->s.ti)
#define SYMBOL_IS_FULL_INSTANCE(sym) (sym && (sym)->type != SYMBOL_TYPE_TYPE \
				      && (sym)->s.ii)
#define SYMBOL_IS_FULL_VAR(sym) (sym && (sym)->type == SYMBOL_TYPE_VAR \
				 && (sym)->s.ii)
#define SYMBOL_IS_FULL_FUNCTION(sym) (sym && (sym)->type == SYMBOL_TYPE_FUNCTION \
				      && (sym)->s.ii)
#define SYMBOL_IS_FULL_LABEL(sym) (sym && (sym)->type == SYMBOL_TYPE_LABEL \
				   && (sym)->s.ii)

typedef enum {
    SYMBOL_SOURCE_DWARF   = 0,
    SYMBOL_SOURCE_ELF     = 1,
} symbol_source_t;
extern char *SYMBOL_SOURCE_STRINGS[];
#define SYMBOL_SOURCE(n) (((n) < (sizeof(SYMBOL_SOURCE_STRINGS) \
				  / sizeof(SYMBOL_SOURCE_STRINGS[0]))) \
			  ? SYMBOL_SOURCE_STRINGS[(n)] : NULL)
#define SYMBOL_IS_DWARF(sym) ((sym) && (sym)->source == SYMBOL_SOURCE_DWARF)
#define SYMBOL_IS_ELF(sym)  ((sym) && (sym)->source == SYMBOL_SOURCE_ELF)

typedef enum {
    LOADTYPE_UNLOADED     = 0,
    LOADTYPE_FULL         = 1,
    LOADTYPE_PARTIAL      = 2,
} load_type_t;

#define SYMBOL_IS_FULL(sym) ((sym)->loadtag == LOADTYPE_FULL)
#define SYMBOL_IS_PARTIAL(sym) ((sym)->loadtag == LOADTYPE_PARTIAL)

/*
 * In the symbol struct, these fields share a 32-bit int, divided this
 * way.  If you add more symbol types, or load types, adjust these
 * accordingly!
 */
#define LOAD_TYPE_BITS      2
#define SYMBOL_TYPE_BITS    3
#define SYMBOL_SOURCE_BITS   1
#define DATATYPE_CODE_BITS  4
#define SRCLINE_BITS       20

/* We use this enum type for filtering during symbol searching, when the
 * caller might accept multiple different symbol types.
 */
typedef enum {
    SYMBOL_TYPE_FLAG_NONE     = 0,
    SYMBOL_TYPE_FLAG_TYPE     = 1 << SYMBOL_TYPE_TYPE,
    SYMBOL_TYPE_FLAG_VAR      = 1 << SYMBOL_TYPE_VAR,
    SYMBOL_TYPE_FLAG_FUNCTION = 1 << SYMBOL_TYPE_FUNCTION,
    SYMBOL_TYPE_FLAG_LABEL    = 1 << SYMBOL_TYPE_LABEL,
} symbol_type_flag_t;

typedef enum {
    SYMBOL_VAR_TYPE_NONE      = 0,
    SYMBOL_VAR_TYPE_ARG       = 1,
    SYMBOL_VAR_TYPE_LOCAL     = 2,
    SYMBOL_VAR_TYPE_GLOBAL    = 3,
    __SYMBOL_VAR_TYPE_MAX,
} symbol_var_type_t;
extern char *SYMBOL_VAR_TYPE_STRINGS[];
#define SYMBOL_VAR_TYPE(n) (((n) < __SYMBOL_VAR_TYPE_MAX) ? SYMBOL_VAR_TYPE_STRINGS[(n)] : NULL)

typedef enum {
    SYMBOL_VAR_TYPE_FLAG_NONE     = 0,
    SYMBOL_VAR_TYPE_FLAG_ARG      = 1 << SYMBOL_VAR_TYPE_ARG,
    SYMBOL_VAR_TYPE_FLAG_LOCAL    = 1 << SYMBOL_VAR_TYPE_LOCAL,
    SYMBOL_VAR_TYPE_FLAG_GLOBAL   = 1 << SYMBOL_VAR_TYPE_GLOBAL,
} symbol_var_type_flag_t;

typedef enum {
    DATATYPE_VOID         = 0,
    DATATYPE_ARRAY        = 1,
    DATATYPE_STRUCT       = 2,
    DATATYPE_ENUM         = 3,
    DATATYPE_PTR          = 4,
    DATATYPE_FUNCTION     = 5,
    DATATYPE_TYPEDEF      = 6,
    DATATYPE_UNION        = 7,
    DATATYPE_BASE         = 8,
    DATATYPE_CONST        = 9,
    DATATYPE_VOL          = 10,
    DATATYPE_BITFIELD     = 11,
    __DATATYPE_MAX,
} datatype_code_t;
extern char *DATATYPE_STRINGS[];
#define DATATYPE(n) (((n) < __DATATYPE_MAX) ? DATATYPE_STRINGS[(n)] : NULL)

#define SYMBOL_IST_VOID(sym)     (SYMBOL_IS_TYPE(sym) \
			          && (sym)->datatype_code == DATATYPE_VOID)
#define SYMBOL_IST_ARRAY(sym)    (SYMBOL_IS_TYPE(sym) \
			          && (sym)->datatype_code == DATATYPE_ARRAY)
#define SYMBOL_IST_FULL_ARRAY(sym)    (SYMBOL_IS_FULL_TYPE(sym) \
				       && (sym)->datatype_code == DATATYPE_ARRAY)
#define SYMBOL_IST_STRUCT(sym)   (SYMBOL_IS_TYPE(sym) \
				  && (sym)->datatype_code == DATATYPE_STRUCT)
#define SYMBOL_IST_ENUM(sym)     (SYMBOL_IS_TYPE(sym) \
			          && (sym)->datatype_code == DATATYPE_ENUM)
#define SYMBOL_IST_PTR(sym)      (SYMBOL_IS_TYPE(sym) \
			          && (sym)->datatype_code == DATATYPE_PTR)
#define SYMBOL_IST_FUNCTION(sym) (SYMBOL_IS_TYPE(sym) \
				  && (sym)->datatype_code \
				                == DATATYPE_FUNCTION)
#define SYMBOL_IST_FULL_FUNCTION(sym) (SYMBOL_IS_FULL_TYPE(sym) \
				       && (sym)->datatype_code \
				                == DATATYPE_FUNCTION)
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
#define SYMBOL_IST_BITFIELD(sym) (SYMBOL_IS_TYPE(sym) \
				  && (sym)->datatype_code \
				                == DATATYPE_BITFIELD)
/* convenient! */
#define SYMBOL_IST_STUN(sym)     (SYMBOL_IS_TYPE(sym) \
	                          && ((sym)->datatype_code \
	                                        == DATATYPE_STRUCT \
	                              || (sym)->datatype_code \
				                == DATATYPE_UNION))
#define SYMBOL_IST_FULL_STUN(sym) (SYMBOL_IS_FULL_TYPE(sym) \
				   && ((sym)->datatype_code \
				                == DATATYPE_STRUCT \
				       || (sym)->datatype_code \
				                == DATATYPE_UNION))

typedef enum {
    LOCTYPE_UNKNOWN       = 0,
    LOCTYPE_ADDR          = 1,
    LOCTYPE_REG           = 2,
    LOCTYPE_REG_ADDR      = 3,
    LOCTYPE_REG_OFFSET    = 4,
    LOCTYPE_MEMBER_OFFSET = 5,
    LOCTYPE_FBREG_OFFSET  = 6,
    LOCTYPE_LOCLIST       = 7,
    LOCTYPE_REALADDR      = 8,
    /* add here */
    LOCTYPE_RUNTIME       = 9,
    __LOCTYPE_MAX,
} location_type_t;
extern char *LOCTYPE_STRINGS[];
#define LOCTYPE(n) (((n) < __LOCTYPE_MAX) ? LOCTYPE_STRINGS[(n)] : NULL)

/*
 * Returns 1 if resolving this location might be dependent on the IP; 0
 * otherwise.
 */
#define LOCATION_COND_IP(loc)  (!((loc)->loctype == LOCTYPE_ADDR	\
				  || (loc)->loctype == LOCTYPE_REALADDR))
/*
 * Returns 1 if resolving this location might be dependent on memory; 0
 * otherwise.
 */
#define LOCATION_COND_MEM(loc) (!((loc)->loctype == LOCTYPE_REG		\
				  || (loc)->loctype == LOCTYPE_REG_ADDR	\
				  || (loc)->loctype == LOCTYPE_REG_OFFSET))
/*
 * Returns 1 if resolving this location might be dependent on memory; 0
 * otherwise.
 */
#define LOCATION_IN_REG(loc) ((loc)->loctype == LOCTYPE_REG)

/*
 * These match the dwarf encoding codes.
 */
typedef enum {
    ENCODING_ADDRESS = 1,
    ENCODING_BOOLEAN = 2,
    ENCODING_COMPLEX_FLOAT = 3,
    ENCODING_FLOAT = 4,
    ENCODING_SIGNED = 5,
    ENCODING_SIGNED_CHAR =6,
    ENCODING_UNSIGNED = 7,
    ENCODING_UNSIGNED_CHAR = 8,
    ENCODING_IMAGINARY_FLOAT = 9,
    ENCODING_PACKED_DECIMAL = 10,
    ENCODING_NUMERIC_STRING = 11,
    ENCODING_EDITED = 12,
    ENCODING_SIGNED_FIXED = 13,
    ENCODING_UNSIGNED_FIXED = 14,
} encoding_t;

typedef enum {
    RANGE_TYPE_NONE = 0,
    RANGE_TYPE_PC = 1,
    RANGE_TYPE_LIST = 2,
    __RANGE_TYPE_MAX
} range_type_t;

extern char *RANGE_TYPE_STRINGS[];
#define RANGE_TYPE(n) (((n) < __RANGE_TYPE_MAX) ? RANGE_TYPE_STRINGS[(n)] : NULL)

#define RANGE_IS_PC(sym)   (sym && (sym)->rtype == RANGE_TYPE_PC)
#define RANGE_IS_LIST(sym) (sym && (sym)->rtype == RANGE_TYPE_LIST)

/**
 ** Debugfiles.
 **/
struct debugfile *debugfile_filename_create(char *filename,debugfile_type_t type);
struct debugfile *debugfile_create(char *filename,debugfile_type_t type,
				   char *name,char *version,char *idstr);
/* Populate a libsymd debugfile with DWARF debuginfo from an ELF file. */
int debugfile_load(struct debugfile *debugfile,
		   struct debugfile_load_opts *opts);
int debugfile_expand_symbol(struct debugfile *debugfile,struct symbol *symbol);
int debugfile_expand_cu(struct debugfile *debugfile,struct symtab *cu_symtab,
			struct array_list *die_offsets,int expand_dies);

struct debugfile_load_opts *debugfile_load_opts_parse(char *optstr);
void debugfile_load_opts_free(struct debugfile_load_opts *opts);

char *debugfile_build_idstr(char *filename,char *name,char *version);
int debugfile_filename_info(char *filename,char **realfilename,
			    char **name,char **version);
int debugfile_add_cu_symtab(struct debugfile *debugfile,struct symtab *symtab);
int debugfile_add_global(struct debugfile *debugfile,struct symbol *symbol);
struct symbol *debugfile_find_type(struct debugfile *debugfile,
				   char *typename);
int debugfile_add_type_name(struct debugfile *debugfile,
			    char *name,struct symbol *symbol);
void debugfile_dump(struct debugfile *debugfile,struct dump_info *ud,
		    int types,int globals,int symtabs,int elfsymtab);
REFCNT debugfile_free(struct debugfile *debugfile,int force);

/**
 ** Symbol tables.
 **/
struct symtab *symtab_create(struct debugfile *debugfile,SMOFFSET offset,
			     char *name,struct symbol *symtab_symtab,
			     int noautoinsert);
int symtab_get_size_simple(struct symtab *symtab);
int symtab_insert(struct symtab *symtab,struct symbol *symbol,OFFSET anonaddr);
struct symbol *symtab_get_sym(struct symtab *symtab,const char *name);
int symtab_insert_fakename(struct symtab *symtab,char *fakename,
			   struct symbol *symbol,OFFSET anonaddr);
void symtab_remove(struct symtab *symtab,struct symbol *symbol);
void symtab_steal(struct symtab *symtab,struct symbol *symbol);
char *symtab_get_name(struct symtab *symtab);
void symtab_set_name(struct symtab *symtab,char *srcfilename,int noautoinsert);
void symtab_set_compdirname(struct symtab *symtab,char *compdirname);
void symtab_set_producer(struct symtab *symtab,char *producer);
void symtab_set_language(struct symtab *symtab,int language);
void symtab_dump(struct symtab *symtab,struct dump_info *ud);
/*
 * Since we can get symtab info from multiple places (i.e.,
 * .debug_aranges, and from .debug_info), we need to be able to update
 * 1) the symtab's ranges, and 2) the debugfile's ranges lookup data
 * struct.  This function handles adding a new range, or updating an old
 * one whose end address may have changed (i.e., dwarf inconsistencies),
 * or converting a RANGE_TYPE_PC to a RANGE_TYPE_LIST.  If you supply
 * @rt_hint, and the current type of the symtab's range is NONE, we will
 * create a range of type @rt_hint (i.e., if you know that there will be
 * more than one range entry, supply RANGE_TYPE_LIST; if this is the
 * only one, use RANGE_TYPE_PC).
 */
void symtab_update_range(struct symtab *symtab,ADDR start,ADDR end,
			 range_type_t rt_hint);
void symtab_free(struct symtab *symtab);
#ifdef DWDEBUG_USE_STRTAB
int symtab_str_in_elf_strtab(struct symtab *symtab,char *strp);
int symtab_str_in_dbg_strtab(struct symtab *symtab,char *strp);
#endif

/**
 ** Symbols.
 **/
struct symbol *symbol_create(struct symtab *symtab,SMOFFSET offset,
			     char *name,symbol_type_t symtype,
			     symbol_source_t source,int full);
char *symbol_get_name(struct symbol *symbol);
char *symbol_get_name_orig(struct symbol *symbol);
void symbol_set_name(struct symbol *symbol,char *name);
void symbol_build_extname(struct symbol *symbol);
struct symtab *symbol_get_root_symtab(struct symbol *symbol);
void symbol_change_symtab(struct symbol *symbol,struct symtab *symtab,
			  int noinsert,int typerecurse);
/*
 * Returns a real, valid type for the symbol.  If it is an inline
 * instance, we skip to the abstract origin root and use that datatype.
 * If not, for now we just return @symbol->type.
 */
struct symbol *symbol_get_datatype(struct symbol *symbol);
void symbol_set_type(struct symbol *symbol,symbol_type_t symtype);
void symbol_set_srcline(struct symbol *symbol,int srcline);

int symbol_contains_addr(struct symbol *symbol,ADDR obj_addr);

int symbol_is_inlined(struct symbol *symbol);
int symbol_type_equal(struct symbol *t1,struct symbol *t2,
		      GHashTable *updated_datatype_refs);
int symbol_type_is_char(struct symbol *type);
/*
 * For a SYMBOL_TYPE_TYPE symbol, return the type's byte size.
 */
int symbol_type_bytesize(struct symbol *symbol);
unsigned int symbol_type_array_bytesize(struct symbol *type);
/* Return either type_array_bytesize or type_bytesize */
unsigned int symbol_type_full_bytesize(struct symbol *type);
struct symbol *symbol_type_skip_ptrs(struct symbol *type);
struct symbol *symbol_type_skip_qualifiers(struct symbol *type);
void symbol_dump(struct symbol *symbol,struct dump_info *ud);
void symbol_type_dump(struct symbol *symbol,struct dump_info *ud);
void symbol_function_dump(struct symbol *symbol,struct dump_info *ud);
void symbol_var_dump(struct symbol *symbol,struct dump_info *ud);

int symbol_get_location_offset(struct symbol *symbol,OFFSET *offset_saveptr);
int symbol_get_location_addr(struct symbol *symbol,ADDR *addr_saveptr);

/*
 * Takes a reference to the symbol.  Users should not call this.
 */
REFCNT symbol_hold(struct symbol *symbol);
/*
 * Releases a reference to the symbol and tries to free it.
 */
REFCNT symbol_release(struct symbol *symbol);
/* 
 * Frees a symbol.  Users should never call this; call symbol_release
 * instead.
 */
REFCNT symbol_free(struct symbol *symbol,int force);
void symbol_type_mark_members_free_next_pass(struct symbol *symbol,int force);

/* Creates an lsymbol data structure and takes references to all its
 * symbols.  Users probably never should call this function.
 *
 * This function takes a ref to each symbol in @chain, BUT NOT to
 * @return (call lsymbol_hold() to get that ref).
 */
struct lsymbol *lsymbol_create(struct symbol *symbol,struct array_list *chain);
/* If we already know that @member is a member of @symbol -- i.e., it is
 * a nested var in a struct or function, or a function/function type
 * param, etc... we can just clone @parent's chain and extend it by one
 * to include the child.
 *
 * Users might sometimes wish to call this function to obtain an lsymbol
 * structure, but they shouldn't need to.
 *
 * This function takes a ref to each symbol in @chain, BUT NOT to
 * @return (call lsymbol_hold() to get that ref).
 */
struct lsymbol *lsymbol_create_from_member(struct lsymbol *parent,
					   struct symbol *member);
/*
 * Creates an lsymbol from an existing symbol.  This is a best-effort
 * process that may not lead to what you want.  Why?  Suppose that you
 * lookup 'struct mystruct.mymember'.  In this case, your lsymbol will
 * have two items on the chain; one for 'struct mystruct', and one for
 * 'mymember'.  If you pass the 'mymember' symbol into this function,
 * you will get the same chain.
 *
 * However, if you lookup 'ms.mymember', where 'ms' is an instance of
 * 'mystruct', your lsymbol chain will have the two symbols for 'ms' and
 * 'mymember'.  Then if you pass the symbol for 'mymember' to this
 * function, you will still get the 'struct mystruct', 'mymember' chain.
 *
 * This result is expected and happens because we cannot trace up
 * instance chains.  We cannot know *which* instance of 'struct
 * mystruct' you want to have as the parent of 'mymember'.
 *
 * This function takes a ref to each symbol in its chain, BUT NOT to
 * @return (call lsymbol_hold() to get that ref).
 */
struct lsymbol *lsymbol_create_from_symbol(struct symbol *symbol);
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
char *lsymbol_get_name(struct lsymbol *lsymbol);
struct symbol *lsymbol_get_symbol(struct lsymbol *lsymbol);
void lsymbol_dump(struct lsymbol *lsymbol,struct dump_info *ud);
/*
 * Takes a reference to the lsymbol (NOT to the symbols on the chain!).
 * Users should never call this function; the lookup functions return
 * lsymbols that have been held.  The user should only call
 * lsymbol_release on them.
 */
void lsymbol_hold(struct lsymbol *lsymbol);
/*
 * Takes references to the symbols on the lsymbol chain!.  Users should
 * never call this function unless they call lsymbol_create*(); the
 * lookup functions return lsymbols that have been held.  The user
 * should only call lsymbol_release on them.
 */
void lsymbol_hold_int(struct lsymbol *lsymbol);
/*
 * Releases the reference to the lsymbol, and frees it if its refcnt is
 * 0.
 */
void lsymbol_release(struct lsymbol *lsymbol);
/*
 * Releases references to the symbols on the chain and tries to free the
 * lsymbol (not the underlying symbols!).
 */
REFCNT lsymbol_free(struct lsymbol *lsymbol,int force);

/**
 ** Locations.
 **/
struct location *location_create(void);
void location_dump(struct location *location,struct dump_info *ud);
void location_internal_free(struct location *location);
void location_free(struct location *location);

OFFSET location_resolve_offset(struct location *location,
			       struct array_list *symbol_chain,
			       struct symbol **top_symbol_saveptr,
			       int *chain_top_symbol_idx_saveptr);

/**
 ** Symtab (PC) lookup functions.
 **/
/*
 * Find the symbol table corresponding to the supplied PC.
 *
 * XXX: We don't refcnt symtabs.  There is no point to refcnt'ing top-level
 * symtabs, since they are always around as long as the debugfile is.
 * However, we probably should RHOLD on the symtab's parent symbol.  But
 * that is confusing!  Hm.
 */
struct symtab *symtab_lookup_pc(struct symtab *symtab,ADDR pc);

/**
 ** Symbol/memaddr lookup functions.
 **/
/* 
 * Look up a (possibly delimited with @delim) symbol named @name in
 * @debugfile.  @ftype contains symbol_type_flag_t flags controlling
 * which kind of symbols we will return.  If @ftype == SYMBOL_TYPE_FLAG_NONE, 
 * we will return the first match of any symbol type on the given name;
 * _NONE is a wildcard.  If @ftype is the wildcard, or has any of
 * SYMBOL_TYPE_FLAG_VAR, SYMBOL_TYPE_FLAG_FUNCTION, SYMBOL_TYPE_FLAG_LABEL
 * set, we will first consult the global names (functions or variables)
 * in the debugfile.  If no matches result from that, and @ftype is the
 * wildcard or SYMBOL_TYPE_FLAG_TYPE, we consult the global types table.
 *
 * If the global tables don't have our symbol, we scan through the
 * symbol tables for each source file in the debugfile (each source file
 * from the original compilation gets its own top-level symbol table).
 * This part of the search is tricky; why?  Because we want to return
 * the "best" match, and the "best" match for a var/function is its
 * definition -- not a declaration (i.e., an 'extern ...' reference).
 * We may encounter lots of declarations before we find the definition,
 * so it's kind of wasteful.  Anyway... if we find a type match, we
 * return it right away.  If we find a declaration, we return it right
 * away.  If we find a definition, and never find a subsequent
 * definition or type, we return the first definition we found.
 *
 * If this function returns an lsymbol, it takes a reference to the
 * lsymbol itself, AND to lsymbol->symbol, and to each symbol in
 * lsymbol->chain.  lsymbol_release is the correct way to release these
 * refs.
 * 
 * If you know which debugfile contains your symbol, this is fastest.
 */
struct lsymbol *debugfile_lookup_sym(struct debugfile *debugfile,
				     char *name,const char *delim,
				     struct rfilter *srcfile_filter,
				     symbol_type_flag_t ftype);

/*
 * We return a list of all matching symbols in the debugfile, that are
 * either globals, or are at the "top level" of a CU.  In other words,
 * we do not look for nested symbols.  That would be very slow...
 *
 * If @globals_only is set and @srcfile_filter is NULL, we only search
 * the globals or types/shared_types hashes in the debugfile; we do not
 * examine each CU's symtab.
 *
 * If @globals is set and @srcfile_filter is NOT NULL, we will search
 * through all CUs that match srcfile_filter, but only return symbol
 * names that match IF they are global symbols.
 *
 * If @globals is not set and @srcfile_filter is not set, we go through
 * all CUs.
 *
 * Our search and return values will be restricted by which @ftype
 * symbol type flags you set; you can set a combination; if you set it
 * to 0 (SYMBOL_TYPE_FLAG_NONE), we do not restrict our symbol search or
 * return values.
 *
 * The returned GList must be freed using g_list_free; if any of the
 * debugfile/symtab hashtables is modified later (i.e., the debugfile is
 * only partially loaded), this list may not be used.
 *
 * The items on this list are struct symbol *, and if you want to use
 * them, you MUST symbol_hold() them!  This function does not do it for
 * you!
 */
GList *debugfile_match_syms(struct debugfile *debugfile,
			    struct rfilter *symbol_filter,
			    symbol_type_flag_t ftype,
			    struct rfilter *srcfile_filter,
			    int globals_only);

GList *debugfile_match_syms_as_lsymbols(struct debugfile *debugfile,
					struct rfilter *symbol_filter,
					symbol_type_flag_t ftype,
					struct rfilter *srcfile_filter,
					int globals_only);
/*
 * Look up a specific address and find its symbol.
 * 
 * This function attempts to trace back the lookup chain as best as
 * possible; it builds up the lsymbol's lookup chain in reverse.  BUT,
 * it can only do this if the symbol at @addr is not a struct member,
 * nor a param of a function type.  Why?  Because those symbols are
 * members of a type -- not at instance -- so we don't know how to trace
 * back further than the struct or function type, respectively.
 *
 * However, this should never bite us; lookups by address should only
 * return functions or global (or static local) variables; these can
 * always be looked up.
 *
 * So, we can basically return hierarchies of nested vars and function
 * symbols.
 *
 * If this function returns an lsymbol, it takes a reference to the
 * lsymbol itself, AND to lsymbol->symbol, and to each symbol in
 * lsymbol->chain.  lsymbol_release is the correct way to release these
 * refs.
 */
struct lsymbol *debugfile_lookup_addr(struct debugfile *debugfile,ADDR addr);

struct array_list *debugfile_lookup_addrs_line(struct debugfile *debugfile,
					       char *filename,int line);
struct lsymbol *debugfile_lookup_sym_line(struct debugfile *debugfile,
					  char *filename,int line,
					  SMOFFSET *offset,ADDR *addr);

/* Look up one symbol in a symbol table by name.
 *
 * If this function returns an lsymbol, it takes a reference to the
 * lsymbol itself, AND to lsymbol->symbol, and to each symbol in
 * lsymbol->chain.  lsymbol_release is the correct way to release these
 * refs.
 */
struct lsymbol *symtab_lookup_sym(struct symtab *symtab,
				  const char *name,const char *delim,
				  symbol_type_flag_t ftype);

struct lsymbol *lsymbol_lookup_member(struct lsymbol *lsymbol,
				      const char *name,const char *delim);

struct lsymbol *symbol_lookup_member(struct symbol *symbol,
				     const char *name,const char *delim);

/*
 * Returns a clone of @lsymbol, with reference taken, and if @newchild
 * is not NULL, @newchild is appended
 */
struct lsymbol *lsymbol_clone(struct lsymbol *lsymbol,struct symbol *newchild);

/*
 * Returns a list of lsymbols that correspond to the members of
 * @lsymbol.  If @argsonly is set, only function argument members will
 * be returned.  Only function or struct/enum types may have members, so
 * expect NULL if you pass anything else!  If you do pass a valid
 * @lsymbol, but it has no members of the kind you are looking (i.e.,
 * how @argsonly is set), then an empty list will be returned.
 *
 * If @lsymbol has multiple levels (i.e., a hierarchy of nested
 * struct/enum members), or a function with nested symtabs, only those
 * members in the first level are returned!
 * 
 * This list *does* contain lsymbols that need to be released with
 * lsymbol_release.
 *
 * @kinds - 0 means all, 1 means func args only, 2 means locals only
 */
struct array_list *lsymbol_get_members(struct lsymbol *lsymbol,
				       symbol_var_type_flag_t kinds);

/*
 * @symbol may be either a SYMBOL_TYPE_TYPE, a SYMBOL_TYPE_FUNCTION, or
 * a SYMBOL_TYPE_VAR.  This function is really about returning an instance
 * symbol, BUT we allow it to take an instance symbol that is either a
 * function, so we can get the type symbol for an arg, or a
 * struct/union, so we can get the type symbol for a member.  Sugar.
 * Hopefully not too confusing.
 *
 * SYMBOL_TYPE_TYPE:
 *   DATATYPE_FUNCTION: find an arg matching @member.
 *   DATATYPE_ENUM: find a matching enumerator.
 *   DATATYPE_(STRUCT|UNION): find a matching member.  If @symbol
 *     contains anonymous members, we recurse into those in a BFS.
 * SYMBOL_TYPE_FUNCTION: find an arg matching @member.
 * SYMBOL_VAR:
 *   DATATYPE_(STRUCT|UNION): find a matching member.  If @symbol
 *     contains anonymous members, we recurse into those in a BFS.
 *
 * If this function returns a symbol, it takes a reference to it.
 * symbol_release is the correct way to release these refs.
 */
struct symbol *symbol_get_one_member(struct symbol *symbol,char *member);
/*
 * Given a starting symbol, searches its member hierarchy according to
 * the given delimited string of member variables.
 *
 * If this function returns a symbol, it takes a reference to it.
 * symbol_release is the correct way to release these refs.
 */
struct symbol *symbol_get_member(struct symbol *symbol,char *memberlist,
				 const char *delim);
/*
 * Given an IP (as an object-relative address), check and see if this
 * symbol is currently visible (in scope).  To do this we, check if the
 * IP is in the symtab's range; or if it is in any child symtab's range
 * where no symbol in that symtab overrides the primary symbol name!
 */
int symbol_visible_at_ip(struct symbol *symbol,ADDR ip);

/*
 * Range/location list stuff.
 *
 * XXX: this should not be exposed to the user, probably.
 */
struct range_list *range_list_create(int initsize);
int range_list_add(struct range_list *list,ADDR start,ADDR end);
void range_list_internal_free(struct range_list *list);
void range_list_free(struct range_list *list);
struct loc_list *loc_list_create(int initsize);
int loc_list_add(struct loc_list *list,ADDR start,ADDR end,struct location *loc);
void loc_list_free(struct loc_list *list);

/*
 * Dwarf util stuff.
 */
int get_lines(struct debugfile *debugfile,struct symtab *cu_symtab,
	      Dwarf_Off offset,size_t address_size);

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

/*
 * Elf util stuff.
 */
int elf_get_base_addrs(Elf *elf,
		       ADDR *base_virt_addr_saveptr,
		       ADDR *base_phys_addr_saveptr);
int elf_get_debuginfo_info(Elf *elf,
			   int *has_debuginfo_saveptr,
			   char **buildid_saveptr,
			   char **gnu_debuglinkfile_saveptr,
			   uint32_t *gnu_debuglinkfile_crc_saveptr);
int elf_get_arch_info(Elf *elf,int *wordsize,int *endian);
int elf_is_dynamic_exe(Elf *elf);
int elf_load_symtab(Elf *elf,char *elf_filename,struct debugfile *debugfile);

/**
 ** Data structure definitions.
 **/
struct debugfile_load_opts {
    struct rfilter *debugfile_filter;
    struct rfilter *srcfile_filter;
    struct rfilter *symbol_filter;
    debugfile_load_flags_t flags;
};

struct debugfile {
    /* The type of debugfile */
    debugfile_type_t type;

    /* Our reference count. */
    REFCNT refcnt;

    /* Save the options we were loaded with, forever. */
    struct debugfile_load_opts *opts;

    /*
     * If the symtab was loaded partially (or not loaded beyond the CU
     * header), we keep the debuginfo file loaded), so we have to save
     * off the elfutils info.
     */
    int fd;
    Dwfl *dwfl;
    Ebl *ebl;

    /* filename:name:version string.  If version is null, we use __NULL
       instead. */
    char *idstr;
    /* 
     * The source filename.  This is a unique ID.  We support internal
     * reuse of already-loaded debugfiles, and if the user tries to open
     * one, if the filename matches an already-loaded one, we assume
     * that we can use that one.  In other words, we don't try to
     * version on individual filenames.  This means that if you update a
     * debuginfo file after it has been loaded, IT WILL NOT BE RELOADED
     * until it is garbage-collected!
     */
    char *filename;

    /*
     * Currently unused -- we always garbage collect unused debugfiles.
     * We'll do persistence later.
     */
    /* the time this file was loaded */
    time_t ltime;
    /* the last mtime of this file */
    time_t mtime;
    
    /*
     * The name of the program or lib, minus any version info.
     * For shared libs, this is "libz"; for the kernel, it
     * is literally just the name "vmlinux"; for kernel modules,
     * it is the module name; for programs, it is the executable name.
     */
    char *name;
    /*
     * The kernel, kmods, and shared libs should all have versions.
     * Programs probably won't have versions
     */
    char *version;

    struct list_head debugfile;

    /* 
     * If this debugfile is for a kernel mod, its
     * "parent" is pointed to here.  We need this so that we can share
     * type info for the kernel modules, which seems like a perfectly
     * valid thing to do.
     */
    struct debugfile *kernel_debugfile;

    /*
     * The string table for this file.  All ELF string pointers are
     * checked for presence in this table before freeing.
     *
     * This table persists until the debugfile is freed.
     *
     * NOTE: this may either come from the debuginfo file, OR the ELF
     * binary.  Different distros fragment out the symtab into those
     * files differently; we check the ELF binary first, then the
     * debuginfo file.
     */
    char *elf_strtab;

    /*
     * The ELF symtab for this file; all symbols in this table are ELF
     * symbols, not DWARF symbols.  They cannot be expanded into
     * fully-loaded symbols.
     */
    struct symtab *elf_symtab;

    /* 
     * We keep a separate range structure for ELF symbols, because the
     * normal debugfile->ranges range structure contains symtabs, not
     * symbols.  So they can't be mixed... unfortunate.
     */
    clrange_t elf_ranges;

    /*
     * The debug string table for this file.  All debuginfo string pointers are
     * checked for presence in this table before freeing.
     *
     * This table persists until the debugfile is freed.
     */
    char *dbg_strtab;

    /*
     * The debug location table for this file.
     *
     * This table is only live while the file is being processed.
     */
    char *loctab;

    /*
     * The range table for this file.
     *
     * This table is only live while the file is being processed.
     */
    char *rangetab;

    /*
     * The line table for this file.
     *
     * This table is only live while the file is being processed.
     */
    char *linetab;

    /* Table lengths -- moved here for struct packing. */
    unsigned int elf_strtablen;
    unsigned int dbg_strtablen;
    unsigned int loctablen;
    unsigned int rangetablen;
    unsigned int linetablen;

    /* does this file get automatically garbage collected? */
    uint8_t infinite;

    /*
     * Each srcfile in a debugfile gets its own symtable.  The symtable
     * is the authoritative source of 
     *
     * h(srcfile) -> struct symtab *
     */
    GHashTable *srcfiles;

    /*
     * Each CU debugfile gets its own symtable.  This is a map between
     * CU offsets (i.e., in aranges and pubnames) and symtabs.
     *
     * h(offset) -> struct symtab *
     */
    GHashTable *cuoffsets;

    /*
     * Assume that, per-debug-info file, type names are unique -- i.e.,
     * they are not per-srcfile foreach srcfile in the debugfile.
     *
     * For kernel modules, we can probably shortcut this and share the
     * main exe type table with all modules.  I am less convinced we can
     * do this for user-space libraries and the main exe -- especially
     * for typedefs.
     *
     * Let's do it for now and see what breaks.
     */
    /* h(typename) -> struct symbol * */
    GHashTable *types;

    struct symtab *shared_types;

    /*
     * Each global var/function (i.e., not declared as static, and not
     * local to a function) symbol is also in this table.  Note: when
     * cleaning up a struct debugfile, we should free this table first,
     * before srcfiles, and not free the values until freeing the
     * per-srcfile symtabs.
     *
     * h(identifier) = struct symbol *
     */
    GHashTable *globals;

    /*
     * Any symbol that has a fixed address location gets an entry in
     * this table.  ELF symbols from the ELF symtab may also be in this
     * table, but debuginfo symbols always take precedence over them.
     *
     * h(address) = struct symbol *
     */
    GHashTable *addresses;

    /*
     * Any symbol in the pubnames table for any CUs in this debugfile is
     * in here, with a pointer to its global DIE offset (i.e., from
     * start of debug_info section.  This tells us what we need to load
     * IF we don't already have @identifier.
     *
     * h(identifier) = global_die_offset
     */
    GHashTable *pubnames;

    clrange_t ranges;

    GHashTable *srclines;
};

struct dwarf_cu_die_ref {
    SMOFFSET cu_offset;
    SMOFFSET die_offset;
};

struct range_list_entry {
    ADDR start;
    ADDR end;
};

struct range_list {
    int32_t len;
    int32_t alen;
    struct range_list_entry **list;
};

struct range {
    range_type_t rtype;
    union {
	struct {
	    ADDR lowpc;
	    ADDR highpc;
	} a;
	struct range_list rlist;
    } r;
};

struct loc_list_entry {
    ADDR start;
    ADDR end;
    struct location *loc;
};

struct loc_list {
    int32_t len;
    int32_t alen;
    struct loc_list_entry **list;
};

struct location {
    location_type_t loctype;
    union {
	ADDR addr;
	REG reg;
	OFFSET fboffset;
	struct {
	    REG reg;
	    OFFSET offset;
	} regoffset;
	OFFSET member_offset;
	struct {
	    char *data;
	    uint16_t len;
	} runtime;
	struct loc_list *loclist;
    } l;
};

#define SYMTAB_IS_ROOT(symtab) ((symtab)->parent == NULL)
#define SYMTAB_IS_CU(symtab)   ((symtab)->meta != NULL)
#define SYMTAB_IS_ANON(symtab) ((symtab)->symtab_symbol == NULL)

struct dwarf_cu_meta {
    Dwfl_Module *dwflmod;
    Dwarf *dbg;
    size_t cuhl;
    Dwarf_Half version;
    uint8_t addrsize;
    uint8_t offsize;
    Dwarf_Off abbroffset;
    Dwarf_Off nextcu;

    /* If this was a source filename, a compilation dir should be set. */
    char *compdirname;

    /*
     * Any symbol in the pubnames table for any CUs in this debugfile is
     * in here, with a pointer to its CU's symtab.
     */
    GHashTable *pubnames;

    char *producer;
    short int language;

    /* Right now, this is only set for top-level CU symtabs. */
    load_type_t loadtag:LOAD_TYPE_BITS;
};

/*
 * Symbol tables are mostly just backreferences to the objects they are
 * associated with (the parent debugfile they are in, and the srcfile
 * from the original source they are present in)... and the hashtable
 * itself.
 */
struct symtab {
    struct debugfile *debugfile;

    /* If this is a top-level (CU) symtab, we need some extra info. */
    struct dwarf_cu_meta *meta;

    /* This may be the source filename, OR a subscope name. */
    char *name;

    /* The range for this symtab is either a list of ranges, or a
     * low_pc/high_pc range.
     */
    struct range range;

    /* The offset where this symtab came from.  For CU symtabs, it is
     * the CU; for function symtabs, it is the function's DIE.
     */
    SMOFFSET ref;

    /*
     * If this is a symtab for symbol (i.e., for a function), this is
     * that symbol.
     */
    struct symbol *symtab_symbol;

    /*
     * If this symtab is a child, this is its parent.
     */
    struct symtab *parent;
    /* If this symtab has subscopes, this list is the symtabs for each
     * subscope.  Of course, each subscope could have more children.
     */
    struct list_head subtabs;
    /* If this symtab is a child of some other symtab, it will be on
     * that symtab's list.
     */
    struct list_head member;

    /* 
     * This hashtable stores only *named* symbols that existed in this
     * scope.  If the symbol exists multiple times in this symtab, then
     * it is not in this table, but rather in duptab below.  If we have
     * to insert a symbol already present in this table, we create a
     * list and move it to the duptab.
     *
     * h(sym) -> struct symbol *
     */
    GHashTable *tab;

    /* 
     * This hashtable stores lists of duplicate symbols in this symtab.
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

struct symbol_type;
struct symbol_instance;

struct symbol {
    /*
     * Our name, if any.
     *
     * BUT, see comments about 'extname' below!!!  Do not free .name if
     * extname is set!  Right now it can only be set for type symbols;
     * hence, it is in the type section of the primary union below.
     */
    char *name;

    /* The primary symbol table we are resident in. */
    struct symtab *symtab;

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

    unsigned int issynthetic:1,
	isshared:1,
	usesshareddatatype:1,
	freenextpass:1,
	isexternal:1,
	isdeclaration:1,
	isprototyped:1,
	isparam:1,
	ismember:1,
	isenumval:1,
	isinlineinstance:1,
	has_base_addr:1;

    /* Our refcnt. */
    REFCNT refcnt;

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
     */
    uint32_t size;

    /* If not a SYMBOL_TYPE_TYPE, our data type.
     * For functions, it is the return type; for anything else, its data
     * type.
     */
    struct symbol *datatype;

    /* If this symbol has an address (or multiple addresses, or a range
     * of addresses, this is the smallest one.
     */
    ADDR base_addr;

    union {
	struct symbol_type *ti;
	struct symbol_instance *ii;
    } s;
};

struct symbol_type {
    union {
	struct {
	    uint16_t bit_size;
	    encoding_t encoding:16;
	} t;
	struct {
	    struct list_head members;
	    int count;
	} e;
	struct {
	    struct list_head members;
	    int count;
	} su;
	struct {
	    int *subranges;
	    int count;
	    int alloc;
	} a;
	struct {
	    int nptrs;
	} p;
	/* For a function type (i.e., a DW_TAG_subroutine_type)
	 * this data describes the function's arg type info.
	 * The return type, if any, is specified in
	 * type_datatype above.
	 */
	struct {
	    struct list_head args;
	    uint16_t count;
	    uint8_t hasunspec:1;
	} f;
    } d;
};

struct symbol_instance {
    uint8_t isdeclinline:1,
	    isinlined:1;

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
    struct array_list *inline_instances;

    /* If this instance already has a value, this is it! */
    void *constval;

    union {
	/* For a function instance (i.e., a DW_TAG_subprogram or
	 * DW_TAG_inlined_subroutine, this data describes the
	 * function's "type" information.
	 */
	struct {
	    struct list_head args;
	    uint16_t count;
	    uint8_t hasunspec:1,
		    hasentrypc:1,
		       /* If the fb loc is a list or single loc. */
		    fbisloclist:1,
		    fbissingleloc:1,
		    prologue_guessed:1;
		       /* The frame base location.  Can be a list or
		        * single location.
			*/
	    union {
		struct loc_list *list;
		struct location *loc;
	    } fb;
	    struct symtab *symtab;
	    ADDR entry_pc;
	    ADDR prologue_end;
	    ADDR epilogue_begin;
	} f;
	struct {
	    /* If this symbol is a member of another, this is its list
	     * entry.  Right now, only variable symbols are members.
	     * Note that we also keep a pointer back to the symbol
	     * containing this symbol_instance struct; need this for
	     * list traversals.  Then we also keep a pointer back to the
	     * parent symbol we are a member of.
	     */
	    struct list_head member;
	    struct symbol *member_symbol;
	    struct symbol *parent_symbol;
	    uint16_t bit_offset;
	    uint16_t bit_size;
	} v;
	struct {
	    struct range range;
	} l;
    } d;

    struct location l;
};

/*
 * We return "elaborated" symbols from symbol lookups, and store location
 * resolution info in here too.  An elaborated symbol has the symbol's
 * chain if it is a nested symbol after a symbol lookup was performed.
 * After a symbol load has been performed, it also has the memory region
 * it currently exists in, the id the region had when the symbol was
 * loaded (so we know if we have to actually reload it later or not, OR
 * re-resolve its addr), and the resolved address it is at.  Since not
 * all symbols may have addresses (i.e., they may be in registers, OR
 * their location may change depending on the value of the PC), we also
 * set an addr_valid bit only if addr is set to something real.
 */
struct lsymbol {
    /* Our refcnt. */
    REFCNT refcnt;

    /*
     * If it is not a nested symbol, only the symbol itself.  Otherwise,
     * the deepest nested symbol.
     */
    struct symbol *symbol;
    /*
     * Contains a top-to-bottom list of symbols that have a hierarchical
     * relationship.  This list should have @symbol at the end if it
     * exists and has elements.
     */
    struct array_list *chain;
};

#endif
