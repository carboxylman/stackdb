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

/**
 ** Some forward declarations.
 **/

/**
 ** Binfile decls.  Users don't get to see anything about these.
 **/
struct binfile;
struct binfile_ops;
struct binfile_instance;

/**
 ** Debugfile decls.  Users get to see some of this stuff.
 **/
struct debugfile;
struct debugfile_ops;
struct debugfile_load_opts;
struct scope;
struct symbol;
struct lsymbol;

/**
 ** Invisible things.
 **/
struct symdict;

/**
 ** Library users must call these to initialize global library state.
 ** They may be called as many times as necessary; but are NOT thread
 ** safe.
 **/
void dwdebug_init(void);
void dwdebug_fini(void);

void dwdebug_evict(struct debugfile *debugfile);
void dwdebug_evict_all(void);

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
    DEBUGFILE_LOAD_FLAG_NODWARF   = 1 << 2,
    /*
     * If this is set, all scope ranges will be added to the primary
     * range fast lookup struct.  This makes loading slow, but should
     * result in the fastest possible lookups.
     */
    DEBUGFILE_LOAD_FLAG_ALLRANGES = 1 << 3,
    /*
     * By default, declaration symbols that are defined are replaced
     * with those definition symbols (i.e., they are deleted, and
     * anything that referenced them is changed to use the definition
     * symbol instead).
     *
     * This simplifies the view of the program the user sees; but
     * sometimes the user might *want* to access the declaration
     * symbol (or the defn/decl resolution code might make mistakes!);
     * hence, this option exists.
     */
    DEBUGFILE_LOAD_FLAG_KEEPDECLS = 1 << 4,
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
    SYMBOL_TYPE_NONE      = 0,
    SYMBOL_TYPE_ROOT      = 1,
    SYMBOL_TYPE_TYPE      = 2,
    SYMBOL_TYPE_VAR       = 3,
    SYMBOL_TYPE_FUNC      = 4,
    SYMBOL_TYPE_LABEL     = 5,
    SYMBOL_TYPE_BLOCK     = 6,
} symbol_type_t;
char *SYMBOL_TYPE(int n);

typedef enum {
    SYMBOL_SOURCE_DWARF   = 0,
    SYMBOL_SOURCE_ELF     = 1,
    SYMBOL_SOURCE_PHP     = 2,
} symbol_source_t;
char *SYMBOL_SOURCE(int n);

typedef enum {
    LOADTYPE_UNLOADED     = 0,
    LOADTYPE_FULL         = 1,
    LOADTYPE_PARTIAL      = 2,
} load_type_t;

/*
 * In the symbol struct, these fields share a 32-bit int, divided this
 * way.  If you add more symbol types, or load types, adjust these
 * accordingly!
 *
 * Ok, that comment is no longer accurate.  You just have to check the
 * bitfield usage in struct symbol before changing these.  We don't want
 * to go over 64 bits total used there in all the bitfields.
 */
#define LOAD_TYPE_BITS      2
#define SYMBOL_TYPE_BITS    3
#define SYMBOL_SOURCE_BITS  2
#define DATATYPE_CODE_BITS  4
#define SRCLINE_BITS       20

/* We use this enum type for filtering during symbol searching, when the
 * caller might accept multiple different symbol types.
 */
typedef enum {
    SYMBOL_TYPE_FLAG_NONE     = 0,
    SYMBOL_TYPE_FLAG_ROOT     = 1 << SYMBOL_TYPE_ROOT,
    SYMBOL_TYPE_FLAG_TYPE     = 1 << SYMBOL_TYPE_TYPE,
    SYMBOL_TYPE_FLAG_VAR      = 1 << SYMBOL_TYPE_VAR,
    SYMBOL_TYPE_FLAG_FUNC     = 1 << SYMBOL_TYPE_FUNC,
    SYMBOL_TYPE_FLAG_LABEL    = 1 << SYMBOL_TYPE_LABEL,
    SYMBOL_TYPE_FLAG_BLOCK    = 1 << SYMBOL_TYPE_BLOCK,
    /*
     * We don't distinguish "kinds" of variables, but it is useful to do
     * so for searching!  So this is nasty but ok.
     */
    SYMBOL_TYPE_FLAG_VAR_ARG      = 1 << 24,
    SYMBOL_TYPE_FLAG_VAR_LOCAL    = 1 << 25,
    SYMBOL_TYPE_FLAG_VAR_GLOBAL   = 1 << 26,
    SYMBOL_TYPE_FLAG_VAR_MEMBER   = 1 << 27,
} symbol_type_flag_t;

typedef enum {
    DATATYPE_VOID         = 0,
    DATATYPE_ARRAY        = 1,
    DATATYPE_STRUCT       = 2,
    DATATYPE_ENUM         = 3,
    DATATYPE_PTR          = 4,
    DATATYPE_REF          = 5,
    DATATYPE_FUNC         = 6,
    DATATYPE_TYPEDEF      = 7,
    DATATYPE_UNION        = 8,
    DATATYPE_BASE         = 9,
    DATATYPE_CONST        = 10,
    DATATYPE_VOL          = 11,
    DATATYPE_NAMESPACE    = 12,
    DATATYPE_CLASS        = 13,
    DATATYPE_TEMPLATE     = 14,
    DATATYPE_DYNAMIC      = 15,
} datatype_code_t;
char *DATATYPE(int n);

/**
 ** Location decls.
 **/
struct location;
struct location_ops;
struct location_ctxt;
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
    LOCTYPE_IMPLICIT_WORD = 9,
    LOCTYPE_IMPLICIT_DATA = 10,
    /* add here */
    LOCTYPE_RUNTIME       = 11,
} loctype_t;

/*
 * Provided so that regular users can call (l)symbol_resolve_location
 * and still have a valid output location value, without having to know
 * the details of the location struct (which are gory).
 */
struct location *location_create(void);
void location_free(struct location *location);

/*
 * These match the dwarf encoding codes, for base types, up to 32.
 * After that, they are what we need them to be -- i.e., special base
 * types.  These special base types need to be loaded by custom loaders
 * in whatever is using dwdebug; probably target/, in a specific
 * backend.
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

    /*
     * Dynamic, untyped, or partially-typed languages may have a notion
     * of variables with dynamic types.
     *
     * But rather than create a custom encoding for this use, we prefer
     * that DATATYPE_DYNAMIC is used.
     */

    /*
     * Some languages have a notion of string types that are not defined
     * by another kind of base type.
     */
    ENCODING_STRING = 32,
    /*
     * Some languages have a notion of associative arrays, hashes,
     * dictionaries, etc.  This is that stuff.
     */
    ENCODING_HASH   = 33,
} encoding_t;

/**
 ** Debugfiles.
 **/
/*
 * This is the only function users should call to obtain debugfiles.  It
 * tries to share already-loaded debugfiles based off a global cache;
 * handles the case where the user passes in a file with debuginfo
 * embedded in it, OR the case when they pass in an executable or
 * library (by attempting to track down the debuginfo file).
 *
 * There are several scenarios in which we want to load a debugfile.
 *  1)  We have a filename, and we want to load the debuginfo that it
 *      contains, or that it points to (via symlink, or internal
 *      content).
 *  2a) We have a binfile_instance with a binfile associated with it.
 *      In this case, we must first open a copy of the binfile
 *      associated with the instance data, UNLESS the binfile is already
 *      associated with this exact instance (if that is true, we just
 *      return the binfile).
 *  2b) We have a binfile_instance with a filename, and no associated
 *      binfile.  We just open the filename against the instance.
 *  3)  We have a binfile; just load debuginfo from that file, or from
 *      the file that that binfile points to.
 */
struct debugfile *debugfile_from_file(char *filename,char *root_prefix,
				      struct array_list *debugfile_load_opts_list);
struct debugfile *debugfile_from_instance(struct binfile_instance *bfinst,
					  struct array_list *debugfile_load_opts_list);
struct debugfile *debugfile_from_binfile(struct binfile *binfile,
					 struct array_list *debugfile_load_opts_list);
/*
 * Search the debugfile path @DFPATH (if NULL, use default PATH) for a
 * filepath @filename, possibly in a root_prefix dir @root_prefix, and
 * try the @debug_postfix if @filename is not found directly (if
 * @debug_postfix is NULL, ".debug" will be used).  If @buf is not NULL,
 * we write as much of the found path as possible (given @buflen) into
 * @buf.  On success, a valid path is returned; on error, NULL is
 * returned and ESRCH is set.  If the user did not supply @buf, a buffer
 * is allocated.
 */
char *debugfile_search_path(char *filename,char *root_prefix,char *debug_postfix,
			    const char *DFPATH[],char *buf,int buflen);
struct array_list *debugfile_get_loaded_debugfiles();
struct debugfile_load_opts *debugfile_load_opts_parse(char *optstr);
int debugfile_load_opts_checklist(struct array_list *opts_list,char *name,
				  struct debugfile_load_opts **match_saveptr);
void debugfile_load_opts_free(struct debugfile_load_opts *opts);
char *debugfile_get_name(struct debugfile *debugfile);
char *debugfile_get_version(struct debugfile *debugfile);
int debugfile_filename_info(char *filename,char **realfilename,
			    char **name,char **version);
void debugfile_dump(struct debugfile *debugfile,struct dump_info *ud,
		    int types,int globals,int symtabs,int elfsymtab,
		    int doranges);
//REFCNT debugfile_release(struct debugfile *debugfile);

/**
 ** Symbols.
 **/
/*
 * Create a symbol.  If @name_copy is set, @name will be copied into new
 * memory; else not.  @offset is a value that functions as a pointer to
 * the raw location of the symbol description in its original file.  If
 * @full is set, this will be a full symbol, and all memory for its
 * @symtype is allocated.  Otherwise, only a partial symbol is created.
 */
struct symbol *symbol_create(symbol_type_t symtype,symbol_source_t source,
			     char *name,int name_copy,SMOFFSET offset,
			     load_type_t loadtype,struct scope *scope);
/*
 * Returns the name of the symbol.  Might be modified if it was an
 * inline instance (in which case call symbol_get_name_inline() to get
 * the inlined function's real name), or if it was an enum/struct/union
 * (in which case we prefix the enum/struct/union part -- see
 * symbol_build_extname).
 */
char *symbol_get_name(struct symbol *symbol);
/*
 * If this is an inline instance, we try to return the real name of the
 * inlined function -- instead of the modified, unique inline instance
 * name.
 */
char *symbol_get_name_inline(struct symbol *symbol);

char *symbol_get_srcfile(struct symbol *symbol);
int symbol_get_srcline(struct symbol *symbol);
char *symbol_get_compdirname(struct symbol *symbol);
symbol_type_t symbol_get_type(struct symbol *symbol);
symbol_source_t symbol_get_source(struct symbol *symbol);
/*
 * symbol_get_datatype returns the "meaningful" datatype of symbol --
 * i.e., it follows inline info, skips type qualifiers).
 * symbol_get_datatype_real follows inline info, but does not skip type
 * qualifiers.
 *
 * These functions do not hold a ref to the return value.
 */
struct symbol *symbol_get_datatype(struct symbol *symbol);
struct symbol *symbol_get_datatype_real(struct symbol *symbol);
struct symbol *symbol_get_inline_origin(struct symbol *symbol);

int symbol_is_synthetic(struct symbol *symbol);
int symbol_is_external(struct symbol *symbol);
int symbol_is_definition(struct symbol *symbol);
int symbol_is_declaration(struct symbol *symbol);
int symbol_is_decldefined(struct symbol *symbol);
int symbol_is_prototyped(struct symbol *symbol);
int symbol_is_parameter(struct symbol *symbol);
int symbol_is_member(struct symbol *symbol);
int symbol_is_enumerator(struct symbol *symbol);
int symbol_is_inlineinstance(struct symbol *symbol);
int symbol_has_addr(struct symbol *symbol);
int symbol_has_unspecified_parameters(struct symbol *symbol);
int symbol_is_inlined(struct symbol *symbol);
int symbol_is_declinline(struct symbol *symbol);
int symbol_is_bitsize(struct symbol *symbol);
int symbol_is_bytesize(struct symbol *symbol);
uint32_t symbol_get_bytesize(struct symbol *symbol);
uint32_t symbol_get_bitsize(struct symbol *symbol);
uint32_t symbol_get_bitoffset(struct symbol *symbol);
uint32_t symbol_get_bitctbytes(struct symbol *symbol);
ADDR symbol_get_addr(struct symbol *symbol);
int symbol_type_flags_match(struct symbol *symbol,symbol_type_flag_t flags);
struct symbol *symbol_find_parent(struct symbol *symbol);
struct symbol *symbol_find_root(struct symbol *symbol);
int symbol_contains_addr(struct symbol *symbol,ADDR obj_addr);
int symbol_type_equal(struct symbol *t1,struct symbol *t2,
		      GHashTable *eqcache,GHashTable *updated_datatype_refs);
int symbol_type_is_char(struct symbol *type);
unsigned int symbol_type_array_bytesize(struct symbol *type);
/* Return either type_array_bytesize or type_bytesize */
unsigned int symbol_type_full_bytesize(struct symbol *type);
struct symbol *symbol_type_skip_ptrs(struct symbol *type);
struct symbol *symbol_type_skip_qualifiers(struct symbol *type);

void symbol_dump(struct symbol *symbol,struct dump_info *ud);
void symbol_type_dump(struct symbol *symbol,struct dump_info *ud);
void symbol_function_dump(struct symbol *symbol,struct dump_info *ud);
void symbol_var_dump(struct symbol *symbol,struct dump_info *ud);

/*
 * Returns a new GSList * with the ordered member symbols of @symbol.
 * i.e., the function's arguments; the struct's members; an enumerated
 * type's enumerators.  The symbols on the list must be released with
 * symbol_release when you finish with them.
 */
GSList *symbol_get_ordered_members(struct symbol *symbol,
				   symbol_type_flag_t flags);
/*
 * Returns a new GSList * with the member symbols of @symbol.  The
 * symbols on the list must be released with symbol_release when you
 * finish with them.
 */
GSList *symbol_get_members(struct symbol *symbol,
			   symbol_type_flag_t flags);

/*
 * Returns LOCTYPE_REG, LOCTYPE_ADDR, or LOCTYPE_MEMBER_OFFSET, on success;
 * LOCTYPE_UNKNOWN on error (or if the location really is
 * LOCTYPE_UNKNOWN), or -LOCTYPE_X on error resolving a specific kind of
 * location.  If LOCTYPE_UNKNOWN or negative, errno should be set.
 *
 * Some locations cannot be resolved without @lctxt->lops.  Also, if
 * they can (i.e., they are already of LOCTYPE_ADDR or LOCTYPE_REG or
 * LOCTYPE_MEMBER_OFFSET), the return values will not be relocated if
 * @lctxt->lops is not set.
 *
 * Also note that lsymbol_resolve_location() does not allow you to
 * resolve an offset.  The only reason that symbol_resolve_location and
 * location_resolve() do provide an offset outparam is because single
 * symbols/locations are sometimes offsets.
 */

loctype_t symbol_resolve_location(struct symbol *symbol,
				  struct location_ctxt *lctxt,
				  struct location *o_loc);
int symbol_resolve_bounds(struct symbol *symbol,
			  struct location_ctxt *lctxt,
			  ADDR *start,ADDR *end,int *is_noncontiguous,
			  ADDR *o_alt_start,ADDR *o_alt_end);
loctype_t lsymbol_resolve_location(struct lsymbol *lsymbol,ADDR base_addr,
				   struct location_ctxt *lctxt,
				   struct location *o_loc);
int lsymbol_resolve_bounds(struct lsymbol *lsymbol,ADDR base_addr,
			   struct location_ctxt *lctxt,
			   ADDR *start,ADDR *end,int *is_noncontiguous,
			   ADDR *alt_start,ADDR *alt_end);

/*
 * Holds a ref to @symbol.  This is useful for users because some
 * functions (i.e., symbol_get_datatype) do not hold a ref to their
 * return value.  Lookup functions tend to hold refs, 
 */
void symbol_hold(struct symbol *symbol);
/*
 * Releases a reference to the symbol and tries to free it.
 */
REFCNT symbol_release(struct symbol *symbol);


/* If we already know that @member is a member of @symbol -- i.e., it is
 * a nested var in a struct or function, or a function/function type
 * param, etc... we can just clone @parent's chain and extend it by one
 * to include the child.
 *
 * Users might sometimes wish to call this function to obtain an lsymbol
 * structure, but they shouldn't need to.
 *
 * You must call lsymbol_release() to unhold the return value.
 */
struct lsymbol *lsymbol_create_from_member(struct lsymbol *parent,
					   struct symbol *member);
/*
 * Clones the non-inlineinstance part of @lsymbol.
 *
 * You must call lsymbol_release() to unhold the return value.
 */
struct lsymbol *lsymbol_create_noninline(struct lsymbol *lsymbol);
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
 * You must call lsymbol_release() to unhold the return value.
 */
struct lsymbol *lsymbol_create_from_symbol(struct symbol *symbol);
char *lsymbol_get_name(struct lsymbol *lsymbol);
struct symbol *lsymbol_get_symbol(struct lsymbol *lsymbol);
/*
 * Returns the deepest non-inline-instance symbol in the lookup chain.
 * So if you want the first function that contains one (or more nested)
 * inline instance, you can use this function.
 */
struct symbol *lsymbol_get_noninline_parent_symbol(struct lsymbol *lsymbol);
void lsymbol_dump(struct lsymbol *lsymbol,struct dump_info *ud);
/*
 * Releases the reference to the lsymbol, and frees it if its refcnt is
 * 0.
 */
REFCNT lsymbol_release(struct lsymbol *lsymbol);

/**
 ** Scope (PC) lookup functions.
 **/
/*
 * Find the symbol table corresponding to the supplied PC.
 */
struct scope *scope_lookup_addr(struct scope *scope,ADDR pc);

/**
 ** Symbol/memaddr lookup functions.
 **/
/* 
 * Look up a (possibly delimited with @delim) symbol named @name in
 * @debugfile.  @flags contains symbol_type_flag_t flags controlling
 * which kind of symbols we will return.  If @flags == SYMBOL_TYPE_FLAG_NONE, 
 * we will return the first match of any symbol type on the given name;
 * _NONE is a wildcard.  If @flags is the wildcard, or has any of
 * SYMBOL_TYPE_FLAG_VAR, SYMBOL_TYPE_FLAG_FUNC, SYMBOL_TYPE_FLAG_LABEL
 * set, we will first consult the global names (functions or variables)
 * in the debugfile.  If no matches result from that, and @flags is the
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
				     symbol_type_flag_t flags);

/*
 * Lookup an offset of a member in a variable (of type struct/union), or
 * in a type of struct/union.
 */
OFFSET symbol_offsetof(struct symbol *symbol,
		       const char *name,const char *delim);

/*
 * Lookup an offset of a member in a variable (of type struct/union), or
 * in a type of struct/union.
 */
OFFSET lsymbol_offsetof(struct lsymbol *lsymbol,
			const char *name,const char *delim);

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
 * Our search and return values will be restricted by which @flags
 * symbol type flags you set; you can set a combination; if you set it
 * to 0 (SYMBOL_TYPE_FLAG_NONE), we do not restrict our symbol search or
 * return values.
 *
 * The returned GSList must be freed using g_list_free; if any of the
 * debugfile/symtab hashtables is modified later (i.e., the debugfile is
 * only partially loaded), this list may not be used.
 *
 * The items on this list are struct symbol *, and if you want to use
 * them, you MUST RHOLD() them!  This function does not do it for
 * you!
 */
GSList *debugfile_match_syms(struct debugfile *debugfile,
			     struct rfilter *symbol_filter,
			     symbol_type_flag_t flags,
			     struct rfilter *srcfile_filter);

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
int debugfile_lookup_line_addr(struct debugfile *debugfile,
			       char *filename,ADDR addr);
int debugfile_lookup_filename_line_addr(struct debugfile *debugfile,
					ADDR addr,char **filename,int *line);
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

struct lsymbol *lsymbol_lookup_sym(struct lsymbol *lsymbol,
				   const char *name,const char *delim);

struct symbol *symbol_get_sym(struct symbol *symbol,const char *name,
			      symbol_type_flag_t flags);
struct lsymbol *symbol_lookup_sym(struct symbol *symbol,
				  const char *name,const char *delim);

/*
 * Returns a clone of @lsymbol, with reference taken, and if @newchild
 * is not NULL, @newchild is appended
 */
struct lsymbol *lsymbol_clone(struct lsymbol *lsymbol,struct symbol *newchild);

/*
 * @symbol may be either a SYMBOL_TYPE_TYPE, a SYMBOL_TYPE_FUNC, or
 * a SYMBOL_TYPE_VAR.  This function is really about returning an instance
 * symbol, BUT we allow it to take an instance symbol that is either a
 * function, so we can get the type symbol for an arg, or a
 * struct/union, so we can get the type symbol for a member.  Sugar.
 * Hopefully not too confusing.
 *
 * SYMBOL_TYPE_TYPE:
 *   DATATYPE_FUNC: find an arg matching @member.
 *   DATATYPE_ENUM: find a matching enumerator.
 *   DATATYPE_(STRUCT|UNION): find a matching member.  If @symbol
 *     contains anonymous members, we recurse into those in a BFS.
 * SYMBOL_TYPE_FUNC: find an arg matching @member.
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
 * Returns a real, valid type for the symbol.  If it is an inline
 * instance, we skip to the abstract origin root and use that datatype.
 * If not, for now we just return @symbol->type.
 *
 * If this function returns a symbol, it takes a reference to it.
 * symbol_release is the correct way to release these refs.
 */
struct symbol *symbol_get_datatype(struct symbol *symbol);
/*
 * Given an IP (as an object-relative address), check and see if this
 * symbol is currently visible (in scope).  To do this we, check if the
 * IP is in the symtab's range; or if it is in any child symtab's range
 * where no symbol in that symtab overrides the primary symbol name!
 */
int symbol_visible_at_ip(struct symbol *symbol,ADDR ip);

/**
 ** Data structure definitions.
 **/
struct debugfile_load_opts {
    struct rfilter *debugfile_filter;
    struct rfilter *srcfile_filter;
    struct rfilter *symbol_filter;
    debugfile_load_flags_t flags;
};

/*
 * Only support DWARF debugfiles right now; but also support fake
 * debuginfo from ELF symtabs if the ELF files don't have DWARF
 * debuginfo; that way they can use the same interfaces for symbol
 * lookup, etc.
 */
typedef enum {
    DEBUGFILE_TYPE_NONE  = 0,
    DEBUGFILE_TYPE_ELF = 1 << 0,
    DEBUGFILE_TYPE_DWARF = 1 << 1,
    DEBUGFILE_TYPE_PHP = 1 << 1,
} debugfile_type_t;

typedef enum {
    DEBUGFILE_TYPE_FLAG_NONE   = 0,
    DEBUGFILE_TYPE_FLAG_KERNEL = 1 << 0,
    DEBUGFILE_TYPE_FLAG_KMOD   = 1 << 1,
} debugfile_type_flag_t;
typedef int debugfile_type_flags_t;

struct debugfile {
    /*
     * The debugfile type and flags.
     */
    debugfile_type_t type;
    debugfile_type_flags_t flags;

    /* Our reference count. */
    REFCNT refcnt;
    /* Our weak reference count. */
    //REFCNT refcntw;

    /*
     * debugfile backend type-specific ops and state.
     */
    struct debugfile_ops *ops;
    void *priv;

    /* Save the options we were loaded with, forever. */
    struct debugfile_load_opts *opts;

    /*
     * The binfile we are extracting debuginfo and ELF info from.
     */
    struct binfile *binfile;

    /*
     * This should be a copy of @binfile->filename; this way, we still
     * have the name of the file even if binfile is binfile_close()d or
     * binfile_free()d.
     *
     * This is a unique ID used for caching.
     */
    char *filename;

    /*
     * This is a unique integer ID when we need one (XML SOAP server);
     * just comes from ++debugfile_id_idx .
     */
    int id;

    /*
     * The binfile that pointed us to @binfile; if set, it is likely a
     * stripped executable, library, or object file that points to a
     * non-stripped, or debuginfo-only, binfile.
     */
    struct binfile *binfile_pointing;

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

    /*
     * The frame table for this file (CFA).  It is live until
     * debugfile_free, since we interpret it on-demand.
     */
    char *frametab;

    /* Table lengths -- moved here for struct packing. */
    unsigned int dbg_strtablen;
    unsigned int loctablen;
    unsigned int rangetablen;
    unsigned int linetablen;
    unsigned int frametablen;

    /*
     * Each srcfile in a debugfile gets its own SYMBOL_TYPE_ROOT symbol.
     *
     * h(srcfile) -> struct symbol *
     *
     * (Well, except for when srcfiles are included multiple times in a
     * build; see next hash.  Those srcfile/root symtab pairs are moved
     * into the table below.)
     */
    GHashTable *srcfiles;

    /*
     * Some srcfiles are included multiple times at different points in
     * the build (should be mostly assembly source files).
     *
     * h(srcfile) -> struct array_list * -> struct symbol *
     */
    GHashTable *srcfiles_multiuse;

    /*
     * Each CU srcfile gets its own SYMBOL_TYPE_ROOT symbol.  This is a
     * map between CU offsets (i.e., in aranges and pubnames) and symbols.
     *
     * h(offset) -> struct symbol *
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

    /*
     * This hashtable holds types that have been shared across srcfiles.
     */
    GHashTable *shared_types;

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
     * Since types and instances can be declared in one CU, but defined
     * in another CU, as we load, we populate this hashtable with lists
     * of declared, undefined symbols.  Then, when we load a global
     * instance symbol, or a "global" type, we try to resolve them.
     */
    GHashTable *decllists;

    /*
     * When we *do* resolve a declaration to some definition symbol, we
     * have to save the fact that we did so somewhere, because we copy
     * mem from the defn to decl.  We would have liked to have
     * RHOLD(decl,defn), but we cannot store the defn pointer in the
     * decl symbol -- no room.  We cannot guarantee we could trace to
     * the debugfile (the other obvious place to store the fact that
     * decl holds defn) during symbol_free, because the parent hierarchy
     * may already be being torn down.
     *
     * So, the only strategy we are left with is when a defn is used for
     * the first time by a decl, take a ref on the defn and store that
     * in this table, and only release the ref when the debugfile is
     * destroyed.  This could be wasteful if we ever wanted to free
     * parts of debugfiles but not their entirety; but we don't support
     * that for now so it doesn't matter.
     */
    GHashTable *decldefnsused;

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
    GHashTable *srcaddrlines;
};

struct dwarf_cu_die_ref {
    SMOFFSET cu_offset;
    SMOFFSET die_offset;
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
    /* Our weak reference count. */
    //REFCNT refcntw;

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
