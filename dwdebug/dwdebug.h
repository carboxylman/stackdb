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

#ifndef __LIBDWDEBUG_H__
#define __LIBDWDEBUG_H__

#include <stdint.h>
#include <stdio.h>
#include <glib.h>
#include <wchar.h>

#include <elfutils/libdw.h>

#include "debugpred.h"
#include "list.h"
#include "alist.h"
#include "config.h"
#include "log.h"
#include "output.h"
#include "common.h"

#if ELFUTILS_NO_VERSION_H
#define _INT_ELFUTILS_VERSION ELFUTILS_BIN_VERSION
#else
#include "elfutils/version.h"
#define _INT_ELFUTILS_VERSION _ELFUTILS_VERSION
#endif

/*
 * Any library users must call these to initialize global library state.
 */
void dwdebug_init(void);
void dwdebug_fini(void);

/**
 ** Some forward declarations.
 **/
struct debugfile;
struct symtab;
struct symbol;
struct lsymbol;
struct location;
struct range_list;
struct range_list_entry;
struct range;
struct loc_list_entry;
struct loc_list;

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

#define SYMBOL_IS_FULL_TYPE(sym) (sym && (sym)->type == SYMBOL_TYPE_TYPE \
				  && (sym)->s.ti)
#define SYMBOL_IS_FULL_VAR(sym) (sym && (sym)->type == SYMBOL_TYPE_VAR \
				 && (sym)->s.ii)
#define SYMBOL_IS_FULL_FUNCTION(sym) (sym && (sym)->type == SYMBOL_TYPE_FUNCTION \
				      && (sym)->s.ii)
#define SYMBOL_IS_FULL_LABEL(sym) (sym && (sym)->type == SYMBOL_TYPE_LABEL \
				   && (sym)->s.ii)

typedef enum {
    LOADTYPE_FULL         = 0,
    LOADTYPE_PARTIAL      = 1,
} load_type_t;

/*
 * In the symbol struct, these fields share a 32-bit int, divided this
 * way.  If you add more symbol types, or load types, adjust these
 * accordingly!
 */
#define LOAD_TYPE_BITS   1
#define SYMBOL_TYPE_BITS 3
#define SRCLINE_BITS     28

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

#define DATATYPE_CODE_BITS 4

#define SYMBOL_IST_VOID(sym)     (SYMBOL_IS_FULL_TYPE(sym) \
			          && (sym)->s.ti->datatype_code == DATATYPE_VOID)
#define SYMBOL_IST_ARRAY(sym)    (SYMBOL_IS_FULL_TYPE(sym) \
			          && (sym)->s.ti->datatype_code == DATATYPE_ARRAY)
#define SYMBOL_IST_STRUCT(sym)   (SYMBOL_IS_FULL_TYPE(sym) \
				  && (sym)->s.ti->datatype_code == DATATYPE_STRUCT)
#define SYMBOL_IST_ENUM(sym)     (SYMBOL_IS_FULL_TYPE(sym) \
			          && (sym)->s.ti->datatype_code == DATATYPE_ENUM)
#define SYMBOL_IST_PTR(sym)      (SYMBOL_IS_FULL_TYPE(sym) \
			          && (sym)->s.ti->datatype_code == DATATYPE_PTR)
#define SYMBOL_IST_FUNCTION(sym) (SYMBOL_IS_FULL_TYPE(sym) \
				  && (sym)->s.ti->datatype_code \
				                == DATATYPE_FUNCTION)
#define SYMBOL_IST_TYPEDEF(sym)  (SYMBOL_IS_FULL_TYPE(sym) \
				  && (sym)->s.ti->datatype_code \
				                == DATATYPE_TYPEDEF)
#define SYMBOL_IST_UNION(sym)    (SYMBOL_IS_FULL_TYPE(sym) \
			          && (sym)->s.ti->datatype_code == DATATYPE_UNION)
#define SYMBOL_IST_BASE(sym)     (SYMBOL_IS_FULL_TYPE(sym) \
			          && (sym)->s.ti->datatype_code == DATATYPE_BASE)
#define SYMBOL_IST_CONST(sym)    (SYMBOL_IS_FULL_TYPE(sym) \
			          && (sym)->s.ti->datatype_code == DATATYPE_CONST)
#define SYMBOL_IST_VOL(sym)      (SYMBOL_IS_FULL_TYPE(sym) \
			          && (sym)->s.ti->datatype_code == DATATYPE_VOL)
#define SYMBOL_IST_BITFIELD(sym) (SYMBOL_IS_FULL_TYPE(sym) \
				  && (sym)->s.ti->datatype_code \
				                == DATATYPE_BITFIELD)
/* convenient! */
#define SYMBOL_IST_STUN(sym)     (SYMBOL_IS_FULL_TYPE(sym) \
	                          && ((sym)->s.ti->datatype_code \
	                                        == DATATYPE_STRUCT \
	                              || (sym)->s.ti->datatype_code \
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
int debugfile_load(struct debugfile *debugfile);

char *debugfile_build_idstr(char *filename,char *name,char *version);
int debugfile_filename_info(char *filename,char **realfilename,
			    char **name,char **version);
int debugfile_add_symtab(struct debugfile *debugfile,struct symtab *symtab);
int debugfile_add_global(struct debugfile *debugfile,struct symbol *symbol);
struct symbol *debugfile_find_type(struct debugfile *debugfile,
				   char *typename);
int debugfile_add_type(struct debugfile *debugfile,struct symbol *symbol);
int debugfile_add_type_fakename(struct debugfile *debugfile,
				char *fakename,struct symbol *symbol);
void debugfile_dump(struct debugfile *debugfile,struct dump_info *ud);
void debugfile_free(struct debugfile *debugfile);

/**
 ** Symbol tables.
 **/
struct symtab *symtab_create(struct debugfile *debugfile,
			     char *srcfilename,char *compdirname,
			     int language,char *producer);
int symtab_insert(struct symtab *symtab,struct symbol *symbol,OFFSET anonaddr);
int symtab_insert_fakename(struct symtab *symtab,char *fakename,
			   struct symbol *symbol,OFFSET anonaddr);
/* These symtab_set functions are about dealing with memory stuff, not
 * about hiding symtabs from dwarf or anything.
 */
void symtab_set_name(struct symtab *symtab,char *srcfilename);
void symtab_set_compdirname(struct symtab *symtab,char *compdirname);
void symtab_set_producer(struct symtab *symtab,char *producer);
void symtab_dump(struct symtab *symtab,struct dump_info *ud);
void symtab_free(struct symtab *symtab);
#ifdef DWDEBUG_USE_STRTAB
int symtab_str_in_strtab(struct symtab *symtab,char *strp);
#endif

/**
 ** Symbols.
 **/
struct symbol *symbol_create(struct symtab *symtab,SMOFFSET offset,
			     char *name,symbol_type_t symtype);
struct symbol *symbol_create_full(struct symtab *symtab,SMOFFSET offset,
				  char *name,symbol_type_t symtype);
void symbol_set_type(struct symbol *symbol,symbol_type_t symtype);
void symbol_set_name(struct symbol *symbol,char *name);
void symbol_set_srcline(struct symbol *symbol,int srcline);

int symbol_contains_addr(struct symbol *symbol,ADDR obj_addr);

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
void symbol_free(struct symbol *symbol);

struct lsymbol *lsymbol_create(struct symbol *symbol,struct array_list *chain);
void lsymbol_dump(struct lsymbol *lsymbol,struct dump_info *ud);
void lsymbol_free(struct lsymbol *lsymbol);

/**
 ** Locations.
 **/
struct location *location_create(void);
int location_is_conditional(struct location *location);
void location_dump(struct location *location,struct dump_info *ud);
void location_internal_free(struct location *location);
void location_free(struct location *location);

/**
 ** Symtab (PC) lookup functions.
 **/
/*
 * Find the symbol table corresponding to the supplied PC.
 */
struct symtab *symtab_lookup_pc(struct symtab *symtab,ADDR pc);

/**
 ** Symbol/memaddr lookup functions.
 **/
/* If you know which debugfile contains your symbol, this is fastest. */
struct lsymbol *debugfile_lookup_sym(struct debugfile *debugfile,
				     char *name,const char *delim,
				     char *srcfile,symbol_type_flag_t ftype);
struct symbol *debugfile_lookup_addr(struct debugfile *debugfile,ADDR addr);

/* Look up one symbol in a symbol table by name. */
struct lsymbol *symtab_lookup_sym(struct symtab *symtab,
				  char *name,const char *delim,
				  symbol_type_flag_t ftype);
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
 */
struct symbol *symbol_get_one_member(struct symbol *symbol,char *member);
/*
 * Given a starting symbol, searches its member hierarchy according to
 * the given delimited string of member variables.
 */
struct symbol *symbol_get_member(struct symbol *symbol,char *memberlist,
				 const char *delim);/*
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
int get_lines(struct debugfile *debugfile,Dwarf_Off offset,size_t address_size);

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


/**
 ** Data structure definitions.
 **/
struct debugfile {
    /* The type of debugfile */
    debugfile_type_t type;

    int refcnt;

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
     * The debug string table for this file.  All string pointers are
     * checked for presence in this table before freeing.
     *
     * This table persists until the debugfile is freed.
     */
    char *strtab;

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
    unsigned int strtablen;
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
     * this table.
     *
     * h(address) = struct symbol *
     */
    GHashTable *addresses;
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
	};
	struct range_list rlist;
    };
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

/*
 * Symbol tables are mostly just backreferences to the objects they are
 * associated with (the parent debugfile they are in, and the srcfile
 * from the original source they are present in)... and the hashtable
 * itself.
 */
struct symtab {
    struct debugfile *debugfile;

    /* This may be the source filename, OR a subscope name. */
    char *name;
    /* If this was a source filename, a compilation dir should be set. */
    char *compdirname;

    /* The range for this symtab is either a list of ranges, or a
     * low_pc/high_pc range.
     */
    struct range range;

    char *producer;
    int language;

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
     * scope.
     *
     * h(sym) -> struct symbol * 
     */
    GHashTable *tab;

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

    /* Our refcnt. */
    REFCNT refcnt;

    /* Our offset location in the debugfile. */
    SMOFFSET ref;

    /* If we see the use of the type before the type, or we're doing
     * partial loads, we can only fill in the ref and fill the datatype
     * in a postpass.
     */
    SMOFFSET datatype_ref;

    /* Are we full or partial? */
    load_type_t loadtag:LOAD_TYPE_BITS;

    /* The kind of symbol we are. */
    symbol_type_t type:SYMBOL_TYPE_BITS;

    /* Where we exist. */
    unsigned int srcline:SRCLINE_BITS;

    /* If not a SYMBOL_TYPE_TYPE, our data type.
     * For functions, it is the return type; for anything else, its data
     * type.
     */
    struct symbol *datatype;

    /* If this symbol is a member of another, this is its list entry. */
    /* XXX: maybe move this into the type detail stuff to save mem? */
    struct list_head member;

    union {
	struct symbol_type *ti;
	struct symbol_instance *ii;
    } s;
};

struct symbol_type {
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
     * When the fakename pointer is non-NULL, that means that
     * the symbol's name is in fakename + offset (i.e., if 'X'
     * is a struct type, then fakename + 7 = 'X'.  In this case,
     * we set name to fakename + offset -- AND MOST IMPORTANTLY,
     * don't free name -- but only fakename.
     *
     * What a mess.
     */
    char *extname;

    datatype_code_t datatype_code:DATATYPE_CODE_BITS;

    uint8_t isanon:1,
            isvoid:1,
	    isexternal:1,
	    isprototyped:1;

    uint16_t byte_size;

    /* If we see the use of the type before the type, we
     * can only fill in the ref and fill the datatype in
     * a postpass.
     */
    SMOFFSET type_datatype_ref;
    struct symbol *type_datatype;

    union {
	struct {
	    encoding_t encoding;
	    int bit_size;
	} v;
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
    uint8_t isparam:1,
	    ismember:1,
	    isenumval:1,
	    isdeclinline:1,
	    isinlined:1,
	    isinlineinstance:1,
	    isexternal:1,
	    isprototyped:1;

    /* If this instance is inlined, these point back to the
     * source for the inlined instance.  If it was a forward ref
     * in the DWARF info, origin_ref is set and origin has to be
     * filled in a postpass.
     */
    SMOFFSET origin_ref;
    struct symbol *origin;

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
		struct loc_list *fblist;
		struct location *fbloc;
	    };
	    struct symtab *symtab;
	    ADDR entry_pc;
	    ADDR prologue_end;
	    ADDR epilogue_begin;
	} f;
	struct {
	    uint16_t byte_size;
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
    /*
     * If it is not a nested symbol, only the symbol itself.  Otherwise,
     * the deepest nested symbol.
     */
    struct symbol *symbol;
    /*
     * Contains a top-to-bottom list of symbols that have a hierarchical
     * relationship.
     */
    struct array_list *chain;
};

#endif
