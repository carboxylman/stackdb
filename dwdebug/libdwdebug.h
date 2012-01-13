#ifndef __LIBDWDEBUG_H__
#define __LIBDWDEBUG_H__

#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdint.h>
#include <stdio.h>
#include <glib.h>
#include <wchar.h>

#include "list.h"
#include "config.h"

#if ELFUTILS_NO_VERSION_H
#define _INT_ELFUTILS_VERSION ELFUTILS_BIN_VERSION
#else
#include "elfutils/version.h"
#define _INT_ELFUTILS_VERSION _ELFUTILS_VERSION
#endif

/*
 * Everybody's gotta call this!
 */
void libdwdebug_init(void);

void libdwdebug_set_debug_level(int level);
#ifdef LIBDWDEBUG_DEBUG
void _libdwdebug_debug(int level,char *format,...);

#define ldebug(level,format,...) _libdwdebug_debug(level,"LDDEBUG: %s:%d: "format, __FUNCTION__, __LINE__, ## __VA_ARGS__)
#else
#define ldebug(devel,format,...) ((void)0)
#endif

#define lerror(format,...) fprintf(stderr, "LDERROR: %s:%d: "format, __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define lwarn(format,...) fprintf(stderr, "LDWARNING: %s:%d: "format, __FUNCTION__, __LINE__, ## __VA_ARGS__)

/**
 ** Some forward declarations.
 **/
struct target;
struct target_ops;
struct addrspace;
struct memregion;
struct debugfile;
struct symtab;
struct symbol;
struct symbol_chain;
struct location;
struct range_list_entry;
struct range;
struct loc_list_entry;
struct loc_list;

struct dump_info;

/* Might have to split these out into platform-specific stuff later; for
 * now, just make them big enough for anything.
 */
typedef uint64_t ADDR;
typedef int64_t OFFSET;
typedef uint8_t REG;
typedef uint64_t REGVAL;

#define PRIxADDR PRIx64
#define PRIuADDR PRIu64

#define DATA_BIG_ENDIAN 0
#define DATA_LITTLE_ENDIAN 1

#define PROT_READ         0x00000001
#define PROT_WRITE        0x00000002
#define PROT_EXEC         0x00000004
#define PROT_SHARED       0x00000008

typedef enum {
    STATUS_UNKNOWN        = 0,
    STATUS_RUNNING        = 1,
    STATUS_PAUSED         = 2,
    STATUS_DEAD           = 3,
    STATUS_STOPPED        = 4,
    STATUS_ERROR          = 5,
    STATUS_DONE           = 6,
    __STATUS_MAX,
} target_status_t;
extern char *STATUS_STRINGS[];
#define STATUS(n) (((n) < __STATUS_MAX) ? STATUS_STRINGS[(n)] : NULL)

typedef enum {
    REGION_TYPE_HEAP           = 0,
    REGION_TYPE_STACK          = 1,
    REGION_TYPE_VDSO           = 2,
    REGION_TYPE_VSYSCALL       = 3,
    REGION_TYPE_ANON           = 4,
    REGION_TYPE_MAIN           = 5,
    REGION_TYPE_LIB            = 6,
    __REGION_TYPE_MAX,
} region_type_t;
extern char *REGION_STRINGS[];
#define REGION_TYPE(n) (((n) < __REGION_TYPE_MAX) ? REGION_TYPE_STRINGS[(n)] : NULL)

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

#define SYMBOL_IST_VOID(sym)     (sym && (sym)->type == SYMBOL_TYPE_TYPE \
			          && (sym)->s.ti.datatype_code == DATATYPE_VOID)
#define SYMBOL_IST_ARRAY(sym)    (sym && (sym)->type == SYMBOL_TYPE_TYPE \
			          && (sym)->s.ti.datatype_code == DATATYPE_ARRAY)
#define SYMBOL_IST_STRUCT(sym)   (sym && (sym)->type == SYMBOL_TYPE_TYPE \
				  && (sym)->s.ti.datatype_code == DATATYPE_STRUCT)
#define SYMBOL_IST_ENUM(sym)     (sym && (sym)->type == SYMBOL_TYPE_TYPE \
			          && (sym)->s.ti.datatype_code == DATATYPE_ENUM)
#define SYMBOL_IST_PTR(sym)      (sym && (sym)->type == SYMBOL_TYPE_TYPE \
			          && (sym)->s.ti.datatype_code == DATATYPE_PTR)
#define SYMBOL_IST_FUNCTION(sym) (sym && (sym)->type == SYMBOL_TYPE_TYPE \
				  && (sym)->s.ti.datatype_code \
				                == DATATYPE_FUNCTION)
#define SYMBOL_IST_TYPEDEF(sym)  (sym && (sym)->type == SYMBOL_TYPE_TYPE \
				  && (sym)->s.ti.datatype_code \
				                == DATATYPE_TYPEDEF)
#define SYMBOL_IST_UNION(sym)    (sym && (sym)->type == SYMBOL_TYPE_TYPE \
			          && (sym)->s.ti.datatype_code == DATATYPE_UNION)
#define SYMBOL_IST_BASE(sym)     (sym && (sym)->type == SYMBOL_TYPE_TYPE \
			          && (sym)->s.ti.datatype_code == DATATYPE_BASE)
#define SYMBOL_IST_CONST(sym)    (sym && (sym)->type == SYMBOL_TYPE_TYPE \
			          && (sym)->s.ti.datatype_code == DATATYPE_CONST)
#define SYMBOL_IST_VOL(sym)      (sym && (sym)->type == SYMBOL_TYPE_TYPE \
			          && (sym)->s.ti.datatype_code == DATATYPE_VOL)
#define SYMBOL_IST_BITFIELD(sym) (sym && (sym)->type == SYMBOL_TYPE_TYPE \
				  && (sym)->s.ti.datatype_code \
				                == DATATYPE_BITFIELD)
/* convenient! */
#define SYMBOL_IST_STUN(sym)     (sym && (sym)->type == SYMBOL_TYPE_TYPE \
	                          && ((sym)->s.ti.datatype_code \
	                                        == DATATYPE_STRUCT \
	                              || (sym)->s.ti.datatype_code \
				                == DATATYPE_UNION))

typedef enum {
    LOCTYPE_UNKNOWN       = 0,
    LOCTYPE_ADDR          = 1,
    LOCTYPE_REG           = 2,
    LOCTYPE_REG_ADDR      = 3,
    LOCTYPE_REG_OFFSET    = 4,
    LOCTYPE_MEMBER_OFFSET = 5,
    LOCTYPE_FBREG_OFFSET  = 6,
    /* add here */
    LOCTYPE_RUNTIME       = 7,
    __LOCTYPE_MAX,
} location_type_t;
extern char *LOCTYPE_STRINGS[];
#define LOCTYPE(n) (((n) < __LOCTYPE_MAX) ? LOCTYPE_STRINGS[(n)] : NULL)

typedef enum {
    LOAD_FLAG_NONE = 0,
    LOAD_FLAG_MMAP = 2,
    LOAD_FLAG_CHECK_VISIBILITY = 4,
    LOAD_FLAG_AUTO_DEREF = 8,
} load_flags_t;

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
 ** These functions form the target API.
 **/
int target_open(struct target *target);
target_status_t target_monitor(struct target *target);
int target_resume(struct target *target);
struct value *target_read(struct target *target,struct symbol *symbol);
int target_write(struct target *target,struct symbol *symbol,struct value *value);
int target_close(struct target *target);
unsigned char *target_read_addr(struct target *target,
				unsigned long long addr,
				unsigned long length,
				unsigned char *buf);
int target_write_addr(struct target *target,unsigned long long addr,
		      unsigned long length,unsigned char *buf);

unsigned char *target_generic_fd_read(int fd,
				      unsigned long long addr,
				      unsigned long length,
				      unsigned char *buf);

unsigned long target_generic_fd_write(int fd,
				      unsigned long long addr,
				      unsigned long length,
				      unsigned char *buf);
char *target_reg_name(struct target *target,REG reg);
REGVAL target_read_reg(struct target *target,REG reg);
int target_write_reg(struct target *target,REG reg,REGVAL value);

/* Populate a libsymd debugfile with DWARF debuginfo from an ELF file. */
int load_debug_info(struct debugfile *debugfile);

/* linux userproc target ops */
struct target *linux_userproc_attach(int pid);
struct target *linux_userproc_launch(char *filename,char **argv,char **envp);
int linux_userproc_last_signo(struct target *target);
int linux_userproc_stopped_by_syscall(struct target *target);

/* linux corefile target ops */
// XXX write

/**
 ** Address spaces.
 **/
struct addrspace *addrspace_create(char *name,int id,int pid);
void addrspace_free(struct addrspace *space);
void addrspace_dump(struct addrspace *space,struct dump_info *ud);

/**
 ** Memory regions. 
 **/
struct memregion *memregion_create(struct addrspace *space,region_type_t type,
				   char *filename);
int memregion_contains(struct memregion *region,ADDR addr);
struct target *memregion_target(struct memregion *region);
void memregion_free(struct memregion *region);

/**
 ** Debugfiles.
 **/
struct debugfile *debugfile_create(char *filename,debugfile_type_t type);
struct debugfile *debugfile_attach(struct memregion *region,
				   char *filename,debugfile_type_t type);
int debugfile_add_symtab(struct debugfile *debugfile,struct symtab *symtab);
int debugfile_add_global(struct debugfile *debugfile,struct symbol *symbol);
struct symbol *debugfile_find_type(struct debugfile *debugfile,
				   char *typename);
int debugfile_add_type(struct debugfile *debugfile,struct symbol *symbol);
void debugfile_dump(struct debugfile *debugfile,struct dump_info *ud);
void debugfile_free(struct debugfile *debugfile);

/**
 ** Symbol tables.
 **/
struct symtab *symtab_create(struct debugfile *debugfile,
			     char *srcfilename,char *compdirname,
			     int language,char *producer);
/* These symtab_set functions are about dealing with memory stuff, not
 * about hiding symtabs from dwarf or anything.
 */
void symtab_set_name(struct symtab *symtab,char *srcfilename);
void symtab_set_compdirname(struct symtab *symtab,char *compdirname);
void symtab_set_producer(struct symtab *symtab,char *producer);
void symtab_dump(struct symtab *symtab,struct dump_info *ud);
void symtab_free(struct symtab *symtab);
int symtab_str_in_strtab(struct symtab *symtab,char *strp);

/**
 ** Symbols.
 **/
struct symbol *symbol_create(struct symtab *symtab,
			     char *name,symbol_type_t symtype);
void symbol_set_type(struct symbol *symbol,symbol_type_t symtype);
int symbol_insert(struct symbol *symbol);
void symbol_set_name(struct symbol *symbol,char *name);
void symbol_set_srcline(struct symbol *symbol,int srcline);
/*
 * For a SYMBOL_TYPE_TYPE symbol, return the type's byte size.
 */
int symbol_type_bytesize(struct symbol *symbol);
void symbol_dump(struct symbol *symbol,struct dump_info *ud);
void symbol_type_dump(struct symbol *symbol,struct dump_info *ud);
void symbol_function_dump(struct symbol *symbol,struct dump_info *ud);
void symbol_var_dump(struct symbol *symbol,struct dump_info *ud);
void symbol_free(struct symbol *symbol);

void symbol_chain_dump(struct symbol_chain *symbol_chain,struct dump_info *ud);

/**
 ** Locations.
 **/
void location_dump(struct location *location,struct dump_info *ud);
ADDR location_resolve(struct memregion *region,struct location *location,
		      struct loc_list *fblist,struct location *fbloc);
int location_load(struct memregion *region,struct location *location,
		  struct loc_list *fblist,struct location *fbloc,
		  load_flags_t flags,void *buf,int bufsiz);

/**
 ** Symtab (PC) lookup functions.
 **/
/*
 * Find the symbol table corresponding to the supplied PC.
 */
struct symtab *addrspace_lookup_pc(struct addrspace *space,uint64_t pc);
struct symtab *symtab_lookup_pc(struct symtab *symtab,uint64_t pc);

/**
 ** Symbol/memaddr lookup functions.
 **/
/*
 * We need to associate symbols and regions when looking up symbols on a
 * target (as opposed to a debugfile or symtab, in which case we can't
 * know what bit of memory the symbol might be associated with --
 * indeed, it might not be associated with any memory.  So, if the user
 * didn't know in which memory region the symbol was, and queried the
 * target globally, we optionally fill in the region pointer with the
 * region that contained the debugfile containing the symbol.
 */
struct symbol *target_lookup_sym(struct target *target,char *name,
				 char *srcfile,symbol_type_flag_t ftype,
				 struct memregion **region);
/*
 * Like the above function, except looks up a hierarchy of symbols.  At
 * present, only structures and unions and function instances can be
 * nested.  Each symbol chain member is either a SYMBOL_TYPE_VAR or a
 * SYMBOL_TYPE_FUNCTION -- unless the first member in your @name string
 * resolves to a SYMBOL_TYPE_TYPE.  In this case, the first member will
 * be a SYMBOL_TYPE_TYPE!
 */
struct symbol_chain *target_lookup_nested_sym(struct target *target,
					      char *name,const char *delim,
					      char *srcfile,
					      symbol_type_flag_t ftype,
					      struct memregion **retregion);
/* If you know which debugfile contains your symbol, this is fastest. */
struct symbol *debugfile_lookup_sym(struct debugfile *debugfile,char *name,
				    char *srcfile,symbol_type_flag_t ftype);
/* Look up one symbol in a symbol table by name. */
struct symbol *symtab_lookup_sym(struct symtab *symtab,char *name,
				 symbol_type_flag_t ftype);
/* Look up a nested symbol in a symbol table by name. */
struct symbol_chain *symtab_lookup_nested_sym(struct symtab *symtab,char *name,
					      const char *delim,
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
				 const char *delim);

/**
 ** Symbolic target access.
 **/
/*
 * Load a symbol's value, but just return a raw pointer.  If flags
 * contains LOAD_FLAGS_MMAP, we try to mmap the target's memory instead
 * of reading and copying the data; if that fails, we return NULL.  If
 * buf is not NULL, it should be sized to
 * symbol->datatype->s.ti.byte_size (best available as symbol_get
 */
int symbol_load(struct memregion *region,struct symbol *symbol,
		load_flags_t flags,void **buf,int *bufsiz);
/* Like the above, but load the last (deepest) symbol in the chain,
 * using the chain info as necessary!  For instance, this is necessary
 * when loading structure members.
 */
int symbol_nested_load(struct memregion *region,struct symbol_chain *chain,
		       load_flags_t flags,void **buf,int *bufsiz);
/*
 * Load a symbol's value into a value struct, which contains a union
 * with basic type members (of the compiler of the library) and a single
 * "raw" field for complex types.  A "fat" value may also contain
 * metadata.
 */
struct value *symbol_load_fat(struct memregion *region,struct symbol *symbol,
			      load_flags_t flags,void *buf);

void symbol_rvalue_print(FILE *stream,struct memregion *region,
			 struct symbol *symbol,void *buf,int bufsiz);
void symbol_rvalue_tostring(struct symbol *symbol,char **buf,int *bufsiz,
			    char *cur);

signed char      rvalue_c(void *buf);
unsigned char    rvalue_uc(void *buf);
wchar_t          rvalue_wc(void *buf);
uint8_t          rvalue_u8(void *buf);
uint16_t         rvalue_u16(void *buf);
uint32_t         rvalue_u32(void *buf);
uint64_t         rvalue_u64(void *buf);
int8_t           rvalue_i8(void *buf);
int16_t          rvalue_i16(void *buf);
int32_t          rvalue_i32(void *buf);
int64_t          rvalue_i64(void *buf);

/*
 * Given a region, and a symbol in a debugfile attached to that region,
 * encode the value as a string.
 */
char *symbol_to_string(struct memregion *region,
		       struct symbol *symbol);

/*
 * Dwarf util stuff.
 */
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
struct target {
    char *type;
    uint8_t live;
    uint8_t writeable;
    uint8_t attached;
    uint8_t wordsize;
    uint8_t ptrsize;
    uint8_t endian;
    REG fbregno;
    REG ipregno;

    void *state;
    struct target_ops *ops;

    struct addrspace *space;
};

struct target_ops {
    /* init any target state, like a private per-target state struct */
    int (*init)(struct target *target);
    /* init any target state, like a private per-target state struct */
    int (*fini)(struct target *target);
    /* actually connect to the target to enable read/write */
    int (*attach)(struct target *target);
    /* detach from target, but don't unload */
    int (*detach)(struct target *target);

    /* divide the address space into regions with different protection
     * flags, that might come from different source binary files.
     */
    int (*loadregions)(struct target *target);
    /* for each loaded region, load one or more debugfiles and associate
     * them with the region.
     */
    int (*loaddebugfiles)(struct target *target,
			  struct memregion *region);

    /* get target status. */
    target_status_t (*status)(struct target *target);
    /* pause a target */
    int (*pause)(struct target *target);
    /* resume from a paused state */
    int (*resume)(struct target *target);
    /* wait for something to happen to the target */
    target_status_t (*monitor)(struct target *target);

    /* get/set contents of a register */
    char *(*regname)(struct target *target,REG reg);
    REGVAL (*readreg)(struct target *target,REG reg);
    int (*writereg)(struct target *target,REG reg,REGVAL value);

    /* read some memory, potentially into a supplied buffer. */
    unsigned char *(*read) (struct target *target,unsigned long long addr,
			    unsigned long length,unsigned char *buf);
    /* write some memory */
    unsigned long (*write)(struct target *target,unsigned long long addr,
			   unsigned long length,unsigned char *buf);
};

/*
 * An address space is the primary abstraction for associating debuginfo
 * with memory regions.  But, note that debuginfo files are associated
 * specifically with regions -- each address space is associated with
 * subentities I call regions.  A region closely corresponds to Linux's
 * notion of describing a process's address space as a collection of
 * mmaps of the program text/data, its libs, anonymous maps, and heap,
 * stack, syscall trampolines, etc -- and the protections associated
 * with those regions.
 *
 * We associate debuginfo files with regions, not address spaces, since
 * debuginfo applies to one or more regions (depending on the
 * size/protection needs of the main executable or library).
 */

struct addrspace {
    /* name:id:pid */
    char *idstr;

    char *name;
    int id;
    int pid;

    struct list_head regions;

    struct target *target;

    struct list_head space;
    int refcnt;
};

struct memregion {
    /* backref to containing space */
    struct addrspace *space;

    unsigned long long start;
    unsigned long long end;
    unsigned int prot_flags;
    unsigned long long offset;
    char *filename;
    region_type_t type;

    GHashTable *debugfiles;

    struct list_head region;
};

struct debugfile {
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
    /* The type of debugfile */
    debugfile_type_t type;

    /*
     * Currently unused -- we always garbage collect unused debugfiles.
     * We'll do persistence later.
     */
    /* the time this file was loaded */
    time_t ltime;
    /* the last mtime of this file */
    time_t mtime;
    /* does this file get automatically garbage collected? */
    uint8_t infinite;
    
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

    int refcnt;

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
    unsigned int strtablen;

    /*
     * The debug location table for this file.
     *
     * This table is only live while the file is being processed.
     */
    char *loctab;
    unsigned int loctablen;

    /*
     * The range table for this file.
     *
     * This table is only live while the file is being processed.
     */
    char *rangetab;
    unsigned int rangetablen;

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
};

struct range_list_entry {
    ADDR start;
    ADDR end;
};

struct range_list {
    int32_t len;
    struct range_list_entry **list;
};

struct range {
    range_type_t rtype;
    union {
	struct {
	    uint64_t lowpc;
	    uint64_t highpc;
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
    struct loc_list_entry **list;
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

    /* h(sym) -> struct symbol * */
    GHashTable *tab;
};

struct location {
    location_type_t loctype;
    union {
	ADDR addr;
	REG reg;
	int64_t fboffset;
	struct {
	    REG reg;
	    int64_t offset;
	} regoffset;
	int32_t member_offset;
	struct {
	    char *data;
	    uint16_t len;
	} runtime;
    } l;
};

struct symbol {
    /* the primary symbol table we are resident in */
    struct symtab *symtab;

    /* Our name, if any */
    char *name;
    /* The kind of symbol we are. */
    symbol_type_t type;
    /* If not a SYMBOL_TYPE_TYPE, our data type.
     * For functions, it is the return type; for anything else, its data
     * type.
     */
    struct symbol *datatype;
    /* If we see the use of the type before the type, we can only fill
     * in the ref and fill the datatype in a postpass.
     */
    uint64_t datatype_addr_ref;

    /* Where we exist. */
    int srcline;

    /* If this symbol is a member of another, this is its list entry. */
    /* XXX: maybe move this into the type detail stuff to save mem? */
    struct list_head member;

    /* Words fail me. */
    union {
	/* datatype info */
	struct {
	    datatype_code_t datatype_code;
	    uint16_t byte_size;

	    uint8_t isanon:1,
 		    isvoid:1,
		    isexternal:1,
		    isprototyped:1;

	    /* If we see the use of the type before the type, we
	     * can only fill in the ref and fill the datatype in
	     * a postpass.
	     */
	    struct symbol *type_datatype;
	    uint64_t type_datatype_ref;

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
	} ti;
	/* instance info */
	struct {
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
	    struct symbol *origin;
	    uint64_t origin_ref;

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
			    /* If the fb loc is a list or single loc. */
			    fbisloclist:1,
			    fbissingleloc:1;
		    /* The frame base location.  Can be a list or
		     * single location.
		     */
		    union {
			struct loc_list *fblist;
			struct location *fbloc;
		    };
		    struct symtab *symtab;
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
	} ii;
    } s;
};

/*
 * Contains a top-to-bottom list of symbols that have a hierarchical
 * relationship.
 */
struct symbol_chain {
    int count;
    struct symbol **chain;
};

struct value {
    union {
	signed char c;
	unsigned char uc;
	int8_t i8;
	uint8_t u8;
	int16_t i16;
	uint16_t u16;
	int32_t i32;
	uint32_t u32;
	int64_t i64;
	uint64_t u64;

	float f;
	double d;
	long double ld;

	void *p;

	void *data;
    };
};

struct dump_info {
    char *prefix;
    FILE *stream;
    int meta;
    int detail;
};


#define DEBUGPRED 1
#ifndef PIC
#define PIC 1
#endif

/**
 ** likely/unlikely from elfutils.
 **/
#if DEBUGPRED
# ifdef __x86_64__
asm (".section predict_data, \"aw\"; .previous\n"
     ".section predict_line, \"a\"; .previous\n"
     ".section predict_file, \"a\"; .previous");
#  ifndef PIC
#   define debugpred__(e, E) \
  ({ long int _e = !!(e); \
     asm volatile (".pushsection predict_data; ..predictcnt%=: .quad 0; .quad 0\n" \
                   ".section predict_line; .quad %c1\n" \
                   ".section predict_file; .quad %c2; .popsection\n" \
                   "addq $1,..predictcnt%=(,%0,8)" \
                   : : "r" (_e == E), "i" (__LINE__), "i" (__FILE__)); \
    __builtin_expect (_e, E); \
  })
#  endif
# elif defined __i386__
asm (".section predict_data, \"aw\"; .previous\n"
     ".section predict_line, \"a\"; .previous\n"
     ".section predict_file, \"a\"; .previous");
#  ifndef PIC
#   define debugpred__(e, E) \
  ({ long int _e = !!(e); \
     asm volatile (".pushsection predict_data; ..predictcnt%=: .long 0; .long 0\n" \
                   ".section predict_line; .long %c1\n" \
                   ".section predict_file; .long %c2; .popsection\n" \
                   "incl ..predictcnt%=(,%0,8)" \
                   : : "r" (_e == E), "i" (__LINE__), "i" (__FILE__)); \
    __builtin_expect (_e, E); \
  })
#  endif
# endif
# ifdef debugpred__
#  define unlikely(e) debugpred__ (e,0)
#  define likely(e) debugpred__ (e,1)
# endif
#endif
#ifndef likely
# define unlikely(expr) __builtin_expect (!!(expr), 0)
# define likely(expr) __builtin_expect (!!(expr), 1)
#endif

#endif
