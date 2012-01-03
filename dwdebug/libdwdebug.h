#ifndef __LIBDWDEBUG_H__
#define __LIBDWDEBUG_H__

#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdint.h>
#include <stdio.h>
#include <glib.h>

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
struct location;
struct value;

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
    SYMBOL_TYPE_TYPE      = 0,
    SYMBOL_TYPE_VAR       = 1,
    SYMBOL_TYPE_FUNCTION  = 2,
    __SYMBOL_TYPE_MAX,
} symbol_type_t;
extern char *SYMBOL_TYPE_STRINGS[];
#define SYMBOL_TYPE(n) (((n) < __SYMBOL_TYPE_MAX) ? SYMBOL_TYPE_STRINGS[(n)] : NULL)

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

#define SYMBOL_IST_PTR(sym) (sym && (sym)->type == SYMBOL_TYPE_TYPE && (sym)->s.ti.datatype_code == DATATYPE_PTR)

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

struct location {
    location_type_t loctype;
    union {
	uint64_t addr;
	uint8_t reg;
	int64_t fboffset;
	struct {
	    uint8_t reg;
	    int64_t offset;
	} regoffset;
	int32_t member_offset;
	struct {
	    char *data;
	    uint16_t len;
	} runtime;
    } l;
};

struct dump_info {
    char *prefix;
    FILE *stream;
    int meta;
    int detail;
};

/**
 ** Functions.
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

/* Populate a libsymd debugfile with DWARF debuginfo from an ELF file. */
int load_debug_info(struct debugfile *debugfile);

/* linux userproc target ops */
struct target *linux_userproc_attach(int pid);
struct target *linux_userproc_launch(char *filename,char **argv,char **envp);

/* linux corefile target ops */
// XXX write

struct addrspace *addrspace_create(char *name,int id,int pid);
void addrspace_free(struct addrspace *space);
void addrspace_dump(struct addrspace *space,struct dump_info *ud);
struct memregion *memregion_create(struct addrspace *space,region_type_t type,
				   char *filename);
void memregion_free(struct memregion *region);
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
struct symtab *symtab_create(struct debugfile *debugfile,
			     char *srcfilename,char *compdirname,
			     int language,char *producer,
			     unsigned long lowpc,unsigned long highpc);
/* These symtab_set functions are about dealing with memory stuff, not
 * about hiding symtabs from dwarf or anything.
 */
void symtab_set_name(struct symtab *symtab,char *srcfilename);
void symtab_set_compdirname(struct symtab *symtab,char *compdirname);
void symtab_set_producer(struct symtab *symtab,char *producer);
void symtab_dump(struct symtab *symtab,struct dump_info *ud);
void symbol_type_dump(struct symbol *symbol,struct dump_info *ud);
void symbol_function_dump(struct symbol *symbol,struct dump_info *ud);
void symbol_var_dump(struct symbol *symbol,struct dump_info *ud);
void symtab_free(struct symtab *symtab);
int symtab_str_in_strtab(struct symtab *symtab,char *strp);
struct symbol *symbol_create(struct symtab *symtab,
			     char *name,symbol_type_t symtype);
void symbol_set_type(struct symbol *symbol,symbol_type_t symtype);
int symbol_insert(struct symbol *symbol);
void symbol_set_name(struct symbol *symbol,char *name);
void symbol_set_srcline(struct symbol *symbol,int srcline);
void symbol_dump(struct symbol *symbol,struct dump_info *ud);
void symbol_free(struct symbol *symbol);
void location_dump(struct location *location,struct dump_info *ud);

/**
 ** Lookup stuff!
 **/

/*
 * Find the symbol table corresponding to the supplied PC.
 */
struct symtab *lookup_symtab(struct addrspace *space,uint64_t pc);
struct symbol *debugfile_lookup_sym(struct debugfile *debugfile,
				    char *srcfile,char *name);

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
     */
    char *strtab;
    int strtablen;

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

    uint64_t lowpc;
    uint64_t highpc;

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
		    isvoid:1;
	    union {
		struct {
		    int encoding;
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
		    struct symbol *array_datatype;
		    uint64_t array_datatype_addr_ref;
		    int *subranges;
		    int count;
		    int alloc;
		} a;
		struct {
		    struct symbol *ptr_datatype;
		    /* If we see the use of the type before the type, we
		     * can only fill in the ref and fill the datatype in
		     * a postpass.
		     */
		    uint64_t ptr_datatype_addr_ref;
		    int nptrs;
		} p;
		struct {
		    struct symbol *td_datatype;
		    uint64_t td_datatype_addr_ref;
		} td;
		struct {
		    struct symbol *const_datatype;
		    uint64_t const_datatype_addr_ref;
		} cq;
		struct {
		    struct symbol *vol_datatype;
		    uint64_t vol_datatype_addr_ref;
		} vq;
	    } d;
	} ti;
	/* instance info */
	struct {
	    uint8_t isparam:1,
		    isconst:1,
		    isenumval:1;
	    union {
		void *constval;
		struct {
		    struct list_head args;
		    uint16_t count;
		    uint8_t external:1;
		    uint8_t prototyped:1;
		    uint64_t lowpc;
		    uint64_t highpc;
		    struct symtab *symtab;
		} f;
		struct {
		    uint16_t byte_size;
		    uint16_t bit_offset;
		    uint16_t bit_size;
		} v;
	    } d;
	    struct location l;
	} ii;
    } s;
};

struct value {
    struct type *type;
    union {
	signed char sc;
	unsigned char uc;
	signed short int ssi;
	unsigned short int usi;
	signed int si;
	unsigned int ui;
	signed long int sli;
	unsigned long int uli;
	signed long long int slli;
	unsigned long long int ulli;
	double d;
	long double ld;
	float f;
	void *p;
	unsigned char *bytes;
    } v;
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
