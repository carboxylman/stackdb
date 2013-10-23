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

/**
 ** Binfiles (i.e., ELF).
 **/

#include "dwdebug_priv.h"
#include "dwdebug.h"

/*
 * For now, these just match ELF types that we support.  As we add more
 * backends, we might need to add more types.
 */
typedef enum {
    BINFILE_TYPE_NONE        = 0,
    BINFILE_TYPE_REL         = 1,
    BINFILE_TYPE_EXEC        = 2,
    BINFILE_TYPE_DYN         = 3,
    BINFILE_TYPE_CORE        = 4,
} binfile_type_t;
static inline const char *BINFILE_TYPE(int n) {
    switch (n) {
    case BINFILE_TYPE_NONE:  return "none";
    case BINFILE_TYPE_REL:   return "relocatable";
    case BINFILE_TYPE_EXEC:  return "executable";
    case BINFILE_TYPE_DYN:   return "dynamic";
    case BINFILE_TYPE_CORE:  return "core";
    default:                 return NULL;
    }
}

/*
 * Library init routines.
 */
void binfile_init(void);

struct binfile *binfile_create(char *filename,struct binfile_ops *bfops,
			       void *priv);
int binfile_cache_clean(void);
/*
 * Tries all backends, or the one referred to by @bfinst, to open
 * @filename.  @returns a struct binfile if successful; NULL otherwise.
 * If @root_prefix is set, any other filenames with absolute paths this
 * library tries to open because of this binfile will be prefixed with
 * @root_prefix prior to opening.  This supports the target API; if you
 * are not using that, you should have no reason to use @root_prefix.
 *
 * If successful, and if the resulting binfile is shareable (not created
 * based on an instance), the returned binfile has a ref taken on the
 * caller's behalf, so the caller must call RPUT(binfile) to release
 * (and free) it.
 *
 * If @DFPATH is set, it should be a NULL-terminated array of char *
 * that specify dirs to look into for files containing debuginfo.  This
 * is right now only used by the ELF backend to load debuginfo for files
 * that include a build-id and use that as a means to identify which
 * file contains debuginfo (i.e., the path is often something like
 * /usr/lib/debug/.build-id/xx/xx...xx.debug -- where the xx's are the
 * hex string repr of the build id).  So, the default DFPATH is
 * /usr/lib/debug,/usr/local/lib/debug,NULL.
 *
 * Note also that even if you specify DFPATH, you should *not* prefix it
 * with @root_prefix; @root_prefix will be *prepended* to the entries in
 * DFPATH if they are searched.
 */
struct binfile *binfile_open(char *filename,char *root_prefix,
			     struct binfile_instance *bfinst);
struct binfile *binfile_open_debuginfo(struct binfile *binfile,
				       struct binfile_instance *bfinst,
				       const char *DFPATH[]);

/*
 * Loads @filename as a binfile, then uses that binfile backend's ops to
 * infer a default program layout, informed by the @base load address,
 * and any key/value pairs in @config.  This function holds a ref to the
 * return value; you must free it with binfile_instance_release().
 *
 * @param filename  A path to a binary file.
 * @param root_prefix A path to prepend to any other file opens this
 *     library might need; should be the same prefix @filename has.
 * @param base      The base load address as the program image is or was
 *     constructed.
 * @param config    A simple char *->char * hash of key/value pairs; its use
 *     is backend-specific. 
 *
 * @returns  A binfile_instance that represents a program image.
 */
struct binfile_instance *binfile_infer_instance(char *filename,
						char *root_prefix,
						ADDR base,GHashTable *config);
/*
 * @param binfile  A loaded binfile.
 * @returns  The name of the backend that loaded @binfile.
 */
const char *binfile_get_backend_name(struct binfile *binfile);
/*
 * @param binfile  A loaded binfile.
 * @returns  The type of @binfile.
 */
binfile_type_t binfile_get_type(struct binfile *binfile);

int binfile_get_root_scope_sizes(struct binfile *binfile,
				 int *named,int *duplicated,int *anon,
				 int *numscopes);
/*
 * Closes all resources associated with loading @binfile, but does not
 * free the result of loading the binfile -- i.e., any symbols or
 * metadata that were cached into internal structures after "load".
 *
 * @param binfile  A loaded binfile.
 *
 * @returns  A result code.
 */
int binfile_close(struct binfile *binfile);
/*
 * Releases a reference @binfile.  If this is the last reference, the
 * binfile is freed.  At this point, the caller must not use any symbols
 * or data obtained from the binfile.
 */
REFCNT binfile_release(struct binfile *binfile);
/*
 * Releases a reference @bfi.  If this is the last reference, the
 * binfile_instance is freed.  At this point, the caller must not use
 * the binfile_instance.
 */
REFCNT binfile_instance_release(struct binfile_instance *bfi);
/*
 * Frees a binfile_instance.  These are not refcnt'd, so can be freed
 * directly (no release).
 */
REFCNT binfile_instance_free(struct binfile_instance *bfi,int force);

struct binfile *binfile_lookup(char *filename);
int binfile_cache(struct binfile *binfile);
int binfile_uncache(struct binfile *binfile);
/*
 * Internal versions; do not hold a ref to their return values!
 */
struct binfile *binfile_open__int(char *filename,char *root_prefix,
				  struct binfile_instance *bfinst);
struct binfile *binfile_open_debuginfo__int(struct binfile *binfile,
					    struct binfile_instance *bfinst,
					    const char *DFPATH[]);
REFCNT binfile_free(struct binfile *binfile,int force);

/*
 * Each binfile supports a simple per-backend lifecycle.  @open (invoked
 * via binfile_open) creates the binfile datastructures, opens a
 * binfile, loads its metadata and symbols).  @close closes any open
 * files and releases any resources related to processing the file.
 * @free release any other releases that were independent of processing
 * -- such as symbols, metadata, etc.  binfile backends must keep enough
 * state around to support their symbol table until @free is called.
 */
struct binfile_ops {
    const char *(*get_backend_name)(void);
    struct binfile *(*open)(char *filename,char *root_prefix,
			    struct binfile_instance *bfinst);
    struct binfile *(*open_debuginfo)(struct binfile *binfile,
				      struct binfile_instance *bfinst,
				      const char *DFPATH[]);
    struct binfile_instance *(*infer_instance)(struct binfile *binfile,
					       ADDR base,GHashTable *config);
    int (*close)(struct binfile *bfile);
    void (*free)(struct binfile *bfile);
    void (*free_instance)(struct binfile_instance *bfi);
};

/*
 * binfiles store basic information about compiled binary files.  They
 * provide basic string table, symbol table, and address range
 * abstractions.  Any binary file that is the result of a compilation
 * will have such tables; some binary files might have more information
 * regarding loading and layout, and/or relocation.  For now, this
 * information must be stored in the backend-specific @priv field.
 */
struct binfile {
    /* Our reference count. */
    REFCNT refcnt;
    /* Our weak reference count. */
    //REFCNT refcntw;

    binfile_type_t type;

    uint8_t is_dynamic:1,
	    has_debuginfo:1;

    /* If @has_debuginfo, which type. */
    debugfile_type_t has_debuginfo_type;

    /*
     * Opened binfiles have either @fd > 0, or non-NULL @image (right
     * now, image is used when the binfile has to be loaded into memory
     * for whatever reason -- initially, relocation in the backend).
     */
    char *image;
    int fd;

    int wordsize;
    int endian;

    /*
     * The string table for this file.  All binfile string pointers are
     * checked for presence in this table before freeing.
     *
     * This table persists until the binfile is freed.
     */
    unsigned int strtablen;
    char *strtab;

    /*
     * The dynamic string table for this file.  All binfile string pointers are
     * checked for presence in this table before freeing.
     *
     * This table persists until the binfile is freed.
     */
    unsigned int dynstrtablen;
    char *dynstrtab;

    /*
     * This must be an absolute path; binfile_create will try to resolve
     * its @filename argument and place the result here; but if the
     * backend updates it, the backend must enforce this constraint.
     *
     * This is a unique ID used for caching.
     */
    char *filename;
    
    /*
     * binfile_open does a best-effort pass at these fields via regexps;
     * however, backends are free to update these fields via free() and
     * malloc() during @binfile_ops->open.
     *
     * @name is the name of the binfile, minus any path and version info.
     * For shared libs, this is "libz"; for the kernel, it
     * is literally just the name "vmlinux"; for kernel modules,
     * it is the module name; for programs, it is the executable name.
     *
     * @version: the kernel, kmods, and shared libs should all have versions.
     * Programs probably won't have versions.
     */
    char *name;
    char *version;

    /*
     * Backend info.
     */
    struct binfile_ops *ops;
    void *priv;

    /*
     * The root for this binfile.  All symbols contained in it are 
     * per-backend symbols, not DWARF symbols.  They cannot be expanded
     * into fully-loaded symbols.
     */
    struct symbol *root;

    /* 
     * We keep a separate range structure for binfile symbols, because
     * the normal debugfile->ranges range structure contains symtabs,
     * not symbols.  So they can't be mixed... unfortunate.
     */
    clrange_t ranges;

    /*
     * These are the minimum phys/virt address pairs that we learn from
     * looking at the program headers.
     */
    ADDR base_phys_addr;
    ADDR base_virt_addr;

    /*
     * The binfile_instance that was used to load and relocate this
     * binfile.
     *
     * If @binfile_instance is set, this binfile cannot be shared
     * (because we relocated bits in the binfile using the instance
     * info).
     *
     * If we loaded a binfile that does not depend on the instance,
     * this field should NOT be set.
     *
     * The backend is in charge of setting this field correctly!
     */
    struct binfile_instance *instance;

    /*
     * This is an alternate prefix that will be prepended to any files
     * that the binfile code attempts to open.  This helps us load
     * binary file information for filenames whose binaries are not
     * actually at that location in the / filesystem that the library
     * code is running on.  For instance, this is useful when we use the
     * target library to open ELF/debuginfo for files that are really
     * inside a VM that we are inspecting; it helps us look for them in
     * this prefix instead of our root.
     *
     * Why put this here?  Because the library attempts to infer new
     * files to open sometimes (i.e. as it loads debuginfo), so we have
     * to make sure it looks in the right place.  When the user says to
     * open a binary file as a debugfile, they must use the real path
     * (i.e., including @root_prefix below).  But, those files
     * themselves may have embedded links to other files -- and if those
     * links are absolute, we have to prepend our @root_prefix.
     */
    char *root_prefix;

    /*
     * Currently unused.
     */
    time_t load_time;
    time_t mod_time;
};

struct binfile_elf {
    int class;
    size_t shstrndx;
    char *buildid;
    char *gnu_debuglinkfile;
    uint32_t gnu_debuglinkfile_crc;

    unsigned int num_symbols;

    /*
     * We save off full copies of this stuff so that even if the ELF
     * file is closed, we still have it.
     */
    GElf_Ehdr ehdr;
    GElf_Phdr *phdrs;
    GElf_Shdr *shdrs;

    /*
     * Save off the elfutils info until we're done with it.
     */
    Elf *elf;
    Ebl *ebl;
    Dwfl *dwfl;
    int dwfl_fd;
};

/*
 * Instances are simple.  They map a binfile filename to a loaded
 * instance of it.  We do not necessarily map struct binfile to the
 * instance, because we might not have loaded the binfile yet!  In other
 * words, the instance might be used to load a (relocated) version of
 * the binfile; or it might be simply used to load a shareable
 * (non-relocated) version of the binfile, and then discarded.
 */
struct binfile_instance {
    /* Our reference count. */
    REFCNT refcnt;

    char *filename;
    /*
     * Since the binfile library is capable of opening files on behalf
     * of loaded binfiles or binfile_instances, it needs to know if the
     * real place those files are to be loaded from is a fake (or
     * alternate) root filesystem.  See the comments in struct debugfile
     * for more information.
     */
    char *root_prefix;

    ADDR base;
    ADDR start;
    ADDR end;
    struct binfile_ops *ops;
    void *priv;
};

struct binfile_instance_elf {
    unsigned int num_sections;
    unsigned int num_symbols;
    /* A map of ELF section index to an address in the instance. */
    ADDR *section_tab;
    /* A map of ELF symtab index to an address in the instance. */
    ADDR *symbol_tab;

    /*
     * When loading an instance, we might modify the section headers.
     * If we do, this has the mods for us to apply.
     */
    GElf_Shdr *shdrs;
};
