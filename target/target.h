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

#ifndef __TARGET_H__
#define __TARGET_H__

#include <stdint.h>
#include <inttypes.h>
#include <glib.h>

#include "debugpred.h"
#include "list.h"
#include "alist.h"
#include "config.h"
#include "log.h"

#include "target_api.h"
#include "dwdebug.h"

/**
 ** Some forward declarations.
 **/
struct addrspace;
struct memregion;
struct memrange;
struct value;

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
extern char *REGION_TYPE_STRINGS[];
#define REGION_TYPE(n) (((n) < __REGION_TYPE_MAX) ? REGION_TYPE_STRINGS[(n)] : NULL)

typedef enum {
    LOAD_FLAG_NONE = 0,
    LOAD_FLAG_SHOULD_MMAP = 1,
    LOAD_FLAG_MUST_MMAP = 2,
    LOAD_FLAG_NO_CHECK_BOUNDS = 4,
    LOAD_FLAG_NO_CHECK_VISIBILITY = 8,
    LOAD_FLAG_AUTO_DEREF = 16,
    LOAD_FLAG_AUTO_DEREF_RECURSE = 32,
    LOAD_FLAG_AUTO_STRING = 64,
    LOAD_FLAG_NO_AUTO_RESOLVE = 128,
} load_flags_t;

/**
 ** Target functions.
 **/
struct value *target_location_load_type(struct target *target,
					struct location *location,
					load_flags_t flags,
					struct symbol *type);
int target_contains(struct target *target,ADDR addr);
int target_find_range_real(struct target *target,ADDR addr,
			   struct addrspace **space_saveptr,
			   struct memregion **region_saveptr,
			   struct memrange **range_saveptr);
struct value *target_location_load_raw(struct target *target,
				       struct location *location,
				       load_flags_t flags,
				       char **buf,int *bufsiz);


int target_resume(struct target *target);
struct value *target_read(struct target *target,struct symbol *symbol);
int target_write(struct target *target,struct symbol *symbol,struct value *value);

unsigned char *target_generic_fd_read(int fd,
				      unsigned long long addr,
				      unsigned long length,
				      unsigned char *buf);
unsigned long target_generic_fd_write(int fd,
				      unsigned long long addr,
				      unsigned long length,
				      unsigned char *buf);
struct debugfile *target_associate_debugfile(struct target *target,
					     struct memregion *region,
					     char *filename,
					     debugfile_type_t type);
/**
 ** Address spaces.
 **/
struct addrspace *addrspace_create(struct target *target,
				   char *name,int id,int pid);
struct memregion *addrspace_find_region(struct addrspace *space,char *name);
int addrspace_find_range_real(struct addrspace *space,ADDR addr,
			      struct memregion **region_saveptr,
			      struct memrange **range_saveptr);
void addrspace_free(struct addrspace *space);
void addrspace_dump(struct addrspace *space,struct dump_info *ud);

/**
 ** Memory region regions and ranges.
 **/
struct memregion *memregion_create(struct addrspace *space,
					       region_type_t type,char *name);
int memregion_contains_real(struct memregion *region,ADDR addr);
struct memrange *memregion_find_range_real(struct memregion *region,
					   ADDR real_addr);
struct memrange *memregion_find_range_obj(struct memregion *region,
					  ADDR obj_addr);
struct target *memregion_target(struct memregion *region);
void memregion_dump(struct memregion *region,struct dump_info *ud);
void memregion_free(struct memregion *region);

struct memrange *memrange_create(struct memregion *region,
				   ADDR start,ADDR end,OFFSET offset,
				   unsigned int prot_flags);
int memrange_contains_real(struct memrange *range,ADDR real_addr);
int memrange_contains_obj(struct memrange *range,ADDR obj_addr);
ADDR memrange_unrelocate(struct memrange *range,ADDR real);
ADDR memrange_relocate(struct memrange *range,ADDR obj);
struct target *memrange_target(struct memrange *range);
struct addrspace *memrange_space(struct memrange *range);
void memrange_dump(struct memrange *range,struct dump_info *ud);
void memrange_free(struct memrange *range);

struct mmap_entry *target_lookup_mmap_entry(struct target *target,
					    ADDR base_addr);
void target_attach_mmap_entry(struct target *target,
			      struct mmap_entry *mme);
void target_release_mmap_entry(struct target *target,
			       struct mmap_entry *mme);

/**
 ** Bound symbols.
 **/
struct bsymbol *bsymbol_create(struct memregion *region,
			       struct lsymbol *lsymbol);
void bsymbol_dump(struct bsymbol *bsymbol,struct dump_info *ud);
void bsymbol_free(struct bsymbol *bsymbol);

/**
 ** Location resolution.
 **/
ADDR location_resolve(struct target *target,struct memregion *region,
		      struct location *location,
		      struct array_list *symbol_chain,
		      struct memrange **range_saveptr);
int location_can_mmap(struct location *location,struct target *target);

/**
 ** Location loading functions.
 **/
char *location_load(struct target *target,struct memregion *region,
		    struct location *location,load_flags_t flags,
		    void *buf,int bufsiz,
		    struct array_list *symbol_chain,
		    struct memrange **range_saveptr);
char *location_addr_load(struct target *target,struct memrange *range,
			 ADDR addr,load_flags_t flags,
			 void *buf,int bufsiz);
char *location_obj_addr_load(struct target *target,struct memrange *range,
			     ADDR addr,load_flags_t flags,
			     void *buf,int bufsiz);
struct mmap_entry *location_mmap(struct target *target,
				 struct memregion *region,
				 struct location *location,
				 load_flags_t flags,char **offset,
				 struct array_list *symbol_chain,
				 struct memrange **range_saveptr);
/**
 ** Value loading functions.
 **/
/*
 * Load a symbol's value, but just return a raw pointer.  If flags
 * contains LOAD_FLAGS_MMAP, we try to mmap the target's memory instead
 * of reading and copying the data; if that fails, we return NULL.  If
 * buf is not NULL, it should be sized to
 * symbol->datatype->s.ti.byte_size (best available as symbol_get
 */
struct value *bsymbol_load(struct bsymbol *bsymbol,load_flags_t flags);
struct value *target_load_raw(struct target *target,struct memregion *region,
			      struct location *location,load_flags_t flags,
			      int len);
struct value *target_load_raw_obj_location(struct target *target,
					   struct memregion *region,
					   ADDR obj_addr,load_flags_t flags,
					   int len);
/*
 * Values.
 */
int value_alloc_buf(struct value *value,int len);
struct value *value_create_raw(int len);
struct value *value_create_type(struct symbol *type);
struct value *value_create(struct bsymbol *bsymbol,struct symbol *type);
struct value *value_create_noalloc(struct bsymbol *bsymbol,struct symbol *type);
void value_free(struct value *value);

void symbol_rvalue_print(FILE *stream,struct symbol *symbol,
			 void *buf,int bufsiz,
			 load_flags_t flags,struct target *target);

/**
 ** Data structure definitions.
 **/
/*
 * An address space is the primary abstraction for associating debuginfo
 * with memory ranges.  But, note that debuginfo files are associated
 * specifically with regions -- each address space is associated with
 * subentities I call regions, which include one or more ranges.  A
 * range closely corresponds to Linux's notion of describing a process's
 * address space as a collection of mmaps of the program text/data, its
 * libs, anonymous maps, and heap, stack, syscall trampolines, etc --
 * and the protections associated with those ranges.  Ranges can be
 * grouped; the analogue is when an ELF object file is loaded into
 * memory, it is split into several distinct memory ranges, each with
 * different memory protections.  HOWEVER, each of these ranges
 * corresponds to the same debugfile(s) that have debuginfo for the ELF
 * object file.
 *
 * Regions, then, hold references to debugfiles, and potentially include
 * multiple ranges.
 */

struct addrspace {
    /* name:id:pid */
    char *idstr;

    char *name;
    int id;
    int pid;

    /* Our member node on the global spaces list */
    struct list_head space;

    /* The regions contained in this address space. */
    struct list_head regions;

    /* A backref to the target containing this address space. */
    struct target *target;

    int refcnt;
};

/*
 * Regions contain one or more ranges.  The initial reason to have a
 * two-level hierarchy here is that when we load symbols, we know the
 * symbol is in some debugfile, but if we maintained the mapping between
 * debugfiles and ranges within the range data structure itself, we
 * would not know which range the resolved symbol is associated with!
 *
 * More generally, when we lookup a symbol in a target's debugfiles, we
 * don't know which range the symbol is in until we resolve its address
 * (and address resolution can be a runtime process involving reading
 * target execution state like registers).  So, we can only bind a
 * symbol to one or more of the ranges that are connected to the
 * debugfiles.
 *
 * This requires us to have a region structure that binds debugfile(s)
 * to one or more ranges.  Regions are named and typed; we expect that
 * the range itself is just an address range, potentially with an
 * offset, and a set of protection flags.
 */
struct memregion {
    /* backref to containing space */
    struct addrspace *space;

    char *name;
    region_type_t type;

    /*
     * Debugfiles associated with this region.
     */
    GHashTable *debugfiles;

    /* This is an identifier that must be changed every time this
     * memrange changes status, and something about it has been
     * reloaded.  For instance, if it is now using different memory
     * addresses than when we were last resolved symbols to locations
     * inside of it, we need those symbols to be re-resolved before
     * loading them again.
     */
    uint32_t stamp;

    /* The list node linking this into the addrspace. */
    struct list_head region;

    /* The ranges contained in this region. */
    struct list_head ranges;
};

struct memrange {
    /* backref to containing region */
    struct memregion *region;

    ADDR start;
    ADDR end;
    ADDR offset;
    /*
     * For a shared library, this is the object-relative start address.
     * If in userspace, the regions are not laid out back to back, or if
     * the object-relative addresses are not contiguous (i.e., a shared
     * lib), we must have the base address to relocate like the dynamic
     * loader did!
     *
     * XXX: for now, this is unsupported, because we have no good way of
     * figuring out what the dynamic loader did in linux userspace.
     * Eventually, we have to load the ELF object file ourselves, and
     * note the object relative addresses and their offsets in the file.
     */
    ADDR base_obj_addr;
    unsigned int prot_flags;

    /* The list node linking this into the region. */
    struct list_head range;
};

/*
 * This is a symbol that is bound to a memory region.  At binding time,
 * we record the stamp of the region, so we can tell later if the region
 * "changed" in some way after this symbol was bound (we might need to
 * rebind).  Finally, we include the address so that a bound symbol can
 * be resolved (i.e., its address filled in).  Address resolution may
 * need to be recomputed every time the PC changes, although the region
 * binding may still be valid.
 */
struct bsymbol {
    /*
     * The lookup information -- the deepest-nested symbol, and a
     * top-to-bottom list of parents.
     */
    struct lsymbol *lsymbol;

    /* Binding to a target region. */
    struct memregion *region;
};

/*
 * An mmap entry records a mapping of target memory we made while
 * loading a value.
 */
struct mmap_entry {
    char *base_address;
    int pages;
    int refcnt;
};

struct value {
    /*
     * The type of value -- it may NOT be the primary type of the
     * bsymbol!  i.e., it may be the pointed-to type, or we may have
     * stripped off the const/vol qualifiers.
     *
     * We could also save the load flags so we always know what type of
     * memory this object is pointing to, but we'll skip that for now.
     */
    struct symbol *type;

    /*
     * A backreference to the symbol this value is associated with.
     */
    struct lsymbol *lsymbol;

    /* The memrange this value exists in. */
    struct memrange *range;

    /* The region stamp at load time. */
    uint32_t region_stamp;

    /* If this value is mmap'd instead of alloc'd, store that too. */
    struct mmap_entry *mmap;
    char *buf;
    int bufsiz;
    uint8_t ismmap:1,
	    isstring:1;

    /* The resolved address of the value. */
    ADDR addr;
    /* The value of the PC when we last resolved this symbol's address. */
    ADDR addr_resolved_ip;
};

#endif
