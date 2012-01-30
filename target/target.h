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
void addrspace_free(struct addrspace *space);
void addrspace_dump(struct addrspace *space,struct dump_info *ud);

/**
 ** Memory regions. 
 **/
struct memregion *memregion_create(struct addrspace *space,region_type_t type,
				   char *filename);
int memregion_contains(struct memregion *region,ADDR addr);
ADDR memregion_unrelocate(struct memregion *region,ADDR real);
ADDR memregion_relocate(struct memregion *region,ADDR obj);
struct target *memregion_target(struct memregion *region);
struct addrspace *memregion_space(struct memregion *region);
void memregion_dump(struct memregion *region,struct dump_info *ud);
void memregion_free(struct memregion *region);

struct mmap_entry *target_lookup_mmap_entry(struct target *target,
					    ADDR base_addr);
void target_attach_mmap_entry(struct target *target,
			      struct mmap_entry *mme);
void target_release_mmap_entry(struct target *target,
			       struct mmap_entry *mme);

/**
 ** Bound symbols.
 **/
struct bsymbol *bsymbol_create(struct memregion *region,struct symbol *symbol,
			       struct array_list *chain);
void bsymbol_dump(struct bsymbol *bsymbol,struct dump_info *ud);
void bsymbol_free(struct bsymbol *bsymbol);

/**
 ** Location resolution.
 **/
ADDR location_resolve(struct target *target,struct memregion *region,
		      struct location *location,
		      struct array_list *symbol_chain);
int location_can_mmap(struct location *location,struct target *target);

/**
 ** Location loading functions.
 **/
char *location_load(struct target *target,struct memregion *region,
		    struct location *location,struct array_list *symbol_chain,
		    load_flags_t flags,void *buf,int bufsiz);
char *location_addr_load(struct target *target,struct memregion *region,
			 ADDR addr,load_flags_t flags,
			 void *buf,int bufsiz);
char *location_obj_addr_load(struct target *target,struct memregion *region,
			     ADDR addr,load_flags_t flags,
			     void *buf,int bufsiz);
struct mmap_entry *location_mmap(struct target *target,struct memregion *region,
				 struct location *location,
				 struct array_list *symbol_chain,
				 load_flags_t flags,char **offset);
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
struct value *value_create_raw(struct memregion *region,int len);
struct value *value_create_type(struct memregion *region,struct symbol *type);
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

    /* Our member node on the global spaces list */
    struct list_head space;

    /* The regions contained in this address space. */
    struct list_head regions;

    /* A backref to the target containing this address space. */
    struct target *target;

    int refcnt;
};

struct memregion {
    /* backref to containing space */
    struct addrspace *space;

    char *filename;
    unsigned long long start;
    unsigned long long end;
    unsigned long long offset;
    unsigned int prot_flags;
    region_type_t type;

    /* This is an identifier that must be changed every time this
     * memregion changes status, and something about it has been
     * reloaded.  For instance, if it is now using different memory
     * addresses than when we were last resolved symbols to locations
     * inside of it, we need those symbols to be re-resolved before
     * loading them again.
     */
    uint32_t stamp;

    GHashTable *debugfiles;

    struct list_head region;
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

    struct memregion *region;

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
