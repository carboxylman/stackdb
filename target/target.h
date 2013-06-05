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
#include "disasm.h"
#include "probe.h"

#define LOGDUMPBSYMBOL(dl,lt,s) \
    vdebugc((dl),(lt), \
	    "bsymbol(lsymbol(%s,%s,%"PRIxSMOFFSET";chainlen=%d),"	\
	    "region=(%s(space=%s)))",					\
	    symbol_get_name((s)->lsymbol->symbol),			\
	    SYMBOL_TYPE((s)->lsymbol->symbol->type),			\
	    (s)->lsymbol->symbol->ref,					\
	    array_list_len((s)->lsymbol->chain),			\
	    (s)->region ? (s)->region->name : NULL,			\
	    (s)->region ? (s)->region->space->idstr : NULL);

#define LOGDUMPBSYMBOL_NL(dl,lt,s) \
    LOGDUMPBSYMBOL((dl),(lt),(s)); \
    vdebugc((dl),(lt),"\n");

#define ERRORDUMPBSYMBOL(s) \
    verrorc("bsymbol(lsymbol(%s,%s,%"PRIxSMOFFSET";chainlen=%d),"	\
	    "region=(%s(space=%s)))",					\
	    symbol_get_name((s)->lsymbol->symbol),			\
	    SYMBOL_TYPE((s)->lsymbol->symbol->type),			\
	    (s)->lsymbol->symbol->ref,					\
	    array_list_len((s)->lsymbol->chain),			\
	    (s)->region ? (s)->region->name : NULL,			\
	    (s)->region ? (s)->region->space->idstr : NULL);

#define ERRORDUMPBSYMBOL_NL(s) \
    ERRORDUMPBSYMBOL((s)); \
    verrorc("\n");

/**
 ** Some forward declarations.
 **/
struct addrspace;
struct memregion;
struct memrange;
struct value;

typedef enum {
    REGION_TYPE_UNKNOWN        = 0,
    REGION_TYPE_HEAP           = 1,
    REGION_TYPE_STACK          = 2,
    REGION_TYPE_VDSO           = 3,
    REGION_TYPE_VSYSCALL       = 4,
    REGION_TYPE_ANON           = 5,
    REGION_TYPE_MAIN           = 6,
    REGION_TYPE_LIB            = 7,
    __REGION_TYPE_MAX,
} region_type_t;
extern char *REGION_TYPE_STRINGS[];
#define REGION_TYPE(n) (((n) < __REGION_TYPE_MAX) ? REGION_TYPE_STRINGS[(n)] : NULL)

/**
 ** Target functions.
 **/
struct target_ops *target_get_ops(target_type_t target_type);
struct target *target_create(char *type,struct target_spec *spec);
struct mmap_entry *target_lookup_mmap_entry(struct target *target,
					    ADDR base_addr);
void target_attach_mmap_entry(struct target *target,
			      struct mmap_entry *mme);
void target_release_mmap_entry(struct target *target,
			       struct mmap_entry *mme);

unsigned char *target_generic_fd_read(int fd,
				      ADDR addr,
				      unsigned long length,
				      unsigned char *buf);
unsigned long target_generic_fd_write(int fd,
				      ADDR addr,
				      unsigned long length,
				      unsigned char *buf);

int target_associate_debugfile(struct target *target,
			       struct memregion *region,
			       struct debugfile *debugfile);

/*
 * Given a range and some flags, does the actual target_addr_read after
 * checking bounds (if the flags wanted it).
 */
unsigned char *__target_load_addr_real(struct target *target,
				       struct memrange *range,
				       ADDR addr,load_flags_t flags,
				       unsigned char *buf,int bufsiz);

/**
 ** Overlays.
 **/
struct target *target_lookup_overlay(struct target *target,tid_t tid);

/**
 ** Threads.
 **/
struct target_thread *target_lookup_thread(struct target *target,tid_t tid);
struct target_thread *target_create_thread(struct target *target,tid_t tid,
					   void *tstate);
void target_reuse_thread_as_global(struct target *target,
				   struct target_thread *thread);
void target_detach_thread(struct target *target,struct target_thread *tthread);
void target_delete_thread(struct target *target,struct target_thread *thread,
			  int nohashdelete);

int target_invalidate_all_threads(struct target *target);
int target_invalidate_thread(struct target *target,
			     struct target_thread *tthread);

void target_set_status(struct target *target,target_status_t status);
void target_thread_set_status(struct target_thread *tthread,
			      thread_status_t status);
void target_tid_set_status(struct target *target,tid_t tid,
			   thread_status_t status);

/**
 ** Address spaces.
 **/
struct addrspace *addrspace_create(struct target *target,char *name,int id);
struct memregion *addrspace_find_region(struct addrspace *space,char *name);
struct memregion *addrspace_match_region_name(struct addrspace *space,
					      region_type_t rtype,char *name);
struct memregion *addrspace_match_region_start(struct addrspace *space,
					       region_type_t rtype,ADDR start);
int addrspace_find_range_real(struct addrspace *space,ADDR addr,
			      struct memregion **region_saveptr,
			      struct memrange **range_saveptr);
REFCNT addrspace_free(struct addrspace *space,int force);
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
ADDR memregion_relocate(struct memregion *region,ADDR obj_addr,
			struct memrange **range_saveptr);
struct target *memregion_target(struct memregion *region);
struct memrange *memregion_match_range(struct memregion *region,ADDR start);
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
 ** State changes.
 **/
void target_add_state_change(struct target *target,tid_t tid,
			     target_state_change_type_t chtype,
			     unsigned long code,unsigned long data,
			     ADDR start,ADDR end,char *msg);
void target_clear_state_changes(struct target *target);

/**
 ** Probes and actions.
 **/
/*
 * Attaches a probe to a target.  For now, simply returns a target-wide
 * probe ID, and places the probe in the target's hashtable with that ID.
 */
int target_attach_probe(struct target *target,struct target_thread *thread,
			struct probe *probe);

/*
 * Detaches a probe from a target.
 */
int target_detach_probe(struct target *target,struct probe *probe);

/*
 * Attaches an action to a target.  For now, simply returns a target-wide
 * action ID, and places the action in the target's hashtable with that ID.
 */
int target_attach_action(struct target *target,struct action *action);

/*
 * Detaches a action from a target.
 */
int target_detach_action(struct target *target,struct action *action);

/**
 ** Bound symbols.
 **/
/*
 * Binds an lsymbol to a memregion.  Does NOT hold a ref to the returned
 * bsymbol; the user must do that if they want to use the bsymbol in
 * their code.
 */
struct bsymbol *bsymbol_create(struct lsymbol *lsymbol,
			       struct memregion *region);
/* 
 * Frees a bsymbol.  Users should never call this; call bsymbol_release
 * instead.
 */
REFCNT bsymbol_free(struct bsymbol *bsymbol,int force);

/**
 ** Location resolution.
 **/
/*
 * Resolves @location to an address or register.  If necessary, uses @symbol_chain
 * to do the resolution (i.e., sometimes local vars need a virtual
 * frame base register value that is computed by looking up the
 * containing symbol hierarchy).
 *
 * If the location resolves to an address, we return 1 and set
 * @addr_saveptr and @range_saveptr if they are not NULL.
 *
 * If you pass a location that would "resolve" to a register, not a
 * memory address, we return 2 and set @reg_saveptr if it is not NULL.
 *
 *we return 0 and set errno EADDRNOTAVAIL.  On other
 * errors, we return nonzero with errno set appropriately.
 */
int location_resolve(struct target *target,tid_t tid,struct memregion *region,
		      struct location *location,
		      struct array_list *symbol_chain,
		      REG *reg_saveptr,ADDR *addr_saveptr,
		      struct memrange **range_saveptr);
struct location *location_resolve_loclist(struct target *target,tid_t tid,
					  struct memregion *region,
					  struct location *location);
int location_can_mmap(struct location *location,struct target *target);
int location_resolve_lsymbol_base(struct target *target,tid_t tid,
				  struct lsymbol *lsymbol,
				  struct memregion *region,
				  ADDR *addr_saveptr,
				  struct memrange **range_saveptr);
int location_resolve_symbol_base(struct target *target,tid_t tid,
				 struct bsymbol *bsymbol,ADDR *addr_saveptr,
				 struct memrange **range_saveptr);
int location_resolve_function_base(struct target *target,
				   struct lsymbol *lsymbol,
				   struct memregion *region,
				   ADDR *addr_saveptr,
				   struct memrange **range_saveptr);
int location_resolve_function_prologue_end(struct target *target,
					   struct bsymbol *bsymbol,
					   ADDR *addr_saveptr,
					   struct memrange **range_saveptr);

/**
 ** Location loading functions.
 **/
char *location_load(struct target *target,tid_t tid,struct memregion *region,
		    struct location *location,load_flags_t flags,
		    void *buf,int bufsiz,
		    struct array_list *symbol_chain,
		    ADDR *addr_saveptr,
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
 * Values.
 */
struct value *value_create_raw(struct target *target,
			       struct target_thread *thread,
			       struct memrange *range,int len);
struct value *value_create_type(struct target_thread *thread,
				struct memrange *range,struct symbol *type);
struct value *value_create(struct target_thread *thread,struct memrange *range,
			   struct lsymbol *lsymbol,struct symbol *type);
struct value *value_create_noalloc(struct target_thread *thread,
				   struct memrange *range,
				   struct lsymbol *lsymbol,struct symbol *type);

void value_set_strlen(struct value *value,int len);

int value_set_addr(struct value *value,ADDR addr);
int value_set_mmap(struct value *value,ADDR addr,struct mmap_entry *mmap,
		   char *offset_ptr);
int value_set_reg(struct value *value,REG reg);
int value_set_child(struct value *value,struct value *parent_value,ADDR addr);

void symbol_rvalue_print(FILE *stream,struct symbol *symbol,
			 void *buf,int bufsiz,
			 load_flags_t flags,struct target *target);

/**
 ** Disassembly helpers.
 **/
#ifdef ENABLE_DISTORM
const char *disasm_get_inst_name(inst_type_t type);
int disasm_generic(struct target *target,
		   unsigned char *inst_buf,unsigned int buf_len,
		   struct array_list **idata_list_saveptr,int noabort);
int disasm_get_control_flow_offsets(struct target *target,inst_cf_flags_t flags,
				    unsigned char *inst_buf,unsigned int buf_len,
				    struct array_list **offset_list,ADDR base,
				    int noabort);
int disasm_get_prologue_stack_size(struct target *target,
				   unsigned char *inst_buf,unsigned int buf_len,
				   int *sp);
#endif

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

    /* Our member node on the global spaces list */
    struct list_head space;

    /*
     * The regions contained in this address space.
     *
     * Regions may overlap; thus, lookup functions should query
     * binfiles/debugfiles based on tightest region match, then fall
     * back to next tightest, and so on.  This was added to account for
     * a single giant kernel region, but then to have "sub" regions for
     * modules.  Process address spaces do not need this.
     */
    struct list_head regions;

    /* A backref to the target containing this address space. */
    struct target *target;

    REFCNT refcnt;
    REFCNT refcntw;
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
    int8_t exists:1,
	   new:1;

    /*
     * Debugfiles associated with this region.
     *
     * Really, there should be only one, but I guess this does allow the
     * debuginfo to be split into multiple files.  I doubt this ever
     * happens.
     */
    GHashTable *debugfiles;

    /*
     * A ref to the primary binfile
     */
    struct binfile *binfile;

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

    /*
     * This is the base physical address the region's code got loaded
     * at.  We have to use this to translate addresses for the relocated
     * object in its debuginfo.
     */
    ADDR base_load_addr;

    /*
     * These are the minimum phys/virt address pairs that we learn from
     * looking at the program headers in the binfile (in fact, these
     * should be propagated from the binfile backing the code loaded
     * into this region -- target backend should set it when it loads
     * the debugfile(s) for the region).
     */
    ADDR base_phys_addr;
    ADDR base_virt_addr;

    /* Once we have base_virt_addr and base_phys_addr after looking at
     * the ELF program headers (the ones of type load -- maybe we should
     * check other ones later), we can determine the virt_to_phys
     * offset.
     *
     * We later use this in virt<->phys address translation.
     */
    OFFSET phys_offset;
};

struct memrange {
    /* backref to containing region */
    struct memregion *region;

    ADDR start;
    ADDR end;
    ADDR offset;

    unsigned int prot_flags;
    int8_t same:1,
	   updated:1,
	   new:1;

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

    /* Binding to a target region/range pair. */
    struct memregion *region;
    //struct memrange *range;

    REFCNT refcnt;
    REFCNT refcntw;
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

#endif
