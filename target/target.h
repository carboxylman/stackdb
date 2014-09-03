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

#ifndef __TARGET_H__
#define __TARGET_H__

#include "config.h"

#include <stdint.h>
#include <inttypes.h>
#include <glib.h>

#include "common.h"
#include "object.h"
#include "debugpred.h"
#include "alist.h"
#include "log.h"
#include "memcache.h"
#include "target_api.h"
#include "dwdebug.h"
#ifdef ENABLE_DISTORM
#include "disasm.h"
#endif
#include "probe.h"

#define LOGDUMPBSYMBOL(dl,lt,s) \
    vdebugc((dl),(lt), \
	    "bsymbol(lsymbol(%s,%s,%"PRIxSMOFFSET";chainlen=%d),"	\
	    "region=(%s(space=%s:0x%"PRIxADDR")))",			\
	    symbol_get_name((s)->lsymbol->symbol),			\
	    SYMBOL_TYPE((s)->lsymbol->symbol->type),			\
	    (s)->lsymbol->symbol->ref,					\
	    array_list_len((s)->lsymbol->chain),			\
	    (s)->region ? (s)->region->name : NULL,			\
	    (s)->region ? (s)->region->space->name : NULL,		\
	    (s)->region ? (s)->region->space->tag : 0);

#define LOGDUMPBSYMBOL_NL(dl,lt,s) \
    LOGDUMPBSYMBOL((dl),(lt),(s)); \
    vdebugc((dl),(lt),"\n");

#define ERRORDUMPBSYMBOL(s) \
    verrorc("bsymbol(lsymbol(%s,%s,%"PRIxSMOFFSET";chainlen=%d),"	\
	    "region=(%s(space=%s:0x%"PRIxADDR")))",			\
	    symbol_get_name((s)->lsymbol->symbol),			\
	    SYMBOL_TYPE((s)->lsymbol->symbol->type),			\
	    (s)->lsymbol->symbol->ref,					\
	    array_list_len((s)->lsymbol->chain),			\
	    (s)->region ? (s)->region->name : NULL,			\
	    (s)->region ? (s)->region->space->name : NULL,		\
	    (s)->region ? (s)->region->space->tag : 0);

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

int target_attach_space(struct target *target,struct addrspace *space);
int target_detach_space(struct target *target,struct addrspace *space);

/*
 * Utility function for targets and personalities to set a register
 * value during thread loading.  It's like target_write_reg, but it
 * doesn't mark the thread valid nor load it.  It just sets the value.
 * This is currently necessary for personalities to initialize thread
 * values independent of the target itself.
 */
int target_load_reg(struct target *target,struct target_thread *tthread,
		    REG reg,REGVAL regval);

/*
 * Given a range and some flags, does the actual target_addr_read after
 * checking bounds (if the flags wanted it).
 */
unsigned char *__target_load_addr_real(struct target *target,
				       struct memrange *range,
				       ADDR addr,load_flags_t flags,
				       unsigned char *buf,int bufsiz);

/*
 * The default underlying function for inserting sw breakpoints.
 * Basically, it exposes @is_phys to backends that want to implement
 * breakpoints as phys addrs instead of or in addition to virt addrs.
 */
struct target_memmod *_target_insert_sw_breakpoint(struct target *target,
						   tid_t tid,ADDR addr,
						   int is_phys);

/**
 ** Register regcache helpers.
 **/
int target_regcache_init_reg_tidctxt(struct target *target,
				     struct target_thread *tthread,
				     thread_ctxt_t tctxt,
				     REG reg,REGVAL regval);
int target_regcache_init_done(struct target *target,
			      tid_t tid,thread_ctxt_t tctxt);
typedef int (*target_regcache_regval_handler_t)(struct target *target,
						struct target_thread *tthread,
						thread_ctxt_t tctxt,
						REG reg,REGVAL regval,
						void *priv);
typedef int (*target_regcache_rawval_handler_t)(struct target *target,
						struct target_thread *tthread,
						thread_ctxt_t tctxt,
						REG reg,void *rawval,int rawlen,
						void *priv);
int target_regcache_foreach_dirty(struct target *target,
				  struct target_thread *tthread,
				  thread_ctxt_t tctxt,
				  target_regcache_regval_handler_t regh,
				  target_regcache_rawval_handler_t rawh,
				  void *priv);
int target_regcache_readreg_ifdirty(struct target *target,
				    struct target_thread *tthread,
				    thread_ctxt_t tctxt,REG reg,REGVAL *regval);
int target_regcache_isdirty_reg(struct target *target,
				struct target_thread *tthread,
				thread_ctxt_t tctxt,REG reg);
int target_regcache_isdirty_reg_range(struct target *target,
				      struct target_thread *tthread,
				      thread_ctxt_t tctxt,REG start,REG end);
struct regcache *target_regcache_get(struct target *target,
				     struct target_thread *tthread,
				     thread_ctxt_t tctxt);
int target_regcache_snprintf(struct target *target,struct target_thread *tthread,
			     thread_ctxt_t tctxt,char *buf,int bufsiz,
			     int detail,char *sep,char *kvsep,int flags);
int target_regcache_zero(struct target *target,struct target_thread *tthread,
			 thread_ctxt_t tctxt);
int target_regcache_mark_flushed(struct target *target,
				 struct target_thread *tthread,
				 thread_ctxt_t tctxt);
int target_regcache_invalidate(struct target *target,
				 struct target_thread *tthread,
				 thread_ctxt_t tctxt);
int target_regcache_copy_all(struct target_thread *sthread,
			     thread_ctxt_t stidctxt,
			     struct target_thread *dthread,
			     thread_ctxt_t dtidctxt);
int target_regcache_copy_all_zero(struct target_thread *sthread,
				  thread_ctxt_t stidctxt,
				  struct target_thread *dthread,
				  thread_ctxt_t dtidctxt);
int target_regcache_copy_from(struct target_thread *dthread,
			      thread_ctxt_t dtidctxt,
			      struct regcache *sregcache);
int target_regcache_copy_dirty_to(struct target_thread *sthread,
				  thread_ctxt_t stidctxt,
				  struct regcache *dregcache);
/*
 * These are the drop-ins for the backend register functions.
 */
REGVAL target_regcache_readreg(struct target *target,tid_t tid,REG reg);
int target_regcache_writereg(struct target *target,tid_t tid,
			     REG reg,REGVAL value);
GHashTable *target_regcache_copy_registers(struct target *target,tid_t tid);
REGVAL target_regcache_readreg_tidctxt(struct target *target,
				       tid_t tid,thread_ctxt_t tidctxt,
				       REG reg);
int target_regcache_writereg_tidctxt(struct target *target,
				     tid_t tid,thread_ctxt_t tidctxt,
				     REG reg,REGVAL value);
GHashTable *target_regcache_copy_registers_tidctxt(struct target *target,
						   tid_t tid,
						   thread_ctxt_t tidctxt);
/**
 ** Target personality stuff, and personality ops wrappers.  These
 ** should only be called by backends, or by the target api wrappers.
 **/
struct target_personality_info {
    char *personality;
    target_personality_t ptype;
    struct target_personality_ops *ptops;
    void *pops;
};

int target_personality_attach(struct target *target,
			      char *personality,char *personality_lib);
int target_personality_register(char *personality,target_personality_t pt,
				struct target_personality_ops *ptops,void *pops);

/**
 ** Overlays.
 **/
struct target *target_lookup_overlay(struct target *target,tid_t tid);
void target_detach_overlay(struct target *base,tid_t overlay);
int target_attach_overlay_thread(struct target *base,struct target *overlay,
				 tid_t newtid);
int target_detach_overlay_thread(struct target *base,struct target *overlay,
				 tid_t tid);

/**
 ** Target breakpoints.
 **/
/*
 * We need to "wrap" SW breakpoint information, because not all targets
 * implement breakpoints as direct memory modifications (esp interpreted
 * languages).
 */
typedef enum {
    BP_NONE    = 0,
    BP_SW      = 1,
    BP_HW      = 2,
    BP_PROBE   = 3,
} target_breakpoint_type_t;

struct target_breakpoint {
    struct target *target;
    tid_t tid;
    target_breakpoint_type_t bptype;
    union {
	struct target_memmod *mmod;
	REG hwreg;
	struct {
	    struct probe *pre;
	    struct probe *post;
	} probe;
    };
};

/**
 ** Target memmods.
 **/

/*
 * Oftentimes, we want to edit memory with a replacement that is live as
 * long as the target is open (i.e., a software breakpoint), with
 * temporary changes (i.e., the original instruction during single step;
 * OR a substitute for the original instruction).  The long-term
 * replacement can be set in place via target_memmod_create and
 * target_memmod_set; the original can be returned to by
 * target_memmod_unset (or target_memmod_release); a short-term
 * temporary can be set via target_memmod_set_tmp.
 *
 * In a flat target with all pages accessible to all threads within the
 * same address space (a linux kernel in a VM, or a ptraced process in
 * userspace), we don't need to worry about collisions between threads
 * requiring memmod writes (i.e., writes to the same location) IF the
 * target supports thread control (i.e., ptrace).
 *
 * If the target does not support thread control, the target can either
 * operate in LOOSE mode, where it intentionally acknowledges that one
 * thread might miss a breakpoint (if the original code was substituted
 * in for another thread for a single step there); OR (really risky) if
 * some tmp code was injected at that breakpoint (i.e., a return
 * action) for another thread... the first thread would execute the
 * return action *unintended*.  Both are "dangerous" depending on the
 * debugging user's model.
 *
 * Our only alternative, then, to support a STRICT mode on targets where
 * you cannot simply pause all threads to allow a single thread to do
 * all the single stepping or custom injected code runs at a breakpoint
 * that the user might want -- is to track thread scheduling within the
 * target and ensure that the memmod is *consistent* for the thread that
 * is about to run.
 *
 *   XXX: this is not implemented yet.
 *
 * This abstraction also helps support the case where threads in an
 * overlay target set breakpoints in pages that are shared with other
 * threads that are not members of an overlay target.  In this case, the
 * underlying target would see different virtual addresses that map to
 * the same physical page.  If the physical address of a memmod is
 * known, that is used in preference to its virtual address.
 */
typedef enum {
    MMT_NONE  = 0,
    MMT_BP    = 1,
    MMT_DATA  = 2,
    MMT_CODE  = 3,
} target_memmod_type_t;
#define MEMMOD_TYPE_BITS 2

struct target_memmod *target_memmod_create(struct target *target,tid_t tid,
					   ADDR addr,int is_phys,
					   target_memmod_type_t mmt,
					   unsigned char *code,
					   unsigned int code_len);
struct target_memmod *target_memmod_lookup(struct target *target,tid_t tid,
					   ADDR addr,int is_phys);
unsigned long target_memmod_length(struct target *target,
				   struct target_memmod *mmod);
result_t target_memmod_emulate_bp_handler(struct target *target,tid_t tid,
					  struct target_memmod *mmod);
result_t target_memmod_emulate_ss_handler(struct target *target,tid_t tid,
					  struct target_memmod *mmod);
int target_memmod_set(struct target *target,tid_t tid,
		      struct target_memmod *mmod);
int target_memmod_unset(struct target *target,tid_t tid,
			struct target_memmod *mmod);
int target_memmod_set_tmp(struct target *target,tid_t tid,
			  struct target_memmod *mmod,
			  unsigned char *code,unsigned long code_len);
int target_memmod_release(struct target *target,tid_t tid,
			  struct target_memmod *mmod);
int target_memmod_free(struct target *target,tid_t tid,
		       struct target_memmod *mmod,int force);

typedef enum {
    MMS_ORIG  = 1,
    MMS_SUBST = 2,
    MMS_TMP   = 3,
} target_memmod_state_t;
#define MEMMOD_STATE_BITS 2

struct target_memmod {
    struct target *target;
    /*
     * Eventually, this will just be one thread; for now, it is global
     * to the target.
     */
    //struct target_thread *thread;
    struct array_list *threads;

    target_memmod_type_t type:MEMMOD_TYPE_BITS;
    target_memmod_state_t state:MEMMOD_STATE_BITS;
    unsigned int is_phys:1;

    ADDR addr;

    /*
     * The original contents of memory -- not free until memmod is
     * freed.  This is always a copy.
     */
    unsigned char *orig;
    unsigned long orig_len;
    /*
     * The long-term substitution -- not free until memmod is freed.  If
     * this is not target->breakpoint_instrs, it will be freed when the
     * memmod is removed.
     */
    unsigned char *mod;
    unsigned long mod_len;
    /*
     * A short-term substitution -- copied and freed at need.
     */
    unsigned char *tmp;
    unsigned long tmp_len;

    /*
     * If state is MMS_ORIG or MMS_TMP, this is the owner.  For now, we
     * cannot handle collisions when changing the memmod at all -- we
     * just detect them and warn.
     *
     * Eventually, to handle collisions, whenever there is a
     * modification to a shared page, we have to track thread schedule
     * and ensure that the shared write state is consistent with what
     * the incoming thread expects to see.  This will be expensive, but
     * it is the only way to stay sane without modifying the underlying
     * platform.
     */
    struct target_thread *owner;
};

/**
 ** Probe linkage.
 **/
struct probepoint *target_lookup_probepoint(struct target *target,
					    struct target_thread *tthread,
					    ADDR addr);
int target_insert_probepoint(struct target *target,
			     struct target_thread *tthread,
			     struct probepoint *probepoint);
int target_remove_probepoint(struct target *target,
			     struct target_thread *tthread,
			     struct probepoint *probepoint);
int target_attach_space(struct target *target,struct addrspace *space);
int target_detach_space(struct target *target,struct addrspace *space);

/**
 ** Targets.
 **/
target_status_t target_get_status(struct target *target);
void target_set_status(struct target *target,target_status_t status);

/**
 * Propagates object tracking flags to a target.  Nobody should call
 * this directly; the OBJ*() macros in object.h call it.
 */
int target_obj_flags_propagate(struct target *target,
			       obj_flags_t orf,obj_flags_t nandf);
/**
 * Frees a target.  Nobody should call this directly; the refcnt system
 * calls it.  Internal library users should call RHOLD/RPUT instead.
 */
REFCNT target_free(struct target *target,int force);

/**
 ** Threads.
 **/
struct target_thread *target_lookup_thread(struct target *target,tid_t tid);
struct target_thread *target_create_thread(struct target *target,tid_t tid,
					   void *tstate,void *tpstate);
void target_reuse_thread_as_global(struct target *target,
				   struct target_thread *thread);
void target_detach_thread(struct target *target,struct target_thread *tthread);
int target_thread_obj_flags_propagate(struct target_thread *tthread,
				      obj_flags_t orf,obj_flags_t nandf);
REFCNT target_thread_free(struct target_thread *tthread,int force);

int target_invalidate_thread(struct target *target,
			     struct target_thread *tthread);
int target_invalidate_all_threads(struct target *target);

void target_thread_set_status(struct target_thread *tthread,
			      thread_status_t status);
void target_tid_set_status(struct target *target,tid_t tid,
			   thread_status_t status);

/**
 ** Address spaces.
 **/
struct addrspace *addrspace_create(struct target *target,char *name,ADDR tag);
struct memregion *addrspace_find_region(struct addrspace *space,char *name);
struct memregion *addrspace_match_region_name(struct addrspace *space,
					      region_type_t rtype,char *name);
struct memregion *addrspace_match_region_start(struct addrspace *space,
					       region_type_t rtype,ADDR start);
int addrspace_find_range_real(struct addrspace *space,ADDR addr,
			      struct memregion **region_saveptr,
			      struct memrange **range_saveptr);
int addrspace_detach_region(struct addrspace *space,struct memregion *region);
void addrspace_obj_flags_propagate(struct addrspace *addrspace,
				   obj_flags_t orf,obj_flags_t nandf);
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
ADDR memregion_unrelocate(struct memregion *region,ADDR real_addr,
			  struct memrange **range_saveptr);
struct memrange *memregion_match_range(struct memregion *region,ADDR start);
void memregion_dump(struct memregion *region,struct dump_info *ud);
int memregion_detach_range(struct memregion *region,struct memrange *range);
void memregion_obj_flags_propagate(struct memregion *region,
				   obj_flags_t orf,obj_flags_t nandf);
REFCNT memregion_free(struct memregion *region,int force);

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
void memrange_obj_flags_propagate(struct memrange *range,
				  obj_flags_t orf,obj_flags_t nandf);
REFCNT memrange_free(struct memrange *range,int force);

struct mmap_entry *target_lookup_mmap_entry(struct target *target,
					    ADDR base_addr);
void target_attach_mmap_entry(struct target *target,
			      struct mmap_entry *mme);
void target_release_mmap_entry(struct target *target,
			       struct mmap_entry *mme);

/**
 ** Per-target and per-thread runtime key/value store.  These always
 ** copy the key and free it on remove so that the user doesn't have to
 ** worry.  Thus, the dtors MUST NOT free the key -- it is for info
 ** purposes only.
 **/
typedef void (*target_gkv_dtor_t)(struct target *target,char *key,void *value);
typedef void (*target_thread_gkv_dtor_t)(struct target *target,tid_t tid,
					 char *key,void *value);

static inline void target_gkv_dtor_free(struct target *target,
					char *key,void *value) {
    if (value)
	free(value);
}
static inline void target_gkv_dtor_bsymbol(struct target *target,
					   char *key,void *value) {
    if (value)
	bsymbol_release((struct bsymbol *)value);
}
static inline void target_gkv_dtor_probe(struct target *target,
					 char *key,void *value) {
    if (value)
	probe_free((struct probe *)value,0);
}
static inline void target_gkv_dtor_alist_deep_free(struct target *target,
						   char *key,void *value) {
    if (value)
	array_list_deep_free((struct array_list *)value);
}
static inline void target_thread_gkv_dtor_free(struct target *target,
					       char *key,void *value) {
    if (value)
	free(value);
}

int target_gkv_insert(struct target *target,char *key,void *value,
		      target_gkv_dtor_t dtor);
void *target_gkv_lookup(struct target *target,char *key);
void *target_gkv_steal(struct target *target,char *key);
void target_gkv_remove(struct target *target,char *key);
/* NB: internal. */
void target_gkv_destroy(struct target *target);

int target_thread_gkv_insert(struct target *target,tid_t tid,
			     char *key,void *value,
			     target_thread_gkv_dtor_t dtor);
void *target_thread_gkv_lookup(struct target *target,tid_t tid,char *key);
void *target_thread_gkv_steal(struct target *target,tid_t tid,char *key);
void target_thread_gkv_remove(struct target *target,tid_t tid,char *key);
/* NB: internal. */
void target_thread_gkv_destroy(struct target *target,
			       struct target_thread *tthread);

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
extern struct location_ops target_location_ops;

/**
 ** Location resolution functions.
 **/

int target_symbol_resolve_bounds(struct target *target,
				 struct target_location_ctxt *tlctxt,
				 struct symbol *symbol,
				 ADDR *start,ADDR *end,int *is_noncontiguous,
				 ADDR *alt_start,ADDR *alt_end);
loctype_t target_lsymbol_resolve_location(struct target *target,
					  struct target_location_ctxt *tlctxt,
					  struct lsymbol *lsymbol,
					  ADDR base_addr,
					  load_flags_t flags,
					  struct location *o_loc,
					  struct symbol **o_datatype,
					  struct memrange **o_range);
int target_lsymbol_resolve_bounds(struct target *target,
				  struct target_location_ctxt *tlctxt,
				  struct lsymbol *lsymbol,ADDR base_addr,
				  ADDR *start,ADDR *end,int *is_noncontiguous,
				  ADDR *alt_start,ADDR *alt_end);
int target_bsymbol_resolve_bounds(struct target *target,
				  struct target_location_ctxt *tlctxt,
				  struct bsymbol *bsymbol,ADDR base_addr,
				  ADDR *start,ADDR *end,int *is_noncontiguous,
				  ADDR *alt_start,ADDR *alt_end);

/**
 ** Target name-value filters.  Eventually, this is intended to support
 ** a full expr evaluation mechanism for any name-value coupling.  Right
 ** now, we use it for filtering on value probes and target thread
 ** context values.
 **/
struct target_nv_filter_regex {
    char *value_name;
    regex_t regex;
};

struct target_nv_filter {
    /* A list of struct target_nv_filter_regex. */
    GSList *value_regex_list;
};

struct target_nv_filter *target_nv_filter_parse(char *expr);
void target_nv_filter_free(struct target_nv_filter *pf);

int target_thread_filter_check(struct target *target,tid_t tid,
			       struct target_nv_filter *tf);

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
int value_set_mmap(struct value *value,ADDR addr,struct memcache_mmap_entry *mme,
		   char *offset_ptr);
int value_set_reg(struct value *value,REG reg);
int value_set_child(struct value *value,struct value *parent_value,ADDR addr);
void value_set_const(struct value *value);

void symbol_rvalue_print(FILE *stream,struct symbol *symbol,
			 void *buf,int bufsiz,
			 load_flags_t flags,struct target *target);

/**
 ** Disassembly helpers.
 **/
#ifdef ENABLE_DISTORM
const char *disasm_get_inst_name(inst_type_t type);
/*
 * XXX: if either of the array_list outvars get set, the caller must
 * free them with array_list_deep_free .  Yes, this is bad.
 */
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
 ** Target/Personality API wrappers.
 **/
#define SAFE_PERSONALITY_OP_WARN(op,outvar,expoutval,target,...)	\
    do {								\
	if (target->personality_ops && target->personality_ops->op) {	\
	    vdebug(5,LA_TARGET,LF_TARGET,				\
		   "target(%s): personality_ops->" #op "\n",		\
		   target->name);					\
	    outvar = target->personality_ops->op(target, ## __VA_ARGS__); \
	    if (outvar != expoutval) {					\
		vwarnopt(5,LA_TARGET,LF_TARGET,				\
			 "target(%s): personality_ops->" #op " failed!\n", \
			 target->name);					\
		return outvar;						\
	    }								\
	}								\
	else								\
	    outvar = expoutval;						\
    } while (0);

#define SAFE_PERSONALITY_OP_WARN_NORET(op,outvar,expoutval,target,...)	\
    do {								\
	if (target->personality_ops && target->personality_ops->op) {	\
	    vdebug(5,LA_TARGET,LF_TARGET,				\
		   "target(%s): personality_ops->" #op "\n",	\
		   target->name);					\
	    outvar = target->personality_ops->op(target, ## __VA_ARGS__); \
	    if (outvar != expoutval) {					\
		vwarnopt(5,LA_TARGET,LF_TARGET,				\
			 "target(%s): personality_ops->" #op " failed!\n", \
			 target->name);					\
	    }								\
	}								\
	else								\
	    outvar = expoutval;						\
    } while (0);

#define SAFE_PERSONALITY_OP(op,outvar,defoutval,target,...)		\
    do {								\
	if (target->personality_ops && target->personality_ops->op) {	\
	    vdebug(5,LA_TARGET,LF_TARGET,				\
		   "target(%s): personality_ops->" #op "\n",		\
		   target->name);					\
	    outvar = target->personality_ops->op(target, ## __VA_ARGS__); \
	}								\
	else								\
	    outvar = defoutval;						\
    } while (0);

#define SAFE_TARGET_OP(op,outvar,expoutval,target,...)			\
    do {								\
	if (target->ops && target->ops->op) {	\
	    vdebug(5,LA_TARGET,LF_TARGET,				\
		   "target(%s): ops->" #op "\n",			\
		   target->name);					\
	    outvar = target->ops->op(target, ## __VA_ARGS__);		\
	    if (outvar != expoutval) {					\
		vwarnopt(5,LA_TARGET,LF_TARGET,				\
			 "target(%s): ops->" #op " failed!\n",		\
			 target->name);					\
		return outvar;						\
	    }								\
	}								\
	else if (target->personality_ops && target->personality_ops->op) { \
	    vdebug(5,LA_TARGET,LF_TARGET,				\
		   "target(%s): personality_ops->" #op "\n",		\
		   target->name);					\
	    outvar = target->personality_ops->op(target, ## __VA_ARGS__); \
	    if (outvar != expoutval) {					\
		vwarnopt(5,LA_TARGET,LF_TARGET,				\
			 "target(%s): personality_ops->" #op " failed!\n", \
			 target->name);					\
		return outvar;						\
	    }								\
	}								\
	else								\
	    outvar = expoutval;						\
    } while (0);

#define SAFE_TARGET_OP_WARN_NORET(op,outvar,expoutval,target,...)			\
    do {								\
	if (target->ops && target->ops->op) {	\
	    vdebug(5,LA_TARGET,LF_TARGET,				\
		   "target(%s): ops->" #op "\n",			\
		   target->name);					\
	    outvar = target->ops->op(target, ## __VA_ARGS__);		\
	    if (outvar != expoutval) {					\
		vwarnopt(5,LA_TARGET,LF_TARGET,				\
			 "target(%s): ops->" #op " failed!\n",		\
			 target->name);					\
	    }								\
	}								\
	else if (target->personality_ops && target->personality_ops->op) { \
	    vdebug(5,LA_TARGET,LF_TARGET,				\
		   "target(%s): personality_ops->" #op "\n",		\
		   target->name);					\
	    outvar = target->personality_ops->op(target, ## __VA_ARGS__); \
	    if (outvar != expoutval) {					\
		vwarnopt(5,LA_TARGET,LF_TARGET,				\
			 "target(%s): personality_ops->" #op " failed!\n", \
			 target->name);					\
	    }								\
	}								\
	else								\
	    outvar = expoutval;						\
    } while (0);

#define SAFE_TARGET_ONLY_OP(op,outvar,expoutval,target,...)		\
    do {								\
	if (target->ops && target->ops->op) {				\
	    vdebug(5,LA_TARGET,LF_TARGET,				\
		   "target(%s): ops->" #op "\n",			\
		   target->name);					\
	    outvar = target->ops->op(target, ## __VA_ARGS__);		\
	    if (outvar != expoutval) {					\
		vwarnopt(5,LA_TARGET,LF_TARGET,				\
			 "target(%s): ops->" #op " failed!\n",		\
			 target->name);					\
		return outvar;						\
	    }								\
	}								\
	else 								\
	    outvar = expoutval;						\
    } while (0);

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
    /* A backref to the target containing this address space. */
    struct target *target;

    ADDR tag;
    char *name;

    /*
     * The regions contained in this address space.
     *
     * Regions may overlap; thus, lookup functions should query
     * binfiles/debugfiles based on tightest region match, then fall
     * back to next tightest, and so on.  This was added to account for
     * a single giant kernel region, but then to have "sub" regions for
     * modules.  Process address spaces do not need this.
     */
    GList *regions;

    REFCNT refcnt;
    REFCNT refcntw;
    obj_flags_t obj_flags;
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

    obj_flags_t obj_flags;
    REFCNT refcnt;
    REFCNT refcntw;

    /* The ranges contained in this region. */
    GList *ranges;

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

    obj_flags_t obj_flags;
    REFCNT refcnt;
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
};

#endif
