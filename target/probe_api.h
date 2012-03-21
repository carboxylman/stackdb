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

#ifndef __PROBE_API_H__
#define __PROBE_API_H__

/*
 *
 * probes and probepoints:
 *   types: hardware or software (flags should control whether it must
 *     have hw, or must have sw, or would like hw)
 *   breakpoitns and watchpoints
 *   should associate the "containing" symbol, if any, with teh address
 *   should be built on a mechanism for saving and replacing and
 *     restoring arbitrary memory chunks.
 */

struct probepoint;
struct probe;
struct probeset;
struct action;
struct target;
struct memrange;
struct lsymbol;
struct bsymbol;

typedef int (*probe_handler_t)(struct probe *probe,void *handler_data,
			       struct probe *trigger);

struct probe_ops {
    /* Should return a unique type string. */
    const char *(*gettype)(struct probe *probe);
    /* Called after a probe has been freshly malloc'd and its base
     * fields have been initialized.
     */
    int (*init)(struct probe *probe);
    /* Called after a probe has been registered -- either when
     * registered on a probepoint, or when registered on a new source.
     */
    int (*registered)(struct probe *probe);
    /* Called whenever this probe is enabled. */
    int (*enabled)(struct probe *probe);
    /* Called whenever this probe is disabled. */
    int (*disabled)(struct probe *probe);
    /* Called after this probe has been unregistered. */
    int (*unregistered)(struct probe *probe);
    /* Called just before this probe is deallocated.  If you allocated
     * any probe-specific data structures, or took a reference to this
     * probe and it is an autofree probe, you must free those
     * probe-specific data structures, and release your references.
     */
    int (*fini)(struct probe *probe);
};

#define PROBE_SAFE_OP(probe,op) (((probe)->ops && (probe)->ops->op) \
                                 ? (probe)->ops->op((probe)) \
                                 : 0)

int probe_do_sink_pre_handlers (struct probe *probe,void *handler_data,
				struct probe *trigger);
int probe_do_sink_post_handlers(struct probe *probe,void *handler_data,
				struct probe *trigger);

typedef enum {
    PROBEPOINT_BREAK = 1,
    PROBEPOINT_WATCH,
} probepoint_type_t;

typedef enum {
    PROBEPOINT_HW = 1,
    PROBEPOINT_SW,
    PROBEPOINT_FASTEST,
} probepoint_style_t;

typedef enum {
    PROBEPOINT_EXEC = 0,
    PROBEPOINT_WRITE = 1,
    PROBEPOINT_READWRITE = 3,
} probepoint_whence_t;

typedef enum {
    PROBEPOINT_LAUTO = -1,
    PROBEPOINT_L0 = 0,
    PROBEPOINT_L2 = 1,
    PROBEPOINT_L4 = 3,
    PROBEPOINT_L8 = 2,
} probepoint_watchsize_t;

typedef enum {
    ACTION_RETURN     = 0,
    ACTION_REGMOD     = 1,
    ACTION_MEMMOD     = 2,
    ACTION_CUSTOMCODE = 3,
} action_type_t;

typedef enum {
    ACTION_UNSCHED    = 0,
    ACTION_ONESHOT    = 1,
    ACTION_REPEATPRE  = 2,
    ACTION_REPEATPOST = 3,
} action_whence_t;

typedef enum {
    ACTION_FLAG_NOINT   = 1,
    ACTION_FLAG_SAVECTX = 2,
    ACTION_FLAG_DOBREAKREPLACEATEND = 4,
} action_flag_t;

/**
 ** Useful higher-level library functions.
 **/

/*
 * Registers @probe in such a way that probe->pre_handler is called when
 * the function entry point is hit (if @force_at_entry is set, the entry
 * point is the entry point -- which may be the entry point as set in
 * the debuginfo, or the lowest address if not set in debuginfo; if
 * @force_at_entry is NOT set, we try to use the end of prologue address
 * in preference to the entry point).  probe->post_handler is called
 * when any of the return sites are hit.
 *
 * Note that @probe->(pre|post)_handler is called from the pre_handler
 * of the triggering probe, not the post_handler!  This gives you time
 * to tweak args or the return value before the function executes or
 * returns.
 */
struct probe *probe_register_function(struct probe *probe,
				      probepoint_style_t style,
				      struct bsymbol *bsymbol,
				      int force_at_entry);

/*
 * Registers @probe atop source probes at each return site in this
 * function.  @probe->pre_handler will be called from the triggering
 * probe's pre_handler, and @probe->post_handler will be called from the
 * triggering probe's post_handler.
 */
#ifdef ENABLE_DISTORM
#include <disasm.h>
struct probe *probe_register_function_instrs(struct probe *probe,
					     probepoint_style_t style,
					     struct bsymbol *bsymbol,
					     inst_cf_flags_t flags);
#endif

/**
 ** Core probe library functions.
 **/

/*
 * Creates a probe with the given name (should not be NULL, but need not
 * be unique), based on the probe_ops specified (all or part possibly
 * NULL), with the pre and post handlers (at least one must be non-NULL)
 * and handler_data (may be NULL).  If @autofree is set to non-zero, the
 * probe core library will handle destruction for you.  This is useful
 * when you don't care about maintaining a handle to your probe, because
 * it is a source probe of some other sink probe you *do* keep a handle
 * to.  In this way, the library can try to automatically
 * garbage-collect probes that were created merely to serve as sinks for
 * other sources... when there are no more sinks on a particular source,
 * that source probe (and any of its children) can be auto-freed.
 *
 * NOTE: probes are only autofreed when all sinks attached to them have
 * been detached.  There is no magic that frees probes if the process
 * crashes, for instance.  We don't internally track probes that have
 * been created.  We *do* call the @pops.fini function just before
 * destroying a probe, though, so the creator can be notified if it
 * cares, and remove the probe from any place it is referenced.
 *
 * A good rule of thumb: if you set autofree, and the probe is
 * successfully initialized (which you can know about if your
 * @pops.init() function is called), the probe library will autofree the
 * probe on *any* subsequent errors involving the probe -- like a
 * failure to register it; or if it no longer has any consumers (i.e.,
 * its last sink is unregistered).
 *
 * This is syntactic sugar, and may be too complicated to be useful.
 */
struct probe *probe_create(struct target *target,struct probe_ops *pops,
			   const char *name,
			   probe_handler_t pre_handler,
			   probe_handler_t post_handler,
			   void *handler_data,int autofree);

/*
 * If the probe was not specified as an @autofree probe, anybody who
 * calls probe_create must call this function to avoid leaking memory.
 *
 * If the probe is still registered, we try to unregister if we can.
 */
int probe_free(struct probe *probe,int force);

/* 
 * Registers a probe (created with probe_create()) on some symbol.  It
 * will create a breakpoint or watchpoint depending on the type of
 * symbol.  @style, @whence determine how the break/watchpoint is
 * configured; and @watchsize configures a watchpoint.
 */
struct probe *probe_register_symbol(struct probe *probe,struct bsymbol *bsymbol,
				    probepoint_style_t style,
				    probepoint_whence_t whence,
				    probepoint_watchsize_t watchsize);

/*
 * If you have a specific address in mind, use this function instead.
 * If @addr is within a symbol (i.e., a function offset), you can
 * specify the symbol itself for better debug messages, etc.
 */
struct probe *probe_register_addr(struct probe *probe,ADDR addr,
				  probepoint_type_t type,
				  probepoint_style_t style,
				  probepoint_whence_t whence,
				  probepoint_watchsize_t watchsize,
				  struct bsymbol *bsymbol);

/*
 * Fully unregisters a probe.  If it is connected to a probepoint,
 * unregister from that.  If it is connected to sources, unregister from
 * each of them.  If the probepoint is not in use by any other sources,
 * unregister it.  If the sources it was connected to are not in use,
 * unregister them recursively.
 */
int probe_unregister(struct probe *probe,int force);

/*
 * Unregister one probe; do not attempt to unregister anything beneath
 * it, even if its probepoint or sources are not in use!
 */
int probe_unregister_one(struct probe *probe,int force);

/*
 * Registers a sink probe on one source.
 */
struct probe *probe_register_source(struct probe *sink,struct probe *src);

/*
 * Registers a sink probe on each source.
 */
struct probe *probe_register_sources(struct probe *sink,struct probe *src,...);

/*
 * Unregisters one sink probe from one of its sources.  This function
 * also recursively unregisters and frees all autofreeable source probes
 * that are not already in use, and could ultimately remove any
 * probepoints.
 */
int probe_unregister_source(struct probe *sink,struct probe *src,int force);

/*
 * Unregisters only this source from this sink; no recursion.
 */
int probe_unregister_source_one(struct probe *sink,struct probe *src,
				int force);

/*
 * Enable this probe, and all its sources (all the way to the base
 * probes).
 */
int probe_enable_all(struct probe *probe);

/*
 * Disable not only this probe, but all its source probes that do not
 * themselves have enabled sinks.  So, we push the disable operation
 * as low as we can each time.
 */
int probe_disable(struct probe *probe);

int probe_register_batch(struct target *target,ADDR *addrlist,int count,
			 probepoint_type_t type,probepoint_style_t style,
			 probepoint_whence_t whence,
			 probepoint_watchsize_t watchsize,
			 probe_handler_t pre_handler,
			 probe_handler_t post_handler,
			 void *handler_data,
			 struct probe **probelist,
			 int failureaction);

int probe_unregister_batch(struct target *target,struct probe **probelist,
			   int listlen,int force);

probepoint_watchsize_t probepoint_closest_watchsize(int size);

/*
 * Disables a running probe. When disabled, both pre- and post-handlers are 
 * ignored until the probe is enabled back.
 *
 * NOTE: To enable a probe, call enable_vmprobe() function below.
 */
int probe_disable_one(struct probe *probe);

/*
 * Enables an inactive probe.
 * Returns a value of 0 upon successful completion, or a value of -1 if the
 * given handle is invalid.
 */
int probe_enable(struct probe *probe);

/*
 * Indicates whether a probe is enabled or not.
 * Returns a non-zero value if the probe is active, a value of 0 if the 
 * probe is inactive, or a value of -1 if the given handle is invalid.
 */
int probe_enabled(struct probe *probe);

/*
 * Returns non-zero if the probe is a "base" probe; if it is directly
 * attached to a probepoint.
 */
int probe_is_base(struct probe *probe);

/*
 * Returns the address the a probe is targeting.
 * If the given handle is invalid, the function returns a value of 0.
 */
ADDR probe_addr(struct probe *probe);

/*
 * Returns the type of the probe.
 */
probepoint_type_t probe_type(struct probe *probe);

/*
 * Returns the style of the probe.
 */
probepoint_style_t probe_style(struct probe *probe);

/*
 * Returns the whence of the probe.
 */
probepoint_whence_t probe_whence(struct probe *probe);

/* 
 * Schedules an action to occur, given a probe handler.  Actions can
 * only occur when a domain is paused after a probe breakpoint has been
 * hit.  Actions can be scheduled prior to beginning probing, or they
 * can be scheduled at probe handler runtime.
 *
 * Some actions may preclude others in the future.  For instance, a
 * return action depends greatly on the body of the called function NOT
 * being executed at all, so that %eax may be set and a 'ret'
 * instruction executed (so it's immediately after the 'call'
 * instruction; there is no state to clean up, etc.  Allowing a custom
 * code action prior to a return action might change the validity of
 * this assumption.
 *
 * But for now, the only restriction is
 *   - one return action per handle, and it will be performed after
 *     execution of the pre handler.
 *
 * Actions do not have priorities; they are executed in the order
 * scheduled.
 *
 * If @autofree is set, once this action is passed into this function,
 * the user should no longer attempt to free it.  As long as its parent
 * probe is freed by the user (or is autofreed itself), the action will
 * be freed too.  That means if sched produces an error, it will be
 * freed.  Otherwise, if it is a one-shot probe, it will be freed after
 * its execution.  Otherwise, if its probepoint goes away, it will be
 * freed.  Otherwise, if its probe goes away, it will be freed.  Or, if
 * the user cancels it, it will be freed.
 */
int action_sched(struct probe *probe,struct action *action,
		 action_whence_t whence,int autofree);

/*
 * Cancel an action.
 */
void action_cancel(struct action *action);

/*
 * High-level actions that require little ASM knowledge.
 */
struct action *action_return(REGVAL retval);

/*
 * Low-level actions that require little ASM knowledge, and may or may
 * not be permitted.
 */
struct action *action_code(void **code,uint32_t len,uint32_t flags);
struct action *action_regmod(REG regnum,REGVAL regval);
struct action *action_memmod(ADDR destaddr,void *data,uint32_t len);

/*
 * Destroy an action (and cancel it first if necessary!).
 */
void action_destroy(struct action *action);

#endif /* __PROBE_API_H__ */
