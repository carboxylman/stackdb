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

#ifndef __PROBE_H__
#define __PROBE_H__

#include "common.h"
#include "list.h"
#include "probe_api.h"

#include <glib.h>

#define PROBE_SAFE_OP(probe,op) (((probe)->ops && (probe)->ops->op) \
                                 ? (probe)->ops->op((probe)) \
                                 : 0)
#define PROBE_SAFE_OP_ARGS(probe,op,...) (((probe)->ops && (probe)->ops->op) \
					  ? (probe)->ops->op((probe), ## __VA_ARGS__) \
					  : 0)

#define LOGDUMPPROBEPOINT(dl,la,lt,pp)	      \
    if ((pp)->bsymbol && (pp)->symbol_addr) { \
	vdebugc((dl),(la),(lt),"probepoint(0x%"PRIxADDR" %s:%+d) ",	\
		(pp)->addr,(pp)->bsymbol->lsymbol->symbol->name, \
		(pp)->symbol_addr - (pp)->addr);	\
    } \
    else if ((pp)->bsymbol) { \
	vdebugc((dl),(la),(lt),"probepoint(0x%"PRIxADDR" %s) ",	 \
	       (pp)->addr,(pp)->bsymbol->lsymbol->symbol->name); \
    } \
    else { \
	vdebugc((dl),(la),(lt),"probepoint(0x%"PRIxADDR") ",	\
	       (pp)->addr); \
    }

#define LOGDUMPPROBEPOINT_NL(dl,la,lt,p)	\
    LOGDUMPPROBEPOINT((dl),(la),(lt),(p));	\
    vdebugc((dl),(la),(lt),"\n");

#define LOGDUMPPROBE(dl,la,lt,p)		 \
    vdebugc((dl),(la),(lt),"probe(%s) ",probe->name);	\
    if ((p)->bsymbol) { \
	vdebugc((dl),(la),(lt),"(on %s) ",		\
		(p)->bsymbol->lsymbol->symbol->name);	\
    } \
    else { \
	vdebugc((dl),(la),(lt),"(on <UNKNOWN>) ");	\
    } \
    if ((p)->probepoint) { 			  \
	LOGDUMPPROBEPOINT(dl,la,lt,(p)->probepoint);	\
    } \
    if ((p)->sources) { 			\
	vdebugc((dl),(la),(lt)," (%d sources)",g_list_length((p)->sources)); \
    } \
    if ((p)->sinks) { 			\
	vdebugc((dl),(la),(lt)," (%d sinks)",g_list_length((p)->sinks)); \
    }

#define LOGDUMPPROBE_NL(dl,la,lt,p)		\
    LOGDUMPPROBE((dl),(la),(lt),(p));		\
    vdebugc((dl),(la),(lt),"\n");

/*
 * probepoint_state_t -- various states of a probe point.  Probepoint
 * state is about how target state is altered to support the
 * probepoint.  For instance, a probepoint may be set, handling, or
 * disabled (inserting/removing are very temporary states, and are
 * meaningless since this library is not reentrant).
 *
 * Probepoints *must* be handled atomically -- we only can single step
 * one instruction after the breakpoint is hit.  This means that any
 * action that happens before the one single step (or replaces it) must
 * be able to do all its dirty work before/during that one single step.
 * The result of that single step is that the breakpoint *must* be
 * replaced -- before any other threads have a chance to hit the
 * breakpoint.
 *
 * Fire-and-forget actions, like a command to single step, or a complex
 * action, like custom code, are still permitted -- but the custom code
 * action must be a call or jump that is single stepped.
 */
typedef enum {
    PROBE_INSERTING = 1,    /* domain quiescing prior to breakpoint insertion */
    PROBE_BP_SET,           /* breakpoint in place */
    PROBE_BP_PREHANDLING,   /* handling a breakpoint's pre handlers */
    PROBE_BP_ACTIONHANDLING,/* handling a breakpoint's actions */
    PROBE_BP_POSTHANDLING,  /* handling a breakpoint's post handlers */
    PROBE_REMOVING,         /* domain quiescing prior to breakpoint removal */
    PROBE_DISABLED,         /* breakpoint removal completed */
    PROBE_ACTION_RUNNING,   /* executing an action */
    PROBE_ACTION_DONE,      /* finished an action */
} probepoint_state_t;

/*
 * Prototypes of the standard breakpoint and single step debug event
 * handlers.  Target implementers probably want to set the bp_handler
 * and ss_handler of the `struct target_ops` representing their target
 * type to these functions.  Without them, the standard probe API is
 * useless, unless the target implements similar semantics.
 */
result_t probepoint_bp_handler(struct target *target,
			       struct target_thread *tthread,
			       struct probepoint *probepoint,
			       int was_stepping);
result_t probepoint_ss_handler(struct target *target,
			       struct target_thread *tthread,
			       struct probepoint *probepoint);
result_t probepoint_interrupted_ss_handler(struct target *target,
					   struct target_thread *tthread,
					   struct probepoint *probepoint);
/*
 * For targets providing thread control, the probe API may choose to
 * "pause" the handling of a thread A at a debug exception, if another
 * thread B already owns the probepoint (i.e., is handling and modifying
 * it).  The thread will not be unpaused, but the probe API will try to
 * handle it in this function.  The idea is that target implementers
 * should call it just before the target is resumed for additional
 * monitoring.
 */
result_t probepoint_resumeat_handler(struct target *target,
				     struct target_thread *tthread);

/*
 * Local prototypes.
 */
struct probe *__probe_register_addr(struct probe *probe,ADDR addr,
				    struct memrange *range,
				    probepoint_type_t type,
				    probepoint_style_t style,
				    probepoint_whence_t whence,
				    probepoint_watchsize_t watchsize,
				    struct bsymbol *bsymbol,ADDR symbol_addr);

/*
 * A probe point is the address site where an actual break/watch point
 * is registered.  We associate multiple logical probes with a single
 * probe point.
 *
 * Currently, the model is that hardware probepoints are per-thread, and
 * are only "alive" in the thread that requested them.  However,
 * software probepoints are shared, since memory is shared, amongst
 * threads.  BUT, how this is realized is target-specific.  Some targets
 * are in control of all threads in the target (i.e., ptrace), and they
 * must pause all threads in the process BEFORE single-stepping past a
 * probepoint, or handling its actions -- since another thread could
 * "miss" a breakpoint if the breakpoint is changed into the real
 * instruction and another thread runs the real thing before the single
 * step can occur.  But in other targets, like the Xen target, we cannot
 * pause threads.  The only thing we can do is disable interrupts while
 * the single step happens (and this won't disable NMIs, of course).
 * This effectively pauses all other threads, unless we are single
 * stepping the context switch itself, or an NMI occurs.
 *
 * In any case, the *probepoint* infrastructure does *not* maintain
 * per-thread probepoint state, nor probe action state.  To support
 * THREAD_BPMODE_STRICT, targets must guarantee that when a probepoint
 * is being handled, only the thread that hit it first will execute
 * until we are finished handling the probepoint for that thread.
 * See also the documentation for THREAD_BPMODE_SEMI_STRICT and
 * THREAD_BPMODE_LOOSE for less safe modes of operation.
 *
 * BUT, we do need to handle multiple probepoint and action states per
 * thread.  Threads could hit one probepoint, and then hit another
 * before completely handling of the previous one.  And we need to track
 * action contexts per thread probepoint context, AND for single step
 * actions, we need to track those on a per-thread basis.
 *
 * To support these goals, we have the thread_probepoint_context; a new
 * one of these is pushed onto the thread's probepoint context stack
 * each time a probepoint is hit by a thread.  We also have the
 * thread_action_context struct, which keeps track of which action is
 * executing at a probepoint context, AND for single step actions, how
 * many steps have executed for that action (note that single step
 * thread_action_contexts are not probepoint-specific -- they accumulate
 * on a thread's list, and the thread stays in single step mode until
 * all actions have finished.  Handling single step actions is separate
 * from handling probepoint contexts.
 */

struct target_thread;
struct action;

struct thread_action_context {
    struct action *action;
    int stepped;

    /* If this context is on a list, this is the element's next/prev ptrs. */
    struct list_head tac;
};

struct thread_probepoint_context {
    struct target_thread *thread;
    struct probepoint *probepoint;

    /* The currently executing complex action. */
    struct thread_action_context tac;

    int action_obviated_orig;
    int did_orig_instr;
};

struct probepoint {
    /* Location of the probe point */
    ADDR addr;

    probepoint_state_t state;

    probepoint_type_t type;
    probepoint_style_t style;
    /*
     * If the user registered the probepoint with PROBEPOINT_FASTEST, we
     * need to save the original style so if it is
     * unregistered/re-registered, we can still make the FASTEST choice,
     * instead of sticking with what we got at last registration.
     */
    probepoint_style_t orig_style;
    probepoint_whence_t whence;
    probepoint_watchsize_t watchsize;

    /* 
     * The target context (target,thread) this probe point is associated
     * with.  @thread is only valid if the probepoint is a hardware
     * probepoint, since right now, only hardware debug registers are
     * per-thread (i.e., software breakpoints are not, since
     * fundamentally, threads, share code pages).
     */
    struct target *target;
    struct target_thread *thread;

    /* If this probepoint is associated with a symbol, save it! */
    struct bsymbol *bsymbol;
    /* If we have a symbol, save its resolved base addr (which may be
     * different than the addr above, of course.
     */
    ADDR symbol_addr;

    /* Always save off which memrange the probe is in. */
    struct memrange *range;
    
    /* list of probes at this probe-point */
    struct list_head probes;

    /*
     * Lists of actions that may be executed at this probepoint.
     * Simple actions are REGMOD and MEMMOD, for now.
     * Complex actions are RETURN, SINGLESTEP, and CUSTOMCODE, for now.
     *
     * Simple actions can all be run immediately post-breakpoint,
     * pre-singlestep, because they just quickly change machine state.
     *
     * Complex actions either run back-to-back, or there is only one of
     * them.
     */
    struct list_head simple_actions;
    struct list_head complex_actions;
    struct list_head ss_actions;
    
    /* 
     * The target_memmod supporting this probepoint.
     */
    struct target_memmod *mmod;

    /*
     * If we ever have to change the instruction at the probepoint
     * address while we handle it, or disable the hw breakpoint
     * register, this is the thread probepoint context struct with the
     * info we need -- and says which thread "holds" this probepoint.
     * Only one thread can be adjusting a probepoint at once.
     *
     * We have to "share" the probepoint anytime we can't boost either
     * the one instruction we have to single step, or if we had to run
     * action code at the breakpoint instead of somewhere else in the
     * target.
     *
     * So, this field is only valid when @state is PROBE_BP_PREHANDLING,
     * PROBE_BP_ACTIONHANDLING, PROBE_BP_POSTHANDLING, and
     * PROBE_ACTION_RUNNING (if the action is not boosted -- i.e., is
     * happening inline at the breakpoint).
     */
    struct thread_probepoint_context *tpc;

    /* If this is a hardware-assisted probepoint, this is the debug
     * register number.
     */
    REG debugregnum;
    int debugregdisabled;

    /* If the instruction at this probepoint might context switch, mark
     * it here.  We try to set this in __probepoint_create.
     */
    int can_switch_context;
};

struct probe {
    /*
     * This is a per-target id.
     */
    int id;

    char *name;

    struct probe_ops *ops;

    void *priv;

    /*
     * This is controlled by the functions in probe_value.c .  It is
     * always a hash of tid_t to <something>.  But the <something> might
     * either be a struct probe_value * directly, OR it could be a
     * GSList * stack of struct probe_value * (this handles reentrant
     * symbols).
     *
     * In any case, it is controlled by probe_ops for this probe.  Users
     * must access it only through the probe_value*() functions.
     */
    GHashTable *values;

    /* 
     * The target context this probe is associated with.
     *
     * NB: we store the tid the probe was created with separately from
     * the thread the target_lookup_thread(target,tid) gave us --
     * because TID_GLOBAL might map to a real thread with a tid that is
     * real, and is not TID_GLOBAL.  We need to know if this was
     * *supposed* to be a TID_GLOBAL probe so we can do pre/post handler
     * filtering appropriately.
     */
    struct target *target;
    struct target_thread *thread;
    tid_t tid;

    /* The target probe-point */
    struct probepoint *probepoint;

    /* User handler to run before probe-point is executed */
    probe_handler_t pre_handler;
    struct target_nv_filter *pre_filter;

    /* User handler to run after probe-point is executed */
    probe_handler_t post_handler;
    struct target_nv_filter *post_filter;

    struct target_nv_filter *thread_filter;

    void *handler_data;

    /* True when the vmprobe is enabled */
    uint8_t enabled;

    uint8_t autofree;

    /*
     * True when the target is tracking this probe; such probes will be
     * automatically freed on target_free().
     *
     * This is useful for cleanup on unexpected target exit, or
     * application crash.  BUT, if you are building probe libraries and
     * use lower-level probes to build higher-level probes, you should
     * only track the higher-level probes; those should free/unregister
     * the probes they use internally themselves.
     */
    uint8_t tracked;

    /* Link to the probe list  */
    struct list_head probe;

    /* A list of probes we listen to.
     */
    GList *sources;

    /* A list of "listening" probes.
     */
    GList *sinks;

    struct bsymbol *bsymbol;
};

struct action {
    /*
     * This is a per-target id.
     */
    int id;

    /*
     * Since actions can be on shared probepoints, and might be being
     * performed on multiple threads at once (i.e., one thread starts a
     * single step action, is switched out, and another thread starts
     * the same single step action before the first thread can finish)
     */
    REFCNT refcnt;

    action_type_t type;
    action_whence_t whence;

    union {
	struct {
	    REGVAL retval;
	    int8_t prologue:1,
		   prologue_uses_bp:1,
		   prologue_has_sp_offset:1;
	    int prologue_sp_offset;
	} ret;
	struct {
	    unsigned char *buf;
	    uint32_t buflen;
	    action_flag_t flags;
	    unsigned int instr_count;
	} code;
	struct {
	    REG regnum;
	    REGVAL regval;
	} regmod;
	struct {
	    ADDR destaddr;
	    unsigned char *data;
	    uint32_t len;
	} memmod;
    } detail;

    int boosted;
    int obviates;

    action_handler_t handler;
    void *handler_data;

    int steps;
    ADDR start_addr;

    /*
     * An action can only be attached to one probepoint at a time.
     *
     * An action is on a probepoint's list, but it is added for a probe
     * attached to that probepoint.
     */
    struct list_head action;
    struct probe *probe;

    struct target *target;
};

/* The target_api code needs to call this, but we don't want it exposed
 * to users.  So it's here.
 */
void probepoint_free_ext(struct probepoint *probepoint);

#endif /* __PROBE_H__ */
