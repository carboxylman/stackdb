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

#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "common.h"
#include "log.h"

#include "dwdebug.h"
#include "dwdebug_priv.h"

#include "target_api.h"
#include "target.h"

#include "probe_api.h"
#include "probe.h"

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
	vdebugc((dl),(la),(lt)," (%d sinks)",g_list_length((p)->sources)); \
    }

#define LOGDUMPPROBE_NL(dl,la,lt,p)		\
    LOGDUMPPROBE((dl),(la),(lt),(p));		\
    vdebugc((dl),(la),(lt),"\n");

/*
 * Local prototypes.
 */
static void action_finish_handling(struct action *action,
				   struct thread_action_context *tac);

/*
 * If the user doesn't supply pre/post handlers, and the probe has sinks
 * attached to it, we invoke these handlers to pass the event to the
 * sinks.  Users that write their own handlers should call these
 * handlers from within their handler, so that sinks can attach to their
 * handlers if desired.
 */
result_t probe_do_sink_pre_handlers (struct probe *probe,void *handler_data,
				     struct probe *trigger) {
    struct probe *ptmp;
    GList *list;
    int retval = 0;
    int rc;

    if (probe->sinks) {
	vdebug(5,LA_PROBE,LF_PROBE,"");
	LOGDUMPPROBE_NL(5,LA_PROBE,LF_PROBE,probe);

	list = probe->sinks;
	while (list) {
	    ptmp = (struct probe *)list->data;
	    /* Signal each of the sinks. */
	    if (ptmp->pre_handler) {
		rc = ptmp->pre_handler(ptmp,ptmp->handler_data,trigger);
		if (rc == RESULT_ERROR) {
		    probe_disable(ptmp);
		    retval |= rc;
		}
	    }
	    list = g_list_next(list);
	}
    }

    return retval;
}

result_t probe_do_sink_post_handlers(struct probe *probe,void *handler_data,
				     struct probe *trigger) {
    struct probe *ptmp;
    GList *list;
    int retval = 0;
    int rc;

    if (probe->sinks) {
	vdebug(5,LA_PROBE,LF_PROBE,"");
	LOGDUMPPROBE_NL(5,LA_PROBE,LF_PROBE,probe);

	list = probe->sinks;
	while (list) {
	    ptmp = (struct probe *)list->data;
	    /* Signal each of the sinks. */
	    if (ptmp->post_handler) {
		rc = ptmp->post_handler(ptmp,ptmp->handler_data,trigger);
		if (rc == RESULT_ERROR) {
		    probe_disable(ptmp);
		    retval |= rc;
		}
	    }
	    list = g_list_next(list);
	}
    }

    return retval;
}

static struct probepoint *probepoint_lookup(struct target *target,
					    struct target_thread *tthread,
					    ADDR addr) {
    struct probepoint *retval;

    if (tthread 
	&& (retval = (struct probepoint *) \
	    g_hash_table_lookup(tthread->hard_probepoints,(gpointer)addr))) {
	vdebug(9,LA_PROBE,LF_PROBEPOINT,"found hard ");
	LOGDUMPPROBEPOINT_NL(9,LA_PROBE,LF_PROBEPOINT,retval);
    }
    else if ((retval = (struct probepoint *) \
	      g_hash_table_lookup(target->soft_probepoints,(gpointer)addr))) {
	vdebug(9,LA_PROBE,LF_PROBEPOINT,"found soft ");
	LOGDUMPPROBEPOINT_NL(9,LA_PROBE,LF_PROBEPOINT,retval);
    }
    else
	vdebug(9,LA_PROBE,LF_PROBEPOINT,"did not find probepoint at 0x%"PRIxADDR"\n",
	       addr);

    return retval;
}

static struct probepoint *__probepoint_create(struct target *target,ADDR addr,
					      struct memrange *range,
					      probepoint_type_t type,
					      probepoint_style_t style,
					      probepoint_whence_t whence,
					      probepoint_watchsize_t watchsize,
					      struct bsymbol *bsymbol,
					      ADDR symbol_addr) {
    struct probepoint *probepoint;

    probepoint = (struct probepoint *)malloc(sizeof(*probepoint));
    if (!probepoint) {
        verror("failed to allocate a new probepoint");
        return NULL;
    }
    memset(probepoint,0,sizeof(*probepoint));
    
    probepoint->addr = addr;
    probepoint->range = range;
    probepoint->target = target;
    probepoint->thread = NULL;
    probepoint->state = PROBE_DISABLED;

    probepoint->type = type;
    probepoint->style = probepoint->orig_style = style;
    probepoint->whence = whence;
    probepoint->watchsize = watchsize;

    if (bsymbol) {
	probepoint->bsymbol = bsymbol;
	RHOLD(bsymbol,probepoint);
    }
    probepoint->symbol_addr = symbol_addr;
    
    probepoint->debugregnum = -1;

    INIT_LIST_HEAD(&probepoint->probes);
    INIT_LIST_HEAD(&probepoint->simple_actions);
    INIT_LIST_HEAD(&probepoint->ss_actions);
    INIT_LIST_HEAD(&probepoint->complex_actions);

    if (target->ops->instr_can_switch_context) {
	if ((probepoint->can_switch_context = \
	     target->ops->instr_can_switch_context(target,addr)) < 0) {
	    vwarn("could not determine if instr at 0x%"PRIxADDR" can switch"
		  " context; but continuing!\n",addr);
	    probepoint->can_switch_context = 0;
	}
    }

    vdebug(5,LA_PROBE,LF_PROBEPOINT,"created ");
    LOGDUMPPROBEPOINT(5,LA_PROBE,LF_PROBEPOINT,probepoint);
    if (probepoint->can_switch_context) {
	vdebugc(5,LA_PROBE,LF_PROBEPOINT," (instr can switch context (0x%x)\n",
	       probepoint->can_switch_context);
    }
    else
	vdebugc(5,LA_PROBE,LF_PROBEPOINT,"\n");

    return probepoint;
}

static struct probepoint *probepoint_create_break(struct target *target,
						  ADDR addr,
						  struct memrange *range,
						  probepoint_style_t style,
						  struct bsymbol *bsymbol,
						  ADDR symbol_addr) {
    struct probepoint *probepoint = __probepoint_create(target,addr,range,
							PROBEPOINT_BREAK,style,
							PROBEPOINT_EXEC,0,
							bsymbol,symbol_addr);
    return probepoint;
}

static struct probepoint *probepoint_create_watch(struct target *target,
						  ADDR addr,
						  struct memrange *range,
						  probepoint_style_t style,
						  probepoint_whence_t whence,
						  probepoint_watchsize_t watchsize,
						  struct bsymbol *bsymbol,
						  ADDR symbol_addr) {
    if (style == PROBEPOINT_SW) {
	verror("software watchpoints not supported right now!\n");
	errno = EINVAL;
	return NULL;
    }

    return __probepoint_create(target,addr,range,PROBEPOINT_WATCH,style,
			       whence,watchsize,bsymbol,symbol_addr);
}

static void probepoint_free_internal(struct probepoint *probepoint) {
    struct probe *probe;
    struct probe *ptmp;
    struct action *action;
    struct action *atmp;
    REFCNT trefcnt;

    /* Destroy any actions it might have (probe_free does this too,
     * but this is much more efficient.
     */
    list_for_each_entry_safe(action,atmp,&probepoint->simple_actions,action) {
	if (action->autofree)
	    action_free(action,0);
	else
	    action_cancel(action);
    }
    list_for_each_entry_safe(action,atmp,&probepoint->ss_actions,action) {
	if (action->autofree)
	    action_free(action,0);
	else
	    action_cancel(action);
    }
    list_for_each_entry_safe(action,atmp,&probepoint->complex_actions,action) {
	if (action->autofree)
	    action_free(action,0);
	else
	    action_cancel(action);
    }

    /* Destroy the probes. */
    list_for_each_entry_safe(probe,ptmp,&probepoint->probes,probe) 
	if (probe->autofree)
	    probe_free(probe,0);
    /* XXX: we could also go *up* the src/sink chain and destroy all the
     * sinks... should we?
     */

    if (probepoint->bsymbol) {
	RPUT(probepoint->bsymbol,bsymbol,probepoint,trefcnt);
	probepoint->bsymbol = NULL;
    }
}

/**
 ** Probe unregistration/registration.
 **/
static int __probepoint_remove(struct probepoint *probepoint,int force,
			       int nohashdelete) {
    struct target *target;
    tid_t tid,htid;
    int ret;
    struct thread_probepoint_context *tpc;
    int action_did_obviate = 0;

    target = probepoint->target;

    /* Check if the probepoint has already been inserted; we do not want
     * to backup a previously inserted breakpoint.
     */
    if (probepoint->state == PROBE_DISABLED) {
	/* return success, the probepoint is already removed */
	vdebug(11,LA_PROBE,LF_PROBEPOINT,"");
	LOGDUMPPROBEPOINT(7,LA_PROBE,LF_PROBEPOINT,probepoint);
	vdebugc(11,LA_PROBE,LF_PROBEPOINT," already disabled\n");

        return 0;
    }

    vdebug(5,LA_PROBE,LF_PROBEPOINT,"removing ");
    LOGDUMPPROBEPOINT_NL(5,LA_PROBE,LF_PROBEPOINT,probepoint);

    /*
     * If the style is software, and it's a watchpoint, forget it; we
     * don't support that right now.
     */
    if (probepoint->style == PROBEPOINT_SW 
	&& probepoint->type == PROBEPOINT_WATCH) {
	verror("no software watchpoint support!\n");
	errno = EINVAL;
	return 1;
    }

    /* 
     * If the probepoint is not currently being handled, simply remove
     * it.  Otherwise, we have to handle complex cases!
     */
    if (probepoint->state == PROBE_BP_SET) {
	vdebug(7,LA_PROBE,LF_PROBE,"doing easy removal of ");
	LOGDUMPPROBEPOINT(7,LA_PROBE,LF_PROBE,probepoint);
	vdebugc(7,LA_PROBE,LF_PROBE,"; removing probepoint!\n");
    }
    /*
     * Handle complex stuff :).
     */
    else if (!force) {
	vwarn("probepoint being handled (state %d); not forcing removal yet!\n",
	      probepoint->state);
	errno = EAGAIN;
	return -1;
    }
    else {
	if (probepoint->state == PROBE_ACTION_RUNNING) {
	    vwarn("forced probepoint removal while it is running action;"
		  " trying to clean up normally!\n");
	    /* We need to remove the action code, if any, reset the EIP
	     * to what it would have been if we had just hit the BP, and
	     * then do the normal breakpoint removal.
	     */
	    tpc = probepoint->tpc;

	    if (tpc->action_orig_mem && tpc->action_orig_mem_len) {
		if (target_write_addr(target,probepoint->addr,
				      tpc->action_orig_mem_len,
				      tpc->action_orig_mem)	\
		    != tpc->action_orig_mem_len) {
		    verror("could not write orig code for forced action remove;"
			   " badness will probably ensue!\n");
		    probepoint->state = PROBE_DISABLED;
		}
		else {
		    probepoint->state = PROBE_BP_SET;
		}
		free(tpc->action_orig_mem);
		tpc->action_orig_mem = NULL;
	    }
	    else {
		vwarn("action running, but no orig mem to restore (maybe ok)!\n");
		probepoint->state = PROBE_BP_SET;
	    }

	    if (tpc->action_obviated_orig)
		action_did_obviate = 1;

	    /* NULL these out to be safe. */
	    tpc->action_orig_mem = NULL;
	    tpc->action_orig_mem_len = 0;
	    tpc->tac.action = NULL;
	    tpc->tac.stepped = 0;
	    tpc->action_obviated_orig = 0;
	}
	else if (probepoint->state == PROBE_BP_PREHANDLING) {
	    vwarn("force probepoint removal while prehandling it;"
		  " trying to clean up normally!\n");
	}
	else if (probepoint->state == PROBE_BP_ACTIONHANDLING) {
	    vwarn("force probepoint removal while handling an action;"
		  " trying to clean up normally!\n");
	}
	else if (probepoint->state == PROBE_BP_POSTHANDLING) {
	    vwarn("force probepoint removal while posthandling it;"
		  " trying to clean up normally!\n");
	}
	else if (probepoint->state == PROBE_INSERTING) {
	    vwarn("forced probepoint removal while it is inserting;"
		  " trying to clean up normally!\n");
	    probepoint->state = PROBE_BP_SET;
	}

	/*
	 * If we're doing initial BP handling, reset EIP to the
	 * probepoint addr; else if we're doing BP handling after the
	 * single step, *don't* reset IP, since we already did the
	 * original instruction.  UNLESS we were executing an action
	 * that obviated the original code control flow -- then we
	 * replace the original code below, BUT DO NOT update EIP!
	 */
	if (probepoint->state != PROBE_DISABLED) {
	    /* Reset EIP to the right thing. */
	    if ((probepoint->state == PROBE_BP_PREHANDLING 
		 || probepoint->state == PROBE_BP_ACTIONHANDLING 
		 || probepoint->state == PROBE_ACTION_RUNNING
		 || probepoint->state == PROBE_ACTION_DONE)
		&& !action_did_obviate
		&& probepoint->type != PROBEPOINT_WATCH) {
		/* We still must execute the original instruction. */
		/* BUT NOT for watchpoints!  We do not know anything
		 * about the original instruction.
		 */
		if (probepoint->style == PROBEPOINT_HW) {
		    tid = probepoint->thread->tid;
		}
		else
		    tid = TID_GLOBAL;

		if (target_write_reg(target,tid,
				     target->ipregno,probepoint->addr)) {
		    verror("could not reset IP to bp addr 0x%"PRIxADDR" for"
			   " forced breakpoint remove; badness will probably"
			   " ensue!\n",
			   probepoint->addr);
		}
	    }
	}
    }

    /*
     * If we're going to remove it, do it!
     */

    /*
     * If it's hardware, use the target API to remove it.
     */
    if (probepoint->style == PROBEPOINT_HW) {
	if (probepoint->debugregnum > -1) {
	    htid = probepoint->thread->tid;

	    if (probepoint->type == PROBEPOINT_BREAK) {
		if ((ret = target_unset_hw_breakpoint(target,htid,
						      probepoint->debugregnum))) {
		    verror("failure while removing hw breakpoint; cannot recover!\n");
		}
		else {
		    vdebug(4,LA_PROBE,LF_PROBEPOINT,"removed HW break ");
		    LOGDUMPPROBEPOINT_NL(4,LA_PROBE,LF_PROBEPOINT,probepoint);
		}
	    }
	    else {
		if ((ret = target_unset_hw_watchpoint(target,htid,
						      probepoint->debugregnum))) {
		    verror("failure while removing hw watchpoint; cannot recover!\n");
		}
		else {
		    vdebug(4,LA_PROBE,LF_PROBEPOINT,"removed HW watch ");
		    LOGDUMPPROBEPOINT_NL(4,LA_PROBE,LF_PROBEPOINT,probepoint);
		}
	    }
	}
	else 
	    ret = 0;

	if (ret) 
	    return 1;
	else if (!nohashdelete)
	    g_hash_table_remove(probepoint->thread->hard_probepoints,
				(gpointer)probepoint->addr);

	probepoint->debugregnum = -1;
    }
    /* Otherwise do software. */
    else {
	if (probepoint->breakpoint_orig_mem
	    && probepoint->breakpoint_orig_mem_len > 0) {
	    /* restore the original instruction */
	    if (target_write_addr(target,probepoint->addr,
				  probepoint->breakpoint_orig_mem_len,
				  probepoint->breakpoint_orig_mem) \
		!= probepoint->breakpoint_orig_mem_len) {
		verror("could not restore orig instrs for bp remove");
		return 1;
	    }
	}

	if (target_notify_sw_breakpoint(target,probepoint->addr,0)) 
	    verror("target sw breakpoint removal notification failed; nonfatal!\n");

	vdebug(4,LA_PROBE,LF_PROBEPOINT,"removed SW break ");
	LOGDUMPPROBEPOINT_NL(4,LA_PROBE,LF_PROBEPOINT,probepoint);

	free(probepoint->breakpoint_orig_mem);
	probepoint->breakpoint_orig_mem = NULL;

	if (!nohashdelete)
	    g_hash_table_remove(probepoint->target->soft_probepoints,
				(gpointer)probepoint->addr);
    }

    probepoint->state = PROBE_DISABLED;

    vdebug(2,LA_PROBE,LF_PROBEPOINT,"removed ");
    LOGDUMPPROBEPOINT(2,LA_PROBE,LF_PROBEPOINT,probepoint);
    /*
     * This is just in case it was registered with PROBEPOINT_FASTEST;
     * we need to make sure if it gets re-registered that we make the
     * choice of FASTEST again at that time.
     */
    if (probepoint->style != probepoint->orig_style) {
	vdebug(2,LA_PROBE,LF_PROBEPOINT,"removed (style was %d; now %d)",
	       probepoint->style,probepoint->orig_style);

	probepoint->style = probepoint->orig_style;
    }
    else
	vdebug(2,LA_PROBE,LF_PROBEPOINT,"\n");

    return 0;
}

static void probepoint_free(struct probepoint *probepoint) {
    __probepoint_remove(probepoint,0,0);

    probepoint_free_internal(probepoint);

    vdebug(5,LA_PROBE,LF_PROBEPOINT,"freed ");
    LOGDUMPPROBEPOINT_NL(5,LA_PROBE,LF_PROBEPOINT,probepoint);

    free(probepoint);
}

/* We need this in case the target needs to quickly remove all the
 * probes (i.e., on a signal) -- and in that case, we have to let the
 * target remove the probepoint from its hashtables itself.
 */
void probepoint_free_ext(struct probepoint *probepoint) {
    __probepoint_remove(probepoint,0,1);

    probepoint_free_internal(probepoint);

    vdebug(5,LA_PROBE,LF_PROBEPOINT,"freed (ext) ");
    LOGDUMPPROBEPOINT_NL(5,LA_PROBE,LF_PROBEPOINT,probepoint);

    free(probepoint);
}

/*
 * Note: you *must* pass the target_thread whose debug registers need to
 * be written -- that means if TID_GLOBAL means a "real" thread on a
 * target, like Xen, we need to modify the global thread's debug
 * register state.  For the ptrace target, where the TID_GLOBAL thread
 * might be an alias for a real "primary" thread, we need to *not* have
 * the global thread supplied here, but instead the real thread that is
 * being aliased.
 *
 * So, this comment is just to highlight this issue for
 * __probepoint_insert.  In other functions in this probe library, once
 * a probe is inserted, we carefully use the probepoint->thread->tid tid
 * value for making hardware debug register state changes, if the
 * probepoint is hardware.
 */
static int __probepoint_insert(struct probepoint *probepoint,
			       struct target_thread *tthread) {
    struct target *target;
    tid_t tid;
    int ret;
    REG reg;

    target = probepoint->target;
    tid = tthread->tid;

    /* Check if the probepoint has already been inserted; we do not want
     * to backup a previously inserted breakpoint.
     */
    if (probepoint->state != PROBE_DISABLED) {
	/* return success, the probepoint is already being managed */
	vdebug(11,LA_PROBE,LF_PROBEPOINT,"");
	LOGDUMPPROBEPOINT(9,LA_PROBE,LF_PROBEPOINT,probepoint);
	vdebugc(11,LA_PROBE,LF_PROBEPOINT," already inserted\n");

        return 0;
    }

    vdebug(5,LA_PROBE,LF_PROBEPOINT,"inserting ");
    LOGDUMPPROBEPOINT_NL(5,LA_PROBE,LF_PROBEPOINT,probepoint);

    probepoint->state = PROBE_INSERTING;

    /*
     * Check to see if there are any hardware resources; use them if so.
     */
    if (probepoint->style == PROBEPOINT_FASTEST) {
	if ((reg = target_get_unused_debug_reg(target,tid)) > -1) {
	    probepoint->style = PROBEPOINT_HW;
	    probepoint->debugregnum = reg;

	    vdebug(3,LA_PROBE,LF_PROBEPOINT,"using HW reg %d for ",reg);
	    LOGDUMPPROBEPOINT_NL(3,LA_PROBE,LF_PROBEPOINT,probepoint);
	}
	else {
	    probepoint->style = PROBEPOINT_SW;

	    vdebug(3,LA_PROBE,LF_PROBEPOINT,"using SW for FASTEST ");
	    LOGDUMPPROBEPOINT_NL(3,LA_PROBE,LF_PROBEPOINT,probepoint);
	}
    }
    else if (probepoint->style == PROBEPOINT_HW) {
	if ((reg = target_get_unused_debug_reg(target,tid)) > -1) {
	    probepoint->debugregnum = reg;

	    vdebug(3,LA_PROBE,LF_PROBEPOINT,"using HW reg %d for ",reg);
	    LOGDUMPPROBEPOINT_NL(3,LA_PROBE,LF_PROBEPOINT,probepoint);
	}
	else {
	    vwarn("could not get a debug reg!\n");
	    errno = ENOMEM;
	    probepoint->state = PROBE_DISABLED;
	    return 1;
	}
    }

    /*
     * If the style is software, and it's a watchpoint, forget it; we
     * don't support that right now.
     */
    if (probepoint->style == PROBEPOINT_SW 
	&& probepoint->type == PROBEPOINT_WATCH) {
	verror("no software watchpoint support!\n");
	errno = EINVAL;
	probepoint->state = PROBE_DISABLED;
	return 1;
    }

    /*
     * If it's hardware, use the target API to insert it.
     */
    if (probepoint->style == PROBEPOINT_HW) {
	if (probepoint->type == PROBEPOINT_BREAK) {
	    if ((ret = target_set_hw_breakpoint(target,tid,probepoint->debugregnum,
						probepoint->addr))) {
		verror("failure inserting hw breakpoint!\n");
	    }
	    else {
		vdebug(7,LA_PROBE,LF_PROBEPOINT,"inserted hw break at ");
		LOGDUMPPROBEPOINT_NL(7,LA_PROBE,LF_PROBEPOINT,probepoint);
	    }
	}
	else {
	    if ((ret = target_set_hw_watchpoint(target,tid,probepoint->debugregnum,
						probepoint->addr,
						probepoint->whence,
						probepoint->watchsize))) {
		verror("failure inserting hw watchpoint!\n");
	    }
	    else {
		vdebug(7,LA_PROBE,LF_PROBEPOINT,"inserted hw watch at ");
		LOGDUMPPROBEPOINT_NL(7,LA_PROBE,LF_PROBEPOINT,probepoint);
	    }
	}

	if (ret) {
	    probepoint->state = PROBE_DISABLED;
	    return 1;
	}

	g_hash_table_insert(tthread->hard_probepoints,
			    (gpointer)probepoint->addr,(gpointer)probepoint);
	probepoint->thread = tthread;
    }
    /* Otherwise do software. */
    else {
	/* backup the original instruction */
	probepoint->breakpoint_orig_mem_len = target->breakpoint_instrs_len;
	probepoint->breakpoint_orig_mem = malloc(probepoint->breakpoint_orig_mem_len);
	if (!probepoint->breakpoint_orig_mem) {
	    verror("could not malloc to save orig instrs for bp insert\n");
	    probepoint->state = PROBE_DISABLED;
	    return 1;
	}

	unsigned char ibuf[7];
	if (!target_read_addr(target,probepoint->addr,
			      6,ibuf)) {
	    verror("could not check orig instrs for bp insert\n");
	}
	vdebug(7,LA_PROBE,LF_PROBEPOINT,
	       "orig bytes: %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx\n",
	      (int)ibuf[0],(int)ibuf[1],(int)ibuf[2],(int)ibuf[3],(int)ibuf[4],(int)ibuf[5]);

	if (!target_read_addr(target,probepoint->addr,
			      probepoint->breakpoint_orig_mem_len,
			      probepoint->breakpoint_orig_mem)) {
	    verror("could not save orig instrs for bp insert\n");
	    probepoint->state = PROBE_DISABLED;
	    free(probepoint->breakpoint_orig_mem);
	    probepoint->breakpoint_orig_mem = NULL;
	    return 1;
	}

	vdebug(3,LA_PROBE,LF_PROBEPOINT,"saved orig mem under SW ");
	LOGDUMPPROBEPOINT_NL(3,LA_PROBE,LF_PROBEPOINT,probepoint);

	if (target_write_addr(target,probepoint->addr,
			      target->breakpoint_instrs_len,
			      target->breakpoint_instrs) \
	    != target->breakpoint_instrs_len) {
	    verror("could not write breakpoint instrs for bp insert\n");
	    probepoint->state = PROBE_DISABLED;
	    free(probepoint->breakpoint_orig_mem);
	    probepoint->breakpoint_orig_mem = NULL;
	    return 1;
	}

	if (target_notify_sw_breakpoint(target,probepoint->addr,1)) 
	    verror("target sw breakpoint insertion notification failed; nonfatal!\n");

	vdebug(3,LA_PROBE,LF_PROBEPOINT,"inserted SW ");
	LOGDUMPPROBEPOINT_NL(3,LA_PROBE,LF_PROBEPOINT,probepoint);

	g_hash_table_insert(target->soft_probepoints,
			    (gpointer)probepoint->addr,(gpointer)probepoint);
	probepoint->thread = NULL;
    }

    probepoint->state = PROBE_BP_SET;

    vdebug(2,LA_PROBE,LF_PROBEPOINT,"inserted ");
    LOGDUMPPROBEPOINT_NL(2,LA_PROBE,LF_PROBEPOINT,probepoint);

    return 0;
}

struct probe *probe_create(struct target *target,tid_t tid,struct probe_ops *pops,
			   const char *name,
			   probe_handler_t pre_handler,
			   probe_handler_t post_handler,
			   void *handler_data,int autofree,int tracked) {
    struct probe *probe;
    struct target_thread *tthread;

    if (!(tthread = target_lookup_thread(target,tid))) {
	verror("thread %"PRIiTID" not loaded yet?\n",tid);
	return NULL;
    }

    probe = (struct probe *)malloc(sizeof(*probe));
    if (!probe) {
        verror("failed to allocate a new probe\n");
        return NULL;
    }
    memset(probe,0,sizeof(*probe));
    probe->id = -1;

    probe->name = (name) ? strdup(name) : NULL;
    probe->pre_handler = pre_handler;
    probe->post_handler = post_handler;
    probe->handler_data = handler_data;
    probe->enabled = 0; // disabled at first
    probe->autofree = autofree;
    probe->tracked = tracked;
    probe->ops = pops;

    target_attach_probe(target,tthread,probe);

    if (PROBE_SAFE_OP(probe,init)) {
	verror("probe %s init failed, calling fini!\n",probe->name);
	PROBE_SAFE_OP(probe,fini);
	if (name)
	    free(probe->name);
	free(probe);
	return NULL;
    }

    vdebug(5,LA_PROBE,LF_PROBE,"initialized ");
    LOGDUMPPROBE_NL(5,LA_PROBE,LF_PROBE,probe);

    return probe;
}

int probe_free(struct probe *probe,int force) {
    REFCNT trefcnt;

    vdebug(5,LA_PROBE,LF_PROBE,"");
    LOGDUMPPROBE_NL(5,LA_PROBE,LF_PROBE,probe);

    if (probe->sinks && !force) {
	verror("could not free probe %s with sinks remaining!\n",
	       probe->name);
	return -1;
    }
    else if (probe->probepoint && !force) {
	verror("could not free probe %s with probepoint remaining!\n",
	       probe->name);
	return -1;
    }
    
    if (probe->sinks) 
	vwarn("forcefully freeing probe %s that had sinks/probepoint remaining!\n",
	      probe->name);

    /* If we still need to unregister, we call probe_unregister, which
     * will call us again if the probe was an autofree probe.  So, if it
     * is an autofree probe, let probe_unregister call us again if it
     * succeeds.  If it fails, and we're forcing the free, do it anyway.
     */
    if (probe->probepoint || probe->sources) {
	if (!probe_unregister(probe,force)) {
	    if (probe->autofree)
		return 0;
	}
	else {
	    if (force) 
		verror("probe_unregister %s failed, forcing free to continue",
		       probe->name);
	    else {
		verror("probe_unregister %s failed, not forcing!",probe->name);
		return -1;
	    }
	}
    }

    if (probe->target) 
	target_detach_probe(probe->target,probe);

    if (PROBE_SAFE_OP(probe,fini)) {
	verror("probe %s fini failed, aborting!\n",probe->name);
	return -1;
    }

    if (probe->bsymbol) {
	RPUT(probe->bsymbol,bsymbol,probe,trefcnt);
	probe->bsymbol = NULL;
    }

    vdebug(5,LA_PROBE,LF_PROBE,"almost done: ");
    LOGDUMPPROBE_NL(5,LA_PROBE,LF_PROBE,probe);

    if (probe->name)
	free(probe->name);
    free(probe);

    return 0;
}

void probe_rename(struct probe *probe,const char *name) {
    vdebug(5,LA_PROBE,LF_PROBE,"renaming ");
    LOGDUMPPROBE_NL(5,LA_PROBE,LF_PROBE,probe);

    if (probe->name)
	free(probe->name);

    probe->name = (name) ? strdup(name) : NULL;

    vdebugc(5,LA_PROBE,LF_PROBE," to ");
    LOGDUMPPROBE_NL(5,LA_PROBE,LF_PROBE,probe);

}

int probe_hard_disable(struct probe *probe,int force) {
    struct probe *ptmp;
    GList *list;
    GList *list2;
    int anyenabled = 0;
    int rc = 0;

    list = probe->sources;
    while (list) {
	ptmp = (struct probe *)list->data;

	/* Disable recursively *if* the source doesn't have any
	 * enabled sinks.
	 */
	if (probe_enabled(ptmp)) {
	    list2 = ptmp->sinks;
	    anyenabled = 0;
	    while (list2) {
		if (((struct probe *)(list->data))->enabled) {
		    ++anyenabled;
		}
		list2 = g_list_next(list2);
	    }
	    if (!anyenabled || force) {
		if (force) {
		    vdebug(3,LA_PROBE,LF_PROBE,"forcibly hard disabling source probe");
		    LOGDUMPPROBE(3,LA_PROBE,LF_PROBE,ptmp);
		    vdebug(3,LA_PROBE,LF_PROBE," although it has enabled sink!\n");
		}
		rc += probe_hard_disable(ptmp,force);
	    }
	    else if (anyenabled) {
		vdebug(3,LA_PROBE,LF_PROBE,"not forcibly hard disabling source probe");
		LOGDUMPPROBE(3,LA_PROBE,LF_PROBE,ptmp);
		vdebug(3,LA_PROBE,LF_PROBE," because it has enabled sink(s)!\n");
		++rc;
	    }
	    list = g_list_next(list);
	}
    }

    if (probe_is_base(probe) && __probepoint_remove(probe->probepoint,force,0)) {
	verror("failed to remove probepoint under probe (%d)\n!",force);
	++rc;
    }

    return rc;
}

int probe_hard_enable(struct probe *probe) {
    struct probe *ptmp;
    GList *list;
    int rc = 0;

    /* Do it for all the sources. */
    list = probe->sources;
    while (list) {
	ptmp = (struct probe *)list->data;

	rc += probe_hard_enable(ptmp);

	list = g_list_next(list);
    }

    /* If we have a probepoint directly underneath, do it. */
    if (probe_is_base(probe) 
	&& __probepoint_insert(probe->probepoint,probe->thread)) {
	verror("failed to insert probepoint under probe\n!");
	++rc;
    }

    return rc;
}

static int __probe_unregister(struct probe *probe,int force,int onlyone) {
    struct probepoint *probepoint = probe->probepoint;
    struct target *target = probe->target;
    target_status_t status;
    struct action *action;
    struct action *tmp;
    struct probe *ptmp;
    GList *list;

    vdebug(5,LA_PROBE,LF_PROBE,"");
    LOGDUMPPROBE(5,LA_PROBE,LF_PROBE,probe);
    vdebugc(5,LA_PROBE,LF_PROBE,"(force=%d,onlyone=%d)\n",force,onlyone);

    if (probe->sources) 
	vdebug(5,LA_PROBE,LF_PROBE,"detaching probe %s from sources\n",probe->name);

    if (probe->sinks && !force) {
	verror("could not unregister a probe that had sinks remaining!\n");
	return -1;
    }
    else if (probe->sinks) {
	vwarn("forcefully unregistering a probe that had sinks remaining!\n");
    }

    /* Target must be paused before we do anything. */
    status = target_status(target);
    if (status != TSTATUS_PAUSED) {
        verror("target not paused (%d), cannot remove!\n",status);
	errno = EINVAL;
	return -1;
    }

    /* Disable it (and its sources if necessary). */
    if (onlyone) 
	probe_disable_one(probe);
    else 
	probe_disable(probe);

    if (probepoint) {
	/* Remove the probe from the probepoint's list. */
	list_del(&probe->probe);
	probe->probepoint = NULL;

	/* Cancel (and possibly destroy) any actions it might have. */
	list_for_each_entry_safe(action,tmp,&probepoint->simple_actions,action) {
	    if (probe == action->probe) {
		if (action->autofree) 
		    action_free(action,0);
		else
		    action_cancel(action);
	    }
	}
	list_for_each_entry_safe(action,tmp,&probepoint->ss_actions,action) {
	    if (probe == action->probe) {
		if (action->autofree)
		    action_free(action,0);
		else
		    action_cancel(action);
	    }
	}
	list_for_each_entry_safe(action,tmp,&probepoint->complex_actions,action) {
	    if (probe == action->probe) {
		if (action->autofree)
		    action_free(action,0);
		else
		    action_cancel(action);
	    }
	}
    }

    /* If we are a source on somebody's sink list, remove ourselves! */
    if (probe->sinks) {
	list = probe->sinks;
	while (list) {
	    ptmp = (struct probe *)list->data;
	    ptmp->sources = g_list_remove(ptmp->sources,probe);
	    list = g_list_next(list);
	}
	probe->sinks = NULL;
    }

    /* Unregister from any sources. */
    if (probe->sources) {
	list = probe->sources;
	while (list) {
	vdebug(5,LA_PROBE,LF_PROBE,"removing source\n");
	    ptmp = (struct probe *)list->data;
	    /* We MUST get the next ptr before calling the
	     * probe_unregister_source* functions, because they will
	     * remove our element!
	     */
	    list = g_list_next(list);
	    /* Unregister from the sources, possibly recursively. */
	    if (onlyone)
		probe_unregister_source_one(probe,ptmp,force);
	    else 
		probe_unregister_source(probe,ptmp,force);
	}
	g_list_free(probe->sources);
	probe->sources = NULL;
	vdebug(5,LA_PROBE,LF_PROBE,"probe sources removed\n");
    }

    if (probe->bsymbol) {
	bsymbol_release(probe->bsymbol);
	probe->bsymbol = NULL;
    }

    /* At this point, the probe is unregistered; what remains is to
     * remove its probepoint, if necessary, and we don't have to wait to
     * let the user know.
     */
    if (PROBE_SAFE_OP(probe,unregistered)) {
	verror("probe '%s': unregistered failed, aborting\n",probe->name);
	return -1;
    }

    /* Free the probe if it is an autofree probe. */
    if (probe->autofree)
	if (probe_free(probe,force))
	    verror("could not autofree probe; continuing anyway!\n");

    /* If it's just a source/sink probe, we're done; otherwise, try to
     * remove the probepoint too if no one else is using it.
     */
    if (!probepoint) 
	return 0;

    /* If this is the last probe at this probepoint, remove the
     * probepoint too -- IF possible, or IF forced!
     */
    if (!list_empty(&probepoint->probes)) 
	return 0;

    vdebug(5,LA_PROBE,LF_PROBE,"no more probes at ");
    LOGDUMPPROBEPOINT(5,LA_PROBE,LF_PROBE,probepoint);
    vdebugc(5,LA_PROBE,LF_PROBE,"; removing probepoint!\n");

    if (!__probepoint_remove(probepoint,force,0))
	probepoint_free(probepoint);
    else if (force) {
	verror("probepoint_remove failed, but force freeing!\n");
	probepoint_free(probepoint);
	return -1;
    }
    else {
	verror("probepoint_remove failed; not force freeing!\n");
	return -1;
    }

    return 0;
}

/*
 * Unregisters a probe.
 * Upon successful completion, a value of 0 is returned. Otherwise, a value
 * of -1 is returned and the global integer variable errno is set to indicate 
 * the error.
 */
int probe_unregister(struct probe *probe,int force) {
    return __probe_unregister(probe,force,0);
}

int probe_unregister_one(struct probe *probe,int force) {
    return __probe_unregister(probe,force,1);
}

int probe_unregister_source(struct probe *sink,struct probe *src,int force) {
    target_status_t status;
    struct target *target = sink->target;

    if (!sink->sources) {
	verror("probe %s has no sources!\n",sink->name);
	return -1;
    }

    /* Target must be paused before we do anything. */
    status = target_status(target);
    if (status != TSTATUS_PAUSED) {
        verror("target not paused (%d), cannot remove!\n",status);
	errno = EINVAL;
	return -1;
    }

    sink->sources = g_list_remove(sink->sources,src);
    src->sinks = g_list_remove(src->sinks,sink);

    /* Do it recursively! */
    if (src->autofree && !src->sinks)
	__probe_unregister(src,force,0);

    if (PROBE_SAFE_OP(sink,unregistered)) {
	verror("probe %s: unregistered failed, aborting\n",sink->name);
	return -1;
    }

    if (sink->autofree) {
	return probe_free(sink,force);
    }

    return 0;
}

int probe_unregister_source_one(struct probe *sink,struct probe *src,
				int force) {
    if (!sink->sources) {
	verror("probe %s has no sources!\n",sink->name);
	return -1;
    }

    sink->sources = g_list_remove(sink->sources,src);
    src->sinks = g_list_remove(src->sinks,sink);

    if (PROBE_SAFE_OP(sink,unregistered)) {
	verror("probe %s: unregistered failed, aborting\n",sink->name);
	return -1;
    }

    if (sink->autofree) {
	return probe_free(sink,force);
    }

    return 0;
}

/*
 * This function always frees its probes, BUT the underlying probepoints
 * might fail to be freed.  If so, we return the number of probepoints
 * that failed to free (note that if other probes are attached, those
 * probepoints are not freed and it's not an error).
 */
int probe_unregister_batch(struct target *target,struct probe **probelist,
			   int listlen,int force) {
    int i;
    int retval = 0;

    if (!probelist)
	return -1;
    if (!listlen) 
	return 0;

    /* Target must be paused before we do anything. */
    if (target_status(target) != TSTATUS_PAUSED) {
        verror("target not paused!\n");
	errno = EINVAL;
	return -1;
    }

    for (i = 0; i < listlen; ++i) {
	/* allow sparse lists */
	if (probelist[i] == NULL)
	    continue;

	if (__probe_unregister(probelist[i],force,1)) {
	    ++retval;
	}
	probelist[i] = NULL;
    }

    return retval;
}

struct probe *__probe_register_addr(struct probe *probe,ADDR addr,
				    struct memrange *range,
				    probepoint_type_t type,
				    probepoint_style_t style,
				    probepoint_whence_t whence,
				    probepoint_watchsize_t watchsize,
				    struct bsymbol *bsymbol,ADDR symbol_addr) {
    struct probepoint *probepoint;
    int created = 0;
    struct target *target = probe->target;

    if (type == PROBEPOINT_WATCH && style == PROBEPOINT_SW) {
	verror("software watchpoints are unsupported!\n");
	errno = EINVAL;
	goto errout;
    }

    /* Target must be paused before we do anything. */
    if (target_status(target) != TSTATUS_PAUSED) {
        verror("target not paused!\n");
	errno = EINVAL;
	goto errout;
    }

    /* If the user has associated a bound symbol with this probe
     * registration, try to look up its start addr (and grab the range
     * if we can).
     */
    if (bsymbol) {
	location_resolve_symbol_base(target,probe->thread->tid,
				     bsymbol,&symbol_addr,
				     (!range) ? &range : NULL);
	probe->bsymbol = bsymbol;
	RHOLD(bsymbol,probe);
    }

    /* If we don't have a range yet, get it. */
    if (!range) {
	target_find_memory_real(target,addr,NULL,NULL,&range);
	if (!range) {
	    verror("could not find range for 0x%"PRIxADDR"\n",addr);
	    goto errout;
	}
    }

    /* Create a probepoint if this is a new addr. */
    if ((probepoint = probepoint_lookup(target,probe->thread,addr))) {
	/* If the style matches for breakpoints, and if the style,
	 * whence, and watchsize match for watchpoints, reuse it!
	 */
	if (!((type == PROBEPOINT_BREAK
	       && type == probepoint->type
	       && ((probepoint->style == PROBEPOINT_HW
		    && (style == PROBEPOINT_HW
			|| style == PROBEPOINT_FASTEST))
		   || (probepoint->style == PROBEPOINT_SW
		       && (style == PROBEPOINT_SW
			   || style == PROBEPOINT_FASTEST))))
	      || (type == PROBEPOINT_WATCH
		  && type == probepoint->type
		  && style == probepoint->style
		  && whence == probepoint->whence
		  && watchsize == probepoint->watchsize))) {
	    verror("addr 0x%"PRIxADDR" already has a probepoint with different properties!\n",addr);
	    errno = EADDRINUSE;
	    goto errout;
	}
    }
    else {
        if (type == PROBEPOINT_BREAK) {
	    if (!(probepoint = probepoint_create_break(target,addr,range,style,
						       bsymbol,symbol_addr))) {
		verror("could not create breakpoint for 0x%"PRIxADDR"\n",addr);
		goto errout;
	    }
	}
	else {
	    if (whence == PROBEPOINT_WAUTO) 
		whence = PROBEPOINT_READWRITE;

	    if (!(probepoint = probepoint_create_watch(target,addr,range,
						       style,whence,watchsize,
						       bsymbol,symbol_addr))) {
		verror("could not create watchpoint for 0x%"PRIxADDR"\n",addr);
		goto errout;
	    }
	}

	created = 1;
    }

    /* Inject the probepoint. */
    if (__probepoint_insert(probepoint,probe->thread)) {
	verror("could not insert probepoint at 0x%"PRIxADDR"\n",addr);
	if (created) 
	    probepoint_free(probepoint);
	goto errout;
    }

    list_add_tail(&probe->probe,&probepoint->probes);
    probe->probepoint = probepoint;

    if (PROBE_SAFE_OP(probe,registered)) {
	verror("probe '%s': registered failed, aborting\n",probe->name);
	if (created) 
	    probepoint_free(probepoint);
	goto errout;
    }

    if (probe_enable(probe) && created) {
	probepoint_free(probepoint);
	goto errout;
    }

    vdebug(5,LA_PROBE,LF_PROBE,"probe %s attached to ",probe->name);
    LOGDUMPPROBEPOINT(5,LA_PROBE,LF_PROBE,probe->probepoint);
    vdebugc(5,LA_PROBE,LF_PROBE,"\n");

    return probe;

 errout:
    if (bsymbol) {
	bsymbol_release(bsymbol);
	probe->bsymbol = NULL;
    }
    if (probe->autofree)
	probe_free(probe,1);
    return NULL;
}

struct probe *probe_register_addr(struct probe *probe,ADDR addr,
				  probepoint_type_t type,
				  probepoint_style_t style,
				  probepoint_whence_t whence,
				  probepoint_watchsize_t watchsize,
				  struct bsymbol *bsymbol) {
    return __probe_register_addr(probe,addr,NULL,type,style,whence,watchsize,
				 bsymbol,0);
}

struct probe *probe_register_line(struct probe *probe,char *filename,int line,
				  probepoint_style_t style,
				  probepoint_whence_t whence,
				  probepoint_watchsize_t watchsize) {
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;
    struct memrange *range;
    ADDR start = 0;
    ADDR probeaddr;
    struct bsymbol *bsymbol = NULL;

    bsymbol = target_lookup_sym_line(target,filename,line,NULL,&probeaddr);
    if (!bsymbol)
	return NULL;

    /* No need to RHOLD(); __probe_register_addr() does it. 
     * IN FACT, we need to release when we exit!
     */

    if (!SYMBOL_IS_FULL_INSTANCE(bsymbol->lsymbol->symbol)) {
	verror("cannot probe a partial symbol!\n");
	goto errout;
    }

    if (SYMBOL_IS_FULL_FUNCTION(bsymbol->lsymbol->symbol)) {
	if (location_resolve_symbol_base(target,tid,bsymbol,&start,&range)) {
	    verror("could not resolve entry PC for function %s!\n",
		   bsymbol->lsymbol->symbol->name);
	    goto errout;
	}

	probe = __probe_register_addr(probe,probeaddr,range,
				      PROBEPOINT_BREAK,style,whence,watchsize,
				      bsymbol,start);
    }
    else if (SYMBOL_IS_FULL_LABEL(bsymbol->lsymbol->symbol)) {
	if (location_resolve_symbol_base(target,tid,bsymbol,&start,&range)) {
	    verror("could not resolve base addr for label %s!\n",
		   bsymbol->lsymbol->symbol->name);
	    goto errout;
	}

	probe = __probe_register_addr(probe,probeaddr,range,
				      PROBEPOINT_BREAK,style,whence,watchsize,
				      bsymbol,start);
    }
    else {
	verror("unknown symbol type '%s'!\n",
	       SYMBOL_TYPE(bsymbol->lsymbol->symbol->type));
	goto errout;
    }

    bsymbol_release(bsymbol);
    return probe;

 errout:
    if (probe->autofree)
	probe_free(probe,1);
    if (bsymbol)
	bsymbol_release(bsymbol);
    return NULL;
}

struct probe *probe_register_symbol(struct probe *probe,struct bsymbol *bsymbol,
				    probepoint_style_t style,
				    probepoint_whence_t whence,
				    probepoint_watchsize_t watchsize) {
    struct target *target = probe->target;
    tid_t tid = probe->thread->tid;
    struct memrange *range;
    ADDR start;
    ADDR prologueend;
    ADDR probeaddr;
    int ssize;

    /* No need to RHOLD(); __probe_register_addr() does it. */

    if (SYMBOL_IS_FUNCTION(bsymbol->lsymbol->symbol)) {
	if (location_resolve_symbol_base(target,tid,bsymbol,&start,&range)) {
	    verror("could not resolve entry PC for function %s!\n",
		   bsymbol->lsymbol->symbol->name);
	    goto errout;
	}
	else 
	    probeaddr = start;

	if (location_resolve_function_prologue_end(target,bsymbol,
						   &prologueend,&range)) {
	    vwarn("could not resolve prologue_end for function %s!\n",
		  bsymbol->lsymbol->symbol->name);
	}
	else 
	    probeaddr = prologueend;

	probe = __probe_register_addr(probe,probeaddr,range,
				      PROBEPOINT_BREAK,style,whence,watchsize,
				      bsymbol,start);
    }
    else if (SYMBOL_IS_FULL_LABEL(bsymbol->lsymbol->symbol)) {
	if (location_resolve_symbol_base(target,tid,bsymbol,&probeaddr,&range)) {
	    verror("could not resolve base addr for label %s!\n",
		   bsymbol->lsymbol->symbol->name);
	    goto errout;
	}

	probe = __probe_register_addr(probe,probeaddr,range,
				      PROBEPOINT_BREAK,style,whence,watchsize,
				      bsymbol,probeaddr);
    }
    else if (SYMBOL_IS_FULL_VAR(bsymbol->lsymbol->symbol)) {
	if (watchsize == PROBEPOINT_LAUTO) {
	    ssize = symbol_type_full_bytesize(symbol_get_datatype__int(bsymbol->lsymbol->symbol));
	    if (ssize <= 0) {
		verror("bad size (%d) for type of %s!\n",
		       ssize,bsymbol->lsymbol->symbol->name);
		goto errout;
	    }

	    watchsize = probepoint_closest_watchsize(ssize);
	}

	if (location_resolve_symbol_base(target,tid,bsymbol,&probeaddr,&range)) {
	    verror("could not resolve base addr for var %s!\n",
		   bsymbol->lsymbol->symbol->name);
	    goto errout;
	}

	probe = __probe_register_addr(probe,probeaddr,range,
				      PROBEPOINT_WATCH,style,whence,watchsize,
				      bsymbol,probeaddr);
    }
    else {
	verror("unknown symbol type '%s'!\n",
	       SYMBOL_TYPE(bsymbol->lsymbol->symbol->type));
	goto errout;
    }

    vdebug(5,LA_PROBE,LF_PROBE,"registered probe on %s at 0x%"PRIxADDR"\n",
	   bsymbol->lsymbol->symbol->name,probeaddr);

    return probe;

 errout:
    if (probe->autofree)
	probe_free(probe,1);
    return NULL;
}

struct probe *probe_register_source(struct probe *sink,struct probe *src) {
    struct target *target = sink->target;
    int held_src_bsymbol = 0;
    REFCNT trefcnt;

    /* XXX: should we do this?  Steal the src's bsymbol if we don't have
     * one!
     */
    if (!sink->bsymbol && src->bsymbol) {
	sink->bsymbol = src->bsymbol;
	RHOLD(src->bsymbol,sink);
	held_src_bsymbol = 1;
    }

    if (sink->target != src->target) {
	verror("sink %s/src %s targets different!\n",sink->name,src->name);
	goto errout;
    }

    /* Target must be paused before we do anything. */
    if (target_status(target) != TSTATUS_PAUSED) {
        verror("target not paused!\n");
	errno = EINVAL;
	goto errout;
    }

    /* Add this sink to the src, and vice versa! */
    sink->sources = g_list_prepend(sink->sources,src);
    src->sinks = g_list_prepend(src->sinks,sink);

    if (PROBE_SAFE_OP(sink,registered)) {
	verror("probe '%s': registered failed, aborting\n",sink->name);
	goto errout;
    }

    /* Enable everybody downstream. */
    if (probe_enable(sink)) {
	verror("failed to enable sink probe '%s', aborting\n",sink->name);
	goto errout;
    }

    return sink;

 errout:
    if (held_src_bsymbol) {
	RPUT(sink->bsymbol,bsymbol,sink,trefcnt);
	sink->bsymbol = NULL;
    }
    if (sink->autofree)
	probe_free(sink,1);
    return NULL;
}

struct probe *probe_register_sources(struct probe *sink,struct probe *src,...) {
    va_list ap;
    struct probe *rc;
    struct probe *tsrc;

    va_start(ap,src);
    while ((tsrc = va_arg(ap,struct probe *))) {
	if (tsrc->target != sink->target) {
	    verror("sink %s and src %s targets differ!\n",sink->name,src->name);
	    return NULL;
	}
    }
    va_end(ap);

    if (!(rc = probe_register_source(sink,src)))
	return rc;

    va_start(ap,src);
    while ((tsrc = va_arg(ap,struct probe *))) {
	if (!(rc = probe_register_source(sink,tsrc)))
	    return rc;
	/*
	 * XXX: need to unwind registrations, too, in case of failure,
	 * just like for probe batch registration!
	 */
    }
    va_end(ap);

    return sink;
}

int probe_register_batch(struct target *target,tid_t tid,
			 ADDR *addrlist,int listlen,
			 probepoint_type_t type,probepoint_style_t style,
			 probepoint_whence_t whence,
			 probepoint_watchsize_t watchsize,
			 probe_handler_t pre_handler,
			 probe_handler_t post_handler,
			 void *handler_data,
			 struct probe **probelist,
			 int failureaction) {
    int i;
    int retval = 0;
    struct probe *probe;
    char *buf;

    if (!probelist)
	return -1;
    if (!listlen) 
	return 0;

    if (type == PROBEPOINT_WATCH && style == PROBEPOINT_SW) {
	verror("software watchpoints are unsupported!\n");
	errno = EINVAL;
	return -1;
    }

    /* Target must be paused before we do anything. */
    if (target_status(target) != TSTATUS_PAUSED) {
        verror("target not paused!\n");
	errno = EINVAL;
	return -1;
    }

    for (i = 0; i < listlen; ++i) {
	/* allow sparse lists */
	if (addrlist[i] == 0)
	    continue;

	buf = malloc(5+1+16+1);
	sprintf(buf,"probe@%"PRIxADDR,addrlist[i]);
	probe = probe_create(target,tid,NULL,buf,pre_handler,post_handler,
			     handler_data,0,1);

	if (!(probelist[i] = probe_register_addr(probe,addrlist[i],
						 type,style,whence,watchsize,
						 NULL))) {
	    if (failureaction == 2) {
		++retval;
		continue;
	    }
	    else if (failureaction == 1) {
		++retval;
		goto errunreg;
	    }
	    else {
		retval = 1;
		goto out;
	    }
	}
    }
    goto out;

 errunreg:
    for (i = 0; i < listlen; ++i) {
	if (addrlist[i] == 0)
	    continue;

	if (probelist[i] == NULL)
	    continue;

	/* Don't force this unregister.  If there are dangling
	 * probepoints, they'll have to get harvested later.  This
	 * totally should not happen here though -- the batch
	 * registration is like a transaction.
	 */
	__probe_unregister(probelist[i],0,1);
    }

 out:
    return retval;
}

probepoint_watchsize_t probepoint_closest_watchsize(int size) {
    if (size <= 1)
	return PROBEPOINT_L0;
    else if (size <= 2)
	return PROBEPOINT_L2;
    else {
#if __WORDSIZE == 64
	if (size <= 4)
	    return PROBEPOINT_L4;
	else 
	    return PROBEPOINT_L8;
#else
	return PROBEPOINT_L4;
#endif
    }
}

void *probe_summarize(struct probe *probe) {
    if (!probe->ops || !probe->ops->summarize) 
	return NULL;

    return probe->ops->summarize(probe);
}

int probe_disable_one(struct probe *probe) {
    probe->enabled = 0;

    if (PROBE_SAFE_OP(probe,disabled)) {
	verror("probe '%s': disabled failed, ignoring\n",probe->name);
	return -1;
    }

    return 0;
}

int probe_disable(struct probe *probe) {
    struct probe *ptmp;
    GList *list;
    GList *list2;
    int anyenabled = 0;
    int retval = 0;

    if (probe_disable_one(probe))
	return -1;

    if (probe->sources) {
	list = probe->sources;
	while (list) {
	    ptmp = (struct probe *)list->data;

	    /* Disable recursively *if* the source doesn't have any
	     * enabled sinks.
	     */
	    if (probe_enabled(ptmp)) {
		list2 = ptmp->sinks;
		while (list2) {
		    if (((struct probe *)(list->data))->enabled) {
			anyenabled = 1;
			break;
		    }
		    list2 = g_list_next(list2);
		}
		if (!anyenabled)
		    retval |= probe_disable(ptmp);
		anyenabled = 0;
	    }
	    list = g_list_next(list);
	}
    }

    return retval;
}

int probe_enable_one(struct probe *probe) {
    probe->enabled = 1;

    if (PROBE_SAFE_OP(probe,enabled)) {
	verror("probe '%s': enabled failed, disabling!\n",probe->name);
	probe->enabled = 0;
	return -1;
    }

    return 0;
}

int probe_enable(struct probe *probe) {
    struct probe *ptmp;
    GList *list;
    GList *list2;
    int anyenabled = 0;

    if (probe->sources) {
	list = probe->sources;
	while (list) {
	    ptmp = (struct probe *)list->data;
	    if (!probe_enabled(ptmp))
		probe_enable(ptmp);
	    list = g_list_next(list);
	}
    }

    probe->enabled = 1;

    if (PROBE_SAFE_OP(probe,enabled)) {
	verror("probe '%s': enabled failed, disabling\n",probe->name);
	probe->enabled = 0;
	if (probe->sources) {
	    list = probe->sources;
	    while (list) {
		ptmp = (struct probe *)list->data;

		/* basically do probe_disable, but don't notify probe! */
		if (probe_enabled(ptmp)) {
		    list2 = ptmp->sinks;
		    while (list2) {
			if (((struct probe *)(list->data))->enabled) {
			    anyenabled = 1;
			    break;
			}
			list2 = g_list_next(list2);
		    }
		    if (!anyenabled)
			probe_disable(ptmp);
		    anyenabled = 0;
		}
		list = g_list_next(list);
	    }
	}
	return -1;
    }

    return 0;
}

/*
 * Indicates whether a probe is enabled or not.
 * Returns a non-zero value if the probe is active, a value of 0 if the 
 * probe is inactive, or a value of -1 if the given handle is invalid.
 */
int probe_enabled(struct probe *probe) {
    return probe->enabled;
}

int probe_is_base(struct probe *probe) {
    return probe->probepoint != NULL;
}

int probe_num_sources(struct probe *probe) {
    if (probe->sources)
	return g_list_length(probe->sources);
    return 0;
}

int probe_num_sinks(struct probe *probe) {
    if (probe->sinks)
	return g_list_length(probe->sinks);
    return 0;
}

char *probe_name(struct probe *probe) {
    return probe->name;
}

void *probe_priv(struct probe *probe) {
    return probe->priv;
}

/*
 * Returns the address the a probe is targeting, or 0 if the probe is a
 * sink without a probepoint.
 */
ADDR probe_addr(struct probe *probe) {
    if (probe->probepoint)
	return probe->probepoint->addr;
    return 0;
}

/*
 * Returns the type of the probe.
 */
probepoint_type_t probe_type(struct probe *probe) {
    return probe->probepoint->type;
}

/*
 * Returns the style of the probe.
 */
probepoint_style_t probe_style(struct probe *probe) {
    return probe->probepoint->style;
}

/*
 * Returns the whence of the probe.
 */
probepoint_whence_t probe_whence(struct probe *probe) {
    return probe->probepoint->whence;
}


static int run_post_handlers(struct target *target,
			     struct target_thread *tthread,
			     struct probepoint *probepoint);
static int setup_post_single_step(struct target *target,
				  struct target_thread *tthread,
				  struct probepoint *probepoint);
static int handle_simple_actions(struct target *target,
				 struct target_thread *tthread,
				 struct probepoint *probepoint);
static int handle_complex_actions(struct target *target,
				  struct target_thread *tthread,
				  struct probepoint *probepoint);

/*
 * Runs and cleans up any simple actions that should happen at this
 * probepoint.  We run all simple actions after the probe prehandlers
 * have been run, but before the singlestep of the probepoint happens.
 */
static int handle_simple_actions(struct target *target,
				 struct target_thread *tthread,
				 struct probepoint *probepoint) {
    struct action *action;
    struct action *taction;
    int retval = 0;
    int rc;
    unsigned long rcb;

    list_for_each_entry_safe(action,taction,&probepoint->simple_actions,action) {
	rc = 0;

	if (!probe_enabled(action->probe)) {
	    vdebug(3,LA_PROBE,LF_ACTION,"skipping disabled probe at ");
	    LOGDUMPPROBEPOINT(3,LA_PROBE,LF_ACTION,probepoint);
	    vdebugc(3,LA_PROBE,LF_ACTION,"\n");
	    continue;
	}

	if (action->type == ACTION_REGMOD) {
	    rc = target_write_reg(tthread->target,tthread->tid,
				  action->detail.regmod.regnum,
				  action->detail.regmod.regval);
	    if (rc)
		vwarn("could not write reg %"PRIiREG"!\n",
		      action->detail.regmod.regnum);
	    else 
		vdebug(4,LA_PROBE,LF_ACTION,"wrote 0x%"PRIxREGVAL" to %"PRIiREG"\n",
		       action->detail.regmod.regval,action->detail.regmod.regnum);
	}
	else if (action->type == ACTION_MEMMOD) {
	    rcb = target_write_addr(tthread->target,
				    action->detail.memmod.destaddr,
				    action->detail.memmod.len,
				    (unsigned char *)action->detail.memmod.data);
	    if (rcb != action->detail.memmod.len) {
		vwarn("could not write %d bytes to 0x%"PRIxADDR"!\n",
		      action->detail.memmod.len,action->detail.memmod.destaddr);
		rc = 1;
	    }
	    else
		vdebug(4,LA_PROBE,LF_ACTION,"wrote %d bytes to 0x%"PRIxADDR"\n",
		       action->detail.memmod.len,action->detail.memmod.destaddr);
	}
	else {
	    verror("BUG: unsupported action type %d -- not doing it!\n",
		   action->type);
	    rc = 1;
	}

	if (rc) {
	    ++retval;
	    if (action->handler)
		action->handler(action,tthread,action->probe,probepoint,
				MSG_FAILURE,0,action->handler_data);
	}
	else if (action->handler) 
	    action->handler(action,tthread,action->probe,probepoint,
			    MSG_SUCCESS,0,action->handler_data);


	/* cleanup oneshot actions! */
	action_finish_handling(action,NULL);
    }

    return retval;
}
/*
 * Returns: <0 on error; 0 if not stepping; 1 if stepping.
 */
static int setup_single_step_actions(struct target *target,
				     struct target_thread *tthread,
				     struct probepoint *probepoint,
				     int isbp,int stepping) {
    tid_t tid = tthread->tid;
    struct action *action, *taction;

    /*
     * If we need to do any single step actions, set that up if
     * handle_complex_actions didn't already.  This should be pretty
     * rare, but if some injected code doesn't need single stepping
     * because it "notifies" when it's done via breakpoint, we can
     * save a lot of debug interrupts.
     */
    if (list_empty(&probepoint->ss_actions)) 
	return 0;

    /*
     * If the action was not boosted (i.e. is running at the
     * probepoint), and we're not already single stepping, we need
     * to tell the single step routine that we're stepping at a
     * breakpoint location.
     */
    if (!stepping) {
	vdebug(4,LA_PROBE,LF_PROBEPOINT,"setting up single step actions for ");
	LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");

	if (probepoint->style == PROBEPOINT_HW
	    && isbp
	    && !target->nodisablehwbponss) {
	    /*
	     * We need to disable the hw breakpoint before we single
	     * step because the target can't do it.
	     */
	    target_disable_hw_breakpoint(target,probepoint->thread->tid,probepoint->debugregnum);
	    probepoint->debugregdisabled = 1;
	}

	if (target_singlestep(target,tid,isbp) < 0) {
	    verror("could not keep single stepping target!\n");

	    if (probepoint->style == PROBEPOINT_HW
		&& isbp
		&& !target->nodisablehwbponss) {
		/*
		 * Reenable the hw breakpoint we just disabled.
		 */
		target_enable_hw_breakpoint(target,probepoint->thread->tid,probepoint->debugregnum);
		probepoint->debugregdisabled = 0;
	    }

	    if (target_singlestep_end(target,tid))
		verror("could not stop single stepping target"
		       " after failed sstep!\n");

	    /*
	     * All we can really do is notify all the single step
	     * actions that we had an error, and nuke them, and keep
	     * going.
	     */
	    list_for_each_entry_safe(action,taction,&probepoint->ss_actions,
				     action) {
		if (action->handler) 
		    action->handler(action,tthread,action->probe,probepoint,
				    MSG_FAILURE,0,action->handler_data);

		action_finish_handling(action,NULL);
	    }

	    stepping = -1;
	}
	else {
	    vdebug(4,LA_PROBE,LF_PROBEPOINT,"sstep command succeeded for ");
	    LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	    vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");

	    stepping = 1;
	}
    }
    else {
	vdebug(4,LA_PROBE,LF_PROBEPOINT,
	       "already stepping; building tacs for single step actions for ");
	LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");
    }

    /* 
     * If single step init succeeded, let the ss handler take over.
     * Also, take a reference to all the ss_actions actions and
     * place contexts for them on our thread's list.
     */
    if (stepping == 1) {
	list_for_each_entry_safe(action,taction,&probepoint->ss_actions,action) {
	    struct thread_action_context *tac = \
		(struct thread_action_context *)calloc(1,sizeof(*tac));
	    tac->action = action;
	    RHOLD(action,tac);
	    tac->stepped = 0;
	    INIT_LIST_HEAD(&tac->tac);

	    list_add_tail(&tac->tac,&tthread->ss_actions);
	}
    }

    return stepping;
}

static int run_post_handlers(struct target *target,
			     struct target_thread *tthread,
			     struct probepoint *probepoint) {
    int rc;
    int noreinject = 0;
    struct probe *probe;
    int i = 0;

    /*
     * Run post-handlers
     */
    list_for_each_entry(probe,&probepoint->probes,probe) {
	++i;
	if (probe->enabled) {
	    if (probe->post_handler) {
		vdebug(4,LA_PROBE,LF_PROBEPOINT,"running post handler at ");
		LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
		vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");

		rc = probe->post_handler(probe,probe->handler_data,probe);
		if (rc == RESULT_ERROR) 
		    probe_disable(probe);
		else if (rc == RESULT_ABORT) 
		    /* don't reinject the probe! */
		    noreinject = 1;
	    }
	    else if (0 && probe->sinks) {
		vdebug(4,LA_PROBE,LF_PROBEPOINT,
		       "running default probe sink post_handler at ");
		LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
		vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");

		probe_do_sink_post_handlers(probe,NULL,probe);
	    }
	}
    }

    if (i > 1 && noreinject) {
	vwarn("cannot skip reinjection of breakpoint because multiple probes present!\n");
	noreinject = 0;
    }

    return noreinject;
}

void probepoint_release(struct target *target,struct target_thread *tthread,
			struct probepoint *probepoint) {
    /* Only release if we owned it! */
    if (probepoint->tpc == tthread->tpc)
	probepoint->tpc = NULL;
}

struct thread_probepoint_context *probepoint_hold(struct target *target,
						  struct target_thread *tthread,
						  struct probepoint *probepoint,
						  struct thread_probepoint_context *tpc) {
    if (probepoint->style == PROBEPOINT_SW
	&& probepoint->tpc != NULL
	&& probepoint->tpc->thread != tthread)
	return probepoint->tpc;

    probepoint->tpc = tpc;
    return tpc;
}

int probepoint_pause_handling(struct target *target,
			      struct target_thread *tthread,
			      struct probepoint *probepoint,
			      thread_resumeat_t resumeat) {
    if (target->threadctl) {
	vdebug(5,LA_PROBE,LF_PROBEPOINT,
	       "pausing thread %"PRIiTID" (%d) until thread %"PRIiTID" finishes"
	       " handling ",tthread->tid,resumeat,probepoint->tpc->thread->tid);
	LOGDUMPPROBEPOINT_NL(3,LA_PROBE,LF_PROBEPOINT,probepoint);

	tthread->resumeat = resumeat;
	return 0;
    }

    return -1;
}

static struct thread_probepoint_context *tpc_new(struct target_thread *tthread,
						 struct probepoint *probepoint) {
    struct thread_probepoint_context *tpc = (struct thread_probepoint_context *) \
	calloc(1,sizeof(*tpc));
    tpc->thread = tthread;
    tpc->probepoint = probepoint;

    return tpc;
}

void tpc_free(struct thread_probepoint_context *tpc) {
    free(tpc);
}

/*
 * We will not run a single step of the real instruction in two cases.
 * First, if any complex action obviated the real instruction, we skip
 * the real instruction, and do nothing to EIP.  We just run
 * post-handlers, if there are any.
 * Second, if there are no post-handlers
 *
 * Return <0 on error; 0 if we skipped a sstep because the action
 * obviated it; 1 if we setup a single step; 2 if we "paused" the thread
 * because we couldn't hold the probepoint to do the single step.
 */
static int setup_post_single_step(struct target *target,
				  struct target_thread *tthread,
				  struct probepoint *probepoint) {
    int doit = 0;
    struct probe *probe;
    tid_t tid = tthread->tid;
    struct thread_probepoint_context *tpc = tthread->tpc;
    int noreinject;
    struct thread_probepoint_context *htpc;

    /*
     * We're now handling post stuff at the breakpoint.
     *
     * But, note that we don't change state to POSTHANDLING until we
     * know we're going to single step the real instruction.  If we
     * don't do that, we don't change -- and we only adjust the state of
     * the probepoint if we own the probepoint.  Otherwise we have to
     * pause this thread until we do own it.
     */

    if (tpc->action_obviated_orig) {
	vdebug(4,LA_PROBE,LF_PROBEPOINT,"skipping sstep due to action obviation of ");
	LOGDUMPPROBEPOINT_NL(4,LA_PROBE,LF_PROBEPOINT,probepoint);

	/* Just run the posthandlers; don't single step the orig. */
	noreinject = run_post_handlers(target,tthread,probepoint);

	if (!noreinject) {
	    /*
	     * If the action was boosted, we have nothing to replace.
	     * If it wasn't, when we removed it, we put the BP back in.
	     * So don't do anything here, because if the action was
	     * boosted, some other thread might hold the probepoint!
	     *
	     * But, if we had disabled a hw breakpoint, reenable it!
	     */
	    if (probepoint->style == PROBEPOINT_HW 
		&& probepoint->debugregdisabled) {
		/*
		 * Enable hardware bp here!
		 */
		target_enable_hw_breakpoint(target,probepoint->thread->tid,probepoint->debugregnum);
		probepoint->debugregdisabled = 0;

		probepoint->state = PROBE_BP_SET;
	    }
	}
	else {
	    free(probepoint->breakpoint_orig_mem);
	    probepoint->breakpoint_orig_mem = NULL;
	    __probepoint_remove(probepoint,0,0);
	}

	/*
	 * Only release our hold on the probepoint if we actually held
	 * it; if we had been running a boosted action, we might not
	 * hold the probepoint.
	 */
	probepoint_release(target,tthread,probepoint);

	return 0;
    }

    /*
     * Now that we've handled the case where an action might have
     * replaced the real instruction, we have to figure out if we should
     * single step the original instruction or not.
     *
     * If we're hardware and there are no enabled probes with
     * post-handlers, single step; otherwise, just proceed.  If we're
     * software, *always* single step after replacing the original
     * instruction.
     */
    if (probepoint->style == PROBEPOINT_HW) {
	list_for_each_entry(probe,&probepoint->probes,probe) {
	    if (probe->enabled && (probe->post_handler || probe->sinks)) {
		doit = 1;
		break;
	    }
	}

	/*
	 * XXX: for now, always force single step even for HW
	 * breakpoints, since the Xen VM backend will get stuck in
	 * an infinite loop at the breakpoint location.
	 *
	 * For whatever reason, this does not happen for the Linux
	 * userspace process target.  Until we know why, just always
	 * single step here.
	 */
	doit = 1;

	if (!doit) {
	    probepoint->state = PROBE_BP_SET;

	    vdebug(4,LA_PROBE,LF_PROBEPOINT,"skipping sstep for HW ");
	    LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	    vdebugc(4,LA_PROBE,LF_PROBEPOINT,"; no post handlers\n");

	    /*
	     * Don't run posthandlers because we haven't done the
	     * breakpointed instruction!  Well, this is not quite true
	     * for watchpoints, but...
	     */
	}
	else {
	    /* We already own the probepoint because it's hardware. */
	    probepoint->state = PROBE_BP_POSTHANDLING;
	}
    }
    /*
     * If we're software, replace the original.
     */
    else if (probepoint->style == PROBEPOINT_SW) {
	/* Restore the original instruction. */
	vdebug(4,LA_PROBE,LF_PROBEPOINT,"restoring orig instr for SW ");
	LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");

	doit = 1;

	/*
	 * Grab hold of the probepoint, since we might have run boosted
	 * instructions in the past.  If we can't grab the probepoint,
	 * we have to pause this thread until we can grab it.
	 */
	if ((htpc = probepoint_hold(target,tthread,probepoint,tpc)) != tpc) {
	    if (probepoint_pause_handling(target,tthread,probepoint,
					  THREAD_RESUMEAT_SSR)) {
		verror("thread %"PRIiTID" hit ss when thread %"PRIiTID" already"
		       " handling it; target failed to ctl thread!\n",
		       tthread->tid,htpc->thread->tid);
		/*
		 * There literally is nothing we can do -- we cannot
		 * handle this breakpoint interrupt.
		 */
		return -1;
	    }
	    else 
		return 2;
	}
	else {
	    /*
	     * If we're in BPMODE_STRICT, we have to pause all the other
	     * threads.
	     */
	    if (target->spec->bpmode == THREAD_BPMODE_STRICT) {
		if (target_pause(target)) {
		    vwarn("could not pause the target for blocking thread"
			  " %"PRIiTID"!\n",tthread->tid);
		    return -1;
		}
		target->blocking_thread = tthread;
	    }

	    if (target_write_addr(target,probepoint->addr,
				  probepoint->breakpoint_orig_mem_len,
				  probepoint->breakpoint_orig_mem)	\
		!= probepoint->breakpoint_orig_mem_len) {
		verror("could not restore orig code that breakpoint"
		       " replaced; assuming breakpoint is left in place and"
		       " skipping single step, but badness will ensue!");

		if (target->blocking_thread == tthread)
		    target->blocking_thread = NULL;
		probepoint->state = PROBE_BP_SET;
		probepoint_release(target,tthread,probepoint);
		tpc_free(tthread->tpc);
		tthread->tpc = (struct thread_probepoint_context *) \
		    array_list_remove(tthread->tpc_stack);

		return -1;
	    }
	    else {
		/* We already own it. */
		probepoint->state = PROBE_BP_POSTHANDLING;
	    }
	}
    }

    if (!doit) {
	/*
	 * Only release our hold on the probepoint if we actually held
	 * it; if we had been running a boosted action, we might not
	 * hold the probepoint.
	 */
	if (probepoint->tpc == tthread->tpc) {
	    probepoint->state = PROBE_BP_SET;
	    probepoint_release(target,tthread,probepoint);
	}

	return 0;
    }

    /* 
     * Command the single step to happen.  We hold the probepoint now,
     * so we can do anything.
     */
    vdebug(4,LA_PROBE,LF_PROBEPOINT,"doing sstep for ");
    LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
    vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");

    if (probepoint->style == PROBEPOINT_HW && !target->nodisablehwbponss) {
	/*
	 * We need to disable the hw breakpoint before we single
	 * step because the target can't do it.
	 */
	target_disable_hw_breakpoint(target,probepoint->thread->tid,probepoint->debugregnum);
	probepoint->debugregdisabled = 1;
    }

    if (target_singlestep(target,tid,1) < 0) {
	verror("could not single step target after BP!\n");

	if (target_singlestep_end(target,tid))
	    verror("could not stop single stepping target"
		   " after failed sstep for breakpoint!\n");

	if (probepoint->style == PROBEPOINT_HW && !target->nodisablehwbponss) {
	    /*
	     * Reenable the hw breakpoint we just disabled.
	     */
	    target_enable_hw_breakpoint(target,probepoint->thread->tid,probepoint->debugregnum);
	    probepoint->debugregdisabled = 0;
	}

	if (probepoint->style != PROBEPOINT_HW) {
	    if (target_write_addr(target,probepoint->addr,
				  probepoint->breakpoint_orig_mem_len,
				  probepoint->breakpoint_orig_mem)	\
		!= probepoint->breakpoint_orig_mem_len) {
		verror("could not restore orig code that breakpoint"
		       " replaced; assuming breakpoint is left in place and"
		       " skipping single step, but badness will ensue!");
	    }
	}

	/*
	 * If we were supposed to single step, and it failed,
	 * the best we can do is act like the BP is still set.
	 */
	if (target->blocking_thread == tthread)
	    target->blocking_thread = NULL;
	probepoint->state = PROBE_BP_SET;
	probepoint_release(target,tthread,probepoint);
	tpc_free(tthread->tpc);
	tthread->tpc = (struct thread_probepoint_context *) \
	    array_list_remove(tthread->tpc_stack);

	return -1;
    }
    else {
	/* 
	 * If single step init succeeded, let the ss handler take
	 * over.
	 *
	 * Don't call target_resume after a successful target_singlestep.
	 */
	vdebug(4,LA_PROBE,LF_PROBEPOINT,"sstep command succeeded for ");
	LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");

	if (probepoint->can_switch_context) {
	    vdebug(4,LA_PROBE,LF_PROBEPOINT,"can_switch_context (%d) -- ",
		   probepoint->can_switch_context);
	    LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	    vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");
	}

	return 1;
    }
}

/*
 * In many ways, the goal of this function is to figure out if we need
 * to do a single step after the breakpoint.  There's lots of cases.
 *   * If BP is SW:
 *      - if any actions obviate (replace) the original instruction, do
 *        not single step, just reset the state to BP_SET (AND re-insert
 *        the BP right away) -- unless the
 *        action requires one or more single steps; if so, do them.
 *      - otherwise, replace the original instruction and set state to
 *        BP_HANDLING and single step
 *      - 
 *   * If BP is HW:
 *      - if any actions obviate (replace) the original instruction, do
 *        not single step, just reset the state to BP_SET -- unless the
 *        action requires one or more single steps; if so, do them.
 *      - otherwise, if no enabled probes have post handlers, do not
 *        single step, just reset the state to BP_SET.
 *      - otherwise, set state to BP_HANDLING and single step.
 *
 * NOTE: if we try to single step, we always disable hardware
 * breakpoints first.  If the single step init fails, we re-enable
 * them.  HW breakpoints are re-enabled in the ss handler below once
 * we're sure we don't need to do any more single steps.
 */
result_t probepoint_bp_handler(struct target *target,
			       struct target_thread *tthread,
			       struct probepoint *probepoint,
			       int was_stepping) {
    struct probe *probe;
    REGVAL ipval;
    int doit = 0;
    int rc;
    tid_t tid = tthread->tid;
    struct thread_probepoint_context *tpc, *htpc;
    int stepping = 0;
    struct action *action;
    struct thread_action_context *tac,*ttac;

    vdebug(5,LA_PROBE,LF_PROBEPOINT,"handling bp at ");
    LOGDUMPPROBEPOINT(5,LA_PROBE,LF_PROBEPOINT,probepoint);
    vdebugc(5,LA_PROBE,LF_PROBEPOINT,"\n");

    /*
     * If the thread is already handling this probepoint, the cause is
     * almost certainly that some action we ran recursed, running some
     * code that triggered the breakpoint again.
     *
     * We keep trying to handle it if we can below...
     */
    if (tthread->tpc && tthread->tpc->probepoint == probepoint)
	vwarn("existing thread probepoint same as bp probepoint;"
	      " BUG or recursion due to action?\n");

    /*
     * If we were single stepping when we hit the breakpoint, and we hit
     * a hardware breakpoint, we need to fire the single step action
     * handlers off.  If it's a software breakpoint, the trap after the
     * last instruction was allowed to happen before the breakpoint was
     * executed.  But with hardware breakpoints, the single step trap
     * for the instruction preceding the breakpoint, and the breakpoint,
     * seem to happen in the same interrupt.
     */
    if (probepoint->style == PROBEPOINT_HW 
	&& was_stepping 
	&& !list_empty(&tthread->ss_actions)) {
	list_for_each_entry_safe(tac,ttac,&tthread->ss_actions,tac) {
	    action = tac->action;
	    ++tac->stepped;

	    if (action->steps == -2 
		|| (action->steps > 0 && tac->stepped >= action->steps)) {
		if (action->handler)
		    action->handler(action,tthread,action->probe,action->probe->probepoint,
				    MSG_SUCCESS,tac->stepped,action->handler_data);

		action_finish_handling(action,tac);

		list_del(&tac->tac);
		free(tac);
	    }
	    else {
		if (action->handler) 
		    action->handler(action,tthread,action->probe,action->probe->probepoint,
				    MSG_STEPPING_AT_BP,tac->stepped,
				    action->handler_data);
	    }
	}

	if (list_empty(&tthread->ss_actions)) 
	    was_stepping = 0;
    }

    /*
     * Push a new context for handling this probepoint.
     */
    tpc = tpc_new(tthread,probepoint);
    if (tthread->tpc) {
	array_list_append(tthread->tpc_stack,tthread->tpc);

	vdebug(3,LA_PROBE,LF_PROBEPOINT,
	       "already handling %d probepoints in thread %d; most recent"
	       " (tpc %p) was ",
	       array_list_len(tthread->tpc_stack),tthread->tid,tthread->tpc);
	LOGDUMPPROBEPOINT_NL(3,LA_PROBE,LF_PROBEPOINT,tthread->tpc->probepoint);
    }
    tthread->tpc = tpc;

    /*
     * Check: do we need to hold the probepoint?  That depends on:
     *  - is the probepoint software?  hardware probepoints can always
     *    be held, although which tpc the thread is handling may change
     *    (i.e. if we are recursing trhough the same breakpoint again)
     *  - do we have unboosted complex actions?
     *  - do we have need to run the original instruction at the
     *    probepoint?
     * But we can't even answer the second one until we know that the
     * pre-handlers haven't added any actions (which they must be able
     * to do), so we have no choice -- we must hold the breakpoint
     * before handling it at all.  We may be able to release it sooner
     * than we think at the moment, but we can't know.  The only time we
     * can just automatically hold the probepoint is if 
     */
    if ((htpc = probepoint_hold(target,tthread,probepoint,tpc)) != tpc) {
	/*
	 * If the BP is in some unset state, it might be being handled
	 * for another thread.  If not, we have a bug, because the state
	 * is wrong, but we obviously hit the BP so it *is* set and we
	 * just "handle" it.
	 *
	 * If it *is* being handled by another thread -- this could only
	 * have happened if this thread hit the BP at about the same
	 * time another thread did, but if we have scheduled the single
	 * step for the other thread and executed it -- and then the
	 * next time the target checked for debug interrupts, it checked
	 * this thread first instead of the single-stepping thread.
	 *
	 * In this case, if we have thread control, we pause this thread
	 * until we can handle the breakpoint (i.e., until nothing else
	 * is).  Of course, if we have thread control, we assume the
	 * thread is already paused (it's at a debug interrupt, after
	 * all); we just have to be careful not to unpause it until we
	 * have handled its interrupt.
	 *
	 * If we don't have thread control, there's really nothing we
	 * can do.  Sometimes loose mode sucks :).
	 */
	if (probepoint->state != PROBE_BP_SET) {
	    if (!probepoint->tpc) {
		verror("probepoint state is not BP_SET; BUG!\n");

		probepoint->state = PROBE_BP_SET;
	    }
	    else if (probepoint_pause_handling(target,tthread,probepoint,
					       THREAD_RESUMEAT_BPH)) {
		verror("thread %"PRIiTID" hit bp when thread %"PRIiTID" already"
		       " handling it; target could not pause thread!\n",
		       tthread->tid,probepoint->tpc->thread->tid);
		/*
		 * There literally is nothing we can do -- we cannot
		 * handle this breakpoint interrupt.
		 */
		return RESULT_ERROR;
	    }
	    else 
		return RESULT_SUCCESS;
	}
    }

    /*
     * We own this probepoint now.  BUT, we might still have to pause
     * other threads in the target if we have to adjust the probepoint.
     */

    /* We move into the HANDLING state while we run the pre-handlers. */
    probepoint->state = PROBE_BP_PREHANDLING;

    /*
     * Prepare for handling: save the original ip value in case
     * something bad happens during the pre-handlers.
     */
    errno = 0;
    ipval = target_read_reg(target,tid,target->ipregno);
    if (probepoint->style == PROBEPOINT_SW && errno) {
	verror("could not read EIP to reset it for SW probepoint; skipping!");
	probepoint->state = PROBE_BP_SET;
	probepoint_release(target,tthread,probepoint);
	tpc_free(tthread->tpc);
	tthread->tpc = (struct thread_probepoint_context *) \
	    array_list_remove(tthread->tpc_stack);
	return RESULT_ERROR;
    }

    vdebug(5,LA_PROBE,LF_PROBEPOINT,"EIP is 0x%"PRIxREGVAL" at ",ipval);
    LOGDUMPPROBEPOINT(5,LA_PROBE,LF_PROBEPOINT,probepoint);
    vdebugc(5,LA_PROBE,LF_PROBEPOINT,"\n");


    /* If SW bp, reset EIP and write it back *now*, because it's easy
     * here, and then if the user tries to read it, it's "correct".
     */
    if (probepoint->style == PROBEPOINT_SW) {
	ipval -= target->breakpoint_instrs_len;
	errno = 0;
	target_write_reg(target,tid,target->ipregno,ipval);
	if (errno) {
	    verror("could not reset EIP before pre handlers; skipping!\n");
	    probepoint->state = PROBE_BP_SET;
	    probepoint_release(target,tthread,probepoint);
	    tpc_free(tthread->tpc);
	    tthread->tpc = (struct thread_probepoint_context *) \
		array_list_remove(tthread->tpc_stack);
	    return RESULT_ERROR;
	}

	vdebug(4,LA_PROBE,LF_PROBEPOINT,"reset EIP to 0x%"PRIxREGVAL" for SW ",ipval);
	LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");
    }

    /*
     * Run pre-handlers if we have encountered our breakpoint for the
     * first time on this pass (which means we should not have an action
     * set!)
     */
    list_for_each_entry(probe,&probepoint->probes,probe) {
	if (probe->enabled) {
	    if (probe->pre_handler) {
		vdebug(4,LA_PROBE,LF_PROBEPOINT,"running pre handler at ");
		LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
		vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");

		rc = probe->pre_handler(probe,probe->handler_data,probe);
		if (rc == RESULT_ERROR) 
		    probe_disable(probe);
	    }
	    else if (0 && probe->sinks) {
		vdebug(4,LA_PROBE,LF_PROBEPOINT,
		       "running default probe sink pre_handler at ");
		LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
		vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");
		probe_do_sink_pre_handlers(probe,NULL,probe);
	    }
	    doit = 1;
	}
    }

    /* Restore ip register if we ran a handler. */
    if (doit) {
	errno = 0;
	target_write_reg(target,tid,target->ipregno,ipval);
	if (errno) {
	    verror("could not reset EIP after pre handlers!\n");
	    probepoint->state = PROBE_BP_SET;
	    probepoint_release(target,tthread,probepoint);
	    tpc_free(tthread->tpc);
	    tthread->tpc = (struct thread_probepoint_context *) \
		array_list_remove(tthread->tpc_stack);
	    return RESULT_ERROR;
	}
        
	vdebug(9,LA_PROBE,LF_PROBEPOINT,
	       "ip 0x%"PRIxREGVAL" restored after pre handlers at ",ipval);
	LOGDUMPPROBEPOINT(9,LA_PROBE,LF_PROBEPOINT,probepoint);
	vdebugc(9,LA_PROBE,LF_PROBEPOINT,"\n");
    }

    /* Now we're handling actions. */
    probepoint->state = PROBE_BP_ACTIONHANDLING;

    /*
     * Run the simple actions now.
     */
    if ((rc = handle_simple_actions(target,tthread,probepoint))) 
	vwarn("failed to handle %d simple actions!\n",rc);

    /*
     * Set up complex actions.  The output of the setup is what code we
     * need to place at the breakpoint site; the min single steps before
     * we can replace that code with 1) the original code, if the tmp
     * code does not replace the orig; or 2) the breakpoint again, if
     * the tmp code *does* replace the orig.  Or, it could be nothing.
     *
     * (If the complex action requires more than one single step, we
     * cannot support it unless the target is capable of pausing all
     * other threads (i.e., ensuring that the current thread cannot be
     * preempted).  We need this because we can basically assume that
     * the first single step will not be "interrupted" after a
     * breakpoint unless an interrupt happened to fire at the same time
     * as the breakpoint.  But, we can't assume that N single steps
     * won't be interrupted; if they are, the probepoint is storing
     * per-thread context, and it could get messed up bad.  Plus, the
     * probepoint might have arbitrary code at its location, instead of
     * the breakpoint or original instruction.)
     *
     * If the output is nothing (i.e., no complex actions), we decide if
     * we need to single step (always do for SW; if HW, and no probes
     * are enabled, or none of the enalbed probes have posthandlers, we
     * can skip the SW breakpoint; OR ALSO do if we have one or more
     * single step actions).
     *
     * Then in the ss handler, we have to check what state we're in.
     * First, if we are called with no probepoint, we must be sstep'ing
     * for an sstep action(s).  Otherwise, if probepoint->action is set,
     * we must be sstep'ing a complex action (or on behalf of it).
     * Otherwise, we must just be sstep'ing the original instr under the
     * breakpoint.
     *
     * In the first case, just hanlde the ss_actions list.
     *
     * In the second case, continue sstep'ing if the action requires it;
     * otherwise, either setup another complex action, or replace the
     * underlying code if the action didn't obviate it -- and single
     * step the orig code.  Then put the breakpoint back in.
     *
     * In the third case, just put the breakpoint back in.
     *
     * In all cases, leave single step enabled if there are still
     * ss_actions running for the thread.
     */
    if ((stepping = handle_complex_actions(target,tthread,probepoint)) < 0) 
	vwarn("failed to handle %d complex actions!\n",rc);

    /*
     * If there is a complex action, just setup single step actions (and
     * we might already be single stepping for the complex action).
     * handle_complex_actions also paused all other threads if we needed to.
     */
    if (tpc->tac.action) {
	vdebug(4,LA_PROBE,LF_PROBEPOINT,"setup complex action for ");
	LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");

	int _isbp = 0;
	if (!tpc->tac.action->boosted)
	    _isbp = 1;

	rc = setup_single_step_actions(target,tthread,probepoint,_isbp,stepping);
	if (rc == 1)
	    rc = 0;
    }
    /*
     * Otherwise, if we did not perform a complex action, or if the
     * complex action did not require any single steps, figure out if we
     * should re-execute the original instructions -- and do we boost
     * them or replace them at the breakpoint and single step it.
     */
    else {
	tpc->did_orig_instr = 1;

	vdebug(4,LA_PROBE,LF_PROBEPOINT,"setting up post handling single step for ");
	LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");
	rc = setup_post_single_step(target,tthread,probepoint);

	if (rc == 0) {
	    /*
	     * No single step scheduled, but no error, so we're done
	     * handling the probepoint in this thread; pop the stack.
	     */
	    if (target->blocking_thread == tthread)
		target->blocking_thread = NULL;
	    probepoint_release(target,tthread,probepoint);
	    tpc_free(tthread->tpc);
	    tthread->tpc = (struct thread_probepoint_context *) \
		array_list_remove(tthread->tpc_stack);

	    vdebug(5,LA_PROBE,LF_PROBEPOINT,
		   "thread %"PRIiTID" skipped orig instruction; clearing tpc!\n",
		   tthread->tid);

	    /*
	     * We need to setup single step actions to happen because we
	     * are not stepping yet, and we might need to.
	     */
	    rc = setup_single_step_actions(target,tthread,probepoint,1,0);
	    if (rc == 1) {
		/*
		 * Don't call target_resume; we've already called
		 * target_singlestep.
		 */
		return RESULT_SUCCESS;
	    }
	}
	else if (rc == 1) {
	    /*
	     * If we need to keep single stepping, just let that happen
	     * -- it's already been set up (or might have been setup in
	     * setup_post_single_step).
	     *
	     * We need to setup single step actions to happen even if
	     * we're already stepping (bookkeeping).
	     */
	    rc = setup_single_step_actions(target,tthread,probepoint,1,1);

	    /*
	     * Don't call target_resume; we've already called
	     * target_singlestep.
	     */
	    return RESULT_SUCCESS;
	}
	else if (rc == 2) {
	    /* The thread blocked because it could not hold the probepoint. */
	    vdebug(5,LA_PROBE,LF_PROBEPOINT,
		   "thread %"PRIiTID" blocked before single step; thread"
		   " %"PRIiTID" owned probepoint -- BUG!!!\n",
		   tthread->tid,probepoint->tpc->thread->tid);
	}
	else if (rc < 0) {
	    verror("could not setup single step; badness will probably ensue!\n");
	}
    }

    return RESULT_SUCCESS;
}

/*
 * This function handles single step events.  It broadly handles a few
 * cases.  First, are there pending single step actions; if so, stay in
 * single step mode after we're done.  Second, try to handle any complex
 * actions that might be needing single steps, if there are, let that
 * keep going.  Finally, if we're done with any complex actions, and we
 * still haven't run the original instruction (and if none of hte
 * complex actions obviated (replaced) the original one), we run the
 * original instruction via single step (if necessary -- it might not be
 * necessary if we don't have posthandlers and if the breakpoint is hw,
 * or if the orig instruction was boostable.
 */
result_t probepoint_ss_handler(struct target *target,
			       struct target_thread *tthread,
			       struct probepoint *probepoint) {
    struct thread_action_context *tac,*ttac;
    struct action *action;
    tid_t tid = tthread->tid;
    int rc;
    int handled_ss_actions = 0;
    int keep_stepping = 0;
    struct thread_probepoint_context *tpc = tthread->tpc;
    int noreinject;
    handler_msg_t amsg;
    struct probepoint *aprobepoint;

    /*
     * If we had to disable a hw breakpoint before we single stepped it,
     * reenable it now.  If it's a hardware breakpoint, we own it, so
     * that's why we don't check that.
     */
    if (probepoint
	&& probepoint->style == PROBEPOINT_HW
	&& probepoint->debugregdisabled
	&& !target->nodisablehwbponss) {
	/*
	 * Reenable the hw breakpoint we just disabled.
	 */
	target_enable_hw_breakpoint(target,probepoint->thread->tid,probepoint->debugregnum);
	probepoint->debugregdisabled = 0;
    }

    /*
     * First, if there is no probepoint (or if there is and we have
     * single step actions pending) and if this thread has pending
     * ss_actions.  If one or the other, go through that list, increment
     * the counts, notify the handlers, and remove any ss_actions that
     * are done.  If all are done, end singlestep mode and resume.
     * Otherwise, stay in single step mode.
     */
    if (!list_empty(&tthread->ss_actions)) {
	handled_ss_actions = 1;

	/*
	 * If this address is an enalbed breakpiont, we need to send
	 * MSG_STEPPING_AT_BP instead.  This covers the software
	 * breakpiont case; for the hardware one, see bp_handler.
	 */
	amsg = MSG_STEPPING;
	if ((aprobepoint = \
	     probepoint_lookup(target,tthread,
			       target_read_reg(target,tthread->tid,target->ipregno))) 
	    && aprobepoint->state != PROBE_DISABLED)
	    amsg = MSG_STEPPING_AT_BP;

	list_for_each_entry_safe(tac,ttac,&tthread->ss_actions,tac) {
	    action = tac->action;
	    ++tac->stepped;

	    if (action->steps < 0 || tac->stepped < action->steps) {
		if (action->handler) 
		    action->handler(action,tthread,action->probe,action->probe->probepoint,
				    amsg,tac->stepped,action->handler_data);
	    }
	    else {
		if (action->handler) 
		    action->handler(action,tthread,action->probe,action->probe->probepoint,
				    MSG_SUCCESS,tac->stepped,action->handler_data);

		action_finish_handling(action,tac);

		list_del(&tac->tac);
		free(tac);
	    }
	}

	if (!list_empty(&tthread->ss_actions)) 
	    keep_stepping = 1;
    }
    /*
     * If there is no probepoint, we return to the caller without
     * unpausing the target.
     */
    else if (!probepoint) {
	vwarn("thread %"PRIiTID" unexpected single step!\n",tthread->tid);
	return RESULT_ERROR;
    }

    /*
     * If we're done handling actions and the post single step of the
     * original instruction, AND if we were the owners of the
     * probepoint, nuke the tpc state!
     *
     * BUT, we have to check if we should keep single stepping for
     * pending single step actions.
     */
    if (probepoint 
	&& probepoint->tpc == tpc
	&& probepoint->state == PROBE_BP_POSTHANDLING 
	&& tpc->did_orig_instr) {
	noreinject = run_post_handlers(target,tthread,probepoint);

	if (!noreinject) {
	    if (probepoint->style == PROBEPOINT_SW) {
		/* Re-inject a breakpoint for the next round */
		if (target_write_addr(target,probepoint->addr,
				      target->breakpoint_instrs_len,
				      target->breakpoint_instrs)	\
		    != target->breakpoint_instrs_len) {
		    verror("could not write breakpoint instrs for bp re-insert, disabling!\n");
		    probepoint->state = PROBE_DISABLED;
		    free(probepoint->breakpoint_orig_mem);
		    return RESULT_ERROR;
		}
		else 
		    probepoint->state = PROBE_BP_SET;
	    }
	    else if (probepoint->debugregdisabled) {
		/*
		 * Enable hardware bp here!
		 */
		target_enable_hw_breakpoint(target,probepoint->thread->tid,probepoint->debugregnum);
		probepoint->debugregdisabled = 0;

		probepoint->state = PROBE_BP_SET;
	    }
	    else {
		probepoint->state = PROBE_BP_SET;
	    }
	}
	else {
	    free(probepoint->breakpoint_orig_mem);
	    probepoint->breakpoint_orig_mem = NULL;
	    __probepoint_remove(probepoint,0,0);
	}

	if (target_singlestep_end(target,tid))
	    verror("could not stop single stepping target"
		   " after failed sstep!\n");

	if (target->blocking_thread == tthread)
	    target->blocking_thread = NULL;
	probepoint_release(target,tthread,probepoint);
	tpc_free(tthread->tpc);
	tthread->tpc = (struct thread_probepoint_context *) \
	    array_list_remove(tthread->tpc_stack);
	tpc = NULL;

	vdebug(5,LA_PROBE,LF_PROBEPOINT,
	       "thread %"PRIiTID" ran orig instruction; cleared tpc!\n",
	       tthread->tid);

	if (keep_stepping)
	    goto keep_stepping;
	else 
	    /* We're done with this, and don't want anything else below. */
	    return RESULT_SUCCESS;
    }

    /* 
     * Handle complex actions.  This function does everything it might
     * need; if it leaves an action in tpc->tac.action, we just call
     * target_resume and trust that it did all the setup it needs.
     */
    if (tpc) 
	rc = handle_complex_actions(target,tthread,probepoint);

    /*
     * NOTE: after this giant if stmt, the default return case is
     * RESULT_SUCCESS, unless another return stmt occurs.
     */

    if (tpc && tpc->tac.action) {
	/*
	 * If handle_complex_actions left something in tpc->tac.action,
	 * we just want to return success and wait and see what happens
	 * with the action via future debug expections.
	 */
	;
    }
    /*
     * If we stepped an action first, we might still need to single step
     * the original instruction; do that if so.  Or at least attempt it
     * -- if the action obviated the orig instruction,
     * setup_post_single_step handles that case and does the right things.
     */
    else if (tpc && !tpc->did_orig_instr) {
	vdebug(4,LA_PROBE,LF_PROBEPOINT,"setting up post handling single step for ");
	LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");
	rc = setup_post_single_step(target,tthread,probepoint);

	if (rc == 0) {
	    /*
	     * No single step scheduled, but no error, so we're done
	     * handling the probepoint in this thread; pop the stack.
	     */
	    if (target->blocking_thread == tthread)
		target->blocking_thread = NULL;
	    probepoint_release(target,tthread,probepoint);
	    tpc_free(tthread->tpc);
	    tthread->tpc = (struct thread_probepoint_context *) \
		array_list_remove(tthread->tpc_stack);

	    vdebug(5,LA_PROBE,LF_PROBEPOINT,
		   "thread %"PRIiTID" skipping orig instruction; clearing tpc!\n",
		   tthread->tid);

	    /*
	     * If we need to keep stepping for single step actions, do
	     * that here.
	     */
	    if (keep_stepping)
		goto keep_stepping;
	    /*
	    else {
	        return RESULT_SUCCESS;
	    }
	    */
	}
	else if (rc == 1) {
	    /* Stepping, so just return without target_resume! */
	    tpc->did_orig_instr = 1;
	    //return RESULT_SUCCESS;
	}
	else if (rc == 2) {
	    /* The thread blocked because it could not hold the probepoint. */
	    vdebug(5,LA_PROBE,LF_PROBEPOINT,
		   "thread %"PRIiTID" blocked before single step real; thread"
		   " %"PRIiTID" owned probepoint\n",
		   tthread->tid,probepoint->tpc->thread->tid);
	    //return RESULT_SUCCESS;
	}
	else if (rc < 0) {
	    verror("could not setup single step; badness will probably ensue!\n");
	    //return RESULT_SUCCESS;
	}
    }
    /*
     * If we don't have any complex actions to handle, we might still
     * need to stay in single step mode if any singlestep actions were
     * in progress for this thread.  So check that.
     *
     * The difference between this single step and a single step at the
     * probepoint is that we don't disable hardware breakpoints before
     * single stepping!
     */
    else if (keep_stepping) {
    keep_stepping:
	if (probepoint) {
	    vdebug(4,LA_PROBE,LF_PROBEPOINT,"continuing single step for ");
	    LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	    vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");
	}
	else 
	    vdebug(4,LA_PROBE,LF_PROBEPOINT,
		   "continuing single step after probepoint\n");

	if (target_singlestep(target,tid,0) < 0) {
	    verror("could not keep single stepping target!\n");

	    if (target_singlestep_end(target,tid))
		verror("could not stop single stepping target"
		       " after failed sstep!\n");

	    /*
	     * All we can really do is notify all the single step
	     * actions that we had an error, and nuke them, and keep
	     * going.
	     */
	    list_for_each_entry_safe(tac,ttac,&tthread->ss_actions,tac) {
		if (tac->action->handler) 
		    tac->action->handler(tac->action,tthread,tac->action->probe,
					 tac->action->probe->probepoint,
					 MSG_FAILURE,tac->stepped,
					 tac->action->handler_data);

		action_finish_handling(tac->action,tac);

		list_del(&tac->tac);
		free(tac);
	    }

	    return RESULT_ERROR;
	}
	else {
	    /* 
	     * If single step init succeeded, let the ss handler take
	     * over.
	     *
	     * Don't call target_resume after a successful target_singlestep.
	     */
	    if (probepoint) {
		vdebug(4,LA_PROBE,LF_PROBEPOINT,"sstep command succeeded for ");
		LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
		vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");
	    }
	    else 
		vdebug(4,LA_PROBE,LF_PROBEPOINT,
		       "sstep command succeeded after probepoint\n");
	}
    }
    /*
    else if (tpc->did_orig_instr) {
         *
	 * We're totally done with this probepoint.
	 *
	rc = 0;
	goto out;
    }
    */
    else if (!probepoint && !tpc && handled_ss_actions && !keep_stepping) {
	vdebug(4,LA_PROBE,LF_PROBEPOINT,
	       "finished single step actions after probepoint\n");

	if (target_singlestep_end(target,tid))
	    verror("could not stop single stepping target after single step"
		   " actions after probepoint!\n");
    }
    else {
	verror("unexpected state!  BUG?\n");
	return RESULT_ERROR;
    }

    return RESULT_SUCCESS;
}

/*
 * This function should be called for each thread that has been left
 * paused before target_resume completes; if bp_handler or ss_handler
 * cleared 
 */
result_t probepoint_resumeat_handler(struct target *target,
				     struct target_thread *tthread) {
    struct probepoint *probepoint;
    struct thread_probepoint_context *tpc = tthread->tpc;
    int rc;
    tid_t tid = tthread->tid;
    struct thread_action_context *tac,*ttac;

    switch (tthread->resumeat) {
    case THREAD_RESUMEAT_NONE:
	return RESULT_ERROR;
    case THREAD_RESUMEAT_BPH:
	return probepoint_bp_handler(target,tthread,tthread->tpc->probepoint,0);
    case THREAD_RESUMEAT_SSR:
	return setup_post_single_step(target,tthread,tthread->tpc->probepoint);
    case THREAD_RESUMEAT_NA:
	/*
	 * This could have only been interrupted comoing from the ss
	 * handler, so we know that if it does not do an action and does
	 * not stay in single step, we have to try to do the post single
	 * step too (?)
	 */
	probepoint = tthread->tpc->probepoint;
	handle_complex_actions(target,tthread,probepoint);
	if (!tpc->tac.action && !tpc->did_orig_instr) {
	    vdebug(4,LA_PROBE,LF_PROBEPOINT,"setting up post handling single step for ");
	    LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	    vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");
	    rc = setup_post_single_step(target,tthread,probepoint);

	    if (rc == 0) {
		/*
		 * No single step scheduled, but no error, so we're done
		 * handling the probepoint in this thread; pop the stack.
		 */
		if (target->blocking_thread == tthread)
		    target->blocking_thread = NULL;
		probepoint_release(target,tthread,probepoint);
		tpc_free(tthread->tpc);
		tthread->tpc = (struct thread_probepoint_context *)	\
		    array_list_remove(tthread->tpc_stack);

		vdebug(5,LA_PROBE,LF_PROBEPOINT,
		       "thread %"PRIiTID" skipping orig instruction; clearing tpc!\n",
		       tthread->tid);

	    }
	    else if (rc == 1) {
		/* Stepping, so just return without target_resume! */
		tpc->did_orig_instr = 1;
		//return RESULT_SUCCESS;
	    }
	    else if (rc == 2) {
		/* The thread blocked because it could not hold the probepoint. */
		vdebug(5,LA_PROBE,LF_PROBEPOINT,
		       "thread %"PRIiTID" blocked before single step real; thread"
		       " %"PRIiTID" owned probepoint\n",
		       tthread->tid,probepoint->tpc->thread->tid);
		//return RESULT_SUCCESS;
	    }
	    else if (rc < 0) {
		verror("could not setup single step; badness will probably ensue!\n");
		//return RESULT_SUCCESS;
	    }
	}
	else if (!tpc->tac.action && !tpc->tac.action->steps 
		 && !list_empty(&tthread->ss_actions)) {
	    vdebug(4,LA_PROBE,LF_PROBEPOINT,
		   "continuing single step after probepoint\n");

	    if (target_singlestep(target,tid,0) < 0) {
		verror("could not keep single stepping target!\n");

		if (target_singlestep_end(target,tid))
		    verror("could not stop single stepping target"
			   " after failed sstep!\n");

		/*
		 * All we can really do is notify all the single step
		 * actions that we had an error, and nuke them, and keep
		 * going.
		 */
		list_for_each_entry_safe(tac,ttac,&tthread->ss_actions,tac) {
		    if (tac->action->handler) 
			tac->action->handler(tac->action,tthread,
					     tac->action->probe,
					     tac->action->probe->probepoint,
					     MSG_FAILURE,tac->stepped,
					     tac->action->handler_data);

		    action_finish_handling(tac->action,tac);

		    list_del(&tac->tac);
		    free(tac);
		}

		return RESULT_ERROR;
	    }
	    else {
		/* 
		 * If single step init succeeded, let the ss handler take
		 * over.
		 *
		 * Don't call target_resume after a successful target_singlestep.
		 */
		vdebug(4,LA_PROBE,LF_PROBEPOINT,"sstep command succeeded for resumeat ");
		LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
		vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");
	    }
	}
	else {
	    vdebug(4,LA_PROBE,LF_PROBEPOINT,
		   "finished handling after resumeat\n");

	    if (target_singlestep_end(target,tid))
		verror("could not stop single stepping target after single step"
		       " actions after probepoint!\n");
	}
	return RESULT_SUCCESS;
    case THREAD_RESUMEAT_PH:
	return RESULT_ERROR;
    default:
	return RESULT_ERROR;
    }
}

static int __remove_action(struct target *target,struct probepoint *probepoint,
			   struct action *action) {
    struct thread_probepoint_context *tpc;

    /*
     * If it was boosted, it will be removed when the action is destroyed.
     */
    if (action->boosted)
	return 0;

    tpc = probepoint->tpc;

    if (tpc->action_orig_mem && tpc->action_orig_mem_len) {
	if (target_write_addr(target,action->start_addr,
			      tpc->action_orig_mem_len,tpc->action_orig_mem)
	    != tpc->action_orig_mem_len) {
	    verror("could not write back orig code for action remove;"
		   " badness will probably ensue!\n");
	    return -1;
	}
	free(tpc->action_orig_mem);
	tpc->action_orig_mem = NULL;
    }

    probepoint->state = PROBE_ACTION_DONE;

    return 0;
}

static int __insert_action(struct target *target,struct target_thread *tthread,
			   struct probepoint *probepoint,struct action *action) {
    struct thread_probepoint_context *tpc;
    unsigned int buflen;
    unsigned char *buf;
    REGVAL rval;

    /* Set EIP to the address of our code. */
    if (target_write_reg(target,tthread->tid,target->ipregno,action->start_addr)) {
	verror("could not set EIP to action's first instruction (0x%"PRIxADDR")!\n",
	       action->start_addr);
	return -1;
    }

    /*
     * If it was boosted, it was inserted when it was scheduled.
     */
    if (action->boosted)
	return 0;

    tpc = probepoint->tpc;

    if (action->type == ACTION_RETURN) {
	/*
	 * If we have executed a prologue: if the prologue contains
	 * a save of the frame pointer (0x55), all we have to do is
	 * set rsp to rbp, call leaveq, and call retq.
	 * If the prologue does not contain a save of the frame
	 * pointer, we have to track all modifications to rsp during
	 * the prologue, undo them, and call leaveq, and retq.
	 */
	if (action->detail.ret.prologue) {
	    if (action->detail.ret.prologue_uses_bp) {
		vdebug(3,LA_PROBE,LF_ACTION,
		       "setting ESP to EBP and returning (prologue uses EBP) at ");
		LOGDUMPPROBEPOINT(3,LA_PROBE,LF_ACTION,probepoint);
		vdebugc(3,LA_PROBE,LF_ACTION,"\n");

		errno = 0;
		rval = target_read_reg(target,tthread->tid,target->fbregno);
		if (errno) {
		    verror("read EBP failed; action failed!\n");
		    return -1;
		}

		if (target_write_reg(target,tthread->tid,target->spregno,rval)) {
		    verror("set ESP to EBP failed; action failed and badness will ensue!\n");
		    return -1;
		}

		buf = target->full_ret_instrs;
		buflen = target->full_ret_instrs_len;
		action->steps = target->full_ret_instr_count;
	    }
	    else {
		vdebug(3,LA_PROBE,LF_ACTION,
		       "undoing prologue ESP changes (%d) and returning at ",
		       action->detail.ret.prologue_sp_offset);
		LOGDUMPPROBEPOINT(3,LA_PROBE,LF_ACTION,probepoint);
		vdebugc(3,LA_PROBE,LF_ACTION,"\n");

		errno = 0;
		rval = target_read_reg(target,tthread->tid,target->spregno);
		if (errno) {
		    verror("read ESP failed; action failed!\n");
		    return -1;
		}

		if (target_write_reg(target,tthread->tid,target->spregno,
				     rval + (REGVAL)-action->detail.ret.prologue_sp_offset)) {
		    verror("undoing prologue ESP changes failed; action failed!\n");
		    return -1;
		}

		buf = target->ret_instrs;
		buflen = target->ret_instrs_len;
		action->steps = target->ret_instr_count;
	    }
	}
	else {
	    buf = target->ret_instrs;
	    buflen = target->ret_instrs_len;
	    action->steps = target->ret_instr_count;
	}
    }
    else if (action->type == ACTION_CUSTOMCODE) {
	buf = action->detail.code.buf;
	buflen = action->detail.code.buflen;
    }
    else {
	verror("cannot handle unknown action type %d!\n",action->type);
	return -1;
    }

    tpc->action_orig_mem = malloc(buflen);
    tpc->action_orig_mem_len = buflen;
    if (!target_read_addr(target,action->start_addr,
			  tpc->action_orig_mem_len,
			  tpc->action_orig_mem)) {
	verror("could not save original under-action code at 0x%"PRIxADDR"!\n",
	       action->start_addr);
	free(tpc->action_orig_mem);
	tpc->action_orig_mem = NULL;
	return -1;
    }
    if (target_write_addr(target,action->start_addr,buflen,buf) != buflen) {
	if (action->type == ACTION_RETURN && action->detail.ret.prologue)
	    verror("could not insert action code; action failed (and badness will ensue)!\n");
	else 
	    verror("could not insert action code; action failed!\n");
	free(tpc->action_orig_mem);
	tpc->action_orig_mem = NULL;
	return -1;
    }

    probepoint->state = PROBE_ACTION_RUNNING;

    return 0;
}

struct action *__get_next_complex_action(struct probepoint *probepoint,
					 struct action *current) {
    struct list_head *head = &probepoint->complex_actions;

    if (list_empty(head))
	return NULL;
    else if (!current) 
	return list_entry(head->next,typeof(*current),action);
    else if (current->action.next == head)
	return NULL;
    else
	return list_entry(current->action.next,struct action,action);
}

/*
 * This copies code into the breakpoint as necessary and single steps as
 * necessary, or sets things up to handle boosted instructions if that's
 * what we're doing.  It also handles single step events it has set up.
 * Basically, anything to do with complex actions, it handles.
 *
 * It does setup only; it does not resume the target; only its callers
 * should do that.
 *
 * If we setup a complex action, we are going to have to single step at
 * least one instruction (and maybe more).  If we did not set up an
 * action, we have to replace the original instruction by the real thing
 * and single step -- OR if it was boostable and target supported it, we
 * set EIP to the boosted location, and single step there if necessary,
 * and mess with EIP again afterward (or let the boosted instruction JMP
 * back to the real instruction following the real boosted
 * instruction.and its effects took the place of the original
 * instruction (obviated it), enable single stepping if needed.
 *
 * Returns: <0 on error; 0 if no actions requiring single step were
 * setup; 1 if actions requiring single step were setup (and thus single
 * step mode was enabled).
 */
static int handle_complex_actions(struct target *target,
				  struct target_thread *tthread,
				  struct probepoint *probepoint) {
    struct action *action,*nextaction = NULL;
    struct thread_probepoint_context *tpc;
    tid_t tid = tthread->tid;
    struct thread_action_context *tac,*ttac;
    struct thread_probepoint_context *htpc;

    tpc = tthread->tpc;

    /*
     * If we had paused this thread before handling an action because we
     * needed to hold the probepoint, but couldn't, jump straight to
     * that part.
     */
    if (tthread->resumeat == THREAD_RESUMEAT_NA) {
	action = nextaction = tpc->tac.action;
	goto nextaction;
    }

    /* 
     * If we just arrived here after hitting the breakpoint, reset our
     * state, and try to start an action.
     */
    if (probepoint->tpc == tpc 
	&& probepoint->state == PROBE_BP_ACTIONHANDLING) {
	vdebug(5,LA_PROBE,LF_ACTION,
	       "resetting actions state after bp hit at ");
	LOGDUMPPROBEPOINT(3,LA_PROBE,LF_ACTION,probepoint);
	vdebugc(5,LA_PROBE,LF_ACTION,"\n");

	tpc->tac.action = NULL;
	tpc->tac.stepped = 0;
	tpc->action_obviated_orig = 0;
	tpc->action_orig_mem = NULL;
	tpc->action_orig_mem_len = 0;

	/* 
	 * XXX: this could fail bad if whatever the current action
	 * points to on the probepoint's list is removed from the list.
	 * What to do???
	 */
	nextaction = action = __get_next_complex_action(probepoint,NULL);
	if (!action) {
	    vdebug(3,LA_PROBE,LF_ACTION,"no actions to run at ");
	    LOGDUMPPROBEPOINT(3,LA_PROBE,LF_ACTION,probepoint);
	    vdebugc(3,LA_PROBE,LF_ACTION,"\n");

	    return 0;
	}
    }
    /*
     * If we need to keep stepping through this action, keep stepping.
     */
    else if (tpc->tac.action && tpc->tac.action->steps) {
	action = tpc->tac.action;
	/*
	 * Increment the single step count no matter what.
	 */
	++tpc->tac.stepped;

	if (action->steps < 0 || tpc->tac.stepped < action->steps) {
	    vdebug(5,LA_PROBE,LF_ACTION,
		   "did %d steps; still more at ",tpc->tac.stepped);
	    LOGDUMPPROBEPOINT(5,LA_PROBE,LF_ACTION,probepoint);
	    vdebugc(5,LA_PROBE,LF_ACTION,"\n");

	    if (action->handler) 
		action->handler(action,tthread,action->probe,probepoint,
				MSG_STEPPING,tpc->tac.stepped,
				action->handler_data);
	}
	else {
	    vdebug(5,LA_PROBE,LF_ACTION,
		   "finished %d steps; done and removing action at ",
		   tpc->tac.stepped);
	    LOGDUMPPROBEPOINT(5,LA_PROBE,LF_ACTION,probepoint);
	    vdebugc(5,LA_PROBE,LF_ACTION,"\n");
	    /*
	     * If we know the action is done because it has finished its
	     * set amount of single steps, we need to "finish" it:
	     */
	    if (action->handler) 
		action->handler(action,tthread,action->probe,probepoint,
				MSG_SUCCESS,tpc->tac.stepped,
				action->handler_data);

	    __remove_action(target,probepoint,action);

	    if (target_singlestep_end(target,tid))
		verror("could not stop single stepping target"
		       " after single stepped action!\n");

	    /* Grab the next one before we destroy this one. */
	    nextaction = __get_next_complex_action(probepoint,action);

	    action_finish_handling(action,&tpc->tac);

	    action = nextaction;

	    if (!nextaction) {
		tpc->tac.action = NULL;
		tpc->tac.stepped = 0;
	    }
	}
    }
    /*
     * If we have a current action, but don't need single steps, we
     * don't want to do *anything* -- because we didn't initiate this
     * single step!  In future, we could warn the user...
     */
    else if (tpc->tac.action) {
	vwarn("unexpected single step!\n");
	return 0;
    }
    else if (!tpc->tac.action) {
	vdebug(5,LA_PROBE,LF_ACTION,"no action being handled at ");
	LOGDUMPPROBEPOINT(3,LA_PROBE,LF_ACTION,probepoint);
	vdebugc(5,LA_PROBE,LF_ACTION,"\n");
	return 0;
    }

 nextaction:
    if (nextaction) {
	/*
	 * Start this action up!
	 */

	/* Clean up state, then setup next action if there is one. */
	tpc->action_orig_mem = NULL;
	tpc->action_orig_mem_len = 0;

	if (!nextaction->boosted) {
	    /*
	     * We need to grab the probepoint before we run this one!
	     */
	    if ((htpc = probepoint_hold(target,tthread,probepoint,tpc)) != tpc) {
		if (probepoint_pause_handling(target,tthread,probepoint,
					      THREAD_RESUMEAT_NA)) {
		    verror("thread %"PRIiTID" hit nextaction when thread %"PRIiTID" already"
			   " handling it; target does not support thread ctl!\n",
			   tthread->tid,htpc->thread->tid);
		    /*
		     * There literally is nothing we can do -- we cannot
		     * handle this breakpoint interrupt.
		     */
		    return -1;
		}
		else 
		    return 0;
	    }

	    /*
	     * If the action requires more than one single step, has
	     * more than one instruction, and we're in the right BPMODE,
	     * we have to pause all the other threads.
	     */
	    if (target->spec->bpmode == THREAD_BPMODE_STRICT
		|| (target->spec->bpmode == THREAD_BPMODE_SEMI_STRICT
		    && (action->steps > 1
			|| (action->type == ACTION_CUSTOMCODE 
			    && action->detail.code.instr_count > 1)))) {
		if (target_pause(target)) {
		    vwarn("could not pause the target for blocking thread"
			  " %"PRIiTID"!\n",tthread->tid);
		    return -1;
		}
		target->blocking_thread = tthread;
	    }
	    else {
		if (target->blocking_thread == tthread)
		    target->blocking_thread = NULL;
	    }

	    probepoint->state = PROBE_ACTION_RUNNING;
	}
	else {
	    if (target->blocking_thread == tthread)
		target->blocking_thread = NULL;
	}

	__insert_action(target,tthread,probepoint,nextaction);

	tpc->tac.action = nextaction;

	tpc->action_obviated_orig |= nextaction->obviates;

	action = nextaction;
    }

    /*
     * Single step if the current action needs it.
     */
    if (tpc->tac.action && tpc->tac.action->steps) {
	vdebug(4,LA_PROBE,LF_PROBEPOINT,"single step for action at ");
	LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");

	int _isbp = 0;
	if (!tpc->tac.action->boosted && !tpc->tac.stepped) 
	    _isbp = 1;

	if (probepoint->style == PROBEPOINT_HW
	    && _isbp
	    && !target->nodisablehwbponss) {
	    /*
	     * We need to disable the hw breakpoint before we single
	     * step because the target can't do it.
	     */
	    target_disable_hw_breakpoint(target,probepoint->thread->tid,probepoint->debugregnum);
	    probepoint->debugregdisabled = 1;
	}

	if (target_singlestep(target,tid,_isbp) < 0) {
	    verror("could not keep single stepping target!\n");

	    if (probepoint->style == PROBEPOINT_HW
		&& _isbp
		&& !target->nodisablehwbponss) {
		/*
		 * Reenable the hw breakpoint we just disabled.
		 */
		target_enable_hw_breakpoint(target,probepoint->thread->tid,probepoint->debugregnum);
		probepoint->debugregdisabled = 0;
	    }

	    if (target_singlestep_end(target,tid))
		verror("could not stop single stepping target"
		       " after failed sstep!\n");

	    /*
	     * All we can really do is notify all the single step
	     * actions that we had an error, and nuke them, and keep
	     * going.
	     */
	    list_for_each_entry_safe(tac,ttac,&tthread->ss_actions,tac) {
		if (tac->action->handler) 
		    tac->action->handler(tac->action,tthread,tac->action->probe,
					 action->probe->probepoint,
					 MSG_FAILURE,tac->stepped,
					 tac->action->handler_data);

		action_finish_handling(action,tac);

		list_del(&tac->tac);
		free(tac);
	    }

	    return -1;
	}
	else {
	    /* 
	     * If single step init succeeded, let the ss handler take
	     * over.
	     *
	     * Don't call target_resume after a successful target_singlestep.
	     */
	    vdebug(4,LA_PROBE,LF_PROBEPOINT,"sstep command succeeded for action at ");
	    LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	    vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");

	    return 0;
	}

	return 1;
    }
    else if (tpc->tac.action) {
	vdebug(4,LA_PROBE,LF_PROBEPOINT,"NOT single stepping for action at ");
	LOGDUMPPROBEPOINT(4,LA_PROBE,LF_PROBEPOINT,probepoint);
	vdebugc(4,LA_PROBE,LF_PROBEPOINT,"\n");
    }

    return 0;
}

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
 * Actions do not have priorities; they are executed in the order scheduled.
 */
int action_sched(struct probe *probe,struct action *action,
		 action_whence_t whence,int autofree,
		 action_handler_t handler,void *handler_data) {
    struct action *lpc;
    unsigned char *code;
    unsigned int code_len = 0;
    struct probepoint *probepoint;
    struct target *target;

    if (action->probe != NULL) {
	verror("action already associated with probe!\n");
	return -1;
    }

    if (!probe->probepoint) {
	errno = EINVAL;
	verror("probe not attached to a probepoint!\n");
	return -1;
    }

    if (whence != ACTION_ONESHOT && whence != ACTION_REPEATPRE
	&& whence != ACTION_REPEATPOST) {
	verror("unknown whence %d for action\n",whence);
	errno = EINVAL;
	return -1;
    }

    probepoint = probe->probepoint;
    target = probepoint->target;

    /*
     * If it's boosted, it's already set.
     */
    if (!action->boosted)
	action->start_addr = probepoint->addr;

    if (action->type == ACTION_REGMOD || action->type == ACTION_MEMMOD) {
	list_add_tail(&action->action,&probe->probepoint->simple_actions);
    }
    /* right now you can always enable singlestep actions */
    else if (action->type == ACTION_SINGLESTEP) {
	list_add_tail(&action->action,&probe->probepoint->ss_actions);
    }
    /* only allow one return action per probepoint */
    else if (action->type == ACTION_RETURN) {
	list_for_each_entry(lpc,&probe->probepoint->complex_actions,action) {
	    if (lpc->type == ACTION_RETURN) {
		verror("probepoint already has return action\n");
		return -1;
	    }
	    else if (lpc->type == ACTION_CUSTOMCODE) {
		verror("probepoint already has customcode action\n");
		return -1;
	    }
	}

	/* Try to disassemble and setup return from the prologue. */
	if (probepoint->symbol_addr 
	    && probepoint->symbol_addr != probepoint->addr) {
	    if (probepoint->symbol_addr > probepoint->addr) {
		vwarn("probepoint symbol addr < probepoint addr -- bad\n");
	    }
	    else {
		action->detail.ret.prologue = 1;

		/* Read the prologue; if the first byte is 0x55, we're
		 * using frame pointers and we don't need to analyze the
		 * prologue to watch the stack grow so we can undo it.
		 * Otherwise, read the stack growth during the prologue
		 * so we can undo it during a return.
		 */
		code_len = probepoint->addr - probepoint->symbol_addr;
		code = (unsigned char *)malloc(code_len);
		memset(code,0,code_len);

		if (!target_read_addr(target,probepoint->symbol_addr,
				      code_len,code)) {
		    vwarn("could not read prologue code; skipping disasm!\n");
		    free(code);
		    code = NULL;
		}
		else {
		    if (*code == 0x55) {
			free(code);
			action->detail.ret.prologue_uses_bp = 1;
			vdebug(3,LA_PROBE,LF_ACTION,
			       "skipping prologue disassembly for function %s: first instr push EBP\n",
			       probepoint->bsymbol ? probepoint->bsymbol->lsymbol->symbol->name : "<UNKNOWN>");
		    }
		    else if (disasm_get_prologue_stack_size(target,code,code_len,
							    &action->detail.ret.prologue_sp_offset)) {
			verror("could not disassemble function prologue that needed stack tracking for return action!\n");
			free(code);
			return -1;
		    }
		    else {
			vdebug(3,LA_PROBE,LF_ACTION,
			       "disassembled prologue for function %s: sp moved %d\n",
			       probepoint->bsymbol ? probepoint->bsymbol->lsymbol->symbol->name : "<UNKNOWN>",
			       action->detail.ret.prologue_sp_offset);
		    }
		}
	    }
	}

	/*
	 * First check is redundant due to check in target_open, but
	 * in case that goes away, it's here too.
	 */
	if (target->spec->bpmode == THREAD_BPMODE_STRICT && !target->threadctl) {
	    verror("cannot do return on strict target without threadctl!\n");
	    errno = ENOTSUP;
	    return -1;
	}
	else if (action->detail.ret.prologue && action->detail.ret.prologue_uses_bp
		 && !action->boosted
		 && !target->threadctl
		 && target->full_ret_instr_count > 1
		 && target->spec->bpmode == THREAD_BPMODE_SEMI_STRICT) {
	    verror("cannot do non-boosted, multi-instruction return"
		   " on strict target without threadctl!\n");
	    errno = ENOTSUP;
	    return -1;
	}

	/*
	 * We do not need to manually boost return instructions; if the
	 * target supported it and had room, these are added to the
	 * target when we attach.  BUT, return instructions ALWAYS must
	 * be single stepped, because otherwise we don't know when we're
	 * done returning (and thus can't call action handlers,
	 * probepoint post handlers, garbage collect anything, etc).
	 */

	list_add_tail(&action->action,&probe->probepoint->complex_actions);
    }
    /* only allow one customcode action per probepoint */
    else if (action->type == ACTION_CUSTOMCODE) {

	/*
	 * For now, we always boost custom code so that it doesn't
	 * interfere with the handling of the probepoint.  So, we
	 * assemble our code buf according to the flags, copy in the
	 * user's code, and end the code frag with a special breakpoint
	 * probepoint so that we know when we're done with the custom
	 * code.
	 *
	 * We have to assemble the code buf before we ask the target for
	 * space from its boostable memory (if there is any -- there
	 * might not be, or might not be enough).
	 */

	list_for_each_entry(lpc,&probe->probepoint->complex_actions,action) {
	    if (lpc->type == ACTION_RETURN) {
		verror("probepoint already has return action\n");
		return -1;
	    }
	    else if (lpc->type == ACTION_CUSTOMCODE) {
		verror("probepoint already has customcode action\n");
		return -1;
	    }
	}

	/* XXX: this check should really let 1-instr actions go through */
	if ((target->spec->bpmode == THREAD_BPMODE_STRICT 
	     || target->spec->bpmode == THREAD_BPMODE_SEMI_STRICT)
	    && !action->boosted
	    && !target->threadctl) {
	    verror("cannot do return on strict target without threadctl!\n");
	    errno = ENOTSUP;
	    return -1;
	}

	list_add_tail(&action->action,&probe->probepoint->complex_actions);
    }

    /*
     * Ok, we're safe; memo-ize all the sched info into the action struct.
     */
    action->whence = whence;

    action->autofree = autofree;
    action->handler = handler;
    action->handler_data = handler_data;

    action->probe = probe;

    target_attach_action(target,action);

    return 0;
}

/*
void __action_cancel_in_thread(struct target_thread *tthread,
			       struct action *action) {
    int i;
    struct thread_probepoint_context *tpc;

    if (!array_list_len(tthread->tpc_stack))
	return;

    for (i = 0; i < array_list_len(tthread->tpc_stack); ++i) {
	tpc = (struct thread_probepoint_context *) \
	    array_list_item(tthread->tpc_stack,i);

	if (tpc->tac.action == action) {
	    if (!action->isboosted) 
		vwarn("canceling a non-boosted action running in"
		      " thread %"PRIiTID"; badness!!!\n",tthread->tid);

	    // We have to mark it as canceled
	    tpc->tac.canceled = 1;
	    tpc->tac.nextaction = \
		__get_next_complex_action(action->probe->probepoint,action);

	    action_release(action);
	}
    }

    // XXX: but we still have the problem of what happens when an
    //	   action still has code at the breakpoint
}
*/

/*
 * Cancel an action.
 */
int action_cancel(struct action *action) {
    if (!action->probe) {
	verror("cannot cancel action not associated with a probe!\n");
	return 1;
    }

    /*
     * XXX: this is bad, but correct.  We have to check all threads and
     * make sure that this action is not the one they are currently
     * executing; if so, we have to go mark the
     * thread_probepoint_context that was holding it as deleted, and
     * "release" the action manually.  I guess this means that actions
     * don't really need refcnting...
     */
    /*
    target = action->probe->probepoint->target;
    

    if (action->probe 
	&& action->probe->probepoint
	&& action->probe->probepoint->action == action) {
	verror("cannot cancel a currently-running action!\n");
	return 1;
    }
    */

    action->handler = NULL;
    action->handler_data = NULL;

    list_del(&action->action);
    action->probe = NULL;

    target_detach_action(action->target,action);

    return 0;
}

/*
 * High-level actions that require little ASM knowledge.
 */
struct action *action_return(REGVAL retval) {
    struct action *action;

    action = (struct action *)calloc(1,sizeof(struct action));
    if (!action) {
	verror("could not malloc action: %s\n",strerror(errno));
	return NULL;
    }

    action->type = ACTION_RETURN;
    action->whence = ACTION_UNSCHED;
    INIT_LIST_HEAD(&action->action);

    action->detail.ret.retval = retval;

    action->obviates = 1;

    return action;
}

/*
 * Low-level actions that require little ASM knowledge, and may or may
 * not be permitted.
 */
struct action *action_singlestep(int nsteps) {
    struct action *action;

    if (nsteps == 0 || (nsteps < 0 && nsteps != SINGLESTEP_INFINITE 
			           && nsteps != SINGLESTEP_NEXTBP)) {
	errno = EINVAL;
	return NULL;
    }

    action = (struct action *)calloc(1,sizeof(struct action));
    if (!action) {
	verror("could not malloc action: %s\n",strerror(errno));
	return NULL;
    }

    action->type = ACTION_SINGLESTEP;
    action->whence = ACTION_UNSCHED;
    INIT_LIST_HEAD(&action->action);

    action->steps = nsteps;

    return action;
}

struct action *action_code(char *buf,uint32_t buflen,action_flag_t flags) {
    struct action *action;

    action = (struct action *)calloc(1,sizeof(struct action));
    if (!action) {
	verror("could not malloc action: %s\n",strerror(errno));
	return NULL;
    }

    action->type = ACTION_CUSTOMCODE;
    action->whence = ACTION_UNSCHED;
    INIT_LIST_HEAD(&action->action);

    action->detail.code.buf = malloc(buflen);
    memcpy(action->detail.code.buf,buf,buflen);
    action->detail.code.buflen = buflen;
    action->detail.code.flags = flags;

    return action;
}

struct action *action_regmod(REG regnum,REGVAL regval) {
    struct action *action;

    action = (struct action *)calloc(1,sizeof(struct action));
    if (!action) {
	verror("could not malloc action: %s\n",strerror(errno));
	return NULL;
    }

    action->type = ACTION_REGMOD;
    action->whence = ACTION_UNSCHED;
    INIT_LIST_HEAD(&action->action);

    action->detail.regmod.regnum = regnum;
    action->detail.regmod.regval = regval;

    return action;
}

struct action *action_memmod(ADDR dest,char *data,uint32_t len) {
    struct action *action;

    action = (struct action *)calloc(1,sizeof(struct action));
    if (!action) {
	verror("could not malloc action: %s\n",strerror(errno));
	return NULL;
    }

    action->type = ACTION_MEMMOD;
    action->whence = ACTION_UNSCHED;
    INIT_LIST_HEAD(&action->action);

    action->detail.memmod.destaddr = dest;
    action->detail.memmod.data = malloc(len);
    memcpy(action->detail.memmod.data,data,len);
    action->detail.memmod.len = len;

    return action;
}

REFCNT action_release(struct action *action) {
    REFCNT refcnt;
    RPUT(action,action,action,refcnt);
    return refcnt;
}

static void action_finish_handling(struct action *action,
				   struct thread_action_context *tac) {
    REFCNT trefcnt;

    /*
     * If the action is oneshot, cancel it.
     */
    if (action->whence == ACTION_ONESHOT) {
	if (tac)
	    RPUTNF(action,action,tac);

	action_cancel(action);

	if (action->autofree)
	    action_free(action,0);
    }
}

/*
 * Destroy an action (and cancel it first if necessary!).
 */
REFCNT action_free(struct action *action,int force) {
    int retval = action->refcnt;

    if (action->probe) {
	if (action_cancel(action)) {
	    verror("could not cancel action; cannot destroy!\n");
	    return 1;
	}
    }

    if (retval) {
	if (!force) {
	    vwarn("cannot free action (%d refs)!\n",retval);
	    return retval;
	}
	else {
	    verror("forced free action (%d refs)\n",retval);
	}
    }

    if (action->type == ACTION_CUSTOMCODE
	&& action->detail.code.buf) {
	free(action->detail.code.buf);
    }
    else if (action->type == ACTION_MEMMOD
	     && action->detail.memmod.len) {
	free(action->detail.memmod.data);
    }

    free(action);

    return retval;
}
