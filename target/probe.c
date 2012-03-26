#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "common.h"
#include "log.h"

#include "dwdebug.h"

#include "target_api.h"
#include "target.h"

#include "probe_api.h"
#include "probe.h"

#define LOGDUMPPROBEPOINT(dl,lt,pp) \
    if ((pp)->bsymbol && (pp)->symbol_addr) { \
	vdebugc((dl),(lt),"probepoint(0x%"PRIxADDR" %s:%+d) ", \
		(pp)->addr,(pp)->bsymbol->lsymbol->symbol->name, \
		(pp)->symbol_addr - (pp)->addr);	\
    } \
    else if ((pp)->bsymbol) { \
        vdebugc((dl),(lt),"probepoint(0x%"PRIxADDR" %s) ", \
	       (pp)->addr,(pp)->bsymbol->lsymbol->symbol->name); \
    } \
    else { \
        vdebugc((dl),(lt),"probepoint(0x%"PRIxADDR") ", \
	       (pp)->addr); \
    }

#define LOGDUMPPROBEPOINT_NL(dl,lt,p) \
    LOGDUMPPROBEPOINT((dl),(lt),(p)); \
    vdebugc((dl),(lt),"\n");

#define LOGDUMPPROBE(dl,lt,p) \
    vdebugc((dl),(lt),"probe(%s) ",probe->name); \
    if ((p)->bsymbol) { \
	vdebugc((dl),(lt),"(on %s) ", \
		(p)->bsymbol->lsymbol->symbol->name);	\
    } \
    else { \
        vdebugc((dl),(lt),"(on <UNKNOWN>) ");	\
    } \
    if ((p)->probepoint) { 			  \
	LOGDUMPPROBEPOINT(dl,lt,(p)->probepoint); \
    } \
    if ((p)->sources) { 			\
	vdebugc((dl),(lt)," (%d sources)",g_list_length((p)->sources));	\
    } \
    if ((p)->sinks) { 			\
	vdebugc((dl),(lt)," (%d sinks)",g_list_length((p)->sources)); \
    }

#define LOGDUMPPROBE_NL(dl,lt,p) \
    LOGDUMPPROBE((dl),(lt),(p)); \
    vdebugc((dl),(lt),"\n");

/*
 * If the user doesn't supply pre/post handlers, and the probe has sinks
 * attached to it, we invoke these handlers to pass the event to the
 * sinks.  Users that write their own handlers should call these
 * handlers from within their handler, so that sinks can attach to their
 * handlers if desired.
 */
int probe_do_sink_pre_handlers (struct probe *probe,void *handler_data,
				struct probe *trigger) {
    struct probe *ptmp;
    GList *list;
    int retval = 0;
    int rc;

    if (probe->sinks) {
	LOGDUMPPROBE(5,LOG_P_PROBE,probe);

	list = probe->sinks;
	while (list) {
	    ptmp = (struct probe *)list->data;
	    /* Signal each of the sinks. */
	    if (ptmp->pre_handler) {
		if ((rc = ptmp->pre_handler(ptmp,ptmp->handler_data,trigger))) {
		    probe_disable(ptmp);
		    retval |= rc;
		}
	    }
	    list = g_list_next(list);
	}
    }

    return retval;
}

int probe_do_sink_post_handlers(struct probe *probe,void *handler_data,
				struct probe *trigger) {
    struct probe *ptmp;
    GList *list;
    int retval = 0;
    int rc;

    if (probe->sinks) {
	LOGDUMPPROBE(5,LOG_P_PROBE,probe);

	list = probe->sinks;
	while (list) {
	    ptmp = (struct probe *)list->data;
	    /* Signal each of the sinks. */
	    if (ptmp->post_handler) {
		if ((rc = ptmp->post_handler(ptmp,ptmp->handler_data,trigger))) {
		    probe_disable(ptmp);
		    retval |= rc;
		}
	    }
	    list = g_list_next(list);
	}
    }

    return retval;
}

static struct probepoint *probepoint_lookup(struct target *target,ADDR addr) {
    struct probepoint *retval = \
	(struct probepoint *)g_hash_table_lookup(target->probepoints,
						 (gpointer)addr);

    if (retval) {
	vdebug(9,LOG_P_PROBEPOINT,"found ");
	LOGDUMPPROBEPOINT_NL(9,LOG_P_PROBEPOINT,retval);
    }
    else
	vdebug(9,LOG_P_PROBEPOINT,"did not find probepoint at 0x%"PRIxADDR"\n",
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
    probepoint->state = PROBE_DISABLED;

    probepoint->type = type;
    probepoint->style = style;
    probepoint->whence = whence;
    probepoint->watchsize = watchsize;

    probepoint->bsymbol = bsymbol;
    probepoint->symbol_addr = symbol_addr;
    
    probepoint->debugregnum = -1;

    INIT_LIST_HEAD(&probepoint->probes);
    INIT_LIST_HEAD(&probepoint->actions);

    g_hash_table_insert(target->probepoints,(gpointer)addr,probepoint);

    vdebug(5,LOG_P_PROBEPOINT,"created ");
    LOGDUMPPROBEPOINT_NL(5,LOG_P_PROBEPOINT,probepoint);

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

    /* Destroy any actions it might have (probe_free does this too,
     * but this is much more efficient.
     */
    list_for_each_entry_safe(action,atmp,&probepoint->actions,action) {
	if (action->autofree)
	    action_destroy(action);
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
}

static void probepoint_free(struct probepoint *probepoint) {
    probepoint_free_internal(probepoint);

    g_hash_table_remove(probepoint->target->probepoints,
			(gpointer)probepoint->addr);

    vdebug(5,LOG_P_PROBEPOINT,"freed ");
    LOGDUMPPROBEPOINT_NL(5,LOG_P_PROBEPOINT,probepoint);

    free(probepoint);
}

/* We need this in case the target needs to quickly remove all the
 * probes (i.e., on a signal) -- and in that case, we have to let the
 * target remove the probepoint from its hashtables itself.
 */
void probepoint_free_ext(struct probepoint *probepoint) {
    probepoint_free_internal(probepoint);

    vdebug(5,LOG_P_PROBEPOINT,"freed (ext) ");
    LOGDUMPPROBEPOINT_NL(5,LOG_P_PROBEPOINT,probepoint);

    free(probepoint);
}

/**
 ** Probe unregistration/registration.
 **/

static int __probepoint_remove(struct probepoint *probepoint) {
    struct target *target;
    int ret;

    target = probepoint->target;

    vdebug(5,LOG_P_PROBEPOINT,"removing ");
    LOGDUMPPROBEPOINT_NL(5,LOG_P_PROBEPOINT,probepoint);

    /* Check if the probepoint has already been inserted; we do not want
     * to backup a previously inserted breakpoint.
     */
    if (probepoint->state == PROBE_DISABLED) {
	/* return success, the probepoint is already removed */
	vdebug(7,LOG_P_PROBEPOINT,"");
	LOGDUMPPROBEPOINT(7,LOG_P_PROBEPOINT,probepoint);
	vdebugc(7,LOG_P_PROBEPOINT," already disabled\n");

        return 0;
    }

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

    probepoint->state = PROBE_REMOVING;

    /*
     * If it's hardware, use the target API to remove it.
     */
    if (probepoint->style == PROBEPOINT_HW
	&& probepoint->debugregnum > -1) {
	if (probepoint->type == PROBEPOINT_BREAK) {
	    if ((ret = target_unset_hw_breakpoint(target,
						  probepoint->debugregnum))) {
		verror("failure while removing hw breakpoint; cannot recover!\n");
	    }
	    else {
		vdebug(4,LOG_P_PROBEPOINT,"removed HW break ");
		LOGDUMPPROBEPOINT_NL(4,LOG_P_PROBEPOINT,probepoint);
	    }
	}
	else {
	    if ((ret = target_unset_hw_watchpoint(target,
						  probepoint->debugregnum))) {
		verror("failure while removing hw watchpoint; cannot recover!\n");
	    }
	    else {
		vdebug(4,LOG_P_PROBEPOINT,"removed HW watch ");
		LOGDUMPPROBEPOINT_NL(4,LOG_P_PROBEPOINT,probepoint);
	    }
	}

	if (ret) 
	    return 1;

	probepoint->debugregnum = -1;
    }
    /* Otherwise do software. */
    else if (probepoint->breakpoint_orig_mem
	     && probepoint->breakpoint_orig_mem_len > 0) {
	/* restore the original instruction */
	if (target_write_addr(target,probepoint->addr,
			      probepoint->breakpoint_orig_mem_len,
			      probepoint->breakpoint_orig_mem,NULL) \
	    != probepoint->breakpoint_orig_mem_len) {
	    verror("could not restore orig instrs for bp remove");
	    return 1;
	}

	if (target_notify_sw_breakpoint(target,probepoint->addr,0)) 
	    verror("target sw breakpoint removal notification failed; nonfatal!\n");

	vdebug(4,LOG_P_PROBEPOINT,"removed SW break ");
	LOGDUMPPROBEPOINT_NL(4,LOG_P_PROBEPOINT,probepoint);

	free(probepoint->breakpoint_orig_mem);
	probepoint->breakpoint_orig_mem = NULL;
    }

    probepoint->state = PROBE_DISABLED;

    vdebug(2,LOG_P_PROBEPOINT,"removed ");
    LOGDUMPPROBEPOINT_NL(2,LOG_P_PROBEPOINT,probepoint);

    return 0;
}

static int __probepoint_insert(struct probepoint *probepoint) {
    struct target *target;
    int ret;
    REG reg;

    target = probepoint->target;

    vdebug(5,LOG_P_PROBEPOINT,"inserting ");
    LOGDUMPPROBEPOINT_NL(5,LOG_P_PROBEPOINT,probepoint);

    /* Check if the probepoint has already been inserted; we do not want
     * to backup a previously inserted breakpoint.
     */
    if (probepoint->state != PROBE_DISABLED) {
	/* return success, the probepoint is already being managed */
	vdebug(9,LOG_P_PROBEPOINT,"");
	LOGDUMPPROBEPOINT(9,LOG_P_PROBEPOINT,probepoint);
	vdebugc(9,LOG_P_PROBEPOINT," already inserted\n");

        return 0;
    }

    probepoint->state = PROBE_INSERTING;

    /*
     * Check to see if there are any hardware resources; use them if so.
     */
    if (probepoint->style == PROBEPOINT_FASTEST) {
	if ((reg = target_get_unused_debug_reg(target)) > -1) {
	    probepoint->style = PROBEPOINT_HW;
	    probepoint->debugregnum = reg;

	    vdebug(3,LOG_P_PROBEPOINT,"using HW reg %d for ",reg);
	    LOGDUMPPROBEPOINT_NL(3,LOG_P_PROBEPOINT,probepoint);
	}
	else {
	    probepoint->style = PROBEPOINT_SW;

	    vdebug(3,LOG_P_PROBEPOINT,"using SW for FASTEST ");
	    LOGDUMPPROBEPOINT_NL(3,LOG_P_PROBEPOINT,probepoint);
	}
    }
    else if (probepoint->style == PROBEPOINT_HW) {
	if ((reg = target_get_unused_debug_reg(target)) > -1) {
	    probepoint->debugregnum = reg;

	    vdebug(3,LOG_P_PROBEPOINT,"using HW reg %d for ",reg);
	    LOGDUMPPROBEPOINT_NL(3,LOG_P_PROBEPOINT,probepoint);
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
	return 1;
    }

    /*
     * If it's hardware, use the target API to insert it.
     */
    if (probepoint->style == PROBEPOINT_HW) {
	if (probepoint->type == PROBEPOINT_BREAK) {
	    if ((ret = target_set_hw_breakpoint(target,probepoint->debugregnum,
						probepoint->addr))) {
		verror("failure inserting hw breakpoint!\n");
	    }
	    else {
		vdebug(7,LOG_P_PROBEPOINT,"inserted hw break at ");
		LOGDUMPPROBEPOINT_NL(7,LOG_P_PROBEPOINT,probepoint);
	    }
	}
	else {
	    if ((ret = target_set_hw_watchpoint(target,probepoint->debugregnum,
						probepoint->addr,
						probepoint->whence,
						probepoint->watchsize))) {
		verror("failure inserting hw watchpoint!\n");
	    }
	    else {
		vdebug(7,LOG_P_PROBEPOINT,"inserted hw watch at ");
		LOGDUMPPROBEPOINT_NL(7,LOG_P_PROBEPOINT,probepoint);
	    }
	}

	if (ret) {
	    probepoint->state = PROBE_DISABLED;
	    return 1;
	}
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

	if (!target_read_addr(target,probepoint->addr,
			      probepoint->breakpoint_orig_mem_len,
			      probepoint->breakpoint_orig_mem,NULL)) {
	    verror("could not save orig instrs for bp insert\n");
	    probepoint->state = PROBE_DISABLED;
	    free(probepoint->breakpoint_orig_mem);
	    probepoint->breakpoint_orig_mem = NULL;
	    return 1;
	}

	vdebug(3,LOG_P_PROBEPOINT,"saved orig mem under SW ");
	LOGDUMPPROBEPOINT_NL(3,LOG_P_PROBEPOINT,probepoint);

	if (target_write_addr(target,probepoint->addr,
			      target->breakpoint_instrs_len,
			      target->breakpoint_instrs,NULL) \
	    != target->breakpoint_instrs_len) {
	    verror("could not write breakpoint instrs for bp insert\n");
	    probepoint->state = PROBE_DISABLED;
	    free(probepoint->breakpoint_orig_mem);
	    probepoint->breakpoint_orig_mem = NULL;
	    return 1;
	}

	if (target_notify_sw_breakpoint(target,probepoint->addr,1)) 
	    verror("target sw breakpoint insertion notification failed; nonfatal!\n");

	vdebug(3,LOG_P_PROBEPOINT,"inserted SW ");
	LOGDUMPPROBEPOINT_NL(3,LOG_P_PROBEPOINT,probepoint);
    }

    probepoint->state = PROBE_BP_SET;

    vdebug(2,LOG_P_PROBEPOINT,"inserted ");
    LOGDUMPPROBEPOINT_NL(2,LOG_P_PROBEPOINT,probepoint);

    return 0;
}

struct probe *probe_create(struct target *target, struct probe_ops *pops,
			   const char *name,
			   probe_handler_t pre_handler,
			   probe_handler_t post_handler,
			   void *handler_data,int autofree) {
    struct probe *probe;

    probe = (struct probe *)malloc(sizeof(*probe));
    if (!probe) {
        verror("failed to allocate a new probe\n");
        return NULL;
    }
    memset(probe,0,sizeof(*probe));

    probe->target = target;
    probe->name = (name) ? strdup(name) : NULL;
    probe->pre_handler = pre_handler;
    probe->post_handler = post_handler;
    probe->handler_data = handler_data;
    probe->enabled = 0; // disabled at first
    probe->autofree = autofree;
    probe->ops = pops;

    if (PROBE_SAFE_OP(probe,init)) {
	verror("probe %s init failed, calling fini!\n",probe->name);
	PROBE_SAFE_OP(probe,fini);
	if (name)
	    free(probe->name);
	free(probe);
	return NULL;
    }

    vdebug(5,LOG_P_PROBE,"initialized ");
    LOGDUMPPROBE_NL(5,LOG_P_PROBE,probe);

    return probe;
}

int probe_free(struct probe *probe,int force) {
    vdebug(5,LOG_P_PROBE,"");
    LOGDUMPPROBE_NL(5,LOG_P_PROBE,probe);

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

    if (PROBE_SAFE_OP(probe,fini)) {
	verror("probe %s fini failed, aborting!\n",probe->name);
	return -1;
    }

    vdebug(5,LOG_P_PROBE,"almost done: ");
    LOGDUMPPROBE_NL(5,LOG_P_PROBE,probe);

    if (probe->name)
	free(probe->name);
    free(probe);

    return 0;
}

static int __probe_unregister(struct probe *probe,int force,int onlyone) {
    struct probepoint *probepoint = probe->probepoint;
    struct target *target = probe->target;
    int action_did_obviate = 0;
    target_status_t status;
    struct action *action;
    struct action *tmp;
    struct probe *ptmp;
    GList *list;

    vdebug(5,LOG_P_PROBE,"");
    LOGDUMPPROBE(5,LOG_P_PROBE,probe);
    vdebugc(5,LOG_P_PROBE,"(force=%d,onlyone=%d)\n",force,onlyone);

    if (probe->sources) 
	vdebug(5,LOG_P_PROBE,"detaching probe %s from sources\n",probe->name);

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
	list_for_each_entry_safe(action,tmp,&probepoint->actions,
				 action) {
	    if (probe == action->probe) {
		if (action->autofree) 
		    action_destroy(action);
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
	vdebug(5,LOG_P_PROBE,"removing source\n");
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
	vdebug(5,LOG_P_PROBE,"probe sources removed\n");
    }

    probe->bsymbol = NULL;

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

    vdebug(5,LOG_P_PROBE,"no more probes at ");
    LOGDUMPPROBEPOINT(5,LOG_P_PROBE,probepoint);
    vdebugc(5,LOG_P_PROBE,"; removing probepoint!\n");

    /* 
     * If the probepoint is not currently being handled, simply remove
     * it.  Otherwise, we have to handle complex cases!
     */
    if (probepoint->state == PROBE_BP_SET || probepoint->state == PROBE_DISABLED) {
	vdebug(7,LOG_P_PROBE,"doing easy removal of ");
	LOGDUMPPROBEPOINT(7,LOG_P_PROBE,probepoint);
	vdebugc(7,LOG_P_PROBE,"; removing probepoint!\n");

	__probepoint_remove(probepoint);
	probepoint_free(probepoint);

	return 0;
    }
    /*
     * Handle complex stuff :).
     */
    else if (!force) {
	vwarn("probepoint being handled (state %d); not forcing unregister yet!\n",
	      probepoint->state);
	errno = EAGAIN;
	return -1;
    }
    else {
	if (probepoint->state == PROBE_BP_HANDLING) {
	    vwarn("force unregister probe while its breakpoint is being handled; trying to clean up normally!\n");
	}
	else if (probepoint->state == PROBE_BP_HANDLING_POST) {
	    vwarn("force unregister probe while its breakpoint is being post handled; trying to clean up normally!\n");
	}
	else if (probepoint->state == PROBE_INSERTING) {
	    vwarn("forced unregister probe while it is inserting; trying to clean up normally!\n");
	    probepoint->state = PROBE_BP_SET;
	}
	else if (probepoint->state == PROBE_REMOVING) {
	    vwarn("forced unregister probe while it is removing; trying to clean up normally!\n");
	    probepoint->state = PROBE_BP_SET;
	}
	else if (probepoint->state == PROBE_ACTION_RUNNING) {
	    vwarn("forced unregister probe while it is running action; trying to clean up normally!\n");
	    /* We need to remove the action code, if any, reset the EIP
	     * to what it would have been if we had just hit the BP, and
	     * then do the normal breakpoint removal.
	     */
	    if (probepoint->action
		&& probepoint->action_orig_mem
		&& probepoint->action_orig_mem_len) {
		if (target_write_addr(target,probepoint->addr,
				      probepoint->action_orig_mem_len,
				      probepoint->action_orig_mem,NULL) \
		    != probepoint->action_orig_mem_len) {
		    verror("could not write orig code for forced action remove; badness will probably ensue!\n");
		    probepoint->state = PROBE_DISABLED;
		}
		else {
		    probepoint->state = PROBE_BP_SET;
		}
		free(probepoint->action_orig_mem);
		probepoint->action_orig_mem = NULL;
	    }
	    else {
		vwarn("action running, but no orig mem to restore (might be ok)!\n");
		probepoint->state = PROBE_BP_SET;
	    }
	    
	    if (probepoint->action && probepoint->action_obviates_orig)
		action_did_obviate = 1;

	    /* NULL these out to be safe. */
	    probepoint->action_orig_mem = NULL;
	    probepoint->action_orig_mem_len = 0;
	    probepoint->action = NULL;
	    probepoint->action_obviates_orig = 0;
	    probepoint->action_needs_ssteps = 0;
	}

	/*
	 * Coming out of the above checks, the probepoint must be in either
	 * the PROBE_DISABLED, PROBE_BP_SET, PROBE_BP_HANDLING, or
	 * PROBE_BP_HANDLING_POST states.  If it's disabled, we do nothing.
	 * If it's set, we replace the breakpoint instructions with the
	 * original contents; and if we're doing initial BP handling, reset
	 * EIP to the probepoint addr; else if we're doing BP handling after
	 * the single step, *don't* reset IP, since we already did the
	 * original instruction.  UNLESS we were executing an action that
	 * obviated the original code control flow -- then we replace the
	 * original code, BUT DO NOT update EIP!!!
	 *
	 * Man, I hope that's everything.
	 */

	if (probepoint->state != PROBE_DISABLED) {
	    /* Replace the original code. */
	    if (probepoint->style == PROBEPOINT_SW
		&& probepoint->breakpoint_orig_mem
		&& probepoint->breakpoint_orig_mem_len) {
		if (target_write_addr(target,probepoint->addr,
				      probepoint->breakpoint_orig_mem_len,
				      probepoint->breakpoint_orig_mem,NULL) \
		    != probepoint->breakpoint_orig_mem_len) {
		    verror("could not write orig code for forced breakpoint remove; badness will probably ensue!\n");
		}
		else {
		    free(probepoint->breakpoint_orig_mem);
		    probepoint->breakpoint_orig_mem = NULL;
		}
	    }
	    else if (probepoint->style == PROBEPOINT_HW) {
		if (target_unset_hw_breakpoint(target,probepoint->debugregnum)) {
		    verror("could not remove hardware breakpoint; cannot repair!\n");
		}
	    }

	    /* Reset EIP to the right thing. */
	    if (probepoint->state == PROBE_BP_HANDLING && !action_did_obviate
		&& probepoint->type != PROBEPOINT_WATCH) {
		/* We still must execute the original instruction. */
		/* BUT NOT for watchpoints!  We do not know anything
		 * about the original instruction.
		 */
		if (target_write_reg(target,target->ipregno,probepoint->addr)) {
		    verror("could not reset IP to bp addr 0x%"PRIxADDR" for forced breakpoint remove; badness will probably ensue!\n",
			   probepoint->addr);
		}
	    }
	    else if (probepoint->state == PROBE_BP_HANDLING_POST) {
		/* We already replaced and reset the original instruction, so
		 * don't reset IP!
		 */
		;
	    }

	    /* At this point, the probepoint will be "disabled" no
	     * matter what happens; we can't repair anything that goes
	     * wrong.
	     */
	    probepoint->state = PROBE_DISABLED;
	}
    }

    /* Now, actually free the probepoint! */
    probepoint_free(probepoint);

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
	return NULL;
    }

    /* Target must be paused before we do anything. */
    if (target_status(target) != TSTATUS_PAUSED) {
        verror("target not paused!\n");
	errno = EINVAL;
	return NULL;
    }

    /* If the user has associated a bound symbol with this probe
     * registration, try to look up its start addr (and grab the range
     * if we can).
     */
    if (bsymbol) {
	location_resolve_symbol_base(target,bsymbol,&symbol_addr,
				     (!range) ? &range : NULL);
	probe->bsymbol = bsymbol;
    }

    /* If we don't have a range yet, get it. */
    if (!range) {
	target_find_range_real(target,addr,NULL,NULL,&range);
	if (!range) {
	    verror("could not find range for 0x%"PRIxADDR"\n",addr);
	    goto errout;
	}
    }

    /* Create a probepoint if this is a new addr. */
    if ((probepoint = probepoint_lookup(target,addr))) {
	/* If the style matches for breakpoints, and if the style,
	 * whence, and watchsize match for watchpoints, reuse it!
	 */
	if (!((type == PROBEPOINT_BREAK
	       && type == probepoint->type
	       && ((probepoint->style == PROBEPOINT_HW
		    && (style == PROBEPOINT_HW
			|| style == PROBEPOINT_FASTEST))
		   || (probepoint->style == PROBEPOINT_SW
		       && (style == PROBEPOINT_HW
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

	g_hash_table_insert(target->probepoints,(gpointer)addr,probepoint);
    }

    /* Inject the probepoint. */
    if (__probepoint_insert(probepoint)) {
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

    vdebug(5,LOG_P_PROBE,"probe %s attached to ",probe->name);
    LOGDUMPPROBEPOINT(5,LOG_P_PROBE,probe->probepoint);
    vdebugc(5,LOG_P_PROBE,"\n");

    return probe;

 errout:
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

struct probe *probe_register_symbol(struct probe *probe,struct bsymbol *bsymbol,
				    probepoint_style_t style,
				    probepoint_whence_t whence,
				    probepoint_watchsize_t watchsize) {
    struct target *target = probe->target;
    struct memrange *range;
    ADDR start;
    ADDR prologueend;
    ADDR probeaddr;
    int ssize;

    if (!SYMBOL_IS_FULL_INSTANCE(bsymbol->lsymbol->symbol)) {
	verror("cannot probe a partial symbol!\n");
	return NULL;
    }

    if (SYMBOL_IS_FULL_FUNCTION(bsymbol->lsymbol->symbol)) {
	if (location_resolve_symbol_base(target,bsymbol,&start,&range)) {
	    verror("could not resolve entry PC for function %s!\n",
		   bsymbol->lsymbol->symbol->name);
	    return NULL;
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
	if (location_resolve_symbol_base(target,bsymbol,&probeaddr,&range)) {
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
	    ssize = symbol_type_full_bytesize(bsymbol->lsymbol->symbol->datatype);
	    if (ssize <= 0) {
		verror("bad size (%d) for type of %s!\n",
		       ssize,bsymbol->lsymbol->symbol->name);
		goto errout;
	    }

	    watchsize = probepoint_closest_watchsize(ssize);
	}

	if (location_resolve_symbol_base(target,bsymbol,&probeaddr,&range)) {
	    verror("could not resolve base addr for var %s!\n",
		   bsymbol->lsymbol->symbol->name);
	    goto errout;
	}

	probe = __probe_register_addr(probe,probeaddr,range,
				      PROBEPOINT_BREAK,style,whence,watchsize,
				      bsymbol,probeaddr);
    }
    else {
	verror("unknown symbol type '%s'!\n",
	       SYMBOL_TYPE(bsymbol->lsymbol->symbol->type));
	goto errout;
    }

    return probe;

 errout:
    if (probe->autofree)
	probe_free(probe,1);
    return NULL;
}

struct probe *probe_register_source(struct probe *sink,struct probe *src) {
    struct target *target = sink->target;

    // XXX: what if the sources have different symbols??
    sink->bsymbol = src->bsymbol;

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

int probe_register_batch(struct target *target,ADDR *addrlist,int listlen,
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
	probe = probe_create(target,NULL,buf,pre_handler,post_handler,
			     handler_data,0);

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

/*
 * Returns the address the a probe is targeting.
 * If the given handle is invalid, the function returns a value of 0.
 */
ADDR probe_addr(struct probe *probe) {
    return probe->probepoint->addr;
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

static int handle_actions(struct probepoint *probepoint);

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
int probepoint_bp_handler(struct target *target,
			  struct probepoint *probepoint) {
    struct probe *probe;
    REGVAL ipval;
    int doit = 0;

    vdebug(5,LOG_P_PROBEPOINT,"handling bp at ");
    LOGDUMPPROBEPOINT(5,LOG_P_PROBEPOINT,probepoint);
    vdebugc(5,LOG_P_PROBEPOINT,"\n");

    /* We move into the HANDLING state while we run the pre-handlers. */
    probepoint->state = PROBE_BP_HANDLING;

    /* Save the original ip value in case something bad happens. */
    errno = 0;
    ipval = target_read_reg(target,target->ipregno);
    if (probepoint->style == PROBEPOINT_SW && errno) {
	verror("could not read EIP to reset it for SW probepoint; skipping!");
	probepoint->state = PROBE_BP_SET;
	return -1;
    }

    vdebug(5,LOG_P_PROBEPOINT,"EIP is 0x%"PRIxREGVAL" at ",ipval);
    LOGDUMPPROBEPOINT(5,LOG_P_PROBEPOINT,probepoint);
    vdebugc(5,LOG_P_PROBEPOINT,"\n");


    /* If SW bp, reset EIP and write it back *now*, because it's easy
     * here, and then if the user tries to read it, it's "correct".
     */
    if (probepoint->style == PROBEPOINT_SW) {
	ipval -= target->breakpoint_instrs_len;
	errno = 0;
	target_write_reg(target,target->ipregno,ipval);
	if (errno) {
	    verror("could not reset EIP before pre handlers; skipping!\n");
	    probepoint->state = PROBE_BP_SET;
	    return -1;
	}

	vdebug(4,LOG_P_PROBEPOINT,"reset EIP to 0x%"PRIxREGVAL" for SW ",ipval);
	LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
	vdebugc(4,LOG_P_PROBEPOINT,"\n");
    }

    /*
     * Run pre-handlers if we have encountered our breakpoint for the
     * first time on this pass (which means we should not have an action
     * set!)
     */
    list_for_each_entry(probe,&probepoint->probes,probe) {
	if (probe->enabled) {
	    if (probe->pre_handler) {
		vdebug(4,LOG_P_PROBEPOINT,"running pre handler at ");
		LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
		vdebugc(4,LOG_P_PROBEPOINT,"\n");

		if (probe->pre_handler(probe,probe->handler_data,probe))
		    probe_disable(probe);
	    }
	    else if (0 && probe->sinks) {
		vdebug(4,LOG_P_PROBEPOINT,
		       "running default probe sink pre_handler at ");
		LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
		vdebugc(4,LOG_P_PROBEPOINT,"\n");
		probe_do_sink_pre_handlers(probe,NULL,probe);
	    }
	    doit = 1;
	}
    }

    /* Restore ip register if we ran a handler. */
    if (doit) {
	errno = 0;
	target_write_reg(target,target->ipregno,ipval);
	if (errno) {
	    verror("could not reset EIP after pre handlers; skipping!\n");
	    probepoint->state = PROBE_BP_SET;
	    return -1;
	}
        
	vdebug(5,LOG_P_PROBEPOINT,
	       "ip 0x%"PRIxREGVAL" restored after pre handlers at ",ipval);
	LOGDUMPPROBEPOINT(5,LOG_P_PROBEPOINT,probepoint);
	vdebugc(5,LOG_P_PROBEPOINT,"\n");
    }

    /* We move back into the SET state before we do the next things. */
    probepoint->state = PROBE_BP_SET;

    /*
     * If we might have to run an action, do it!
     */
    handle_actions(probepoint);

    /*
     * If we did an action and its effects took the place of the
     * original instruction (obviated it), enable single stepping if needed.
     */
    if (probepoint->action) {
	/* If our action needs single steps to execute (i.e., we added
	 * some code and we want to step through it), do those.
	 */
	if (probepoint->action_needs_ssteps) {
	    /* NOTE: do the single step here; decrement the ssteps
	     * counter in the ss handler below.
	     */
	    /* Before we single step, we temporarily disable any
	     * hardware breakpoints!
	     */
	    vdebug(4,LOG_P_PROBEPOINT,"%d ssteps to do for ",
		   probepoint->action_needs_ssteps);
	    LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
	    vdebugc(4,LOG_P_PROBEPOINT,"\n");

	    if (target_disable_hw_breakpoints(target) < 0) {
		verror("could not temporarily disable hw breakpoints while"
		       " sstep'ing; proceeding anyway!\n");
	    }
	    if (target_singlestep(target) < 0) {
		verror("could not single step target for action;"
		       " restoring BP if necessary!\n");
	
		if (target_singlestep_end(target))
		    verror("could not stop single stepping target"
			   " after failed sstep for action!\n");

		if (probepoint->action_orig_mem
		    && target_write_addr(target,probepoint->addr,
					 probepoint->action_orig_mem_len,
					 probepoint->action_orig_mem,NULL) \
		    != probepoint->action_orig_mem_len) {
		    verror("could not restore orig code that action"
			   " replaced; assuming breakpoint is left in place and"
			   " skipping single step, but badness will ensue!");
		}

		if (target_enable_hw_breakpoints(target) < 0) {
		    verror("could not enable hw breakpoints after failed"
			   " sstep; proceeding anyway!\n");
		}

		probepoint->action_needs_ssteps = 0;
		probepoint->state = PROBE_BP_SET;
	    }
	    else {
		/* leave the state as action running */
		probepoint->state = PROBE_ACTION_RUNNING;
		target->sstep_probepoint = probepoint;

		vdebug(4,LOG_P_PROBEPOINT,"sstep for ");
		LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
		vdebugc(4,LOG_P_PROBEPOINT,"\n");

		return 0;
	    }
	}
	else if (0) {
	    /*
	     * Actually, we don't need to do this because handle_actions
	     * would have removed any code it inserted, unless there was
	     * an error.  I think.
	     */

	    /* If there was an action and it modified code, restore the
	     * original code it replaced.  This might not include the
	     * breakpoint if it was software (well, it should because
	     * this is the first action handled that replaced code
	     * because we're in the BP handler; the ss handler will have
	     * to replace the saved code, and replace the breakpoint --
	     * yes, this is correct).
	     */
	    if (probepoint->action_orig_mem) {
		if (target_write_addr(target,probepoint->addr,
				      probepoint->action_orig_mem_len,
				      probepoint->action_orig_mem,NULL) \
		    != probepoint->action_orig_mem_len) {
		    verror("could not restore orig code that action replaced;"
			   " continuing, but badness will ensue!");
		    free(probepoint->action_orig_mem);
		    probepoint->action_orig_mem = NULL;
		}
		probepoint->state = PROBE_BP_SET;
	    }
	}
    }
    else {
	/* Now it is simple, now that we've handled actions.  If we're
	 * hardware and there are no enabled probes with post-handlers,
	 * single step; otherwise, just proceed.  If we're software,
	 * *always* single step after replacing the original
	 * instruction.
	 */
	doit = 0;
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

		vdebug(4,LOG_P_PROBEPOINT,"skipping sstep for HW ");
		LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
		vdebugc(4,LOG_P_PROBEPOINT,"; no post handlers\n");
	    }
	}

	/* If we're software, replace the original; AND (and if we're
	 * hardware and there and enabled post-handlers) single step.
	 */
	if (probepoint->style == PROBEPOINT_SW) {
	    /* Restore the original instruction. */
	    vdebug(4,LOG_P_PROBEPOINT,"restoring orig instr for SW ");
	    LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
	    vdebugc(4,LOG_P_PROBEPOINT,"\n");

	    if (target_write_addr(target,probepoint->addr,
				  probepoint->breakpoint_orig_mem_len,
				  probepoint->breakpoint_orig_mem,NULL) \
		!= probepoint->breakpoint_orig_mem_len) {
		verror("could not restore orig code that breakpoint"
		       " replaced; assuming breakpoint is left in place and"
		       " skipping single step, but badness will ensue!");
		probepoint->state = PROBE_BP_SET;
	    }
	    else
		doit = 1;
	}

	if (doit) {
	    /* NOTE: do the single step here; decrement the ssteps
	     * counter in the ss handler below.
	     */
	    vdebug(4,LOG_P_PROBEPOINT,"doing sstep for ");
	    LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
	    vdebugc(4,LOG_P_PROBEPOINT,"\n");

	    /* Before we single step, we temporarily disable any
	     * hardware breakpoints!
	     */
	    if (target_disable_hw_breakpoints(target) < 0) {
		verror("could not temporarily disable hw breakpoints before"
		       " sstep'ing; proceeding anyway!\n");
	    }

	    probepoint->state = PROBE_BP_HANDLING;
	    target->sstep_probepoint = probepoint;
	    if (target_singlestep(target) < 0) {
		if (probepoint->style == PROBEPOINT_HW) {
		    verror("could not single step target after BP;"
			   " stopping single step and restoring BP!\n");

		    if (target_singlestep_end(target))
			verror("could not stop single stepping target"
			       " after failed sstep for breakpoint!\n");

		    probepoint->state = PROBE_BP_SET;
		}
		else {
		    verror("could not single step target after BP;"
			   " stopping single step and restoring BP!\n");

		    if (target_singlestep_end(target))
			verror("could not stop single stepping target"
			       " after failed sstep for breakpoint!\n");

		    if (target_enable_hw_breakpoints(target) < 0) {
			verror("could not enable hw breakpoints after failed"
			       " sstep; proceeding anyway!\n");
		    }

		    if (target_write_addr(target,probepoint->addr,
					  probepoint->breakpoint_orig_mem_len,
					  probepoint->breakpoint_orig_mem,NULL) \
			!= probepoint->breakpoint_orig_mem_len) {
			verror("could not restore orig code that breakpoint"
			       " replaced; assuming breakpoint is left in place and"
			       " skipping single step, but badness will ensue!");
		    }
		}
		/* If we were supposed to single step, and it failed,
		 * the best we can do is act like the BP is still set.
		 */
		probepoint->state = PROBE_BP_SET;
		target->sstep_probepoint = NULL;
	    }
	    else {
		/* If single step init succeeded, let the ss handler take
		 * over.
		 */
		vdebug(4,LOG_P_PROBEPOINT,"sstep command succeeded for ");
		LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
		vdebugc(4,LOG_P_PROBEPOINT,"\n");

		return 0;
	    }
	}
    }

    /*
     * Just continue on...
     */
    target_resume(target);

    return 0;
}

/*
 * The goal of this function is to handle our single step.  We can
 * arrive here due to 1) an action that needed a single step; 2) a
 * software breakpoint that needed a single step; or 3) a hardware
 * breakpoint that needed a single step because it had enabled probes
 * with post-handlers.  2) and 3) are handled the same way.
 *
 * Basically, if our action needs more single steps, just keep doing
 * them and return.
 *
 * Otherwise, if we have more actions, do whatever they need us to do,
 * just like in the breakpoint handler.
 *
 * Otherwise, run our post handlers, then if software, re-insert the
 * breakpoint.
 *
 * Finally, once we know we aren't doing *more* single stepping,
 * re-enable hardware breakpoints.
 */
int probepoint_ss_handler(struct target *target,
			  struct probepoint *probepoint) {
    struct probe *probe;
    struct action *action;
    struct action *taction;

    /* First, if we were running an action that needed single stepping,
     * decrement the single step counter.
     */
    if (probepoint->action && probepoint->action_needs_ssteps)
	--probepoint->action_needs_ssteps;

    /* Otherwise, find more actions.  If we need to do more single steps
     * to support them, do it.
     */
    handle_actions(probepoint);
    if (probepoint->action_needs_ssteps) {
	/* Force a singlestep. */
	if (target_singlestep(target) < 0) {
	    verror("could not single step target for action;"
		   " removing action!\n");
	
	    if (target_singlestep_end(target))
		verror("could not stop single stepping target"
		       " after failed sstep for action!\n");

	    if (probepoint->action_orig_mem) {
		if (target_write_addr(target,probepoint->addr,
				      probepoint->action_orig_mem_len,
				      probepoint->action_orig_mem,NULL) \
		    != probepoint->action_orig_mem_len) {
		    verror("could not restore orig code that action replaced;"
			   " continuing, but badness will ensue!");
		    free(probepoint->action_orig_mem);
		    probepoint->action_orig_mem = NULL;
		}
	    }

	    if (target_enable_hw_breakpoints(target) < 0) {
		verror("could not enable hw breakpoints after failed"
		       " sstep; proceeding anyway!\n");
	    }

	    probepoint->action_needs_ssteps = 0;
	    probepoint->state = PROBE_BP_SET;

	    /* Don't run post handlers on error! */
	    target_resume(target);

	    return -1;
	}
	else {
	    /* Next single step is in place, so let it keep going. */
	    return 0;
	}
    }

    /*
     * Run post-handlers
     */
    list_for_each_entry(probe,&probepoint->probes,probe) {
	if (probe->enabled) {
	    if (probe->post_handler) {
		vdebug(4,LOG_P_PROBEPOINT,"running post handler at ");
		LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
		vdebugc(4,LOG_P_PROBEPOINT,"\n");

		if (probe->post_handler(probe,probe->handler_data,probe)) 
		    probe_disable(probe);
	    }
	    else if (0 && probe->sinks) {
		vdebug(4,LOG_P_PROBEPOINT,
		       "running default probe sink pre_handler at ");
		LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
		vdebugc(4,LOG_P_PROBEPOINT,"\n");

		probe_do_sink_post_handlers(probe,NULL,probe);
	    }
	}
    }
    
    /*
     * We're done handling this breakpoint!  Leave single step; if SW
     * probepoint, replace breakpoint; reenable hardware breakpoints.
     */
    if (target_singlestep_end(target))
	verror("could not stop single stepping target; continuing anyway!\n");

    target->sstep_probepoint = NULL;

    if (probepoint->style == PROBEPOINT_SW) {
	/* Re-inject a breakpoint for the next round */
	if (target_write_addr(target,probepoint->addr,
			      target->breakpoint_instrs_len,
			      target->breakpoint_instrs,NULL) \
	    != target->breakpoint_instrs_len) {
	    verror("could not write breakpoint instrs for bp re-insert, disabling!\n");
	    probepoint->state = PROBE_DISABLED;
	    free(probepoint->breakpoint_orig_mem);
	}
	else 
	    probepoint->state = PROBE_BP_SET;
    }
    else 
	probepoint->state = PROBE_BP_SET;

    /* cleanup oneshot actions! */
    list_for_each_entry_safe(action,taction,&probepoint->actions,action) {
	if (action->whence == ACTION_ONESHOT) {
	    if (action->autofree)
		action_destroy(action);
	    else 
		action_cancel(action);
	}
    }

    /*
     * Enable hw breakpoints since we're done single stepping...
     */
    if (target_enable_hw_breakpoints(target) < 0) {
	verror("could not enable hw breakpoints after failed"
	       " sstep; proceeding anyway!\n");
    }

    /*
     * Just continue on...
     */
    target_resume(target);

    return 0;
}

/*
 * Basically, we insert and remove action code as necessary.  We don't
 * do any single stepping.  If the action executing is done, we remove
 * its code, if any.  If there is another to execute, we do it,
 * inserting its code as necessary.
 *
 * Do we need to handle changing EIP as we execute code?  Probably
 * should just reset it to the probepoint addr (i.e., wherever we load
 * code!).
 */
static int handle_actions(struct probepoint *probepoint) {
    struct target *target = probepoint->target;
    struct action *action;
    REGVAL rval;
    void *local_ret_instrs;
    unsigned int local_ret_instrs_len;
    unsigned int local_ret_instr_count;

    /* Reset if we are executing actions for this BP right after hit. */
    if (probepoint->state == PROBE_BP_SET) {
	vdebug(3,LOG_P_ACTION,
	       "resetting actions state after bp hit at ");
	LOGDUMPPROBEPOINT(3,LOG_P_ACTION,probepoint);
	vdebugc(3,LOG_P_ACTION,"\n");

	probepoint->action = NULL;
	probepoint->action_obviates_orig = 0;
	probepoint->action_needs_ssteps = 0;
	probepoint->action_orig_mem = NULL;
    }

    /*
     * If we need to keep stepping through this action, OR if it is
     * done, but there are more actions to do... then do them right
     * away!
     */
    if (probepoint->state == PROBE_ACTION_RUNNING) {
	/* XXX: check later if other kinds are "done" */
	if (!probepoint->action_needs_ssteps
	    && probepoint->action_orig_mem) {
	    /* Restore whatever was under the action code (i.e., the
	     * breakpoint and anything else).
	     */
	    vdebug(3,LOG_P_ACTION,
		   "action finished at ");
	    LOGDUMPPROBEPOINT(3,LOG_P_ACTION,probepoint);
	    vdebugc(3,LOG_P_ACTION,"; restoring code\n");

	    if (target_write_addr(target,probepoint->addr,
				  probepoint->action_orig_mem_len,
				  probepoint->action_orig_mem,NULL) \
		!= probepoint->action_orig_mem_len) {
		verror("could not restore orignal under-action code, disabling probe!\n");
		probepoint->state = PROBE_DISABLED;
		free(probepoint->action_orig_mem);
		probepoint->action_orig_mem = NULL;
	    }
	    else {
		probepoint->state = PROBE_ACTION_DONE;
	    }
	}
	else if (probepoint->action_needs_ssteps) {
	    vdebug(3,LOG_P_ACTION,
		   "action single step continues at ");
	    LOGDUMPPROBEPOINT(3,LOG_P_ACTION,probepoint);
	    vdebug(3,LOG_P_ACTION,"\n");
	    return 1;
	}
    }

    if (list_empty(&probepoint->actions)) {
	vdebug(3,LOG_P_ACTION,
	       "no actions to run at ");
	LOGDUMPPROBEPOINT(3,LOG_P_ACTION,probepoint);
	vdebugc(3,LOG_P_ACTION,"\n");
	return 0;
    }

    /*
     * If there is a "current" action, we want to continue with the action
     * after that. Otherwise we want to start with the first action on the
     * list.
     *
     * XXX the "otherwise" case is why the first param of the list_entry
     * is strange: we treat the header embedded in the probepoint struct
     * as though it were embedded in an action struct so that when the
     * list_blahblah_continue() operator takes the "next" element, it
     * actually gets the first action on the probepoint list. This is a
     * note to myself so that I don't try to "fix" this code again,
     * thereby breaking it!
     */
    if (probepoint->action) 
	action = probepoint->action;
    else 
	action = list_entry(&probepoint->actions,typeof(*action),action);
    list_for_each_entry_continue(action,&probepoint->actions,action) {
	if (!action->probe->enabled) {
	    vdebug(3,LOG_P_ACTION,
		   "skipping disabled probe at ");
	    LOGDUMPPROBEPOINT(3,LOG_P_ACTION,probepoint);
	    vdebugc(3,LOG_P_ACTION,"\n");
	    continue;
	}

	if (action->type == ACTION_CUSTOMCODE) {
	    /*
	     * Need to:
	     *  - copy code in
	     *  - single step until we're to the IP of
	     *    breakpoint+codelen, then restore orig code and BP;
	     *  <OR>
	     *  - restore breakpoint and just let code exec (no
	     *    post handler or any other actions!)
	     */
	}
	else if (action->type == ACTION_RETURN) {
	    if (probepoint->action_obviates_orig) {
		vwarn("WARNING: cannot run return action; something else"
		      " already changed control flow!\n");
		continue;
	    }

	    vdebug(3,LOG_P_ACTION,
		   "starting return action at ");
	    LOGDUMPPROBEPOINT(3,LOG_P_ACTION,probepoint);
	    vdebugc(3,LOG_P_ACTION,"\n");

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
		    vdebug(3,LOG_P_ACTION,
			   "setting ESP to EBP and returning (prologue uses EBP) at ");
		    LOGDUMPPROBEPOINT(3,LOG_P_ACTION,probepoint);
		    vdebugc(3,LOG_P_ACTION,"\n");

		    errno = 0;
		    rval = target_read_reg(target,target->fbregno);
		    if (errno) {
			verror("read EBP failed; disabling probepoint!\n");
			probepoint->state = PROBE_DISABLED;
			free(probepoint->action_orig_mem);
			probepoint->action = NULL;
			probepoint->action_orig_mem = NULL;
			probepoint->action_needs_ssteps = 0;

			return 0;
		    }

		    if (target_write_reg(target,target->spregno,rval)) {
			verror("set ESP to EBP failed; disabling probepoint!\n");
			probepoint->state = PROBE_DISABLED;
			free(probepoint->action_orig_mem);
			probepoint->action = NULL;
			probepoint->action_orig_mem = NULL;
			probepoint->action_needs_ssteps = 0;

			return 0;
		    }

		    local_ret_instrs = target->full_ret_instrs;
		    local_ret_instrs_len = target->full_ret_instrs_len;
		    local_ret_instr_count = target->full_ret_instr_count;
		}
		else {
		    vdebug(3,LOG_P_ACTION,
			   "undoing prologue ESP changes (%d) and returning at ",
			   action->detail.ret.prologue_sp_offset);
		    LOGDUMPPROBEPOINT(3,LOG_P_ACTION,probepoint);
		    vdebugc(3,LOG_P_ACTION,"\n");

		    errno = 0;
		    rval = target_read_reg(target,target->spregno);
		    if (errno) {
			verror("read ESP failed; disabling probepoint!\n");
			probepoint->state = PROBE_DISABLED;
			free(probepoint->action_orig_mem);
			probepoint->action = NULL;
			probepoint->action_orig_mem = NULL;
			probepoint->action_needs_ssteps = 0;

			return 0;
		    }

		    if (target_write_reg(target,target->spregno,
					 rval + (REGVAL)-action->detail.ret.prologue_sp_offset)) {
			verror("undoing prologue ESP changes failed; disabling probepoint!\n");
			probepoint->state = PROBE_DISABLED;
			free(probepoint->action_orig_mem);
			probepoint->action = NULL;
			probepoint->action_orig_mem = NULL;
			probepoint->action_needs_ssteps = 0;

			return 0;
		    }

		    local_ret_instrs = target->ret_instrs;
		    local_ret_instrs_len = target->ret_instrs_len;
		    local_ret_instr_count = target->ret_instr_count;
		}
	    }
	    else {
		local_ret_instrs = target->ret_instrs;
		local_ret_instrs_len = target->ret_instrs_len;
		local_ret_instr_count = target->ret_instr_count;
	    }

	    /*
	     * Save the original code at the probepoint, and replace it
	     * with the action code, and set EIP to the probepoint.
	     */

	    /*
	     * If our prologue used a frame pointer, we have to do a
	     * full return (LEAVE,RET).  Otherwise, just RET.
	     */

	    probepoint->action_orig_mem = malloc(local_ret_instrs_len);
	    probepoint->action_orig_mem_len = local_ret_instrs_len;
	    if (!target_read_addr(target,probepoint->addr,
				  probepoint->action_orig_mem_len,
				  probepoint->action_orig_mem,NULL)) {
		verror("could not save original under-action code; disabling probepoint!\n");
		probepoint->state = PROBE_DISABLED;
		free(probepoint->action_orig_mem);
		probepoint->action = NULL;
		probepoint->action_orig_mem = NULL;
		probepoint->action_needs_ssteps = 0;

		return 0;
	    }
	    if (target_write_addr(target,probepoint->addr,
				  local_ret_instrs_len,
				  local_ret_instrs,NULL) \
		!= probepoint->action_orig_mem_len) {
		verror("could not insert action code; disabling probepoint!\n");
		probepoint->state = PROBE_DISABLED;
		free(probepoint->action_orig_mem);
		probepoint->action = NULL;
		probepoint->action_orig_mem = NULL;
		probepoint->action_needs_ssteps = 0;

		return 0;
	    }
	    if (target_write_reg(target,target->ipregno,probepoint->addr)) {
		verror("could not reset EIP for action code; disabling probepoint!\n");
		probepoint->state = PROBE_DISABLED;
		free(probepoint->action_orig_mem);
		probepoint->action = NULL;
		probepoint->action_orig_mem = NULL;
		probepoint->action_needs_ssteps = 0;

		return 0;
	    }

	    vdebug(3,LOG_P_ACTION,"ret(0x%"PRIxREGVAL") inserted at ",
		   action->detail.ret.retval);
	    LOGDUMPPROBEPOINT(3,LOG_P_ACTION,probepoint);
	    vdebugc(3,LOG_P_ACTION,"\n");

	    /*
	     * Break out of this loop, and don't do any more
	     * actions.  This action is the final one.
	     */
	    probepoint->action_obviates_orig = 1;
	    probepoint->action_needs_ssteps = local_ret_instr_count;
	    probepoint->action = action;
	    probepoint->state = PROBE_ACTION_RUNNING;

	    return 1;
	}
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
		 action_whence_t whence,int autofree) {
    struct action *lpc;
    unsigned char *code;
    unsigned int code_len = 0;
    struct probepoint *probepoint;
    struct target *target;

    action->autofree = autofree;

    if (action->probe != NULL) {
	verror("action already associated with probe!\n");
	return -1;
    }

    if (!probe->probepoint) {
	errno = EINVAL;
	verror("probe not attached to a probepoint!\n");
	return -1;
    }

    probepoint = probe->probepoint;
    target = probepoint->target;

    /* only allow one return action per probepoint */
    if (action->type == ACTION_RETURN) {
	list_for_each_entry(lpc,&probe->probepoint->actions,action) {
	    if (lpc->type == ACTION_RETURN) {
		verror("probepoint already has return action\n");
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
				      code_len,code,NULL)) {
		    vwarn("could not read prologue code; skipping disasm!\n");
		    free(code);
		    code = NULL;
		}
		else {
		    if (*code == 0x55) {
			free(code);
			action->detail.ret.prologue_uses_bp = 1;
			vdebug(3,LOG_P_ACTION,
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
			vdebug(3,LOG_P_ACTION,
			       "disassembled prologue for function %s: sp moved %d\n",
			       probepoint->bsymbol ? probepoint->bsymbol->lsymbol->symbol->name : "<UNKNOWN>",
			       action->detail.ret.prologue_sp_offset);
		    }
		}
	    }
	}
    }

    if (whence != ACTION_ONESHOT && whence != ACTION_REPEATPRE
	&& whence != ACTION_REPEATPOST) {
	verror("unknown whence %d for action\n",whence);
	return -1;
    }
    action->whence = whence;

    /*
     * Ok, we're safe; add to list!
     */
    list_add_tail(&action->action,&probe->probepoint->actions);
    action->probe = probe;

    return 0;
}

/*
 * Cancel an action.
 */
void action_cancel(struct action *action) {
    if (!action->probe)
	return;

    list_del(&action->action);
    action->probe = NULL;

    return;
}

/*
 * High-level actions that require little ASM knowledge.
 */
struct action *action_return(REGVAL retval) {
    struct action *action;

    action = (struct action *)malloc(sizeof(struct action));
    if (!action) {
	verror("could not malloc action: %s\n",strerror(errno));
	return NULL;
    }
    memset((void *)action,0,sizeof(*action));

    action->type = ACTION_RETURN;
    action->whence = ACTION_UNSCHED;
    INIT_LIST_HEAD(&action->action);

    action->detail.ret.retval = retval;

    return action;
}

/*
 * Low-level actions that require little ASM knowledge, and may or may
 * not be permitted.
 */
struct action *action_code(void **code,uint32_t len,uint32_t flags) {
    /* XXX: fill */
    return NULL;
}
struct action *action_regmod(REG regnum,REGVAL regval) {
    /* XXX: fill */
    return NULL;
}
struct action *action_memmod(ADDR destaddr,void *data,uint32_t len) {
    /* XXX: fill */
    return NULL;
}

/*
 * Destroy an action (and cancel it first if necessary!).
 */
void action_destroy(struct action *action) {
    unsigned int i;

    if (action->probe) 
	action_cancel(action);

    if (action->type == ACTION_CUSTOMCODE
	&& action->detail.code.instrs) {
	for (i = 0; i < action->detail.code.instrs_count; ++i) {
	    free(action->detail.code.instrs[i]);
	}
	free(action->detail.code.instrs);
    }
    else if (action->type == ACTION_MEMMOD
	     && action->detail.memmod.len) {
	free(action->detail.memmod.data);
    }

    free(action);
    return;
}
