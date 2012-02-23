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
    if ((pp)->lsymbol && (pp)->symbol_addr) { \
	vdebugc((dl),(lt),"probepoint(0x%"PRIxADDR" %s:%d) ", \
		(pp)->addr,(pp)->lsymbol->symbol->name, \
		(pp)->symbol_addr - (pp)->addr);	\
    } \
    else if ((pp)->lsymbol) { \
        vdebugc((dl),(lt),"probepoint(0x%"PRIxADDR" %s) ", \
	       (pp)->addr,(pp)->lsymbol->symbol->name); \
    } \
    else { \
        vdebugc((dl),(lt),"probepoint(0x%"PRIxADDR") ", \
	       (pp)->addr); \
    }

/**
 ** Data structure stuff.
 **/

static struct probe *probe_create(struct probepoint *probepoint,
				  probe_handler_t pre_handler,
				  probe_handler_t post_handler) {
    struct probe *probe;

    probe = (struct probe *)malloc(sizeof(*probe));
    if (!probe) {
        verror("failed to allocate a new probe\n");
        return NULL;
    }
    memset(probe,0,sizeof(*probe));
    
    probe->pre_handler = pre_handler;
    probe->post_handler = post_handler;
    probe->probepoint = probepoint;
    probe->enabled = 0; // disabled at first
    
    list_add_tail(&probe->probe,&probepoint->probes);

    vdebug(5,LOG_P_PROBE,"probe at ");
    LOGDUMPPROBEPOINT(5,LOG_P_PROBE,probe->probepoint);
    vdebugc(5,LOG_P_PROBE," added\n");

    return probe;
}

static void probe_free(struct probe *probe) {
    struct action *action;
    struct action *tmp;

    /* destroy any actions it might have */
    list_for_each_entry_safe(action,tmp,&probe->probepoint->actions,action) {
	if (probe == action->probe)
	    action_destroy(action);
    }

    list_del(&probe->probe);

    vdebug(5,LOG_P_PROBE,"probe at ");
    LOGDUMPPROBEPOINT(5,LOG_P_PROBE,probe->probepoint);
    vdebugc(5,LOG_P_PROBE," removed\n");

    free(probe);
}

static struct probepoint *probepoint_lookup(struct target *target,ADDR addr) {
    struct probepoint *retval = \
	(struct probepoint *)g_hash_table_lookup(target->probepoints,
						 (gpointer)addr);

    if (retval) {
	vdebug(9,LOG_P_PROBEPOINT,"found probepoint ");
	LOGDUMPPROBEPOINT(9,LOG_P_PROBEPOINT,retval);
	vdebugc(9,LOG_P_PROBEPOINT,"\n");
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
					      struct lsymbol *lsymbol,
					      ADDR symbol_addr) {
    struct probepoint *probepoint;

    probepoint = (struct probepoint *)malloc(sizeof(*probepoint));
    if (!probepoint) {
        verror("failed to allocate a new probepoint");
        return NULL;
    }
    memset(probepoint,0,sizeof(*probepoint));
    
    probepoint->addr = addr;
    probepoint->target = target;
    probepoint->state = PROBE_DISABLED;

    probepoint->type = type;
    probepoint->style = style;
    probepoint->whence = whence;
    probepoint->watchsize = watchsize;

    probepoint->lsymbol = lsymbol;
    probepoint->symbol_addr = symbol_addr;
    
    probepoint->debugregnum = -1;

    INIT_LIST_HEAD(&probepoint->probes);
    INIT_LIST_HEAD(&probepoint->actions);

    g_hash_table_insert(target->probepoints,(gpointer)addr,probepoint);

    vdebug(5,LOG_P_PROBEPOINT,"");
    LOGDUMPPROBEPOINT(5,LOG_P_PROBEPOINT,probepoint);
    vdebugc(5,LOG_P_PROBEPOINT," added\n");

    return probepoint;
}

static struct probepoint *probepoint_create_break(struct target *target,
						  ADDR addr,
						  struct memrange *range,
						  probepoint_style_t style,
						  struct lsymbol *lsymbol,
						  ADDR symbol_addr) {
    struct probepoint *probepoint = __probepoint_create(target,addr,range,
							PROBEPOINT_BREAK,style,
							PROBEPOINT_EXEC,0,
							lsymbol,symbol_addr);
    return probepoint;
}

static struct probepoint *probepoint_create_watch(struct target *target,
						  ADDR addr,
						  struct memrange *range,
						  probepoint_style_t style,
						  probepoint_whence_t whence,
						  probepoint_watchsize_t watchsize,
						  struct lsymbol *lsymbol,
						  ADDR symbol_addr) {
    if (style == PROBEPOINT_SW) {
	verror("software watchpoints not supported right now!\n");
	errno = EINVAL;
	return NULL;
    }

    return __probepoint_create(target,addr,range,PROBEPOINT_WATCH,style,
			       whence,watchsize,lsymbol,symbol_addr);
}

static void probepoint_free_internal(struct probepoint *probepoint) {
    struct probe *probe;
    struct probe *ptmp;
    struct action *action;
    struct action *atmp;

    /* Destroy any actions it might have (probe_free does this too,
     * but this is much more efficient.
     */
    list_for_each_entry_safe(action,atmp,&probepoint->actions,action) 
	action_destroy(action);

    /* Destroy the probes. */
    list_for_each_entry_safe(probe,ptmp,&probepoint->probes,probe) 
	probe_free(probe);
}

static void probepoint_free(struct probepoint *probepoint) {
    probepoint_free_internal(probepoint);

    g_hash_table_remove(probepoint->target->probepoints,
			(gpointer)probepoint->addr);

    vdebug(5,LOG_P_PROBEPOINT,"freed probepoint ");
    LOGDUMPPROBEPOINT(5,LOG_P_PROBEPOINT,probepoint);
    vdebugc(5,LOG_P_PROBEPOINT,"\n");

    free(probepoint);
}

/* We need this in case the target needs to quickly remove all the
 * probes (i.e., on a signal) -- and in that case, we have to let the
 * target remove the probepoint from its hashtables itself.
 */
void probepoint_free_ext(struct probepoint *probepoint) {
    probepoint_free_internal(probepoint);

    vdebug(5,LOG_P_PROBEPOINT,"freed probepoint ");
    LOGDUMPPROBEPOINT(5,LOG_P_PROBEPOINT,probepoint);
    vdebugc(5,LOG_P_PROBEPOINT," (ext)\n");

    free(probepoint);
}

/**
 ** Probe unregistration/registration.
 **/

static int __probepoint_remove(struct probepoint *probepoint) {
    struct target *target;
    int ret;

    target = probepoint->target;

    vdebug(5,LOG_P_PROBEPOINT,"removing probepoint ");
    LOGDUMPPROBEPOINT(5,LOG_P_PROBEPOINT,probepoint);
    vdebugc(5,LOG_P_PROBEPOINT,"\n");

    /* Check if the probepoint has already been inserted; we do not want
     * to backup a previously inserted breakpoint.
     */
    if (probepoint->state == PROBE_DISABLED) {
	/* return success, the probepoint is already removed */
	vdebug(7,LOG_P_PROBEPOINT,"probepoint ");
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
		vdebug(4,LOG_P_PROBEPOINT,"removed HW breakpoint ");
		LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
		vdebugc(4,LOG_P_PROBEPOINT,"\n");
	    }
	}
	else {
	    if ((ret = target_unset_hw_watchpoint(target,
						  probepoint->debugregnum))) {
		verror("failure while removing hw watchpoint; cannot recover!\n");
	    }
	    else {
		vdebug(4,LOG_P_PROBEPOINT,"removed HW watchpoint ");
		LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
		vdebugc(4,LOG_P_PROBEPOINT,"\n");
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

	vdebug(4,LOG_P_PROBEPOINT,"removed SW breakpoint ");
	LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
	vdebugc(4,LOG_P_PROBEPOINT,"\n");

	free(probepoint->breakpoint_orig_mem);
	probepoint->breakpoint_orig_mem = NULL;
    }

    probepoint->state = PROBE_DISABLED;

    vdebug(2,LOG_P_PROBEPOINT,"");
    LOGDUMPPROBEPOINT(2,LOG_P_PROBEPOINT,probepoint);
    vdebugc(2,LOG_P_PROBEPOINT," removed\n");

    return 0;
}

/*
 * We never fail to remove the probe; this function only returns errors
 * if it tried to remove the underlying probepoint and failed.
 */
static int __probe_unregister(struct probe *probe,int force) {
    struct probepoint *probepoint = probe->probepoint;
    struct target *target = probepoint->target;
    int action_did_obviate = 0;
    target_status_t status;

    vdebug(5,LOG_P_PROBE,"unregistering probe at ");
    LOGDUMPPROBEPOINT(5,LOG_P_PROBE,probepoint);
    vdebugc(5,LOG_P_PROBE,"\n");

    /* Target must be paused before we do anything. */
    status = target_status(target);
    if (status != TSTATUS_PAUSED) {
        verror("target not paused (%d), cannot remove!\n",status);
	errno = EINVAL;
	return -1;
    }

    /* Free the probe first of all; current state of the probepoint
     * doesn't matter for this operation, BECAUSE we traverse the list
     * of pre/post handlers *safely* to guard against deletes here.
     *
     * Yes, this means a pre/post handler can delete the probe.
     */
    probe_free(probe);

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
	free(probepoint);

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
	    }
	    else if (probepoint->style == PROBEPOINT_HW) {
		if (target_unset_hw_breakpoint(target,probepoint->debugregnum)) {
		    verror("could not remove hardware breakpoint; cannot repair!\n");
		}
	    }

	    /* Reset EIP to the right thing. */
	    if (probepoint->state == PROBE_BP_HANDLING && !action_did_obviate) {
		/* We still must execute the original instruction. */
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
    return __probe_unregister(probe,force);
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

	if (__probe_unregister(probelist[i],force)) {
	    ++retval;
	}
	probelist[i] = NULL;
    }

    return retval;
}

static int __probepoint_insert(struct probepoint *probepoint) {
    struct target *target;
    int ret;
    REG reg;

    target = probepoint->target;

    vdebug(5,LOG_P_PROBEPOINT,"inserting ");
    LOGDUMPPROBEPOINT(5,LOG_P_PROBEPOINT,probepoint);
    vdebugc(5,LOG_P_PROBEPOINT,"\n");

    /* Check if the probepoint has already been inserted; we do not want
     * to backup a previously inserted breakpoint.
     */
    if (probepoint->state != PROBE_DISABLED) {
	/* return success, the probepoint is already being managed */
	vdebug(9,LOG_P_PROBEPOINT," ");
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
	    LOGDUMPPROBEPOINT(3,LOG_P_PROBEPOINT,probepoint);
	    vdebugc(3,LOG_P_PROBEPOINT,"\n");
	}
	else {
	    probepoint->style = PROBEPOINT_SW;

	    vdebug(3,LOG_P_PROBEPOINT,"using SW for FASTEST ");
	    LOGDUMPPROBEPOINT(3,LOG_P_PROBEPOINT,probepoint);
	    vdebugc(3,LOG_P_PROBEPOINT,"\n");
	}
    }
    else if (probepoint->style == PROBEPOINT_HW) {
	if ((reg = target_get_unused_debug_reg(target)) > -1) {
	    probepoint->debugregnum = reg;

	    vdebug(3,LOG_P_PROBEPOINT,"using HW reg %d for ",reg);
	    LOGDUMPPROBEPOINT(3,LOG_P_PROBEPOINT,probepoint);
	    vdebugc(3,LOG_P_PROBEPOINT,"\n");
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
		vdebug(7,LOG_P_PROBEPOINT,"inserted hw breakpoint at ");
		LOGDUMPPROBEPOINT(7,LOG_P_PROBEPOINT,probepoint);
		vdebugc(7,LOG_P_PROBEPOINT,"\n");
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
		vdebug(7,LOG_P_PROBEPOINT,"inserted hw watchpoint at ");
		LOGDUMPPROBEPOINT(7,LOG_P_PROBEPOINT,probepoint);
		vdebugc(7,LOG_P_PROBEPOINT,"\n");
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
	    return 1;
	}

	vdebug(3,LOG_P_PROBEPOINT,"saved orig mem under SW ");
	LOGDUMPPROBEPOINT(3,LOG_P_PROBEPOINT,probepoint);
	vdebugc(3,LOG_P_PROBEPOINT,"\n");

	if (target_write_addr(target,probepoint->addr,
			      target->breakpoint_instrs_len,
			      target->breakpoint_instrs,NULL) \
	    != target->breakpoint_instrs_len) {
	    verror("could not write breakpoint instrs for bp insert\n");
	    probepoint->state = PROBE_DISABLED;
	    free(probepoint->breakpoint_orig_mem);
	    return 1;
	}

	vdebug(3,LOG_P_PROBEPOINT,"inserted SW ");
	LOGDUMPPROBEPOINT(3,LOG_P_PROBEPOINT,probepoint);
	vdebugc(3,LOG_P_PROBEPOINT,"\n");
    }

    probepoint->state = PROBE_BP_SET;

    vdebug(2,LOG_P_PROBEPOINT,"");
    LOGDUMPPROBEPOINT(2,LOG_P_PROBEPOINT,probepoint);
    vdebugc(2,LOG_P_PROBEPOINT," inserted\n");

    return 0;
}

struct probe *__probe_register(struct target *target,ADDR addr,
			       struct memrange *range,
			       probepoint_type_t type,
			       probepoint_style_t style,
			       probepoint_whence_t whence,
			       probepoint_watchsize_t watchsize,
			       probe_handler_t pre_handler,
			       probe_handler_t post_handler,
			       struct lsymbol *lsymbol,
			       ADDR symbol_addr) {
    struct probe *probe;
    struct probepoint *probepoint;
    int created = 0;

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
	    return NULL;
	}
    }
    else {
        if (type == PROBEPOINT_BREAK) {
	    if (!(probepoint = probepoint_create_break(target,addr,range,style,
						       lsymbol,symbol_addr))) {
		verror("could not create breakpoint for 0x%"PRIxADDR"\n",addr);
		return NULL;
	    }
	}
	else {
	    if (!(probepoint = probepoint_create_watch(target,addr,range,
						       style,whence,watchsize,
						       lsymbol,symbol_addr))) {
		verror("could not create breakpoint for 0x%"PRIxADDR"\n",addr);
		return NULL;
	    }
	}

	created = 1;
    }

    /* Create the probe and attach it to the probepoint. */
    probe = probe_create(probepoint,pre_handler,post_handler);
    if (!probe) {
	verror("could not create probe for 0x%"PRIxADDR"\n",addr);
	if (created)
	    probepoint_free(probepoint);
        return NULL;
    }

    /* Inject the probepoint. */
    if (__probepoint_insert(probepoint)) {
	verror("could not insert probepoint at 0x%"PRIxADDR"\n",addr);
	probe_free(probe);
	if (created)
	    probepoint_free(probepoint);
	return NULL;
    }

    probe->enabled = 1;

    return probe;
}

struct probe *probe_register_break(struct target *target,ADDR addr,
				   struct memrange *range,
				   probepoint_style_t style,
				   probe_handler_t pre_handler,
				   probe_handler_t post_handler,
				   struct lsymbol *lsymbol,ADDR symbol_addr) {
    return __probe_register(target,addr,range,PROBEPOINT_BREAK,style,
			    PROBEPOINT_EXEC,0,pre_handler,post_handler,
			    lsymbol,symbol_addr);
}

struct probe *probe_register_watch(struct target *target,ADDR addr,
				   struct memrange *range,
				   probepoint_style_t style,
				   probepoint_whence_t whence,
				   probepoint_watchsize_t watchsize,
				   probe_handler_t pre_handler,
				   probe_handler_t post_handler,
				   struct lsymbol *lsymbol,ADDR symbol_addr) {
    return __probe_register(target,addr,range,PROBEPOINT_WATCH,style,
			    whence,watchsize,pre_handler,post_handler,
			    lsymbol,symbol_addr);
}

int probe_register_batch(struct target *target,ADDR *addrlist,int listlen,
			 probepoint_type_t type,probepoint_style_t style,
			 probepoint_whence_t whence,
			 probepoint_watchsize_t watchsize,
			 probe_handler_t pre_handler,
			 probe_handler_t post_handler,
			 struct probe **probelist,
			 int failureaction) {
    int i;
    int retval = 0;

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

	if (!(probelist[i] = __probe_register(target,addrlist[i],NULL,type,style,
					      whence,watchsize,
					      pre_handler,post_handler,
					      NULL,0))) {
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
	__probe_unregister(probelist[i],0);
    }

 out:
    return retval;
}

probepoint_watchsize_t probepoint_closest_watchsize(int size) {
    if (size <= 1)
	return PROBEPOINT_L0;
    else if (size <= 2)
	return PROBEPOINT_L2;
    else 
	return PROBEPOINT_L4;
}

/*
 * Disables a running probe. When disabled, both pre- and post-handlers are 
 * ignored until the probe is enabled back.
 * Returns a value of 0 upon successful completion, or a value of -1 if the
 * given handle is invalid.
 * NOTE: To enable a probe, call enable_probe() function below.
 */
int probe_disable(struct probe *probe) {
    probe->enabled = 0;
    return 0;
}

/*
 * Enables an inactive probe.
 * Returns a value of 0 upon successful completion, or a value of -1 if the
 * given handle is invalid.
 */
int probe_enable(struct probe *probe) {
    probe->enabled = 1;
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
	if (probe->enabled && probe->pre_handler) {
	    vdebug(4,LOG_P_PROBEPOINT,"running pre handler at ");
	    LOGDUMPPROBEPOINT(4,LOG_P_PROBEPOINT,probepoint);
	    vdebugc(4,LOG_P_PROBEPOINT,"\n");

	    probe->enabled = !probe->pre_handler(probe);
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
		if (probe->enabled && probe->post_handler) {
		    doit = 1;
		    break;
		}
	    }
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
	if (probe->enabled && probe->post_handler)
	    probe->enabled = !probe->post_handler(probe);
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
	if (action->whence == ACTION_ONESHOT)
	    action_cancel(action);
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
		 action_whence_t whence) {
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
			       probe->probepoint->lsymbol->symbol->name);
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
			       probe->probepoint->lsymbol->symbol->name,
			       action->detail.ret.prologue_sp_offset);
		    }
		}
	    }
	}
	else {
	    /* Check the first byte at addr; if it is 0x55, we're using
	     * frame pointers and we don't need to analyze the prologue.
	     */
	    code_len = 1;
	    code = (unsigned char *)malloc(code_len);
	    memset(code,0,code_len);

	    if (!target_read_addr(target,probepoint->symbol_addr,
				  code_len,code,NULL)) {
		vwarn("could not read first byte of prologue code in non-prologue frame pointer usage check!\n");
		free(code);
		return -1;
	    }
	    else if (*code != 0x55) {
		verror("cannot schedule a return from a function that lacks prologue info and does not use frame pointers; your stack would be smashed!\n");
		free(code);
		return -1;
	    }

	    free(code);
	    action->detail.ret.prologue_uses_bp = 1;
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
