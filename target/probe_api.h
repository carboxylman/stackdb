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
struct action;
struct target;
struct memrange;
struct lsymbol;

typedef int (*probe_handler_t)(struct probe *probe);

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
    PROBEPOINT_L0 = 0,
    PROBEPOINT_L2 = 1,
    PROBEPOINT_L4 = 3,
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

/* 
 * Registers a probe at a given virtual address in a domain, with pre- and
 * post-handlers.
 * If the probe has been successfully registered, the function will return a
 * new handle to the probe. Alternatively, the function can return a value of
 * -1 indicating that it failed to register the probe.
 */
struct probe *probe_register_break(struct target *target,ADDR addr,
				   struct memrange *range,
				   probepoint_style_t style,
				   probe_handler_t pre_handler,
				   probe_handler_t post_handler,
				   struct lsymbol *lsymbol,ADDR symbol_addr);
struct probe *probe_register_watch(struct target *target,ADDR addr,
				   struct memrange *range,
				   probepoint_style_t style,
				   probepoint_whence_t whence,
				   probepoint_watchsize_t watchsize,
				   probe_handler_t pre_handler,
				   probe_handler_t post_handler,
				   struct lsymbol *lsymbol,ADDR symbol_addr);

struct probe *probe_register_child(struct probe *parent,OFFSET offset,
				   probepoint_style_t style,
				   probe_handler_t pre_handler,
				   probe_handler_t post_handler);

int probe_register_batch(struct target *target,ADDR *addrlist,int count,
			 probepoint_type_t type,probepoint_style_t style,
			 probepoint_whence_t whence,
			 probepoint_watchsize_t watchsize,
			 probe_handler_t pre_handler,
			 probe_handler_t post_handler,
			 struct probe **probelist,
			 int failureaction);

/*
 * Unregisters a probe.
 * Upon successful completion, a value of 0 is returned. Otherwise, a value
 * of -1 is returned and the global integer variable errno is set to indicate 
 * the error.
 */
int probe_unregister(struct probe *probe,int force);
int probe_unregister_children(struct probe *probe,int force);

int probe_unregister_batch(struct target *target,struct probe **probelist,
			   int listlen,int force);

probepoint_watchsize_t probepoint_closest_watchsize(int size);

/*
 * Disables a running probe. When disabled, both pre- and post-handlers are 
 * ignored until the probe is enabled back.
 * Returns a value of 0 upon successful completion, or a value of -1 if the
 * given handle is invalid.
 * NOTE: To enable a probe, call enable_vmprobe() function below.
 */
int probe_disable(struct probe *probe);

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
 * Actions do not have priorities; they are executed in the order scheduled.
 */
int action_sched(struct probe *probe,struct action *action,
		 action_whence_t whence);

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
