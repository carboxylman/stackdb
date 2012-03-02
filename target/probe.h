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

#ifndef __PROBE_H__
#define __PROBE_H__

#include "common.h"
#include "list.h"
#include "probe_api.h"

#include <glib.h>

/*
 * probepoint_state_t -- various states of a probe point
 */
typedef enum {
    PROBE_INSERTING = 1,    /* domain quiescing prior to breakpoint insertion */
    PROBE_BP_SET,           /* breakpoint in place */
    PROBE_BP_HANDLING,      /* handling a breakpoint */
    PROBE_BP_HANDLING_POST, /* handling a breakpoint, after
			       single-stepping the original instr */
    PROBE_REMOVING,         /* domain quiescing prior to breakpoint removal */
    PROBE_DISABLED,         /* breakpoint removal completed */
    PROBE_ACTION_RUNNING,   /* executing an action */
    PROBE_ACTION_DONE,      /* finished an action */
} probepoint_state_t;

int probepoint_bp_handler(struct target *target,
			  struct probepoint *probepoint);
int probepoint_ss_handler(struct target *target,
			  struct probepoint *probepoint);

/*
 * A probe point is the address site where an actual break/watch point
 * is registered.  We associate multiple logical probes with a single
 * probe point.
 */
struct probepoint {
    /* Location of the probe point */
    ADDR addr;

    probepoint_type_t type;
    probepoint_style_t style;
    probepoint_whence_t whence;
    probepoint_watchsize_t watchsize;

    probepoint_state_t state;

    /* backref to the target this probe point is associated with */
    struct target *target;

    /* If this probepoint is associated with a symbol, save it! */
    struct lsymbol *lsymbol;
    /* If we have a symbol, save its resolved addr (which may be
     * different than the addr above, of course.
     */
    ADDR symbol_addr;

    /* Always save off which memrange the probe is in. */
    struct memrange *range;
    
    /* list of probes at this probe-point */
    struct list_head probes;

    /* Lists of actions that may be executed at this probepoint. */
    struct list_head actions;

    /* Currently executing action. */
    struct action *action;
    int action_obviates_orig;
    int action_needs_ssteps;
    
    /* Saved opcode (which has been replaced with breakpoint) */
    void *breakpoint_orig_mem;
    /* Saved instructions (which were replaced with action's code) */
    void *action_orig_mem;

    unsigned int breakpoint_orig_mem_len;
    unsigned int action_orig_mem_len;

    /* If this is a hardware-assisted probepoint, this is the debug
     * register number.
     */
    REG debugregnum;
};

struct probe {
    /* The target probe-point */
    struct probepoint *probepoint;

    /* User handler to run before probe-point is executed */
    probe_handler_t pre_handler;

    /* User handler to run after probe-point is executed */
    probe_handler_t post_handler;

    /* True when the vmprobe is enabled */
    uint8_t enabled;

    /* Link to the probe list  */
    struct list_head probe;

    /* A list of "child" probes -- i.e., perhaps breakpoints within a
     * function whose entry point is this probe.
     */
    struct list_head child_probes;

    /* If this probe is a child of some parent, this is its node on the
     * above `child_probes' list.
     */
    struct list_head child_probe;

    /* If this probe is a child of some parent, this is its parent. */
    struct probe *parent;
};

struct action {
    action_type_t type;
    action_whence_t whence;
    union {
	struct {
	    REGVAL retval;
	    int8_t prologue:1,
		   prologue_uses_bp:1;
	    int prologue_sp_offset;
	} ret;
	struct {
	    void **instrs;
	    uint32_t instrs_count;
	    action_flag_t flags;
	} code;
	struct {
	    REG regnum;
	    REGVAL regval;
	} regmod;
	struct {
	    ADDR destaddr;
	    void *data;
	    uint32_t len;
	} memmod;
    } detail;

    ADDR ss_dst_eip;

    int executed_this_pass;

    /* An action can only be attached to one vmprobe at a time. */
    struct list_head action;

    struct probe *probe;
};

/* The target_api code needs to call this, but we don't want it exposed
 * to users.  So it's here.
 */
void probepoint_free_ext(struct probepoint *probepoint);

#endif /* __PROBE_H__ */
