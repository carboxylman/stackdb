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
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "target_api.h"
#include "target.h"
#include "probe_api.h"
#include "probe.h"

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/**
 ** The generic target API!
 **/

int target_open(struct target *target) {
    int rc;
    struct addrspace *space;
    struct memregion *region;

    vdebug(5,LOG_T_TARGET,"opening target type %s\n",target->type);

    vdebug(5,LOG_T_TARGET,"target type %s: init\n",target->type);
    if ((rc = target->ops->init(target))) {
	return rc;
    }

    vdebug(5,LOG_T_TARGET,"target type %s: loadspaces\n",target->type);
    if ((rc = target->ops->loadspaces(target))) {
	return rc;
    }

    list_for_each_entry(space,&target->spaces,space) {
	vdebug(5,LOG_T_TARGET,"target type %s: loadregions\n",target->type);
	if ((rc = target->ops->loadregions(target,space))) {
	    return rc;
	}
    }

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if (region->type == REGION_TYPE_HEAP
		|| region->type == REGION_TYPE_STACK
		|| region->type == REGION_TYPE_VDSO
		|| region->type == REGION_TYPE_VSYSCALL) 
		continue;

	    vdebug(5,LOG_T_TARGET,
		   "loaddebugfiles target(%s:%s):region(%s:%s)\n",
		   target->type,space->idstr,
		   region->name,REGION_TYPE(region->type));
	    if ((rc = target->ops->loaddebugfiles(target,space,region))) {
		vwarn("could not open debuginfo for region %s (%d)\n",
		      region->name,rc);
	    }

	    /*
	     * Once the region has been loaded and associated with a
	     * debuginfo file, we calculate the phys_offset of the
	     * loaded code -- which is the base_phys_addr - base_virt_addr
	     * from the ELF program headers.
	     */
	    if (region->type == REGION_TYPE_MAIN)
		region->phys_offset = 0;
	    else 
		region->phys_offset = region->base_load_addr		\
		    + (region->base_phys_addr - region->base_virt_addr);

	    vdebug(5,LOG_T_TARGET,
		   "target(%s:%s) finished region(%s:%s,"
		   "base_load_addr=0x%"PRIxADDR",base_phys_addr=0x%"PRIxADDR
		   ",base_virt_addr=0x%"PRIxADDR
		   ",phys_offset=%"PRIiOFFSET" (0x%"PRIxOFFSET"))",
		   target->type,space->idstr,
		   region->name,REGION_TYPE(region->type),
		   region->base_load_addr,region->base_phys_addr,
		   region->base_virt_addr,region->phys_offset,
		   region->phys_offset);
	}
    }

    vdebug(5,LOG_T_TARGET,"attach target(%s)\n",target->type);
    if ((rc = target->ops->attach(target))) {
	return rc;
    }

    return 0;
}
    
target_status_t target_monitor(struct target *target) {
    vdebug(9,LOG_T_TARGET,"monitoring target(%s)\n",target->type);
    return target->ops->monitor(target);
}

target_status_t target_poll(struct target *target,
			    target_poll_outcome_t *outcome,int *pstatus) {
    vdebug(10,LOG_T_TARGET,"polling target(%s)\n",target->type);
    return target->ops->poll(target,outcome,pstatus);
}
    
int target_resume(struct target *target) {
    vdebug(9,LOG_T_TARGET,"resuming target(%s)\n",target->type);
    return target->ops->resume(target);
}
    
int target_pause(struct target *target) {
    vdebug(5,LOG_T_TARGET,"pausing target(%s)\n",target->type);
    return target->ops->pause(target);
}

target_status_t target_status(struct target *target) {
    vdebug(5,LOG_T_TARGET,"getting target(%s) status\n",target->type);
    return target->ops->status(target);
}

unsigned char *target_read_addr(struct target *target,
				ADDR addr,
				unsigned long length,
				unsigned char *buf,
				void *targetspecdata) {
    vdebug(5,LOG_T_TARGET,"reading target(%s) at 0x%"PRIxADDR" into %p (%d)\n",
	   target->type,addr,buf,length);
    return target->ops->read(target,addr,length,buf,targetspecdata);
}

unsigned long target_write_addr(struct target *target,ADDR addr,
				unsigned long length,unsigned char *buf,
				void *targetspecdata) {
    vdebug(5,LOG_T_TARGET,"writing target(%s) at 0x%"PRIxADDR" (%d)\n",
	   target->type,addr,length);
    return target->ops->write(target,addr,length,buf,targetspecdata);
}

char *target_reg_name(struct target *target,REG reg) {
    vdebug(5,LOG_T_TARGET,"target(%s) reg name %d)\n",target->type,reg);
    return target->ops->regname(target,reg);
}

REGVAL target_read_reg(struct target *target,REG reg) {
    vdebug(5,LOG_T_TARGET,"reading target(%s) reg %d)\n",target->type,reg);
    return target->ops->readreg(target,reg);
}

int target_write_reg(struct target *target,REG reg,REGVAL value) {
    vdebug(5,LOG_T_TARGET,"writing target(%s) reg %d 0x%" PRIxREGVAL ")\n",
	   target->type,reg,value);
    return target->ops->writereg(target,reg,value);
}

int target_flush_context(struct target *target) {
    vdebug(5,LOG_T_TARGET,"flushing target(%s) cpu context\n",target->type);
    return target->ops->flush_context(target);
}

int target_close(struct target *target) {
    int rc;

    vdebug(5,LOG_T_TARGET,"closing target(%s)\n",target->type);

    vdebug(6,LOG_T_TARGET,"detach target(%s)\n",target->type);
    if ((rc = target->ops->detach(target))) {
	return rc;
    }

    vdebug(6,LOG_T_TARGET,"fini target(%s)\n",target->type);
    if ((rc = target->ops->fini(target))) {
	return rc;
    }

    return 0;
}

void target_free(struct target *target) {
    GHashTableIter iter;
    gpointer key;
    struct probepoint *probepoint;
    struct addrspace *space;
    struct addrspace *tmp;

    vdebug(5,LOG_T_TARGET,"freeing target(%s)\n",target->type);

    g_hash_table_destroy(target->mmaps);

    /* We have to free the probepoints manually, then remove all.  We
     * can't remove an element during an iteration, but we *can* free
     * the data :).
     */
    g_hash_table_iter_init(&iter,target->probepoints);
    while (g_hash_table_iter_next(&iter,
				  (gpointer)&key,(gpointer)&probepoint)) {
	probepoint_free_ext(probepoint);
    }

    g_hash_table_destroy(target->probepoints);
    g_hash_table_destroy(target->probes);

    array_list_free(target->sstep_stack);

    /* Unload the debugfiles we might hold, if we can */
    list_for_each_entry_safe(space,tmp,&target->spaces,space) {
	RPUT(space,addrspace);
    }

    if (target->breakpoint_instrs)
	free(target->breakpoint_instrs);

    if (target->ret_instrs)
	free(target->ret_instrs);

    if (target->full_ret_instrs)
	free(target->full_ret_instrs);

    free(target);
}

void ghash_mmap_entry_free(gpointer data) {
    struct mmap_entry *mme = (struct mmap_entry *)data;

    free(mme);
}

struct target *target_create(char *type,void *state,struct target_ops *ops,
			     struct debugfile_load_opts **dfoptlist) {
    struct target *retval = malloc(sizeof(struct target));
    memset(retval,0,sizeof(struct target));

    retval->type = type;
    retval->state = state;
    retval->ops = ops;
    retval->debugfile_opts_list = dfoptlist;

    INIT_LIST_HEAD(&retval->spaces);

    retval->mmaps = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					  /* No names to free! */
					  NULL,ghash_mmap_entry_free);

    retval->probepoints = g_hash_table_new(g_direct_hash,g_direct_equal);

    retval->probes = g_hash_table_new(g_direct_hash,g_direct_equal);

    retval->sstep_stack = array_list_create(4);

    /*
     * Hm, I think we should do this by default, and let target backends
     * override it if they need.
     */
    retval->bp_handler = probepoint_bp_handler;
    retval->ss_handler = probepoint_ss_handler;

    return retval;
}

struct mmap_entry *target_lookup_mmap_entry(struct target *target,
					    ADDR base_addr) {
    /* XXX: fill later. */
    return NULL;
}

void target_attach_mmap_entry(struct target *target,
			      struct mmap_entry *mme) {
    /* XXX: fill later. */
    return;
}

void target_release_mmap_entry(struct target *target,
			       struct mmap_entry *mme) {
    /* XXX: fill later. */
    return;
}

REG target_get_unused_debug_reg(struct target *target) {
    REG retval;
    vdebug(5,LOG_T_TARGET,"getting unused debug reg for target(%s)\n",
	   target->type);
    retval = target->ops->get_unused_debug_reg(target);
    vdebug(5,LOG_T_TARGET,"got unused debug reg for target(%s): %"PRIiREG"\n",
	   target->type,retval);
    return retval;
}

int target_set_hw_breakpoint(struct target *target,REG reg,ADDR addr) {
    vdebug(5,LOG_T_TARGET,
	   "setting hw breakpoint at 0x%"PRIxADDR" on target(%s) dreg %d\n",
	   addr,target->type,reg);
    return target->ops->set_hw_breakpoint(target,reg,addr);
}

int target_set_hw_watchpoint(struct target *target,REG reg,ADDR addr,
			     probepoint_whence_t whence,int watchsize) {
    vdebug(5,LOG_T_TARGET,
	   "setting hw watchpoint at 0x%"PRIxADDR" on target(%s) dreg %d (%d)\n",
	   addr,target->type,reg,watchsize);
    return target->ops->set_hw_watchpoint(target,reg,addr,whence,watchsize);
}

int target_unset_hw_breakpoint(struct target *target,REG reg) {
    vdebug(5,LOG_T_TARGET,
	   "removing hw breakpoint on target(%s) dreg %d\n",
	   target->type,reg);
    return target->ops->unset_hw_breakpoint(target,reg);
}

int target_unset_hw_watchpoint(struct target *target,REG reg) {
    vdebug(5,LOG_T_TARGET,
	   "removing hw watchpoint on target(%s) dreg %d\n",
	   target->type,reg);
    return target->ops->unset_hw_watchpoint(target,reg);
}


int target_disable_hw_breakpoints(struct target *target) {
    vdebug(5,LOG_T_TARGET,
	   "disable hw breakpoints on target(%s)\n",target->type);
    return target->ops->disable_hw_breakpoints(target);
}

int target_enable_hw_breakpoints(struct target *target) {
    vdebug(5,LOG_T_TARGET,
	   "enable hw breakpoints on target(%s)\n",target->type);
    return target->ops->enable_hw_breakpoints(target);
}

int target_notify_sw_breakpoint(struct target *target,ADDR addr,
				int notification) {
    vdebug(5,LOG_T_TARGET,
	   "notify sw breakpoint (%d) on target(%s)\n",
	   notification,target->type);
    return target->ops->notify_sw_breakpoint(target,addr,notification);
}

int target_singlestep(struct target *target) {
    vdebug(5,LOG_T_TARGET,"single stepping target(%s)\n",target->type);
    return target->ops->singlestep(target);
}

int target_singlestep_end(struct target *target) {
    if (target->ops->singlestep_end) {
	vdebug(5,LOG_T_TARGET,"ending single stepping of target(%s)\n",
	       target->type);
	return target->ops->singlestep_end(target);
    }
    return 0;
}


/*
 * Util stuff.
 */
char *TSTATUS_STRINGS[] = {
    "UNKNOWN",
    "RUNNING",
    "PAUSED",
    "DEAD",
    "STOPPED",
    "ERROR",
    "DONE",
};

char *POLL_STRINGS[] = {
    "NOTHING",
    "ERROR",
    "SUCCESS",
    "UNKNOWN",
};
