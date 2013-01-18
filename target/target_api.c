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

#include "target_linux_userproc.h"
#ifdef ENABLE_XENACCESS
#include "target_xen_vm.h"
#endif

/**
 ** The generic target API!
 **/

/*
 * Generic function that launches or attaches to a target, given @spec.
 */
struct target *target_instantiate(struct target_spec *spec) {
    struct target *target = NULL;

    if (spec->target_type == TARGET_TYPE_PTRACE) {
	target = linux_userproc_instantiate(spec);
    }
#ifdef ENABLE_XENACCESS
    else if (spec->target_type == TARGET_TYPE_XEN) {
	target = xen_vm_instantiate(spec);
    }
#endif

    if (target) {
	target->spec = spec;
	return target;
    }

    errno = EINVAL;
    return NULL;
}

struct target_spec *target_build_spec(target_type_t type,target_mode_t mode) {
    struct target_spec *tspec;

    if (type == TARGET_TYPE_NONE) {
	tspec = calloc(1,sizeof(*tspec));
    }
    else if (type == TARGET_TYPE_PTRACE) {
	tspec = calloc(1,sizeof(*tspec));
	tspec->backend_spec = linux_userproc_build_spec();
    }
#ifdef ENABLE_XENACCESS
    else if (type == TARGET_TYPE_XEN) {
	tspec = calloc(1,sizeof(*tspec));
	tspec->backend_spec = xen_vm_build_spec();
    }
#endif
    else {
	errno = EINVAL;
	return NULL;
    }

    tspec->target_type = type;
    tspec->target_mode = mode;
    tspec->style = PROBEPOINT_FASTEST;

    return tspec;
}

void target_free_spec(struct target_spec *spec) {
    if (spec->backend_spec) {
	if (spec->target_type == TARGET_TYPE_PTRACE) {
	    linux_userproc_free_spec((struct linux_userproc_spec *)spec->backend_spec);
	}
#ifdef ENABLE_XENACCESS
	else if (spec->target_type == TARGET_TYPE_XEN) {
	    xen_vm_free_spec((struct xen_vm_spec *)spec->backend_spec);
	}
#endif
    }

    free(spec);
}

target_type_t target_type(struct target *target) {
    return target->spec->target_type;
}

char *target_name(struct target *target) {
    return target->name;
}

int target_id(struct target *target) {
    return target->id;
}

int target_open(struct target *target) {
    int rc;
    struct addrspace *space;
    struct memregion *region;

    vdebug(5,LA_TARGET,LF_TARGET,"opening target type(%d)\n",target_type(target));

    vdebug(5,LA_TARGET,LF_TARGET,"target type(%d): init\n",target_type(target));
    if ((rc = target->ops->init(target))) {
	return rc;
    }

    target->name = target_tostring(target,NULL,0);

    if (!target->spec) {
	verror("cannot open a target without a specification!\n");
	errno = EINVAL;
	return -1;
    }

    if (target->spec->bpmode == THREAD_BPMODE_STRICT && !target->threadctl) {
	verror("cannot init a target in BPMODE_STRICT that does not have"
	       " threadctl!\n");
	errno = ENOTSUP;
	return -1;
    }

    vdebug(5,LA_TARGET,LF_TARGET,"target(%s): loadspaces\n",target->name);
    if ((rc = target->ops->loadspaces(target))) {
	return rc;
    }

    list_for_each_entry(space,&target->spaces,space) {
	vdebug(5,LA_TARGET,LF_TARGET,"target(%s): loadregions\n",target->name);
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

	    vdebug(5,LA_TARGET,LF_TARGET,
		   "loaddebugfiles target(%s:%s):region(%s:%s)\n",
		   target->name,space->idstr,
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

	    vdebug(5,LA_TARGET,LF_TARGET,
		   "target(%s:%s) finished region(%s:%s,"
		   "base_load_addr=0x%"PRIxADDR",base_phys_addr=0x%"PRIxADDR
		   ",base_virt_addr=0x%"PRIxADDR
		   ",phys_offset=%"PRIiOFFSET" (0x%"PRIxOFFSET"))\n",
		   target->name,space->idstr,
		   region->name,REGION_TYPE(region->type),
		   region->base_load_addr,region->base_phys_addr,
		   region->base_virt_addr,region->phys_offset,
		   region->phys_offset);
	}
    }

    vdebug(5,LA_TARGET,LF_TARGET,"postloadinit target(%s)\n",target->name);
    if ((rc = target->ops->postloadinit(target))) {
	return rc;
    }

    vdebug(5,LA_TARGET,LF_TARGET,"attach target(%s)\n",target->name);
    if ((rc = target->ops->attach(target))) {
	return rc;
    }

    return 0;
}

char *target_tostring(struct target *target,char *buf,int bufsiz) {
    vdebug(16,LA_TARGET,LF_TARGET,"target(%s)\n",target->name);
    return target->ops->tostring(target,buf,bufsiz);
}

int target_attach_evloop(struct target *target,struct evloop *evloop) {
    if (target->evloop) {
	verror("an evloop is already associated with target(%s)!\n",
	       target->name);
	errno = EINVAL;
	return -1;
    }
    vdebug(16,LA_TARGET,LF_TARGET,"target(%s)\n",target->name);
    target->evloop = evloop;
    return target->ops->attach_evloop(target,evloop);
}    

int target_detach_evloop(struct target *target) {
    int rc;

    if (!target->evloop) {
	vwarn("no evloop is associated with target(%s)!\n",
	       target->name);
	return -1;
    }

    vdebug(16,LA_TARGET,LF_TARGET,"target(%s)\n",target->name);
    rc = target->ops->detach_evloop(target);

    target->evloop = NULL;

    return rc;
}
    
target_status_t target_monitor(struct target *target) {
    vdebug(8,LA_TARGET,LF_TARGET,"monitoring target(%s)\n",target->name);
    return target->ops->monitor(target);
}

target_status_t target_poll(struct target *target,struct timeval *tv,
			    target_poll_outcome_t *outcome,int *pstatus) {
    vdebug(8,LA_TARGET,LF_TARGET,"polling target(%s)\n",target->name);
    return target->ops->poll(target,tv,outcome,pstatus);
}
    
int target_resume(struct target *target) {
    vdebug(8,LA_TARGET,LF_TARGET,"resuming target(%s)\n",target->name);
    return target->ops->resume(target);
}
    
int target_pause(struct target *target) {
    vdebug(8,LA_TARGET,LF_TARGET,"pausing target(%s)\n",target->name);
    return target->ops->pause(target,0);
}

target_status_t target_status(struct target *target) {
    vdebug(16,LA_TARGET,LF_TARGET,"getting target(%s) status\n",target->name);
    return target->ops->status(target);
}

unsigned char *target_read_addr(struct target *target,ADDR addr,
				unsigned long length,unsigned char *buf) {
    vdebug(16,LA_TARGET,LF_TARGET,"reading target(%s) at 0x%"PRIxADDR" into %p (%d)\n",
	   target->name,addr,buf,length);
    return target->ops->read(target,addr,length,buf);
}

unsigned long target_write_addr(struct target *target,ADDR addr,
				unsigned long length,unsigned char *buf) {
    vdebug(16,LA_TARGET,LF_TARGET,"writing target(%s) at 0x%"PRIxADDR" (%d)\n",
	   target->name,addr,length);
    return target->ops->write(target,addr,length,buf);
}

char *target_reg_name(struct target *target,REG reg) {
    vdebug(16,LA_TARGET,LF_TARGET,"target(%s) reg name %d)\n",target->name,reg);
    return target->ops->regname(target,reg);
}

REG target_dw_reg_no(struct target *target,common_reg_t reg) {
    vdebug(16,LA_TARGET,LF_TARGET,"target(%s) common reg %d)\n",target->name,reg);
    return target->ops->dwregno(target,reg);
}

REGVAL target_read_reg(struct target *target,tid_t tid,REG reg) {
    vdebug(16,LA_TARGET,LF_TARGET,"reading target(%s:%"PRIiTID") reg %d)\n",
	   target->name,tid,reg);
    return target->ops->readreg(target,tid,reg);
}

int target_write_reg(struct target *target,tid_t tid,REG reg,REGVAL value) {
    vdebug(16,LA_TARGET,LF_TARGET,
	   "writing target(%s:%"PRIiTID") reg %d 0x%"PRIxREGVAL")\n",
	   target->name,tid,reg,value);
    return target->ops->writereg(target,tid,reg,value);
}

REGVAL target_read_creg(struct target *target,tid_t tid,common_reg_t reg) {
    REG treg;

    errno = 0;
    treg = target_dw_reg_no(target,reg);
    if (errno)
	return 0;

    return target_read_reg(target,tid,treg);
}

int target_write_creg(struct target *target,tid_t tid,common_reg_t reg,
		      REGVAL value) {
    REG treg;

    errno = 0;
    treg = target_dw_reg_no(target,reg);
    if (errno)
	return 0;

    return target_write_reg(target,tid,treg,value);
}

GHashTable *target_copy_registers(struct target *target,tid_t tid) {
    vdebug(16,LA_TARGET,LF_TARGET,
	   "copying target(%s:%"PRIiTID") regs\n",
	   target->name,tid);
    return target->ops->copy_registers(target,tid);
}

struct array_list *target_list_tids(struct target *target) {
    struct array_list *retval;
    GHashTableIter iter;
    struct target_thread *tthread;
    gpointer key;

    retval = array_list_create(g_hash_table_size(target->threads));

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,&key,(gpointer)&tthread)) 
	if ((tid_t)(uintptr_t)key == TID_GLOBAL
	    && tthread->tid != TID_GLOBAL)
	    continue;

	array_list_append(retval,(void *)(ptr_t)tthread->tid);

    return retval;
}

struct array_list *target_list_threads(struct target *target) {
    struct array_list *retval;
    GHashTableIter iter;
    struct target_thread *tthread;
    gpointer key;

    retval = array_list_create(g_hash_table_size(target->threads));

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,&key,(gpointer)&tthread)) {
	if ((tid_t)(uintptr_t)key == TID_GLOBAL
	    && tthread->tid != TID_GLOBAL)
	    continue;

	array_list_append(retval,tthread);
    }

    return retval;
}

GHashTable *target_hash_threads(struct target *target) {
    GHashTable *retval;
    GHashTableIter iter;
    gpointer key;
    struct target_thread *tthread;

    retval = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,&key,(gpointer)&tthread)) 
	if ((tid_t)(uintptr_t)key == TID_GLOBAL
	    && tthread->tid != TID_GLOBAL)
	    continue;

	g_hash_table_insert(retval,key,tthread);

    return retval;
}

struct array_list *target_list_available_tids(struct target *target) {
    vdebug(12,LA_TARGET,LF_TARGET,"target(%s)\n",target->name);
    return target->ops->list_available_tids(target);
}

GHashTable *target_hash_available_tids(struct target *target) {
    int i;
    struct array_list *tids;
    GHashTable *retval;
    tid_t tid;

    tids = target_list_available_tids(target);
    if (!tids) {
	verror("could not load available tids!\n");
	return NULL;
    }

    retval = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    for (i = 0; i < array_list_len(tids); ++i) {
	tid = (tid_t)(ptr_t)array_list_item(tids,i);
	g_hash_table_insert(retval,(gpointer)(ptr_t)tid,(gpointer)(ptr_t)tid);
    }
    array_list_free(tids);

    return retval;
}

int target_load_available_threads(struct target *target,int force) {
    vdebug(12,LA_TARGET,LF_TARGET,"target(%s)\n",target->name);
    return target->ops->load_available_threads(target,force);
}

struct target_thread *target_load_current_thread(struct target *target,
						 int force) {
    vdebug(8,LA_TARGET,LF_TARGET,"loading target(%s) current thread\n",target->name);
    return target->ops->load_current_thread(target,force);
}

struct target_thread *target_load_thread(struct target *target,tid_t tid,
					 int force) {
    vdebug(8,LA_TARGET,LF_TARGET,"loading target(%s:%"PRIiTID") thread\n",
	   target->name,tid);
    return target->ops->load_thread(target,tid,force);
}

int target_load_all_threads(struct target *target,int force) {
    vdebug(8,LA_TARGET,LF_TARGET,"loading all target(%s) threads\n",target->name);
    return target->ops->load_all_threads(target,force);
}

int target_pause_thread(struct target *target,tid_t tid,int nowait) {
    vdebug(12,LA_TARGET,LF_TARGET,"pausing target(%s) thread %"PRIiTID" (nowait=%d)\n",
	   target->name,tid,nowait);
    return target->ops->pause_thread(target,tid,nowait);
}

int target_flush_current_thread(struct target *target) {
    vdebug(8,LA_TARGET,LF_TARGET,"flushing target(%s) current thread\n",target->name);
    return target->ops->flush_current_thread(target);
}

int target_flush_thread(struct target *target,tid_t tid) {
    vdebug(8,LA_TARGET,LF_TARGET,"flushing target(%s:%"PRIiTID") thread\n",
	   target->name,tid);
    return target->ops->flush_thread(target,tid);
}

int target_flush_all_threads(struct target *target) {
    vdebug(8,LA_TARGET,LF_TARGET,"flushing all target(%s) threads\n",target->name);
    return target->ops->flush_all_threads(target);
}

int target_gc_threads(struct target *target) {
    int rc = 0;
    int i;
    struct array_list *cached_tids;
    GHashTable *real_tids;
    tid_t tid;
    struct target_thread *tthread;

    vdebug(8,LA_TARGET,LF_TARGET,"garbage collecting cached threads (%s)\n",target->name);
    if (target->ops->gc_threads) 
	return target->ops->gc_threads(target);


    cached_tids = target_list_tids(target);
    if (!cached_tids) {
	verror("could not list cached threads!\n");
	return -1;
    }

    real_tids = target_hash_available_tids(target);
    if (!real_tids) {
	verror("could not load currently available threads!\n");
	array_list_free(cached_tids);
	return -1;
    }

    for (i = 0; i < array_list_len(cached_tids); ++i) {
	tid = (tid_t)(ptr_t)array_list_item(cached_tids,i);

	if (tid == TID_GLOBAL)
	    continue;

	if (!g_hash_table_lookup_extended(real_tids,(gpointer)(ptr_t)tid,
					  NULL,NULL)) {
	    if (target->current_thread && target->current_thread->tid == tid) {
		vwarn("thread %d seems to no longer exist, but is the"
		      " current thread; not removing!\n",tid);
		continue;
	    }

	    vdebug(5,LA_TARGET,LF_TARGET | LF_THREAD,
		   "cached thread %"PRIiTID" no longer exists; removing!\n",tid);
	    tthread = target_lookup_thread(target,tid);
	    target_delete_thread(target,tthread,0);
	    ++rc;
	}
    }
    array_list_free(cached_tids);
    g_hash_table_destroy(real_tids);

    if (rc)
	vdebug(5,LA_TARGET,LF_TARGET,"garbage collected %d cached threads (%s)\n",
	       rc,target->name);

    return rc;
}

char *target_thread_tostring(struct target *target,tid_t tid,int detail,
			     char *buf,int bufsiz) {
    vdebug(16,LA_TARGET,LF_TARGET,"target(%s:%"PRIiTID") thread\n",target->name,tid);
    return target->ops->thread_tostring(target,tid,detail,buf,bufsiz);
}

void target_dump_thread(struct target *target,tid_t tid,FILE *stream,int detail) {
    char *buf;
    vdebug(16,LA_TARGET,LF_TARGET,"dumping target(%s:%"PRIiTID") thread\n",
	   target->name,tid);

    if (!target_lookup_thread(target,tid))
	verror("thread %"PRIiTID" does not exist?\n",tid);

    if ((buf = target_thread_tostring(target,tid,detail,NULL,0))) 
	fprintf(stream ? stream : stdout,"tid(%"PRIiTID"): %s\n",tid,buf);
    else 
	fprintf(stream ? stream : stdout,"tid(%"PRIiTID"): <API ERROR>\n",tid);

    free(buf);
}

void target_dump_all_threads(struct target *target,FILE *stream,int detail) {
    struct target_thread *tthread;
    GHashTableIter iter;

    vdebug(16,LA_TARGET,LF_TARGET,"dumping all target(%s) threads\n",target->name);

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) 
	target_dump_thread(target,tthread->tid,stream,detail);
}

int target_close(struct target *target) {
    int rc;
    GHashTableIter iter;
    gpointer key;
    struct target_thread *tthread;
    struct probepoint *probepoint;

    vdebug(5,LA_TARGET,LF_TARGET,"closing target(%s)\n",target->name);

    target_flush_all_threads(target);

    /* 
     * We have to free the soft probepoints manually, then remove all.  We
     * can't remove an element during an iteration, but we *can* free
     * the data :).
     */
    vdebug(2,LA_PROBE,LF_PROBEPOINT,"%d soft probepoints to free!\n",
	   g_hash_table_size(target->soft_probepoints));
    g_hash_table_iter_init(&iter,target->soft_probepoints);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&probepoint)) {
	probepoint_free_ext(probepoint);
    }
    g_hash_table_destroy(target->soft_probepoints);

    /* Delete all the threads except the global thread (which we remove 
     * manually because targets are allowed to "reuse" one of their real
     * threads as the "global" thread.
     */
    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,
				  (gpointer)&key,(gpointer)&tthread)) {
	if (tthread == target->global_thread) {
	    g_hash_table_iter_remove(&iter);
	}
	else {
	    target_delete_thread(target,tthread,1);
	    g_hash_table_iter_remove(&iter);
	}
    }
    target_delete_thread(target,target->global_thread,0);

    /* Target should not mess with these after close! */
    target->global_thread = target->current_thread = NULL;

    vdebug(5,LA_TARGET,LF_TARGET,"detach target(%s)\n",target->name);
    if ((rc = target->ops->detach(target))) {
	return rc;
    }

    return 0;
}

int target_kill(struct target *target) {
    vdebug(5,LA_TARGET,LF_TARGET,"killing target(%s)\n",target->name);
    return target->ops->kill(target);
}

struct probe *target_lookup_probe(struct target *target,int probe_id) {
    return (struct probe *)g_hash_table_lookup(target->probes,
					       (gpointer)(uintptr_t)probe_id);
}

struct action *target_lookup_action(struct target *target,int action_id) {
    return (struct action *)g_hash_table_lookup(target->actions,
						(gpointer)(uintptr_t)action_id);
}

REG target_get_unused_debug_reg(struct target *target,tid_t tid) {
    REG retval;
    vdebug(5,LA_TARGET,LF_TARGET,"getting unused debug reg for target(%s):0x%"PRIx64"\n",
	   target->name,tid);
    retval = target->ops->get_unused_debug_reg(target,tid);
    vdebug(5,LA_TARGET,LF_TARGET,"got unused debug reg for target(%s):0x%"PRIx64": %"PRIiREG"\n",
	   target->name,tid,retval);
    return retval;
}

int target_set_hw_breakpoint(struct target *target,tid_t tid,REG reg,ADDR addr) {
    vdebug(5,LA_TARGET,LF_TARGET,
	   "setting hw breakpoint at 0x%"PRIxADDR" on target(%s:%"PRIiTID") dreg %d\n",
	   addr,target->name,tid,reg);
    return target->ops->set_hw_breakpoint(target,tid,reg,addr);
}

int target_set_hw_watchpoint(struct target *target,tid_t tid,REG reg,ADDR addr,
			     probepoint_whence_t whence,int watchsize) {
    vdebug(5,LA_TARGET,LF_TARGET,
	   "setting hw watchpoint at 0x%"PRIxADDR" on target(%s:%"PRIiTID") dreg %d (%d)\n",
	   addr,target->name,tid,reg,watchsize);
    return target->ops->set_hw_watchpoint(target,tid,reg,addr,whence,watchsize);
}

int target_unset_hw_breakpoint(struct target *target,tid_t tid,REG reg) {
    vdebug(5,LA_TARGET,LF_TARGET,
	   "removing hw breakpoint on target(%s:%"PRIiTID") dreg %d\n",
	   target->name,tid,reg);
    return target->ops->unset_hw_breakpoint(target,tid,reg);
}

int target_unset_hw_watchpoint(struct target *target,tid_t tid,REG reg) {
    vdebug(5,LA_TARGET,LF_TARGET,
	   "removing hw watchpoint on target(%s:%"PRIiTID") dreg %d\n",
	   target->name,tid,reg);
    return target->ops->unset_hw_watchpoint(target,tid,reg);
}

int target_disable_hw_breakpoints(struct target *target,tid_t tid) {
    vdebug(5,LA_TARGET,LF_TARGET,
	   "disable hw breakpoints on target(%s:%"PRIiTID")\n",target->name,tid);
    return target->ops->disable_hw_breakpoints(target,tid);
}

int target_enable_hw_breakpoints(struct target *target,tid_t tid) {
    vdebug(5,LA_TARGET,LF_TARGET,
	   "enable hw breakpoints on target(%s:%"PRIiTID")\n",target->name,tid);
    return target->ops->enable_hw_breakpoints(target,tid);
}

int target_disable_hw_breakpoint(struct target *target,tid_t tid,REG dreg) {
    vdebug(5,LA_TARGET,LF_TARGET,
	   "disable hw breakpoint %"PRIiREG" on target(%s:%"PRIiTID")\n",
	   dreg,target->name,tid);
    return target->ops->disable_hw_breakpoint(target,tid,dreg);
}

int target_enable_hw_breakpoint(struct target *target,tid_t tid,REG dreg) {
    vdebug(5,LA_TARGET,LF_TARGET,
	   "enable hw breakpoint %"PRIiREG" on target(%s:%"PRIiTID")\n",
	   dreg,target->name,tid);
    return target->ops->enable_hw_breakpoint(target,tid,dreg);
}

int target_notify_sw_breakpoint(struct target *target,ADDR addr,
				int notification) {
    vdebug(5,LA_TARGET,LF_TARGET,
	   "notify sw breakpoint (%d) on target(%s)\n",
	   notification,target->name);
    return target->ops->notify_sw_breakpoint(target,addr,notification);
}

int target_singlestep(struct target *target,tid_t tid,int isbp) {
    vdebug(5,LA_TARGET,LF_TARGET,"single stepping target(%s:%"PRIiTID") isbp=%d\n",
	   target->name,tid,isbp);
    return target->ops->singlestep(target,tid,isbp);
}

int target_singlestep_end(struct target *target,tid_t tid) {
    if (target->ops->singlestep_end) {
	vdebug(5,LA_TARGET,LF_TARGET,"ending single stepping of target(%s:%"PRIiTID")\n",
	       target->name,tid);
	return target->ops->singlestep_end(target,tid);
    }
    return 0;
}

tid_t target_gettid(struct target *target) {
    tid_t retval = 0;

    vdebug(9,LA_TARGET,LF_TARGET,"gettid target(%s)\n",target->name);
    retval = target->ops->gettid(target);
    vdebug(5,LA_TARGET,LF_TARGET,"gettid target(%s) -> 0x%"PRIx64" \n",
	   target->name,retval);

    return retval;
}

uint64_t target_get_tsc(struct target *target) {
    if (target->ops->get_tsc)
	return target->ops->get_tsc(target);
    errno = EINVAL;
    return UINT64_MAX;
}

uint64_t target_get_time(struct target *target) {
    if (target->ops->get_time)
	return target->ops->get_time(target);
    errno = EINVAL;
    return UINT64_MAX;
}

uint64_t target_get_counter(struct target *target) {
    if (target->ops->get_counter)
	return target->ops->get_counter(target);
    errno = EINVAL;
    return UINT64_MAX;
}

int target_enable_feature(struct target *target,int feature,void *arg) {
    if (target->ops->enable_feature)
	return target->ops->enable_feature(target,feature,arg);
    errno = EINVAL;
    return -1;
}

int target_disable_feature(struct target *target,int feature) {
    if (target->ops->disable_feature)
	return target->ops->disable_feature(target,feature);
    errno = EINVAL;
    return -1;
}

int target_thread_is_valid(struct target *target,tid_t tid) {
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("no such thread %"PRIiTID"\n",tid);
	errno = EINVAL;
	return -1;
    }

    return tthread->valid;
}

int target_thread_is_dirty(struct target *target,tid_t tid) {
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("no such thread %"PRIiTID"\n",tid);
	errno = EINVAL;
	return -1;
    }

    return tthread->dirty;
}

thread_status_t target_thread_status(struct target *target,tid_t tid) {
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("no such thread %"PRIiTID"\n",tid);
	errno = EINVAL;
	return THREAD_STATUS_UNKNOWN;
    }

    return tthread->status;
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
