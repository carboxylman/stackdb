/*
 * Copyright (c) 2013, 2014 The University of Utah
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

#include <assert.h>
#include <glib.h>

#include "object.h"
#include "glib_wrapper.h"
#include "target.h"
#include "probe_api.h"
#include "probe.h"
#include "target_os.h"
#include "target_event.h"

target_os_type_t target_os_type(struct target *target) {
    SAFE_TARGET_OS_OP(target,os_type,TARGET_OS_TYPE_NONE,
		      target);
}

uint64_t target_os_version(struct target *target) {
    SAFE_TARGET_OS_OP(target,os_version,0,
		      target);
}

int target_os_version_cmp(struct target *target,uint64_t vers) {
    SAFE_TARGET_OS_OP(target,os_version_cmp,0,
		      target,vers);
}

int target_os_thread_get_pgd_phys(struct target *target,tid_t tid,ADDR *pgdp) {
    struct target_thread *tthread = target_load_thread(target,tid,0);
    if (!tthread)
	return -1;
    SAFE_TARGET_OS_OP(target,thread_get_pgd_phys,-1,target,tthread,pgdp);
}

int target_os_thread_is_user(struct target *target,tid_t tid) {
    struct target_thread *tthread = target_load_thread(target,tid,0);
    if (!tthread)
	return -1;
    SAFE_TARGET_OS_OP(target,thread_is_user,-1,target,tthread);
}
    
tid_t target_os_thread_get_leader(struct target *target,tid_t tid) {
    struct target_thread *tthread = target_load_thread(target,tid,0);
    if (!tthread)
	return -1;
    SAFE_TARGET_OS_OP_NORET(target,thread_get_leader,NULL,tthread,target,tthread);
    if (tthread)
	return tthread->tid;
    else
	return -1;
}

int target_os_update_process_threads_generic(struct target_process *process,
					     int no_event_send) {
    tid_t tid;
    tid_t tgid;
    tid_t ptid;
    int done = 0;
    REFCNT trefcnt;
    GHashTableIter iter;
    gpointer vp;
    struct target_thread *tthread,*othread;
    struct target_process *child,*child_old,*parent;
    struct target_event *event;
    GList *newlist = NULL;
    GList *t1;

    tid = process->thread->tid;
    tgid = process->thread->tgid;
    ptid = process->thread->ptid;

    /*
     * Find all the threads in the process, based on
     * process->thread->tgid == Nthread->tgid equivalency.  This means
     * we have to load all the threads, then go through them.
     */
    if (tgid > -1) {
	if (!done) {
	    target_load_available_threads(process->target,0);
	    done = 1;
	}

	//g_hash_table_remove_all(process->threads);
	g_hash_table_iter_init(&iter,process->target->threads);
	while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	    tthread = (struct target_thread *)vp;
	    if (tthread->tid == TID_GLOBAL)
		continue;

	    if (tthread->tgid == tgid) {
		othread = (struct target_thread *) \
		    g_hash_table_lookup(process->threads,
					(gpointer)(uintptr_t)tthread->tid);
		if (othread) {
		    if (othread != tthread) {
			RPUT(othread,target_thread,process,trefcnt);
			g_hash_table_iter_remove(&iter);
			newlist = g_list_prepend(newlist,tthread);
		    }
		}
		else {
		    newlist = g_list_prepend(newlist,tthread);
		}
	    }
	}
    }

    /* Add new threads. */
    if (newlist) {
	v_g_list_foreach(newlist,t1,tthread) {
	    g_hash_table_insert(process->threads,
				(gpointer)(uintptr_t)tthread->tid,tthread);
	    RHOLD(tthread,process);
	}
	g_list_free(newlist);
	newlist = NULL;
    }


    /*
     * Now, remove any "dead" threads:
     */
    g_hash_table_iter_init(&iter,process->threads);
    while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	tthread = (struct target_thread *)vp;
	if (!OBJLIVE(tthread)) {
	    g_hash_table_iter_remove(&iter);
	    RPUT(tthread,target_thread,process,trefcnt);
	}
    }

    /*
     * Find all the children of the process, based on
     * process->thread->tid == Nthread->ptid equivalency.  This means we
     * have to load all the threads, then go through them.
     */
    if (ptid > -1) {
	if (!done) {
	    target_load_available_threads(process->target,0);
	    done = 1;
	}

	//g_hash_table_remove_all(process->children);
	g_hash_table_iter_init(&iter,process->target->threads);
	while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	    tthread = (struct target_thread *)vp;
	    if (tthread->tid == TID_GLOBAL)
		continue;

	    if (tthread->ptid == tid) {
		child = target_os_process_get(process->target,tthread->tid);
		child_old = (struct target_process *) \
		    g_hash_table_lookup(process->children,
					(gpointer)(uintptr_t)tthread->tid);
		if (child_old) {
		    if (child_old != child) {
			vdebug(8,LA_TARGET,LF_OS,
			       "removing old child pid %d for pid %d\n",
			       child_old->tid,process->tid);
			RPUT(child_old,target_process,process,trefcnt);
			g_hash_table_iter_remove(&iter);
			if (child)
			    newlist = g_list_prepend(newlist,child);
		    }
		}
		else if (child) {
		    newlist = g_list_prepend(newlist,child);
		}
	    }
	}
    }

    /* Add new children. */
    if (newlist) {
	v_g_list_foreach(newlist,t1,child) {
	    g_hash_table_insert(process->children,
				(gpointer)(uintptr_t)child->tid,child);
	    RHOLD(child,process);
	    vdebug(8,LA_TARGET,LF_OS,
		   "added child %d to pid %d\n",child->tid,process->tid);
	}
	g_list_free(newlist);
	newlist = NULL;
    }

    /*
     * Now, remove any "dead" threads:
     */
    g_hash_table_iter_init(&iter,process->threads);
    while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	tthread = (struct target_thread *)vp;
	if (!OBJLIVE(tthread)) {
	    g_hash_table_iter_remove(&iter);
	    RPUT(tthread,target_thread,process,trefcnt);
	    vdebug(8,LA_TARGET,LF_OS,
		   "removed stale thread %d from pid %d\n",
		   tthread->tid,process->tid);
	}
    }

    /* Fill the parent. */
    if (process->thread->ptid > -1) {
	parent = target_os_process_get(process->target,process->thread->ptid);

	if (!process->parent && parent) {
	    process->parent = parent;
	    RHOLDW(parent,process);
	    vdebug(8,LA_TARGET,LF_OS,
		   "new parent pid %d for pid %d\n",parent->tid,process->tid);
	}
	else if (process->parent && !parent) {
	    RPUTW(process->parent,target_process,process,trefcnt);
	    process->parent = NULL;
	    vdebug(8,LA_TARGET,LF_OS,
		   "removed parent pid %d\n",process->tid);
	}
	else if (process->parent && parent && process->parent != parent) {
	    RPUTW(process->parent,target_process,process,trefcnt);
	    process->parent = parent;
	    RHOLDW(parent,process);
	    vdebug(8,LA_TARGET,LF_OS,
		   "changed parent to pid %d for pid %d\n",
		   parent->tid,process->tid);
	}
    }

    return 0;
}

GHashTable *target_os_process_table_get(struct target *target) {
    SAFE_TARGET_OS_OP(target,processes_get,NULL,target);
}

struct target_process *target_os_process_get(struct target *target,tid_t tid) {
    struct target_thread *tthread = target_load_thread(target,tid,0);
    if (!tthread)
	return NULL;
    SAFE_TARGET_OS_OP(target,process_get,NULL,target,tthread);
}

int target_os_signal_enqueue(struct target *target,tid_t tid,
			     int signo,void *data) {
    struct target_thread *tthread = target_load_thread(target,tid,0);
    if (!tthread)
	return -1;
    SAFE_TARGET_OS_OP(target,signal_enqueue,-1,target,tthread,signo,data);
}

const char *target_os_signal_to_name(struct target *target,int signo) {
    SAFE_TARGET_OS_OP(target,signal_to_name,NULL,target,signo);
}

int target_os_signal_from_name(struct target *target,const char *name) {
    SAFE_TARGET_OS_OP(target,signal_from_name,-1,target,name);
}

int target_os_syscall_table_load(struct target *target) {
    SAFE_TARGET_OS_OP(target,syscall_table_load,-1,
		      target);
}

int target_os_syscall_table_unload(struct target *target) {
    SAFE_TARGET_OS_OP(target,syscall_table_unload,-1,
		      target);
}

GHashTable *target_os_syscall_table_get(struct target *target) {
    SAFE_TARGET_OS_OP(target,syscall_table_get,NULL,
		      target);
}

int target_os_syscall_table_get_max_num(struct target *target) {
    GHashTable *sctab = target_os_syscall_table_get(target);
    if (!sctab)
	return -1;
    return g_hash_table_size(sctab);
}

struct target_os_syscall *target_os_syscall_lookup_name(struct target *target,
							char *name) {
    SAFE_TARGET_OS_OP(target,syscall_lookup_name,NULL,
		      target,name);
}

struct target_os_syscall *target_os_syscall_lookup_num(struct target *target,
						       int num) {
    SAFE_TARGET_OS_OP(target,syscall_lookup_num,NULL,
		      target,num);
}

struct target_os_syscall *target_os_syscall_lookup_addr(struct target *target,
							ADDR addr) {
    SAFE_TARGET_OS_OP(target,syscall_lookup_addr,NULL,
		      target,addr);
}

int target_os_syscall_table_reload(struct target *target,int force) {
    SAFE_TARGET_OS_OP(target,syscall_table_reload,-1,
		      target,force);
}

int target_os_syscall_table_store(struct target *target) {
    SAFE_TARGET_OS_OP(target,syscall_table_store,-1,
		      target);
}

struct probe *target_os_syscall_probe(struct target *target,tid_t tid,
				      struct target_os_syscall *syscall,
				      probe_handler_t pre_handler,
				      probe_handler_t post_handler,
				      void *handler_data) {
    SAFE_TARGET_OS_OP(target,syscall_probe,NULL,
		      target,tid,syscall,pre_handler,post_handler,handler_data);
}

struct probe *target_os_syscall_probe_all(struct target *target,tid_t tid,
					  probe_handler_t pre_handler,
					  probe_handler_t post_handler,
					  void *handler_data) {
    SAFE_TARGET_OS_OP(target,syscall_probe_all,NULL,
		      target,tid,pre_handler,post_handler,handler_data);
}

/*
 * Syscall probe type.
 */
static const char *_target_os_syscall_probe_gettype(struct probe *probe) {
    return "target_os_syscall_probe";
}

#define TARGET_OS_SYSCALL_GKV_KEY "target_os_syscall_state"

void *target_os_syscall_probe_summarize(struct probe *probe) {
    return target_gkv_lookup(probe->target,TARGET_OS_SYSCALL_GKV_KEY);
}

void *target_os_syscall_probe_summarize_tid(struct probe *probe,tid_t tid) {
    return target_thread_gkv_lookup(probe->target,tid,TARGET_OS_SYSCALL_GKV_KEY);
}

struct probe_ops target_os_syscall_ret_probe_ops = {
    .gettype = _target_os_syscall_probe_gettype,

    .summarize = target_os_syscall_probe_summarize,
    .summarize_tid = target_os_syscall_probe_summarize_tid,
};

static void _target_os_syscall_state_dtor(struct target *target,tid_t tid,
					  char *key,void *value) {
    struct target_os_syscall_state *scs;
    int i;
    struct value *v;

    if (!value)
	return;

    scs = (struct target_os_syscall_state *)value;

    if (scs->argvals) {
	array_list_foreach(scs->argvals,i,v) {
	    if (!v)
		continue;
	    value_free(v);
	}
	array_list_free(scs->argvals);
    }
    if (scs->regvals)
	array_list_free(scs->regvals);

    free(scs);
}

struct target_os_syscall_state *target_os_syscall_probe_last(struct target *target,
							     tid_t tid) {
    return (struct target_os_syscall_state *) \
	target_thread_gkv_lookup(target,tid,TARGET_OS_SYSCALL_GKV_KEY);
}

int target_os_syscall_record_clear(struct target *target,tid_t tid) {
    target_thread_gkv_remove(target,tid,TARGET_OS_SYSCALL_GKV_KEY);
    return 0;
}

struct target_os_syscall_state *
target_os_syscall_record_entry(struct target *target,tid_t tid,
			       struct target_os_syscall *syscall) {
    struct target_os_syscall_state *scs;

    target_thread_gkv_remove(target,tid,TARGET_OS_SYSCALL_GKV_KEY);

    scs = calloc(1,sizeof(*scs));
    scs->syscall = syscall;

    if (target_thread_gkv_insert(target,tid,TARGET_OS_SYSCALL_GKV_KEY,scs,
				 _target_os_syscall_state_dtor)) {
	verror("could not insert syscall state for tid %"PRIiTID"!\n",tid);
	free(scs);
	return NULL;
    }

    return scs;
}

int target_os_syscall_record_argv(struct target *target,tid_t tid,
				  struct array_list *regvals,
				  struct array_list *argvals) {
    struct target_os_syscall_state *scs;

    scs = (struct target_os_syscall_state *) \
	target_thread_gkv_lookup(target,tid,TARGET_OS_SYSCALL_GKV_KEY);
    if (!scs) {
	verror("could not store arg values; no syscall entry recorded!\n");
	return -1;
    }

    scs->regvals = regvals;
    scs->argvals = argvals;

    return 0;
}

int target_os_syscall_record_return(struct target *target,tid_t tid,
				    REGVAL retval) {
    struct target_os_syscall_state *scs;

    scs = (struct target_os_syscall_state *) \
	target_thread_gkv_lookup(target,tid,TARGET_OS_SYSCALL_GKV_KEY);
    if (!scs) {
	verror("could not store return value; no syscall entry recorded!\n");
	return -1;
    }

    scs->returned = 1;
    scs->retval = retval;

    return 0;
}
