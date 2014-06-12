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

#include "target.h"
#include "probe_api.h"
#include "probe.h"
#include "target_os.h"

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
