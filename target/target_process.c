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

#include "common.h"
#include "glib_wrapper.h"
#include "object.h"
#include "target.h"
#include "target_process.h"

/**
 * Creates a target_process.
 *
 * \param target The target object this process is associated with.  If
 *   the target program is a process, the target object is the target
 *   itself; if the target program is an OS, the target object is the
 *   target object for the OS.  Hopefully, this will not lead to
 *   confusion!
 * \param tthread The main thread in the process.  The thread's target
 *   object should be the same as the target object parameter above.
 * \param space The addrspace associated with the process.  Again, the
 *   space's target should be the same as the target param above.
 *
 * \return A target_process.
 */
struct target_process *target_process_create(struct target *target,
					     struct target_thread *tthread,
					     struct addrspace *space) {
    struct target_process *process;

    assert(target);
    assert(tthread);

    process = (struct target_process *)calloc(1,sizeof(*process));

    process->target = target;
    RHOLDW(target,process);

    process->threads = g_hash_table_new(g_direct_hash,g_direct_equal);
    process->children = g_hash_table_new(g_direct_hash,g_direct_equal);

    process->thread = tthread;
    process->tid = tthread->tid;
    RHOLD(tthread,process);
    g_hash_table_insert(process->threads,
			(gpointer)(uintptr_t)tthread->tid,tthread);

    process->space = space;
    if (space) {
	RHOLD(space,process);
    }

    return process;
}

/**
 * This is a noop.  We don't propagate any flags, because technically we
 * don't own any of our children --- they can exist independently of us.
 *
 * The driver needs to be aware of this!  We assume it is maintaining
 * the address space separately; but perhaps not.  At any rate, we
 * cannot propagate.
 */
void target_process_obj_flags_propagate(struct target_process *process,
					obj_flags_t orf,obj_flags_t nandf) {
    return;
}

REFCNT target_process_free(struct target_process *process,int force) {
    REFCNT trefcnt;
    REFCNT retval;
    GHashTableIter iter;
    gpointer vp;
    struct target_process *child;
    struct target_thread *tthread;

    assert(process);

    if (process->refcnt) {
	if (!force) {
	    verror("cannot free (%d refs) process %"PRIiTID"\n",
		   process->refcnt,process->tid);
	    return process->refcnt;
	}
	else {
	    vwarn("forcing free (%d refs) process %"PRIiTID"\n",
		   process->refcnt,process->tid);
	}
    }

    RWGUARD(process);

    vdebug(8,LA_TARGET,LF_PROCESS,"freeing process %d\n",process->tid);

    /* Free our children... */
    g_hash_table_iter_init(&iter,process->children);
    while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	child = (struct target_process *)vp;
	RPUT(child,target_process,process,trefcnt);
	g_hash_table_iter_remove(&iter);
    }

    if (process->refcntw) {
	if (!force) {
	    vdebug(8,LA_TARGET,LF_PROCESS,
		   "cannot free (%d wrefs) process %"PRIiTID"\n",
		   process->refcntw,process->tid);
	    RWUNGUARD(process);
	    return process->refcntw;
	}
	else {
	    vwarn("forcing free (%d refs) process %"PRIiTID"\n",
		   process->refcntw,process->tid);
	}
    }

    g_hash_table_iter_init(&iter,process->threads);
    while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	tthread = (struct target_thread *)vp;
	RPUT(tthread,target_thread,process,trefcnt);
    }
    g_hash_table_destroy(process->threads);
    process->threads = NULL;
    process->thread = NULL;
    process->tid = 0;

    g_hash_table_iter_init(&iter,process->children);
    while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	child = (struct target_process *)vp;
	/* Best we can do, if we're forcing. */
	child->parent = NULL;
    }
    g_hash_table_destroy(process->children);
    process->children = NULL;

    if (process->parent) {
	RPUTW(process->parent,target_process,process,trefcnt);
	process->parent = NULL;
    }

    if (process->space) {
	RPUT(process->space,addrspace,process,trefcnt);
	process->space = NULL;
    }

    if (process->target) {
	RPUTW(process->target,target,process,trefcnt);
	process->target = NULL;
    }

    retval = process->refcnt + process->refcntw - 1;

    free(process);

    return retval;
}
