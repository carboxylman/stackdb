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

#ifndef __TARGET_PROCESS_H__
#define __TARGET_PROCESS_H__

#include <glib.h>

#include "target_api.h"

typedef enum {
    TARGET_PROCESS_TYPE_NONE  = 0,
    TARGET_PROCESS_TYPE_LINUX = 1,
} target_process_type_t;

#define SAFE_TARGET_PROCESS_OP(target,op,errval,...)			\
    do {								\
        if (target->personality != TARGET_PERSONALITY_PROCESS) {	\
	    verror("target %s is not a process!\n",target->name);	\
	    errno = EINVAL;						\
	    return (errval);						\
	}								\
	else if (!target->process_ops || !target->process_ops->op) {	\
	    verror("target %s does not support process operation '%s'!\n", \
		   target->name,#op);					\
	    errno = ENOSYS;						\
	    return (errval);						\
	}								\
	else {								\
	    return target->process_ops->op(__VA_ARGS__);		\
	}								\
    } while (0);

struct target_process {
    struct target *target;
    /*
     * The primary thread.
     */
    struct target_thread *thread;
    tid_t tid;

    obj_flags_t obj_flags;
    REFCNT refcnt;
    REFCNT refcntw;

    /*
     * A hashtable of tid_t to struct target_thread *.
     */
    GHashTable *threads;

    /*
     * A hashtable of tid_t to struct target_thread *.
     */
    GHashTable *children;

    /*
     * An addrspace containing regions.  This isn't very good, because
     * individual threads in the process might have their own address
     * spaces.  However, we don't tend to see this much in practice, so
     * for now it's good enough.
     */
    struct addrspace *space;

    struct target_process *parent;
};

/*
 * Helper functions for backend builders.
 */

struct target_process *target_process_create(struct target *target,
					     struct target_thread *tthread,
					     struct addrspace *space);
REFCNT target_process_free(struct target_process *process,int force);

/*
 * The intent here is to provide a generic interface to common
 * process-level abstractions.
 */
struct target_process_ops {
    int (*init)(struct target *target);
    int (*fini)(struct target *target);

    target_process_type_t (*type)(struct target *target);

};

#endif /* __TARGET_PROCESS_H__ */
