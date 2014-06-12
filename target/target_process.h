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

struct target_process_syscall {
    int num;
    ADDR addr;
    struct bsymbol *bsymbol;
};

struct target_process_signal {
    int num;
    char *name;
};

/*
 * The intent here is to provide a generic interface to common OS-level
 * abstractions.
 */
struct target_process_ops {
    int (*init)(struct target *target);
    int (*fini)(struct target *target);

    /*
     * Version info.
     */
    target_process_type_t (*process_type)(struct target *target);
    uint64_t (*os_version)(struct target *target);
    char *(*os_version_string)(struct target *target);
    int (*os_version_cmp)(struct target *target,uint64_t vers);
};

#endif /* __TARGET_PROCESS_H__ */
