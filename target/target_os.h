/*
 * Copyright (c) 2013 The University of Utah
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

#ifndef __TARGET_OS_H__
#define __TARGET_OS_H__

#include <glib.h>

#include "target_api.h"

typedef enum {
    TARGET_OS_TYPE_NONE  = 0,
    TARGET_OS_TYPE_LINUX = 1,
} target_os_type_t;

extern struct target_os_ops os_linux_generic_ops;

struct target_os_syscall {
    int num;
    ADDR addr;
    struct bsymbol *bsymbol;
    /*
     * If @bsymbol, this is the list of struct symbol *s returned by
     * symbol_get_members().
     */
    struct array_list *args;
};

struct target_os_syscall_state {
    unsigned int returned:1;
    struct target_os_syscall *syscall;
    /* A list of REGVALs. */
    struct array_list *regvals;
    /* A list of struct value *s loaded from REGVALs according to @syscall. */
    struct array_list *argvals;
    REGVAL retval;
};

#define SAFE_TARGET_OS_OP(target,op,errval,...)				\
    do {								\
        if (target->kind != TARGET_KIND_OS) {				\
	    verror("target %s is not an OS!\n",target->name);		\
	    errno = EINVAL;						\
	    return (errval);						\
	}								\
	else if (!target->kind_ops.os || !target->kind_ops.os->op) {	\
	    verror("target %s does not support OS operation '%s'!\n",	\
		   target->name,#op);					\
	    errno = ENOSYS;						\
	    return (errval);						\
	}								\
	else {								\
	    return target->kind_ops.os->op(__VA_ARGS__);		\
	}								\
    } while (0);


target_os_type_t target_os_type(struct target *target);
uint64_t target_os_version(struct target *target);
int target_os_version_cmp(struct target *target,uint64_t vers);
int target_os_syscall_table_load(struct target *target);
int target_os_syscall_table_unload(struct target *target);
GHashTable *target_os_syscall_table_get(struct target *target);
int target_os_syscall_table_get_max_num(struct target *target);
struct target_os_syscall *target_os_syscall_lookup_name(struct target *target,
							char *name);
struct target_os_syscall *target_os_syscall_lookup_num(struct target *target,
						       int num);
struct target_os_syscall *target_os_syscall_lookup_addr(struct target *target,
							ADDR addr);
int target_os_syscall_table_reload(struct target *target,int force);
int target_os_syscall_table_store(struct target *target);

struct probe *target_os_syscall_probe(struct target *target,tid_t tid,
				      struct target_os_syscall *syscall,
				      probe_handler_t pre_handler,
				      probe_handler_t post_handler,
				      void *handler_data);
struct probe *target_os_syscall_probe_all(struct target *target,tid_t tid,
					  probe_handler_t pre_handler,
					  probe_handler_t post_handler,
					  void *handler_data);
struct target_os_syscall_state *target_os_syscall_probe_last(struct target *target,
							     tid_t tid);

/* These can be used in os personality implementations. */
void *target_os_syscall_probe_summarize(struct probe *probe);
void *target_os_syscall_probe_summarize_tid(struct probe *probe,tid_t tid);

/*
 * The intent here is to provide a generic interface to common OS-level
 * abstractions.
 */
struct target_os_ops {
    int (*init)(struct target *target);
    int (*close)(struct target *target);
    int (*fini)(struct target *target);

    /*
     * Version info.
     */
    target_os_type_t (*os_type)(struct target *target);
    uint64_t (*os_version)(struct target *target);
    char *(*os_version_string)(struct target *target);
    int (*os_version_cmp)(struct target *target,uint64_t vers);

    /*
     * Syscalls.
     */
    /* Mandatory -- if supply one, supply all. */
    int (*syscall_table_load)(struct target *target);
    int (*syscall_table_unload)(struct target *target);
    GHashTable *(*syscall_table_get)(struct target *target);
    struct target_os_syscall *(*syscall_lookup_name)(struct target *target,
						     char *name);
    struct target_os_syscall *(*syscall_lookup_num)(struct target *target,
						    int num);
    struct target_os_syscall *(*syscall_lookup_addr)(struct target *target,
						     ADDR addr);
    /* Optional. */
    int (*syscall_table_reload)(struct target *target,int force);
    int (*syscall_table_store)(struct target *target);

    /*
     * Syscall probing.
     *
     * The probes returned here *must* be of type
     * target_os_syscall_probe; and they are not autofree.  This probe
     * type tracks syscall state, and probe_summarize_tid() will return
     * the current/last syscall state for that thread.  State should be
     * cleared when a new syscall is hit.
     *
     * When a user gets one of these probes, and registers one of their
     * probes on it, their pre_handler will be called whenever a syscall
     * is entered (either directly at the function itself; or on the
     * general syscall entry path); and their post_handler will be
     * called when the system returns (depending on the backend, this
     * could be either the syscall function's RET, or on the
     * SYSRET/SYSEXIT/IRET from kernel space into userland).
     *
     * Syscall probes should always fire handlers when the CPU is in the
     * kernel.  This means that if the backend places a probe on a
     * SYSRET or IRET, only the pre-handler should be used.
     *
     * (This is here because there is no other better place for it.
     * Syscall probing is fundamentally a per-OS thing because of the
     * complexities of system entry/exit.  For instance, some syscall
     * function bodies in the Linux kernel don't return directly (i.e.,
     * stub_execve just JMPs to sys_execve after doing some stuff) -- so
     * we can't depend on being able to just probe the function entry
     * instruction and any of its RETs.  Also, there might be
     * opportunities to combine _probe and _probe_all (suppose user
     * requests a probe of mmap, and then requests a probe of all -- for
     * the kernel, the all probe makes the mmap probe irrelevant).
     * Anyway, for now, syscall probing is in here.)
     */
    struct probe *(*syscall_probe)(struct target *target,tid_t tid,
				   struct target_os_syscall *syscall,
				   probe_handler_t pre_handler,
				   probe_handler_t post_handler,
				   void *handler_data);
    struct probe *(*syscall_probe_all)(struct target *target,tid_t tid,
				       probe_handler_t pre_handler,
				       probe_handler_t post_handler,
				       void *handler_data);
};

extern struct probe_ops target_os_syscall_ret_probe_ops;

/*
 * Helper functions for backend builders.
 */
struct target_os_syscall_state *
target_os_syscall_record_entry(struct target *target,tid_t tid,
			       struct target_os_syscall *syscall);
/*
 * If either record_argv or record_return fail, the caller must free the
 * values; otherwise, it must *not* free the values, nor ever use them
 * again!
 */
int target_os_syscall_record_argv(struct target *target,tid_t tid,
				  struct array_list *regvals,
				  struct array_list *argvals);
int target_os_syscall_record_return(struct target *target,tid_t tid,
				    REGVAL retval);
int target_os_syscall_record_clear(struct target *target,tid_t tid);

#endif /* __TARGET_OS_H__ */