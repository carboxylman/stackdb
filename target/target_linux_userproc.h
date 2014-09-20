/*
 * Copyright (c) 2011, 2012, 2013, 2014 The University of Utah
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

#ifndef __TARGET_LINUX_USERPROC_H__
#define __TARGET_LINUX_USERPROC_H__

#include <sys/ptrace.h>
#include <sys/user.h>
#include <glib.h>

#include "evloop.h"

#include "target_api.h"

extern struct target_ops linux_userspace_process_ops;

/* linux userproc target ops */

struct target *linux_userproc_instantiate(struct target_spec *spec,
					  struct evloop *evloop);
struct linux_userproc_spec *linux_userproc_build_spec(void);
void linux_userproc_free_spec(struct linux_userproc_spec *lspec);
int linux_userproc_spec_to_argv(struct target_spec *spec,int *argc,char ***argv);

int linux_userproc_attach_thread(struct target *target,tid_t parent,tid_t tid);
int linux_userproc_detach_thread(struct target *target,tid_t tid,
				 int detaching_all,int stay_paused);

/*
 * Once attached to a process, attach to one of its threads.
 */


int linux_userproc_last_signo(struct target *target,tid_t tid);
int linux_userproc_last_status(struct target *target,tid_t tid);

int linux_userproc_at_syscall(struct target *target,tid_t tid);
int linux_userproc_at_exec(struct target *target,tid_t tid);
int linux_userproc_at_exit(struct target *target,tid_t tid);

int linux_userproc_pid(struct target *target);

#if __WORDSIZE == 64
typedef unsigned long int ptrace_reg_t;
#else
typedef int ptrace_reg_t;
#endif

struct linux_userproc_spec {
    int pid;
    char *program;
    char **argv;
    char **envp;
};

struct linux_userproc_thread_state {
    int8_t ctl_sig_sent:1, /* If set, don't reinject a signal on restart. */
	   ctl_sig_recv:1, /* If set, don't reinject a signal on restart. */
	   ctl_sig_synch:1,/* If set, don't handle any signals in evloop. */
	   ctl_sig_pause_all:1;
    int last_status;
    int last_signo;

    struct user_regs_struct regs;

    /* XXX: can we debug a 32-bit target on a 64-bit host?  If yes, how 
     * we use this might have to change.
     */
    ptrace_reg_t dr[8];
};

struct linux_userproc_state {
    int pid;
    int memfd;

    int8_t initdidattach:1,
	   ctl_sig_pausing_all:1;

    /*
     * This is weird, but for the ptrace target, we always "know" which
     * thread is the current one, because wait() tells us.  BUT, we need
     * to communicate this to various other target API functions like
     * load_current_thread(), so save it off here.
     */
    int current_tid;

    int32_t ptrace_opts;
    int32_t ptrace_opts_new;
    enum __ptrace_request ptrace_type;

    /*
     * If a newly-cloned thread signals its initial ptrace SIGSTOP, and
     * we get that signal before we get notified about the clone event
     * via SIGCHLD, don't die on error IF the thread exists in /proc.
     *
     * We also have to save its waitpid status here so we can know if we
     * saw it when we actually DO get the SIGCHLD and add the new thread
     * -- so we don't try to wait for the SIGSTOP again.
     */
    GHashTable *new_racy_threads;
};

struct linux_userproc_exception_handler_state {
    tid_t tid;
    int pstatus;
};

#endif /* __TARGET_LINUX_USERPROC_H__ */
