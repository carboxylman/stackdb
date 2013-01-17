/*
 * Copyright (c) 2012, 2013 The University of Utah
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

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <inttypes.h>

#include "log.h"
#include "waitpipe.h"
#include "evloop.h"

/*
 * We just fork several children, and use the event loop and
 * waitpipe stuff to monitor child death in a loop.  Good enough.
 */

int evloop_error_handler(int errortype,int fd,int fdtype,
			 struct evloop_fdinfo *error_fdinfo) {
    printf("ERROR: type %d on fd %d (fdtype %d)\n",
	   errortype,fd,fdtype);
    return 0;
}

int evloop_handler(int fd,int evloop_fdtype,void *state) {
    int pid = (int)(uintptr_t)state;
    int status = 0;

    /* wait for it... */
    printf("pid %d finished?\n",pid);
    waitpid(pid,&status,0);
    printf("pid %d finished status %d\n",pid,WEXITSTATUS(status));

    /* nuke the pipe */
    waitpipe_remove(pid);

    /* remove the fds from the event loop */
    return EVLOOP_HRET_REMOVEALLTYPES;
}

void alt_sigchld_handler(int signo,siginfo_t *siginfo,void *ucontext) {
    int status;

    printf("alt_sigchld from pid %d\n",siginfo->si_pid);
    waitpid(siginfo->si_pid,&status,0);
    printf("alt_sigchld from pid %d; status %d\n",
	  siginfo->si_pid,WEXITSTATUS(status));
}

int main(int argc,char **argv) {
    struct evloop *evloop;
    struct evloop_fdinfo *error_fdinfo;
    int i;
    int n = 4;
    int pid;
    int fd;

    vmi_set_log_level(16);
    vmi_set_log_area_flags(LA_LIB,LF_EVLOOP | LF_WAITPIPE);

    waitpipe_init_auto(alt_sigchld_handler);

    evloop = evloop_create(evloop_error_handler);

    for (i = 0; i < n; ++i) {
	if ((pid = fork())) {
	    /* The first child is a test of alt_sigchld_handler */
	    if (i > 0) {
		fd = waitpipe_add(pid);
		evloop_set_fd(evloop,fd,EVLOOP_FDTYPE_R,evloop_handler,(void *)(uintptr_t)(pid));
	    }
	}
	else {
	    sleep(4 + 2*i);
	    exit(i);
	}
    }

    /* Now wait for them all via an event loop. */
    while (evloop_maxsize(evloop) > -1) {
	evloop_run(evloop,NULL,&error_fdinfo);
    }

    evloop_free(evloop);

    waitpipe_fini();

    printf("Test finished.\n");

    exit(0);
}
