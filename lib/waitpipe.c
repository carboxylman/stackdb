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

#include "log.h"
#include "waitpipe.h"

#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

struct waitpipectl {
    GHashTable *pids;
    GHashTable *readfds;
    void (*alt_handler)(int,siginfo_t *,void *);
};

/* Our internal sighandler. */
static void waitpipe_sigchld(int signo,siginfo_t *siginfo,void *ucontext);

/*
 * There can only be one waitpipe per process, so this is safe.
 */
static struct waitpipectl waitpipe = { NULL,NULL,NULL };
static struct sigaction waitpipe_act = {
    .sa_sigaction = waitpipe_sigchld,
    .sa_flags = SA_SIGINFO,
};

void waitpipe_notify(int signo,siginfo_t *siginfo) {
    return waitpipe_sigchld(signo,siginfo,NULL);
}

static void waitpipe_sigchld(int signo,siginfo_t *siginfo,void *ucontext) {
    pid_t pid;
    /* int code; */
    /* int status; */
    int *pipefds;
    /* int rc; */

    pid = siginfo->si_pid;
    if (signo == SIGCHLD && pid > 0) {

	/*
	 * code = siginfo->si_code;
	 * status = siginfo->si_status;
	 */
	vdebug(9,LA_LIB,LF_WAITPIPE,"pid %d code 0x%08x status 0x%08x\n",
	       pid,siginfo->si_code,siginfo->si_status);

	pipefds = (int *)g_hash_table_lookup(waitpipe.pids,
					     (gpointer)(uintptr_t)pid);
	if (pipefds) {
	    /*
	     * NB: we could also write the code or status, but waitpid()
	     * can get those things too, so why bother?
	     */
	    vdebug(9,LA_LIB,LF_WAITPIPE,"writing to writefd %d for pid %d\n",
		   pipefds[1],pid);

	    if (write(pipefds[1],"",1) < 0) 
		verror("write(fd %d): %s\n",pipefds[1],strerror(errno));
	}
	else if (waitpipe.alt_handler) {
	    vdebug(9,LA_LIB,LF_WAITPIPE,"invoking alt sigchld handler for pid %d\n",
		   pid);

	    waitpipe.alt_handler(signo,siginfo,ucontext);
	}
	/*
	 * XXX: don't try this!  We cannot wait for "unknown" children;
	 * they might just signal us before we record them in our
	 * table.  Or, they might be *vanishing* from our table, but
	 * signal us, I think?  Anyway, we can't wait for anything here;
	 * any waiting has to happen elsewhere once we *know* that a
	 * specific process should be signaling us.
	 */
	/*
	else {
	    status = 0;
	    rc = waitpid(pid,&status,WNOHANG);
	    if (rc == 0) {
		vdebug(9,LA_LIB,LF_WAITPIPE,
		       "SIGCHLD for %d, but waitpid returned nothing!\n",pid);
	    }
	    else if (rc < 0) {
		verror("waitpid(%d): %s\n",pid,strerror(errno));
	    }
	    else {
		vdebug(9,LA_LIB,LF_WAITPIPE,
		       "waited for unknown child %d successfully\n",pid);
	    }
	}
	*/
    }
}

int waitpipe_is_initialized(void) {
    if (waitpipe.pids)
	return 1;

    return 0;
}

int waitpipe_init_ext(void (*alt_handler)(int,siginfo_t *,void *)) {
    if (waitpipe.pids) {
	vwarn("global waitpipe already initialized!\n");
	errno = EBUSY;
	return -1;
    }

    vdebug(9,LA_LIB,LF_WAITPIPE,"alt_handler = %p\n",alt_handler);

    waitpipe.pids = g_hash_table_new(g_direct_hash,g_direct_equal);
    waitpipe.readfds = g_hash_table_new(g_direct_hash,g_direct_equal);
    waitpipe.alt_handler = alt_handler;

    return 0;
}

int waitpipe_init_auto(void (*alt_handler)(int,siginfo_t *,void *)) {
    if (waitpipe.pids) {
	vwarn("global waitpipe already initialized!\n");
	errno = EBUSY;
	return -1;
    }

    vdebug(9,LA_LIB,LF_WAITPIPE,"alt_handler = %p\n",alt_handler);

    waitpipe.pids = g_hash_table_new(g_direct_hash,g_direct_equal);
    waitpipe.readfds = g_hash_table_new(g_direct_hash,g_direct_equal);
    waitpipe.alt_handler = alt_handler;

    if (sigaction(SIGCHLD,&waitpipe_act,NULL)) {
	g_hash_table_destroy(waitpipe.pids);
	g_hash_table_destroy(waitpipe.readfds);
	waitpipe.pids = NULL;
	waitpipe.readfds = NULL;
	waitpipe.alt_handler = NULL;
	verror("sigaction: %s\n",strerror(errno));
	return -1;
    }

    return 0;
}

int waitpipe_fini(void) {
    if (waitpipe.pids) {
	g_hash_table_destroy(waitpipe.pids);
	g_hash_table_destroy(waitpipe.readfds);
    }
    waitpipe.pids = NULL;
    waitpipe.readfds = NULL;
    waitpipe.alt_handler = NULL;

    vdebug(9,LA_LIB,LF_WAITPIPE,"fini\n");

    return 0;
}

/*
 * Returns half of a pipe -- the end that will receive the write when a
 * SIGCHLD comes in for one of our pids.
 */
int waitpipe_add(int pid) {
    int *pipefds;
    int rc;
    siginfo_t si;

    if (!waitpipe.pids) {
	verror("waitpipe not initialized!\n");
	errno = EINVAL;
	return -1;
    }

    pipefds = malloc(sizeof(*pipefds)*2);

    pipefds[0] = -1;
    pipefds[1] = -1;

    if (pipe(pipefds)) {
	verror("pipe: %s\n",strerror(errno));
	free(pipefds);
	return -1;
    }

    /*
     * Make them nonblocking so our sighandler doesn't block on a full
     * pipe.  I can't imagine much how this could happen, but I suppose
     * if the ptrace target has a bug and breakpoint keeps being hit
     * over and over again, and the waitpipe_sigchld handler is called
     * at least max pipe size times before the thread with the select()
     * handling the other end of the waitpipe is called, then we have a
     * problem.  Other than that though...
     *
     * And it is also convenient for the child not to block on a read()
     * of the pipe if there is nothing there, doh.
     */
    fcntl(pipefds[0],F_SETFL,fcntl(pipefds[0],F_GETFL) | O_NONBLOCK);
    fcntl(pipefds[1],F_SETFL,fcntl(pipefds[1],F_GETFL) | O_NONBLOCK);

    /*
     * Also make them close on exec; we don't want any forked/exec
     * targets/analyses to inherit these...
     */
    fcntl(pipefds[0],F_SETFD,FD_CLOEXEC);
    fcntl(pipefds[1],F_SETFD,FD_CLOEXEC);

    /* Place the pipe in the child pid demux table. */
    g_hash_table_insert(waitpipe.pids,
			(gpointer)(uintptr_t)pid,(gpointer)(uintptr_t)pipefds);

    /* Place the readfd/pid in the reverse child pid demux table. */
    g_hash_table_insert(waitpipe.readfds,
			(gpointer)(uintptr_t)pipefds[0],
			(gpointer)(uintptr_t)pid);

    /*
     * NB: once it is in our tables, and thus is ready to responded to
     * from our signal handler, check and make sure @pid is actually
     * live.  If it is not, we won't get signaled.
     */
    memset(&si,0,sizeof(si));
    rc = waitid(P_PID,pid,&si,WNOHANG | WEXITED | WNOWAIT);
    if (rc < 0) {
	if (errno == ECHILD) {
	    if (kill(pid,0) < 0 && errno == ESRCH) {
		/* Unwind everything we just did. */
		g_hash_table_remove(waitpipe.pids,(gpointer)(uintptr_t)pid);
		g_hash_table_remove(waitpipe.readfds,(gpointer)(uintptr_t)pipefds[0]);
		close(pipefds[1]);
		close(pipefds[0]);

		vwarn("pid %d disappeared before it could be added: %s!\n",
		      pid,strerror(errno));
		errno = EINVAL;
		return -1;
	    }
	}
	else {
	    vwarn("pid %d disappeared before it could be added: %s!\n",
		  pid,strerror(errno));
	    errno = EINVAL;
	    return -1;
	}
    }
    else if (rc == 0 && si.si_pid == pid) {
	if (!g_hash_table_lookup(waitpipe.pids,(gpointer)(uintptr_t)pid)) {
	    vwarn("pid %d exited before we tracked it; notifying.\n",pid);
	    waitpipe_notify(si.si_signo,&si);
	}
	else {
	    vwarn("pid %d exited before we fully tracked it; notification"
		  " already in progress.\n",pid);
	}
	return 0;
    }

    vdebug(9,LA_LIB,LF_WAITPIPE,"pid %d wfd %d rfd %d\n",pid,pipefds[1],pipefds[0]);

    /* Return the read half of the pipe for a select()-based loop to wait on. */
    return pipefds[0];
}

int waitpipe_remove(int pid) {
    int *pipefds;

    if (!waitpipe.pids) {
	verror("waitpipe not initialized!\n");
	errno = EINVAL;
	return -1;
    }

    pipefds = (int *)g_hash_table_lookup(waitpipe.pids,(gpointer)(uintptr_t)pid);
    if (pipefds) {
	g_hash_table_remove(waitpipe.pids,(gpointer)(uintptr_t)pid);
	g_hash_table_remove(waitpipe.readfds,(gpointer)(uintptr_t)pipefds[0]);
	close(pipefds[1]);
	close(pipefds[0]);

	vdebug(9,LA_LIB,LF_WAITPIPE,"pid %d wfd %d rfd %d\n",pid,pipefds[1],pipefds[0]);

	return 0;
    }
    else {
	errno = ESRCH;
	return -1;
    }
}

int waitpipe_get(int pid) {
    int *pipefds;

    if (!waitpipe.pids) {
	verror("waitpipe not initialized!\n");
	errno = EINVAL;
	return -1;
    }

    pipefds = (int *)g_hash_table_lookup(waitpipe.pids,
					 (gpointer)(uintptr_t)pid);
    if (pipefds && pipefds[0]) 
	return pipefds[0];
    else {
	vdebug(9,LA_LIB,LF_WAITPIPE,"cannot find readfd for pid %d\n",pid);
	errno = ESRCH;
	return -1;
    }
}

int waitpipe_get_pid(int readfd) {
    int pid;

    if (!waitpipe.pids) {
	verror("waitpipe not initialized!\n");
	errno = EINVAL;
	return -1;
    }

    pid = (int)(uintptr_t)g_hash_table_lookup(waitpipe.readfds,
					      (gpointer)(uintptr_t)readfd);
    if (pid) 
	return pid;
    else {
	vdebug(9,LA_LIB,LF_WAITPIPE,"cannot find pid for readfd %d\n",readfd);
	errno = ESRCH;
	return -1;
    }
}

int waitpipe_drain(int pid) {
    /* Do not make static to keep thread-safe. */
    char buf[128];
    int *pipefds;
    int rc;
    int retval = 0;

    if (!waitpipe.pids) {
	verror("waitpipe not initialized!\n");
	errno = EINVAL;
	return -1;
    }

    pipefds = (int *)g_hash_table_lookup(waitpipe.pids,(gpointer)(uintptr_t)pid);
    if (pipefds) {
	while ((rc = read(pipefds[0],buf,sizeof(buf)))) {
	    if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
		    return retval;
		else if (errno == EINTR)
		    /* Keep trying? */
		    ;
		else {
		    verror("read pipefd(pid %d): %s\n",pid,strerror(errno));
		    return -1;
		}
	    }
	    else 
		retval += rc;
	}

	vdebug(9,LA_LIB,LF_WAITPIPE,"pid %d wfd %d rfd %d: %d bytes\n",
	       pid,pipefds[1],pipefds[0],retval);

	return retval;
    }
    else {
	errno = ESRCH;
	return -1;
    }
}
