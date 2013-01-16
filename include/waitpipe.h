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

#ifndef __WAITPIPE_H__
#define __WAITPIPE_H__

#include <signal.h>
#include <glib.h>

/*
 * The idea is to turn SIGCHLD into select()able events.
 *
 * The only restriction on this little library is that it cannot handle
 * pid 0; only pids > 0 are allowed.  No problem for us, since 0 cannot
 * be any process's child.
 */

/* @return 1 if the waitpipe is initialized; 0 otherwise. */
int waitpipe_is_initialized(void);

/*
 * Initialize the waitpipe, but do not install a SIGCHLD handler via
 * sigaction.  We expect to be notified via waitpipe_notify() by some
 * external signal handler.
 */
int waitpipe_init_ext(void (*alt_handler)(int,siginfo_t *,void *));

/*
 * Initialize the waitpipe and install a SIGCHLD handler via sigaction.
 */
int waitpipe_init_auto(void (*alt_handler)(int,siginfo_t *,void *));

/*
 * External SIGCHLD handlers should call this, if the waitpipe was
 * initialized via waitpipe_init_ext() above.
 */
void waitpipe_notify(int signo,siginfo_t *siginfo);

int waitpipe_fini(void);

/*
 * Returns half of a pipe -- the end that will receive the write when a
 * SIGCHLD comes in for one of our pids.
 */
int waitpipe_add(int pid);
/*
 * Removes the pipe for @pid and closes its halves.
 */
int waitpipe_remove(int pid);
/*
 * Returns how many bytes were available to read() from the read half of
 * the pipe for @pid.  Returns 0 if none; -1 on error; or a positive
 * integer which corresponds to the number of signals (and this number
 * may cap out at the max pipe size if the pipe got full due to too many
 * signals).
 */
int waitpipe_drain(int pid);

/*
 * Returns the readfd associated with this pid, if one already exists.
 */
int waitpipe_get(int readfd);

/*
 * Returns the pid associated with this read half of the pipe.
 *
 * This is useful so that the library user doesn't have to keep their
 * own lookup structure at all.
 */
int waitpipe_get_pid(int readfd);

#endif /* __WAITPIPE_H__ */
