/*
 * Copyright (c) 2012 The University of Utah
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

struct waitpipectl {
    GHashTable *pids;
    GHashTable *readfds;
    void (*alt_handler)(int,siginfo_t *,void *);
};

int waitpipe_init(void (*alt_handler)(int,siginfo_t *,void *));
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
 * Returns the pid associated with this read half of the pipe.
 *
 * This is useful so that the library user doesn't have to keep their
 * own lookup structure at all.
 */
int waitpipe_get_pid(int readfd);

/* Our internal sighandler. */
void waitpipe_sigchld(int signo,siginfo_t *siginfo,void *ucontext);

#endif /* __WAITPIPE_H__ */

/*
Don't mix alarm() with wait(). You can lose error information that way.

Use the self-pipe trick. This turns any signal into a select()able event:

int selfpipe[2];
void selfpipe_sigh(int n)
{
    write(selfpipe[1], "",1);
}
void selfpipe_setup(void)
{
    static struct sigaction act;
    if (pipe(selfpipe) == -1) { abort(); }

    //fixed the misspelling of fcntl in the 3rd argument
    fcntl(selfpipe[0],F_SETFL,fcntl(selfpipe[0],F_GETFL)|O_NONBLOCK);
    fcntl(selfpipe[1],F_SETFL,fcntl(selfpipe[1],F_GETFL)|O_NONBLOCK);
    memset(&act, 0, sizeof(act));
    act.sa_handler = selfpipe_sigh;
    sigaction(SIGCHLD, &act, NULL);
}

Then, your waitpid-like function looks like this:

int selfpipe_waitpid(void)
{
    static char dummy[4096];
    fd_set rfds;
    struct timeval tv;
    int died = 0, st;

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    FD_ZERO(&rfds);
    FD_SET(selfpipe[0], &rfds);
    if (select(selfpipe[0]+1, &rfds, NULL, NULL, &tv) > 0) {
       while (read(selfpipe[0],dummy,sizeof(dummy)) > 0);
       while (waitpid(-1, &st, WNOHANG) != -1) died++;
    }
    return died;
}
*/
