/*
 * Copyright (c) 2012, 2013, 2014 The University of Utah
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

#ifndef __EVLOOP_H__
#define __EVLOOP_H__

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>

#define EVLOOP_FDTYPE_A 0
#define EVLOOP_FDTYPE_R 1
#define EVLOOP_FDTYPE_W 2
#define EVLOOP_FDTYPE_X 3

#define EVLOOP_HRET_BADERROR      -2
#define EVLOOP_HRET_ERROR         -1
#define EVLOOP_HRET_SUCCESS        0
#define EVLOOP_HRET_REMOVETYPE     1
#define EVLOOP_HRET_REMOVEALLTYPES 2
#define EVLOOP_HRET_DONE_SUCCESS   3
#define EVLOOP_HRET_DONE_FAILURE   4

struct evloop;
struct evloop_fdinfo;

typedef enum {
    EVLOOP_RETONINT = 1 << 0,
} evloop_flags_t;

/*
 * Event loop handlers return 0 on success; 1 if they want the caller to
 * remove the fd/fdtype tuple from the set; 2 if they want the caller to
 * remove all fd types for this fd from the set (i.e.,
 * read/write/exception, not just one type).
 *
 *  They also can return -1 to indicate that evloop_run should quit looping
 * -- this should only happen when the event simply cannot be handled
 * and the only choice is to terminate the program/function calling
 * evloop_run.  Why?  Because the caller of evloop_run is supposed to not be
 * able to handle the semantics of the things it is running.  Hmm, is
 * this true?
 */
typedef int (*evloop_handler_t)(int fd,int fdtype,void *state);
typedef int (*evloop_error_handler_t)(int errortype,int fd,int fdtype,
				      struct evloop_fdinfo *error_fdinfo);

struct evloop {
    int nfds;

    evloop_error_handler_t eh;

    fd_set rfds;
    fd_set wfds;
    fd_set xfds;

    fd_set rfds_master;
    fd_set wfds_master;
    fd_set xfds_master;

    GHashTable *tab;
};

struct evloop_fdinfo {
    int fd;

    evloop_handler_t rh;
    void *rhstate;
    evloop_handler_t wh;
    void *whstate;
    evloop_handler_t xh;
    void *xhstate;
};

/*
 * Create an evloop.  If you don't set @ehandler, if any of the per-fd
 * handlers returns EVLOOP_HRET_ERROR or EVLOOP_HRET_BADERROR, that
 * fd/fdtype pair will be removed from the evloop automatically.
 */
struct evloop *evloop_create(evloop_error_handler_t ehandler);

int evloop_maxsize(struct evloop *evloop);

int evloop_set_fd(struct evloop *evloop,int fd,int fdtype,
		  evloop_handler_t handler,void *state);
int evloop_unset_fd(struct evloop *evloop,int fd,int fdtype);

int evloop_run(struct evloop *evloop,evloop_flags_t flags,struct timeval *timeout,
	       struct evloop_fdinfo **error_fdinfo);
/*
 * This is a glorified select.  It returns 0 if there are no more FDs to
 * handle (check via evloop_maxsize() < 0); returns 0 if the timeout is
 * hit (check the @timeout struct); returns 0 if an FD was handled
 * successfully (check @*handled_fdinfo and see if it was set); returns
 * 0 with @hrc set to EVLOOP_HRET_DONE_FAILURE if it handled an FD
 * successfully but the handler failed.
 *
 * Then, for error conditions: returns -1 with errno set if select
 * failed; returns -1 on internal bug/user error (and sets errno EBADFD
 * if select thought fd was in evloop set, but it was not set; or errno
 * set to ENOENT if select claimed some fd was set but we couldn't find
 * one); errno set to EBADSLT if the FD was set but there is no handler
 * (this should only happen if user mucks with fdinfo data struct
 * badly); ENOTSUP if the handler returns an unsupported error code.
 *
 * If flags & EVLOOP_RETONINT, if select() is interrupted, it returns -1
 * and leaves errno set to EINTR.  If !(flags & EVLOOP_RETONINT), the
 * loop continues even if select() was interrupted.  If you need to
 * handle signals synchronously with respect to whatever you're looping
 * over, setting flags | EVLOOP_RETONINT will help.
 */
int evloop_handleone(struct evloop *evloop,evloop_flags_t flags,
		     struct timeval *timeout,
		     struct evloop_fdinfo **handled_fdinfo,
		     int *handled_fdtype,int *handled_hrc);

void evloop_free(struct evloop *evloop);

#endif /* __EVLOOP_H__ */
