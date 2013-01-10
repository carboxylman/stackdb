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

struct evloop *evloop_create(evloop_error_handler_t ehandler);

int evloop_maxsize(struct evloop *evloop);

int evloop_set_fd(struct evloop *evloop,int fd,int fdtype,
		  evloop_handler_t handler,void *state);
int evloop_unset_fd(struct evloop *evloop,int fd,int fdtype);

int evloop_run(struct evloop *evloop,struct timeval *timeout,
	       struct evloop_fdinfo **error_fdinfo);
int evloop_handleone(struct evloop *evloop,struct timeval *timeout);

void evloop_free(struct evloop *evloop);

#endif /* __EVLOOP_H__ */
