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

#include "evloop.h"
#include "log.h"

#include <stdlib.h>
#include <glib.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>

struct evloop *evloop_create(evloop_error_handler_t ehandler) {
    struct evloop *evloop = calloc(1,sizeof(*evloop));

    evloop->tab = g_hash_table_new(g_direct_hash,g_direct_equal);
    evloop->nfds = -1;

    evloop->eh = ehandler;

    FD_ZERO(&evloop->rfds_master);
    FD_ZERO(&evloop->wfds_master);
    FD_ZERO(&evloop->xfds_master);

    return evloop;
}

int evloop_set_fd(struct evloop *evloop,int fd,int fdtype,
		  evloop_handler_t handler,void *state) {
    struct evloop_fdinfo *fdinfo;

    if (!handler) {
	verror("must set a handler!\n");
	errno = EINVAL;
	return -1;
    }

    fdinfo = (struct evloop_fdinfo *)g_hash_table_lookup(evloop->tab,
						      (gpointer)(uintptr_t)fd);
    if (!fdinfo) {
	fdinfo = calloc(1,sizeof(*fdinfo));
	fdinfo->fd = fd;

	if (fd > evloop->nfds)
	    evloop->nfds = fd;

	g_hash_table_insert(evloop->tab,
			    (gpointer)(uintptr_t)fd,(gpointer)fdinfo);
    }

    if (fdtype == EVLOOP_FDTYPE_R || fdtype == EVLOOP_FDTYPE_A) {
	fdinfo->rh = handler;
	fdinfo->rhstate = state;

	FD_SET(fd,&evloop->rfds_master);
    }

    if (fdtype == EVLOOP_FDTYPE_W || fdtype == EVLOOP_FDTYPE_A) {
	fdinfo->wh = handler;
	fdinfo->whstate = state;

	FD_SET(fd,&evloop->wfds_master);
    }

    if (fdtype == EVLOOP_FDTYPE_X || fdtype == EVLOOP_FDTYPE_A) {
	fdinfo->xh = handler;
	fdinfo->xhstate = state;

	FD_SET(fd,&evloop->xfds_master);
    }

    vdebug(9,LOG_OTHER,"fd %d fdtype %d handler %p state %p\n",
	   fd,fdtype,handler,state);

    return 0;
}

static int __evloop_unset_fd(struct evloop *evloop,int fd,int fdtype) {
    struct evloop_fdinfo *fdinfo;
    GHashTableIter iter;
    int new_max_fd = -2;

    fdinfo = (struct evloop_fdinfo *)g_hash_table_lookup(evloop->tab,
						     (gpointer)(uintptr_t)fd);
    if (!fdinfo) {
	verror("no such fd %d\n",fd);
	errno = EINVAL;
	return -1;
    }

    vdebug(9,LOG_OTHER,"fd %d fdtype %d\n",fd,fdtype);

    /*
     * Note that below we clear both fdsets in case we're removing an fd
     * during the handling of a select() call in evloop_run().
     */
    if (fdtype == EVLOOP_FDTYPE_R || fdtype == EVLOOP_FDTYPE_A) {
	fdinfo->rh = NULL;
	fdinfo->rhstate = NULL;

	FD_CLR(fd,&evloop->rfds_master);
	FD_CLR(fd,&evloop->rfds);
    }

    if (fdtype == EVLOOP_FDTYPE_W || fdtype == EVLOOP_FDTYPE_A) {
	fdinfo->wh = NULL;
	fdinfo->whstate = NULL;

	FD_CLR(fd,&evloop->wfds_master);
	FD_CLR(fd,&evloop->wfds);
    }

    if (fdtype == EVLOOP_FDTYPE_X || fdtype == EVLOOP_FDTYPE_A) {
	fdinfo->xh = NULL;
	fdinfo->xhstate = NULL;

	FD_CLR(fd,&evloop->xfds_master);
	FD_CLR(fd,&evloop->xfds);
    }

    /* Recalculate evloop->nfds if we have no handlers left. */
    if (!fdinfo->rh && !fdinfo->wh && !fdinfo->xh) {
	/* Recalculate evloop->nfds. */
	g_hash_table_iter_init(&iter,evloop->tab);
	while (g_hash_table_iter_next(&iter,NULL,(gpointer)&fdinfo)) {
	    if (fdinfo->fd > new_max_fd)
		new_max_fd = fdinfo->fd;
	}

	evloop->nfds = new_max_fd;

	vdebug(9,LOG_OTHER,"removed fd %d (except from hashtable); nfds = %d\n",
	       fd,evloop->nfds);
    }

    return 0;
}

int evloop_unset_fd(struct evloop *evloop,int fd,int fdtype) {
    struct evloop_fdinfo *fdinfo;

    fdinfo = (struct evloop_fdinfo *)g_hash_table_lookup(evloop->tab,
						     (gpointer)(uintptr_t)fd);
    if (!fdinfo) {
	verror("no such fd %d\n",fd);
	errno = EINVAL;
	return -1;
    }

    __evloop_unset_fd(evloop,fd,fdtype);

    vdebug(9,LOG_OTHER,"fd %d fdtype %d\n",fd,fdtype);

    /* Remove the fd if we have no handlers left. */
    if (!fdinfo->rh && !fdinfo->wh && !fdinfo->xh) {
	g_hash_table_remove(evloop->tab,(gpointer)(uintptr_t)fd);
	free(fdinfo);

	vdebug(9,LOG_OTHER,"removed fd %d completely; nfds = %d\n",
	       fd,evloop->nfds);
    }

    return 0;
}

int evloop_maxsize(struct evloop *evloop) {
    return evloop->nfds;
}

int evloop_run(struct evloop *evloop,struct timeval *timeout,
	    struct evloop_fdinfo **error_fdinfo) {
    int rc;
    int hrc;
    int i;
    struct evloop_fdinfo *fdinfo;
    GHashTableIter iter;

    if (evloop->nfds < 0) {
	vwarn("no file descriptors to monitor!\n");
	//errno = EINVAL;
	return 0;
    }

    while (1) {
	evloop->rfds = evloop->rfds_master;
	evloop->wfds = evloop->wfds_master;
	evloop->xfds = evloop->xfds_master;

	if (evloop->nfds < 0) {
	    /*
	     * We removed all the FDs; end.
	     *
	     * User must distinguish this case from the timeout
	     * expiration case by calling evloop_maxsize() and checking to
	     * see if it is < 0.
	     */
	    return 0;
	}

	rc = select(evloop->nfds + 1,&evloop->rfds,&evloop->wfds,&evloop->xfds,timeout);
	if (rc == 0) {
	    /* Timeout expired; return to user. */
	    return 0;
	}
	else if (rc < 0) {
	    if (errno == EINTR)
		continue;
	    else {
		verror("select: %s\n",strerror(errno));
		return -1;
	    }
	}

	vdebug(9,LOG_OTHER,"select() -> %d\n",rc);

	for (i = 0; i < evloop->nfds + 1; ++i) {
	    if (FD_ISSET(i,&evloop->rfds)) {
		fdinfo = (struct evloop_fdinfo *) \
		    g_hash_table_lookup(evloop->tab,(gpointer)(uintptr_t)i);
		if (!fdinfo || !fdinfo->rh) {
		    vwarn("BUG: fd set in select, but not in evloop table"
			  " or no read handler; removing!\n");
		    FD_CLR(i,&evloop->rfds_master);
		}
		else {
		    vdebug(9,LOG_OTHER,"rfd %d\n",i);

		    hrc = fdinfo->rh(i,EVLOOP_FDTYPE_R,fdinfo->rhstate);
		    if (hrc == EVLOOP_HRET_BADERROR) {
			if (error_fdinfo) 
			    *error_fdinfo = fdinfo;
			verror("immediately fatal error on rfd %d\n",i);
			if (evloop->eh)
			    evloop->eh(hrc,i,EVLOOP_FDTYPE_R,fdinfo);
			return -1;
		    }
		    else if (hrc == EVLOOP_HRET_ERROR) {
			if (error_fdinfo && !*error_fdinfo) {
			    *error_fdinfo = fdinfo;
			    verror("triggering fatal error on rfd %d;"
				   " finishing this pass\n",i);
			    if (evloop->eh)
				evloop->eh(hrc,i,EVLOOP_FDTYPE_R,fdinfo);

			}
			else {
			    verror("fatal error on rfd %d;"
				   " finishing this pass\n",i);
			    if (evloop->eh)
				evloop->eh(hrc,i,EVLOOP_FDTYPE_R,fdinfo);

			}
		    }
		    else if (hrc == EVLOOP_HRET_REMOVETYPE) {
			evloop_unset_fd(evloop,i,EVLOOP_FDTYPE_R);
		    }
		    else if (hrc == EVLOOP_HRET_REMOVEALLTYPES) {
			evloop_unset_fd(evloop,i,EVLOOP_FDTYPE_A);
		    }
		    else if (hrc == EVLOOP_HRET_DONE_SUCCESS
			     || hrc == EVLOOP_HRET_DONE_FAILURE) {
			goto done_removeall;
		    }
		}
	    }
	    else if (FD_ISSET(i,&evloop->wfds)) {
		fdinfo = (struct evloop_fdinfo *) \
		    g_hash_table_lookup(evloop->tab,(gpointer)(uintptr_t)i);
		if (!fdinfo || !fdinfo->wh) {
		    vwarn("BUG: fd set in select, but not in evloop table"
			  " or no write handler; removing!\n");
		    FD_CLR(i,&evloop->wfds_master);
		}
		else {
		    vdebug(9,LOG_OTHER,"wfd %d\n",i);

		    hrc = fdinfo->wh(i,EVLOOP_FDTYPE_W,fdinfo->whstate);
		    if (hrc == EVLOOP_HRET_BADERROR) {
			if (error_fdinfo) 
			    *error_fdinfo = fdinfo;
			verror("immediately fatal error on wfd %d\n",i);
			if (evloop->eh)
			    evloop->eh(hrc,i,EVLOOP_FDTYPE_W,fdinfo);
			return -1;
		    }
		    else if (hrc == EVLOOP_HRET_ERROR) {
			if (error_fdinfo && !*error_fdinfo) {
			    *error_fdinfo = fdinfo;
			    verror("triggering fatal error on wfd %d;"
				   " finishing this pass\n",i);
			    if (evloop->eh)
				evloop->eh(hrc,i,EVLOOP_FDTYPE_W,fdinfo);
			}
			else {
			    verror("fatal error on wfd %d;"
				   " finishing this pass\n",i);
			    if (evloop->eh)
				evloop->eh(hrc,i,EVLOOP_FDTYPE_W,fdinfo);
			}
		    }
		    else if (hrc == EVLOOP_HRET_REMOVETYPE) {
			evloop_unset_fd(evloop,i,EVLOOP_FDTYPE_W);
		    }
		    else if (hrc == EVLOOP_HRET_REMOVEALLTYPES) {
			evloop_unset_fd(evloop,i,EVLOOP_FDTYPE_A);
		    }
		    else if (hrc == EVLOOP_HRET_DONE_SUCCESS
			     || hrc == EVLOOP_HRET_DONE_FAILURE) {
			goto done_removeall;
		    }
		}
	    }
	    else if (FD_ISSET(i,&evloop->xfds)) {
		fdinfo = (struct evloop_fdinfo *) \
		    g_hash_table_lookup(evloop->tab,(gpointer)(uintptr_t)i);
		if (!fdinfo || !fdinfo->xh) {
		    vwarn("BUG: fd set in select, but not in evloop table"
			  " or no exception handler; removing!\n");
		    FD_CLR(i,&evloop->xfds_master);
		}
		else {
		    vdebug(9,LOG_OTHER,"xfd %d\n",i);

		    hrc = fdinfo->xh(i,EVLOOP_FDTYPE_X,fdinfo->xhstate);
		    if (hrc == EVLOOP_HRET_BADERROR) {
			if (error_fdinfo) 
			    *error_fdinfo = fdinfo;
			verror("immediately fatal error on xfd %d\n",i);
			if (evloop->eh)
			    evloop->eh(hrc,i,EVLOOP_FDTYPE_X,fdinfo);
			return -1;
		    }
		    else if (hrc == EVLOOP_HRET_ERROR) {
			if (error_fdinfo && !*error_fdinfo) {
			    *error_fdinfo = fdinfo;
			    verror("triggering fatal error on xfd %d;"
				   " finishing this pass\n",i);
			    if (evloop->eh)
				evloop->eh(hrc,i,EVLOOP_FDTYPE_X,fdinfo);
			}
			else {
			    verror("fatal error on xfd %d;"
				   " finishing this pass\n",i);
			    if (evloop->eh)
				evloop->eh(hrc,i,EVLOOP_FDTYPE_X,fdinfo);
			}
		    }
		    else if (hrc == EVLOOP_HRET_REMOVETYPE) {
			evloop_unset_fd(evloop,i,EVLOOP_FDTYPE_X);
		    }
		    else if (hrc == EVLOOP_HRET_REMOVEALLTYPES) {
			evloop_unset_fd(evloop,i,EVLOOP_FDTYPE_A);
		    }
		    else if (hrc == EVLOOP_HRET_DONE_SUCCESS
			     || hrc == EVLOOP_HRET_DONE_FAILURE) {
			goto done_removeall;
		    }
		}
	    }
	}
    }

    /* Never reached. */
    return -1;

 done_removeall:
    /* Remove all FDs; don't signal any though! */
    g_hash_table_iter_init(&iter,evloop->tab);

    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&fdinfo)) {
	__evloop_unset_fd(evloop,fdinfo->fd,EVLOOP_FDTYPE_A);
	g_hash_table_iter_remove(&iter);

	vdebug(9,LOG_OTHER,"removed fd %d completely; nfds = %d\n",
	       fdinfo->fd,evloop->nfds);
	free(fdinfo);
    }

    if (hrc == EVLOOP_HRET_DONE_SUCCESS) {
	vdebug(5,LOG_OTHER,"evloop finished success\n");
	return 0;
    }
    else {
	vdebug(5,LOG_OTHER,"evloop finished failure\n");
	return -1;
    }
}

int evloop_handleone(struct evloop *evloop,struct timeval *timeout) {
    return -1;
}

void evloop_free(struct evloop *evloop) {
    g_hash_table_destroy(evloop->tab);
    free(evloop);
}
