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

#include "monitor_dummy.h"

int monitor_dummy_evh(int fd,int fdtype,void *state) {
    struct dummy *d = (struct dummy *)state;
    char buf[64];
    int rc;

    rc = read(fd,buf,sizeof(buf));
    if (rc < 0) 
	buf[0] = '\0';
    else
	buf[rc] = '\0';

    vdebug(0,LA_USER,1,"fd %d fdtype %d d->id %d d->fd %d rc %d buf %s\n",
	   fd,fdtype,d->id,d->fd,rc,buf);

    return 0;
}

int monitor_dummy_evloop_attach(struct evloop *evloop,void *obj) {
    struct dummy *d = (struct dummy *)obj;

    //evloop_set_fd(evloop,d->fd,EVLOOP_FDTYPE_R,monitor_dummy_evh,d);
    vdebug(0,LA_USER,1,"dummy id %d\n",d->id);

    return 0;
}
int monitor_dummy_evloop_detach(struct evloop *evloop,void *obj) {
    struct dummy *d = (struct dummy *)obj;

    //evloop_unset_fd(evloop,d->fd,EVLOOP_FDTYPE_R);
    vdebug(0,LA_USER,1,"dummy id %d\n",d->id);

    return 0;
}
int monitor_dummy_error(monitor_error_t error,void *obj) {
    vdebug(0,LA_USER,1,"dummy id %d (error %d)\n",((struct dummy *)obj)->id,
	   error);
    return 0;
}
int monitor_dummy_fatal_error(monitor_error_t error,void *obj) {
    vdebug(0,LA_USER,1,"dummy id %d (error %d)\n",((struct dummy *)obj)->id,
	   error);
    //free(dummy);
    return 0;
}

int monitor_dummy_child_recv_msg(struct monitor *monitor,struct monitor_msg *msg) {
    struct dummy *d = (struct dummy *)msg->obj;
    struct monitor_dummy_msg_obj *dmo = 
	(struct monitor_dummy_msg_obj *)msg->msg_obj;
    int i;

    vdebug(0,LA_USER,1,"msg(%d:%d,%d) = '%s'\n",
	   msg->id,msg->seqno,msg->len,msg->msg);

    fprintf(stdout,"STDOUT: msg: '%s'\n",msg->msg);
    fprintf(stderr,"STDERR: msg: '%s'\n",msg->msg);

    if (monitor->flags & MONITOR_FLAG_BIDI) {
	if (monitor->type == MONITOR_TYPE_PROCESS && msg->cmd == DUMMY_EXIT) {
	    monitor_interrupt(monitor);
	}
	else if (msg->cmd == DUMMY_MUTATE) {
	    for (i = 0; i < msg->len; ++i) {
		if (isupper(msg->msg[i]))
		    msg->msg[i] = tolower(msg->msg[i]);
		else if (islower(msg->msg[i]))
		    msg->msg[i] = toupper(msg->msg[i]);
	    }
	}

	++msg->seqno;

	monitor_child_send(msg);
    }
    else {
	monitor_interrupt(monitor);
    }

    monitor_msg_free(msg);

    return 0;
}

int monitor_dummy_recv_msg(struct monitor *monitor,struct monitor_msg *msg) {
    struct dummy *d = (struct dummy *)msg->obj;
    struct monitor_dummy_msg_obj *dmo = 
	(struct monitor_dummy_msg_obj *)msg->msg_obj;

    vdebug(0,LA_USER,1,"msg(%d,%hd:%hd,%d) = '%s' (obj id %d)\n",
	   msg->id,msg->cmd,msg->seqno,msg->len,msg->msg,d->id);

    if (msg->seqno > d->seqno_limit)
	monitor_interrupt(monitor);

    ++msg->seqno;

    monitor_send(msg);

    return 0;
}

struct monitor_objtype_ops monitor_dummy_ops = {
    .evloop_attach = monitor_dummy_evloop_attach,
    .evloop_detach = monitor_dummy_evloop_detach,
    .error = monitor_dummy_error,
    .fatal_error = monitor_dummy_fatal_error,
    .child_recv_msg = monitor_dummy_child_recv_msg,
    .recv_msg = monitor_dummy_recv_msg,
};

