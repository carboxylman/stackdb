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

#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "log.h"
#include "evloop.h"
#include "monitor.h"

struct dummy {
    unsigned long id;
    int fd;
};

struct dummy_msg_obj {
    char *msg;
};

int dummy_evh(int fd,int fdtype,void *state) {
    struct dummy *d = (struct dummy *)state;
    char buf[64];
    int rc;

    rc = read(fd,buf,sizeof(buf));
    if (rc < 0) 
	buf[0] = '\0';
    else
	buf[rc] = '\0';

    vdebug(0,LOG_OTHER,"fd %d fdtype %d d->id %d d->fd %d rc %d buf %s\n",
	   fd,fdtype,d->id,d->fd,rc,buf);

    return 0;
}

int dummy_evloop_attach(struct evloop *evloop,void *obj) {
    struct dummy *d = (struct dummy *)obj;

    //evloop_set_fd(evloop,d->fd,EVLOOP_FDTYPE_R,dummy_evh,d);
    vdebug(0,LOG_OTHER,"dummy id %d\n",d->id);

    return 0;
}
int dummy_evloop_detach(struct evloop *evloop,void *obj) {
    struct dummy *d = (struct dummy *)obj;

    //evloop_unset_fd(evloop,d->fd,EVLOOP_FDTYPE_R);
    vdebug(0,LOG_OTHER,"dummy id %d\n",d->id);

    return 0;
}
int dummy_error(monitor_error_t error,void *obj) {
    vdebug(0,LOG_OTHER,"dummy id %d (error %d)\n",((struct dummy *)obj)->id,
	   error);
    return 0;
}
int dummy_fatal_error(monitor_error_t error,void *obj) {
    vdebug(0,LOG_OTHER,"dummy id %d (error %d)\n",((struct dummy *)obj)->id,
	   error);
    //free(dummy);
    return 0;
}

int dummy_child_recv_msg(struct monitor *monitor,struct monitor_msg *msg) {
    vdebug(0,LOG_OTHER,"msg(%d:%d,%d) = '%s'\n",
	   msg->id,msg->seqno,msg->len,msg->msg);
    return 0;
}

int dummy_recv_msg(struct monitor *monitor,struct monitor_msg *msg) {
    vdebug(0,LOG_OTHER,"msg(%d:%d,%d) = '%s'\n",
	   msg->id,msg->seqno,msg->len,msg->msg);
    return 0;
}

struct monitor_objtype_ops dummy_ops = {
    .evloop_attach = dummy_evloop_attach,
    .evloop_detach = dummy_evloop_detach,
    .error = dummy_error,
    .fatal_error = dummy_fatal_error,
    .child_recv_evh = NULL,
    .recv_evh = NULL,
    .child_recv_msg = dummy_child_recv_msg,
    .recv_msg = dummy_recv_msg,
};

int dummy_objtype = -1;

void *new_thread(void *obj) {
    struct dummy *d = (struct dummy *)obj;
    struct monitor *m;

    //pthread_detach(pthread_self());

    m = monitor_create(MONITOR_TYPE_THREAD,MONITOR_FLAG_NONE,dummy_objtype,d);

    monitor_run(m);

    // normally would have to clean up obj?

    monitor_free(m);

    return NULL;
}
    

int main(int argc,char **argv) {
    struct dummy d1;
    struct dummy_msg_obj d1m = { .msg = "dummy1", };
    struct dummy d2;
    struct dummy_msg_obj d2m = { .msg = "dummy2", };
    struct monitor_msg *m1;
    struct monitor_msg *m2;
    pthread_t tid1;
    pthread_t tid2;
    void *retval;

    vmi_set_log_level(16);
    vmi_set_log_flags(LOG_OTHER);

    d1.id = 111;
    d1.fd = open("/tmp/d1.txt",O_RDONLY | O_CREAT,S_IWUSR | S_IRUSR);
    fcntl(d1.fd,F_SETFL,fcntl(d1.fd,F_GETFL) | O_NONBLOCK);
    d2.id = 222;
    d2.fd = open("/tmp/d2.txt",O_RDONLY | O_CREAT,S_IWUSR | S_IRUSR);
    fcntl(d2.fd,F_SETFL,fcntl(d2.fd,F_GETFL) | O_NONBLOCK);

    dummy_objtype = monitor_register_objtype(dummy_objtype,&dummy_ops);
    vdebug(0,LOG_OTHER,"registered dummy objtype %d\n",dummy_objtype);

    pthread_create(&tid1,NULL,new_thread,&d1);
    pthread_create(&tid2,NULL,new_thread,&d2);

    sleep(1);

    m1 = monitor_msg_create(111,1,5,"m111");
    monitor_sendfor(&d1,m1,&d1m);

    m2 = monitor_msg_create(222,1,5,"m222");
    monitor_sendfor(&d2,m2,&d2m);

    pthread_join(tid1,&retval);
    pthread_join(tid2,&retval);

    exit(0);
}
