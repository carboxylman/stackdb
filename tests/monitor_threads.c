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

#include "monitor_dummy.h"

extern struct monitor_objtype_ops monitor_dummy_ops;

void *new_thread(void *obj) {
    struct dummy *d = (struct dummy *)obj;
    struct monitor *m;

    //pthread_detach(pthread_self());

    m = monitor_create(MONITOR_TYPE_THREAD,MONITOR_FLAG_NONE,
		       d->id,MONITOR_DUMMY_OBJTYPE,d,NULL);

    monitor_run(m);

    // normally would have to clean up obj?

    monitor_destroy(m);

    return NULL;
}
    

int main(int argc,char **argv) {
    struct dummy d1;
    struct monitor_dummy_msg_obj d1m = { .msg = "dummy1", };
    struct dummy d2;
    struct monitor_dummy_msg_obj d2m = { .msg = "dummy2", };
    struct monitor_msg *mm1;
    struct monitor_msg *mm2;
    pthread_t tid1;
    pthread_t tid2;
    void *retval;
    struct monitor *m1;
    struct monitor *m2;

    vmi_set_log_level(16);
    vmi_add_log_area_flags(LA_LIB,LF_MONITOR | LF_EVLOOP);
    vmi_add_log_area_flags(LA_USER,0xffffffff);

    monitor_init();

    d1.id = 111;
    d1.seqno_limit = 2;
    d1.fd = open("/tmp/d1.txt",O_RDONLY | O_CREAT,S_IWUSR | S_IRUSR);
    fcntl(d1.fd,F_SETFL,fcntl(d1.fd,F_GETFL) | O_NONBLOCK);
    d2.id = 222;
    d1.seqno_limit = 8;
    d2.fd = open("/tmp/d2.txt",O_RDONLY | O_CREAT,S_IWUSR | S_IRUSR);
    fcntl(d2.fd,F_SETFL,fcntl(d2.fd,F_GETFL) | O_NONBLOCK);

    if (monitor_register_objtype(MONITOR_DUMMY_OBJTYPE,&monitor_dummy_ops,NULL)
	!= MONITOR_DUMMY_OBJTYPE) {
	verror("registration of dummy objtype %d failed!\n",
	       MONITOR_DUMMY_OBJTYPE);
	exit(-9);
    }
    else
	vdebug(0,LA_USER,1,"registered dummy objtype %d\n",
	       MONITOR_DUMMY_OBJTYPE);

    pthread_create(&tid1,NULL,new_thread,&d1);
    pthread_create(&tid2,NULL,new_thread,&d2);

    sleep(2);

    monitor_lookup_objid(d1.id,NULL,NULL,&m1);
    monitor_lookup_objid(d2.id,NULL,NULL,&m2);

    mm1 = monitor_msg_create(d1.id,-1,DUMMY_ECHO,1,4,"m111",&d1m);
    monitor_send(mm1);

    mm2 = monitor_msg_create(d2.id,2,DUMMY_MUTATE,1,4,"m222",&d2m);
    monitor_send(mm2);

    pthread_join(tid1,&retval);
    pthread_join(tid2,&retval);

    exit(0);
}
