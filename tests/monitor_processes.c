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
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <stdlib.h>

#include "common.h"
#include "log.h"
#include "monitor.h"
#include "monitor_dummy.h"

extern struct monitor_objtype_ops monitor_dummy_ops;

int dummy_stdio_callback(int fd,char *buf,int len) {
    //vdebug(0,LA_USER,1,"read '%s' (%d) on fd %d\n",buf,len,fd);
    return 0;
}

static char *echo_msg = "echo me N times!";
static char *mutate_msg = "mutate me N times!";

char *childprog;

void *new_thread(void *obj) {
    struct dummy *d = (struct dummy *)obj;
    struct monitor_dummy_msg_obj dmo = { .msg = "dmo" };
    struct monitor *m;
    char *msg;
    int msg_len;
    struct monitor_msg *mm;
    int pid;

    //pthread_detach(pthread_self());

    m = monitor_create(MONITOR_TYPE_PROCESS,MONITOR_FLAG_BIDI,
		       d->id,MONITOR_DUMMY_OBJTYPE,d);

    monitor_setup_stdin(m,d->stdin_buf,d->stdin_bufsiz);
    monitor_setup_stdout(m,4096,d->stdout_logfile,dummy_stdio_callback);
    monitor_setup_stderr(m,4096,d->stderr_logfile,dummy_stdio_callback);

    pid = monitor_spawn(m,childprog,NULL,NULL,"/tmp");
    if (pid < 0) {
	verror("error spawning: %d (%s)\n",pid,strerror(errno));
	monitor_destroy(m);
	return NULL;
    }

    // kick things off with a message to the child; recv handler takes
    // over after that.
    if (d->cmd == DUMMY_ECHO)
	msg = strdup(echo_msg);
    else
	msg = strdup(mutate_msg);
    msg_len = strlen(msg);

    mm = monitor_msg_create(d->id,-1,d->cmd,1,msg_len,msg,&dmo);
    monitor_send(mm);
    monitor_msg_free(mm);
    mm = NULL;

    monitor_run(m);

    // normally would have to clean up obj?

    // normally, we might save the object around, sort of like with
    // waitpid(), until something waits for it!
    monitor_destroy(m);

    return NULL;
}
    
int main(int argc,char **argv) {
    struct dummy d1;
    struct dummy d2;
    pthread_t tid1;
    pthread_t tid2;
    void *retval;
    char tmppath[PATH_MAX];
    char path[PATH_MAX];
    char *p;

    if (argc > 1)
	childprog = argv[1];
    else if ((p = rindex(argv[0],'/'))) {
	snprintf(tmppath,PATH_MAX,"%.*s/%s",
		 (int)(p - argv[0]),argv[0],"monitored_dummy_child");
	if (!(childprog = realpath(tmppath,path))) {
	    verror("realpath(%s): %s\n",tmppath,strerror(errno));
	    exit(-11);
	}
    }
    else {
	snprintf(tmppath,PATH_MAX,"%s","monitored_dummy_child");
	if (!(childprog = realpath(tmppath,path))) {
	    verror("realpath(%s): %s\n",tmppath,strerror(errno));
	    exit(-11);
	}
    }

    signal(SIGPIPE,SIG_IGN);

    vmi_set_log_level(16);
    vmi_set_log_area_flags(LA_USER,LF_U_ALL);
    vmi_set_log_area_flags(LA_LIB,LF_ALL);

    monitor_init();

    if (monitor_register_objtype(MONITOR_DUMMY_OBJTYPE,&monitor_dummy_ops)
	!= MONITOR_DUMMY_OBJTYPE) {
	verror("registration of dummy objtype %d failed!\n",
	       MONITOR_DUMMY_OBJTYPE);
	exit(-9);
    }
    else
	vdebug(0,LA_USER,1,"registered dummy objtype %d\n",
	       MONITOR_DUMMY_OBJTYPE);

    d1.id = 111;
    d1.cmd = DUMMY_ECHO;
    d1.seqno_limit = 2;

    d1.fd = open("/tmp/d1.txt",O_RDONLY | O_CREAT,S_IWUSR | S_IRUSR);
    fcntl(d1.fd,F_SETFL,fcntl(d1.fd,F_GETFL) | O_NONBLOCK);
    d1.stdin_buf = strdup("dummy1");
    d1.stdin_bufsiz = strlen(d1.stdin_buf) + 1;
    d1.stdout_logfile = "/tmp/d1.stdout.log";
    d1.stderr_logfile = "/tmp/d1.stderr.log";

    d2.id = 222;
    d2.cmd = DUMMY_MUTATE;
    d2.seqno_limit = 4;

    d2.fd = open("/tmp/d2.txt",O_RDONLY | O_CREAT,S_IWUSR | S_IRUSR);
    fcntl(d2.fd,F_SETFL,fcntl(d2.fd,F_GETFL) | O_NONBLOCK);
    d2.stdin_buf = strdup("dummy2");
    d2.stdin_bufsiz = strlen(d2.stdin_buf) + 1;
    d2.stdout_logfile = "/tmp/d2.stdout.log";
    d2.stderr_logfile = "/tmp/d2.stderr.log";

    //pthread_create(&tid1,NULL,new_thread,&d1);
    pthread_create(&tid2,NULL,new_thread,&d2);

    //pthread_join(tid1,&retval);
    pthread_join(tid2,&retval);

    exit(0);
}
