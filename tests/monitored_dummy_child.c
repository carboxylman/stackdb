#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "common.h"
#include "log.h"
#include "monitor.h"
#include "monitor_dummy.h"

extern struct monitor_objtype_ops monitor_dummy_ops;
extern int monitor_dummy_objtype;

int dummy_stdin_callback(int fd,char *buf,int len) {
    //vdebug(0,LA_USER,1,"read '%s' (%d) on fd %d\n",buf,len,fd);

    if (fd == STDIN_FILENO) {
	fprintf(stderr,"STDIN: '%s' (%d)\n",buf,len);
	fprintf(stdout,"STDIN: '%s' (%d)\n",buf,len);
    }

    return 0;
}

int main(int argc,char **argv) {
    struct dummy dummy;
    struct monitor *m;

    vmi_set_log_level(16);
    vmi_add_log_area_flags(LA_LIB,LF_MONITOR | LF_EVLOOP);
    vmi_add_log_area_flags(LA_USER,0xffffffff);

    monitor_init();
    atexit(monitor_fini);

    if (monitor_register_objtype(MONITOR_DUMMY_OBJTYPE,&monitor_dummy_ops,NULL)
	!= MONITOR_DUMMY_OBJTYPE) {
	verror("registration of dummy objtype %d failed!\n",
	       MONITOR_DUMMY_OBJTYPE);
	monitor_destroy(m);
	exit(-9);
    }
    else
	vdebug(0,LA_USER,1,"registered dummy objtype %d\n",
	       MONITOR_DUMMY_OBJTYPE);

    m = monitor_attach(MONITOR_TYPE_PROCESS,MONITOR_FLAG_BIDI,
		       MONITOR_DUMMY_OBJTYPE,&dummy,NULL,
		       dummy_stdin_callback);
    if (!m) {
	verror("could not attach to monitor (in pid %d)\n",getpid());
	exit(-3);
    }
    dummy.id = m->objid;
    vdebug(0,LA_USER,1,"attached to monitor for objid %d\n",dummy.id);

    if (monitor_run(m) == 0) {
	monitor_destroy(m);
	exit(0);
    }
    else {
	verror("monitor_run() failed; exiting!\n");
	exit(-2);
    }
}
