#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "common.h"
#include "log.h"
#include "monitor.h"
#include "proxyreq.h"

#include "target_rpc.h"
#include "debuginfo_rpc.h"

static int stdin_callback(int fd,char *buf,int len) {
    vdebug(0,LA_USER,1,"read '%s' (%d) on fd %d\n",buf,len,fd);

    return 0;
}

struct target *target = NULL;
struct monitor *monitor = NULL;
struct target_spec *tspec = NULL;

static void cleanup(void) {
    static int cleaning = 0;

    if (cleaning)
	return;
    cleaning = 1;

    if (target) {
	target_close(target);
	target_free(target);
	target = NULL;
    }

    if (monitor) {
	monitor_destroy(monitor);
	monitor = NULL;
    }

    target_free_spec(tspec);

    target_rpc_fini();

#ifdef REF_DEBUG
    REF_DEBUG_REPORT_FINISH();
#endif
}

static void sigh(int signo) {
    if (target) 
	target_pause(target);

    cleanup();

    fprintf(stderr,"Shutdown target and monitor connection; exiting (sig %d).\n",
	    signo);

    exit(1);
}

int main(int argc,char **argv) {
    char *svc_name = "target";
    int rc;

    vmi_set_log_level(9);
    vmi_add_log_area_flags(LA_LIB,LF_ALL);
    vmi_add_log_area_flags(LA_TARGET,LF_ALL);
    vmi_add_log_area_flags(LA_PROBE,LF_ALL);
    vmi_add_log_area_flags(LA_XML,LF_ALL);
    vmi_add_log_area_flags(LA_USER,LF_ALL);

    tspec = target_argp_driver_parse(NULL,NULL,argc,argv,
				     TARGET_TYPE_PTRACE | TARGET_TYPE_XEN,1);
    if (!tspec) {
	verror("could not parse a target specification from arguments!\n");
	monitor_destroy(monitor);
	exit(-11);
    }

    target_rpc_init();
    atexit(target_rpc_fini);

    signal(SIGHUP,sigh);
    signal(SIGINT,sigh);
    signal(SIGQUIT,sigh);
    signal(SIGABRT,sigh);
    signal(SIGKILL,sigh);
    signal(SIGSEGV,sigh);
    signal(SIGPIPE,sigh);
    signal(SIGALRM,sigh);
    signal(SIGTERM,sigh);
    signal(SIGUSR1,sigh);
    signal(SIGUSR2,sigh);

    monitor = monitor_attach(MONITOR_TYPE_PROCESS,MONITOR_FLAG_BIDI,
			     MONITOR_OBJTYPE_TARGET,NULL,NULL,NULL,
			     NULL,NULL); //stdin_callback);
    if (!monitor) {
	verror("could not attach to monitor (in pid %d)\n",getpid());
	exit(-3);
    }

    vdebug(1,LA_XML,LF_RPC,"attached to monitor for target %d\n",
	   monitor->objid);

    target = target_instantiate(tspec,monitor->evloop);

    if (!target) {
	verror("could not instantiate target, detaching from monitor!\n");
	cleanup();
	exit(-12);
    }

    monitor_add_primary_obj(monitor,target->id,MONITOR_OBJTYPE_TARGET,target,NULL);

    vdebug(1,LA_XML,LF_RPC,"instantiated target %d\n",monitor->objid);

    if (target->id > -1 && monitor->objid != tspec->target_id) {
	vwarn("monitored objid %d is not target id %d\n",
	      monitor->objid,tspec->target_id);
	tspec->target_id = monitor->objid;
    }
    else if (tspec->target_id < 0)
	tspec->target_id = monitor->objid;

    while (1) {
	rc = monitor_run(monitor);
	if (rc < 0) {
	    verror("bad internal error in monitor for %s %d; destroying!\n",
		   svc_name,monitor->objid);
	    monitor_destroy(monitor);
	    return -1;
	}
	else {
	    if (monitor_is_done(monitor)) {
		vdebug(2,LA_XML,LF_RPC,
		       "monitoring on %s %d is done; finalizing!\n",
		       svc_name,monitor->objid);
		monitor_destroy(monitor);
		return 0;
	    }
	    else {
		vwarn("%s %d monitor_run finished unexpectedly; finalizing!\n",
		      svc_name,monitor->objid);
		monitor_destroy(monitor);
		return -1;
	    }
	}
    }
}
