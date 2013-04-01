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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <argp.h>

#include <sys/user.h>
#include <sys/ptrace.h>
#include <inttypes.h>

#include <signal.h>

#include "log.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"
#include "target_linux_userproc.h"
#ifdef ENABLE_XENACCESS
#include "target_xen_vm.h"
#endif

#include "probe_api.h"
#include "probe.h"
#include "alist.h"
#include "list.h"

struct dt_argp_state {
    int loopint;
};

struct dt_argp_state opts;

struct target *t = NULL;

GHashTable *probes = NULL;
target_status_t tstat;

void cleanup() {
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;

    if (probes) {
	g_hash_table_iter_init(&iter,probes);
	while (g_hash_table_iter_next(&iter,
				      (gpointer)&key,
				      (gpointer)&probe)) {
	    probe_unregister(probe,1);
	    probe_free(probe,1);
	}
    }
    target_close(t);
    target_free(t);

    if (probes) 
	g_hash_table_destroy(probes);
}

void sigh(int signo) {
    if (t) {
	target_pause(t);
	cleanup();
    }
    exit(0);
}

void siga(int signo) {
    if (tstat == TSTATUS_RUNNING) {
	target_pause(t);
	fprintf(stdout,"Current threads:\n");
	target_load_available_threads(t,1);
	target_dump_all_threads(t,stdout,0);
	target_resume(t);
    }
    alarm(opts.loopint);
}

struct argp_option dt_argp_opts[] = {
    { "loop-interval",'i',"INTERVAL",0,"Loop infinitely using the given interval.",0 },
    { 0,0,0,0,0,0 },
};

error_t dt_argp_parse_opt(int key, char *arg,struct argp_state *state) {
    struct dt_argp_state *opts = \
	(struct dt_argp_state *)target_argp_driver_state(state);

    switch (key) {
    case ARGP_KEY_ARG:
	return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_ARGS:
	return 0;
    case ARGP_KEY_INIT:
	target_driver_argp_init_children(state);
	return 0;
    case ARGP_KEY_END:
    case ARGP_KEY_NO_ARGS:
    case ARGP_KEY_SUCCESS:
	return 0;
    case ARGP_KEY_ERROR:
    case ARGP_KEY_FINI:
	return 0;

    case 'i':
	opts->loopint = atoi(arg);
	break;

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp dt_argp = {
    dt_argp_opts,dt_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};

int main(int argc,char **argv) {
    struct target_spec *tspec;
    char targetstr[128];

    memset(&opts,0,sizeof(opts));

    tspec = target_argp_driver_parse(&dt_argp,&opts,argc,argv,
				     TARGET_TYPE_PTRACE | TARGET_TYPE_XEN,1);

    if (!tspec) {
	verror("could not parse target arguments!\n");
	exit(-1);
    }

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

    signal(SIGALRM,siga);

    dwdebug_init();
    atexit(dwdebug_fini);

    t = target_instantiate(tspec,NULL);
    if (!t) {
	verror("could not instantiate target!\n");
	exit(-1);
    }
    target_tostring(t,targetstr,sizeof(targetstr));

    if (target_open(t)) {
	fprintf(stderr,"could not open %s!\n",targetstr);
	exit(-4);
    }

    /* Install probes... */

    fprintf(stdout,"Initial threads:\n");
    target_load_available_threads(t,1);
    target_dump_all_threads(t,stdout,0);

    if (!opts.loopint) {
	tstat = TSTATUS_DONE;
	goto exit;
    }
    tstat = TSTATUS_RUNNING;
    alarm(opts.loopint);

    /* The target is paused after the attach; we have to resume it now
     * that we've registered probes.
     */
    target_resume(t);

    fprintf(stdout,"Starting thread watch loop!\n");
    fflush(stdout);

    while (1) {
	tstat = target_monitor(t);
	if (tstat == TSTATUS_PAUSED) {
	    tid_t tid = target_gettid(t);
	    fflush(stderr);
	    fflush(stdout);
	    printf("%s thread %"PRIiTID" interrupted at 0x%"PRIxREGVAL"\n",
		   targetstr,tid,target_read_creg(t,tid,CREG_IP));
	    goto resume;

	resume:
	    tstat = TSTATUS_RUNNING;
	    if (target_resume(t)) {
		fprintf(stderr,"could not resume target %s\n",targetstr);
		cleanup();
		exit(-16);
	    }
	}
	else {
	    goto exit;
	}
    }

 exit:
    fflush(stderr);
    fflush(stdout);
    cleanup();
    if (tstat == TSTATUS_DONE)  {
	printf("%s finished.\n",targetstr);
	exit(0);
    }
    else if (tstat == TSTATUS_ERROR) {
	printf("%s monitoring failed!\n",targetstr);
	exit(-9);
    }
    else {
	printf("%s monitoring failed with %d!\n",targetstr,tstat);
	exit(-10);
    }
}
