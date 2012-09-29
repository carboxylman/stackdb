/*
 * Copyright (c) 2012 The University of Utah
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
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

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

extern char *optarg;
extern int optind, opterr, optopt;
extern char **environ;

struct target *t = NULL;

GHashTable *probes = NULL;
target_status_t tstat;
int loopint = 0;

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
    alarm(loopint);
}

int main(int argc,char **argv) {
    char targetstr[128];
    int pid = -1;
    int i;
    int doexe = 0;
    char *exe = NULL;
    char **exeargs = NULL;
    char *exeoutfile = NULL;
    char *exeerrfile = NULL;
    char *domain = NULL;
    int islinux = 0,isxen = 0;
    char ch;
    int debug = -1;
    int xadebug = -1;
    char *optargc;
    log_flags_t flags;
    probepoint_style_t style = PROBEPOINT_FASTEST;
    struct debugfile_load_opts **dlo_list = NULL;
    int dlo_idx = 0;
    struct debugfile_load_opts *opts;
    struct target_opts topts = {
	.bpmode = THREAD_BPMODE_STRICT,
    };
    /*
    struct dump_info udn = {
	.stream = stderr,
	.prefix = "",
	.detail = 1,
	.meta = 1,
    };
    */

    /* Find the '--' and save the remaining args so they can be passed
     * to linux_userproc_launch below.  Truncate argc and argv to just
     * include any function/variable breakpoint/watchpoint params, and
     * any other args, to be parsed later.
     */
    for (i = 0; i < argc; ++i) {
	if (!strcmp(argv[i],"--") && (i + 1) < argc) {
	    exe = argv[i + 1];
	    argv[i] = NULL;
	    argc = i;
	    exeargs = &argv[i + 2];
	    break;
	}
    }

    while ((ch = getopt(argc, argv, "m:p:eE:O:dxsl:F:Li:")) != -1) {
	switch (ch) {
	case 'd':
	    ++debug;
	    break;
	case 'x':
	    ++xadebug;
	    break;
	case 'p':
	    pid = atoi(optarg);
	    break;
	case 'm':
#ifdef ENABLE_XENACCESS
	    domain = optarg;
	    /* Xen does not support STRICT! */
	    if (topts.bpmode == THREAD_BPMODE_STRICT)
		++topts.bpmode;
#else
	    verror("xen support not compiled on this host!\n");
	    exit(-1);
#endif
	    break;
	case 'e':
	    doexe = 1;
	    break;
	case 'E':
	    exeerrfile = optarg;
	    break;
	case 'O':
	    exeoutfile = optarg;
	    break;
	case 's':
	    style = PROBEPOINT_SW;
	    break;
	case 'l':
	    if (vmi_log_get_flag_mask(optarg,&flags)) {
		fprintf(stderr,"ERROR: bad debug flag in '%s'!\n",optarg);
		exit(-1);
	    }
	    vmi_set_log_flags(flags);
	    break;
	case 'F':
	    optargc = strdup(optarg);

	    opts = debugfile_load_opts_parse(optarg);

	    if (!opts)
		goto dlo_err;

	    dlo_list = realloc(dlo_list,sizeof(opts)*(dlo_idx + 2));
	    dlo_list[dlo_idx] = opts;
	    ++dlo_idx;
	    dlo_list[dlo_idx] = NULL;
	    break;
	dlo_err:
	    fprintf(stderr,"ERROR: bad debugfile_load_opts '%s'!\n",optargc);
	    free(optargc);
	    exit(-1);
	case 'L':
	    ++topts.bpmode;
	    if (topts.bpmode > THREAD_BPMODE_LOOSE) {
		fprintf(stderr,"ERROR: bad bpmode!\n");
		exit(-1);
	    }
	    break;
	case 'i':
	    loopint = atoi(optarg);
	    break;
	default:
	    fprintf(stderr,"ERROR: unknown option %c!\n",ch);
	    exit(-1);
	}
    }

    argc -= optind;
    argv += optind;

    dwdebug_init();
    atexit(dwdebug_fini);

    vmi_set_log_level(debug);
#if defined(ENABLE_XENACCESS) && defined(XA_DEBUG)
    xa_set_debug_level(xadebug);
#endif

    if (pid > 0) {
	islinux = 1;
	t = linux_userproc_attach(pid,dlo_list);
	if (!t) {
	    fprintf(stderr,"could not attach to pid %d!\n",pid);
	    exit(-3);
	}
	snprintf(targetstr,128,"pid %d",pid);
    }
#ifdef ENABLE_XENACCESS
    else if (domain) {
	isxen = 1;
	t = xen_vm_attach(domain,dlo_list);
	if (!t) {
	    fprintf(stderr,"could not attach to dom %s!\n",domain);
	    exit(-3);
	}
	snprintf(targetstr,128,"domain %s",domain);
    }
#endif
    else if (doexe) {
	islinux = 1;
	if (!exe) {
	    fprintf(stderr,"must supply at least an executable to launch!\n");
	    exit(-1);
	}

	t = linux_userproc_launch(exe,exeargs,environ,0,
				  exeoutfile,exeerrfile,dlo_list);
	if (!t) {
	    fprintf(stderr,"could not launch exe %s!\n",exe);
	    exit(-3);
	}

	pid = linux_userproc_pid(t);
	snprintf(targetstr,128,"pid %d",pid);
    }
    else {
	fprintf(stderr,"ERROR: must specify a target!\n");
	exit(-2);
    }

    if (target_open(t,&topts)) {
	fprintf(stderr,"could not open domain %s!\n",domain);
	exit(-4);
    }

    /*
     * If we are going to watch for processes, set up monitoring.
     */
    signal(SIGHUP,sigh);
    signal(SIGINT,sigh);
    signal(SIGQUIT,sigh);
    signal(SIGABRT,sigh);
    signal(SIGKILL,sigh);
    signal(SIGSEGV,sigh);
    signal(SIGPIPE,sigh);
    signal(SIGTERM,sigh);
    signal(SIGUSR1,sigh);
    signal(SIGUSR2,sigh);

    signal(SIGALRM,siga);

    /* Install probes... */

    fprintf(stdout,"Initial threads:\n");
    target_load_available_threads(t,1);
    target_dump_all_threads(t,stdout,0);

    if (!loopint) {
	tstat = TSTATUS_DONE;
	goto exit;
    }
    tstat = TSTATUS_RUNNING;
    alarm(loopint);

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
