/*
 * Copyright (c) 2013, 2014 The University of Utah
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

#include "glib_wrapper.h"
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

GList *targets;

struct bt_argp_state {
    int loopint;
    int detail;
    int argc;
    char **argv;
};

struct bt_argp_state opts;

void sigu(siginfo_t *siginfo) {
    struct target *target;
    target_status_t tstat;
    GList *t1;
    int i,rc;
    tid_t tid;
    char buf[1024];

    if (siginfo->si_signo != SIGALRM)
	return;

    v_g_list_foreach(targets,t1,target) {
	tstat = target_status(target);
	if (tstat != TSTATUS_PAUSED)
	    target_pause(target);
    }

    v_g_list_foreach(targets,t1,target) {
	if (target_monitor_handling_exception(target)) {
	    fprintf(stdout,"Cannot examine target %s; handling an exception!\n",
		    target->name);
	    continue;
	}
	else {
	    fprintf(stdout,"Threads in target %s:\n",target->name);
	    fflush(stderr);
	    fflush(stdout);
	    target_load_available_threads(target,1);
	    target_dump_all_threads(target,stdout,opts.detail);
	    fflush(stderr);
	    fflush(stdout);

	    struct array_list *tids = target_list_tids(target);
	    array_list_foreach_fakeptr_t(tids,i,tid,uintptr_t) {
		fflush(stderr);
		fflush(stdout);

		rc = target_unwind_snprintf(buf,sizeof(buf),target,tid,
					    TARGET_UNWIND_STYLE_GDB,"\n",",");
		if (rc < 0)
		    fprintf(stdout,"\nthread %"PRIiTID": (error!)\n",tid);
		else if (rc == 0)
		    fprintf(stdout,"\nthread %"PRIiTID": (nothing)\n",tid);
		else
		    fprintf(stdout,"\nthread %"PRIiTID": \n%s\n",tid,buf);
	    }
	    if (tids)
		array_list_free(tids);
	}
    }

    v_g_list_foreach(targets,t1,target) {
	tstat = target_status(target);
	if (tstat == TSTATUS_PAUSED)
	    target_resume(target);
    }

    alarm(opts.loopint);
}

#define BT_ARGP_INTERVAL 0x444443
#define BT_ARGP_DETAIL 0x444444

struct argp_option bt_argp_opts[] = {
    { "loop-interval",BT_ARGP_INTERVAL,"INTERVAL",0,"Loop infinitely using the given interval.",0 },
    { "dump-detail",BT_ARGP_DETAIL,"DETAIL",0,"Thread detail level (default 0).",0 },

    { 0,0,0,0,0,0 },
};

error_t bt_argp_parse_opt(int key, char *arg,struct argp_state *state) {
    struct bt_argp_state *opts = \
	(struct bt_argp_state *)target_argp_driver_state(state);

    switch (key) {
    case ARGP_KEY_ARG:
	return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_ARGS:
	/* Eat all the remaining args. */
	if (state->quoted > 0)
	    opts->argc = state->quoted - state->next;
	else
	    opts->argc = state->argc - state->next;
	if (opts->argc > 0) {
	    opts->argv = calloc(opts->argc,sizeof(char *));
	    memcpy(opts->argv,&state->argv[state->next],opts->argc*sizeof(char *));
	    state->next += opts->argc;
	}
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

    case BT_ARGP_INTERVAL:
	opts->loopint = atoi(arg);
	break;
    case BT_ARGP_DETAIL:
	opts->detail = atoi(arg);
	break;

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp bt_argp = {
    bt_argp_opts,bt_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};

int main(int argc,char **argv) {
    struct target_spec *primary_target_spec = NULL;
    GList *base_target_specs = NULL;
    GList *overlay_target_specs = NULL;
    int rc;
    struct evloop *evloop;
    sigset_t ignored,interrupt,exitset;
    siginfo_t siginfo;

    target_init();
    atexit(target_fini);

    /*
     * We need to handle SIGALRM specially so we can loop.
     */
    sigemptyset(&ignored);
    sigemptyset(&exitset);
    sigemptyset(&interrupt);

    sigaddset(&exitset,SIGHUP);
    sigaddset(&exitset,SIGINT);
    sigaddset(&exitset,SIGQUIT);
    sigaddset(&exitset,SIGILL);
    sigaddset(&exitset,SIGABRT);
    sigaddset(&exitset,SIGFPE);
    sigaddset(&exitset,SIGSEGV);
    sigaddset(&exitset,SIGPIPE);
    sigaddset(&exitset,SIGTERM);
    sigaddset(&exitset,SIGBUS);
    sigaddset(&exitset,SIGXCPU);
    sigaddset(&exitset,SIGXFSZ);

    sigaddset(&ignored,SIGUSR1);
    sigaddset(&ignored,SIGUSR2);
    sigaddset(&interrupt,SIGALRM);

    target_install_custom_sighandlers(&ignored,&interrupt,&exitset,NULL);

    memset(&opts,0,sizeof(opts));
    rc = target_argp_driver_parse(&bt_argp,&opts,argc,argv,
				  TARGET_TYPE_PTRACE | TARGET_TYPE_XEN
				      | TARGET_TYPE_GDB,1,
				  &primary_target_spec,&base_target_specs,
				  &overlay_target_specs);

    if (rc) {
	verror("could not parse target arguments!\n");
	exit(-1);
    }

    evloop = evloop_create(NULL);

    targets = target_instantiate_and_open(primary_target_spec,
					  base_target_specs,overlay_target_specs,
					  evloop,NULL);
    if (!targets) {
	verror("could not instantiate and open targets!\n");
	exit(-1);
    }

    /* Do it the first time */
    siginfo.si_signo = SIGALRM;
    sigu(&siginfo);

    if (!opts.loopint) {
	rc = 0;
	goto exit;
    }

    alarm(opts.loopint);

    fprintf(stdout,"Starting thread watch loop!\n");
    fflush(stdout);

    while (1) {
	tid_t tid = 0;
	struct target *t;
	target_status_t tstat;
	char *tname;
	siginfo_t siginfo;

	rc = target_monitor_evloop(evloop,NULL,&t,&tstat);

	/* Did we get interrupted safely? */
	if (target_monitor_was_interrupted(&siginfo))
	    sigu(&siginfo);
	/* Did we experience an error in select() or in evloop? */
	else if (rc < 0) {
	    fprintf(stderr,"error in target_monitor_evloop (%d): %s; aborting!\n",
		    rc,strerror(errno));
	    target_default_cleanup();
	    exit(-3);
	}
	/* Did we experience a significant event on a target? */
	else if (rc == 0 && evloop_maxsize(evloop) < 0) {
	    break;
	}
	else if (rc == 0) {
	    tid = target_gettid(t);
	    tname = target_name(t);

	    if (tstat == TSTATUS_ERROR) {
		fprintf(stderr,
			"Error handling target '%s'; closing and finalizing!\n",
			tname);

		target_close(t);
		target_finalize(t);
		targets = g_list_remove(targets,t);
	    }
	    else if (tstat == TSTATUS_DONE) {
		fprintf(stderr,
			"Target '%s' finished; finalizing!\n",
			tname);

		target_close(t);
		target_finalize(t);
		targets = g_list_remove(targets,t);
	    }
	    else if (tstat == TSTATUS_EXITING) {
		fprintf(stderr,"Target '%s' exiting...\n",tname);
	    }
	    else if (tstat == TSTATUS_INTERRUPTED) {
		fprintf(stderr,"Target '%s' interrupted, resuming...\n",tname);
		if (target_resume(t)) {
		    fprintf(stderr,"Could not resume target %s tid %"PRIiTID"\n",
			tname,tid);

		    target_close(t);
		    target_finalize(t);
		    targets = g_list_remove(targets,t);
		}
	    }
	    else {
		fprintf(stderr,
			"Target '%s' tid %d received unexpected status '%s'"
			" at 0x%"PRIxADDR"; attempting to continue!\n",
			tname,tid,TSTATUS(tstat),target_read_reg(t,tid,CREG_IP));
		if (target_resume(t)) {
		    fprintf(stderr,"Could not resume target %s tid %"PRIiTID"\n",
			tname,tid);

		    target_close(t);
		    target_finalize(t);
		    targets = g_list_remove(targets,t);
		}
	    }
	}
    }

 exit:
    fflush(stderr);
    fflush(stdout);
    target_default_cleanup();
    exit(rc);
}
