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
#include <time.h>

#include "log.h"
#include "target_api.h"
#include "target.h"
#include "target_os.h"

static int cleaning = 0;
struct target *t = NULL;
GHashTable *probes = NULL;

void cleanup_probes() {
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
	g_hash_table_destroy(probes);
	probes = NULL;
    }
}

void cleanup() {
    if (cleaning)
	return;
    cleaning = 1;

    cleanup_probes();

    if (t) {
	target_close(t);
	target_free(t);
	t = NULL;
    }

    cleaning = 0;
}

void sigh(int signo) {
    if (t) {
	target_pause(t);
	cleanup();
    }
    target_fini();
    exit(0);
}

result_t syscall_pre_handler(struct probe *probe,tid_t tid,void *handler_data,
			     struct probe *trigger,struct probe *base) {
    struct target_os_syscall_state *scs;
    struct timeval tv = { 0,0 };
    int i;
    struct dump_info ud = { .stream = stdout,.prefix = "",.detail = 0,.meta = 0 };
    struct value *v;
    void *rv;

    scs = target_os_syscall_probe_last(probe_target(probe),tid);
    if (!scs) {
	verror("could not get syscall state!\n");
	/* XXX: don't return _ERROR because that will disable the probe. */
	return RESULT_SUCCESS;
    }

    gettimeofday(&tv,NULL);

    printf("%11ld.%-6ld (%d) tid %6"PRIiTID" %s ",
	   tv.tv_sec,tv.tv_usec,scs->syscall->num,tid,
	   (scs->syscall->bsymbol) ? bsymbol_get_name(scs->syscall->bsymbol) : "");
    if (scs->argvals) {
	printf("(");
	array_list_foreach(scs->argvals,i,v) {
	    if (!v) {
		if (scs->regvals) 
		    printf("0x%"PRIxREGVAL,
			   (REGVAL)array_list_item(scs->regvals,i));
	    }
	    else {
		value_dump_simple(v,&ud);
	    }
	    if (!array_list_foreach_is_last(scs->argvals,i))
		printf(", ");
	}
	printf(")\n");
    }
    else if (scs->regvals) {
	printf("(");
	array_list_foreach(scs->regvals,i,rv) {
	    printf("0x%"PRIxREGVAL,(REGVAL)rv);
	    if (!array_list_foreach_is_last(scs->regvals,i))
		printf(", ");
	}
	printf(")\n");
    }
    else {
	printf("()\n");
    }

    fflush(stdout);

    return RESULT_SUCCESS;
}

result_t syscall_post_handler(struct probe *probe,tid_t tid,void *handler_data,
			     struct probe *trigger,struct probe *base) {
    struct target_os_syscall_state *scs;
    struct timeval tv = { 0,0 };

    scs = target_os_syscall_probe_last(probe_target(probe),tid);
    if (!scs) {
	verror("could not get syscall state!\n");
	/* XXX: don't return _ERROR because that will disable the probe. */
	return RESULT_SUCCESS;
    }

    gettimeofday(&tv,NULL);

    printf("%11ld.%-6ld (%d) tid %6"PRIiTID" %s = 0x%"PRIxREGVAL"\n",
	   tv.tv_sec,tv.tv_usec,scs->syscall->num,tid,
	   (scs->syscall->bsymbol) ? bsymbol_get_name(scs->syscall->bsymbol) : "",
	   scs->retval);
    fflush(stdout);

    return RESULT_SUCCESS;
}

struct strace_argp_state {
    int argc;
    char **argv;
};

struct strace_argp_state opts;

struct argp_option strace_argp_opts[] = {
    { 0,0,0,0,0,0 },
};

error_t strace_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct strace_argp_state *opts = \
	(struct strace_argp_state *)target_argp_driver_state(state);

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

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp strace_argp = {
    strace_argp_opts,strace_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};

int main(int argc,char **argv) {
    struct target_spec *tspec;
    char *targetstr;
    tid_t tid;
    target_status_t tstat;
    int i;
    struct target_os_syscall *syscall;
    struct probe *p;

    tspec = target_argp_driver_parse(&strace_argp,&opts,argc,argv,
				     TARGET_TYPE_XEN,1);

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

    target_init();
    atexit(target_fini);

    t = target_instantiate(tspec,NULL);
    if (!t) {
	verror("could not instantiate target!\n");
	exit(-1);
    }

    if (target_open(t)) {
	fprintf(stderr,"could not open target!\n");
	exit(-4);
    }

    /*
     * Make a permanent copy so we can print useful messages after
     * target_free.
     */
    targetstr = target_name(t);
    if (!targetstr) 
	targetstr = strdup("<UNNAMED_TARGET>");
    else
	targetstr = strdup(targetstr);

    if (target_os_syscall_table_load(t))
	goto exit;

    fflush(stderr);
    fflush(stdout);

    probes = g_hash_table_new(g_direct_hash,g_direct_equal);

    /*
     * If they gave us specific syscalls, look them up and probe them
     * individually; else probe globally.
     */
    if (opts.argc) {
	if (target_os_syscall_table_load(t))
	    goto exit;
	for (i = 0; i < opts.argc; ++i) {
	    syscall = target_os_syscall_lookup_name(t,opts.argv[i]);
	    if (!syscall) {
		verror("could not lookup syscall %s!\n",opts.argv[i]);
		goto exit;
	    }
	    p = target_os_syscall_probe(t,TID_GLOBAL,syscall,syscall_pre_handler,
					syscall_post_handler,NULL);
	    if (!p) {
		verror("could not probe syscall %s!\n",opts.argv[i]);
		goto exit;
	    }
	    g_hash_table_insert(probes,p,p);
	}
    }
    else {
	p = target_os_syscall_probe_all(t,TID_GLOBAL,
					syscall_pre_handler,syscall_post_handler,
					NULL);
	if (!p) {
	    verror("could not probe global syscall entry/exit path!\n");
	    goto exit;
	}
	g_hash_table_insert(probes,p,p);
    }

    target_resume(t);

    while (1) {
	tid = 0;

	tstat = target_monitor(t);

	if (tstat == TSTATUS_RUNNING)
	    continue;
	else if (tstat == TSTATUS_PAUSED) {
	    tid = target_gettid(t);

	    printf("%s thread %"PRIiTID" interrupted at 0x%"PRIxREGVAL"\n",
		   targetstr,tid,target_read_reg(t,tid,CREG_IP));

	    if (target_resume(t)) {
		fprintf(stderr,"could not resume target %s thread %"PRIiTID"\n",
			targetstr,tid);

		cleanup();
		exit(-16);
	    }
	}
	else if (tstat == TSTATUS_EXITING) {
	    tid = target_gettid(t);
	    printf("%s exiting, removing probes safely...\n",targetstr);
	    cleanup_probes();
	    /* Let it resume to "finish" exiting! */
	    if (target_resume(t)) {
		fprintf(stderr,"could not resume target %s thread %"PRIiTID"\n",
			targetstr,tid);

		cleanup();
		exit(-16);
	    }
	}
	else {
	out:
	    fflush(stderr);
	    fflush(stdout);
	    cleanup();

	    if (tstat == TSTATUS_DONE)  {
		printf("%s finished.\n",targetstr);
		free(targetstr);
		exit(0);
	    }
	    else if (tstat == TSTATUS_ERROR) {
		printf("%s monitoring failed!\n",targetstr);
		free(targetstr);
		exit(-9);
	    }
	    else {
		printf("%s monitoring failed with %d!\n",targetstr,tstat);
		free(targetstr);
		exit(-10);
	    }
	}
    }

 exit:
    target_resume(t);

    fflush(stderr);
    fflush(stdout);
    cleanup();

    printf("%s finished.\n",targetstr);
    exit(0);
}
