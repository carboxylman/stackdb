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
#include <errno.h>
#include <string.h>

#include <sys/user.h>
#include <sys/ptrace.h>
#include <inttypes.h>

#include <signal.h>

#include <argp.h>

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

#include "rop.h"

struct target *t = NULL;

GHashTable *probes = NULL;
struct array_list *rop_violation_list = NULL;

target_status_t cleanup_target() {
    target_status_t retval;

    retval = target_close(t);
    target_free(t);

    return retval;
}

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
    }

    if (probes) 
	g_hash_table_destroy(probes);
}

void sigh(int signo) {
    if (t) {
	target_pause(t);
	cleanup_probes();
	cleanup_target();
    }
    exit(0);
}

int rop_handler(struct probe *probe,void *data,struct probe *trigger) {
    char *buf;
    int buflen;
    struct rop_checkret_status *rop_status = \
	(struct rop_checkret_status *)probe_summarize(probe);
    struct rop_checkret_data *rop_data = \
	(struct rop_checkret_data *)probe_priv(probe);

    fflush(stderr);

    if (rop_status->isviolation) {
	fprintf(stdout,"%s: CFI violation %s",probe_name(probe),
		rop_status->isfpviolation ? "(false pos?)" : "");

	buflen = 64 + strlen(rop_data->gadget->meta);
	buf = malloc(buflen);
	snprintf(buf,buflen,"gadget 0x%"PRIxADDR", retaddr 0x%"PRIxADDR
		 "  %s\n",
		 probe_addr(rop_data->entry_probe),rop_status->current_ret_addr,
		 rop_data->gadget->meta);
	array_list_append(rop_violation_list,buf);
    }
    else
	fprintf(stdout,"%s: CFI clean",probe_name(probe));
    fprintf(stdout," (retaddr=0x%"PRIxADDR",violations=%d,total=%d,fpviolations=%d,jmpfpviolations=%d,jccfpviolations=%d)\n",
	    rop_status->current_ret_addr,rop_status->violations,
	    rop_status->total,rop_status->fpviolations,
	    rop_status->jmpfpviolations,rop_status->jccfpviolations);

    fflush(stdout);

    return 0;
}

struct rc_argp_state {
    int argc;
    char **argv;
};

struct rc_argp_state opts;

struct argp_option rc_argp_opts[] = {
    { 0,0,0,0,0,0 },
};

error_t rc_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct rc_argp_state *opts = \
	(struct rc_argp_state *)target_argp_driver_state(state);

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

struct argp rc_argp = {
    rc_argp_opts,rc_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};

int main(int argc,char **argv) {
    target_status_t tstat;
    char *filename;
    GHashTableIter iter;
    gpointer key;
    struct rop_gadget *gadget;
    struct probe *probe;
    int i;
    GHashTable *gadgets;
    struct target_spec *tspec;
    char targetstr[128];

    dwdebug_init();
    atexit(dwdebug_fini);

    memset(&opts,0,sizeof(opts));

    tspec = target_argp_driver_parse(&rc_argp,&opts,argc,argv,TARGET_TYPE_XEN,1);

    if (!tspec) {
	verror("could not parse target arguments!\n");
	exit(-1);
    }

    if (!opts.argc) {
	fprintf(stderr,"ERROR: must supply a gadget file!\n");
	exit(-5);
    }

    filename = opts.argv[0];

    t = target_instantiate(tspec);
    if (!t) {
	verror("could not instantiate target!\n");
	exit(-1);
    }
    target_tostring(t,targetstr,sizeof(targetstr));

    if (target_open(t)) {
	fprintf(stderr,"could not open %s!\n",targetstr);
	exit(-4);
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

    /* Install probes... */
    rop_violation_list = array_list_create(128);
    probes = g_hash_table_new(g_direct_hash,g_direct_equal);
    gadgets = rop_load_gadget_file(filename);
    g_hash_table_iter_init(&iter,gadgets);
    while (g_hash_table_iter_next(&iter,(gpointer)&key,(gpointer)&gadget)) {
	probe = probe_rop_checkret(t,TID_GLOBAL,gadget,NULL,rop_handler,NULL);
	if (!probe) {
	    fprintf(stderr,"could not install probe on gadget at 0x%"PRIxADDR"\n",
		    gadget->start);
	    tstat = TSTATUS_ERROR;
	    goto err;
	}
	g_hash_table_insert(probes,(gpointer)probe,(gpointer)probe);
    }

    /* The target is paused after the attach; we have to resume it now
     * that we've registered probes.
     */
    target_resume(t);

    fprintf(stdout,"Starting watch loop!\n");
    fflush(stdout);

    while (1) {
	tstat = target_monitor(t);
	if (tstat == TSTATUS_PAUSED) {
	    if (target_type(t) == TARGET_TYPE_PTRACE && linux_userproc_at_syscall(t,TID_GLOBAL)) {
		target_resume(t);
		continue;
	    }

	    fflush(stderr);
	    fflush(stdout);
	    printf("target interrupted at 0x%" PRIxREGVAL "\n",
		   target_read_reg(t,TID_GLOBAL,t->ipregno));

	    if (target_resume(t)) {
		fprintf(stderr,"could not resume target\n");
		cleanup_probes();
		cleanup_target();
		exit(-16);
	    }
	}
	else if (tstat == TSTATUS_DONE) {
	    fflush(stderr);
	    fflush(stdout);
	    printf("target exited, cleaning up.\n");
	    cleanup_target();

	    goto out;
	}
	else {
	    fflush(stderr);
	    fflush(stdout);
	    printf("target interrupted at 0x%"PRIxREGVAL" -- NOT PAUSED (%d)\n",
		   target_read_reg(t,TID_GLOBAL,t->ipregno),tstat);
	    goto err;
	}
    }

 err:
    fflush(stderr);
    fflush(stdout);
    cleanup_probes();
    tstat = cleanup_target();

 out:
    if (array_list_len(rop_violation_list)) {
	fprintf(stdout,"Gadgets used:\n");
	for (i = 0; i < array_list_len(rop_violation_list); ++i) {
	    char *rv = (char *)array_list_item(rop_violation_list,i);
	    fprintf(stdout,"%s",rv);
	    free(rv);
	}
    }
    else {
	fprintf(stdout,"No ROP violations detected!\n");
    }

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
