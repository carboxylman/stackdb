/*
 * Copyright (c) 2012, 2013, 2014 The University of Utah
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

struct target *target = NULL;
struct target *otarget = NULL;

static int result_counter = 0;
static int final_result_counter = 0;

static int oldformat = 0;

GHashTable *probes = NULL;
struct array_list *rop_violation_list = NULL;

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

    probes = NULL;
}

void cleanup() {
    if (target)
	target_pause(target);
    cleanup_probes();
    if (otarget) {
	target_close(otarget);
	target_free(otarget);
	otarget = NULL;
    }
    if (target) {
	target_close(target);
	target_free(target);
	target = NULL;
    }
}

void sigh(int signo) {
    cleanup();
    exit(0);
}

result_t rop_handler(struct probe *probe,tid_t tid,void *data,
		     struct probe *trigger,struct probe *base) {
    char *buf;
    int buflen;
    struct rop_checkret_status *rop_status = \
	(struct rop_checkret_status *)probe_summarize(probe);
    struct rop_checkret_data *rop_data = \
	(struct rop_checkret_data *)probe_priv(probe);

    fflush(stderr);

    if (rop_status->isviolation) {
	if (!oldformat) {
	    fprintf(stdout,
		    "RESULT:: (i:%d) rop (2) CFIViolation \"CFI violation!\""
		    " (retaddr=0x%"PRIxADDR",violations=%d,total=%d,"
		    "fpviolations=%d,jmpfpviolations=%d,jccfpviolations=%d,"
		    "isfpviolation=%d,gadgetstart=0x%"PRIxADDR","
		    "gadgetend=0x%"PRIxADDR",gadgetcontinstr=0x%"PRIxADDR
		    ") ::RESULT\n",
		    ++result_counter,rop_status->current_ret_addr,
		    rop_status->violations,rop_status->total,
		    rop_status->fpviolations,rop_status->jmpfpviolations,
		    rop_status->jccfpviolations,rop_status->isfpviolation,
		    rop_data->gadget->start,rop_data->gadget->end,
		    rop_data->cont_instr_start);
	}
	else
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
    else {
	if (!oldformat) {
	    fprintf(stdout,"RESULT:: (i:%d) rop (0) CFIClean \"CFI clean\""
		    " (retaddr=0x%"PRIxADDR",violations=%d,total=%d,"
		    "fpviolations=%d,jmpfpviolations=%d,jccfpviolations=%d,"
		    "isfpviolation=%d,gadgetstart=0x%"PRIxADDR","
		    "gadgetend=0x%"PRIxADDR",gadgetcontinstr=0x%"PRIxADDR
		    ") ::RESULT\n",
		    ++result_counter,rop_status->current_ret_addr,
		    rop_status->violations,rop_status->total,
		    rop_status->fpviolations,rop_status->jmpfpviolations,
		    rop_status->jccfpviolations,rop_status->isfpviolation,
		    rop_data->gadget->start,rop_data->gadget->end,
		    rop_data->cont_instr_start);
	}
	else {
	    fprintf(stdout,"%s: CFI clean",probe_name(probe));
	    fprintf(stdout," (retaddr=0x%"PRIxADDR",violations=%d,total=%d,fpviolations=%d,jmpfpviolations=%d,jccfpviolations=%d)\n",
		    rop_status->current_ret_addr,rop_status->violations,
		    rop_status->total,rop_status->fpviolations,
		    rop_status->jmpfpviolations,rop_status->jccfpviolations);
	}
    }

    fflush(stdout);

    return 0;
}

struct rc_argp_state {
    int argc;
    char **argv;
    char *overlay_name_or_id;
    struct target_spec *overlay_spec;
};

struct rc_argp_state opts;

struct argp_option rc_argp_opts[] = {
    { "overlay",'V',"<name_or_id>:<spec_opts>",0,"Lookup name or id as an overlay target once the main target is instantiated, and try to open it.  All spec_opts (normal target/dwdebug opts) then apply to the overlay target.",0 },
    { 0,0,0,0,0,0 },
};

error_t rc_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct rc_argp_state *opts = \
	(struct rc_argp_state *)target_argp_driver_state(state);
    struct array_list *argv_list;
    char *argptr;
    char *nargptr;
    char *vargptr;
    int inesc;
    int inquote;
    int quotechar;

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
    case 'V':
	/*
	 * We need to split the <name_or_id>:<spec> part; then split
	 * <spec> into an argv.  Simple rules: \ escapes the next char;
	 * space not in ' or " causes us to end the current argv[i] and
	 * start the next one.
	 */
	argptr = index(arg,':');
	if (!argptr) {
	    verror("bad overlay spec!\n");
	    return EINVAL;
	}
	argv_list = array_list_create(32);
	array_list_append(argv_list,"dumptarget_overlay");

	opts->overlay_name_or_id = arg;
	*argptr = '\0';
	++argptr;

	while (*argptr == ' ')
	    ++argptr;

	inesc = 0;
	inquote = 0;
	quotechar = 0;
	nargptr = argptr;
	vargptr = argptr;
	while (*argptr != '\0') {
	    if (*argptr == '\\') {
		if (inesc) {
		    inesc = 0;
		    *nargptr = '\\';
		    ++nargptr;
		}
		else {
		    /* Don't copy the escape char. */
		    inesc = 1;
		    ++argptr;
		    continue;
		}
	    }
	    else if (inesc) {
		inesc = 0;
		/* Just copy it. */
		*nargptr = *argptr;
		++nargptr;
	    }
	    else if (inquote && *argptr == quotechar) {
		/* Ended the quoted sequence; don't copy quotes. */
		inquote = 0;
		quotechar = 0;
		++argptr;
		continue;
	    }
	    else if (*argptr == '\'' || *argptr == '"') {
		inquote = 1;
		quotechar = *argptr;
		++argptr;
		continue;
	    }
	    else if (!inquote && *argptr == ' ') {
		*nargptr = *argptr = '\0';
		if (vargptr) {
		    array_list_append(argv_list,vargptr);
		    //printf("vargptr (%p) = '%s'\n",vargptr,vargptr);
		    vargptr = NULL;
		}
		vargptr = NULL;
		nargptr = ++argptr;
		continue;
	    }
	    else {
		if (!vargptr)
		    vargptr = nargptr;

		*nargptr = *argptr;
		++nargptr;
	    }

	    /* Default increment. */
	    ++argptr;
	}
	if (vargptr) {
	    *nargptr = '\0';
	    array_list_append(argv_list,vargptr);
	    //printf("vargptr (%p) = '%s'\n",vargptr,vargptr);
	}
	array_list_append(argv_list,NULL);

	opts->overlay_spec = target_argp_driver_parse(NULL,NULL,
						      array_list_len(argv_list) - 1,
						      (char **)argv_list->list,
						      TARGET_TYPE_XEN_PROCESS,0);
	if (!opts->overlay_spec) {
	    verror("could not parse overlay spec!\n");
	    array_list_free(argv_list);
	    return EINVAL;
	}

	array_list_free(argv_list);
	break;

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
    GHashTableIter iter;
    gpointer key;
    struct rop_gadget *gadget;
    struct probe *probe;
    int i;
    GHashTable *gadgets;
    struct target_spec *tspec;
    char targetstr[128];
    struct target *rtarget;
    int oid;
    tid_t otid;
    char *tmp = NULL;

    dwdebug_init();
    atexit(dwdebug_fini);

    memset(&opts,0,sizeof(opts));

    tspec = target_argp_driver_parse(&rc_argp,&opts,argc,argv,
				     TARGET_TYPE_PTRACE | TARGET_TYPE_XEN,1);

    if (!tspec) {
	verror("could not parse target arguments!\n");
	exit(-1);
    }

    if (opts.argc > 0)
	gadgets = rop_load_gadget_file(opts.argv[0]);
    else 
	gadgets = rop_load_gadget_stream(stdin);

    if (!gadgets || g_hash_table_size(gadgets) == 0) {
	verror("No gadgets in file!\n");
	return -2;
    }

    rtarget = target = target_instantiate(tspec,NULL);
    if (!target) {
	verror("could not instantiate target!\n");
	exit(-1);
    }
    target_snprintf(target,targetstr,sizeof(targetstr));

    if (target_open(target)) {
	fprintf(stderr,"could not open %s!\n",targetstr);
	exit(-4);
    }

    /*
     * Load an overlay target, if there is one.
     */
    if (opts.overlay_name_or_id && opts.overlay_spec) {
	errno = 0;
	oid = (int)strtol(opts.overlay_name_or_id,&tmp,0);
	if (errno || tmp == opts.overlay_name_or_id)
	    otid = 
		target_lookup_overlay_thread_by_name(target,
						     opts.overlay_name_or_id);
	else
	    otid = target_lookup_overlay_thread_by_id(target,oid);
	if (otid < 0) {
	    verror("could not find overlay thread '%s', exiting!\n",
		   opts.overlay_name_or_id);
	    cleanup();
	    exit(-111);
	}
	otarget = target_instantiate_overlay(target,otid,opts.overlay_spec);
	if (!otarget) {
	    verror("could not instantiate overlay target '%s'!\n",
		   opts.overlay_name_or_id);
	    cleanup();
	    exit(-112);
	}

	if (target_open(otarget)) {
	    fprintf(stderr,"could not open overlay target!\n");
	    cleanup();
	    exit(-114);
	}

	target_snprintf(target,targetstr,sizeof(targetstr));

	rtarget = otarget;
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
    g_hash_table_iter_init(&iter,gadgets);
    while (g_hash_table_iter_next(&iter,(gpointer)&key,(gpointer)&gadget)) {
	probe = probe_rop_checkret(rtarget,TID_GLOBAL,gadget,NULL,rop_handler,NULL);
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
    target_resume(target);

    fprintf(stdout,"Starting watch loop!\n");
    fflush(stdout);

    while (1) {
	tstat = target_monitor(target);
	if (tstat == TSTATUS_PAUSED) {
	    fflush(stderr);
	    fflush(stdout);
	    printf("target interrupted at 0x%"PRIxREGVAL"; trying to resume!\n",
		   target_read_reg(target,TID_GLOBAL,target->ipregno));

	    if (target_resume(target)) {
		fprintf(stderr,"could not resume target\n");
		cleanup();
		exit(-16);
	    }
	}
	else if (tstat == TSTATUS_EXITING) {
	    fflush(stderr);
	    fflush(stdout);
	    fprintf(stdout,"target %s exiting, removing probes safely...\n",
		    targetstr);

	    cleanup_probes();

	    if (target_resume(target)) {
		verror("could not resume target!\n");
		cleanup();
		exit(-16);
	    }
	}
	else if (tstat == TSTATUS_DONE) {
	    fflush(stderr);
	    fflush(stdout);
	    printf("target exited, cleaning up.\n");
	    cleanup();

	    goto out;
	}
	else {
	    fflush(stderr);
	    fflush(stdout);
	    printf("target interrupted at 0x%"PRIxREGVAL" -- bad status (%d)\n",
		   target_read_reg(target,TID_GLOBAL,target->ipregno),tstat);
	    goto err;
	}
    }

 err:
    fflush(stderr);
    fflush(stdout);
    cleanup();

 out:
    if (array_list_len(rop_violation_list)) {
	if (!oldformat) 
	    fprintf(stdout,"RESULT:: (f:%d) rop (1) Violations \"ROP violations detected.\" ::RESULT\n",
		    ++final_result_counter);
	else {
	    fprintf(stdout,"ROP violations detected!\n");

	    fprintf(stdout,"Gadgets used:\n");

	    for (i = 0; i < array_list_len(rop_violation_list); ++i) {
		char *rv = (char *)array_list_item(rop_violation_list,i);
		fprintf(stdout,"%s",rv);
		free(rv);
	    }
	}
    }
    else {
	if (!oldformat) 
	    fprintf(stdout,"RESULT:: (f:%d) rop (0) NoViolations \"No ROP violations detected.\" ::RESULT\n",
		    ++final_result_counter);
	else
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
