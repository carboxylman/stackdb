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

#include <sys/user.h>
#include <sys/ptrace.h>
#include <inttypes.h>

#include <signal.h>

#include <argp.h>

#include "log.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"

#include "probe_api.h"
#include "probe.h"
#include "alist.h"
#include "list.h"

#include "cfi.h"

struct target *target = NULL;
struct probe *cfi_probe = NULL;

static int result_counter = 0;
static int final_result_counter = 0;

target_status_t cleanup() {
    target_status_t retval = TSTATUS_DONE;

    if (cfi_probe) {
	probe_free(cfi_probe,1);
	cfi_probe = NULL;
    }
    if (target) {
	retval = target_close(target);
	target_free(target);
	target = NULL;
    }

    return retval;
}

void sigh(int signo) {
    cleanup();
    exit(0);
}

result_t cfi_handler(struct probe *probe,void *data,struct probe *trigger) {
    tid_t tid;
    struct cfi_data *cfi = (struct cfi_data *)probe_priv(probe);
    struct cfi_thread_status *cts;
    struct cfi_status *cs;
    char *buf;
    int buflen = 0;
    int rc = 0, rcr;
    ADDR base;
    struct bsymbol *function;
    char *name;
    void *retaddr;
    int i;

    tid = target_gettid(cfi->target);

    cts = (struct cfi_thread_status *)probe_summarize_tid(probe,tid);
    cs = (struct cfi_status *)probe_summarize(probe);

    if (cts->status.isviolation) {
	// 0xRETADDR <name> 0xBASEADDR | 
	buflen += array_list_len(cts->shadow_stack) * (sizeof(ADDR) * 4 + 8 + 3);
	array_list_foreach(cts->shadow_stack_symbols,i,function) {
	    if (!function)
		buflen += 4; // NULL
	    else if (bsymbol_get_name(function))
		buflen += strlen(bsymbol_get_name(function));
	    else
		buflen += 4; // NULL
	}
	buflen += 1; // '\0'

	buf = malloc(buflen);
	array_list_foreach(cts->shadow_stack,i,retaddr) {
	    function = (struct bsymbol *) \
		array_list_item(cts->shadow_stack_symbols,i);
	    name = NULL;
	    base = 0;
	    if (function) {
		name = bsymbol_get_name(function);
		target_resolve_symbol_base(cfi->target,cfi->tid,function,
					   &base,NULL);
	    }

	    rcr = snprintf(buf + rc,buflen - rc,
			   "0x%"PRIxADDR" %s 0x%"PRIxADDR" | ",
			   (ADDR)(uintptr_t)retaddr,name,base);
	    rc += rcr;
	}
	if (rc > buflen)
	    buf[buflen - 1] = '\0';
	else
	    buf[rc] = '\0';
	
	fprintf(stdout,
		"RESULT(i:%d): cfi (2) CFIViolation \"CFI violation!\""
		" (badretaddr=0x%"PRIxADDR",oldretaddr=0x%"PRIxADDR","
		" violations=%d,stack=%s)\n",
		++result_counter,
		cts->status.newretaddr,cts->status.oldretaddr,
		cts->status.violations,buf);
	fflush(stdout);
	free(buf);
    }
    /*
    else {
	fprintf(stdout,"RESULT(i:%d): rop (0) CFIClean \"CFI clean\""
		" (retaddr=0x%"PRIxADDR",violations=%d,total=%d,"
		"fpviolations=%d,jmpfpviolations=%d,jccfpviolations=%d,"
		"isfpviolation=%d)\n",
		++result_counter,rop_status->current_ret_addr,
		rop_status->violations,rop_status->total,
		rop_status->fpviolations,rop_status->jmpfpviolations,
		rop_status->jccfpviolations,rop_status->isfpviolation);
    }

    fflush(stdout);
    */
    return 0;
}

struct cc_argp_state {
    cfi_mode_t mode;
    cfi_flags_t flags;
    int argc;
    char **argv;
};

struct cc_argp_state opts;

struct argp_option cc_argp_opts[] = {
    { "mode",'M',"dynamic|static",0,"Set the CFI mode (only dynamic now).",-3 },
    { "no-autofollow",'N',NULL,0,
        "Do not add functions to the CFI checked set.",-3 },
    { "no-singlestep-unknown",'S',NULL,0,
        "Don't singlestep unknown areas in the target.",-3 },
    { "fix-stack",'f',NULL,0,
        "Fix the stack before a RET that would violate CFI.",-3 },
    { 0,0,0,0,0,0 },
};

error_t cc_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct cc_argp_state *opts = \
	(struct cc_argp_state *)target_argp_driver_state(state);

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

struct argp cc_argp = {
    cc_argp_opts,cc_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};

int main(int argc,char **argv) {
    target_status_t tstat;
    struct target_spec *tspec;
    char targetstr[128];
    struct array_list *root_function_list;
    int i;
    struct bsymbol *function;

    target_init();
    atexit(target_fini);

    memset(&opts,0,sizeof(opts));
    opts.mode = CFI_DYNAMIC;

    tspec = target_argp_driver_parse(&cc_argp,&opts,argc,argv,
				     TARGET_TYPE_PTRACE | TARGET_TYPE_XEN,1);

    if (!tspec) {
	verror("could not parse target arguments!\n");
	exit(-1);
    }

    target = target_instantiate(tspec,NULL);
    if (!target) {
	verror("could not instantiate target!\n");
	exit(-1);
    }
    target_tostring(target,targetstr,sizeof(targetstr));

    if (target_open(target)) {
	fprintf(stderr,"could not open %s!\n",targetstr);
	exit(-4);
    }

    if (opts.argc > 0) {
	root_function_list = array_list_create(opts.argc);
	for (i = 0; i < opts.argc; ++i) {
	    function = target_lookup_sym(target,opts.argv[i],NULL,NULL,
					 SYMBOL_TYPE_FLAG_NONE);
	    if (!function) {
		verror("could not lookup symbol %s; aborting!\n",opts.argv[i]);
		cleanup();
		exit(-3);
	    }
	    array_list_append(root_function_list,function);
	}
    }
    else {
	root_function_list = array_list_create(1);
	function = target_lookup_sym(target,"main",NULL,NULL,
				     SYMBOL_TYPE_FLAG_NONE);
	if (!function) {
	    verror("could not lookup symbol %s; aborting!\n","main");
	    cleanup();
	    exit(-3);
	}
	array_list_append(root_function_list,function);
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
    cfi_probe = probe_cfi(target,TID_GLOBAL,opts.mode,opts.flags,
			  root_function_list,
			  cfi_handler,cfi_handler,NULL);
    if (!cfi_probe) {
	verror("could not instantiate the CFI meta-probe; aborting!\n");
	cleanup();
	exit(-4);
    }

    /*
     * The target was paused after instantiation; we have to resume it
     * now that we've registered probes.
     */
    target_resume(target);

    fprintf(stdout,"Starting CFI monitoring!\n");
    fflush(stdout);

    while (1) {
	tstat = target_monitor(target);
	if (tstat == TSTATUS_PAUSED) {
	    fflush(stderr);
	    fflush(stdout);
	    vwarn("target %s interrupted at 0x%"PRIxREGVAL"; trying resume!\n",
		  targetstr,target_read_creg(target,TID_GLOBAL,CREG_IP));

	    if (target_resume(target)) {
		verror("could not resume target\n");
		tstat = cleanup();
		exit(-16);
	    }
	}
	else if (tstat == TSTATUS_DONE) {
	    fflush(stderr);
	    fflush(stdout);
	    fprintf(stdout,"target %s exited, cleaning up.\n",targetstr);
	    tstat = cleanup();

	    goto out;
	}
	else {
	    fflush(stderr);
	    fflush(stdout);
	    fprintf(stdout,
		    "target %s interrupted at 0x%"PRIxREGVAL" -- NOT PAUSED (%d)\n",
		    targetstr,target_read_creg(target,TID_GLOBAL,CREG_IP),tstat);
	    goto err;
	}
    }

 err:
    fflush(stderr);
    fflush(stdout);
    tstat = cleanup();

 out:
    /*
    if (array_list_len(rop_violation_list)) {
	if (!oldformat) 
	    fprintf(stdout,"RESULT(f:%d): rop (1) Violations \"ROP violations detected.\"\n",
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
	    fprintf(stdout,"RESULT(f:%d): rop (0) NoViolations \"No ROP violations detected.\"\n",
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
    */

    exit(0);
}
