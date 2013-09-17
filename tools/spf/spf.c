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
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <argp.h>

#include "log.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"
#include "target_os.h"

#include "probe_api.h"
#include "probe.h"
#include "alist.h"
#include "list.h"

struct target *target = NULL;
struct target *otarget = NULL;

GHashTable *sprobes = NULL;
GHashTable *fprobes = NULL;

void cleanup_probes() {
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;

    target_pause(target);

    if (fprobes) {
	g_hash_table_iter_init(&iter,fprobes);
	while (g_hash_table_iter_next(&iter,
				      (gpointer)&key,
				      (gpointer)&probe)) {
	    probe_unregister(probe,1);
	    probe_free(probe,1);
	}
    }
    if (sprobes) {
	g_hash_table_iter_init(&iter,sprobes);
	while (g_hash_table_iter_next(&iter,
				      (gpointer)&key,
				      (gpointer)&probe)) {
	    probe_unregister(probe,1);
	    probe_free(probe,1);
	}
    }


    if (sprobes) 
	g_hash_table_destroy(sprobes);
    sprobes = NULL;
    if (fprobes) 
	g_hash_table_destroy(fprobes);
    fprobes = NULL;
}

target_status_t cleanup() {
    target_status_t retval = TSTATUS_DONE;

    cleanup_probes();

    if (otarget) {
	target_close(otarget);
	target_free(otarget);
	otarget = NULL;
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

result_t pre_handler(struct probe *probe,tid_t tid,void *data,
		     struct probe *trigger,struct probe *base) {
    GHashTableIter iter;
    gpointer kp,vp;
    char vstrbuf[1024];
    struct value *v;
    GHashTable *vt;
    struct bsymbol *bsymbol;
    struct symbol *symbol;
    int i;
    int rc;

    bsymbol = probe->bsymbol;
    symbol = bsymbol_get_symbol(bsymbol);

    vt = probe_value_get_table(trigger,tid);
    if (!vt) {
	fprintf(stderr,
		"ERROR: could not get value table for probe %s tid %"PRIiTID"!\n",
		probe_name(trigger),tid);
	return RESULT_SUCCESS;
    }
    else {
	if (SYMBOL_IS_FUNCTION(symbol))
	    fprintf(stdout,"%s (",symbol_get_name(symbol));
	i = 0;
	g_hash_table_iter_init(&iter,vt);
	while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	    if (i > 0)
		fprintf(stdout,",");
	    v = (struct value *)vp;
	    rc = value_snprintf(v,vstrbuf,sizeof(vstrbuf));
	    if (rc > 0)
		fprintf(stdout,"%s = %s",(char *)kp,vstrbuf);
	    else
		fprintf(stdout,"%s = ?",(char *)kp);
	    ++i;
	}
	if (SYMBOL_IS_FUNCTION(symbol))
	    fprintf(stdout,")");
	    fprintf(stdout,"\n");
    }

    fflush(stderr);
    fflush(stdout);

    return RESULT_SUCCESS;
}

result_t post_handler(struct probe *probe,tid_t tid,void *data,
		      struct probe *trigger,struct probe *base) {
    GHashTableIter iter;
    gpointer kp,vp;
    char vstrbuf[1024];
    struct value *v;
    GHashTable *vt;
    struct bsymbol *bsymbol;
    struct symbol *symbol;
    int i;
    int rc;

    bsymbol = probe->bsymbol;
    symbol = bsymbol_get_symbol(bsymbol);

    vt = probe_value_get_table(trigger,tid);
    if (!vt) {
	fprintf(stderr,
		"ERROR: could not get value table for probe %s tid %"PRIiTID"!\n",
		probe_name(trigger),tid);
	return RESULT_SUCCESS;
    }
    else {
	if (SYMBOL_IS_FUNCTION(symbol))
	    fprintf(stdout,"%s (",symbol_get_name(symbol));
	i = 0;
	g_hash_table_iter_init(&iter,vt);
	while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	    if (strcmp(PROBE_VALUE_NAME_RETURN,(char *)kp) == 0)
		continue;
	    if (i > 0)
		fprintf(stdout,",");
	    v = (struct value *)vp;
	    rc = value_snprintf(v,vstrbuf,sizeof(vstrbuf));
	    if (rc > 0)
		fprintf(stdout,"%s = %s",(char *)kp,vstrbuf);
	    else
		fprintf(stdout,"%s = ?",(char *)kp);
	    ++i;
	}
	if (SYMBOL_IS_FUNCTION(symbol)) {
	    v = probe_value_get(trigger,tid,PROBE_VALUE_NAME_RETURN);
	    if (v) {
		rc = value_snprintf(v,vstrbuf,sizeof(vstrbuf));
		fprintf(stdout,") = %s",vstrbuf);
	    }
	    else
		fprintf(stdout,") = ?");
	}
	fprintf(stdout,"\n");
    }

    fflush(stderr);
    fflush(stdout);

    return RESULT_SUCCESS;
}

struct spf_argp_state {
    int argc;
    char **argv;
    char *overlay_name_or_id;
    struct target_spec *overlay_spec;
};

struct spf_argp_state opts;

struct argp_option spf_argp_opts[] = {
    { "overlay",'O',"<name_or_id>:<spec_opts>",0,"Lookup name or id as an overlay target once the main target is instantiated, and try to open it.  All spec_opts (normal target/dwdebug opts) then apply to the overlay target.",0 },
    { 0,0,0,0,0,0 },
};

error_t spf_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct spf_argp_state *opts = \
	(struct spf_argp_state *)target_argp_driver_state(state);
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
    case 'O':
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

struct argp spf_argp = {
    spf_argp_opts,spf_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};

int main(int argc,char **argv) {
    target_status_t tstat;
    struct target_spec *tspec;
    char targetstr[128];
    int i;
    struct bsymbol *bsymbol;
    struct target *rtarget;
    int oid;
    tid_t otid;
    char *tmp = NULL;
    struct probe *sprobe, *fprobe;
    char *name, *context;
    char *str;
    char namebuf[128];
    struct probe_filter *pre_pf, *post_pf;
    char *pre_filter, *post_filter;
    int have_syscall_table = 0;
    struct target_os_syscall *syscall;

    target_init();
    atexit(target_fini);

    memset(&opts,0,sizeof(opts));

    tspec = target_argp_driver_parse(&spf_argp,&opts,argc,argv,
				     TARGET_TYPE_PTRACE | TARGET_TYPE_XEN,1);

    if (!tspec) {
	verror("could not parse target arguments!\n");
	exit(-1);
    }

    rtarget = target = target_instantiate(tspec,NULL);
    if (!target) {
	verror("could not instantiate target!\n");
	exit(-1);
    }
    target_tostring(target,targetstr,sizeof(targetstr));

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

	target_tostring(target,targetstr,sizeof(targetstr));

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

    sprobes = g_hash_table_new(g_direct_hash,g_direct_equal);
    fprobes = g_hash_table_new(g_direct_hash,g_direct_equal);

    if (rtarget->kind == TARGET_KIND_OS) {
	if (target_os_syscall_table_load(rtarget))
	    vwarn("could not load the syscall table; target_os_syscall probes"
		  " will not be available!\n");
	else
	    have_syscall_table = 1;
    }

    if (opts.argc > 0) {
	for (i = 0; i < opts.argc; ++i) {
	    pre_filter = post_filter = context = NULL;
	    name = str = opts.argv[i];
	    while (*str != '\0') {
		if (*str == ':' && *(str+1) == ':') {
		    *str = '\0';
		    str += 2;
		    break;
		}
		++str;
	    }
	    if (*str != '\0') {
		if (*str == ':')
		    pre_filter = NULL;
		else
		    pre_filter = str;
	    }
	    while (*str != '\0') {
		if (*str == ':' && *(str+1) == ':') {
		    *str = '\0';
		    str += 2;
		    break;
		}
		++str;
	    }
	    if (*str != '\0') {
		if (*str == ':')
		    post_filter = NULL;
		else
		    post_filter = str;
	    }
	    while (*str != '\0') {
		if (*str == ':' && *(str+1) == ':') {
		    *str = '\0';
		    str += 2;
		    break;
		}
		++str;
	    }
	    if (*str != '\0')
		context = str;

	    sprobe = (struct probe *)g_hash_table_lookup(sprobes,name);
	    if (!sprobe) {
		/*
		 * Create a probe on that symbol:
		 */

		if (have_syscall_table) {
		    syscall = target_os_syscall_lookup_name(rtarget,name);
		    if (syscall) {
			sprobe = \
			    target_os_syscall_probe(rtarget,TID_GLOBAL,syscall,
						    probe_do_sink_pre_handlers,
						    probe_do_sink_post_handlers,
						    NULL);
			if (!sprobe) {
			    verror("could not place syscall value probe on %s;"
				   " aborting!\n",name);
			    cleanup();
			    exit(-5);
			}
		    }
		}

		if (!sprobe) {
		    bsymbol = target_lookup_sym(rtarget,name,NULL,NULL,
						SYMBOL_TYPE_FLAG_NONE);
		    if (!bsymbol) {
			verror("could not lookup symbol %s; aborting!\n",name);
			cleanup();
			exit(-3);
		    }
		    sprobe = probe_value_symbol(rtarget,TID_GLOBAL,bsymbol,
						probe_do_sink_pre_handlers,
						probe_do_sink_post_handlers,NULL);
		    if (!sprobe) {
			verror("could not place value probe on %s; aborting!\n",
			       name);
			cleanup();
			exit(-3);
		    }
		}

		g_hash_table_insert(sprobes,name,sprobe);
	    }

	    /* Create either an empty filter probe or parse the filter! */
	    if (pre_filter) {
		pre_pf = probe_filter_parse(pre_filter);
		if (!pre_pf) {
		    verror("could not parse pre_filter '%s'!\n",pre_filter);
		    cleanup();
		    exit(-4);
		}
	    }
	    else 
		pre_pf = NULL;
	    if (post_filter) {
		post_pf = probe_filter_parse(post_filter);
		if (!post_pf) {
		    verror("could not parse post_filter '%s'!\n",post_filter);
		    cleanup();
		    exit(-4);
		}
	    }
	    else 
		post_pf = NULL;

	    snprintf(namebuf,sizeof(namebuf),"filter_%s_%d",name,i);
	    fprobe = probe_create_filtered(target,TID_GLOBAL,NULL,namebuf,
					   pre_handler,pre_pf,
					   post_handler,post_pf,NULL,0,1);

	    probe_register_source(fprobe,sprobe);

	    g_hash_table_insert(fprobes,namebuf,fprobe);
	}
    }
    else {
	verror("Must supply some symbols to probe!\n");
	cleanup();
	exit(-5);
    }

    /*
     * The target was paused after instantiation; we have to resume it
     * now that we've registered probes.
     */
    target_resume(target);

    fprintf(stdout,"Starting Symbol Probe Filtering!\n");
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
	else if (tstat == TSTATUS_EXITING) {
	    fflush(stderr);
	    fflush(stdout);

	    fprintf(stdout,"target %s exiting, removing probes safely...\n",
		    targetstr);

	    cleanup_probes();

	    if (target_resume(target)) {
		verror("could not resume target!\n");
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
		    "target %s interrupted at 0x%"PRIxREGVAL
		    " -- bad status (%d), exiting\n",
		    targetstr,target_read_creg(target,TID_GLOBAL,CREG_IP),tstat);

	    goto err;
	}
    }

 err:
    fflush(stderr);
    fflush(stdout);
    tstat = cleanup();

 out:
    fflush(stderr);
    fflush(stdout);
    exit(0);
}
