/*
 * Copyright (c) 2011, 2012, 2013, 2014 The University of Utah
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
#include <glib.h>
#include "glib_wrapper.h"

#include "log.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"
#include "probe_api.h"

struct dt_argp_state {
    int do_post;
    int quiet;
    int argc;
    char **argv;
    unsigned int ospecs_len;
};

error_t dt_argp_parse_opt(int key, char *arg,struct argp_state *state);

struct argp_option dt_argp_opts[] = {
    { "post",'P',0,0,"Enable post handlers.",0 },
    { "quiet",'q',0,0,"Silent but deadly.",0 },
    { 0,0,0,0,0,0 },
};

struct argp dt_argp = {
    dt_argp_opts,dt_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};

struct dt_argp_state opts;

result_t handler(struct probe *probe,tid_t tid,void *data,
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
    result_t retval = RESULT_SUCCESS;
    char buf[1024];
    struct target *target;

    target = probe_target(probe);

    /* Grab the symbol associated with the probe. */
    bsymbol = probe_symbol(probe);

    /* bsymbols are wrappers for the underlying symbol; get that. */
    symbol = bsymbol_get_symbol(bsymbol);

    /* Get the current value table: the current values for this probe hit. */
    vt = probe_value_get_table(probe,tid);
    if (!vt) {
	vwarn("probe %s: could not get values from probe %s"
	      " (tid %"PRIiTID")!\n",
	      probe_name(probe),probe_name(trigger),tid);
    }

    fflush(stderr);
    fflush(stdout);

    if (symbol_type_flags_match(symbol,SYMBOL_TYPE_FLAG_FUNC))
	fprintf(stdout,"%s (",symbol_get_name(symbol));

    /* Loop through and print the values by stringifying them. */
    if (vt) {
	i = 0;
	g_hash_table_iter_init(&iter,vt);
	while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	    if (strcmp((char *)kp,PROBE_VALUE_NAME_RETURN) == 0)
		continue;
	    if (i > 0)
		fprintf(stdout,",");
	    v = (struct value *)vp;
	    if (v) {
		rc = value_snprintf(v,vstrbuf,sizeof(vstrbuf));
		if (rc > 0)
		    fprintf(stdout,"%s = %s",(char *)kp,vstrbuf);
		else
		    fprintf(stdout,"%s = ?",(char *)kp);
	    }
	    else
		fprintf(stdout,"%s = ?",(char *)kp);
	    ++i;
	}
    }
    else {
	if (symbol_type_flags_match(symbol,SYMBOL_TYPE_FLAG_FUNC))
	    fprintf(stdout,"?");
	else
	    fprintf(stdout," = ?");
    }

    /*
     * Print the return value using the special name, the macro
     * PROBE_VALUE_NAME_RETURN .
     */
    if (symbol_type_flags_match(symbol,SYMBOL_TYPE_FLAG_FUNC)) {
	fprintf(stdout,")");
	if (vt) {
	    v = (struct value *)					\
		g_hash_table_lookup(vt,PROBE_VALUE_NAME_RETURN);
	    if (v) {
		rc = value_snprintf(v,vstrbuf,sizeof(vstrbuf));
		if (rc > 0)
		    fprintf(stdout," = %s",vstrbuf);
		else
		    fprintf(stdout," = ?");
	    }
	}
    }
    fputs(" ",stdout);

    /* Print a dump of the current thread info, like registers. */
    fputs("[",stdout);
    if (target_thread_snprintf(target,tid,buf,sizeof(buf),
			       2,":","=") < 0) 
	fprintf(stdout,"tid=%"PRIiTID"",tid);
    else
	fprintf(stdout,"%s",buf);

    /* Unwind the current thread and print it too. */
    rc = target_unwind_snprintf(buf,sizeof(buf),target,tid,
				TARGET_UNWIND_STYLE_PROG_KEYS,"|",",");
    if (rc < 0)
	fprintf(stdout," backtrace=[error!]");
    else if (rc == 0)
	fprintf(stdout," backtrace=[empty]");
    else
	fprintf(stdout," backtrace=[%s]",buf);

    fprintf(stdout,"]");

    fputs("\n",stdout);
    fflush(stdout);

    /*
     * Return!  Be careful what you return from probe handlers -- some
     * return values will cause the probe to be removed!!!
     */
    return retval;
}

error_t dt_argp_parse_opt(int key, char *arg,struct argp_state *state) {
    struct dt_argp_state *opts = \
	(struct dt_argp_state *)target_argp_driver_state(state);

    switch (key) {
    case ARGP_KEY_ARG:
	/* We want to process all the remaining args, so bounce to the
	 * next case by returning this value.
	 */
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

    case 'P':
	opts->do_post = 1;
	break;
    case 'q':
	opts->quiet = 1;
	break;

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int main(int argc,char **argv) {
    int i;
    struct probe *probe;
    struct target_spec *primary_target_spec = NULL;
    GList *base_target_specs = NULL;
    GList *overlay_target_specs = NULL;
    GList *targets;
    int rc;
    struct evloop *evloop;
    char *name,*rname;
    GList *t1;
    struct target *target;
    struct bsymbol *bsymbol;

    target_init();
    atexit(target_fini);

    memset(&opts,0,sizeof(opts));
    rc = target_argp_driver_parse(&dt_argp,&opts,argc,argv,
				  TARGET_TYPE_PTRACE | TARGET_TYPE_XEN
				      | TARGET_TYPE_GDB,1,
				  &primary_target_spec,&base_target_specs,
				  &overlay_target_specs);

    if (rc) {
	verror("could not parse target arguments!\n");
	exit(-1);
    }

    target_install_default_sighandlers(NULL);

    evloop = evloop_create(NULL);

    targets = target_instantiate_and_open(primary_target_spec,
					  base_target_specs,overlay_target_specs,
					  evloop,NULL);
    if (!targets) {
	verror("could not instantiate and open targets!\n");
	exit(-1);
    }

    /*
     * Look up symbols!
     */
    for (i = 0; i < opts.argc; ++i) {
	name = opts.argv[i];

	rname = index(name,':');
	if (rname) {
	    *rname = '\0';
	    ++rname;
	    target = target_lookup_target_id(atoi(name));
	    if (!target) {
		fprintf(stderr,
			"Could not lookup target %s for symbol %s; aborting!\n",
			name,rname);
		target_default_cleanup();
		exit(-3);
	    }
	    name = rname;
	    bsymbol = target_lookup_sym(target,name,NULL,NULL,
					SYMBOL_TYPE_FLAG_NONE);
	}
	else {
	    v_g_list_foreach(targets,t1,target) {
		bsymbol = target_lookup_sym(target,name,NULL,NULL,
					    SYMBOL_TYPE_FLAG_NONE);
		if (bsymbol)
		    break;
	    }
	}

	if (!bsymbol) {
	    fprintf(stderr,"could not lookup symbol %s; aborting!\n",name);
	    target_default_cleanup();
	    exit(-3);
	}

	/*
	 * Place a value probe on the symbol.  If this is a function,
	 * the value probe will collect the function arguments when the
	 * function is entered; and on return from the function, it will
	 * collect the return value.  You can get all these values,
	 * stringified, in a GHashTable, like we do in our probe handler
	 * above!
	 */
	probe = probe_value_symbol(target,TID_GLOBAL,bsymbol,
				   handler,handler,NULL);
	if (!probe) {
	    fprintf(stderr,"could not place value probe on %s; aborting!\n",
		    name);
	    target_default_cleanup();
	    exit(-3);
	}

	/*
	 * Currently, the target library's symbol wrappers are
	 * reference-counted.  That means you have to release them when
	 * you are done with them.
	 */
	bsymbol_release(bsymbol);
    }

    /* The target is paused after the attach; we have to resume it now
     * that we've registered probes (or hit the at_symbol).
     */
    v_g_list_foreach(targets,t1,target) {
	target_resume(target);
    }

    fprintf(stdout,"Starting main debugging loop!\n");
    fflush(stdout);

    while (1) {
	tid_t tid = 0;
	struct target *t;
	target_status_t tstat;
	char *tname;

	rc = target_monitor_evloop(evloop,NULL,&t,&tstat);

	/* Did we get interrupted safely? */
	if (target_monitor_was_interrupted(NULL))
	    ;
	/* Did we experience an error in select() or in evloop? */
	else if (rc < 0) {
	    fprintf(stderr,"error in target_monitor_evloop (%d): %s;"
		    " attempting to continue!\n",rc,strerror(errno));
	    continue;
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

    printf("Monitoring completed; exiting!\n");

    exit(0);
}
