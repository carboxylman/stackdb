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

struct overlay_spec {
    char *base_target_id;
    char *base_thread_name_or_id;
    struct target_spec *spec;
};

struct bt_argp_state {
    int loopint;
    tid_t tid;
    int argc;
    char **argv;
    int ospecs_len;
    struct overlay_spec **ospecs;
};

struct bt_argp_state opts;
struct target_spec *tspec = NULL;
struct target *t = NULL;
int ots_len = 0;
struct target **ots = NULL;
char **otnames = NULL;

void cleanup_probes() {
    return;
}

void cleanup() {
    static int cleaning = 0;

    int j;

    if (cleaning)
	return;
    cleaning = 1;

    cleanup_probes();

    if (ots) {
	for (j = ots_len - 1; j >= 0; --j) {
	    if (!ots[j])
		continue;
	    target_close(ots[j]);
	    target_free(ots[j]);
	    ots[j] = NULL;
	}
    }

    target_close(t);
    target_free(t);

    target_free_spec(tspec);

    if (opts.argv)
	free(opts.argv);
}

void sigh(int signo) {
    if (t) {
	target_pause(t);
	cleanup();
    }

    exit(0);
}

void siga(int signo) {
    target_pause(t);
    fprintf(stdout,"Current threads:\n");
    target_load_available_threads(t,1);
    target_dump_all_threads(t,stdout,0);
    target_resume(t);

    alarm(opts.loopint);
}

#define __TARGET_OVERLAY      0x200000

struct argp_option bt_argp_opts[] = {
    //{ "loop-interval",'i',"INTERVAL",0,"Loop infinitely using the given interval.",0 },
    { "overlay",__TARGET_OVERLAY,"[<target_id>:]<thread_name_or_id>:<spec_opts>",0,"Lookup name or id as an overlay target once the main target is instantiated, and try to open it.  All dumptarget options then apply to the overlay.",0 },
    { "thid",'T',"Thread id",0,"Only print stacks for thread id.",0 },
    { 0,0,0,0,0,0 },
};

error_t bt_argp_parse_opt(int key, char *arg,struct argp_state *state) {
    struct bt_argp_state *opts = \
	(struct bt_argp_state *)target_argp_driver_state(state);
    struct array_list *argv_list;
    char *argptr,*argptr2;
    char *nargptr;
    char *vargptr;
    int inesc;
    int inquote;
    int quotechar;
    struct overlay_spec *ospec = NULL;

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

	/*
    case 'i':
	opts->loopint = atoi(arg);
	break;
	*/
    case 'T':
	opts->tid = atoi(arg);
	break;
    case __TARGET_OVERLAY:
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

	ospec = calloc(1,sizeof(*ospec));
	++opts->ospecs_len;
	opts->ospecs = 
	    realloc(opts->ospecs,opts->ospecs_len*sizeof(*opts->ospecs));
	opts->ospecs[opts->ospecs_len - 1] = ospec;

	argv_list = array_list_create(32);
	array_list_append(argv_list,"dumptarget_overlay");

	ospec->base_thread_name_or_id = arg;
	*argptr = '\0';
	++argptr;

	argptr2 = index(argptr,':');
	if (argptr2) {
	    ospec->base_target_id = ospec->base_thread_name_or_id;
	    ospec->base_thread_name_or_id = argptr;
	    *argptr2 = '\0';
	    argptr = ++argptr2;
	}

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

	ospec->spec = target_argp_driver_parse(NULL,NULL,
					       array_list_len(argv_list) - 1,
					       (char **)argv_list->list,
					       TARGET_TYPE_XEN_PROCESS,0);
	if (!ospec->spec) {
	    verror("could not parse overlay spec %d!\n",opts->ospecs_len);
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

struct argp bt_argp = {
    bt_argp_opts,bt_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};

int main(int argc,char **argv) {
    char *targetstr;
    struct target_location_ctxt *tlctxt;
    struct target_location_ctxt_frame *tlctxtf;
    struct array_list *tids;
    tid_t tid;
    int i,j,k,lpc;
    REG ipreg;
    REGVAL ipval;
    char *srcfile = NULL;
    int srcline;
    GSList *args;
    GSList *gsltmp;
    struct symbol *argsym;
    char *name;
    struct value *v;
    char vbuf[1024];
    char *tmp;
    int oid;
    tid_t base_tid;
    struct target *base;
    struct overlay_spec *ospec;
    char namebuf[64];
    struct lsymbol *lsymbol;
    struct bsymbol *bsymbol;
    struct target *ot;

    memset(&opts,0,sizeof(opts));

    tspec = target_argp_driver_parse(&bt_argp,&opts,argc,argv,
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

    /*
     * Load the overlay targets, if any.
     */
    if (opts.ospecs) {
	ots = calloc(opts.ospecs_len,sizeof(*ots));
	otnames = calloc(opts.ospecs_len,sizeof(*otnames));
    }
    for (j = 0; j < opts.ospecs_len; ++j) {
	errno = 0;
	tmp = NULL;
	ospec = opts.ospecs[j];

	if (ospec->base_target_id) {
	    base = target_lookup_target_id(atoi(ospec->base_target_id));
	    if (!base) {
		verror("no existing target with id '%s'!\n",
		       ospec->base_target_id);
		cleanup();
		exit(-113);
	    }
	}
	else 
	    base = t;

	target_snprintf(base,namebuf,sizeof(namebuf));
	otnames[j] = strdup(namebuf);

	oid = (int)strtol(ospec->base_thread_name_or_id,&tmp,0);
	if (errno || tmp == ospec->base_thread_name_or_id)
	    base_tid = 
		target_lookup_overlay_thread_by_name(base,ospec->base_thread_name_or_id);
	else
	    base_tid = target_lookup_overlay_thread_by_id(base,oid);
	if (base_tid < 0) {
	    verror("could not find overlay thread '%s' in base target '%s',"
		   " exiting!\n",
		   ospec->base_thread_name_or_id,namebuf);
	    cleanup();
	    exit(-111);
	}

	ots[j] = target_instantiate_overlay(base,base_tid,ospec->spec);
	++ots_len;
	if (!ots[j]) {
	    verror("could not instantiate overlay on base '%s' thread '%s'!\n",
		   namebuf,ospec->base_thread_name_or_id);
	    cleanup();
	    exit(-112);
	}

	if (target_open(ots[j])) {
	    fprintf(stderr,"could not open overlay on base '%s' thread '%s'!\n",
		    namebuf,ospec->base_thread_name_or_id);
	    cleanup();
	    exit(-114);
	}
    }

    fprintf(stdout,"Initial threads in target '%s':\n",targetstr);
    fflush(stderr);
    fflush(stdout);
    target_load_available_threads(t,1);
    target_dump_all_threads(t,stdout,1);
    fflush(stderr);
    fflush(stdout);

    ipreg = target_dw_reg_no(t,CREG_IP);

    tids = target_list_tids(t);
    array_list_foreach_fakeptr_t(tids,i,tid,uintptr_t) {
	tlctxt = target_unwind(t,tid);
	if (!tlctxt) {
	    fprintf(stdout,"\nthread %"PRIiTID": NOTHING\n",tid);
	    continue;
	}

	fprintf(stdout,"\nthread %"PRIiTID":\n",tid);

	j = 0;
	while (1) {
	    tlctxtf = target_location_ctxt_current_frame(tlctxt);
	    ipval = 0;
	    target_location_ctxt_read_reg(tlctxt,ipreg,&ipval);
	    if (tlctxtf->bsymbol)
		srcfile = symbol_get_srcfile(bsymbol_get_symbol(tlctxtf->bsymbol));
	    else
		srcfile = NULL;
	    if (tlctxtf->bsymbol)
		srcline = target_lookup_line_addr(t,srcfile,ipval);
	    else
		srcline = 0;

	    fprintf(stdout,"  #%d  0x%"PRIxFULLADDR" in %s (",
		    j,ipval,(tlctxtf->bsymbol) ? bsymbol_get_name(tlctxtf->bsymbol) : "");
	    if (tlctxtf->bsymbol) {
		args = symbol_get_ordered_members(bsymbol_get_symbol(tlctxtf->bsymbol),
						  SYMBOL_TYPE_FLAG_VAR_ARG);
		v_g_slist_foreach(args,gsltmp,argsym) {
		    lsymbol = lsymbol_create_from_member(bsymbol_get_lsymbol(tlctxtf->bsymbol),
							 argsym);
		    bsymbol = bsymbol_create(lsymbol,tlctxtf->bsymbol->region);
		    name = symbol_get_name(argsym);

		    v = target_load_symbol(t,tlctxt,bsymbol,
					   //LOAD_FLAG_AUTO_DEREF | 
					   LOAD_FLAG_AUTO_STRING);
		    printf("%s=",name ? name : "()");
		    if (v) {
			//vbuf[0] = '\0';
			if (value_snprintf(v,vbuf,sizeof(vbuf)) < 0)
			    printf("<value_snprintf error>");
			else
			    printf("%s",vbuf);
			printf(" (0x");
			for (k = 0; k < v->bufsiz; ++k) {
			    printf("%02hhx",v->buf[k]);
			}
			printf(")");
			value_free(v);
		    }
		    else
			printf("<?>");
		    printf(",");

		    bsymbol_release(bsymbol);
		    lsymbol_release(lsymbol);
		}
		fprintf(stdout,") at %s:%d\n",srcfile,srcline);
	    }
	    else
		fprintf(stdout,")\n");
		fflush(stdout);
	    fflush(stderr);

	    tlctxtf = target_location_ctxt_prev(tlctxt);
	    if (!tlctxtf)
		break;
	    ++j;
	}
	target_location_ctxt_free(tlctxt);
    }

    for (lpc = 0; lpc < opts.ospecs_len; ++lpc) {
	ot = ots[lpc];

	fprintf(stdout,"\nInitial threads in target '%s':\n",otnames[lpc]);
	fflush(stderr);
	fflush(stdout);
	target_load_available_threads(ot,1);
	target_dump_all_threads(ot,stdout,0);
	fflush(stderr);
	fflush(stdout);

	ipreg = target_dw_reg_no(ot,CREG_IP);

	tids = target_list_tids(ot);
	array_list_foreach_fakeptr_t(tids,i,tid,uintptr_t) {
	if (opts.tid > 0 && tid != opts.tid)
	    continue;

	    tlctxt = target_unwind(ot,tid);
	    fprintf(stdout,"\nthread %"PRIiTID":\n",tid);
	    j = 0;
	    while (1) {
		tlctxtf = target_location_ctxt_current_frame(tlctxt);
		ipval = 0;
		target_location_ctxt_read_reg(tlctxt,ipreg,&ipval);
		srcfile = symbol_get_srcfile(bsymbol_get_symbol(tlctxtf->bsymbol));
		srcline = target_lookup_line_addr(ot,srcfile,ipval);
		fprintf(stdout,"  #%d  0x%"PRIxFULLADDR" in %s (",
			j,ipval,bsymbol_get_name(tlctxtf->bsymbol));
		args = symbol_get_ordered_members(bsymbol_get_symbol(tlctxtf->bsymbol),
						  SYMBOL_TYPE_FLAG_VAR_ARG);
		v_g_slist_foreach(args,gsltmp,argsym) {
		    lsymbol = lsymbol_create_from_member(bsymbol_get_lsymbol(tlctxtf->bsymbol),
							 argsym);
		    bsymbol = bsymbol_create(lsymbol,tlctxtf->bsymbol->region);
		    name = symbol_get_name(argsym);

		    v = target_load_symbol(ot,tlctxt,bsymbol,
					   //LOAD_FLAG_AUTO_DEREF | 
					   LOAD_FLAG_AUTO_STRING);
		    printf("%s=",name ? name : "()");
		    if (v) {
			//vbuf[0] = '\0';
			if (value_snprintf(v,vbuf,sizeof(vbuf)) < 0)
			    printf("<value_snprintf error>");
			else
			    printf("%s",vbuf);
			printf(" (0x");
			for (k = 0; k < v->bufsiz; ++k) {
			    printf("%02hhx",v->buf[k]);
			}
			printf(")");
			value_free(v);
		    }
		    else
			printf("<?>");
		    printf(",");

		    bsymbol_release(bsymbol);
		    lsymbol_release(lsymbol);
		}
		fprintf(stdout,") at %s:%d\n",srcfile,srcline);
		fflush(stdout);
		fflush(stderr);
		tlctxtf = target_location_ctxt_prev(tlctxt);
		if (!tlctxtf)
		    break;
		++j;
	    }
	    target_location_ctxt_free(tlctxt);
	}
    }

    fflush(stderr);
    fflush(stdout);
    cleanup();
    fflush(stderr);
    fflush(stdout);

    printf("%s finished.\n",targetstr);
    exit(0);
}
