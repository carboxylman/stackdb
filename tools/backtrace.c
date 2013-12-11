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

struct dt_argp_state {
    int loopint;
};

struct dt_argp_state opts;

static int cleaning = 0;

struct target *t = NULL;
target_status_t tstat;

void cleanup() {
    if (cleaning)
	return;

    cleaning = 1;
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
    char *targetstr;
    struct target_location_ctxt *tlctxt;
    struct target_location_ctxt_frame *tlctxtf;
    struct array_list *tids;
    tid_t tid;
    int i,j,k;
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

    fprintf(stdout,"Initial threads:\n");
    fflush(stderr);
    fflush(stdout);
    target_load_available_threads(t,1);
    target_dump_all_threads(t,stdout,0);
    fflush(stderr);
    fflush(stdout);

    ipreg = target_dw_reg_no(t,CREG_IP);

    tids = target_list_tids(t);
    array_list_foreach_fakeptr_t(tids,i,tid,uintptr_t) {
	if (opts.tid > 0 && tid != opts.tid)
	    continue;

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

    fflush(stderr);
    fflush(stdout);
    cleanup();
    fflush(stderr);
    fflush(stdout);

    printf("%s finished.\n",targetstr);
    exit(0);
}
