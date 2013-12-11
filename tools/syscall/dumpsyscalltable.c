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

#include <glib.h>
#include "glib_wrapper.h"

#include "log.h"
#include "alist.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"
#include "target_os.h"

static int cleaning = 0;
struct target *t = NULL;

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

int main(int argc,char **argv) {
    struct target_spec *tspec;
    char *targetstr;
    int i,j;
    int maxnum;
    struct target_os_syscall *sc;
    struct symbol *argsym;
    struct dump_info ud = { .stream = stdout,.prefix = "",.detail = 0,.meta = 0 };
    GSList *gsltmp;

    tspec = target_argp_driver_parse(NULL,NULL,argc,argv,TARGET_TYPE_XEN,1);

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

    maxnum = target_os_syscall_table_get_max_num(t);
    if (maxnum < 0) {
	verror("could not get max number of target syscalls!\n");
	goto exit;
    }

    for (i = 0; i < maxnum; ++i) {
	sc = target_os_syscall_lookup_num(t,i);
	if (!sc)
	    continue;
	if (sc->bsymbol) {
	    printf("%.3d\t%"PRIxADDR"\t%s\t",
		   sc->num,sc->addr,bsymbol_get_name(sc->bsymbol));
	    if (sc->args) {
		printf("(");
		j = 0;
		v_g_slist_foreach(sc->args,gsltmp,argsym) {
		    if (likely(j))
			printf(", ");
		    symbol_type_dump(symbol_get_datatype(argsym),&ud);
		    printf(" %s",symbol_get_name(argsym));
		    ++j;
		}
		printf(")");
	    }
	    printf("\n");
	    if (sc->wrapped_bsymbol) {
		printf("\t\twrapped syscall:\t\t%s",
		       bsymbol_get_name(sc->wrapped_bsymbol));
		GSList *wargs = 
		    symbol_get_members(bsymbol_get_symbol(sc->wrapped_bsymbol),
				       SYMBOL_TYPE_FLAG_VAR_ARG);
		if (wargs) {
		    printf("(");
		    j = 0;
		    v_g_slist_foreach(sc->args,gsltmp,argsym) {
			if (likely(j))
			    printf(", ");
			symbol_type_dump(symbol_get_datatype(argsym),&ud);
			printf(" %s",symbol_get_name(argsym));
			++j;
		    }
		    printf(")");
		}
		printf("\n");
	    }
		
	}
	else {
	    printf("%.3d\t%"PRIxADDR"\n",sc->num,sc->addr);
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
