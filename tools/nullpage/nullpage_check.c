/*
 * Copyright (c) 2014 The University of Utah
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

#include "probe_api.h"
#include "probe.h"
#include "alist.h"
#include "list.h"

#include "nullpage.h"

struct target *target = NULL;
struct probe *np_probe = NULL;
struct np_config npc;

target_status_t cleanup() {
    target_status_t retval = TSTATUS_DONE;

    if (np_probe) {
	probe_free(np_probe,1);
	np_probe = NULL;
    }
    if (target) {
	retval = target_close(target);
	target_finalize(target);
	target = NULL;
    }

    return retval;
}

void sigh(int signo) {
    cleanup();
    exit(0);
}

void print_thread_context(FILE *stream,struct target *target,tid_t tid,
                          int ttctx,int ttdetail,int bt,char *sep,char *kvsep,
                          char *tprefix,char *tsep) {
    struct target_thread *tthread;
    char buf[1024];
    struct array_list *tids;
    int i;
    int rc;

    tthread = target_lookup_thread(target,tid);

    if (ttctx == 0)
        return;
    else if (ttctx == 1) {
        if (target_thread_snprintf(target,tid,buf,sizeof(buf),
                                   ttdetail,sep,kvsep) < 0)
            fprintf(stream,"%s[tid=%"PRIiTID"",tprefix,tid);
        else
            fprintf(stream,"%s[%s",tprefix,buf);
        if (bt) {
            rc = target_unwind_snprintf(buf,sizeof(buf),target,tid,
                                        TARGET_UNWIND_STYLE_PROG_KEYS,"|",",");
            if (rc < 0)
                fprintf(stream,"%sbacktrace=[error!]",sep);
            else if (rc == 0)
                fprintf(stream,"%sbacktrace=[empty]",sep);
            else
                fprintf(stream,"%sbacktrace=[%s]",sep,buf);
        }
        fprintf(stream,"]");
    }
    else if (ttctx == 2) {
        /* Just walk up the parent hierarchy. */
        i = 0;
        do {
            if (likely(i > 0))
                fprintf(stream,"%s",tsep);

            if (target_thread_snprintf(target,tthread->tid,buf,sizeof(buf),
                                       ttdetail,sep,kvsep) < 0)
                fprintf(stream,"%s[tid=%"PRIiTID"",tprefix,tthread->tid);
            else
                fprintf(stream,"%s[%s",tprefix,buf);

            if (bt) {
                rc = target_unwind_snprintf(buf,sizeof(buf),target,tthread->tid,
                                            TARGET_UNWIND_STYLE_PROG_KEYS,"|","\
,");
                if (rc < 0)
		    fprintf(stream,"%sbacktrace=[error!]",sep);
		else if (rc == 0)
		    fprintf(stream,"%sbacktrace=[empty]",sep);
		else
		    fprintf(stream,"%sbacktrace=[%s]",sep,buf);
	    }
	    fprintf(stream,"]");

	    ++i;
	    tthread = target_lookup_thread(target,tthread->ptid);
	}
	while (tthread);
    }
    else if (ttctx == 3) {
        if (target_thread_snprintf(target,tid,buf,sizeof(buf),
                                   ttdetail,sep,kvsep) < 0)
            fprintf(stream,"%s[tid=%"PRIiTID"",tprefix,tid);
        else
            fprintf(stream,"%s[%s",tprefix,buf);

	tids = target_list_available_tids(target);

	if (!tids) {
            fprintf(stream,"]");
            return;
        }

	array_list_foreach(tids,i,tthread) {
            if (tthread->tid == tid)
                continue;

            fprintf(stream,"%s",tsep);

            if (target_thread_snprintf(target,tthread->tid,buf,sizeof(buf),
                                       ttdetail,sep,kvsep) < 0)
                fprintf(stream,"%s[tid=%"PRIiTID"",tprefix,tthread->tid);
            else
                fprintf(stream,"%s[%s",tprefix,buf);

            if (bt) {
                rc = target_unwind_snprintf(buf,sizeof(buf),target,tthread->tid,
                                            TARGET_UNWIND_STYLE_PROG_KEYS,"|","\
,");
                if (rc < 0)
                    fprintf(stream,"%sbacktrace=[error!]",sep);
                else if (rc == 0)
                    fprintf(stream,"%sbacktrace=[empty]",sep);
                else
                    fprintf(stream,"%sbacktrace=[%s]",sep,buf);
            }
            fprintf(stream,"]");
        }
    }
}

result_t np_handler(struct probe *probe,tid_t tid,void *data,
		    struct probe *trigger,struct probe *base) {
    struct np_status *nps = (struct np_status *)probe_priv(probe);

    if (NP_IS_MMAP(trigger,nps)) {
	fprintf(stdout,
		"RESULT:: (i:%d) np (30) NullPageUsageMmap"
		" \"NULL Page Usage (mmap)!\""
		" (mmap_violations=%d,",
		nps->total_violations,nps->mmap_violations);
    }
    else if (NP_IS_MPROTECT(trigger,nps)) {
	fprintf(stdout,
		"RESULT:: (i:%d) np (31) NullPageUsageMprotect"
		" \"NULL Page Usage (mprotect)!\""
		" (mprotect_violations=%d,",
		nps->total_violations,nps->mprotect_violations);
    }
    else if (NP_IS_PGFAULT(trigger,nps)) {
	fprintf(stdout,
		"RESULT:: (i:%d) np (32) NullPageUsagePageFault"
		" \"NULL Page Usage (Page Fault)!\""
		" (mmap_violations=%d,",
		nps->total_violations,nps->pgfault_violations);
    }
    else {
	vwarn("trigger was not valid!? BUG!?\n");
	return 0;
    }

    print_thread_context(stdout,probe->target,tid,
			 nps->config->ttctx,nps->config->ttdetail,
			 1,";",":","thread=",",");
    fputs(") ::RESULT\n",stdout);
    fflush(stdout);

    return 0;
}

void np_check_print_final_results(struct probe *probe) {
    return;
}

int main(int argc,char **argv) {
    target_status_t tstat;
    struct target_spec *tspec;
    char targetstr[128];
    char *endptr = NULL;

    target_init();
    atexit(target_fini);

    memset(&npc,0,sizeof(npc));
    npc.ttctx = 1;
    npc.ttdetail = 0;

    tspec = target_argp_driver_parse(&np_argp,&npc,argc,argv,
				     TARGET_TYPE_XEN | TARGET_TYPE_GDB,1);

    if (!tspec) {
	verror("could not parse target arguments!\n");
	exit(-1);
    }

    target = target_instantiate(tspec,NULL);
    if (!target) {
	verror("could not instantiate target!\n");
	exit(-1);
    }
    target_snprintf(target,targetstr,sizeof(targetstr));

    if (target_open(target)) {
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
    np_probe = probe_np(target,&npc,np_handler,NULL,NULL);
    if (!np_probe) {
	verror("could not instantiate the null page usage meta-probe; aborting!\n");
	cleanup();
	exit(-4);
    }

    /*
     * The target was paused after instantiation; we have to resume it
     * now that we've registered probes.
     */
    target_resume(target);

    fprintf(stdout,"Starting Null Page Usage monitoring!\n");
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
	    if (np_probe) {
		fprintf(stdout,"target %s exiting, printing final results...\n",
			targetstr);

		np_check_print_final_results(np_probe);

		fprintf(stdout,"target %s exiting, removing probes safely...\n",
			targetstr);

		probe_free(np_probe,1);
		np_probe = NULL;
	    }

	    if (target_resume(target)) {
		verror("could not resume target!\n");
		tstat = cleanup();
		exit(-16);
	    }
	}
	else if (tstat == TSTATUS_DONE) {
	    fflush(stderr);
	    fflush(stdout);
	    if (np_probe) {
		fprintf(stdout,"target %s exited, printing final results...\n",
			targetstr);

		np_check_print_final_results(np_probe);

		probe_free(np_probe,1);
		np_probe = NULL;
	    }

	    fprintf(stdout,"target %s exited, cleaning up.\n",targetstr);

	    tstat = cleanup();
	    goto out;
	}
	else {
	    fflush(stderr);
	    fflush(stdout);
	    if (np_probe) {
		fprintf(stdout,
			"target %s interrupted at 0x%"PRIxREGVAL
			" -- bad status (%d), printing final results...\n",
			targetstr,target_read_creg(target,TID_GLOBAL,CREG_IP),
			tstat);

		np_check_print_final_results(np_probe);

		probe_free(np_probe,1);
		np_probe = NULL;
	    }

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
