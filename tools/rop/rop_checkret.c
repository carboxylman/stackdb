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
#include <getopt.h>
#include <errno.h>
#include <string.h>

#include <sys/user.h>
#include <sys/ptrace.h>
#include <inttypes.h>

#include <signal.h>

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

extern char *optarg;
extern int optind, opterr, optopt;

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
	fprintf(stdout,"%s: CFI violation (ROP?!)",probe_name(probe));

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
    fprintf(stdout," (retaddr=0x%"PRIxADDR",violations=%d,total=%d)\n",
	    rop_status->current_ret_addr,rop_status->violations,
	    rop_status->total);

    fflush(stdout);

    return 0;
}

extern char **environ;

int main(int argc,char **argv) {
    int pid = -1;
    int doexe = 0;
    char *exe = NULL;
    char **exeargs = NULL;
    char *exeoutfile = NULL;
    char *exeerrfile = NULL;
#ifdef ENABLE_XENACCESS
    char *domain = NULL;
#endif
    char ch;
    int debug = -1;
    char *optargc;
    target_status_t tstat;
    log_flags_t flags;
    probepoint_style_t style = PROBEPOINT_FASTEST;
    struct debugfile_load_opts **dlo_list = NULL;
    int dlo_idx = 0;
    struct debugfile_load_opts *opts;
    char *filename;
    GHashTableIter iter;
    gpointer key;
    struct rop_gadget *gadget;
    struct probe *probe;
    int i;
    GHashTable *gadgets;

    struct dump_info udn = {
	.stream = stderr,
	.prefix = "",
	.detail = 1,
	.meta = 1,
    };

    /* Find the '--' and save the remaining args so they can be passed
     * to linux_userproc_launch below.  Truncate argc and argv to just
     * include any function/variable breakpoint/watchpoint params, and
     * any other args, to be parsed later.
     */
    for (i = 0; i < argc; ++i) {
	if (!strcmp(argv[i],"--") && (i + 1) < argc) {
	    exe = argv[i + 1];
	    argv[i] = NULL;
	    argc = i;
	    exeargs = &argv[i + 1];
	    break;
	}
    }

    while ((ch = getopt(argc, argv, "m:p:eE:O:dvsl:F:")) != -1) {
	switch (ch) {
	case 'd':
	    ++debug;
	    break;
	case 'p':
	    pid = atoi(optarg);
	    break;
	case 'm':
#ifdef ENABLE_XENACCESS
	    domain = optarg;
#else
	    verror("xen support not compiled on this host!\n");
	    exit(-1);
#endif
	    break;
	case 'e':
	    doexe = 1;
	    break;
	case 'E':
	    exeerrfile = optarg;
	    break;
	case 'O':
	    exeoutfile = optarg;
	    break;
	case 's':
	    style = PROBEPOINT_SW;
	    break;
	case 'l':
	    if (vmi_log_get_flag_mask(optarg,&flags)) {
		fprintf(stderr,"ERROR: bad debug flag in '%s'!\n",optarg);
		exit(-1);
	    }
	    vmi_set_log_flags(flags);
	    break;
	case 'F':
	    optargc = strdup(optarg);

	    opts = debugfile_load_opts_parse(optarg);

	    if (!opts)
		goto dlo_err;

	    dlo_list = realloc(dlo_list,sizeof(opts)*(dlo_idx + 2));
	    dlo_list[dlo_idx] = opts;
	    ++dlo_idx;
	    dlo_list[dlo_idx] = NULL;
	    break;
	dlo_err:
	    fprintf(stderr,"ERROR: bad debugfile_load_opts '%s'!\n",optargc);
	    free(optargc);
	    exit(-1);
	default:
	    fprintf(stderr,"ERROR: unknown option %c!\n",ch);
	    exit(-1);
	}
    }

    argc -= optind;
    argv += optind;

    if (!argc) {
	fprintf(stderr,"ERROR: must supply a gadget file!\n");
	exit(-5);
    }

    filename = argv[0];

    /* XXX check args */

    dwdebug_init();
    atexit(dwdebug_fini);

    vmi_set_log_level(debug);
#if defined(ENABLE_XENACCESS) && defined(XA_DEBUG)
    xa_set_debug_level(debug);
#endif

    if (pid > 0) {
	t = linux_userproc_attach(pid,dlo_list);
	if (!t) {
	    fprintf(stderr,"could not attach to pid %d!\n",pid);
	    exit(-3);
	}
    }
#ifdef ENABLE_XENACCESS
    else if (domain) {
	t = xen_vm_attach(domain,dlo_list);
	if (!t) {
	    fprintf(stderr,"could not attach to domain %s!\n",domain);
	    exit(-3);
	}
    }
#endif
    else if (doexe) {
	if (!exe) {
	    fprintf(stderr,"must supply at least an executable to launch (%d)!\n",i);
	    exit(-1);
	}

	t = linux_userproc_launch(exe,exeargs,environ,0,
				  exeoutfile,exeerrfile,dlo_list);
	if (!t) {
	    fprintf(stderr,"could not launch exe %s!\n",exe);
	    exit(-3);
	}
    }
    else {
	fprintf(stderr,"ERROR: must specify a target!\n");
	exit(-2);
    }

    if (target_open(t)) {
	fprintf(stderr,"could not open target!\n");
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
	probe = probe_rop_checkret(t,gadget,NULL,rop_handler,NULL);
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
	    if (linux_userproc_stopped_by_syscall(t)) {
		target_resume(t);
		continue;
	    }

	    fflush(stderr);
	    fflush(stdout);
	    printf("target interrupted at 0x%" PRIxREGVAL "\n",
		   target_read_reg(t,t->ipregno));

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
		   target_read_reg(t,t->ipregno),tstat);
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
	printf("target finished.\n");
	exit(0);
    }
    else if (tstat == TSTATUS_ERROR) {
	printf("domain %s monitoring failed!\n",domain);
	exit(-9);
    }
    else {
	printf("domain %s monitoring failed with %d!\n",domain,tstat);
	exit(-10);
    }
}
