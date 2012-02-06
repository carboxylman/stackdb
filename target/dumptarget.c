/*
 * Copyright (c) 2011, 2012 The University of Utah
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
 * Foundation, 51 Franklin St, Suite 500, Boston, MA 02110-1335, USA.
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

#include "probe_api.h"
#include "probe.h"

extern char *optarg;
extern int optind, opterr, optopt;

struct target *t = NULL;

int len = 0;
struct bsymbol **symbols = NULL;
struct probe **probes = NULL;

void sigh(int signo) {
    int i;

    if (t) {
	target_pause(t);
	fprintf(stderr,"Ending trace.\n");
	for (i = 0; i < len; ++i) {
	    if (probes[i])
		probe_unregister(probes[i],1);
	}
	target_close(t);
	fprintf(stderr,"Ended trace.\n");
    }

    exit(0);
}

int function_dump_args(struct probe *probe) {
    struct value *value;
    int i;
    int j;

    for (i = 0; i < len; ++i) 
	if (probes[i] == probe)
	    break;

    if (i == len) {
	fprintf(stderr,"Could not find our probe/symbol index!\n");
	return 0;
    }

    fprintf(stderr,"%s (0x%"PRIxADDR")\n",symbols[i]->lsymbol->symbol->name,
	    probe->probepoint->addr);

    /* Make a chain with room for one more -- the
     * one more is each arg we're going to process.
     */
    struct symbol *tsym;
    struct array_list *tmp;
    if (!symbols[i]->lsymbol->chain
	|| array_list_len(symbols[i]->lsymbol->chain) == 0) {
	tmp = array_list_clone(symbols[i]->lsymbol->chain,2);
	array_list_add(tmp,symbols[i]->lsymbol->symbol);
    }
    else
	tmp = array_list_clone(symbols[i]->lsymbol->chain,1);
    int len = tmp->len;

    struct lsymbol tlsym = {
	.chain = tmp,
    };
    struct bsymbol tbsym = {
	.lsymbol = &tlsym,
	.region = symbols[i]->region,
    };

    ++tmp->len;
    list_for_each_entry(tsym,&symbols[i]->lsymbol->symbol->s.ii.d.f.args,member) {
	array_list_item_set(tmp,len,tsym);
	tlsym.symbol = tsym;

	if ((value = bsymbol_load(&tbsym,
				  LOAD_FLAG_AUTO_DEREF | 
				  LOAD_FLAG_AUTO_STRING |
				  LOAD_FLAG_NO_CHECK_VISIBILITY |
				  LOAD_FLAG_NO_CHECK_BOUNDS))) {
	    printf("%s = ",tsym->name);
	    symbol_rvalue_print(stdout,tsym,value->buf,value->bufsiz,
				LOAD_FLAG_AUTO_DEREF |
				LOAD_FLAG_AUTO_STRING |
				LOAD_FLAG_NO_CHECK_VISIBILITY |
				LOAD_FLAG_NO_CHECK_BOUNDS,
				t);
	    printf(" (0x");
	    for (j = 0; j < value->bufsiz; ++j) {
		printf("%02hhx",value->buf[j]);
	    }
	    printf(")");
	    value_free(value);
	}
	printf(", ");
    }
    printf("\n");

    array_list_free(tmp);

    return 0;
}

int main(int argc,char **argv) {
    int pid = -1;
    char *exe = NULL;
    char ch;
    int debug = 0;
    target_status_t tstat;
    int raw = 0;
    ADDR *addrs = NULL;
    char *word;
    int i, j;
    struct user_regs_struct regs;
    int ssize;
    log_flags_t flags;
    probepoint_type_t ptype = PROBEPOINT_FASTEST;

    struct dump_info udn = {
	.stream = stderr,
	.prefix = "",
	.detail = 1,
	.meta = 1,
    };

    while ((ch = getopt(argc, argv, "p:e:dvsl:")) != -1) {
	switch(ch) {
	case 'd':
	    ++debug;
	    break;
	case 'p':
	    pid = atoi(optarg);
	    break;
	case 'e':
	    exe = optarg;
	    break;
	case 'v':
	    raw = 1;
	    break;
	case 's':
	    ptype = PROBEPOINT_SW;
	    break;
	case 'l':
	    if (vmi_log_get_flag_mask(optarg,&flags)) {
		fprintf(stderr,"ERROR: bad debug flag in '%s'!\n",optarg);
		exit(-1);
	    }
	    vmi_set_log_flags(flags);
	    break;
	default:
	    fprintf(stderr,"ERROR: unknown option %c!\n",ch);
	    exit(-1);
	}
    }

    argc -= optind;
    argv += optind;

    dwdebug_init();
    vmi_set_log_level(debug);

    if ((pid == -1 && exe == NULL)
	|| (pid != -1 && exe != NULL)) {
	fprintf(stderr,"ERROR: must specify either '-p <pid>' or '-e /path/to/executable!\n");
	exit(-2);
    }

    if (pid > 0) {
	t = linux_userproc_attach(pid);
	if (!t) {
	    fprintf(stderr,"could not attach to pid %d!\n",pid);
	    exit(-3);
	}
    }
    else {
	t = linux_userproc_launch(exe,NULL,NULL);
	if (!t) {
	    fprintf(stderr,"could not launch exe %s!\n",exe);
	    exit(-3);
	}
    }
    if (target_open(t)) {
	fprintf(stderr,"could not open pid %d!\n",pid);
	exit(-4);
    }

    /* Now that we have loaded any symbols we might need, process the
     * rest of our args.
     */
    if (argc) {
	len = argc;
	if (raw) {
	    addrs = (ADDR *)malloc(sizeof(ADDR)*argc);
	    memset(addrs,0,sizeof(ADDR)*argc);
	}
	else {
	    symbols = (struct bsymbol **)malloc(sizeof(struct bsymbol *)*argc);
	    memset(symbols,0,sizeof(struct bsymbol *)*argc);
	    probes = (struct probe **)malloc(sizeof(struct probe *)*argc);
	    memset(probes,0,sizeof(struct probe *)*argc);
	}
    }

    for (i = 0; i < argc; ++i) {
	if (raw) {
	    addrs[i] = strtoll(argv[i],NULL,16);
	    word = malloc(t->wordsize);
	}
	else {
	    if (!(symbols[i] = target_lookup_sym(t,argv[i],".",NULL,
						 SYMBOL_TYPE_FLAG_NONE))) {
		fprintf(stderr,"Could not find symbol %s!\n",argv[i]);
		target_close(t);
		exit(-1);
	    }

	    bsymbol_dump(symbols[i],&udn);

	    if (SYMBOL_IS_FUNCTION(symbols[i]->lsymbol->symbol)) {
		/* Try to insert a breakpoint, fastest possible! */
		ADDR probeaddr;
		struct memrange *range;
		if ((range = location_resolve_function_entry(t,symbols[i],
							     &probeaddr))) {
		    fprintf(stderr,"Could not resolve entry PC for function %s!\n",
			    symbols[i]->lsymbol->symbol->name);
		    exit(-1);
		}
		
		probes[i] = probe_register_break(t,probeaddr,ptype,
						 function_dump_args,NULL,
						 symbols[i]->lsymbol,probeaddr,
						 range);
		
		if (probes[i])
		    fprintf(stderr,"Registered probe for %s at 0x%"PRIxADDR".\n",
			    symbols[i]->lsymbol->symbol->name,probeaddr);
		else {
		    fprintf(stderr,"Failed to register probe for %s at 0x%"PRIxADDR".\n",
			    symbols[i]->lsymbol->symbol->name,probeaddr);
		    --i;
		    for ( ; i >= 0; --i) {
			if (probes[i]) {
			    probe_unregister(probes[i],1);
			}
		    }
		    exit(-1);
		}
	    }
	}
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

    /* The target is paused after the attach; we have to resume it now
     * that we've registered probes.
     */
    target_resume(t);

    fprintf(stdout,"Starting main debugging loop!\n");
    fflush(stdout);

    while (1) {
	tstat = target_monitor(t);
	if (tstat == STATUS_PAUSED) {
	    if (linux_userproc_stopped_by_syscall(t)) 
		goto resume;

	    ptrace(PTRACE_GETREGS,pid,NULL,&regs);
	    printf("pid %d interrupted at 0x%" PRIx64 "\n",pid,regs.rip);

	    goto resume;

	    if (argc && raw) {
		for (i = 0; i < argc; ++i) {
		    if (target_read_addr(t,addrs[i],t->wordsize,
					 (unsigned char *)word) != NULL) {
			printf("0x%08" PRIx64 " = ",addrs[i]);
			for (j = 0; j < t->wordsize; ++j) {
			    printf("%02hhx",word[j]);
			}
			printf("\n");
		    }
		    else
			printf("0x%08" PRIx64 ": could not read value: %s\n",
			       addrs[i],strerror(errno));
		}
	    }
	    else if (argc && !raw) {
		for (i = 0; i < argc; ++i) {
		    //ssize = symbol_get_bytesize(symbols[i]->datatype);
		    //word = malloc(ssize);
		    word = NULL;
		    struct value *value;
		    if (SYMBOL_IS_VAR(symbols[i]->lsymbol->symbol)) {
			if ((value = bsymbol_load(symbols[i],
						  LOAD_FLAG_AUTO_DEREF | 
						  LOAD_FLAG_AUTO_STRING |
						  LOAD_FLAG_NO_CHECK_VISIBILITY |
						  LOAD_FLAG_NO_CHECK_BOUNDS))) {
			    if (1) {
				printf("%s = ",symbols[i]->lsymbol->symbol->name);
				symbol_rvalue_print(stdout,
						    symbols[i]->lsymbol->symbol,
						    value->buf,value->bufsiz,
						    LOAD_FLAG_AUTO_DEREF |
						    LOAD_FLAG_AUTO_STRING |
						    LOAD_FLAG_NO_CHECK_VISIBILITY |
						    LOAD_FLAG_NO_CHECK_BOUNDS,
						    t);
			    }
			    else {
				printf("%s = ",symbols[i]->lsymbol->symbol->name);
				for (j = 0; j < ssize; ++j) {
				    printf("%02hhx",word[j]);
				}
			    }
			    printf("\n");
			    value_free(value);
			}
		    }
		    else if (SYMBOL_IS_FUNCTION(symbols[i]->lsymbol->symbol)) {
			;
		    }
		    else
			printf("%s: could not read value: %s\n",
			       symbols[i]->lsymbol->symbol->name,strerror(errno));
		    fflush(stdout);
		}
	    }

	resume:
	    if (target_resume(t)) {
		fprintf(stderr,"could not resume target pid %d\n",pid);
		target_close(t);
		exit(-16);
	    }
	}
	else {
	    target_close(t);
	    if (tstat == STATUS_DONE)  {
		printf("pid %d finished.\n",pid);
		break;
	    }
	    else if (tstat == STATUS_ERROR) {
		printf("pid %d monitoring failed!\n",pid);
		return -9;
	    }
	    else {
		printf("pid %d monitoring failed with %d!\n",pid,tstat);
		return -10;
	    }
	}
    }

    return 0;
}
