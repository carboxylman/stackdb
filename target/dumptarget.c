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

extern char *optarg;
extern int optind, opterr, optopt;

struct target *t = NULL;

void sigh(int signo) {
    if (t) {
	target_close(t);
	fprintf(stderr,"Ending trace.\n");
    }
    exit(0);
}

int main(int argc,char **argv) {
    int pid = -1;
    char *exe = NULL;
    char ch;
    int debug = 0;
    target_status_t tstat;
    int raw = 0;
    ADDR *addrs = NULL;
    struct bsymbol **symbols = NULL;
    char *word;
    int i, j;
    struct user_regs_struct regs;
    int ssize;
    log_flags_t flags;

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
	    raw = 0;
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
	if (raw) {
	    addrs = (ADDR *)malloc(sizeof(ADDR)*argc);
	    memset(addrs,0,sizeof(ADDR)*argc);
	}
	else {
	    symbols = (struct bsymbol **)malloc(sizeof(struct bsymbol *)*argc);
	    memset(symbols,0,sizeof(struct bsymbol *)*argc);
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

    while (1) {
	tstat = target_monitor(t);
	if (tstat == STATUS_PAUSED) {
	    if (linux_userproc_stopped_by_syscall(t)) 
		goto resume;

	    ptrace(PTRACE_GETREGS,pid,NULL,&regs);
	    printf("pid %d interrupted at 0x%" PRIx64 "\n",pid,regs.rip);

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
		    else
			printf("%s: could not read value: %s\n",
			       symbols[i]->lsymbol->symbol->name,strerror(errno));
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
