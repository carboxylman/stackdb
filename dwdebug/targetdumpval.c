#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>

#include <sys/user.h>
#include <sys/ptrace.h>
#include <inttypes.h>

#include <signal.h>

#include "libdwdebug.h"

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
    struct symbol **symbols = NULL;
    struct symbol_chain **symbolchains = NULL;
    struct memregion **regions = NULL;
    char *word;
    int i, j;
    char *idx;
    struct symbol *ms;
    struct user_regs_struct regs;
    int ssize;

    struct dump_info udn = {
	.stream = stderr,
	.prefix = "",
	.detail = 1,
	.meta = 1,
    };

    while ((ch = getopt(argc, argv, "p:e:dvs")) != -1) {
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
	default:
	    fprintf(stderr,"ERROR: unknown option %c!\n",ch);
	    exit(-1);
	}
    }

    argc -= optind;
    argv += optind;

    libdwdebug_init();
    libdwdebug_set_debug_level(debug);

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
	    symbols = (struct symbol **)malloc(sizeof(struct symbol *)*argc);
	    memset(symbols,0,sizeof(struct symbol *)*argc);
	    symbolchains = (struct symbol_chain **)malloc(sizeof(struct symbol_chain *)*argc);
	    memset(symbolchains,0,sizeof(struct symbol_chain *)*argc);
	    regions = (struct memregion **)malloc(sizeof(struct memregion *)*argc);
	    memset(regions,0,sizeof(struct memregion *)*argc);
	}

	for (i = 0; i < argc; ++i) {
	    if (raw) {
		addrs[i] = strtoll(argv[i],NULL,16);
		word = malloc(t->wordsize);
	    }
	    else {
		idx = index(argv[i],'.');
		if (idx) {
		    symbolchains[i] = target_lookup_nested_sym(t,argv[i],".",NULL,
							       SYMBOL_TYPE_FLAG_NONE,
							       &regions[i]);
		}
		else {
		    symbols[i] = target_lookup_sym(t,argv[i],NULL,
						   SYMBOL_TYPE_FLAG_NONE,
						   &regions[i]);
		}

		if (!symbols[i] && !symbolchains[i]) {
		    fprintf(stderr,"Could not find symbol %s!\n",argv[i]);
		    target_close(t);
		    exit(-1);
		}
		else if (symbols[i])
		    symbol_dump(symbols[i],&udn);
		else 
		    symbol_chain_dump(symbolchains[i],&udn);
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
		    if (symbols[i]) {
			if (!symbol_load(regions[i],symbols[i],
					 LOAD_FLAG_AUTO_DEREF | 
					 LOAD_FLAG_CHAR_PTR_AS_STR,
					 (void **)&word,&ssize)) {
			    if (1) {
				printf("%s = ",symbols[i]->name);
				symbol_rvalue_print(stdout,regions[i],symbols[i],
						    word,ssize,
						    LOAD_FLAG_AUTO_DEREF |
						    LOAD_FLAG_CHAR_PTR_AS_STR);
			    }
			    else {
				printf("%s = ",symbols[i]->name);
				for (j = 0; j < ssize; ++j) {
				    printf("%02hhx",word[j]);
				}
			    }
			    printf("\n");
			    free(word);
			}
			else
			    printf("%s: could not read value: %s\n",
				   symbols[i]->name,strerror(errno));
		    }
		    else {
			struct symbol *real = symbolchains[i]->chain[symbolchains[i]->count - 1];
			if (!symbol_nested_load(regions[i],symbolchains[i],
						LOAD_FLAG_NONE,
						(void **)&word,&ssize)) {
			    if (1) {
				printf("%s = ",real->name);
				symbol_rvalue_print(stdout,regions[i],real,
						    word,ssize,
						    LOAD_FLAG_AUTO_DEREF |
						    LOAD_FLAG_CHAR_PTR_AS_STR);
			    }
			    else {
				printf("%s = ",real->name);
				for (j = 0; j < ssize; ++j) {
				    printf("%02hhx",word[j]);
				}
			    }
			    printf("\n");
			    free(word);
			}
			else
			    printf("%s: could not read value: %s\n",
				   real->name,strerror(errno));
		    }
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
