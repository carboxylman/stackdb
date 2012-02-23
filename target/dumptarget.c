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
#ifdef ENABLE_XENACCESS
#include "target_xen_vm.h"
#endif

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

    fflush(stderr);
    fflush(stdout);

    fprintf(stdout,"%s (0x%"PRIxADDR")\n  ",symbols[i]->lsymbol->symbol->name,
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
    list_for_each_entry(tsym,&symbols[i]->lsymbol->symbol->s.ii.d.f.args,
			member) {
	fflush(stderr);
	fflush(stdout);
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

    fflush(stdout);

    array_list_free(tmp);

    return 0;
}

int function_post(struct probe *probe) {
    int i;

    for (i = 0; i < len; ++i) 
	if (probes[i] == probe)
	    break;

    if (i == len) {
	fprintf(stderr,"Could not find our probe/symbol index!\n");
	return 0;
    }

    fflush(stderr);

    fprintf(stdout,"%s (0x%"PRIxADDR") post handler\n",
	    symbols[i]->lsymbol->symbol->name,probe->probepoint->addr);

    fflush(stdout);

    return 0;
}

int var_pre(struct probe *probe) {
    int i,j;
    struct value *value;

    for (i = 0; i < len; ++i) 
	if (probes[i] == probe)
	    break;

    if (i == len) {
	fprintf(stderr,"Could not find our probe/symbol index!\n");
	return 0;
    }

    fflush(stderr);

    if ((value = bsymbol_load(symbols[i],
			      LOAD_FLAG_AUTO_DEREF | 
			      LOAD_FLAG_AUTO_STRING |
			      LOAD_FLAG_NO_CHECK_VISIBILITY |
			      LOAD_FLAG_NO_CHECK_BOUNDS))) {
	fprintf(stdout,"%s (0x%"PRIxADDR") (pre) = ",
		symbols[i]->lsymbol->symbol->name,probe->probepoint->addr);

	symbol_rvalue_print(stdout,symbols[i]->lsymbol->symbol,
			    value->buf,value->bufsiz,
			    LOAD_FLAG_AUTO_DEREF |
			    LOAD_FLAG_AUTO_STRING |
			    LOAD_FLAG_NO_CHECK_VISIBILITY |
			    LOAD_FLAG_NO_CHECK_BOUNDS,
			    t);
	printf(" (0x");
	for (j = 0; j < value->bufsiz; ++j) {
	    printf("%02hhx",value->buf[j]);
	}
	printf(")\n");
	value_free(value);
    }
    else
	fprintf(stdout,"%s (0x%"PRIxADDR") (pre): could not read value: %s\n",
		symbols[i]->lsymbol->symbol->name,probe->probepoint->addr,
		strerror(errno));

    fflush(stdout);

    return 0;
}

int var_post(struct probe *probe) {
    int i,j;
    struct value *value;

    for (i = 0; i < len; ++i) 
	if (probes[i] == probe)
	    break;

    if (i == len) {
	fprintf(stderr,"Could not find our probe/symbol index!\n");
	return 0;
    }

    fflush(stderr);

    if ((value = bsymbol_load(symbols[i],
			      LOAD_FLAG_AUTO_DEREF | 
			      LOAD_FLAG_AUTO_STRING |
			      LOAD_FLAG_NO_CHECK_VISIBILITY |
			      LOAD_FLAG_NO_CHECK_BOUNDS))) {
	fprintf(stdout,"%s (0x%"PRIxADDR") (post) = ",
		symbols[i]->lsymbol->symbol->name,probe->probepoint->addr);

	symbol_rvalue_print(stdout,symbols[i]->lsymbol->symbol,
			    value->buf,value->bufsiz,
			    LOAD_FLAG_AUTO_DEREF |
			    LOAD_FLAG_AUTO_STRING |
			    LOAD_FLAG_NO_CHECK_VISIBILITY |
			    LOAD_FLAG_NO_CHECK_BOUNDS,
			    t);
	printf(" (0x");
	for (j = 0; j < value->bufsiz; ++j) {
	    printf("%02hhx",value->buf[j]);
	}
	printf(")\n");
	value_free(value);
    }
    else
	fprintf(stdout,"%s (0x%"PRIxADDR") (pre): could not read value: %s\n",
		symbols[i]->lsymbol->symbol->name,probe->probepoint->addr,
		strerror(errno));

    fflush(stdout);

    return 0;
}
    

int main(int argc,char **argv) {
    int pid = -1;
    char *exe = NULL;
#ifdef ENABLE_XENACCESS
    char *domain = NULL;
#endif
    char ch;
    int debug = -1;
    target_status_t tstat;
    int raw = 0;
    ADDR *addrs = NULL;
    char *word;
    int i, j;
    struct user_regs_struct regs;
    int ssize;
    log_flags_t flags;
    probepoint_type_t ptype = PROBEPOINT_FASTEST;
    int do_post = 1;
    int offset = 0;
    int upg = 1;

    struct dump_info udn = {
	.stream = stderr,
	.prefix = "",
	.detail = 1,
	.meta = 1,
    };

    while ((ch = getopt(argc, argv, "m:p:e:dvsl:Po:U")) != -1) {
	switch(ch) {
	case 'U':
	    /* Don't use auto prologue guess. */
	    upg = 0;
	    break;
	case 'o':
	    offset = atoi(optarg);
	    break;
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
	case 'P':
	    do_post = 0;
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
#if defined(ENABLE_XENACCESS) && defined(XA_DEBUG)
    xa_set_debug_level(debug);
#endif

    if (pid > 0) {
	t = linux_userproc_attach(pid);
	if (!t) {
	    fprintf(stderr,"could not attach to pid %d!\n",pid);
	    exit(-3);
	}
    }
#ifdef ENABLE_XENACCESS
    else if (domain) {
	t = xen_vm_attach(domain);
	if (!t) {
	    fprintf(stderr,"could not attach to dom %s!\n",domain);
	    exit(-3);
	}
    }
#endif
    else if (exe) {
	t = linux_userproc_launch(exe,NULL,NULL);
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
	    /* Look for retval code */
	    char *retcode_str = index(argv[i],':');
	    REGVAL retcode = 0;
	    if (retcode_str) {
		*retcode_str = '\0';
		++retcode_str;
		retcode = (REGVAL)atoi(retcode_str);
	    }

	    if (!(symbols[i] = target_lookup_sym(t,argv[i],".",NULL,
						 SYMBOL_TYPE_FLAG_NONE))) {
		fprintf(stderr,"Could not find symbol %s!\n",argv[i]);
		target_close(t);
		exit(-1);
	    }

	    bsymbol_dump(symbols[i],&udn);

	    if (SYMBOL_IS_FUNCTION(symbols[i]->lsymbol->symbol)) {
		/* Try to insert a breakpoint, fastest possible! */
		ADDR start = 0;
		ADDR prologueend = 0;
		ADDR probeaddr = 0;
		struct memrange *range;
		if (location_resolve_function_start(t,symbols[i],
						    &start,&range)) {
		    fprintf(stderr,
			    "Could not resolve entry PC for function %s!\n",
			    symbols[i]->lsymbol->symbol->name);
		    --i;
		    goto err_unreg;
		}
		else {
		    probeaddr = start;
		}
		if (location_resolve_function_prologue_end(t,symbols[i],
							   &prologueend,
							   &range)) {
		    fprintf(stderr,
			    "Could not resolve prologue_end for function %s!\n",
			    symbols[i]->lsymbol->symbol->name);
		}
		else {
		    probeaddr = prologueend;
		}
		
		probes[i] = \
		    probe_register_break(t,probeaddr + offset,range,ptype,
					 function_dump_args,
					 (do_post) ? function_post : NULL,
					 symbols[i]->lsymbol,start);
		
		if (probes[i]) {
		    fprintf(stderr,
			    "Registered probe %s at 0x%"PRIxADDR".\n",
			    symbols[i]->lsymbol->symbol->name,
			    probeaddr + offset);
		    /* Add the retcode action, if any! */
		    if (retcode_str) {
			struct action *action = action_return(retcode);
			if (!action) {
			    fprintf(stderr,"could not create action!\n");
			    goto err_unreg;
			}
			if (action_sched(probes[i],action,ACTION_REPEATPRE)) {
			    fprintf(stderr,"could not schedule action!\n");
			    goto err_unreg;
			}
		    }
		}
		else {
		    fprintf(stderr,
			    "Failed to register probe %s at 0x%"PRIxADDR".\n",
			    symbols[i]->lsymbol->symbol->name,
			    probeaddr + offset);
		    --i;
		    goto err_unreg;
		}
	    }
	    else if (SYMBOL_IS_VAR(symbols[i]->lsymbol->symbol)) {
		/* Try to insert a watchpoint. */
		ADDR addr;
		struct memrange *range;
		ssize = symbol_type_full_bytesize(symbols[i]->lsymbol->symbol->datatype);
		if (ssize <= 0) {
		    fprintf(stderr,
			    "Bad size (%d) for type of %s!\n",
			    ssize,symbols[i]->lsymbol->symbol->name);
		    --i;
		    goto err_unreg;
		}

		errno = 0;
		addr = location_resolve(t,symbols[i]->region,
					&symbols[i]->lsymbol->symbol->s.ii.l,
					symbols[i]->lsymbol->chain,&range);
		if (!addr && errno) {
		    fprintf(stderr,
			    "Could not resolve location for %s!\n",
			    symbols[i]->lsymbol->symbol->name);
		    --i;
		    goto err_unreg;
		}

		probes[i] = \
		    probe_register_watch(t,addr,range,PROBEPOINT_HW,
					 (retcode_str && *retcode_str == 'w') \
					 ? PROBEPOINT_WRITE \
					 : PROBEPOINT_READWRITE,
					 probepoint_closest_watchsize(ssize),
					 var_pre,var_post,
					 symbols[i]->lsymbol,addr);
		
		if (probes[i]) {
		    fprintf(stderr,
			    "Registered probe %s at 0x%"PRIxADDR".\n",
			    symbols[i]->lsymbol->symbol->name,addr);
		}
		else {
		    fprintf(stderr,
			    "Failed to register probe %s at 0x%"PRIxADDR".\n",
			    symbols[i]->lsymbol->symbol->name,addr);
		    --i;
		    goto err_unreg;
		}
	    }

	    continue;

	err_unreg:
	    for ( ; i >= 0; --i) {
		if (probes[i]) {
		    probe_unregister(probes[i],1);
		}
	    }
	    exit(-1);
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
	if (tstat == TSTATUS_PAUSED) {
	    if (linux_userproc_stopped_by_syscall(t)) 
		goto resume;

	    ptrace(PTRACE_GETREGS,pid,NULL,&regs);
#if __WORDSIZE == 64
	    printf("pid %d interrupted at 0x%" PRIx64 "\n",pid,regs.rip);
#else
	    printf("pid %d interrupted at 0x%lx\n",pid,regs.eip);
#endif

	    if (!raw)
		goto resume;
	    else {
		for (i = 0; i < argc; ++i) {
		    if (target_read_addr(t,addrs[i],t->wordsize,
					 (unsigned char *)word,NULL) != NULL) {
			printf("0x%" PRIxADDR " = ",addrs[i]);
			for (j = 0; j < t->wordsize; ++j) {
			    printf("%02hhx",word[j]);
			}
			printf("\n");
		    }
		    else
			printf("0x%" PRIxADDR ": could not read value: %s\n",
			       addrs[i],strerror(errno));
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
	    for (i = 0; i < len; ++i) {
		if (probes[i])
		    probe_unregister(probes[i],1);
	    }
	    target_close(t);
	    if (tstat == TSTATUS_DONE)  {
		printf("pid %d finished.\n",pid);
		break;
	    }
	    else if (tstat == TSTATUS_ERROR) {
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
