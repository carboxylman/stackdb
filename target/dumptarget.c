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
#include "alist.h"

extern char *optarg;
extern int optind, opterr, optopt;

struct target *t = NULL;

int len = 0;
struct bsymbol **symbols = NULL;
GHashTable *probes;
GHashTable *disfuncs;
GHashTable *bsymbols;
struct array_list *shadow_stack;

int doit = 0;

void sigh(int signo) {
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;

    if (t) {
	target_pause(t);
	fprintf(stderr,"Ending trace.\n");
	g_hash_table_iter_init(&iter,probes);
	while (g_hash_table_iter_next(&iter,
				      (gpointer)&key,
				      (gpointer)&probe)) {
	    probe_unregister(probe,1);
	}
	target_close(t);
	fprintf(stderr,"Ended trace.\n");
    }

    exit(0);
}

int retaddr_check(struct probe *probe,void *handler_data,
		  struct probe *trigger);
int retaddr_save(struct probe *probe,void *handler_data,
		 struct probe *trigger);

int dynamic_instr_func(ADDR ip,struct bsymbol *bsymbol) {
    /* Disassemble the called function if we haven't already! */
    if (!g_hash_table_lookup(disfuncs,(gpointer)ip)) {
	/* Dissasemble the function and grab a list of
	 * RET instrs, and insert more child
	 * breakpoints.
	 */
	int bufsiz = strlen(bsymbol->lsymbol->symbol->name)+1+4+1+2+1;
	char *buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"call_in_%s",bsymbol->lsymbol->symbol->name);
	struct probe *cprobe = probe_create(t,NULL,buf,NULL,retaddr_save,
					    NULL,0);
	free(buf);
	bufsiz = strlen(bsymbol->lsymbol->symbol->name)+1+3+1+2+1;
	buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"ret_in_%s",bsymbol->lsymbol->symbol->name);
	struct probe *rprobe = probe_create(t,NULL,buf,retaddr_check,NULL,
					    NULL,0);

	if (!probe_register_function_instrs(bsymbol,PROBEPOINT_SW,
					    INST_RET,rprobe,
					    INST_CALL,cprobe,
					    INST_NONE)) {
	    probe_free(cprobe,1);
	    probe_free(rprobe,1);
	    return -1;
	}

	if (probe_num_sources(cprobe) == 0) {
	    probe_free(cprobe,1);
	    fprintf(stderr,
		    "No call sites in %s.\n",bsymbol->lsymbol->symbol->name);
	}
	else {
	    g_hash_table_insert(probes,(gpointer)cprobe,(gpointer)cprobe);
	    fprintf(stderr,
		    "Registered %d call probes in function %s.\n",
		    probe_num_sources(cprobe),bsymbol->lsymbol->symbol->name);
	}

	if (probe_num_sources(rprobe) == 0) {
	    probe_free(rprobe,1);
	    fprintf(stderr,
		    "No return sites in %s.\n",bsymbol->lsymbol->symbol->name);
	}
	else {
	    g_hash_table_insert(probes,(gpointer)rprobe,(gpointer)rprobe);
	    fprintf(stderr,
		    "Registered %d return probes in function %s.\n",
		    probe_num_sources(rprobe),bsymbol->lsymbol->symbol->name);
	}

	g_hash_table_insert(disfuncs,(gpointer)ip,(gpointer)1);
    }

    return 0;
}

int retaddr_save(struct probe *probe,void *handler_data,
		 struct probe *trigger) {
    struct target *t = probe->target;
    REGVAL sp;
    REGVAL ip;
    ADDR *retaddr;

    fflush(stderr);
    fflush(stdout);

    errno = 0;
    sp = target_read_reg(t,t->spregno);
    if (errno) {
	fprintf(stderr,"Could not read SP in retaddr_save!\n");
	return 0;
    }

    /* Grab the return address on the top of the stack */
    retaddr = malloc(sizeof(*retaddr));
    if (!target_read_addr(t,(ADDR)sp,sizeof(ADDR),
			  (unsigned char *)retaddr,NULL)) {
	fprintf(stderr,"Could not read top of stack in retaddr_save!\n");
	return 0;
    }

    /* Grab the current IP -- the post-call IP */
    ip = target_read_reg(t,t->ipregno);
    if (errno) {
	fprintf(stderr,"Could not read IP in retaddr_save!\n");
	fflush(stderr);
	fflush(stdout);
	return 0;
    }

    struct bsymbol *bsymbol = target_lookup_sym_addr(t,ip);
    if (!bsymbol) {
	fprintf(stdout,
		"(SAVE) call 0x%"PRIxADDR" (<UNKNOWN>)"
		" (from within %s): retaddr = 0x%"PRIxADDR
		" (skipping unknown function!)\n",
		ip,probe->bsymbol->lsymbol->symbol->name,*retaddr);
	free(retaddr);
	return 0;
    }
    else {
	fprintf(stdout,
		"(SAVE) call 0x%"PRIxADDR" (%s)"
		" (from within %s): retaddr = 0x%"PRIxADDR"\n",
		ip,bsymbol->lsymbol->symbol->name,
		probe->bsymbol->lsymbol->symbol->name,
		*retaddr);
    }

    /* Since we know that the call is a known function that we can
     * disasm and instrument return points for, push it onto the shadow
     * stack!
     */
    array_list_add(shadow_stack,retaddr);

    dynamic_instr_func(ip,bsymbol);

    return 0;
}

int retaddr_check(struct probe *probe,void *handler_data,
		  struct probe *trigger) {
    REGVAL sp;
    ADDR newretaddr;
    ADDR *oldretaddr = NULL;

    fflush(stderr);
    fflush(stdout);

    errno = 0;
    sp = target_read_reg(t,t->spregno);
    if (errno) {
	fprintf(stderr,"Could not read SP in retaddr_check!\n");
	return 0;
    }

    oldretaddr = (ADDR *)array_list_remove(shadow_stack);

    if (!oldretaddr) {
	fprintf(stderr,"Could not read from shadow stack; just inserted?\n");
	return 0;
    }

    if (!target_read_addr(t,(ADDR)sp,sizeof(ADDR),
			  (unsigned char *)&newretaddr,NULL)) {
	fprintf(stderr,"Could not read top of stack in retaddr_check!\n");
	free(oldretaddr);
	return 0;
    }

    if (newretaddr != *oldretaddr)
	fprintf(stdout,
		"(CHECK) %s (0x%"PRIxADDR"): newretaddr = 0x%"PRIxADDR";"
		" oldretaddr = 0x%"PRIxADDR" ------ STACK CORRUPTION!\n",
		probe->bsymbol->lsymbol->symbol->name,probe_addr(trigger),
		newretaddr,*oldretaddr);
    else 
	fprintf(stdout,
		"(CHECK) %s (0x%"PRIxADDR"): newretaddr = 0x%"PRIxADDR";"
		" oldretaddr = 0x%"PRIxADDR"\n",
		probe->bsymbol->lsymbol->symbol->name,probe_addr(trigger),
		newretaddr,*oldretaddr);

    if (doit) {
	if (!target_write_addr(t,(ADDR)sp,sizeof(ADDR),
			       (unsigned char *)oldretaddr,NULL)) {
	    fprintf(stderr,"Could not reset top of stack in retaddr_check!\n");
	    free(oldretaddr);
	    return 0;
	}
	else 
	    fprintf(stdout,"Reset stack after corruption!\n");
    }

    fflush(stderr);
    fflush(stdout);

    free(oldretaddr);

    return 0;
}

int function_dump_args(struct probe *probe,void *handler_data,
		       struct probe *trigger) {
    struct value *value;
    int j;

    fflush(stderr);
    fflush(stdout);

    fprintf(stdout,"%s (0x%"PRIxADDR")\n  ",
	    probe->bsymbol->lsymbol->symbol->name,probe_addr(probe));

    /* Make a chain with room for one more -- the
     * one more is each arg we're going to process.
     */
    struct symbol_instance *tsym_instance;
    struct symbol *tsym;
    struct array_list *tmp;
    if (!probe->bsymbol->lsymbol->chain
	|| array_list_len(probe->bsymbol->lsymbol->chain) == 0) {
	tmp = array_list_clone(probe->bsymbol->lsymbol->chain,2);
	array_list_add(tmp,probe->bsymbol->lsymbol->symbol);
    }
    else
	tmp = array_list_clone(probe->bsymbol->lsymbol->chain,1);
    int len = tmp->len;

    struct lsymbol tlsym = {
	.chain = tmp,
    };
    struct bsymbol tbsym = {
	.lsymbol = &tlsym,
	.region = probe->probepoint->range->region,
    };

    ++tmp->len;
    list_for_each_entry(tsym_instance,&probe->bsymbol->lsymbol->symbol->s.ii->d.f.args,
			d.v.member) {
	tsym = tsym_instance->d.v.member_symbol;
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

int function_post(struct probe *probe,void *handler_data,
		  struct probe *trigger) {
    fflush(stderr);

    fprintf(stdout,"%s (0x%"PRIxADDR") post handler\n",
	    probe->bsymbol->lsymbol->symbol->name,
	    probe_addr(probe));

    fflush(stdout);

    return 0;
}

int var_pre(struct probe *probe,void *handler_data,
	    struct probe *trigger) {
    int j;
    struct value *value;
    struct bsymbol *bsymbol = (struct bsymbol *) \
	g_hash_table_lookup(bsymbols,(gpointer)probe_addr(probe));

    fflush(stderr);

    if ((value = bsymbol_load(bsymbol,
			      LOAD_FLAG_AUTO_DEREF | 
			      LOAD_FLAG_AUTO_STRING |
			      LOAD_FLAG_NO_CHECK_VISIBILITY |
			      LOAD_FLAG_NO_CHECK_BOUNDS))) {
	fprintf(stdout,"%s (0x%"PRIxADDR") (pre) = ",
		probe->bsymbol->lsymbol->symbol->name,
		probe_addr(probe));

	symbol_rvalue_print(stdout,probe->bsymbol->lsymbol->symbol,
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
		probe->bsymbol->lsymbol->symbol->name,probe_addr(probe),
		strerror(errno));

    fflush(stdout);

    return 0;
}

int var_post(struct probe *probe,void *handler_data,
	     struct probe *trigger) {
    int j;
    struct value *value;
    struct bsymbol *bsymbol = (struct bsymbol *) \
	g_hash_table_lookup(bsymbols,(gpointer)probe_addr(probe));

    fflush(stderr);

    if ((value = bsymbol_load(bsymbol,
			      LOAD_FLAG_AUTO_DEREF | 
			      LOAD_FLAG_AUTO_STRING |
			      LOAD_FLAG_NO_CHECK_VISIBILITY |
			      LOAD_FLAG_NO_CHECK_BOUNDS))) {
	fprintf(stdout,"%s (0x%"PRIxADDR") (post) = ",
		probe->bsymbol->lsymbol->symbol->name,probe_addr(probe));

	symbol_rvalue_print(stdout,probe->bsymbol->lsymbol->symbol,
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
	fprintf(stdout,"%s (0x%"PRIxADDR") (post): could not read value: %s\n",
		probe->bsymbol->lsymbol->symbol->name,probe_addr(probe),
		strerror(errno));

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
    target_status_t tstat;
    int raw = 0;
    ADDR *addrs = NULL;
    char *word;
    int i, j;
    log_flags_t flags;
    probepoint_style_t style = PROBEPOINT_FASTEST;
    int do_post = 1;
    int offset = 0;
    int upg = 1;
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;

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
	    exeargs = &argv[i + 2];
	    break;
	}
    }

    while ((ch = getopt(argc, argv, "m:p:eE:O:dvsl:Po:U")) != -1) {
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
	    doexe = 1;
	    break;
	case 'E':
	    exeerrfile = optarg;
	    break;
	case 'O':
	    exeoutfile = optarg;
	    break;
	case 'v':
	    raw = 1;
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
    else if (doexe) {
	if (!exe) {
	    fprintf(stderr,"must supply at least an executable to launch (%d)!\n",i);
	    exit(-1);
	}

	t = linux_userproc_launch(exe,exeargs,environ,0,
				  exeoutfile,exeerrfile);
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

	    shadow_stack = array_list_create(64);

	    probes = g_hash_table_new(g_direct_hash,g_direct_equal);
	    disfuncs = g_hash_table_new(g_direct_hash,g_direct_equal);
	    bsymbols = g_hash_table_new(g_direct_hash,g_direct_equal);
	}
    }

    if (raw) {
	for (i = 0; i < argc; ++i) {
	    addrs[i] = strtoll(argv[i],NULL,16);
	    word = malloc(t->wordsize);
	}
    }
    else {
	struct array_list *symlist = array_list_create(0);
	struct bsymbol *bsymbol;
	int *retcodes = (int *)malloc(sizeof(int)*argc);
	char **retcode_strs = (char **)malloc(sizeof(char *)*argc);

	memset(retcodes,0,sizeof(int)*argc);
	memset(retcode_strs,0,sizeof(char *)*argc);

	for (i = 0; i < argc; ++i) {
	    /* Look for retval code */
	    char *retcode_str = index(argv[i],':');
	    if (retcode_str) {
		*retcode_str = '\0';
		++retcode_str;
		retcode_strs[i] = retcode_str;
		retcodes[i] = (REGVAL)atoi(retcode_str);
	    }

	    if (!(bsymbol = target_lookup_sym(t,argv[i],".",NULL,
						 SYMBOL_TYPE_FLAG_NONE))) {
		fprintf(stderr,"Could not find symbol %s!\n",argv[i]);
		target_close(t);
		exit(-1);
	    }

	    array_list_add(symlist,bsymbol);
	}

	/* Now move through symlist (we may add to it!) */
	for (i = 0; i < array_list_len(symlist); ++i) {
	    bsymbol = (struct bsymbol *)array_list_item(symlist,i);

	    bsymbol_dump(bsymbol,&udn);

	    probepoint_whence_t whence;
	    probe_handler_t pre;
	    probe_handler_t post = NULL;

	    if (SYMBOL_IS_FUNCTION(bsymbol->lsymbol->symbol)) {
		whence = PROBEPOINT_EXEC;
		pre = function_dump_args;
		if (do_post)
		    post = function_post;
	    }
	    else {
		pre = var_pre;
		if (do_post)
		    post = var_post;
		if (i < argc && retcode_strs[i] 
		    && *retcode_strs[i] == 'w') {
		    whence = PROBEPOINT_WRITE;
		}
		else 
		    whence = PROBEPOINT_READWRITE;
	    }

	    if (SYMBOL_IS_FUNCTION(bsymbol->lsymbol->symbol)
		&& ((i < argc && retcode_strs[i] 
		     && (*retcode_strs[i] == 'c'
			 || *retcode_strs[i] == 'C')))) {
		ADDR funcstart;
		if (location_resolve_symbol_base(t,bsymbol,&funcstart,NULL)) {
		    fprintf(stderr,
			    "Could not resolve base addr for function %s!\n",
			    bsymbol->lsymbol->symbol->name);
		    goto err_unreg;
		}
		if (dynamic_instr_func(funcstart,bsymbol)) {
		    fprintf(stderr,
			    "Could not instrument function %s (0x%"PRIxADDR")!\n",
			    bsymbol->lsymbol->symbol->name,funcstart);
		    goto err_unreg;
		}
	    }
	    else {
		probe = probe_create(t,NULL,bsymbol->lsymbol->symbol->name,
				     pre,post,NULL,0);
		if (!probe)
		    goto err_unreg;

		if (!probe_register_symbol(probe,bsymbol,style,whence,
					   PROBEPOINT_LAUTO)) {
		    probe_free(probe,1);
		    goto err_unreg;
		}

		g_hash_table_insert(probes,(gpointer)probe,(gpointer)probe);
		g_hash_table_insert(bsymbols,(gpointer)probe_addr(probe),
				    (gpointer)bsymbol);

		if (probe) {
		    fprintf(stderr,
			    "Registered probe %s at 0x%"PRIxADDR".\n",
			    bsymbol->lsymbol->symbol->name,
			    probe_addr(probe));
		    
		    /* Add the retcode action, if any! */
		    if (SYMBOL_IS_FUNCTION(bsymbol->lsymbol->symbol)) {
			if (i < argc && retcode_strs[i]) {
			    struct action *action = action_return(retcodes[i]);
			    if (!action) {
				fprintf(stderr,"could not create action!\n");
				goto err_unreg;
			    }
			    if (action_sched(probe,action,ACTION_REPEATPRE,1)) {
				fprintf(stderr,"could not schedule action!\n");
				goto err_unreg;
			    }
			}
		    }
		}
		else {
		    fprintf(stderr,
			    "Failed to register probe on '%s'\n",
			    bsymbol->lsymbol->symbol->name);
		    --i;
		    goto err_unreg;
		}
	    }

	    continue;

	err_unreg:
	    g_hash_table_iter_init(&iter,probes);
	    while (g_hash_table_iter_next(&iter,
					  (gpointer)&key,
					  (gpointer)&probe)) {
		probe_unregister(probe,1);
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
	    if (
#ifdef ENABLE_XENACCESS
		!domain && 
#endif
		linux_userproc_stopped_by_syscall(t))
		goto resume;

#ifdef ENABLE_XENACCESS
	    if (!domain)
		printf("pid %d interrupted at 0x%" PRIxREGVAL "\n",pid,
		       target_read_reg(t,t->ipregno));
	    else 
		printf("domain %s interrupted at 0x%" PRIxREGVAL "\n",domain,
		       target_read_reg(t,t->ipregno));
#else
	    printf("pid %d interrupted at 0x%" PRIxREGVAL "\n",pid,
		   target_read_reg(t,t->ipregno));
#endif

	    if (!raw
#ifdef ENABLE_XENACCESS
		&& !domain
#endif
		)
		goto resume;
#ifdef ENABLE_XENACCESS
	    else if (domain && !raw) {
		fprintf(stderr,"ERROR: unexpected Xen interrupt; trying to cleanup!\n");
		goto exit;
	    }
#endif
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
	exit:
	    fflush(stderr);
	    fflush(stdout);
	    g_hash_table_iter_init(&iter,probes);
	    while (g_hash_table_iter_next(&iter,
					  (gpointer)&key,
					  (gpointer)&probe)) {
		probe_unregister(probe,1);
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
