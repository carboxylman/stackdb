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
GHashTable *retaddrs;
GHashTable *bsymbols;

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
	    if (!probe->parent) {
		probe_unregister_children(probe,1);
		probe_unregister(probe,1);
	    }
	}
	target_close(t);
	fprintf(stderr,"Ended trace.\n");
    }

    exit(0);
}

int retaddr_save(struct probe *probe) {
    struct probe *parent = NULL;
    REGVAL sp;
    struct array_list *alist;
    ADDR *retaddr;

    if (probe->parent)
	parent = probe->parent;

    if (!parent) {
	fprintf(stderr,"Could not find parent probe in retaddr_save!\n");
	return 0;
    }

    alist = (struct array_list *) \
	g_hash_table_lookup(retaddrs,(gpointer)parent->probepoint->addr);

    if (!alist) {
	fprintf(stderr,"Could not find our parent probe/retaddr index!\n");
	return 0;
    }

    fflush(stderr);
    fflush(stdout);

    errno = 0;
    sp = target_read_reg(t,t->spregno);
    if (errno) {
	fprintf(stderr,"Could not read SP in retaddr_save!\n");
	return 0;
    }

    retaddr = malloc(sizeof(*retaddr));
    if (!target_read_addr(t,(ADDR)sp,sizeof(ADDR),
			  (unsigned char *)retaddr,NULL)) {
	fprintf(stderr,"Could not read top of stack in retaddr_save!\n");
	return 0;
    }

    array_list_add(alist,retaddr);

    fprintf(stdout,"%s (0x%"PRIxADDR"): retaddr = 0x%"PRIxADDR"\n",
	    probe->probepoint->lsymbol->symbol->name,probe->probepoint->addr,
	    *retaddr);

    fflush(stderr);
    fflush(stdout);

    return 0;
}

int retaddr_check(struct probe *probe) {
    struct probe *parent = NULL;
    REGVAL sp;
    ADDR newretaddr;
    ADDR *oldretaddr = NULL;
    struct array_list *alist;

    if (probe->parent)
	parent = probe->parent;

    if (!parent) {
	fprintf(stderr,"Could not find parent probe in retaddr_check!\n");
	return 0;
    }

    alist = (struct array_list *) \
	g_hash_table_lookup(retaddrs,(gpointer)parent->probepoint->addr);

    if (!alist) {
	fprintf(stderr,"Could not find our parent probe/retaddr index!\n");
	return 0;
    }

    fflush(stderr);
    fflush(stdout);

    errno = 0;
    sp = target_read_reg(t,t->spregno);
    if (errno) {
	fprintf(stderr,"Could not read SP in retaddr_check!\n");
	return 0;
    }

    oldretaddr = (ADDR *)array_list_remove(alist);

    if (!oldretaddr) {
	fprintf(stderr,"Could not read from saved retaddrs; just inserted?\n");
	return 0;
    }

    if (!target_read_addr(t,(ADDR)sp,sizeof(ADDR),
			  (unsigned char *)&newretaddr,NULL)) {
	fprintf(stderr,"Could not read top of stack in retaddr_check!\n");
	free(oldretaddr);
	return 0;
    }

    fprintf(stdout,"%s (0x%"PRIxADDR"): newretaddr = 0x%"PRIxADDR"; oldretaddr = 0x%"PRIxADDR"\n",
	    probe->probepoint->lsymbol->symbol->name,probe->probepoint->addr,
	    newretaddr,*oldretaddr);

    fflush(stderr);
    fflush(stdout);

    free(oldretaddr);

    return 0;
}

int function_dump_args(struct probe *probe) {
    struct value *value;
    int j;

    fflush(stderr);
    fflush(stdout);

    fprintf(stdout,"%s (0x%"PRIxADDR")\n  ",probe->probepoint->lsymbol->symbol->name,
	    probe->probepoint->addr);

    /* Make a chain with room for one more -- the
     * one more is each arg we're going to process.
     */
    struct symbol *tsym;
    struct array_list *tmp;
    if (!probe->probepoint->lsymbol->chain
	|| array_list_len(probe->probepoint->lsymbol->chain) == 0) {
	tmp = array_list_clone(probe->probepoint->lsymbol->chain,2);
	array_list_add(tmp,probe->probepoint->lsymbol->symbol);
    }
    else
	tmp = array_list_clone(probe->probepoint->lsymbol->chain,1);
    int len = tmp->len;

    struct lsymbol tlsym = {
	.chain = tmp,
    };
    struct bsymbol tbsym = {
	.lsymbol = &tlsym,
	.region = probe->probepoint->range->region,
    };

    ++tmp->len;
    list_for_each_entry(tsym,&probe->probepoint->lsymbol->symbol->s.ii.d.f.args,
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
    fflush(stderr);

    fprintf(stdout,"%s (0x%"PRIxADDR") post handler\n",
	    probe->probepoint->lsymbol->symbol->name,probe->probepoint->addr);

    fflush(stdout);

    return 0;
}

int var_pre(struct probe *probe) {
    int j;
    struct value *value;
    struct bsymbol *bsymbol = (struct bsymbol *) \
	g_hash_table_lookup(bsymbols,(gpointer)probe->probepoint->addr);

    fflush(stderr);

    if ((value = bsymbol_load(bsymbol,
			      LOAD_FLAG_AUTO_DEREF | 
			      LOAD_FLAG_AUTO_STRING |
			      LOAD_FLAG_NO_CHECK_VISIBILITY |
			      LOAD_FLAG_NO_CHECK_BOUNDS))) {
	fprintf(stdout,"%s (0x%"PRIxADDR") (pre) = ",
		probe->probepoint->lsymbol->symbol->name,probe->probepoint->addr);

	symbol_rvalue_print(stdout,probe->probepoint->lsymbol->symbol,
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
		probe->probepoint->lsymbol->symbol->name,probe->probepoint->addr,
		strerror(errno));

    fflush(stdout);

    return 0;
}

int var_post(struct probe *probe) {
    int j;
    struct value *value;
    struct bsymbol *bsymbol = (struct bsymbol *) \
	g_hash_table_lookup(bsymbols,(gpointer)probe->probepoint->addr);

    fflush(stderr);

    if ((value = bsymbol_load(bsymbol,
			      LOAD_FLAG_AUTO_DEREF | 
			      LOAD_FLAG_AUTO_STRING |
			      LOAD_FLAG_NO_CHECK_VISIBILITY |
			      LOAD_FLAG_NO_CHECK_BOUNDS))) {
	fprintf(stdout,"%s (0x%"PRIxADDR") (post) = ",
		probe->probepoint->lsymbol->symbol->name,probe->probepoint->addr);

	symbol_rvalue_print(stdout,probe->probepoint->lsymbol->symbol,
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
		probe->probepoint->lsymbol->symbol->name,probe->probepoint->addr,
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
    int ssize;
    log_flags_t flags;
    probepoint_type_t ptype = PROBEPOINT_FASTEST;
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

	    probes = g_hash_table_new(g_direct_hash,g_direct_equal);
	    retaddrs = g_hash_table_new(g_direct_hash,g_direct_equal);
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
	    REGVAL retcode = 0;
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

	    if (SYMBOL_IS_FUNCTION(bsymbol->lsymbol->symbol)) {
		/* Try to insert a breakpoint, fastest possible, at the
		 * end of the prologue.  If they specified an int, do a
		 * return with that as the return code.  If they
		 * specified 'c', then add another breakpoint at the
		 * *immediate* entry point of the function, record the
		 * current return addr on the top of the stack, and add
		 * child breakpoints on all the function's return
		 * statements.
		 */
		ADDR start = 0;
		ADDR prologueend = 0;
		ADDR probeaddr = 0;
		struct memrange *range;
		struct array_list *cflist = NULL;
		struct range *funcrange;
		unsigned char *funccode;
		unsigned int funclen;

		if (location_resolve_function_start(t,bsymbol,
						    &start,&range)) {
		    fprintf(stderr,
			    "Could not resolve entry PC for function %s!\n",
			    bsymbol->lsymbol->symbol->name);
		    --i;
		    goto err_unreg;
		}
		else {
		    probeaddr = start;
		}
		if (location_resolve_function_prologue_end(t,bsymbol,
							   &prologueend,
							   &range)) {
		    fprintf(stderr,
			    "Could not resolve prologue_end for function %s!\n",
			    bsymbol->lsymbol->symbol->name);
		}
		else {
		    probeaddr = prologueend;
		}

		if (g_hash_table_lookup(probes,(gpointer)start)
		    || g_hash_table_lookup(probes,(gpointer)prologueend)) {
		    /* This is a function we have already added that was
		     * called by some other function in our call graph;
		     * skip!
		     */
		    continue;
		}
		
		probe = \
		    probe_register_break(t,probeaddr + offset,range,ptype,
					 function_dump_args,
					 (do_post) ? function_post : NULL,
					 bsymbol->lsymbol,start);
		g_hash_table_insert(probes,(gpointer)probe->probepoint->addr,(gpointer)probe);
		g_hash_table_insert(retaddrs,(gpointer)probe->probepoint->addr,(gpointer)array_list_create(0));
		g_hash_table_insert(bsymbols,(gpointer)(probeaddr + offset),(gpointer)bsymbol);
		
		if (probe) {
		    fprintf(stderr,
			    "Registered probe %s at 0x%"PRIxADDR".\n",
			    bsymbol->lsymbol->symbol->name,
			    probeaddr + offset);
		    /* Add the retcode action, if any! */
		    if ((i < argc && retcode_strs[i] && *retcode_strs[i] == 'c')
			/* If we're into symbols past argc, these were
			 * added because we added this symbol after
			 * disassembly.  We don't add return code
			 * actions to it, but we *do* keep
			 * dissassembling and adding more functions
			 * until we find a leaf function.
			 */
			|| i >= argc) {
			/* Add another probe at the entry point to
			 * record the current return addr.
			 */
			struct probe *cprobe;
			if (!(cprobe = probe_register_child(probe,
							    start - probe->probepoint->addr,
							    PROBEPOINT_SW,
							    retaddr_save,NULL))) {
			    fprintf(stderr,"could not create child return addr probe for function %s!\n",
				    bsymbol->lsymbol->symbol->name);
			    goto err_unreg;
			}
			else {
			    fprintf(stderr,
				    "Registered return addr save probe for %s at 0x%"PRIxADDR".\n",
				    bsymbol->lsymbol->symbol->name,start);
			}
			g_hash_table_insert(probes,(gpointer)cprobe->probepoint->addr,(gpointer)cprobe);
			/* Dissasemble the function and grab a list of
			 * RET instrs, and insert more child
			 * breakpoints.
			 */
			funcrange = &bsymbol->lsymbol->symbol->s.ii.d.f.symtab->range;
			if (RANGE_IS_PC(funcrange)) {
			    funclen = funcrange->highpc - funcrange->lowpc;
			    funccode = malloc(funclen);

			    if (!target_read_addr(t,funcrange->lowpc,
						  funclen,funccode,NULL)) {
				fprintf(stderr,"could not read code before disasm of function %s!\n",
				    bsymbol->lsymbol->symbol->name);
				goto err_unreg;
			    }

			    if (disasm_get_control_flow_offsets(t,
								INST_CF_RET |
								INST_CF_CALL,
								funccode,funclen,
								&cflist,
								funcrange->lowpc)) {
				fprintf(stderr,"could not disasm function %s!\n",
					bsymbol->lsymbol->symbol->name);
				goto err_unreg;
			    }

			    /* Now register child breakpoints for each RET! */
			    for (j = 0; j < array_list_len(cflist); ++j) {
				struct inst_cf_data *idata = \
				    (struct inst_cf_data *)array_list_item(cflist,
									   j);
				if (idata->type == INST_RET) {
				    if (!(cprobe = probe_register_child(probe,
									(start + idata->offset) - probe->probepoint->addr,
									PROBEPOINT_SW,
									retaddr_check,NULL))) {
					fprintf(stderr,"could not create child return addr check probe for function %s!\n",
						bsymbol->lsymbol->symbol->name);
					array_list_deep_free(cflist);
					array_list_free(cflist);
					goto err_unreg;
				    }
				    else {
					fprintf(stderr,
						"Registered return addr check probe for %s at 0x%"PRIxADDR".\n",
						bsymbol->lsymbol->symbol->name,start + idata->offset);
				    }
				    g_hash_table_insert(probes,(gpointer)cprobe->probepoint->addr,(gpointer)cprobe);
				}
				else if (idata->type == INST_CALL) {
				    struct bsymbol *callsymbol;
				    /* Find this function and add it to
				     * our monitored set.
				     */
				    if (idata->target_addr 
					&& !g_hash_table_lookup(probes,(gpointer)idata->target_addr)
					&& (callsymbol = target_lookup_sym_addr(t,idata->target_addr))) {
					array_list_add(symlist,callsymbol);
					fprintf(stderr,
						"Adding called function %s at 0x%"PRIxADDR".\n",
						callsymbol->lsymbol->symbol->name,idata->target_addr);
				    }
				}
			    }

			    array_list_deep_free(cflist);
			    array_list_free(cflist);
			}
		    }
		    else if (i < argc && retcode_strs[i]) {
			struct action *action = action_return(retcodes[i]);
			if (!action) {
			    fprintf(stderr,"could not create action!\n");
			    goto err_unreg;
			}
			if (action_sched(probe,action,ACTION_REPEATPRE)) {
			    fprintf(stderr,"could not schedule action!\n");
			    goto err_unreg;
			}
		    }
		}
		else {
		    fprintf(stderr,
			    "Failed to register probe %s at 0x%"PRIxADDR".\n",
			    bsymbol->lsymbol->symbol->name,
			    probeaddr + offset);
		    --i;
		    goto err_unreg;
		}
	    }
	    else if (SYMBOL_IS_VAR(bsymbol->lsymbol->symbol)) {
		/* Try to insert a watchpoint. */
		ADDR addr;
		struct memrange *range;
		ssize = symbol_type_full_bytesize(bsymbol->lsymbol->symbol->datatype);
		if (ssize <= 0) {
		    fprintf(stderr,
			    "Bad size (%d) for type of %s!\n",
			    ssize,bsymbol->lsymbol->symbol->name);
		    --i;
		    goto err_unreg;
		}

		errno = 0;
		addr = location_resolve(t,bsymbol->region,
					&bsymbol->lsymbol->symbol->s.ii.l,
					bsymbol->lsymbol->chain,&range);
		if (!addr && errno) {
		    fprintf(stderr,
			    "Could not resolve location for %s!\n",
			    bsymbol->lsymbol->symbol->name);
		    --i;
		    goto err_unreg;
		}

		probe = \
		    probe_register_watch(t,addr,range,PROBEPOINT_HW,
					 (i < argc && retcode_strs[i] && *retcode_strs[i] == 'w') \
					 ? PROBEPOINT_WRITE \
					 : PROBEPOINT_READWRITE,
					 probepoint_closest_watchsize(ssize),
					 var_pre,var_post,
					 bsymbol->lsymbol,addr);
		
		if (probe) {
		    fprintf(stderr,
			    "Registered probe %s at 0x%"PRIxADDR".\n",
			    bsymbol->lsymbol->symbol->name,addr);
		}
		else {
		    fprintf(stderr,
			    "Failed to register probe %s at 0x%"PRIxADDR".\n",
			    bsymbol->lsymbol->symbol->name,addr);
		    --i;
		    goto err_unreg;
		}
		g_hash_table_insert(probes,(gpointer)addr,(gpointer)probe);
		g_hash_table_insert(bsymbols,(gpointer)addr,(gpointer)bsymbol);
	    }

	    continue;

	err_unreg:
	    g_hash_table_iter_init(&iter,probes);
	    while (g_hash_table_iter_next(&iter,
					  (gpointer)&key,
					  (gpointer)&probe)) {
		if (!probe->parent) {
		    probe_unregister_children(probe,1);
		    probe_unregister(probe,1);
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
	    g_hash_table_iter_init(&iter,probes);
	    while (g_hash_table_iter_next(&iter,
					  (gpointer)&key,
					  (gpointer)&probe)) {
		if (!probe->parent) {
		    probe_unregister_children(probe,1);
		    probe_unregister(probe,1);
		}
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
