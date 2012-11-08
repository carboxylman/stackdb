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

extern char *optarg;
extern int optind, opterr, optopt;

struct target *t = NULL;
int islinux = 0;
int isxen = 0;

int len = 0;
struct bsymbol **symbols = NULL;
GHashTable *probes = NULL;
GHashTable *disfuncs = NULL;
struct array_list *shadow_stack;

int doit = 0;

int at_symbol_hit = 0;
char *at_symbol = NULL;
struct bsymbol *at_bsymbol = NULL;

int until_symbol_hit = 0;
char *until_symbol = NULL;
struct bsymbol *until_bsymbol = NULL;
struct probe *until_probe = NULL;

void cleanup() {
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
	g_hash_table_destroy(probes);
	probes = NULL;
    }
    target_close(t);
    target_free(t);

    if (disfuncs)
	g_hash_table_destroy(disfuncs);

    if (shadow_stack)
	array_list_deep_free(shadow_stack);

    if (symbols)
	free(symbols);
}

int nonrootsethits = 0;

void sigh(int signo) {

    if (t) {
	target_pause(t);
	fprintf(stderr,
		"Ending trace (%d) (hits on probes not from root set: %d).\n",
		signo,nonrootsethits);
	cleanup();
	fprintf(stderr,"Ended trace.\n");
    }

    exit(0);
}

int retaddr_check(struct probe *probe,void *handler_data,
		  struct probe *trigger);
int retaddr_save(struct probe *probe,void *handler_data,
		 struct probe *trigger);

ADDR instrument_func(struct bsymbol *bsymbol,int isroot) {
    ADDR funcstart = 0;

    if (target_resolve_symbol_base(t,TID_GLOBAL,bsymbol,&funcstart,NULL)) {
	fprintf(stderr,
		"Could not resolve base addr for function %s!\n",
		bsymbol->lsymbol->symbol->name);
	return 0;
    }

    /* Disassemble the called function if we haven't already! */
    if (!g_hash_table_lookup(disfuncs,(gpointer)funcstart)) {
	/* Dissasemble the function and grab a list of
	 * RET instrs, and insert more child
	 * breakpoints.
	 */
	int bufsiz = strlen(bsymbol->lsymbol->symbol->name)+1+4+1+2+1;
	char *buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"call_in_%s",bsymbol->lsymbol->symbol->name);
	struct probe *cprobe = probe_create(t,TID_GLOBAL,NULL,buf,
					    NULL,retaddr_save,NULL,0);
	cprobe->handler_data = cprobe->name;
	free(buf);
	struct probe *rprobe;
	if (!isroot) {
	    bufsiz = strlen(bsymbol->lsymbol->symbol->name)+1+3+1+2+1;
	    buf = malloc(bufsiz);
	    snprintf(buf,bufsiz,"ret_in_%s",bsymbol->lsymbol->symbol->name);
	    rprobe = probe_create(t,TID_GLOBAL,NULL,buf,retaddr_check,NULL,buf,0);
	    rprobe->handler_data = rprobe->name;
	    free(buf);
	}


	if (isroot) {
	    if (!probe_register_function_instrs(bsymbol,PROBEPOINT_SW,1,
						INST_CALL,cprobe,
						INST_NONE)) {
		probe_free(cprobe,1);
		return 0;
	    }
	}
	else {
	    if (!probe_register_function_instrs(bsymbol,PROBEPOINT_SW,1,
						INST_RET,rprobe,
						INST_CALL,cprobe,
						INST_NONE)) {
		probe_free(cprobe,1);
		probe_free(rprobe,1);
		return 0;
	    }
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

	if (!isroot) {
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
	}

	g_hash_table_insert(disfuncs,(gpointer)funcstart,(gpointer)1);
    }

    return funcstart;
}

int retaddr_save(struct probe *probe,void *handler_data,
		 struct probe *trigger) {
    struct target *t = probe->target;
    REGVAL sp;
    REGVAL ip;
    ADDR *retaddr;
    tid_t tid = target_gettid(t);

    fflush(stderr);
    fflush(stdout);

    errno = 0;
    sp = target_read_reg(t,tid,t->spregno);
    if (errno) {
	fprintf(stderr,"Could not read SP in retaddr_save!\n");
	return 0;
    }

    /* Grab the return address on the top of the stack */
    retaddr = malloc(sizeof(*retaddr));
    if (!target_read_addr(t,(ADDR)sp,sizeof(ADDR),
			  (unsigned char *)retaddr)) {
	fprintf(stderr,"Could not read top of stack in retaddr_save!\n");
	return 0;
    }

    /* Grab the current IP -- the post-call IP */
    ip = target_read_reg(t,tid,t->ipregno);
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
		" (skipping unknown function!)"
		" (handler_data = %s) (stack depth = %d)\n",
		ip,probe->bsymbol->lsymbol->symbol->name,*retaddr,
		(char *)handler_data,array_list_len(shadow_stack));
	free(retaddr);
	fprintf(stdout,"  (handler_data = %s)\n",(char *)handler_data);

#ifdef ENABLE_XENACCESS
	if (isxen) {
	    struct value *value = linux_load_current_task(t);
	    fprintf(stdout,"  (pid = %d)\n",linux_get_task_pid(t,value));
	    value_free(value);
	}
	fflush(stderr);
	fflush(stdout);
#endif
	return 0;
    }
    else {
	fprintf(stdout,
		"(SAVE) call 0x%"PRIxADDR" (%s)"
		" (from within %s): retaddr = 0x%"PRIxADDR
		" (handler_data = %s) (stack depth = %d)\n",
		ip,bsymbol->lsymbol->symbol->name,
		probe->bsymbol->lsymbol->symbol->name,
		*retaddr,(char *)handler_data,array_list_len(shadow_stack));
	
#ifdef ENABLE_XENACCESS
	if (isxen) {
	    struct value *value = linux_load_current_task(t);
	    fprintf(stdout,"  (pid = %d)\n",linux_get_task_pid(t,value));
	    value_free(value);
	}
	fflush(stderr);
	fflush(stdout);
#endif
    }

    fflush(stderr);
    fflush(stdout);

    /* Since we know that the call is a known function that we can
     * disasm and instrument return points for, push it onto the shadow
     * stack!
     */
    array_list_add(shadow_stack,retaddr);

    instrument_func(bsymbol,0);
    bsymbol_release(bsymbol);

    return 0;
}

int retaddr_check(struct probe *probe,void *handler_data,
		  struct probe *trigger) {
    REGVAL sp;
    ADDR newretaddr;
    ADDR *oldretaddr = NULL;
    tid_t tid = target_gettid(t);

    fflush(stderr);
    fflush(stdout);

    /* These are probably from functions we instrumented, but
     * that were not called from our function root set.
     */
    if (array_list_len(shadow_stack) == 0) {
	++nonrootsethits;
	return 0;
    }

    errno = 0;
    sp = target_read_reg(t,tid,t->spregno);
    if (errno) {
	fprintf(stderr,"Could not read SP in retaddr_check!\n");
	return 0;
    }

    oldretaddr = (ADDR *)array_list_remove(shadow_stack);

    if (!target_read_addr(t,(ADDR)sp,sizeof(ADDR),
			  (unsigned char *)&newretaddr)) {
	fprintf(stderr,"Could not read top of stack in retaddr_check!\n");
	free(oldretaddr);
	return 0;
    }

    if (newretaddr != *oldretaddr) {
	fprintf(stdout,
		"(CHECK) %s (0x%"PRIxADDR"): newretaddr = 0x%"PRIxADDR";"
		" oldretaddr = 0x%"PRIxADDR
		" (handler_data = %s) (stack depth = %d) ---- STACK CORRUPTION!\n",
		probe->bsymbol->lsymbol->symbol->name,probe_addr(trigger),
		newretaddr,*oldretaddr,
		(char *)handler_data,array_list_len(shadow_stack));
    }
    else {
	fprintf(stdout,
		"(CHECK) %s (0x%"PRIxADDR"): newretaddr = 0x%"PRIxADDR";"
		" oldretaddr = 0x%"PRIxADDR
		" (handler_data = %s) (stack depth = %d)\n",
		probe->bsymbol->lsymbol->symbol->name,probe_addr(trigger),
		newretaddr,*oldretaddr,
		(char *)handler_data,array_list_len(shadow_stack));
    }

#ifdef ENABLE_XENACCESS
    if (isxen) {
	struct value *value = linux_load_current_task(t);
	fprintf(stdout,"  (pid = %d)\n",linux_get_task_pid(t,value));
	value_free(value);
    }
    fflush(stderr);
    fflush(stdout);
#endif

    if (doit) {
	if (!target_write_addr(t,(ADDR)sp,sizeof(ADDR),
			       (unsigned char *)oldretaddr)) {
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

int at_handler(struct probe *probe,void *handler_data,
	       struct probe *trigger) {
    ADDR probeaddr;
    struct probepoint *probepoint;
    tid_t tid = target_gettid(t);

    fflush(stderr);
    fflush(stdout);

    if (!probe->probepoint && trigger) {
	probepoint = trigger->probepoint;
	probeaddr = probe_addr(trigger);
    }
    else {
	probeaddr = probe_addr(probe);
	probepoint = probe->probepoint;
    }

    fprintf(stdout,
	    "%s (0x%"PRIxADDR") (thread %"PRIiTID") (at_symbol hit)\n",
	    at_symbol,probeaddr,tid);
    fflush(stdout);

    at_symbol_hit = 1;

    return 0;
}

int until_handler(struct probe *probe,void *handler_data,
		  struct probe *trigger) {
    ADDR probeaddr;
    struct probepoint *probepoint;
    tid_t tid = target_gettid(t);

    fflush(stderr);
    fflush(stdout);

    if (!probe->probepoint && trigger) {
	probepoint = trigger->probepoint;
	probeaddr = probe_addr(trigger);
    }
    else {
	probeaddr = probe_addr(probe);
	probepoint = probe->probepoint;
    }

    fprintf(stdout,
	    "%s (0x%"PRIxADDR") (thread %"PRIiTID") (until_symbol hit)\n",
	    until_symbol,probeaddr,tid);
    fflush(stdout);

    until_symbol_hit = 1;

    return 0;
}

int function_dump_args(struct probe *probe,void *handler_data,
		       struct probe *trigger) {
    struct value *value;
    int j;
    ADDR probeaddr;
    struct probepoint *probepoint;
    tid_t tid = target_gettid(t);

    fflush(stderr);
    fflush(stdout);

    if (!probe->probepoint && trigger) {
	probepoint = trigger->probepoint;
	probeaddr = probe_addr(trigger);
    }
    else {
	probeaddr = probe_addr(probe);
	probepoint = probe->probepoint;
    }

    //struct bsymbol *bsymbol = target_lookup_sym_addr(t,probeaddr);
    //ip = target_read_reg(t,t->ipregno);

    fprintf(stdout,"%s (0x%"PRIxADDR") (thread %"PRIiTID") ",
	    probe->bsymbol->lsymbol->symbol->name,probeaddr,tid);

    struct array_list *args;
    int i;
    struct lsymbol *arg;
    struct bsymbol *bs;

    args = lsymbol_get_members(probe->bsymbol->lsymbol,SYMBOL_VAR_TYPE_FLAG_ARG);
    if (args) {
	for (i = 0; i < array_list_len(args); ++i) {
	    arg = (struct lsymbol *)array_list_item(args,i);
	    bs = bsymbol_create(arg,probe->bsymbol->region);
	    if ((value = target_load_symbol(t,tid,bs,
					    LOAD_FLAG_AUTO_DEREF | 
					    LOAD_FLAG_AUTO_STRING |
					    LOAD_FLAG_NO_CHECK_VISIBILITY |
					    LOAD_FLAG_NO_CHECK_BOUNDS))) {
		printf("%s = ",lsymbol_get_name(arg));
		symbol_rvalue_print(stdout,arg->symbol,value->buf,value->bufsiz,
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
	    bsymbol_free(bs,0);
	    printf(", ");
	}
    }

    fprintf(stdout," (handler_data = %s)\n",(char *)handler_data);

    fflush(stderr);
    fflush(stdout);

    if (args) {
	for (i = 0; i < array_list_len(args); ++i) 
	    lsymbol_release((struct lsymbol *)array_list_item(args,i));
	array_list_free(args);
    }

    return 0;
}

int function_post(struct probe *probe,void *handler_data,
		  struct probe *trigger) {
    ADDR probeaddr;
    struct probepoint *probepoint;
    tid_t tid = target_gettid(probe->target);

    if (!probe->probepoint && trigger) {
	probepoint = trigger->probepoint;
	probeaddr = probe_addr(trigger);
    }
    else {
	probeaddr = probe_addr(probe);
	probepoint = probe->probepoint;
    }

    fflush(stderr);
    fflush(stdout);

    fprintf(stdout,"%s (0x%"PRIxADDR") post handler (thread %"PRIiTID")",
	    probe->bsymbol->lsymbol->symbol->name,
	    probeaddr,tid);
    fprintf(stdout,"  (handler_data = %s)\n",(char *)handler_data);

    fflush(stderr);
    fflush(stdout);

    return 0;
}

int addr_code_pre(struct probe *probe,void *handler_data,struct probe *trigger) {
    tid_t tid;

    fflush(stderr);
    fflush(stdout);

    tid = target_gettid(t);

    fprintf(stdout,"%s (0x%"PRIxADDR") (pre)\n",
	    probe_name(probe),probe_addr(probe));

    fflush(stderr);
    fflush(stdout);

    return 0;
}

int addr_code_post(struct probe *probe,void *handler_data,struct probe *trigger) {
    tid_t tid;

    fflush(stderr);
    fflush(stdout);

    tid = target_gettid(t);

    fprintf(stdout,"%s (0x%"PRIxADDR") (post)\n",
	    probe_name(probe),probe_addr(probe));

    fflush(stderr);
    fflush(stdout);

    return 0;
}

int addr_var_pre(struct probe *probe,void *handler_data,struct probe *trigger) {
    tid_t tid;
    uint32_t word;

    fflush(stderr);
    fflush(stdout);

    tid = target_gettid(t);

    target_read_addr(probe->target,probe_addr(probe),4,(unsigned char *)&word);

    fprintf(stdout,"%s (0x%"PRIxADDR") (pre): watched raw value: 0x%x\n",
	    probe_name(probe),probe_addr(probe),word);

    fflush(stderr);
    fflush(stdout);

    return 0;
}

int addr_var_post(struct probe *probe,void *handler_data,struct probe *trigger) {
    tid_t tid;
    uint32_t word;

    fflush(stderr);
    fflush(stdout);

    tid = target_gettid(t);

    target_read_addr(probe->target,probe_addr(probe),4,(unsigned char *)&word);

    fprintf(stdout,"%s (0x%"PRIxADDR") (post): watched raw value: 0x%x\n",
	    probe_name(probe),probe_addr(probe),word);

    fflush(stderr);
    fflush(stdout);

    return 0;
}

int var_pre(struct probe *probe,void *handler_data,
	    struct probe *trigger) {
    int j;
    struct value *value;
    struct bsymbol *bsymbol = probe->bsymbol;
    tid_t tid = target_gettid(t);

    fflush(stderr);
    fflush(stdout);

    if ((value = target_load_symbol(t,tid,bsymbol,
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
	printf(")");
	value_free(value);
    }
    else
	fprintf(stdout,"%s (0x%"PRIxADDR") (pre): could not read value: %s",
		probe->bsymbol->lsymbol->symbol->name,probe_addr(probe),
		strerror(errno));
    fprintf(stdout,"  (handler_data = %s)\n",(char *)handler_data);

    fflush(stderr);
    fflush(stdout);

    return 0;
}

int var_post(struct probe *probe,void *handler_data,
	     struct probe *trigger) {
    int j;
    struct value *value;
    struct bsymbol *bsymbol = probe->bsymbol;
    tid_t tid = target_gettid(t);

    fflush(stderr);
    fflush(stdout);

    if ((value = target_load_symbol(t,tid,bsymbol,
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
	printf(")");
	value_free(value);
    }
    else
	fprintf(stdout,"%s (0x%"PRIxADDR") (post): could not read value: %s",
		probe->bsymbol->lsymbol->symbol->name,probe_addr(probe),
		strerror(errno));
    fprintf(stdout,"  (handler_data = %s)\n",(char *)handler_data);

    fflush(stderr);
    fflush(stdout);

    return 0;
}

result_t ss_handler(struct action *action,struct probe *probe,
		    struct probepoint *probepoint,
		    handler_msg_t msg,void *handler_data) {
    tid_t tid = target_gettid(t);
    REGVAL ipval = target_read_reg(t,tid,t->ipregno);
    struct bsymbol *func = target_lookup_sym_addr(t,ipval);
    ADDR func_phys_base = 0;
    if (func)
	target_resolve_symbol_base(t,tid,func,&func_phys_base,NULL);

    if (func) {
	fprintf(stdout,"Single step (thread %"PRIiTID") (msg %d) 0x%"PRIxADDR" (%s:+%d)!\n",
		tid,msg,ipval,bsymbol_get_name(func),
		(int)(ipval - func_phys_base));
	bsymbol_release(func);
    }
    else
	fprintf(stdout,"Single step (thread %"PRIiTID") (msg %d) 0x%"PRIxADDR"!\n",
		tid,msg,ipval);

    fflush(stderr);
    fflush(stdout);

    return RESULT_SUCCESS;
}

extern char **environ;

int main(int argc,char **argv) {
    char targetstr[128];
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
    int xadebug = -1;
    target_status_t tstat;
    int raw = 0;
    ADDR *addrs = NULL;
    char *word;
    int i, j;
    log_flags_t flags;
    probepoint_style_t style = PROBEPOINT_FASTEST;
    int do_post = 1;
    int offset = 0;
    struct probe *probe;
    struct debugfile_load_opts **dlo_list = NULL;
    int dlo_idx = 0;
    char *optargc;
    struct debugfile_load_opts *opts;
    struct target_opts topts = {
	.bpmode = THREAD_BPMODE_STRICT,
    };
    target_poll_outcome_t poutcome;
    int pstatus;
    ADDR paddr;
    char *endptr;
    int until_stop_probing = 0;
    int do_bts = 0;

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

    while ((ch = getopt(argc, argv, "m:p:eE:O:dxvsl:Po:FLA:U:BS")) != -1) {
	switch(ch) {
	case 'A':
	    at_symbol = optarg;
	    break;
	case 'U':
	    until_symbol = optarg;
	    break;
	case 'B':
	    do_bts = 1;
	    break;
	case 'S':
	    until_stop_probing = 1;
	    break;
	case 'o':
	    offset = atoi(optarg);
	    break;
	case 'd':
	    ++debug;
	    break;
	case 'x':
	    ++xadebug;
	    break;
	case 'p':
	    pid = atoi(optarg);
	    break;
	case 'm':
#ifdef ENABLE_XENACCESS
	    domain = optarg;
	    /* Xen does not support STRICT! */
	    if (topts.bpmode == THREAD_BPMODE_STRICT)
		++topts.bpmode;
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
	case 'L':
	    ++topts.bpmode;
	    break;
	default:
	    fprintf(stderr,"ERROR: unknown option %c!\n",ch);
	    exit(-1);
	}
    }

    argc -= optind;
    argv += optind;

    dwdebug_init();

    atexit(dwdebug_fini);

    vmi_set_log_level(debug);
#if defined(ENABLE_XENACCESS) && defined(XA_DEBUG)
    xa_set_debug_level(xadebug);
#endif

    if (pid > 0) {
	islinux = 1;
	t = linux_userproc_attach(pid,dlo_list);
	if (!t) {
	    fprintf(stderr,"could not attach to pid %d!\n",pid);
	    exit(-3);
	}
	snprintf(targetstr,128,"pid %d",pid);
    }
#ifdef ENABLE_XENACCESS
    else if (domain) {
	isxen = 1;
	t = xen_vm_attach(domain,dlo_list);
	if (!t) {
	    fprintf(stderr,"could not attach to dom %s!\n",domain);
	    exit(-3);
	}
	snprintf(targetstr,128,"domain %s",domain);
    }
#endif
    else if (doexe) {
	islinux = 1;
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

	pid = linux_userproc_pid(t);
	snprintf(targetstr,128,"pid %d",pid);
    }
    else {
	fprintf(stderr,"ERROR: must specify a target!\n");
	exit(-2);
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

    if (target_open(t,&topts)) {
	fprintf(stderr,"could not open %s!\n",targetstr);
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
	}
    }

    if (raw) {
	word = malloc(t->wordsize);
	for (i = 0; i < argc; ++i) {
	    addrs[i] = strtoll(argv[i],NULL,16);
	}
    }
    else {
	struct array_list *addrlist = array_list_create(0);
	struct array_list *symlist = array_list_create(0);
	struct bsymbol *bsymbol = NULL;
	int *retcodes = (int *)malloc(sizeof(int)*argc);
	char **retcode_strs = (char **)malloc(sizeof(char *)*argc);

	memset(retcodes,0,sizeof(int)*argc);
	memset(retcode_strs,0,sizeof(char *)*argc);

	for (i = 0; i < argc; ++i) {
	    /* Look for retval code */
	    char *retcode_str = index(argv[i],':');
	    int line = -1;
	    if (retcode_str) {
		if (*(retcode_str+1) == 'L') {
		    /* line breakpoint, not retval */
		    *retcode_str = '\0';
		    ++retcode_str;
		    line = retcodes[i] = atoi(retcode_str + 1);
		    retcode_strs[i] = retcode_str;
		}
		else if (*(retcode_str+1) == 's') {
		    *retcode_str = '\0';
		    ++retcode_str;
		    retcodes[i] = atoi(retcode_str + 1);
		    retcode_strs[i] = retcode_str;
		}
		else {
		    *retcode_str = '\0';
		    ++retcode_str;
		    retcode_strs[i] = retcode_str;
		    retcodes[i] = (REGVAL)atoi(retcode_str);
		}
	    }

	    if (strncmp(argv[i],"0x",2) == 0) {
		array_list_add(addrlist,argv[i]);
		array_list_add(symlist,NULL);
	    }
	    else {
		if (line > 0) {
		    if (!(bsymbol = target_lookup_sym_line(t,argv[i],line,
							   NULL,NULL))) {
			fprintf(stderr,"Could not find symbol %s!\n",argv[i]);
			cleanup();
			exit(-1);
		    }
		}
		else {
		    if (!(bsymbol = target_lookup_sym(t,argv[i],".",NULL,
						      SYMBOL_TYPE_FLAG_NONE))) {
			fprintf(stderr,"Could not find symbol %s!\n",argv[i]);
			cleanup();
			exit(-1);
		    }
		}

		array_list_add(symlist,bsymbol);
		array_list_add(addrlist,NULL);
	    }
	}

	if (at_symbol) {
	    if (strncmp(at_symbol,"0x",2) == 0) {
		paddr = (ADDR)strtoll(at_symbol,&endptr,16);
		if (endptr == at_symbol) {
		    fprintf(stderr,"Could not convert %s to address!\n",at_symbol);
		    cleanup();
		    exit(-1);
		}

		probe = probe_create(t,TID_GLOBAL,NULL,at_symbol,
				     function_dump_args,at_handler,NULL,0);
		probe->handler_data = &at_symbol;
		if (!probe)
		    goto err_unreg;

		if (!probe_register_addr(probe,paddr,PROBEPOINT_BREAK,style,
					 PROBEPOINT_EXEC,PROBEPOINT_LAUTO,NULL)) {
		    goto err_unreg;
		}
	    }
	    else {
		if (!(at_bsymbol = target_lookup_sym(t,at_symbol,".",NULL,
						     SYMBOL_TYPE_FLAG_NONE))) {
		    fprintf(stderr,"Could not find symbol %s!\n",argv[i]);
		    cleanup();
		    exit(-1);
		}

		if (!SYMBOL_IS_FUNCTION(at_bsymbol->lsymbol->symbol)) {
		    fprintf(stderr,"pause at symbol %s is not a function!\n",
			    argv[i]);
		    cleanup();
		    exit(-1);
		}

		probe = probe_create(t,TID_GLOBAL,NULL,at_symbol,
				     function_dump_args,at_handler,NULL,0);
		probe->handler_data = &at_symbol;
		if (!probe)
		    goto err_unreg;

		if (!probe_register_symbol(probe,at_bsymbol,style,
					   PROBEPOINT_EXEC,PROBEPOINT_LAUTO)) {
		    goto err_unreg;
		}
	    }

	    target_resume(t);

	    fprintf(stdout,"Starting looking for at_symbol %s!\n",
		    at_symbol);
	    fflush(stdout);

	    while (!at_symbol_hit) {
		struct timeval tv;

		tv.tv_sec = 0;
		tv.tv_usec = 10000;

		tstat = target_poll(t,&tv,&poutcome,&pstatus);
		if (tstat != TSTATUS_PAUSED && tstat != TSTATUS_RUNNING) {
		    fflush(stderr);
		    fflush(stdout);
		    cleanup();
		    if (tstat == TSTATUS_DONE)  {
			printf("%s finished (did not find pause point!\n",
			       targetstr);
			exit(0);
		    }
		    else if (tstat == TSTATUS_ERROR) {
			printf("%s monitoring failed (did not find pause"
			       " point)!\n",targetstr);
			exit(-9);
		    }
		    else {
			printf("%s monitoring failed with %d (did not find"
			       " pause point)!\n",targetstr,tstat);
			exit(-10);
		    }
		}
		if (!at_symbol_hit)
		    target_resume(t);
	    }

	    printf("%s monitoring found at_symbol %s; removing "
		   " pause probe and doing the real thing.\n",
		   targetstr,at_symbol);
	    fflush(stdout);

	    /*
	     * Yank out the at probe.
	     */
	    probe_free(probe,1);
	    probe = NULL;
	}
#if defined(ENABLE_XEN) && defined(CONFIG_DETERMINISTIC_TIMETRAVEL)
	if (isxen && do_bts) {
	    printf("Enabling BTS!\n");
	    fflush(stdout);
	    if (target_enable_feature(t,XV_FEATURE_BTS,NULL))
		verror("failed to enable BTS!\n");
	}
#endif

	if (until_symbol) {
	    /*
	     * Insert the until probe.
	     */
	    if (strncmp(until_symbol,"0x",2) == 0) {
		paddr = (ADDR)strtoll(until_symbol,&endptr,16);
		if (endptr == until_symbol) {
		    fprintf(stderr,"Could not convert %s to address!\n",until_symbol);
		    cleanup();
		    exit(-1);
		}

		probe = probe_create(t,TID_GLOBAL,NULL,until_symbol,
				     function_dump_args,until_handler,NULL,0);
		probe->handler_data = &until_symbol;
		if (!probe)
		    goto err_unreg;

		if (!probe_register_addr(probe,paddr,PROBEPOINT_BREAK,style,
					 PROBEPOINT_EXEC,PROBEPOINT_LAUTO,NULL)) {
		    goto err_unreg;
		}
	    }
	    else {
		if (!(until_bsymbol = target_lookup_sym(t,until_symbol,".",NULL,
						     SYMBOL_TYPE_FLAG_NONE))) {
		    fprintf(stderr,"Could not find until_symbol %s!\n",argv[i]);
		    cleanup();
		    exit(-1);
		}

		if (!SYMBOL_IS_FUNCTION(until_bsymbol->lsymbol->symbol)) {
		    fprintf(stderr,"util_symbol %s is not a function!\n",
			    argv[i]);
		    cleanup();
		    exit(-1);
		}

		probe = probe_create(t,TID_GLOBAL,NULL,until_symbol,
				     function_dump_args,until_handler,NULL,0);
		probe->handler_data = &until_symbol;
		if (!probe)
		    goto err_unreg;

		if (!probe_register_symbol(probe,until_bsymbol,style,
					   PROBEPOINT_EXEC,PROBEPOINT_LAUTO)) {
		    goto err_unreg;
		}
	    }

	    until_probe = probe;

	    fprintf(stdout,"Starting looking for until_symbol %s!\n",
		    until_symbol);
	    fflush(stdout);
	}

	/* Now move through symlist (we may add to it!) */
	for (i = 0; i < array_list_len(symlist); ++i) {
	    bsymbol = (struct bsymbol *)array_list_item(symlist,i);

	    if (!bsymbol)
		continue;

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
		if ((funcstart = instrument_func(bsymbol,1)) == 0) {
		    fprintf(stderr,
			    "Could not instrument function %s (0x%"PRIxADDR")!\n",
			    bsymbol->lsymbol->symbol->name,funcstart);
		    goto err_unreg;
		}
	    }
	    else if (SYMBOL_IS_FUNCTION(bsymbol->lsymbol->symbol)
		     && ((i < argc && retcode_strs[i] 
			  && (*retcode_strs[i] == 'e'
			      || *retcode_strs[i] == 'E')))) {
		probe = probe_create(t,TID_GLOBAL,NULL,bsymbol_get_name(bsymbol),
				     pre,post,NULL,0);
		probe->handler_data = probe->name;
		if (!probe)
		    goto err_unreg;

		if (!probe_register_function_ee(probe,PROBEPOINT_SW,bsymbol,0,1)) {
		    fprintf(stderr,
			    "Could not instrument function %s entry/returns!\n",
			    bsymbol->lsymbol->symbol->name);
		    goto err_unreg;
		}

		g_hash_table_insert(probes,(gpointer)probe,(gpointer)probe);
	    }
	    else {
		probe = probe_create(t,TID_GLOBAL,NULL,bsymbol_get_name(bsymbol),
				     pre,post,NULL,0);
		probe->handler_data = probe->name;
		if (!probe)
		    goto err_unreg;

		if (i < argc && retcode_strs[i] && *retcode_strs[i] == 'L') {
		    if (!probe_register_line(probe,argv[i],retcodes[i],
					     style,whence,PROBEPOINT_LAUTO)) {
			probe_free(probe,1);
			goto err_unreg;
		    }
		}
		else if (symbol_is_inlined(bsymbol_get_symbol(bsymbol))) {
		    if (!probe_register_inlined_symbol(probe,bsymbol,
						       1,
						       style,whence,
						       PROBEPOINT_LAUTO)) {
			probe_free(probe,1);
			goto err_unreg;
		    }
		}
		else {
		    if (!probe_register_symbol(probe,bsymbol,style,whence,
					       PROBEPOINT_LAUTO)) {
			probe_free(probe,1);
			goto err_unreg;
		    }
		}

		g_hash_table_insert(probes,(gpointer)probe,(gpointer)probe);

		if (probe) {
		    fprintf(stderr,
			    "Registered probe %s at 0x%"PRIxADDR".\n",
			    bsymbol_get_name(bsymbol),
			    probe_addr(probe));
		    
		    /* Add the retcode action, if any! */
		    if (SYMBOL_IS_FUNCTION(bsymbol->lsymbol->symbol)) {
			if (i < argc && retcode_strs[i]
			    && *retcode_strs[i] == 's') {
			    struct action *action = action_singlestep(retcodes[i]);
			    if (!action) {
				fprintf(stderr,"could not create action!\n");
				goto err_unreg;
			    }
			    if (action_sched(probe,action,ACTION_REPEATPRE,1,
					     ss_handler,NULL)) {
				fprintf(stderr,"could not schedule action!\n");
				goto err_unreg;
			    }
			}
			else if (i < argc && retcode_strs[i]) {
			    struct action *action = action_return(retcodes[i]);
			    if (!action) {
				fprintf(stderr,"could not create action!\n");
				goto err_unreg;
			    }
			    if (action_sched(probe,action,ACTION_REPEATPRE,1,
					     NULL,NULL)) {
				fprintf(stderr,"could not schedule action!\n");
				goto err_unreg;
			    }
			}
		    }
		}
		else {
		    fprintf(stderr,
			    "Failed to register probe on '%s'\n",
			    bsymbol_get_name(bsymbol));
		    --i;
		    goto err_unreg;
		}
	    }

	    bsymbol_release(bsymbol);

	    continue;

	err_unreg:
	    if (at_bsymbol)
		bsymbol_release(at_bsymbol);
	    if (until_bsymbol)
		bsymbol_release(until_bsymbol);
	    bsymbol_release(bsymbol);
	    array_list_free(symlist);
	    array_list_free(addrlist);
	    free(retcodes);
	    free(retcode_strs);
	    cleanup();
	    exit(-1);
	}

	/* Now move through addrlist (we may add to it!) */
	for (i = 0; i < array_list_len(addrlist); ++i) {
	    char *rawaddr = (char *)array_list_item(addrlist,i);

	    if (!rawaddr)
		continue;

	    char *endptr = NULL;
	    ADDR paddr = (ADDR)strtoull(rawaddr,&endptr,16);

	    if (!endptr) {
		fprintf(stderr,"Bad address %s!\n",rawaddr);
		goto err_unreg;
	    }

	    if (!rawaddr)
		continue;

	    probepoint_type_t type;
	    probepoint_style_t rstyle;
	    probepoint_whence_t whence;
	    probe_handler_t pre;
	    probe_handler_t post = NULL;

	    if (i < argc && retcode_strs[i] && *retcode_strs[i] == 'w') {
		pre = addr_var_pre;
		if (do_post)
		    post = addr_var_post;
		whence = PROBEPOINT_WRITE;
		type = PROBEPOINT_WATCH;
		rstyle = PROBEPOINT_HW;
	    }
	    else if (i < argc && retcode_strs[i] && *retcode_strs[i] == 'r') {
		pre = addr_var_pre;
		if (do_post)
		    post = addr_var_post;
		whence = PROBEPOINT_READWRITE;
		type = PROBEPOINT_WATCH;
		rstyle = PROBEPOINT_HW;
	    }
	    else {
		whence = PROBEPOINT_EXEC;
		type = PROBEPOINT_BREAK;
		rstyle = style;
		pre = addr_code_pre;
		if (do_post)
		    post = addr_code_post;
	    }

	    probe = probe_create(t,TID_GLOBAL,NULL,rawaddr,pre,post,NULL,0);
	    probe->handler_data = rawaddr;
	    if (!probe)
		goto err_unreg2;

	    if (!probe_register_addr(probe,paddr,type,rstyle,whence,
				     PROBEPOINT_L4,NULL)) {
		probe_free(probe,1);
		goto err_unreg2;
	    }

	    g_hash_table_insert(probes,(gpointer)probe,(gpointer)probe);

	    fprintf(stderr,
		    "Registered probe %s at 0x%"PRIxADDR".\n",rawaddr,paddr);

	    continue;

	err_unreg2:
	    if (at_bsymbol)
		bsymbol_release(at_bsymbol);
	    if (until_bsymbol)
		bsymbol_release(until_bsymbol);
	    bsymbol_release(bsymbol);
	    array_list_free(symlist);
	    array_list_free(addrlist);
	    free(retcodes);
	    free(retcode_strs);
	    cleanup();
	    exit(-1);
	}

	array_list_free(symlist);
	array_list_free(addrlist);
	free(retcodes);
	free(retcode_strs);
    }

    /* The target is paused after the attach; we have to resume it now
     * that we've registered probes (or hit the at_symbol).
     */
    target_resume(t);

    fprintf(stdout,"Starting main debugging loop!\n");
    fflush(stdout);

    struct timeval poll_tv = { 0,0 };

    while (1) {
	if (until_probe) {
	    poll_tv.tv_usec = 10000;
	    tstat = target_poll(t,&poll_tv,NULL,NULL);
	}
	else
	    tstat = target_monitor(t);

	if (tstat == TSTATUS_RUNNING && until_probe)
	    continue;
	else if (tstat == TSTATUS_PAUSED) {
	    tid_t tid = target_gettid(t);

	    if (until_probe && until_symbol_hit) {
		printf("%s monitoring found at_symbol %s; removing"
		       " until probe.\n",
		       targetstr,until_symbol);
		fflush(stdout);

		probe_free(until_probe,1);
		until_probe = NULL;

		/*
		 * If we've hit our stopping point, do what we're
		 * supposed to do -- maybe stop branch trace, maybe stop
		 * all probes.
		 */
#if defined(ENABLE_XEN) && defined(CONFIG_DETERMINISTIC_TIMETRAVEL)
		if (isxen && do_bts) {
		    printf("Disabling BTS at until probe.\n");
		    fflush(stdout);
		    if (target_disable_feature(t,XV_FEATURE_BTS))
			verror("failed to disable BTS!\n");
		}
#endif
		if (until_stop_probing) {
		    printf("Stopping monitoring at until probe.\n");
		    fflush(stdout);
		    tstat = TSTATUS_DONE;
		    goto out;
		}
	    }
	    else if (until_probe)
		goto resume;

	    if (islinux && linux_userproc_at_syscall(t,tid))
		goto resume;

	    printf("%s thread %"PRIiTID" interrupted at 0x%" PRIxREGVAL "\n",
		   targetstr,tid,target_read_reg(t,tid,CREG_IP));

	    if (!raw && islinux)
		goto resume;
	    else if (isxen) { // && !raw) {
		goto resume;
		//fprintf(stderr,"ERROR: unexpected Xen interrupt; trying to cleanup!\n");
		//goto exit;
	    }
	    else {
		for (i = 0; i < argc; ++i) {
		    if (target_read_addr(t,addrs[i],t->wordsize,
					 (unsigned char *)word) != NULL) {
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
		fprintf(stderr,"could not resume target %s thread %"PRIiTID"\n",
			targetstr,tid);

		cleanup();
		exit(-16);
	    }
	}
	else {
	out:
	    fflush(stderr);
	    fflush(stdout);
	    cleanup();
	    if (tstat == TSTATUS_DONE)  {
		printf("%s finished.\n",targetstr);
		exit(0);
	    }
	    else if (tstat == TSTATUS_ERROR) {
		printf("%s monitoring failed!\n",targetstr);
		exit(-9);
	    }
	    else {
		printf("%s monitoring failed with %d!\n",targetstr,tstat);
		exit(-10);
	    }
	}
    }

    exit(0);
}
