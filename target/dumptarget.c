/*
 * Copyright (c) 2011, 2012, 2013, 2014 The University of Utah
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

#include <sys/user.h>
#include <sys/ptrace.h>
#include <inttypes.h>

#include <signal.h>

#include <argp.h>

#include <glib.h>
#include "glib_wrapper.h"

#include "log.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"
#include "target_linux_userproc.h"
#ifdef ENABLE_XENSUPPORT
#include "target_xen_vm.h"
#endif

#include "probe_api.h"
#include "probe.h"
#include "alist.h"

struct target *t = NULL;
int ots_len = 0;
struct target **ots = NULL;

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

int nonrootsethits = 0;

struct overlay_spec {
    char *base_target_id;
    char *base_thread_name_or_id;
    struct target_spec *spec;
};

struct dt_argp_state {
    char *at_symbol;
    char *until_symbol;
    int do_bts;
    int until_stop_probing;
    int raw;
    int do_post;
    int quiet;
    int argc;
    char **argv;
    int ospecs_len;
    struct overlay_spec **ospecs;
};

error_t dt_argp_parse_opt(int key, char *arg,struct argp_state *state);

#define __TARGET_OVERLAY      0x200000

struct argp_option dt_argp_opts[] = {
    { "overlay",__TARGET_OVERLAY,"[<target_id>:]<thread_name_or_id>:<spec_opts>",0,"Lookup name or id as an overlay target once the main target is instantiated, and try to open it.  All dumptarget options then apply to the overlay.",0 },
    { "at-symbol",'A',"SYMBOL",0,"Wait for a probe on this symbol/address to be hit before inserting all the other probes.",0 },
    { "until-symbol",'U',"SYMBOL",0,"Remove all probes once a probe on this symbol/address is hit.",0 },
    { "bts",'B',0,0,"Enable BTS (if XenTT) (starting at at-symbol if one was provided; otherwise, enable immediately).",0 },
    { "stop-at-until",'S',0,0,"Stop probing once the until symbol/address is reached.",0 },
    { "raw",'v',0,0,"Enable raw mode.",0 },
    { "post",'P',0,0,"Enable post handlers.",0 },
    { "quiet",'q',0,0,"Silent but deadly.",0 },
    { 0,0,0,0,0,0 },
};

struct argp dt_argp = {
    dt_argp_opts,dt_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};

struct dt_argp_state opts;

struct target_spec *tspec;

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
	g_hash_table_destroy(probes);
	probes = NULL;
    }
}

void cleanup() {
    static int cleaning = 0;
    int j;

    if (cleaning)
	return;
    cleaning = 1;

    cleanup_probes();

    if (ots) {
	for (j = ots_len - 1; j >= 0; --j) {
	    if (!ots[j])
		continue;
	    target_close(ots[j]);
	    target_free(ots[j]);
	    ots[j] = NULL;
	}
    }

    target_close(t);
    target_free(t);

    if (disfuncs)
	g_hash_table_destroy(disfuncs);

    if (shadow_stack)
	array_list_deep_free(shadow_stack);

    if (symbols)
	free(symbols);

    target_free_spec(tspec);

    if (opts.argv)
	free(opts.argv);

    target_fini();

#ifdef REF_DEBUG
    REF_DEBUG_REPORT_FINISH();
#endif
}

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

#ifdef ENABLE_DISTORM
result_t retaddr_check(struct probe *probe,tid_t tid,void *handler_data,
		       struct probe *trigger,struct probe *base);
result_t retaddr_save(struct probe *probe,tid_t tid,void *handler_data,
		      struct probe *trigger,struct probe *base);

ADDR instrument_func(struct bsymbol *bsymbol,int isroot) {
    ADDR funcstart = 0;
    struct target_location_ctxt *tlctxt;

    tlctxt = target_location_ctxt_create_from_bsymbol(t,TID_GLOBAL,bsymbol);
    if (target_lsymbol_resolve_bounds(t,tlctxt,bsymbol->lsymbol,0,
				      &funcstart,NULL,NULL,NULL,NULL)) {
	fprintf(stderr,
		"Could not resolve base addr for function %s!\n",
		bsymbol_get_name(bsymbol));
	target_location_ctxt_free(tlctxt);
	return 0;
    }
    target_location_ctxt_free(tlctxt);

    /* Disassemble the called function if we haven't already! */
    if (!g_hash_table_lookup(disfuncs,(gpointer)funcstart)) {
	/* Dissasemble the function and grab a list of
	 * RET instrs, and insert more child
	 * breakpoints.
	 */
	int bufsiz = strlen(bsymbol_get_name(bsymbol))+1+4+1+2+1;
	char *buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"call_in_%s",bsymbol_get_name(bsymbol));
	struct probe *cprobe = probe_create(t,TID_GLOBAL,NULL,buf,
					    NULL,retaddr_save,NULL,0,1);
	cprobe->handler_data = cprobe->name;
	free(buf);
	struct probe *rprobe;
	if (!isroot) {
	    bufsiz = strlen(bsymbol_get_name(bsymbol))+1+3+1+2+1;
	    buf = malloc(bufsiz);
	    snprintf(buf,bufsiz,"ret_in_%s",bsymbol_get_name(bsymbol));
	    rprobe = probe_create(t,TID_GLOBAL,NULL,buf,retaddr_check,NULL,buf,0,1);
	    rprobe->handler_data = rprobe->name;
	    free(buf);
	}
	else
	    rprobe = NULL;

	if (isroot) {
	    if (!probe_register_function_instrs(bsymbol,PROBEPOINT_SW,1,
						NULL,NULL,
						INST_CALL,cprobe,
						INST_NONE)) {
		probe_free(cprobe,1);
		return 0;
	    }
	}
	else {
	    if (!probe_register_function_instrs(bsymbol,PROBEPOINT_SW,1,
						NULL,NULL,
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
		    "No call sites in %s.\n",bsymbol_get_name(bsymbol));
	}
	else {
	    g_hash_table_insert(probes,(gpointer)cprobe,(gpointer)cprobe);
	    fprintf(stderr,
		    "Registered %d call probes in function %s.\n",
		    probe_num_sources(cprobe),bsymbol_get_name(bsymbol));
	}

	if (!isroot) {
	    if (probe_num_sources(rprobe) == 0) {
		probe_free(rprobe,1);
		fprintf(stderr,
			"No return sites in %s.\n",bsymbol_get_name(bsymbol));
	    }
	    else {
		g_hash_table_insert(probes,(gpointer)rprobe,(gpointer)rprobe);
		fprintf(stderr,
			"Registered %d return probes in function %s.\n",
			probe_num_sources(rprobe),bsymbol_get_name(bsymbol));
	    }
	}

	g_hash_table_insert(disfuncs,(gpointer)funcstart,(gpointer)1);
    }

    return funcstart;
}

result_t retaddr_save(struct probe *probe,tid_t tid,void *handler_data,
		      struct probe *trigger,struct probe *base) {
    struct target *t = probe->target;
    REGVAL sp;
    REGVAL ip;
    ADDR *retaddr;

    fflush(stderr);
    fflush(stdout);

    errno = 0;
    sp = target_read_reg(probe->target,tid,probe->target->spregno);
    if (errno) {
	fprintf(stderr,"Could not read SP in retaddr_save!\n");
	return RESULT_SUCCESS;
    }

    /* Grab the return address on the top of the stack */
    retaddr = malloc(sizeof(*retaddr));
    if (!target_read_addr(t,(ADDR)sp,sizeof(ADDR),
			  (unsigned char *)retaddr)) {
	fprintf(stderr,"Could not read top of stack in retaddr_save!\n");
	return RESULT_SUCCESS;
    }

    /* Grab the current IP -- the post-call IP */
    ip = target_read_reg(t,tid,t->ipregno);
    if (errno) {
	fprintf(stderr,"Could not read IP in retaddr_save!\n");
	fflush(stderr);
	fflush(stdout);
	return RESULT_SUCCESS;
    }

    struct bsymbol *bsymbol = target_lookup_sym_addr(t,ip);
    if (!bsymbol) {
	fprintf(stdout,
		"(SAVE) call 0x%"PRIxADDR" (<UNKNOWN>)"
		" (from within %s): retaddr = 0x%"PRIxADDR
		" (skipping unknown function!)"
		" (handler_data = %s) (stack depth = %d)\n",
		ip,bsymbol_get_name(probe->bsymbol),*retaddr,
		(char *)handler_data,array_list_len(shadow_stack));
	free(retaddr);
	fprintf(stdout,"  (handler_data = %s)\n",(char *)handler_data);

#ifdef ENABLE_XENSUPPORT
	if (target_type(t) == TARGET_TYPE_XEN) {
	    struct value *value = linux_load_current_task(t,0);
	    fprintf(stdout,"  (pid = %d)\n",linux_get_task_pid(t,value));
	    value_free(value);
	}
	fflush(stderr);
	fflush(stdout);
#endif
	return RESULT_SUCCESS;
    }
    else {
	fprintf(stdout,
		"(SAVE) call 0x%"PRIxADDR" (%s)"
		" (from within %s): retaddr = 0x%"PRIxADDR
		" (handler_data = %s) (stack depth = %d)\n",
		ip,bsymbol_get_name(bsymbol),
		bsymbol_get_name(probe->bsymbol),
		*retaddr,(char *)handler_data,array_list_len(shadow_stack));
	
#ifdef ENABLE_XENSUPPORT
	if (target_type(t) == TARGET_TYPE_XEN) {
	    struct value *value = linux_load_current_task(t,0);
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

    return RESULT_SUCCESS;
}

result_t retaddr_check(struct probe *probe,tid_t tid,void *handler_data,
		       struct probe *trigger,struct probe *base) {
    REGVAL sp;
    ADDR newretaddr;
    ADDR *oldretaddr = NULL;

    fflush(stderr);
    fflush(stdout);

    /* These are probably from functions we instrumented, but
     * that were not called from our function root set.
     */
    if (array_list_len(shadow_stack) == 0) {
	++nonrootsethits;
	return RESULT_SUCCESS;
    }

    errno = 0;
    sp = target_read_reg(probe->target,tid,probe->target->spregno);
    if (errno) {
	fprintf(stderr,"Could not read SP in retaddr_check!\n");
	return RESULT_SUCCESS;
    }

    oldretaddr = (ADDR *)array_list_remove(shadow_stack);

    if (!target_read_addr(probe->target,(ADDR)sp,sizeof(ADDR),
			  (unsigned char *)&newretaddr)) {
	fprintf(stderr,"Could not read top of stack in retaddr_check!\n");
	free(oldretaddr);
	return RESULT_SUCCESS;
    }

    if (newretaddr != *oldretaddr) {
	fprintf(stdout,
		"(CHECK) %s (0x%"PRIxADDR"): newretaddr = 0x%"PRIxADDR";"
		" oldretaddr = 0x%"PRIxADDR
		" (handler_data = %s) (stack depth = %d) ---- STACK CORRUPTION!\n",
		bsymbol_get_name(probe->bsymbol),probe_addr(base),
		newretaddr,*oldretaddr,
		(char *)handler_data,array_list_len(shadow_stack));
    }
    else {
	fprintf(stdout,
		"(CHECK) %s (0x%"PRIxADDR"): newretaddr = 0x%"PRIxADDR";"
		" oldretaddr = 0x%"PRIxADDR
		" (handler_data = %s) (stack depth = %d)\n",
		bsymbol_get_name(probe->bsymbol),probe_addr(base),
		newretaddr,*oldretaddr,
		(char *)handler_data,array_list_len(shadow_stack));
    }

#ifdef ENABLE_XENSUPPORT
    if (target_type(probe->target) == TARGET_TYPE_XEN) {
	struct value *value = linux_load_current_task(probe->target,0);
	fprintf(stdout,"  (pid = %d)\n",linux_get_task_pid(probe->target,value));
	value_free(value);
    }
    fflush(stderr);
    fflush(stdout);
#endif

    if (doit) {
	if (!target_write_addr(probe->target,(ADDR)sp,sizeof(ADDR),
			       (unsigned char *)oldretaddr)) {
	    fprintf(stderr,"Could not reset top of stack in retaddr_check!\n");
	    free(oldretaddr);
	    return RESULT_SUCCESS;
	}
	else 
	    fprintf(stdout,"Reset stack after corruption!\n");
    }

    fflush(stderr);
    fflush(stdout);

    free(oldretaddr);

    return RESULT_SUCCESS;
}
#endif /* ENABLE_DISTORM */

result_t at_handler(struct probe *probe,tid_t tid,void *handler_data,
		    struct probe *trigger,struct probe *base) {
    ADDR probeaddr;

    fflush(stderr);
    fflush(stdout);

    if (!probe->probepoint) 
	probeaddr = probe_addr(base);
    else 
	probeaddr = probe_addr(probe);

    fprintf(stdout,
	    "%s (0x%"PRIxADDR") (thread %"PRIiTID") (at_symbol hit)\n",
	    at_symbol,probeaddr,tid);
    fflush(stdout);

    at_symbol_hit = 1;

    return RESULT_SUCCESS;
}

result_t until_handler(struct probe *probe,tid_t tid,void *handler_data,
		       struct probe *trigger,struct probe *base) {
    ADDR probeaddr;

    fflush(stderr);
    fflush(stdout);

    if (!probe->probepoint && base) 
	probeaddr = probe_addr(base);
    else 
	probeaddr = probe_addr(probe);

    fprintf(stdout,
	    "%s (0x%"PRIxADDR") (thread %"PRIiTID") (until_symbol hit)\n",
	    until_symbol,probeaddr,tid);
    fflush(stdout);

    until_symbol_hit = 1;

    return RESULT_SUCCESS;
}

result_t function_dump_args(struct probe *probe,tid_t tid,void *handler_data,
			    struct probe *trigger,struct probe *base) {
    struct value *value;
    int j;
    ADDR probeaddr;
    GSList *gsltmp;
    struct target_location_ctxt *tlctxt;

    if (!opts.quiet) {
	fflush(stderr);
	fflush(stdout);
    }

    if (!probe->probepoint && base) 
	probeaddr = probe_addr(base);
    else 
	probeaddr = probe_addr(probe);

    //struct bsymbol *bsymbol = target_lookup_sym_addr(probe->target,probeaddr);
    //ip = target_read_reg(probe->target,probe->target->ipregno);

    if (!opts.quiet) 
	fprintf(stdout,"%s (0x%"PRIxADDR") (thread %"PRIiTID") ",
		bsymbol_get_name(probe->bsymbol),probeaddr,tid);

    GSList *args;
    struct symbol *arg;
    struct lsymbol *ls;
    struct bsymbol *bs;
    struct dump_info di = { .stream = stdout };

    args = symbol_get_members(probe->bsymbol->lsymbol->symbol,
			      SYMBOL_TYPE_FLAG_VAR_ARG);
    if (args) {
	gsltmp = NULL;
	tlctxt = target_location_ctxt_create_from_bsymbol(probe->target,tid,
							  probe->bsymbol);
	v_g_slist_foreach(args,gsltmp,arg) {
	    ls = lsymbol_create_from_symbol(arg);
	    bs = bsymbol_create(ls,probe->bsymbol->region);
	    lsymbol_release(ls);
	    if ((value = target_load_symbol(probe->target,tlctxt,bs,
					    LOAD_FLAG_AUTO_DEREF | 
					    LOAD_FLAG_AUTO_STRING |
					    LOAD_FLAG_NO_CHECK_VISIBILITY |
					    LOAD_FLAG_NO_CHECK_BOUNDS))) {
		
		if (!opts.quiet) {
		    printf("%s = ",lsymbol_get_name(ls));
		    value_dump_simple(value,&di);
		    printf(" (0x");
		    for (j = 0; j < value->bufsiz; ++j) {
			printf("%02hhx",value->buf[j]);
		    }
		    printf(")");
		}
		value_free(value);
	    }
	    bsymbol_free(bs,0);

	    if (!opts.quiet) 
		printf(", ");
	}
	target_location_ctxt_free(tlctxt);
    }

    if (!opts.quiet) {
	fprintf(stdout," (handler_data = %s)\n",(char *)handler_data);

	fflush(stderr);
	fflush(stdout);
    }

    if (args) {
	g_slist_free(args);
    }

    return RESULT_SUCCESS;
}

result_t function_post(struct probe *probe,tid_t tid,void *handler_data,
		       struct probe *trigger,struct probe *base) {
    ADDR probeaddr;

    if (!probe->probepoint && base) 
	probeaddr = probe_addr(base);
    else 
	probeaddr = probe_addr(probe);

    if (!opts.quiet) {
	fflush(stderr);
	fflush(stdout);

	fprintf(stdout,"%s (0x%"PRIxADDR") post handler (thread %"PRIiTID")",
		bsymbol_get_name(probe->bsymbol),
		probeaddr,tid);
	fprintf(stdout,"  (handler_data = %s)\n",(char *)handler_data);

	fflush(stderr);
	fflush(stdout);
    }

    return RESULT_SUCCESS;
}

result_t addr_code_pre(struct probe *probe,tid_t tid,void *handler_data,
		       struct probe *trigger,struct probe *base) {
    fflush(stderr);
    fflush(stdout);

    fprintf(stdout,"%s (0x%"PRIxADDR") (pre)\n",
	    probe_name(probe),probe_addr(probe));

    fflush(stderr);
    fflush(stdout);

    return RESULT_SUCCESS;
}

result_t addr_code_post(struct probe *probe,tid_t tid,void *handler_data,
			struct probe *trigger,struct probe *base) {
    fflush(stderr);
    fflush(stdout);

    fprintf(stdout,"%s (0x%"PRIxADDR") (post)\n",
	    probe_name(probe),probe_addr(probe));

    fflush(stderr);
    fflush(stdout);

    return RESULT_SUCCESS;
}

result_t addr_var_pre(struct probe *probe,tid_t tid,void *handler_data,
		      struct probe *trigger,struct probe *base) {
    uint32_t word;

    fflush(stderr);
    fflush(stdout);

    target_read_addr(probe->target,probe_addr(probe),4,(unsigned char *)&word);

    fprintf(stdout,"%s (0x%"PRIxADDR") (pre): watched raw value: 0x%x\n",
	    probe_name(probe),probe_addr(probe),word);

    fflush(stderr);
    fflush(stdout);

    return RESULT_SUCCESS;
}

result_t addr_var_post(struct probe *probe,tid_t tid,void *handler_data,
		       struct probe *trigger,struct probe *base) {
    uint32_t word;

    fflush(stderr);
    fflush(stdout);

    target_read_addr(probe->target,probe_addr(probe),4,(unsigned char *)&word);

    fprintf(stdout,"%s (0x%"PRIxADDR") (post): watched raw value: 0x%x\n",
	    probe_name(probe),probe_addr(probe),word);

    fflush(stderr);
    fflush(stdout);

    return RESULT_SUCCESS;
}

result_t var_pre(struct probe *probe,tid_t tid,void *handler_data,
		 struct probe *trigger,struct probe *base) {
    int j;
    struct value *value;
    struct bsymbol *bsymbol = probe->bsymbol;
    struct dump_info di = { .stream = stdout };
    struct target_location_ctxt *tlctxt;

    fflush(stderr);
    fflush(stdout);

    tlctxt = target_location_ctxt_create_from_bsymbol(probe->target,tid,bsymbol);
    if ((value = target_load_symbol(probe->target,tlctxt,bsymbol,
				    LOAD_FLAG_AUTO_DEREF | 
				    LOAD_FLAG_AUTO_STRING |
				    LOAD_FLAG_NO_CHECK_VISIBILITY |
				    LOAD_FLAG_NO_CHECK_BOUNDS))) {
	fprintf(stdout,"%s (0x%"PRIxADDR") (pre) = ",
		bsymbol_get_name(probe->bsymbol),
		probe_addr(probe));

	value_dump_simple(value,&di);
	printf(" (0x");
	for (j = 0; j < value->bufsiz; ++j) {
	    printf("%02hhx",value->buf[j]);
	}
	printf(")");
	value_free(value);
    }
    else
	fprintf(stdout,"%s (0x%"PRIxADDR") (pre): could not read value: %s",
		bsymbol_get_name(probe->bsymbol),probe_addr(probe),
		strerror(errno));
    fprintf(stdout,"  (handler_data = %s)\n",(char *)handler_data);

    fflush(stderr);
    fflush(stdout);

    target_location_ctxt_free(tlctxt);

    return RESULT_SUCCESS;
}

result_t var_post(struct probe *probe,tid_t tid,void *handler_data,
		  struct probe *trigger,struct probe *base) {
    int j;
    struct value *value;
    struct bsymbol *bsymbol = probe->bsymbol;
    struct dump_info di = { .stream = stdout };
    struct target_location_ctxt *tlctxt;

    fflush(stderr);
    fflush(stdout);

    tlctxt = target_location_ctxt_create_from_bsymbol(probe->target,tid,bsymbol);
    if ((value = target_load_symbol(probe->target,tlctxt,bsymbol,
				    LOAD_FLAG_AUTO_DEREF | 
				    LOAD_FLAG_AUTO_STRING |
				    LOAD_FLAG_NO_CHECK_VISIBILITY |
				    LOAD_FLAG_NO_CHECK_BOUNDS))) {
	fprintf(stdout,"%s (0x%"PRIxADDR") (post) = ",
		bsymbol_get_name(probe->bsymbol),probe_addr(probe));

	value_dump_simple(value,&di);
	printf(" (0x");
	for (j = 0; j < value->bufsiz; ++j) {
	    printf("%02hhx",value->buf[j]);
	}
	printf(")");
	value_free(value);
    }
    else
	fprintf(stdout,"%s (0x%"PRIxADDR") (post): could not read value: %s",
		bsymbol_get_name(probe->bsymbol),probe_addr(probe),
		strerror(errno));
    fprintf(stdout,"  (handler_data = %s)\n",(char *)handler_data);

    fflush(stderr);
    fflush(stdout);

    target_location_ctxt_free(tlctxt);

    return RESULT_SUCCESS;
}

result_t ss_handler(struct action *action,struct target_thread *thread,
		    struct probe *probe,struct probepoint *probepoint,
		    handler_msg_t msg,int msg_detail,void *handler_data) {
    tid_t tid = target_gettid(probe->target);
    REGVAL ipval = target_read_reg(probe->target,tid,probe->target->ipregno);
    struct bsymbol *func = target_lookup_sym_addr(probe->target,ipval);
    ADDR func_phys_base = 0;
    struct target_location_ctxt *tlctxt;

    if (func) {
	tlctxt = target_location_ctxt_create_from_bsymbol(thread->target,
							  thread->tid,func);
	target_lsymbol_resolve_bounds(probe->target,tlctxt,func->lsymbol,0,
				      &func_phys_base,NULL,NULL,NULL,NULL);
	fprintf(stdout,"Single step %d (thread %"PRIiTID") (msg %d) 0x%"PRIxADDR" (%s:+%d)!\n",
		msg_detail,tid,msg,ipval,bsymbol_get_name(func),
		(int)(ipval - func_phys_base));
	bsymbol_release(func);
	target_location_ctxt_free(tlctxt);
    }
    else
	fprintf(stdout,"Single step %d (thread %"PRIiTID") (msg %d) 0x%"PRIxADDR"!\n",
		msg_detail,tid,msg,ipval);

    fflush(stderr);
    fflush(stdout);

    return RESULT_SUCCESS;
}

error_t dt_argp_parse_opt(int key, char *arg,struct argp_state *state) {
    struct dt_argp_state *opts = \
	(struct dt_argp_state *)target_argp_driver_state(state);
    struct array_list *argv_list;
    char *argptr,*argptr2;
    char *nargptr;
    char *vargptr;
    int inesc;
    int inquote;
    int quotechar;
    struct overlay_spec *ospec = NULL;

    switch (key) {
    case ARGP_KEY_ARG:
	/* We want to process all the remaining args, so bounce to the
	 * next case by returning this value.
	 */
	return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_ARGS:
	/* Eat all the remaining args. */
	if (state->quoted > 0)
	    opts->argc = state->quoted - state->next;
	else
	    opts->argc = state->argc - state->next;
	if (opts->argc > 0) {
	    opts->argv = calloc(opts->argc,sizeof(char *));
	    memcpy(opts->argv,&state->argv[state->next],opts->argc*sizeof(char *));
	    state->next += opts->argc;
	}
	return 0;
    case ARGP_KEY_INIT:
	target_driver_argp_init_children(state);
	return 0;
    case ARGP_KEY_END:
    case ARGP_KEY_NO_ARGS:
    case ARGP_KEY_SUCCESS:
	return 0;
    case ARGP_KEY_ERROR:
    case ARGP_KEY_FINI:
	return 0;

    case 'A':
	opts->at_symbol = arg;
	break;
    case 'U':
	opts->until_symbol = arg;
	break;
    case 'B':
	opts->do_bts = 1;
	break;
    case 'S':
	opts->until_stop_probing = 1;
	break;
    case 'v':
	opts->raw = 1;
	break;
    case 'P':
	opts->do_post = 1;
	break;
    case 'q':
	opts->quiet = 1;
	break;
    case __TARGET_OVERLAY:
	/*
	 * We need to split the <name_or_id>:<spec> part; then split
	 * <spec> into an argv.  Simple rules: \ escapes the next char;
	 * space not in ' or " causes us to end the current argv[i] and
	 * start the next one.
	 */
	argptr = index(arg,':');
	if (!argptr) {
	    verror("bad overlay spec!\n");
	    return EINVAL;
	}

	ospec = calloc(1,sizeof(*ospec));
	++opts->ospecs_len;
	opts->ospecs = 
	    realloc(opts->ospecs,opts->ospecs_len*sizeof(*opts->ospecs));
	opts->ospecs[opts->ospecs_len - 1] = ospec;

	argv_list = array_list_create(32);
	array_list_append(argv_list,"dumptarget_overlay");

	ospec->base_thread_name_or_id = arg;
	*argptr = '\0';
	++argptr;

	argptr2 = index(argptr,':');
	if (argptr2) {
	    ospec->base_target_id = ospec->base_thread_name_or_id;
	    ospec->base_thread_name_or_id = argptr;
	    *argptr2 = '\0';
	    argptr = ++argptr2;
	}

	while (*argptr == ' ')
	    ++argptr;

	inesc = 0;
	inquote = 0;
	quotechar = 0;
	nargptr = argptr;
	vargptr = argptr;
	while (*argptr != '\0') {
	    if (*argptr == '\\') {
		if (inesc) {
		    inesc = 0;
		    *nargptr = '\\';
		    ++nargptr;
		}
		else {
		    /* Don't copy the escape char. */
		    inesc = 1;
		    ++argptr;
		    continue;
		}
	    }
	    else if (inesc) {
		inesc = 0;
		/* Just copy it. */
		*nargptr = *argptr;
		++nargptr;
	    }
	    else if (inquote && *argptr == quotechar) {
		/* Ended the quoted sequence; don't copy quotes. */
		inquote = 0;
		quotechar = 0;
		++argptr;
		continue;
	    }
	    else if (*argptr == '\'' || *argptr == '"') {
		inquote = 1;
		quotechar = *argptr;
		++argptr;
		continue;
	    }
	    else if (!inquote && *argptr == ' ') {
		*nargptr = *argptr = '\0';
		if (vargptr) {
		    array_list_append(argv_list,vargptr);
		    //printf("vargptr (%p) = '%s'\n",vargptr,vargptr);
		    vargptr = NULL;
		}
		vargptr = NULL;
		nargptr = ++argptr;
		continue;
	    }
	    else {
		if (!vargptr)
		    vargptr = nargptr;

		*nargptr = *argptr;
		++nargptr;
	    }

	    /* Default increment. */
	    ++argptr;
	}
	if (vargptr) {
	    *nargptr = '\0';
	    array_list_append(argv_list,vargptr);
	    //printf("vargptr (%p) = '%s'\n",vargptr,vargptr);
	}
	array_list_append(argv_list,NULL);

	ospec->spec = target_argp_driver_parse(NULL,NULL,
					       array_list_len(argv_list) - 1,
					       (char **)argv_list->list,
					       TARGET_TYPE_PHP | TARGET_TYPE_XEN_PROCESS,0);
	if (!ospec->spec) {
	    verror("could not parse overlay spec %d!\n",opts->ospecs_len);
	    array_list_free(argv_list);
	    return EINVAL;
	}

	array_list_free(argv_list);
	break;

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int main(int argc,char **argv) {
    target_status_t tstat;
    ADDR *addrs = NULL;
    char *word;
    int i, j;
    struct probe *probe;
    target_poll_outcome_t poutcome;
    int pstatus;
    ADDR paddr;
    char *endptr;
    char *targetstr;
    char *tmp;
    int oid;
    tid_t base_tid;
    struct target *base;
    struct overlay_spec *ospec;
    char namebuf[64];

    struct dump_info udn = {
	.stream = stderr,
	.prefix = "",
	.detail = 1,
	.meta = 1,
    };

    memset(&opts,0,sizeof(opts));

    tspec = target_argp_driver_parse(&dt_argp,&opts,argc,argv,
				     TARGET_TYPE_PTRACE | TARGET_TYPE_XEN,1);

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
    tmp = target_name(t);
    if (!tmp) 
	targetstr = strdup("<UNNAMED_TARGET>");
    else
	targetstr = strdup(tmp);
    tmp = NULL;

    /*
     * Load the overlay targets, if any.
     */
    if (opts.ospecs) 
	ots = calloc(opts.ospecs_len,sizeof(*ots));
    for (j = 0; j < opts.ospecs_len; ++j) {
	errno = 0;
	tmp = NULL;
	ospec = opts.ospecs[j];

	if (ospec->base_target_id) {
	    base = target_lookup_target_id(atoi(ospec->base_target_id));
	    if (!base) {
		verror("no existing target with id '%s'!\n",ospec->base_target_id);
		cleanup();
		exit(-113);
	    }
	}
	else 
	    base = t;

	target_snprintf(base,namebuf,sizeof(namebuf));

	oid = (int)strtol(ospec->base_thread_name_or_id,&tmp,0);
	if (errno || tmp == ospec->base_thread_name_or_id)
	    base_tid = 
		target_lookup_overlay_thread_by_name(base,ospec->base_thread_name_or_id);
	else
	    base_tid = target_lookup_overlay_thread_by_id(base,oid);
	if (base_tid < 0) {
	    verror("could not find overlay thread '%s' in base target '%s',"
		   " exiting!\n",
		   ospec->base_thread_name_or_id,namebuf);
	    cleanup();
	    exit(-111);
	}

	ots[j] = target_instantiate_overlay(base,base_tid,ospec->spec);
	++ots_len;
	if (!ots[j]) {
	    verror("could not instantiate overlay on base '%s' thread '%s'!\n",
		   namebuf,ospec->base_thread_name_or_id);
	    cleanup();
	    exit(-112);
	}

	if (target_open(ots[j])) {
	    fprintf(stderr,"could not open overlay on base '%s' thread '%s'!\n",
		    namebuf,ospec->base_thread_name_or_id);
	    cleanup();
	    exit(-114);
	}
    }

    /* Now that we have loaded any symbols we might need, process the
     * rest of our args.
     */
    if (opts.argc) {
	len = opts.argc;
	if (opts.raw) {
	    addrs = (ADDR *)malloc(sizeof(ADDR)*opts.argc);
	    memset(addrs,0,sizeof(ADDR)*opts.argc);
	}
	else {
	    symbols = (struct bsymbol **)malloc(sizeof(struct bsymbol *)*opts.argc);
	    memset(symbols,0,sizeof(struct bsymbol *)*opts.argc);

	    shadow_stack = array_list_create(64);

	    probes = g_hash_table_new(g_direct_hash,g_direct_equal);
	    disfuncs = g_hash_table_new(g_direct_hash,g_direct_equal);
	}
    }

    at_symbol = opts.at_symbol;
    until_symbol = opts.until_symbol;

    if (opts.raw) {
	word = malloc(t->wordsize);
	for (i = 0; i < opts.argc; ++i) {
	    addrs[i] = strtoll(opts.argv[i],NULL,16);
	}
    }
    else {
	struct array_list *addrlist = array_list_create(0);
	struct array_list *symlist = array_list_create(0);
	struct bsymbol *bsymbol = NULL;
	int *retcodes = (int *)malloc(sizeof(int)*opts.argc);
	char **retcode_strs = (char **)malloc(sizeof(char *)*opts.argc);

	memset(retcodes,0,sizeof(int)*opts.argc);
	memset(retcode_strs,0,sizeof(char *)*opts.argc);

	word = NULL;

	char *srcfile = NULL;
	char *symname = NULL;

	for (i = 0; i < opts.argc; ++i) {
	    /* Look for retval code */
	    char *retcode_str = index(opts.argv[i],':');
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
		else if (*(retcode_str+1) == 'r') { 
		    *retcode_str = '\0';
		    ++retcode_str;
		    retcode_strs[i] = retcode_str;
		    retcodes[i] = (REGVAL)atoi(retcode_str);
		}
		else if (*(retcode_str+1) == 'o') {
		    *retcode_str = '\0';
		    ++retcode_str;
		    retcode_strs[i] = retcode_str;
		    ++retcode_str;
		    retcodes[i] = atoi(retcode_str);
		    symname = opts.argv[i];
		}
		else {
		    srcfile = opts.argv[i];
		    *retcode_str = '\0';
		    ++retcode_str;
		    symname = retcode_str;
		}
	    }
	    else
		symname = opts.argv[i];

	    if (strncmp(symname,"0x",2) == 0) {
		array_list_add(addrlist,opts.argv[i]);
		array_list_add(symlist,NULL);
	    }
	    else {
		if (line > 0) {
		    bsymbol = target_lookup_sym_line(t,opts.argv[i],line,
						     NULL,NULL);
		    if (!bsymbol) {
			fprintf(stderr,"Could not find symbol %s!\n",opts.argv[i]);
			cleanup();
			exit(-1);
		    }
		}
		else {
		    if (ots) {
			for (j = ots_len - 1; j >= 0; --j) {
			    bsymbol = target_lookup_sym(ots[j],symname,NULL,
							srcfile,
							SYMBOL_TYPE_FLAG_NONE);
			    if (bsymbol)
				break;
			}
		    }
		    if (!bsymbol) {
			bsymbol = target_lookup_sym(t,symname,NULL,srcfile,
						    SYMBOL_TYPE_FLAG_NONE);
			if (!bsymbol) {
			    fprintf(stderr,"Could not find symbol %s!\n",
				    symname);
			    cleanup();
			    exit(-1);
			}
		    }
		}

		array_list_add(symlist,bsymbol);
		array_list_add(addrlist,NULL);
		bsymbol = NULL;
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
				     function_dump_args,at_handler,NULL,0,1);
		probe->handler_data = &at_symbol;
		if (!probe)
		    goto err_unreg;

		if (!probe_register_addr(probe,paddr,PROBEPOINT_BREAK,t->spec->style,
					 PROBEPOINT_EXEC,PROBEPOINT_LAUTO,NULL)) {
		    goto err_unreg;
		}
	    }
	    else {
		if (!(at_bsymbol = target_lookup_sym(t,at_symbol,".",NULL,
						     SYMBOL_TYPE_FLAG_NONE))) {
		    fprintf(stderr,"Could not find symbol %s!\n",opts.argv[i]);
		    cleanup();
		    exit(-1);
		}

		if (!symbol_type_flags_match(at_bsymbol->lsymbol->symbol,
					     SYMBOL_TYPE_FLAG_FUNC)) {
		    fprintf(stderr,"pause at symbol %s is not a function!\n",
			    opts.argv[i]);
		    cleanup();
		    exit(-1);
		}

		probe = probe_create(at_bsymbol->region->space->target,TID_GLOBAL,NULL,at_symbol,
				     function_dump_args,at_handler,NULL,0,1);
		probe->handler_data = &at_symbol;
		if (!probe)
		    goto err_unreg;

		if (!probe_register_symbol(probe,at_bsymbol,at_bsymbol->region->space->target->spec->style,
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
	if (target_type(t) == TARGET_TYPE_XEN && opts.do_bts) {
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

		probe = probe_create(until_bsymbol->region->space->target,TID_GLOBAL,NULL,until_symbol,
				     function_dump_args,until_handler,NULL,0,1);
		probe->handler_data = &until_symbol;
		if (!probe)
		    goto err_unreg;

		if (!probe_register_addr(probe,paddr,PROBEPOINT_BREAK,until_bsymbol->region->space->target->spec->style,
					 PROBEPOINT_EXEC,PROBEPOINT_LAUTO,NULL)) {
		    goto err_unreg;
		}
	    }
	    else {
		if (!(until_bsymbol = target_lookup_sym(t,until_symbol,".",NULL,
						     SYMBOL_TYPE_FLAG_NONE))) {
		    fprintf(stderr,"Could not find until_symbol %s!\n",opts.argv[i]);
		    cleanup();
		    exit(-1);
		}

		if (!symbol_type_flags_match(until_bsymbol->lsymbol->symbol,
					     SYMBOL_TYPE_FLAG_FUNC)) {
		    fprintf(stderr,"util_symbol %s is not a function!\n",
			    opts.argv[i]);
		    cleanup();
		    exit(-1);
		}

		probe = probe_create(until_bsymbol->region->space->target,TID_GLOBAL,NULL,until_symbol,
				     function_dump_args,until_handler,NULL,0,1);
		probe->handler_data = &until_symbol;
		if (!probe)
		    goto err_unreg;

		if (!probe_register_symbol(probe,until_bsymbol,until_bsymbol->region->space->target->spec->style,
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

	    if (symbol_type_flags_match(bsymbol->lsymbol->symbol,
					SYMBOL_TYPE_FLAG_FUNC)) {
		whence = PROBEPOINT_EXEC;
		pre = function_dump_args;
		if (opts.do_post)
		    post = function_post;
	    }
	    else {
		pre = var_pre;
		if (opts.do_post)
		    post = var_post;
		if (i < opts.argc && retcode_strs[i] 
		    && *retcode_strs[i] == 'w') {
		    whence = PROBEPOINT_WRITE;
		}
		else 
		    whence = PROBEPOINT_READWRITE;
	    }

	    if (symbol_type_flags_match(bsymbol->lsymbol->symbol,
					SYMBOL_TYPE_FLAG_FUNC)
		&& ((i < opts.argc && retcode_strs[i] 
		     && (*retcode_strs[i] == 'c'
			 || *retcode_strs[i] == 'C')))) {
#ifndef ENABLE_DISTORM
		fprintf(stderr,
			"Could not instrument function %s;"
			" DISTORM not configured in!\n",
			bsymbol_get_name(bsymbol));
		goto err_unreg;
#else
		ADDR funcstart;
		if ((funcstart = instrument_func(bsymbol,1)) == 0) {
		    fprintf(stderr,
			    "Could not instrument function %s (0x%"PRIxADDR")!\n",
			    bsymbol_get_name(bsymbol),funcstart);
		    goto err_unreg;
		}
#endif
	    }
	    else if (symbol_type_flags_match(bsymbol->lsymbol->symbol,
					     SYMBOL_TYPE_FLAG_FUNC)
		     && ((i < opts.argc && retcode_strs[i] 
			  && (*retcode_strs[i] == 'e'
			      || *retcode_strs[i] == 'E')))) {
#ifndef ENABLE_DISTORM
		fprintf(stderr,
			"Could not instrument function %s entry/returns;"
			" DISTORM not configured in!\n",
			bsymbol_get_name(bsymbol));
		goto err_unreg;
#else
		probe = probe_create(bsymbol->region->space->target,TID_GLOBAL,NULL,bsymbol_get_name(bsymbol),
				     pre,post,NULL,0,1);
		if (!probe)
		    goto err_unreg;
		probe->handler_data = probe->name;

		if (!probe_register_function_ee(probe,PROBEPOINT_SW,bsymbol,0,1,1)) {
		    fprintf(stderr,
			    "Could not instrument function %s entry/returns!\n",
			    bsymbol_get_name(bsymbol));
		    goto err_unreg;
		}

		g_hash_table_insert(probes,(gpointer)probe,(gpointer)probe);
#endif
	    }
	    else {
		probe = probe_create(bsymbol->region->space->target,TID_GLOBAL,NULL,bsymbol_get_name(bsymbol),
				     pre,post,NULL,0,1);
		if (!probe)
		    goto err_unreg;
		probe->handler_data = probe->name;

		if (i < opts.argc && retcode_strs[i] && *retcode_strs[i] == 'L') {
		    if (!probe_register_line(probe,opts.argv[i],retcodes[i],
					     bsymbol->region->space->target->spec->style,whence,PROBEPOINT_LAUTO)) {
			probe_free(probe,1);
			goto err_unreg;
		    }
		}
		else if (symbol_is_inlined(bsymbol_get_symbol(bsymbol))) {
		    if (!probe_register_inlined_symbol(probe,bsymbol,
						       1,
						       bsymbol->region->space->target->spec->style,whence,
						       PROBEPOINT_LAUTO)) {
			probe_free(probe,1);
			goto err_unreg;
		    }
		}
		else {
		    if (!probe_register_symbol(probe,bsymbol,bsymbol->region->space->target->spec->style,whence,
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
		    if (symbol_type_flags_match(bsymbol->lsymbol->symbol,
						SYMBOL_TYPE_FLAG_FUNC)) {
			if (i < opts.argc && retcode_strs[i]
			    && *retcode_strs[i] == 's') {
			    struct action *action = action_singlestep(retcodes[i]);
			    if (!action) {
				fprintf(stderr,"could not create action!\n");
				goto err_unreg;
			    }
			    if (action_sched(probe,action,ACTION_REPEATPRE,
					     ss_handler,NULL)) {
				fprintf(stderr,"could not schedule action!\n");
				action_release(action);
				goto err_unreg;
			    }
			    else
				action_release(action);
			}
			else if (i < opts.argc && retcode_strs[i]) {
			    struct action *action = action_return(retcodes[i]);
			    if (!action) {
				fprintf(stderr,"could not create action!\n");
				goto err_unreg;
			    }
			    if (action_sched(probe,action,ACTION_REPEATPRE,
					     NULL,NULL)) {
				fprintf(stderr,"could not schedule action!\n");
				action_release(action);
				goto err_unreg;
			    }
			    else
				action_release(action);
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
	    if (bsymbol)
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
	    struct target *tmpt = t;

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

	    if (i < opts.argc && retcode_strs[i] && *retcode_strs[i] == 'w') {
		pre = addr_var_pre;
		if (opts.do_post)
		    post = addr_var_post;
		whence = PROBEPOINT_WRITE;
		type = PROBEPOINT_WATCH;
		rstyle = PROBEPOINT_HW;
	    }
	    else if (i < opts.argc && retcode_strs[i] && *retcode_strs[i] == 'r') {
		pre = addr_var_pre;
		if (opts.do_post)
		    post = addr_var_post;
		whence = PROBEPOINT_READWRITE;
		type = PROBEPOINT_WATCH;
		rstyle = PROBEPOINT_HW;
	    }
	    else if (i < opts.argc && retcode_strs[i] && *retcode_strs[i] == 'o') {
		tmpt = target_lookup_target_id(retcodes[i]);
		if (!tmpt) {
		    verror("No target with ID %d for addr 0x%"PRIxADDR";"
			   " aborting!\n",retcodes[i],paddr);
		    goto err_unreg2;
		}
		pre = addr_var_pre;
		if (opts.do_post)
		    post = addr_var_post;
		whence = PROBEPOINT_WAUTO;
		type = PROBEPOINT_BREAK;
		rstyle = PROBEPOINT_SW;
	    }
	    else {
		whence = PROBEPOINT_EXEC;
		type = PROBEPOINT_BREAK;
		rstyle = PROBEPOINT_FASTEST;
		pre = addr_code_pre;
		if (opts.do_post)
		    post = addr_code_post;
	    }

	    probe = probe_create(tmpt,TID_GLOBAL,NULL,rawaddr,pre,post,NULL,0,1);
	    probe->handler_data = rawaddr;
	    if (!probe)
		goto err_unreg2;

	    if (!probe_register_addr(probe,paddr,type,rstyle,whence,
				     PROBEPOINT_LAUTO,NULL)) {
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
	    if (bsymbol)
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
    tid_t tid;

    while (1) {
	tid = 0;

	if (until_probe) {
	    poll_tv.tv_usec = 10000;
	    tstat = target_poll(t,&poll_tv,NULL,NULL);
	}
	else
	    tstat = target_monitor(t);

	if (tstat == TSTATUS_RUNNING && until_probe)
	    continue;
	else if (tstat == TSTATUS_PAUSED) {
	    tid = target_gettid(t);
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
		if (target_type(t) == TARGET_TYPE_XEN && opts.do_bts) {
		    printf("Disabling BTS at until probe.\n");
		    fflush(stdout);
		    if (target_disable_feature(t,XV_FEATURE_BTS))
			verror("failed to disable BTS!\n");
		}
#endif
		if (opts.until_stop_probing) {
		    printf("Stopping monitoring at until probe.\n");
		    fflush(stdout);
		    tstat = TSTATUS_DONE;
		    goto out;
		}
	    }
	    else if (until_probe)
		goto resume;

	    if (target_type(t) == TARGET_TYPE_PTRACE && linux_userproc_at_syscall(t,tid))
		goto resume;

	    printf("%s thread %"PRIiTID" interrupted at 0x%" PRIxREGVAL "\n",
		   targetstr,tid,target_read_reg(t,tid,CREG_IP));

	    if (!opts.raw && target_type(t) == TARGET_TYPE_PTRACE)
		goto resume;
	    else if (target_type(t) == TARGET_TYPE_XEN) { // && !opts.raw) {
		goto resume;
		//fprintf(stderr,"ERROR: unexpected Xen interrupt; trying to cleanup!\n");
		//goto exit;
	    }
	    else if (word) {
		for (i = 0; i < opts.argc; ++i) {
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
	else if (tstat == TSTATUS_EXITING) {
	    tid = target_gettid(t);
	    printf("%s exiting, removing probes safely...\n",targetstr);
	    cleanup_probes();
	    /* Let it resume to "finish" exiting! */
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
		free(targetstr);
		exit(0);
	    }
	    else if (tstat == TSTATUS_ERROR) {
		printf("%s monitoring failed!\n",targetstr);
		free(targetstr);
		exit(-9);
	    }
	    else {
		printf("%s monitoring failed with %d!\n",targetstr,tstat);
		free(targetstr);
		exit(-10);
	    }
	}
    }

    exit(0);
}
