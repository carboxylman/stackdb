/*
 * Copyright (c) 2012, 2013 The University of Utah
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
#include <errno.h>

#include "log.h"
#include "cfi.h"
#include "probe_api.h"
#include "probe.h"
#include "target.h"
#include "target_api.h"
#include "disasm.h"

static int cfi_instrument_func(struct cfi_data *cfi,struct bsymbol *bsymbol,
			       int isroot);

result_t cfi_dynamic_retaddr_save(struct probe *probe,void *data,
				  struct probe *trigger) {
    struct cfi_data *cfi = (struct cfi_data *)data;
    struct cfi_thread_status *cfit;
    REGVAL sp, ip;
    ADDR retaddr;
    tid_t tid;
    struct bsymbol *bsymbol;

    tid = target_gettid(cfi->target);

    if (cfi->tid != TID_GLOBAL && tid != cfi->tid) {
	vdebug(8,LA_LIB,LF_CFI,
	       "skipping cfi probe in tid %d that is not our tid (%d)\n",
	       tid,cfi->tid);
	return 0;
    }

    cfit = (struct cfi_thread_status *) \
	g_hash_table_lookup(cfi->thread_status,(gpointer)(uintptr_t)tid);
    if (!cfit) {
	cfit = calloc(1,sizeof(*cfit));
	cfit->shadow_stack = array_list_create(16);
	cfit->shadow_stack_symbols = array_list_create(16);
	g_hash_table_insert(cfi->thread_status,(gpointer)(uintptr_t)tid,cfit);
    }

    errno = 0;
    sp = target_read_creg(cfi->target,cfi->tid,CREG_SP);
    if (errno) {
	verror("could not read SP!\n");
	return RESULT_ERROR;
    }

    /* Grab the return address on the top of the stack */
    retaddr = 0;
    if (!target_read_addr(cfi->target,(ADDR)sp,sizeof(ADDR),
			  (unsigned char *)&retaddr)) {
	verror("could not read top of stack!\n");
	return 0;
    }

    /* Grab the current IP -- the post-call IP */
    ip = target_read_creg(cfi->target,cfi->tid,CREG_IP);
    if (errno) {
	verror("could not read IP!\n");
	return 0;
    }

    bsymbol = target_lookup_sym_addr(cfi->target,ip);
    if (!bsymbol) {
	vdebug(5,LA_LIB,LF_CFI,
	       "probe(%s) branch 0x%"PRIxADDR" -> 0x%"PRIxADDR" (unknown!):"
	       " retaddr = 0x%"PRIxADDR" (stack depth = %d)\n",
	       probe_name(probe),probe_addr(probe),ip,
	       retaddr,array_list_len(cfit->shadow_stack));

	/*
	 * XXX: try to instrument the target address, even if we don't
	 * have a symbol for it.
	 */

	return RESULT_SUCCESS;
    }
    else {
	vdebug(5,LA_LIB,LF_CFI,
	       "probe(%s) branch 0x%"PRIxADDR" -> 0x%"PRIxADDR" (%s):"
	       " retaddr = 0x%"PRIxADDR" (stack depth = %d)\n",
	       probe_name(probe),probe_addr(probe),ip,bsymbol_get_name(bsymbol),
	       retaddr,array_list_len(cfit->shadow_stack));
    }

    /* Since we know that the call is a known function that we can
     * disasm and instrument return points for, push it onto the shadow
     * stack!
     */
    array_list_append(cfit->shadow_stack,(void *)(uintptr_t)retaddr);
    array_list_append(cfit->shadow_stack_symbols,bsymbol);

    if (!(cfi->flags & CFI_NOAUTOFOLLOW)) {
	if (bsymbol) {
	    cfi_instrument_func(cfi,bsymbol,0);
	    //bsymbol_release(bsymbol);
	}
	else {
	    /* XXX: instrument addrs */
	    vwarn("could not resolve symbol for 0x%"PRIxADDR"; not tracking!\n",
		  ip);
	}
    }

    //bsymbol_release(bsymbol);

    return 0;
}

result_t cfi_dynamic_jmp_target_instr(struct probe *probe,void *data,
				      struct probe *trigger) {
    struct cfi_data *cfi = (struct cfi_data *)data;
    tid_t tid;
    REGVAL ip;
    struct bsymbol *bsymbol;

    tid = target_gettid(cfi->target);

    if (cfi->tid != TID_GLOBAL && tid != cfi->tid) {
	vdebug(8,LA_LIB,LF_CFI,
	       "skipping cfi probe in tid %d that is not our tid (%d)\n",
	       tid,cfi->tid);
	return 0;
    }

    /* Grab the current IP -- the post-jmp IP */
    ip = target_read_creg(cfi->target,cfi->tid,CREG_IP);
    if (errno) {
	verror("could not read IP!\n");
	return 0;
    }

    bsymbol = target_lookup_sym_addr(cfi->target,ip);

    if (bsymbol) {
	cfi_instrument_func(cfi,bsymbol,0);
	bsymbol_release(bsymbol);
    }
    else {
	/* XXX: instrument addrs */
	vwarn("could not resolve symbol for 0x%"PRIxADDR"; not tracking!\n",
	      ip);
    }

    return RESULT_SUCCESS;
}

result_t cfi_dynamic_retaddr_check(struct probe *probe,void *data,
				   struct probe *trigger) {
    struct cfi_data *cfi = (struct cfi_data *)data;
    struct cfi_thread_status *cfit;
    REGVAL sp;
    ADDR newretaddr;
    ADDR oldretaddr;
    tid_t tid;
    result_t retval;
    struct bsymbol *symbol;
    struct bsymbol *bsymbol;

    tid = target_gettid(cfi->target);

    if (cfi->tid != TID_GLOBAL && tid != cfi->tid) {
	vdebug(8,LA_LIB,LF_CFI,
	       "skipping cfi probe in tid %d that is not our tid (%d)\n",
	       tid,cfi->tid);
	return 0;
    }

    cfit = (struct cfi_thread_status *) \
	g_hash_table_lookup(cfi->thread_status,(gpointer)(uintptr_t)tid);
    if (!cfit) {
	cfit = calloc(1,sizeof(*cfit));
	cfit->shadow_stack = array_list_create(16);
	cfit->shadow_stack_symbols = array_list_create(16);
	g_hash_table_insert(cfi->thread_status,(gpointer)(uintptr_t)tid,cfit);
    }

    /* These are probably from functions we instrumented, but
     * that were not called from our function root set.
     */
    if (array_list_len(cfit->shadow_stack) == 0) {
	++cfi->status.nonrootsethits;
	++cfit->status.nonrootsethits;
	return RESULT_SUCCESS;
    }

    errno = 0;
    sp = target_read_creg(cfi->target,cfi->tid,CREG_SP);
    if (errno) {
	verror("could not read SP!\n");
	return RESULT_ERROR;
    }

    oldretaddr = (ADDR)(uintptr_t) \
	array_list_item(cfit->shadow_stack,
			array_list_len(cfit->shadow_stack) - 1);
    symbol = (struct bsymbol *) \
	array_list_item(cfit->shadow_stack_symbols,
			array_list_len(cfit->shadow_stack_symbols) - 1);

    if (!target_read_addr(cfi->target,(ADDR)sp,sizeof(ADDR),
			  (unsigned char *)&newretaddr)) {
	verror("could not read retaddr from top of stack!\n");
	array_list_remove(cfit->shadow_stack);
	array_list_remove(cfit->shadow_stack_symbols);
	return RESULT_ERROR;
    }

    if (newretaddr != oldretaddr) {
	/*
	 * Check for RET-immediates; if the RET cleans up its stack
	 * *after* reading the retaddr, it is probably really just
	 * jumping elsewhere and cleaning up its current frame and
	 * replacing it with the "jumped"-to addr.  If this is the case,
	 * handle it like we do dynamic jumps, by instrumenting the
	 * jumped-to code.
	 */
	if (g_hash_table_lookup(cfi->ret_immediate_addrs,
				(gpointer)(uintptr_t)probe_addr(trigger))) {
	    bsymbol = target_lookup_sym_addr(cfi->target,newretaddr);

	    if (bsymbol) {
		cfi_instrument_func(cfi,bsymbol,0);
		bsymbol_release(bsymbol);
	    }
	    else {
		/* XXX: instrument addrs */
		vwarn("could not resolve symbol for 0x%"PRIxADDR";"
		      " not tracking!\n",newretaddr);
	    }

	    return 0;
	}
	else {
	    cfi->status.isviolation = 1;
	    cfit->status.isviolation = 1;
	    cfi->status.oldretaddr = oldretaddr;
	    cfit->status.oldretaddr = oldretaddr;
	    cfi->status.newretaddr = newretaddr;
	    cfit->status.newretaddr = newretaddr;

	    retval = cfi->cfi_probe->post_handler(cfi->cfi_probe,
						  cfi->cfi_probe->handler_data,
						  trigger);

	    cfi->status.isviolation = 0;
	    cfit->status.isviolation = 0;
	    cfi->status.oldretaddr = 0;
	    cfit->status.oldretaddr = 0;
	    cfi->status.newretaddr = 0;
	    cfit->status.newretaddr = 0;

	    ++cfi->status.violations;
	    ++cfit->status.violations;

	    vdebug(5,LA_LIB,LF_CFI,
		   "probe %s (0x%"PRIxADDR") detected CFI violation:"
		   " newretaddr = 0x%"PRIxADDR"; oldretaddr = 0x%"PRIxADDR
		   " (stack depth = %d)!\n",
		   probe_name(probe),probe_addr(probe),
		   newretaddr,oldretaddr,array_list_len(cfit->shadow_stack));

	    /*
	     * Maybe try to fix the stack; probably won't work that well :)
	     */
	    if (cfi->flags & CFI_FIXUP) {
		if (!target_write_addr(cfi->target,(ADDR)sp,sizeof(ADDR),
				       (unsigned char *)&oldretaddr)) {
		    verror("could not fixup top of stack in retaddr_check!\n");
		}
		else 
		    vdebug(5,LA_LIB,LF_CFI,"reset stack after corruption!\n");
	    }
	}
    }
    else {
	cfi->status.isviolation = 0;
	cfit->status.isviolation = 0;
	cfi->status.oldretaddr = oldretaddr;
	cfit->status.oldretaddr = oldretaddr;
	cfi->status.newretaddr = newretaddr;
	cfit->status.newretaddr = newretaddr;

	retval = cfi->cfi_probe->pre_handler(cfi->cfi_probe,
					     cfi->cfi_probe->handler_data,
					     trigger);

	cfi->status.isviolation = 0;
	cfit->status.isviolation = 0;
	cfi->status.oldretaddr = 0;
	cfit->status.oldretaddr = 0;
	cfi->status.newretaddr = 0;
	cfit->status.newretaddr = 0;

	vdebug(5,LA_LIB,LF_CFI,
		"probe %s (0x%"PRIxADDR") detected proper CFI:"
	       " newretaddr = 0x%"PRIxADDR"; oldretaddr = 0x%"PRIxADDR
	       " (stack depth = %d)!\n",
	       probe_name(probe),probe_addr(probe),
	       newretaddr,oldretaddr,array_list_len(cfit->shadow_stack));
    }

    /*
     * Wait to free the retaddr and release the symbol until we have
     * called the handlers.
     */
    array_list_remove(cfit->shadow_stack);
    if (symbol)
	bsymbol_release(symbol);
    array_list_remove(cfit->shadow_stack_symbols);

    return 0;
}

struct cfi_probe_disasm_state {
    struct cfi_data *cfi;
    struct array_list *absolute_branch_targets;
};

static int cfi_probe_disasm_handler(struct cf_inst_data *id,ADDR iaddr,
				    void *handler_data,
				    struct probe **probe_alt) {
    struct cfi_probe_disasm_state *s = \
	(struct cfi_probe_disasm_state *)handler_data;

    /*
     * If this is a jump instr, and it has an absolute target address,
     * add that address to our list -- AND DO NOT probe on it!  Also
     * don't probe on any jump target that is in the disasm segment;
     * those don't "go" anywhere :).
     */
    if (id->type == INST_JMP || id->type == INST_JCC) {
	if (id->cf.target_in_segment)
	    return 0;
	else if (id->cf.target_is_valid) {
	    array_list_append(s->absolute_branch_targets,
			      (void *)(uintptr_t)id->cf.target);
	    return 0;
	}
    }
    /*
     * If this is a RET that reads its retaddr off stack top, THEN
     * adjusts the stack to clear the current frame -- assume it is
     * "returning" into or to another function; so we need a different
     * probe handler than the normal ret handler.  Basically, our
     * handler needs to grab the retaddr; if it agrees, assume a normal
     * return; if it does not agree, then assume a *valid* control
     * transfer to another function, and add that function to our
     * tracked set.
     */
    else if (id->type == INST_RET && id->size == 3) {
	if (!(s->cfi->flags & CFI_NOAUTOFOLLOW)) {
	    g_hash_table_insert(s->cfi->ret_immediate_addrs,
				(gpointer)(uintptr_t)iaddr,(gpointer)1);
	    return 1;
	}
    }

    return 1;
}

static int cfi_instrument_func(struct cfi_data *cfi,struct bsymbol *bsymbol,
			       int isroot) {
    ADDR funcstart = 0;
    int bufsiz;
    char *buf;
    struct probe *cprobe = NULL;
    struct probe *rprobe = NULL;
    struct probe *jprobe = NULL;
    char *name;
    struct cfi_probe_disasm_state pds;
    struct bsymbol *absolute_branch_symbol;
    ADDR absolute_branch_addr;
    int i;
    void *item;

    if (location_resolve_symbol_base(cfi->target,cfi->tid,bsymbol,&funcstart,
				     NULL)) {
	verror("could not resolve base addr for function %s!\n",
		bsymbol->lsymbol->symbol->name);
	return -1;
    }

    /* Disassemble the called function if we haven't already! */
    if (!g_hash_table_lookup(cfi->disfuncs,(gpointer)funcstart)) {
	/* Dissasemble the function and grab a list of
	 * RET instrs, and insert more child
	 * breakpoints.
	 */
	name = bsymbol_get_name(bsymbol);
	if (name) {
	    bufsiz = sizeof("call_in_") + strlen(name) + 1;
	    buf = malloc(bufsiz);
	    snprintf(buf,bufsiz,"call_in_%s",name);
	}
	else {
	    bufsiz = sizeof("call_in_") + sizeof(ADDR) * 2 + 1;
	    buf = malloc(bufsiz);
	    snprintf(buf,bufsiz,"call_in_%"PRIxADDR,funcstart);
	}

	cprobe = probe_create(cfi->target,cfi->tid,NULL,buf,NULL,
			      cfi_dynamic_retaddr_save,cfi,0,0);
	free(buf);

	if (!isroot) {
	    if (name) {
		bufsiz = sizeof("ret_in_") + strlen(name) + 1;
		buf = malloc(bufsiz);
		snprintf(buf,bufsiz,"ret_in_%s",name);
	    }
	    else {
		bufsiz = sizeof("ret_in_") + sizeof(ADDR) * 2 + 1;
		buf = malloc(bufsiz);
		snprintf(buf,bufsiz,"ret_in_%"PRIxADDR,funcstart);
	    }

	    rprobe = probe_create(cfi->target,cfi->tid,NULL,buf,
				  cfi_dynamic_retaddr_check,NULL,cfi,0,0);
	    free(buf);
	}

	if (name) {
	    bufsiz = sizeof("jmp_in_") + strlen(name) + 1;
	    buf = malloc(bufsiz);
	    snprintf(buf,bufsiz,"jmp_in_%s",name);
	}
	else {
	    bufsiz = sizeof("jmp_in_") + sizeof(ADDR) * 2 + 1;
	    buf = malloc(bufsiz);
	    snprintf(buf,bufsiz,"jmp_in_%"PRIxADDR,funcstart);
	}

	jprobe = probe_create(cfi->target,cfi->tid,NULL,buf,NULL,
			      cfi_dynamic_jmp_target_instr,cfi,0,0);
	free(buf);

	pds.absolute_branch_targets = array_list_create(0);
	pds.cfi = cfi;

	/*
	 * XXX: can we do this optimization; suppose one of our root
	 * functions is not really a root, but is called by another
	 * function it itself calls.  So we have to catch these RETs
	 * too.
	 *
	 * ???
	 */

	if (isroot) {
	    if (!probe_register_function_instrs(bsymbol,PROBEPOINT_SW,1,
						cfi_probe_disasm_handler,&pds,
						INST_CALL,cprobe,
						INST_JMP,jprobe,
						INST_NONE)) {
		probe_free(cprobe,1);
		return -2;
	    }
	}
	else {
	    if (!probe_register_function_instrs(bsymbol,PROBEPOINT_SW,1,
						cfi_probe_disasm_handler,&pds,
						INST_RET,rprobe,
						INST_CALL,cprobe,
						INST_JMP,jprobe,
						INST_NONE)) {
		probe_free(cprobe,1);
		probe_free(rprobe,1);
		return -2;
	    }
	}

	if (probe_num_sources(cprobe) == 0) {
	    vdebug(5,LA_LIB,LF_CFI,
		   "no call sites in %s; removing\n",probe_name(cprobe));
	    probe_free(cprobe,1);
	}
	else {
	    g_hash_table_insert(cfi->probes,(gpointer)cprobe,(gpointer)cprobe);
	    vdebug(5,LA_LIB,LF_CFI,
		   "registered %d call probes on %s\n",
		   probe_num_sources(cprobe),probe_name(cprobe));
	}

	if (!isroot) {
	    /*
	     * If the function does not have any exit points, don't
	     * bother tracking calls to it!
	     */
	    if (probe_num_sources(rprobe) == 0) {
		vdebug(5,LA_LIB,LF_CFI,
		       "no return sites in %s; removing\n",probe_name(rprobe));
		probe_free(rprobe,1);
	    }
	    else {
		g_hash_table_insert(cfi->probes,(gpointer)rprobe,(gpointer)rprobe);
		vdebug(5,LA_LIB,LF_CFI,
		       "registered %d return probes on %s\n",
		       probe_num_sources(rprobe),probe_name(rprobe));
	    }
	}

	if (probe_num_sources(jprobe) == 0) {
	    vdebug(5,LA_LIB,LF_CFI,
		   "no indirect jmp sites in %s; removing\n",probe_name(jprobe));
	    probe_free(jprobe,1);
	}
	else {
	    g_hash_table_insert(cfi->probes,(gpointer)jprobe,(gpointer)jprobe);
	    vdebug(5,LA_LIB,LF_CFI,
		   "registered %d jmp probes on %s\n",
		   probe_num_sources(jprobe),probe_name(jprobe));
	}

	g_hash_table_insert(cfi->disfuncs,(gpointer)funcstart,(gpointer)1);

	/*
	 * If the function had absolute jump targets outside of it, we
	 * have to instrument the blocks containing those things too!
	 *
	 * NB: this MUST come last (esp after the cfi->disfuncs
	 * insertion above)!  Otherwise, there is a risk of infinite
	 * recursion.
	 */
	if (array_list_len(pds.absolute_branch_targets) > 0) {
	    array_list_foreach(pds.absolute_branch_targets,i,item) {
		absolute_branch_addr = (ADDR)item;
		absolute_branch_symbol = 
		    target_lookup_sym_addr(cfi->target,absolute_branch_addr);
		if (!absolute_branch_symbol) {
		    vwarn("could not find symbol for 0x%"PRIxADDR"; skipping;"
			  " CFI might be BUGGY!\n",absolute_branch_addr);
		}
		else {
		    cfi_instrument_func(cfi,absolute_branch_symbol,0);
		    bsymbol_release(absolute_branch_symbol);
		}
	    }
	}
	array_list_free(pds.absolute_branch_targets);
    }

    return 0;
}

const char *probe_gettype_cfi(struct probe *probe) {
    return "cfi";
}

void *probe_summarize_cfi(struct probe *probe) {
    return &((struct cfi_data *)(probe->priv))->status;
}

void *probe_summarize_tid_cfi(struct probe *probe,tid_t tid) {
    struct cfi_data *cfi = (struct cfi_data *)probe->priv;
    struct cfi_thread_status *ts;

    if (!cfi)
	return NULL;

    ts = (struct cfi_thread_status *) \
	g_hash_table_lookup(cfi->thread_status,(gpointer)(uintptr_t)tid);

    return ts;
}

int probe_fini_cfi(struct probe *probe) {
    struct cfi_data *cfi = (struct cfi_data *)probe->priv;
    GHashTableIter iter;
    struct probe *tprobe;
    struct cfi_thread_status *tdata;
    struct bsymbol *symbol;
    int i;

    g_hash_table_destroy(cfi->disfuncs);
    g_hash_table_destroy(cfi->ret_immediate_addrs);

    g_hash_table_iter_init(&iter,cfi->probes);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&tprobe)) {
	probe_free(tprobe,0);
    }
    g_hash_table_destroy(cfi->probes);

    g_hash_table_iter_init(&iter,cfi->thread_status);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&tdata)) {
	array_list_free(tdata->shadow_stack);
	array_list_foreach(tdata->shadow_stack,i,symbol) {
	    if (symbol)
		bsymbol_release(symbol);
	}
	array_list_free(tdata->shadow_stack_symbols);
	free(tdata);
    }
    g_hash_table_destroy(cfi->thread_status);

    free(cfi);

    return 0;
}

static struct probe_ops probe_ops_cfi = {
    .gettype = probe_gettype_cfi,
    .summarize = probe_summarize_cfi,
    .summarize_tid = probe_summarize_tid_cfi,
    .fini = probe_fini_cfi,
};

struct probe *probe_cfi(struct target *target,tid_t tid,
			cfi_mode_t mode,cfi_flags_t flags,
			struct array_list *root_functions,
			probe_handler_t pre_handler,probe_handler_t post_handler,
			void *handler_data) {
    struct cfi_data *cfi;
    struct probe *cfi_probe;
    char namebuf[64];
    int i;
    struct bsymbol *function;

    /*
     * Only dynamic for now; see cfi.h .
     */
    if (mode != CFI_DYNAMIC) {
	verror("unsupported CFI mode %d!\n",mode);
	return NULL;
    }

    if (flags & CFI_SINGLESTEP_UNKNOWN) {
	vwarn("unsupported SINGLESTEP_UNKNOWN option!\n");
    }

    if (tid != TID_GLOBAL) {
	vwarn("CFI with specific thread %d might be buggy!\n",tid);
    }

    cfi = (struct cfi_data *)calloc(1,sizeof(*cfi));
    snprintf(namebuf,64,"cfi(target %d tid %d)",target->id,tid);

    cfi_probe = 
	probe_create(target,tid,&probe_ops_cfi,namebuf,
		     pre_handler ? pre_handler : probe_do_sink_pre_handlers,
		     post_handler ? post_handler : probe_do_sink_post_handlers,
		     handler_data,0,1);
    cfi_probe->priv = cfi;
    cfi->cfi_probe = cfi_probe;
    cfi->mode = mode;
    cfi->flags = flags;
    cfi->target = target;
    cfi->tid = tid;

    cfi->disfuncs = g_hash_table_new(g_direct_hash,g_direct_equal);
    cfi->probes = g_hash_table_new(g_direct_hash,g_direct_equal);
    cfi->thread_status = g_hash_table_new(g_direct_hash,g_direct_equal);
    cfi->ret_immediate_addrs = g_hash_table_new(g_direct_hash,g_direct_equal);

    /*
     * Just instrument all the functions!  If we fail, then free the
     * whole probe and return.
     */
    array_list_foreach(root_functions,i,function) {
	if (cfi_instrument_func(cfi,function,1)) {
	    probe_free(cfi_probe,1);
	    return NULL;
	}
    }

    return cfi_probe;
}


