/*
 * Copyright (c) 2012, 2013, 2014 The University of Utah
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
static int cfi_instrument_block(struct cfi_data *cfi,ADDR target,int isroot);

static int __cfit_stack_makenull(struct cfi_thread_status *cfit) {
    void *addr;
    void *symbol;

    if (array_list_len(cfit->shadow_stack) > 0) {
	addr = array_list_item(cfit->shadow_stack,
			       array_list_len(cfit->shadow_stack) - 1);
	symbol = array_list_item(cfit->shadow_stack_symbols,
				 array_list_len(cfit->shadow_stack_symbols) - 1);

	if (addr == 0 && symbol == NULL) {
	    /*
	     * Do nothing; already were in an untracked bunch of code;
	     * do not push more NULLs.
	     */
	    return 1;
	}
	else {
	    array_list_append(cfit->shadow_stack,NULL);
	    array_list_append(cfit->shadow_stack_symbols,NULL);

	    return 0;
	}
    }
    else {
	array_list_append(cfit->shadow_stack,NULL);
	array_list_append(cfit->shadow_stack_symbols,NULL);

	return 0;
    }
}

static int __cfit_stack_makelastnull(struct cfi_thread_status *cfit) {
    ADDR oldretaddr;
    struct bsymbol *symbol;
    int len;

    len = array_list_len(cfit->shadow_stack);
    if (len > 0) {
	oldretaddr = (ADDR)(uintptr_t)array_list_item(cfit->shadow_stack,len - 1);
	symbol = (struct bsymbol *) \
	    array_list_item(cfit->shadow_stack_symbols,len - 1);

	if (oldretaddr == 0 && symbol == NULL) {
	    if (len > 1) {
		array_list_remove(cfit->shadow_stack);
		array_list_remove(cfit->shadow_stack_symbols);

		--len;

		oldretaddr = (ADDR)(uintptr_t) \
		    array_list_item(cfit->shadow_stack,len - 1);
		symbol = (struct bsymbol *) \
		    array_list_item(cfit->shadow_stack_symbols,len - 1);
	
		vdebug(8,LA_LIB,LF_CFI,
		       "popping retaddr = 0x%"PRIxADDR" (%d) (0x%s);"
		       " replacing with NULL (also skipped a NULL)\n",
		       oldretaddr,array_list_len(cfit->shadow_stack),
		       bsymbol_get_name(symbol));

		array_list_remove(cfit->shadow_stack);
		array_list_remove(cfit->shadow_stack_symbols);

		bsymbol_release(symbol);

		/* Replace it with a NULL, or don't if NULL was there. */
		return __cfit_stack_makenull(cfit);
	    }
	    else {
		/* End of stack is already NULL; leave it alone! */
		return 1;
	    }
	}
	else {
	    vdebug(8,LA_LIB,LF_CFI,
		   "popping retaddr = 0x%"PRIxADDR" (%d) (0x%s);"
		   " replacing with NULL\n",
		   oldretaddr,array_list_len(cfit->shadow_stack),
		   bsymbol_get_name(symbol));

	    array_list_remove(cfit->shadow_stack);
	    array_list_remove(cfit->shadow_stack_symbols);

	    bsymbol_release(symbol);

	    /* Replace it with a NULL, or don't if NULL was there. */
	    return __cfit_stack_makenull(cfit);
	}
    }
    else {
	/* Add a single NULL. */
	return __cfit_stack_makenull(cfit);
    }
}

result_t cfi_dynamic_retaddr_save(struct probe *probe,tid_t tid,void *data,
				  struct probe *trigger,struct probe *base) {
    struct cfi_data *cfi = (struct cfi_data *)data;
    struct cfi_thread_status *cfit;
    REGVAL sp, ip;
    ADDR retaddr;
    struct bsymbol *bsymbol;

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
    if (bsymbol) {
	if (cfi_instrument_func(cfi,bsymbol,0)) {
	    vwarn("tid %d retaddr = 0x%"PRIxADDR" (%d) branch 0x%"PRIxADDR" ->"
		  " 0x%"PRIxADDR" (%s) probe(%s) (trying code block)!\n",
		  tid,retaddr,array_list_len(cfit->shadow_stack),
		  probe_addr(base),ip,bsymbol_get_name(bsymbol),
		  probe_name(base));

	    bsymbol_release(bsymbol);
	    bsymbol = NULL;
	    //__cfit_stack_makenull(cfit);
	}
	else {
	    vdebug(5,LA_LIB,LF_CFI,
		   "tid %d retaddr = 0x%"PRIxADDR" (%d) branch 0x%"PRIxADDR" ->"
		   " 0x%"PRIxADDR" (%s) probe(%s) (tracking)\n",
		   tid,retaddr,array_list_len(cfit->shadow_stack),
		   probe_addr(base),ip,bsymbol_get_name(bsymbol),
		   probe_name(base));

	    /* Since we know that the call is a known function that
	     * we can disasm and instrument return points for, push
	     * it onto the shadow stack!
	     */
	    array_list_append(cfit->shadow_stack,(void *)(uintptr_t)retaddr);
	    array_list_append(cfit->shadow_stack_symbols,bsymbol);
	}
    }

    if (!bsymbol) {
	vdebug(8,LA_LIB,LF_CFI,
	       "tid %d retaddr = 0x%"PRIxADDR" (%d) branch 0x%"PRIxADDR" ->"
	       " 0x%"PRIxADDR" probe(%s) (trying code block)\n",
	       tid,retaddr,array_list_len(cfit->shadow_stack),
	       probe_addr(base),ip,probe_name(base));

	if (cfi_instrument_block(cfi,ip,0)) {
	    vwarn("tid %d could not instrument code block for ip 0x%"PRIxADDR";"
		  " not tracking!\n",tid,ip);

	    __cfit_stack_makenull(cfit);
	}
	else {
	    /*
	     * Since we know that the call is a known code range (even
	     * though we can't find a symbol for it) that we can disasm
	     * and instrument return points for, push it onto the shadow
	     * stack!
	     */
	    array_list_append(cfit->shadow_stack,(void *)(uintptr_t)retaddr);
	    array_list_append(cfit->shadow_stack_symbols,NULL);

	    return 0;
	}
    }

    if (bsymbol)
	bsymbol_release(bsymbol);

    return 0;
}

result_t cfi_dynamic_jmp_target_instr(struct probe *probe,tid_t tid,void *data,
				      struct probe *trigger,struct probe *base) {
    struct cfi_data *cfi = (struct cfi_data *)data;
    struct cfi_thread_status *cfit;
    REGVAL ip;
    struct bsymbol *bsymbol;

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

    /* Grab the current IP -- the post-jmp IP */
    ip = target_read_creg(cfi->target,cfi->tid,CREG_IP);
    if (errno) {
	verror("could not read IP!\n");
	return 0;
    }

    bsymbol = target_lookup_sym_addr(cfi->target,ip);

    if (bsymbol) {
	if (cfi_instrument_func(cfi,bsymbol,0)) {
	    vwarn("tid %d could not instrument branch 0x%"PRIxADDR" -> (0x%"PRIxADDR
		  " (%s); not tracking (removing last call)!\n",
		  tid,probe_addr(base),ip,bsymbol_get_name(bsymbol));

	    bsymbol_release(bsymbol);
	    bsymbol = NULL;

	    /*
	     * XXX XXX XXX
	     * 
	     * In this case, we need to do the third-stack trick of
	     * knowing whether the last non-null was a call, or a jump.
	     * If it was a call, we have to roll it back and put a NULL
	     * in the other stacks.  If it was a jump, we have to trace
	     * back until we hit a function, then remove that one and
	     * put a NULL in its place.
	     */

	    //__cfit_stack_makelastnull(cfit);
	}
    }

    if (!bsymbol) {
	if (cfi_instrument_block(cfi,ip,0)) {
	    vwarn("tid %d could not instrument code block for branch target"
		  " 0x%"PRIxADDR" -> 0x%"PRIxADDR";"
		  " not tracking (removing last call)!\n",
		  tid,probe_addr(base),ip);

	    __cfit_stack_makelastnull(cfit);
	}
    }

    if (bsymbol)
	bsymbol_release(bsymbol);

    return RESULT_SUCCESS;
}

result_t cfi_dynamic_retaddr_check(struct probe *probe,tid_t tid,void *data,
				   struct probe *trigger,struct probe *base) {
    struct cfi_data *cfi = (struct cfi_data *)data;
    struct cfi_thread_status *cfit;
    REGVAL sp;
    ADDR newretaddr;
    ADDR oldretaddr;
    struct bsymbol *symbol;
    struct bsymbol *bsymbol;
    ADDR oldretaddr2;

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
	verror("tid %d could not read retaddr from top of stack!\n",tid);
	array_list_remove(cfit->shadow_stack);
	array_list_remove(cfit->shadow_stack_symbols);
	return RESULT_ERROR;
    }

    if (oldretaddr == 0 && symbol == NULL) {
	/*
	 * This is an "unknown code" that was jumped into and we halted
	 * tracking; so allow this return!
	 */

	oldretaddr2 = (ADDR)(uintptr_t)		\
	    array_list_item(cfit->shadow_stack,
			    array_list_len(cfit->shadow_stack) - 2);

	/*
	 * If we were off in the unknown code region, and are finally
	 * getting back to known code, allow it!  We basically push a
	 * single NULL -- not multiple NULLs -- so we use it as a
	 * placeholder wildcard, almost :).
	 */
	if (oldretaddr2 == newretaddr) {
	    array_list_remove(cfit->shadow_stack);
	    array_list_remove(cfit->shadow_stack_symbols);

	    oldretaddr = (ADDR)(uintptr_t)		\
		array_list_item(cfit->shadow_stack,
				array_list_len(cfit->shadow_stack) - 1);
	    symbol = (struct bsymbol *)				\
		array_list_item(cfit->shadow_stack_symbols,
				array_list_len(cfit->shadow_stack_symbols) - 1);

	    vdebug(8,LA_LIB,LF_CFI,
		   "tid %d leaving untracked sequence; newretaddr = 0x%"PRIxADDR";"
		   " oldretaddr = 0x%"PRIxADDR" (probe %s)!\n",
		   tid,newretaddr,oldretaddr2,probe_name(base));

	    goto cficlean;
	}
	else {
	    vdebug(8,LA_LIB,LF_CFI,
		   "tid %d not leaving untracked sequence; newretaddr = 0x%"PRIxADDR";"
		   " oldretaddr = 0x%"PRIxADDR" (probe %s)!\n",
		   tid,newretaddr,oldretaddr2,probe_name(base));
	    return 0;
	}
    }
    else if (newretaddr != oldretaddr) {
	/*
	 * Check for RET-immediates; if the RET cleans up its stack
	 * *after* reading the retaddr, it is probably really just
	 * jumping elsewhere and cleaning up its current frame and
	 * replacing it with the "jumped"-to addr.  If this is the case,
	 * handle it like we do dynamic jumps, by instrumenting the
	 * jumped-to code.
	 */
	if (g_hash_table_lookup(cfi->ret_immediate_addrs,
				(gpointer)(uintptr_t)probe_addr(base))) {
	    bsymbol = target_lookup_sym_addr(cfi->target,newretaddr);

	    vdebug(5,LA_LIB,LF_CFI,
		   "tid %d retaddr = 0x%"PRIxADDR" (%d) (ret-immediate; oldretaddr ="
		   " 0x%"PRIxADDR") probe %s (0x%"PRIxADDR")\n",
		   tid,newretaddr,array_list_len(cfit->shadow_stack),oldretaddr,
		   probe_name(probe),probe_addr(base));

	    if (bsymbol) {
		if (cfi_instrument_func(cfi,bsymbol,0)) {
		    vwarn("tid %d could not instrument function %s (0x%"PRIxADDR");"
			  " trying code block!\n",
			  tid,bsymbol_get_name(bsymbol),newretaddr);
		    bsymbol_release(bsymbol);
		    bsymbol = NULL;
		}
	    }

	    if (!bsymbol) {
		if (cfi_instrument_block(cfi,newretaddr,0)) {
		    vwarn("tid %d could not instrument code block for RETI"
			  " newretaddr 0x%"PRIxADDR"; not tracking!\n",
			  tid,newretaddr);
		}
	    }

	    if (bsymbol) {
		bsymbol_release(bsymbol);
		bsymbol = NULL;
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

	    cfi->cfi_probe->post_handler(cfi->cfi_probe,tid,
					 cfi->cfi_probe->handler_data,
					 probe,base);

	    cfi->status.isviolation = 0;
	    cfit->status.isviolation = 0;
	    cfi->status.oldretaddr = 0;
	    cfit->status.oldretaddr = 0;
	    cfi->status.newretaddr = 0;
	    cfit->status.newretaddr = 0;

	    ++cfi->status.violations;
	    ++cfit->status.violations;

	    vdebug(5,LA_LIB,LF_CFI,
		   "tid %d retaddr = 0x%"PRIxADDR" (%d) (violation! oldretaddr ="
		   " 0x%"PRIxADDR") probe %s (0x%"PRIxADDR")\n",
		   tid,newretaddr,array_list_len(cfit->shadow_stack),oldretaddr,
		   probe_name(probe),probe_addr(base));

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
    cficlean:
	cfi->status.isviolation = 0;
	cfit->status.isviolation = 0;
	cfi->status.oldretaddr = oldretaddr;
	cfit->status.oldretaddr = oldretaddr;
	cfi->status.newretaddr = newretaddr;
	cfit->status.newretaddr = newretaddr;

	cfi->cfi_probe->pre_handler(cfi->cfi_probe,tid,
				    cfi->cfi_probe->handler_data,
				    probe,base);

	cfi->status.isviolation = 0;
	cfit->status.isviolation = 0;
	cfi->status.oldretaddr = 0;
	cfit->status.oldretaddr = 0;
	cfi->status.newretaddr = 0;
	cfit->status.newretaddr = 0;

	vdebug(5,LA_LIB,LF_CFI,
	       "tid %d retaddr = 0x%"PRIxADDR" (%d) (clean) probe(%s) (0x%"PRIxADDR")\n",
	       tid,newretaddr,array_list_len(cfit->shadow_stack),
	       probe_name(probe),probe_addr(base));
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
    struct target_location_ctxt *tlctxt;

    tlctxt = target_location_ctxt_create_from_bsymbol(cfi->target,cfi->tid,
						      bsymbol);
    if (target_bsymbol_resolve_base(cfi->target,tlctxt,bsymbol,&funcstart,NULL)) {
	verror("could not resolve base addr for function %s!\n",
		bsymbol_get_name(bsymbol));
	target_location_ctxt_free(tlctxt);
	return -1;
    }
    target_location_ctxt_free(tlctxt);

    if (g_hash_table_lookup(cfi->disfuncs_noflow,(gpointer)funcstart))
	return -1;

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
	    cprobe = NULL;
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
		rprobe = NULL;
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
	    jprobe = NULL;
	}
	else {
	    g_hash_table_insert(cfi->probes,(gpointer)jprobe,(gpointer)jprobe);
	    vdebug(5,LA_LIB,LF_CFI,
		   "registered %d jmp probes on %s\n",
		   probe_num_sources(jprobe),probe_name(jprobe));
	}

	/*
	 * If no control flow was found, we have to return to the caller
	 * with an error; we cannot track this function in dynamic CFI.
	 */
	if (!cprobe && !rprobe && !jprobe) {
	    array_list_free(pds.absolute_branch_targets);

	    g_hash_table_insert(cfi->disfuncs_noflow,
				(gpointer)funcstart,(gpointer)1);

	    return -3;
	}
	else 
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

		if (absolute_branch_symbol) {
		    if (cfi_instrument_func(cfi,absolute_branch_symbol,0)) {
			vdebug(8,LA_LIB,LF_CFI,
			       "could not find symbol for ip 0x%"PRIxADDR" (%s);"
			       " trying code block!\n",
			       absolute_branch_addr,
			       bsymbol_get_name(absolute_branch_symbol));
			bsymbol_release(absolute_branch_symbol);
			absolute_branch_symbol = NULL;
		    }
		}

		if (!absolute_branch_symbol) {
		    if (cfi_instrument_block(cfi,absolute_branch_addr,0)) {
			vwarn("could not instrument block for addr 0x%"PRIxADDR";"
			      " CFI might be BUGGY!\n",
			      absolute_branch_addr);
		    }
		}

		if (absolute_branch_symbol)
		    bsymbol_release(absolute_branch_symbol);
	    }
	}
	array_list_free(pds.absolute_branch_targets);
    }

    return 0;
}

static int cfi_instrument_block(struct cfi_data *cfi,ADDR ip,int isroot) {
    ADDR start = 0,end = 0;
    int bufsiz;
    char *buf;
    struct probe *cprobe = NULL;
    struct probe *rprobe = NULL;
    struct probe *jprobe = NULL;
    struct cfi_probe_disasm_state pds;
    struct bsymbol *absolute_branch_symbol;
    ADDR absolute_branch_addr;
    int i;
    void *item;

    if (target_lookup_safe_disasm_range(cfi->target,ip,&start,&end,NULL)) {
	verror("no safe disasm range contains target ip 0x%"PRIxADDR"!\n",ip);
	return -1;
    }

    if (g_hash_table_lookup(cfi->disfuncs_noflow,(gpointer)start))
	return -1;

    /* Probe the called-into block if we haven't already! */
    if (!g_hash_table_lookup(cfi->disfuncs,(gpointer)start)) {
	bufsiz = sizeof("call_in_") + sizeof(ADDR) * 2 + 1;
	buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"call_in_%"PRIxADDR,start);

	cprobe = probe_create(cfi->target,cfi->tid,NULL,buf,NULL,
			      cfi_dynamic_retaddr_save,cfi,0,0);
	free(buf);

	if (!isroot) {
	    bufsiz = sizeof("ret_in_") + sizeof(ADDR) * 2 + 1;
	    buf = malloc(bufsiz);
	    snprintf(buf,bufsiz,"ret_in_%"PRIxADDR,start);

	    rprobe = probe_create(cfi->target,cfi->tid,NULL,buf,
				  cfi_dynamic_retaddr_check,NULL,cfi,0,0);
	    free(buf);
	}

	bufsiz = sizeof("jmp_in_") + sizeof(ADDR) * 2 + 1;
	buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"jmp_in_%"PRIxADDR,start);

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
	    if (!probe_register_block_instrs(cfi->target,start,end,
					     PROBEPOINT_SW,1,
					     cfi_probe_disasm_handler,&pds,
					     INST_CALL,cprobe,
					     INST_JMP,jprobe,
					     INST_NONE)) {
		probe_free(cprobe,1);
		return -2;
	    }
	}
	else {
	    if (!probe_register_block_instrs(cfi->target,start,end,
					     PROBEPOINT_SW,1,
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
	    cprobe = NULL;
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
		rprobe = NULL;
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
	    jprobe = NULL;
	}
	else {
	    g_hash_table_insert(cfi->probes,(gpointer)jprobe,(gpointer)jprobe);
	    vdebug(5,LA_LIB,LF_CFI,
		   "registered %d jmp probes on %s\n",
		   probe_num_sources(jprobe),probe_name(jprobe));
	}

	/*
	 * If no control flow was found, we have to return to the caller
	 * with an error; we cannot track this function in dynamic CFI.
	 */
	if (!cprobe && !rprobe && !jprobe) {
	    array_list_free(pds.absolute_branch_targets);

	    g_hash_table_insert(cfi->disfuncs_noflow,
				(gpointer)start,(gpointer)1);

	    return -3;
	}
	else 
	    g_hash_table_insert(cfi->disfuncs,(gpointer)start,(gpointer)1);

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

		if (absolute_branch_symbol) {
		    if (cfi_instrument_func(cfi,absolute_branch_symbol,0)) {
			vdebug(8,LA_LIB,LF_CFI,
			       "could not find symbol for ip 0x%"PRIxADDR" (%s);"
			       " trying code block!\n",
			       absolute_branch_addr,
			       bsymbol_get_name(absolute_branch_symbol));
			bsymbol_release(absolute_branch_symbol);
			absolute_branch_symbol = NULL;
		    }
		}

		if (!absolute_branch_symbol) {
		    if (cfi_instrument_block(cfi,absolute_branch_addr,0)) {
			vwarn("could not instrument block for addr 0x%"PRIxADDR";"
			      " CFI might be BUGGY!\n",
			      absolute_branch_addr);
		    }
		}

		if (absolute_branch_symbol)
		    bsymbol_release(absolute_branch_symbol);
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
	array_list_foreach(tdata->shadow_stack_symbols,i,symbol) {
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

char *cfi_thread_backtrace(struct cfi_data *cfi,struct cfi_thread_status *cts,
			   char *sep) {
    char *buf;
    int buflen;
    int rc = 0, rcr;
    ADDR base;
    struct bsymbol *function;
    char *name;
    void *retaddr;
    int i;
    int alen;
    struct target_location_ctxt *tlctxt;

    if (!sep)
	sep = " | ";

    buflen = 0;
    // 0xRETADDR <name> 0xBASEADDR | 
    buflen += array_list_len(cts->shadow_stack) * (sizeof(ADDR) * 4 + 8 + 3);
    array_list_foreach(cts->shadow_stack_symbols,i,function) {
	if (!function)
	    buflen += 4; // NULL
	else if (bsymbol_get_name(function))
	    buflen += strlen(bsymbol_get_name(function));
	else
	    buflen += 4; // NULL
    }
    buflen += 1; // '\0'

    buf = malloc(buflen);
    alen = array_list_len(cts->shadow_stack);
    array_list_foreach(cts->shadow_stack,i,retaddr) {
	function = (struct bsymbol *)array_list_item(cts->shadow_stack_symbols,i);
	name = NULL;
	base = 0;
	if (function) {
	    name = bsymbol_get_name(function);
	    tlctxt = target_location_ctxt_create_from_bsymbol(cfi->target,cfi->tid,
							      function);
	    target_bsymbol_resolve_base(cfi->target,tlctxt,function,&base,NULL);
	    target_location_ctxt_free(tlctxt);
	}
	if (!name)
	    name = "<UNKNOWN>";

	rcr = snprintf(buf + rc,buflen - rc,
		       "0x%"PRIxADDR" %s 0x%"PRIxADDR,
		       (ADDR)(uintptr_t)retaddr,name,base);
	rc += rcr;
	if ((i + 1) < alen) {
	    rcr = snprintf(buf + rc,buflen - rc,"%s",sep);
	    rc += rcr;
	}
    }
    if (rc > buflen)
	buf[buflen - 1] = '\0';
    else
	buf[rc] = '\0';

    return buf;
}

struct probe *probe_cfi(struct target *target,tid_t tid,
			cfi_mode_t mode,cfi_flags_t flags,
			struct array_list *root_functions,
			struct array_list *root_addrs,
			probe_handler_t pre_handler,probe_handler_t post_handler,
			void *handler_data) {
    struct cfi_data *cfi;
    struct probe *cfi_probe;
    char namebuf[64];
    int i;
    struct bsymbol *function;
    ADDR addr;

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
    cfi->disfuncs_noflow = g_hash_table_new(g_direct_hash,g_direct_equal);
    cfi->probes = g_hash_table_new(g_direct_hash,g_direct_equal);
    cfi->thread_status = g_hash_table_new(g_direct_hash,g_direct_equal);
    cfi->ret_immediate_addrs = g_hash_table_new(g_direct_hash,g_direct_equal);

    /*
     * Just instrument all the functions and addrs!  If we fail, then free the
     * whole probe and return.
     */
    if (root_functions) {
	array_list_foreach(root_functions,i,function) {
	    if (cfi_instrument_func(cfi,function,1)) {
		probe_free(cfi_probe,1);
		return NULL;
	    }
	}
    }
    if (root_addrs) {
	array_list_foreach_fakeptr_t(root_addrs,i,addr,uintptr_t) {
	    if (cfi_instrument_block(cfi,addr,1)) {
		probe_free(cfi_probe,1);
		return NULL;
	    }
	}
    }

    return cfi_probe;
}


