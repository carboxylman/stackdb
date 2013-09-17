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

#include "rop.h"
#include "probe_api.h"
#include "probe.h"
#include "target.h"
#include "target_api.h"
#include "disasm.h"

void rop_gadget_free(void *value) {
    struct rop_gadget *rg = (struct rop_gadget *)value;
    if (rg->meta)
	free(rg->meta);
    free(rg);
}

GHashTable *rop_load_gadget_stream(FILE *stream) {
    GHashTable *retval;
    struct rop_gadget *rg;
    int rc;

    retval = g_hash_table_new_full(g_direct_hash,g_direct_equal,
				   /* Just free gadgets, not keys */
				   NULL,rop_gadget_free);

    rg = (struct rop_gadget *)calloc(1,sizeof(*rg));
    errno = 0;
    while ((rc = fscanf(stream,"%"PRIxADDR",%"PRIxADDR" %as",
			&rg->start,&rg->end,&rg->meta)) != EOF) {
	if (rc <= 0 && errno) {
	    if (rc != EAGAIN && rc != EINTR) {
		verror("fscanf: %s\n",strerror(errno));
		return retval;
	    }
	}
	else if (rc == 0) {
	    verror("fscanf: no items matched! (%s)\n",strerror(errno));
	    return retval;
	}
	else if (rc < 2) {
	    verror("Bad line in rop_gadget stream!\n");
	    rg->meta = NULL;
	}
	else {
	    g_hash_table_insert(retval,(gpointer)rg->start,rg);
	    rg = (struct rop_gadget *)calloc(1,sizeof(*rg));
	}
	errno = 0;
    }
    free(rg);

    return retval;
}

GHashTable *rop_load_gadget_file(char *filename) {
    GHashTable *retval;
    FILE *f;
    struct rop_gadget *rg;
    int rc;

    if (!(f = fopen(filename,"r"))) {
	verror("fopen(%s): %s\n",filename,strerror(errno));
	return NULL;
    }

    retval = g_hash_table_new_full(g_direct_hash,g_direct_equal,
				   /* Just free gadgets, not keys */
				   NULL,rop_gadget_free);

    rg = (struct rop_gadget *)calloc(1,sizeof(*rg));
    while ((rc = fscanf(f,"%"PRIxADDR",%"PRIxADDR" %as",
			&rg->start,&rg->end,&rg->meta)) != EOF) {
	if (rc < 2) {
	    verror("Bad line in rop_gadget file %s!\n",filename);
	    rg->meta = NULL;
	}
	else {
	    g_hash_table_insert(retval,(gpointer)rg->start,rg);
	    rg = (struct rop_gadget *)calloc(1,sizeof(*rg));
	}
    }
    free(rg);

    fclose(f);

    return retval;
}

const char *probe_gettype_rop_checkret(struct probe *probe) {
    return "rop_checkret";
}

void *probe_summarize_rop_checkret(struct probe *probe) {
    return &((struct rop_checkret_data *)(probe->priv))->status;
}

int probe_fini_rop_checkret(struct probe *probe) {
    struct rop_checkret_data *rop_data = \
	(struct rop_checkret_data *)probe->priv;

    if (rop_data->cont_probe) {
	probe_unregister(rop_data->cont_probe,0);
	probe_free(rop_data->cont_probe,0);
    }
    if (rop_data->entry_probe) {
	probe_unregister(rop_data->entry_probe,0);
	probe_free(rop_data->entry_probe,0);
    }
    if (rop_data->ret_probe) {
	probe_unregister(rop_data->ret_probe,0);
	probe_free(rop_data->ret_probe,0);
    }

    free(rop_data);

    return 0;
}

static struct probe_ops probe_ops_rop_checkret = {
    .gettype = probe_gettype_rop_checkret,
    .summarize = probe_summarize_rop_checkret,
    .fini = probe_fini_rop_checkret,
};

/*
 * How a ROP gadget can be:
 *  1) gadget starts at real, and ends at real
 *  2) gadget starts in mid of real instr, then ends with real ret
 *  3) gadget starts in mid of real instr, then ends inside a real instr
 *
 *
 * To probe a gadget:
 * 
  - disasm all the way from the containing symbol, then
  - disasm gadget instrs only
  - if gadget is inside a "real" instr, break on head of real instr and
    on gadget head
    - if arrive at real head, remove both real head and gadget head,
      single, and proceed.
    - XXX: should we try to handle this in probe, or let a probe
      handler's function do the gadget remove?  Probably the latter for now.
  - else break on head
  - always break on ret instr too so we know where we're going back to
    - but wait -- if gadget does not include any instrs that modify
      memory or the stack, we already know the ret addr
  - if real head, just note that the real path was used, and note the return
  - if gadget head (or if real == gadgead head) used, note return address
  - once have ret addr, disasm block of code including that ret addr --
    if the instr prior to the ret addr was a call to the function
    including the gadget, we're good

  - XXX: this leaves calls through jump tables; we'll have to add
    support for tracing from a call site into a jump table, into more
    jump tables, to the real thing, perhaps -- otherwise we'll never
    even make it into libc


  - XXX: need to make sure to disasm (or load code) before doing any
    probe inserts, since right now we could potentilaly insert probes
    before doing disasm.  This would lead to bad disasm.
 *
 */

result_t probe_rop_checkret_entry_pre(struct probe *probe,tid_t tid,void *data,
				      struct probe *trigger,struct probe *base) {
    struct rop_checkret_data *rop_data = (struct rop_checkret_data *)data;
    struct probe *rop_probe = rop_data->rop_probe;

    rop_data->status.ingadget = 1;
    rop_data->status.current_ret_addr = 0;
    ++rop_data->status.total;

    /*
     * If the gadget type is MID_MID, we need to insert the gadget's ret
     * probe; the ret_post handler will then remove it after it has
     * single stepped through the exit probe's original instruction.
     */
    if (rop_data->type == GADGET_TYPE_MID_MID) 
	probe_hard_enable(rop_data->ret_probe);

    return rop_probe->pre_handler(rop_data->rop_probe,tid,
				  rop_data->rop_probe->handler_data,probe,base);
}

result_t probe_rop_checkret_ret_pre(struct probe *probe,tid_t tid,void *data,
				    struct probe *trigger,struct probe *base) {
    struct rop_checkret_data *rop_data = (struct rop_checkret_data *)data;

    /* Have to check if the ret addr atop the stack is the addr
     * immediately following a call to the containing function
     * (rop_data->cont_start).
     */
    struct target *target = probe->target;
    REGVAL sp;
    REGVAL ip;
    ADDR retaddr;
    ADDR current_start;
    ADDR current_end;
    ADDR caller_start;
    ADDR caller_end;
    int caller_should_free;
    int clen;
    unsigned char *cbuf = NULL;
    struct array_list *cf_idata_list = NULL;
    struct cf_inst_data *cf_idata = NULL;
    struct cf_inst_data *cf_idata_prev = NULL;
    int i;
    int retval;

    if (!rop_data->status.ingadget)
	return 0;

    sp = target_read_reg(target,tid,target->spregno);
    if (errno) {
	verror("could not read SP!\n");
	goto errout;
    }
    ip = target_read_reg(target,tid,target->ipregno);
    if (errno) {
	verror("could not read IP!\n");
	goto errout;
    }

    /* Grab the return address on the top of the stack */
    if (!target_read_addr(target,(ADDR)sp,sizeof(ADDR),
			  (unsigned char *)&retaddr)) {
	verror("could not read top of stack\n");
	goto errout;
    }

    /*
     * We have to figure out what the instruction prior to the retaddr
     * is so we can check if it was a legitimate call.  We cannot just
     * assume it is a CALL instruction, so we have to disassemble the
     * "safe" chunk of text altogether, then figure out the preceding
     * instruction.
     *
     * If it's a call, we have to read the target address.  If our
     * current EIP (on the RET addr we're about to execute) is pointing
     * into the same "safe" disasm block that the call is in, we call it
     * good for now.
     */

    /* Find the safe disasm block for our current IP; this should never
     * error out; else how could we have setup the probes.
     */
    if (target_lookup_safe_disasm_range(target,ip,&current_start,&current_end,
					NULL)) {
	verror("no safe disasm range contains IP 0x%"PRIxADDR"!\n",ip);
	goto errout;
    }

    /* Find the safe disasm block for our retaddr. */
    if (target_lookup_safe_disasm_range(target,retaddr,
					&caller_start,&caller_end,NULL)) {
	verror("no safe disasm range contains retaddr 0x%"PRIxADDR"!\n",retaddr);
	goto errout;
    }

    /* Load the code containing the return address... */
    clen = caller_end - caller_start;
    cbuf = target_load_code(target,caller_start,clen,0,0,&caller_should_free);
    if (!cbuf) {
	verror("could not load code in range 0x%"PRIxADDR"-0x%"PRIxADDR
	       " containing retaddr at 0x%"PRIxADDR"!\n",
	       caller_start,caller_end,retaddr);
	goto errout;
    }

    /* Disassemble... */
    if (disasm_get_control_flow_offsets(target,INST_CF_ANY,cbuf,clen,
					&cf_idata_list,caller_start,1)) {
	verror("could not disassemble code in range 0x%"PRIxADDR"-0x%"PRIxADDR
	       " containing retaddr at 0x%"PRIxADDR"!\n",
	       caller_start,caller_end,retaddr);
	goto errout;
    }

    /* Look for the control flow instruction prior the return
     * address...
     */
    for (i = 1; i < array_list_len(cf_idata_list); ++i) {
	cf_idata_prev = (struct cf_inst_data *)array_list_item(cf_idata_list,i-1);
	cf_idata = (struct cf_inst_data *)array_list_item(cf_idata_list,i);

	if (cf_idata->offset >= (OFFSET)(retaddr - caller_start))
	    break;
    }
    if (i == array_list_len(cf_idata_list)
	|| cf_idata_prev == NULL) {
	vwarn("no CF instr before retaddr 0x%"PRIxADDR"; "
	      " possible false-positive violation!\n",
	       retaddr);

	rop_data->status.isfpviolation = 1;
	++rop_data->status.fpviolations;
	goto violation;
    }
    else if ((OFFSET)(retaddr - caller_start) 
	     != (cf_idata_prev->offset + cf_idata_prev->size)) {
	//vwarn("no CF instr directly before retaddr 0x%"PRIxADDR"!\n",
	//       retaddr);

	goto violation;
    }
    else if (cf_idata_prev->type != INST_CALL 
	     && cf_idata_prev->type != INST_JMP
	     && cf_idata_prev->type != INST_JCC) {
	vwarn("no CALL/JMP/Jcc instr before retaddr 0x%"PRIxADDR";"
	      " possible false-positive violation!\n",
	       retaddr);

	rop_data->status.isfpviolation = 1;
	++rop_data->status.fpviolations;
	goto violation;
    }
    else if (cf_idata_prev->type == INST_JMP) {
	/* Do not warn about these, but count them up and list them
	 * later.
	 */
	if (!rop_data->status.jmpfpviolations) 
	    vwarn("JMP instr before retaddr 0x%"PRIxADDR";"
		  " possible false-positive violation; only warning once!\n",
		  retaddr);

	rop_data->status.isjmpfpviolation = 1;
	++rop_data->status.jmpfpviolations;

	rop_data->status.isfpviolation = 1;
	++rop_data->status.fpviolations;

	goto violation;
    }
    else if (cf_idata_prev->type == INST_JCC) {
	/* Do not warn about these, but count them up and list them
	 * later.
	 */
	if (!rop_data->status.jccfpviolations) 
	    vwarn("Jcc instr before retaddr 0x%"PRIxADDR";"
		  " possible false-positive violation; only warning once!\n",
		  retaddr);

	rop_data->status.isjccfpviolation = 1;
	++rop_data->status.jccfpviolations;

	rop_data->status.isfpviolation = 1;
	++rop_data->status.fpviolations;

	goto violation;
    }
    else if (cf_idata_prev->cf.target == 0) {
	vwarn("CALL/JMP instr before retaddr 0x%"PRIxADDR" does not have"
	      " static target; not triggering violation; triggering error!\n",
	       retaddr);
	goto errout;
    }

    /* If the target is inside our current safe disasm block containing
     * the retaddr, it is a valid call through the gadget.
     */
    retval = 0;
    if (cf_idata_prev->cf.target >= current_start
	&& cf_idata_prev->cf.target < current_end) {
	rop_data->status.isviolation = 0;
    }
    else {
    violation:
	rop_data->status.isviolation = 1;
	++rop_data->status.violations;
    }

    rop_data->status.current_ret_addr = retaddr;
    retval = rop_data->rop_probe->post_handler(rop_data->rop_probe,tid,
					       rop_data->rop_probe->handler_data,
					       probe,base);
    goto out;


 errout:
    retval = -1;

 out:
    if (cbuf && caller_should_free)
	free(cbuf);
    if (cf_idata_list)
	array_list_deep_free(cf_idata_list);

    return retval;
}

result_t probe_rop_checkret_ret_post(struct probe *probe,tid_t tid,void *data,
				     struct probe *trigger,struct probe *base) {
    struct rop_checkret_data *rop_data = (struct rop_checkret_data *)data;

    rop_data->status.ingadget = 0;
    rop_data->status.isviolation = 0;
    rop_data->status.current_ret_addr = 0;

    /*
     * If this is a GADGET_TYPE_MID_MID, we remove the exit probe, too!
     */
    if (rop_data->type == GADGET_TYPE_MID_MID)
	return 2;
    else 
	return 0;
}

result_t probe_rop_checkret_cont_pre(struct probe *probe,tid_t tid,void *data,
				     struct probe *trigger,struct probe *base) {
    struct rop_checkret_data *rop_data = (struct rop_checkret_data *)data;

    /* Have to hot-remove the probe inside this instruction before we
     * execute it!
     */
    probe_hard_disable(rop_data->entry_probe,0);

    return 0;
}

result_t probe_rop_checkret_cont_post(struct probe *probe,tid_t tid,void *data,
				      struct probe *trigger,struct probe *base) {
    struct rop_checkret_data *rop_data = (struct rop_checkret_data *)data;

    /* Have to hot-insert the probe back into the instruction so it is
     * ready for the next iteration.
     */
    probe_hard_enable(rop_data->entry_probe);

    return 0;
}

struct probe *probe_rop_checkret(struct target *target,tid_t tid,
				 struct rop_gadget *rg,
				 probe_handler_t pre_handler,
				 probe_handler_t post_handler,
				 void *handler_data) {
    struct array_list *idata_list;
    struct array_list *cf_idata_list;
    ADDR cont_start;
    ADDR cont_end;
    unsigned char *cbuf = NULL;
    unsigned char *gbuf = NULL;
    int clen,glen;
    int cont_should_free = 0;
    int gadget_should_free = 0;
    struct inst_data *idata = NULL,*idata2;
    char namebuf[32];
    struct rop_checkret_data *rop_data;
    struct probe *rop_probe;
    ADDR gadget_ret_addr;
    int i,j;
    int aligned = 1;
    ADDR cont_addr;

    /*
     * Create the main rop probe.  The rop probe is really just a
     * pass-through (for future extensibility, testing out API, etc)
     * that invokes the probe handlers the user supplies, OR of the
     * probes attached to it (we assume that if the user does not supply
     * handlers, it will attach more probes to this probe).
     */
    rop_data = (struct rop_checkret_data *)calloc(1,sizeof(*rop_data));
    snprintf(namebuf,32,"rop_checkret_0x%"PRIxADDR,rg->start);
    rop_probe = probe_create(target,tid,&probe_ops_rop_checkret,namebuf,
			     pre_handler ? pre_handler : probe_do_sink_pre_handlers,
			     post_handler ? post_handler : probe_do_sink_post_handlers,
			     handler_data,0,1);
    rop_probe->priv = rop_data;
    rop_data->rop_probe = rop_probe;
    rop_data->gadget = rg;

    /*
     * Get the containing safe disassemble-able range containing the
     * start instruction of the gadget:
     */
    if (target_lookup_safe_disasm_range(target,rg->start,
					&cont_start,&cont_end,NULL)) {
	verror("no safe disasm range contains 0x%"PRIxADDR"!\n",rg->start);
	goto errout;
    }
    rop_data->cont_start = cont_start;

    vdebug(3,LA_USER,LF_U_ALL,"safe disasm range for gadget 0x%"PRIxADDR":"
	   " 0x%"PRIxADDR",0x%"PRIxADDR"\n",
	   rg->start,cont_start,cont_end);

    clen = cont_end - cont_start;
    cbuf = target_load_code(target,cont_start,clen,0,0,&cont_should_free);
    if (!cbuf) {
	verror("could not load code in range 0x%"PRIxADDR"-0x%"PRIxADDR
	       " containing gadget at 0x%"PRIxADDR"!\n",
	       cont_start,cont_end,rg->start);
	goto errout;
    }

    /* Disassemble containing range. */
    if (disasm_generic(target,cbuf,clen,&idata_list,1)) {
	verror("could not disassemble code in range 0x%"PRIxADDR"-0x%"PRIxADDR
	       " containing gadget at 0x%"PRIxADDR"!\n",
	       cont_start,cont_end,rg->start);
	goto errout;
    }

    /* Load and dissassemble gadget. */
    glen = rg->end - rg->start;
    gbuf = target_load_code(target,rg->start,glen,0,0,&gadget_should_free);
    if (!gbuf) {
	verror("could not load gadget code in range 0x%"PRIxADDR"-0x%"PRIxADDR
	       "!\n",rg->start,rg->end);
	goto errout;
    }

    /* Disassemble gadget, looking for exactly one RET. */
    if (disasm_get_control_flow_offsets(target,INST_CF_RET,gbuf,glen,
					&cf_idata_list,rg->start,1)) {
	verror("could not disassemble code at 0x%"PRIxADDR"-0x%"PRIxADDR
	       " containing gadget at 0x%"PRIxADDR"!\n",
	       rg->start,rg->end,rg->start);
	goto errout;
    }
    if (array_list_len(cf_idata_list) == 0) {
	verror("no RETs in gadget disasm!\n");
	goto errout;
    }
    else if (array_list_len(cf_idata_list) > 1) {
	verror("more than one RET in gadget disasm!\n");
	goto errout;
    }
    /*
     * Really, the ret addr should always be the last byte of the
     * gadget's range, but we don't have to assume this.
     */
    gadget_ret_addr = rg->start 
	+ ((struct cf_inst_data *)array_list_item(cf_idata_list,0))->offset;

    /* Figure out if the gadget starts on an instr boundary. */
    for (i = 0; i < array_list_len(idata_list); ++i) {
	idata = (struct inst_data *)array_list_item(idata_list,i);
	if (rg->start == (cont_start + idata->offset)) {
	    aligned = 1;
	    break;
	}
	else if (rg->start < (cont_start + idata->offset)) {
	    /* It's i - 1 since the gadget start is not aligned */
	    --i;
	    idata = (struct inst_data *)array_list_item(idata_list,i);
	    aligned = 0;
	    break;
	}
    }

    for (j = i; j < array_list_len(idata_list); ++j) {
	idata2 = (struct inst_data *)array_list_item(idata_list,j);
	if ((rg->end - 1) == (cont_start + idata2->offset))
	    break;
    }

    /*
     * Create the gadget probes; for now, do these no matter what.
     * Later, we could try to anticipate what the retaddr is if we're
     * sure that none of the gadget instrs will change control flow or
     * mess with the stack.
     */
    snprintf(namebuf,32,"rop_checkret_entry_0x%"PRIxADDR,rg->start);
    rop_data->entry_probe = probe_create(target,tid,NULL,namebuf,
					 probe_rop_checkret_entry_pre,
					 NULL,
					 rop_data,0,0);
    if (!probe_register_addr(rop_data->entry_probe,rg->start,
			     PROBEPOINT_BREAK,PROBEPOINT_SW,
			     PROBEPOINT_WAUTO,PROBEPOINT_LAUTO,NULL)) {
	verror("could not register %s!\n",namebuf);
	goto errout;
    }
    snprintf(namebuf,32,"rop_checkret_ret_0x%"PRIxADDR,gadget_ret_addr);
    rop_data->ret_probe = probe_create(target,tid,NULL,namebuf,
				       probe_rop_checkret_ret_pre,
				       probe_rop_checkret_ret_post,
				       rop_data,0,0);
    if (!probe_register_addr(rop_data->ret_probe,gadget_ret_addr,
			     PROBEPOINT_BREAK,PROBEPOINT_SW,
			     PROBEPOINT_WAUTO,PROBEPOINT_LAUTO,NULL)) {
	verror("could not register %s!\n",namebuf);
	goto errout;
    }
    
    /* Setup probes for which gadget it is! */
    if (aligned) {
	rop_data->type = GADGET_TYPE_REAL;
    }
    else {
	if (j < array_list_len(idata_list)) {
	    rop_data->type = GADGET_TYPE_MID_REAL;
	}
	else {
	    rop_data->type = GADGET_TYPE_MID_MID;
	}

	cont_addr = cont_start + idata->offset;

	/* Add a probe on the real instr preceding the gadget. */
	snprintf(namebuf,32,"rop_checkret_cont_0x%"PRIxADDR,cont_addr);
	rop_data->cont_probe = probe_create(target,tid,NULL,namebuf,
					    probe_rop_checkret_cont_pre,
					    probe_rop_checkret_cont_post,
					    rop_data,0,0);
	if (!probe_register_addr(rop_data->cont_probe,cont_addr,
				 PROBEPOINT_BREAK,PROBEPOINT_SW,
				 PROBEPOINT_WAUTO,PROBEPOINT_LAUTO,NULL)) {
	    verror("could not register %s!\n",namebuf);
	    goto errout;
	}

	/*
	 * Now, suddenly, if the gadget is MID_MID, we *remove* the
	 * probepoint for the exit probe.  It gets dynamically inserted
	 * if we hit the gadget entry point probe, and it removes itself
	 * in its post handler.
	 */
	if (rop_data->type == GADGET_TYPE_MID_MID) 
	    probe_hard_disable(rop_data->ret_probe,0);
    }

    return rop_probe;

 errout:
    if (cbuf && cont_should_free)
	free(cbuf);
    if (gbuf && gadget_should_free)
	free(gbuf);
    if (idata_list)
	array_list_deep_free(idata_list);
    if (rop_data) {
	if (rop_data->cont_probe) {
	    probe_unregister(rop_data->cont_probe,0);
	    probe_free(rop_data->cont_probe,0);
	}
	if (rop_data->entry_probe) {
	    probe_unregister(rop_data->entry_probe,0);
	    probe_free(rop_data->entry_probe,0);
	}
	if (rop_data->ret_probe) {
	    probe_unregister(rop_data->ret_probe,0);
	    probe_free(rop_data->ret_probe,0);
	}
    }
    if (rop_probe)
	probe_free(rop_probe,0);

    return NULL;
}

