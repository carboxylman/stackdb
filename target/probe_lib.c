/*
 * Copyright (c) 2011, 2012, 2013 The University of Utah
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

#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "common.h"
#include "log.h"
#include "alist.h"
#include "glib_wrapper.h"

#include "dwdebug.h"
#include "dwdebug_priv.h"

#include "target_api.h"
#include "target.h"

#include "probe_api.h"
#include "probe.h"

struct probe *probe_simple(struct target *target,tid_t tid,char *name,
			   probe_handler_t pre_handler,
			   probe_handler_t post_handler,
			   void *handler_data) {
    struct probe *probe = probe_create(target,tid,NULL,name,pre_handler,
				       post_handler,handler_data,0,1);
    if (!probe)
	return NULL;

    return probe_register_symbol_name(probe,name,DWDEBUG_DEF_DELIM,
				      PROBEPOINT_FASTEST,PROBEPOINT_WAUTO,
				      PROBEPOINT_LAUTO);
}

struct probe *probe_register_symbol_name(struct probe *probe,
					 char *name,const char *delim,
					 probepoint_style_t style,
					 probepoint_whence_t whence,
					 probepoint_watchsize_t watchsize) {
    struct bsymbol *bsymbol;
    struct target *target = probe->target;

    if (!(bsymbol = target_lookup_sym(target,name,delim,NULL,
				      SYMBOL_TYPE_FLAG_NONE))) {
	verror("could not find symbol %s!\n",name);
	goto errout;
    }

    return probe_register_symbol(probe,bsymbol,style,whence,watchsize);

 errout:
    if (probe->autofree)
	probe_free(probe,1);
    return NULL;
}

#ifdef ENABLE_DISTORM
struct probe *probe_register_function_ee(struct probe *probe,
					 probepoint_style_t style,
					 struct bsymbol *bsymbol,
					 int force_at_entry,int noabort) {
    struct target *target = probe->target;
    struct memrange *range;
    struct memrange *newrange;
    ADDR start;
    ADDR prologueend;
    ADDR probeaddr;
    struct probe *source;
    int j;
    struct array_list *cflist = NULL;
    struct range *funcrange;
    unsigned char *funccode = NULL;
    unsigned int funclen;
    struct cf_inst_data *idata;
    size_t bufsiz;
    char *buf;
    struct target_thread *tthread = probe->thread;
    tid_t tid = tthread->tid;
    int caller_free = 0;

    if (!SYMBOL_IS_FUNCTION(bsymbol->lsymbol->symbol)) {
	verror("must supply a function symbol!\n");
	goto errout;
    }
    else if (!SYMBOL_IS_FULL_FUNCTION(bsymbol->lsymbol->symbol)
	     && symbol_bytesize(bsymbol->lsymbol->symbol) <= 0) {
	verror("partial function symbols must have non-zero length!\n");
	goto errout;
    }

    if (location_resolve_symbol_base(target,tid,bsymbol,&start,&range)) {
	verror("could not resolve entry PC for function %s!\n",
	       bsymbol->lsymbol->symbol->name);
	return NULL;
    }
    else 
	probeaddr = start;

    if (!force_at_entry && SYMBOL_IS_FULL_FUNCTION(bsymbol->lsymbol->symbol)) {
	if (location_resolve_function_prologue_end(target,bsymbol,
						   &prologueend,&range)) {
	    vwarn("could not resolve prologue_end for function %s!\n",
		  bsymbol->lsymbol->symbol->name);
	}
	else 
	    probeaddr = prologueend;
    }

    /*
     * If we've got a post handler, we need to disasm this function
     * before we insert a probe into it!!
     */
    if (SYMBOL_IS_FULL_FUNCTION(bsymbol->lsymbol->symbol)) {
	funcrange = &bsymbol->lsymbol->symbol->s.ii->d.f.symtab->range;
	if (!RANGE_IS_PC(funcrange)) {
	    verror("range type for function %s was %s, not PC!\n",
		   bsymbol->lsymbol->symbol->name,RANGE_TYPE(funcrange->rtype));
	    goto errout;
	}

	funclen = memregion_relocate(bsymbol->region,funcrange->r.a.highpc,NULL)
	    - memregion_relocate(bsymbol->region,funcrange->r.a.lowpc,NULL);
	/* This should not ever happen. */
	if (start != memregion_relocate(bsymbol->region,funcrange->r.a.lowpc,NULL)) {
	    vwarn("full function %s does not have matching base (0x%"PRIxADDR")"
		  " and lowpc (0x%"PRIxADDR") values!\n",
		  bsymbol_get_name(bsymbol),start,
		  memregion_relocate(bsymbol->region,funcrange->r.a.lowpc,NULL));
	    start = memregion_relocate(bsymbol->region,funcrange->r.a.lowpc,NULL);
	    funclen = memregion_relocate(bsymbol->region,funcrange->r.a.highpc,NULL)
		- start;
	}
    }
    else
	funclen = symbol_bytesize(bsymbol->lsymbol->symbol);

    funccode = target_load_code(target,start,funclen,0,0,&caller_free);
    if (!funccode) {
	verror("could not load code for disasm of %s!\n",
	       bsymbol_get_name(bsymbol));
	goto errout;
    }

    /* Create and register the entry point probe if @probe has a
     * pre_handler.
     */
    if (probe->pre_handler) {
	bufsiz = strlen(bsymbol->lsymbol->symbol->name)+1+5+1;
	buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"%s_entry",bsymbol->lsymbol->symbol->name);
	source = probe_create(target,tid,NULL,buf,probe_do_sink_pre_handlers,
			      NULL,NULL,1,1);
	free(buf);
	if (!__probe_register_addr(source,probeaddr,range,
				   PROBEPOINT_BREAK,style,PROBEPOINT_EXEC,
				   PROBEPOINT_LAUTO,bsymbol,start)) {
	    goto errout;
	}

	if (!probe_register_source(probe,source)) {
	    probe_free(source,1);
	    goto errout;
	}

	vdebug(3,LA_PROBE,LF_PROBE,
	       "registered entry addr probe at %s%+d\n",
	       bsymbol->lsymbol->symbol->name,(int)(probeaddr - start));
    }

    /* If @probe has no post_handler, don't register for the return
     * instructions.
     */
    if (!probe->post_handler)
	return probe;

    /* Disassemble the function to find the return instructions. */
    if (disasm_get_control_flow_offsets(target,INST_CF_RET | INST_CF_IRET,
					funccode,funclen,
					&cflist,start,noabort)) {
	verror("could not disasm function %s!\n",bsymbol->lsymbol->symbol->name);
	goto errout;
    }

    if (caller_free)
	free(funccode);
    funccode = NULL;

    /* Now register probes for each return instruction! */
    for (j = 0; j < array_list_len(cflist); ++j) {
	idata = (struct cf_inst_data *)array_list_item(cflist,j);

	if (idata->type != INST_RET && idata->type != INST_IRET) {
	    verror("disasm instr was not RET/IRET!\n");
	    goto errout;
	}

	/* We should be in the same range, of course; this should never
	 * happen!
	 */
	if (0 && (!target_find_memory_real(target,start + idata->offset,
					  NULL,NULL,&newrange)
		  || range != newrange)) {
	    verror("could not find sane range!\n");
	    goto errout;
	}
	else {
	    newrange = range;
	}

	/* Create the j-th exit probe. */
	bufsiz = strlen(bsymbol->lsymbol->symbol->name)+1+4+1+11+1;
	buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"%s_exit_%d",bsymbol->lsymbol->symbol->name,j);
	source = probe_create(target,tid,NULL,buf,probe_do_sink_post_handlers,
			      NULL,NULL,1,1);
	free(buf);

	/* Register the j-th exit probe. */
	probeaddr = start + idata->offset;
	if (!__probe_register_addr(source,probeaddr,newrange,
				   PROBEPOINT_BREAK,style,PROBEPOINT_EXEC,
				   PROBEPOINT_LAUTO,bsymbol,start)) {
	    goto errout;
	}

	if (!probe_register_source(probe,source)) {
	    probe_free(source,1);
	    goto errout;
	}

	vdebug(3,LA_PROBE,LF_PROBE,
	       "registered return addr probe at %s%+d\n",
	       bsymbol->lsymbol->symbol->name,(int)idata->offset);
    }

    if (cflist) {
	array_list_deep_free(cflist);
	cflist = NULL;
    }

    return probe;

 errout:
    if (funccode && caller_free)
	free(funccode);
    if (cflist) {
	array_list_deep_free(cflist);
    }
    probe_unregister(probe,1);
    if (probe->autofree)
	probe_free(probe,1);
    return NULL;
}

struct probe *probe_register_function_invocations(struct probe *probe,
						  probepoint_style_t style,
						  struct bsymbol *caller,
						  struct bsymbol *callee,
						  int noabort) {
    struct target *target;
    struct target_thread *tthread;
    tid_t tid;
    struct memrange *range;
    ADDR caller_start;
    ADDR caller_end;
    unsigned int caller_len;
    struct range *funcrange;
    unsigned char *funccode = NULL;
    int caller_free = 0;
    ADDR callee_start = 0;
    ADDR callee_inlined_start;
    ADDR callee_inlined_end;
    GSList *callee_instances = NULL;
    struct symbol *caller_symbol;
    struct symbol *callee_symbol;
    ADDR probeaddr;
    struct probe *iprobe;
    GSList *probes = NULL;
    GSList *gsltmp;
    int i,j;
    struct array_list *cf_idata_list = NULL;
    struct cf_inst_data *idata;
    char namebuf[128];

    struct __iii {
	struct bsymbol *bsymbol;
	ADDR start;
	ADDR end;
    };
    struct __iii *iii;

    target = probe->target;
    tthread = probe->thread;
    tid = tthread->tid;

    caller_symbol = bsymbol_get_symbol(caller);
    callee_symbol = bsymbol_get_symbol(callee);

    if (!SYMBOL_IS_FUNCTION(caller_symbol) 
	|| !SYMBOL_IS_FUNCTION(callee_symbol)) {
	verror("caller and callee must be function symbols!\n");
	goto errout;
    }
    else if (!SYMBOL_IS_FULL_FUNCTION(caller_symbol)
	     && symbol_bytesize(caller_symbol) <= 0) {
	verror("partial function symbols must have non-zero length!\n");
	goto errout;
    }

    if (location_resolve_symbol_base(target,tid,caller,&caller_start,&range)) {
	verror("could not resolve base addr for caller function %s!\n",
	       bsymbol_get_name(caller));
	return NULL;
    }

    /*
     * We need to know the range of the caller.
     */
    if (SYMBOL_IS_FULL_FUNCTION(caller_symbol)) {
	funcrange = &caller_symbol->s.ii->d.f.symtab->range;
	if (!RANGE_IS_PC(funcrange)) {
	    verror("range type for caller function %s was %s, not PC!\n",
		   caller_symbol->name,RANGE_TYPE(funcrange->rtype));
	    goto errout;
	}

	caller_len = memregion_relocate(caller->region,funcrange->r.a.highpc,NULL)
	    - memregion_relocate(caller->region,funcrange->r.a.lowpc,NULL);
	/* This should not ever happen. */
	if (caller_start 
	    != memregion_relocate(caller->region,funcrange->r.a.lowpc,NULL)) {
	    vwarn("full caller function %s does not have matching"
		  " base (0x%"PRIxADDR") and lowpc (0x%"PRIxADDR") values!\n",
		  bsymbol_get_name(caller),caller_start,
		  memregion_relocate(caller->region,funcrange->r.a.lowpc,NULL));
	    caller_start = memregion_relocate(caller->region,
					      funcrange->r.a.lowpc,NULL);
	    caller_len = memregion_relocate(caller->region,funcrange->r.a.highpc,
					    NULL) - caller_start;
	}
    }
    else
	caller_len = symbol_bytesize(caller_symbol);

    caller_end = caller_start + caller_len;

    /*
     * Grab the base of the callee; there might not be one if it's only inlined.
     */
    if (location_resolve_symbol_base(target,tid,callee,&callee_start,&range))
	callee_start = 0;
    /*
     * Find the inline instances within our caller, if any.
     */
    if (SYMBOL_IS_FULL_FUNCTION(callee_symbol)
	&& callee_symbol->s.ii->inline_instances) {
	struct array_list *iilist = callee_symbol->s.ii->inline_instances;

	for (i = 0; i < array_list_len(iilist); ++i) {
	    struct symtab *isymtab;
	    struct symbol *isymbol = (struct symbol *)array_list_item(iilist,i);

	    if (!SYMBOL_IS_FULL_FUNCTION(isymbol)
		|| !(isymtab = isymbol->s.ii->d.f.symtab))
		continue;

	    /*
	     * Check and see if the instance is in our function; if so,
	     * add it to the list!
	     */
	    if (RANGE_IS_PC(&isymtab->range)) {
		callee_inlined_start = isymtab->range.r.a.lowpc;
		callee_inlined_end = isymtab->range.r.a.highpc;
	    }
	    else if (RANGE_IS_LIST(&isymtab->range)) {
		/* Find the lowest/highest addrs! */
		callee_inlined_start = ADDRMAX;
		callee_inlined_end = 0;
		for (i = 0; i < isymtab->range.r.rlist.len; ++i) {
		    if (isymtab->range.r.rlist.list[i]->start 
			< callee_inlined_start)
			callee_inlined_start = 
			    isymtab->range.r.rlist.list[i]->start;
		    if (isymtab->range.r.rlist.list[i]->end > callee_inlined_end)
			callee_inlined_end = isymtab->range.r.rlist.list[i]->end;
		}
	    }
	    else 
		continue;

	    if (!(caller_start <= callee_inlined_start 
		  && callee_inlined_start <= caller_end
		  && caller_start <= callee_inlined_end
		  && callee_inlined_end <= caller_end)) 
		continue;

	    /* Use __int() version to not RHOLD(); bsymbol_create RHOLDS it. */
	    struct lsymbol *ilsymbol = lsymbol_create_from_symbol__int(isymbol);
	    if (!ilsymbol) {
		verror("could not create lsymbol for inline instance symbol %s!\n",
		       symbol_get_name(isymbol));
		goto errout;
	    }

	    /* Ok, note this one down; we're going to place probes on it. */
	    iii = calloc(1,sizeof(*iii));
	    iii->bsymbol = bsymbol_create(ilsymbol,caller->region);
	    iii->start = callee_inlined_start;
	    iii->end = callee_inlined_end;

	    callee_instances = g_slist_append(callee_instances,iii);
	}
    }

    /* If we didn't find any of these things for the callee, abort! */
    if (!callee_start || !callee_instances) {
	verror("callee function %s has no addr, and/or is not inlined in"
	       " caller function %s!\n",
	       symbol_get_name(callee_symbol),symbol_get_name(caller_symbol));
	goto errout;
    }

    /* If we found a callee addr, disasm to find the calls to it. */
    funccode = target_load_code(target,caller_start,caller_len,0,0,&caller_free);
    if (!funccode) {
	verror("could not load code for disasm of %s!\n",
	       bsymbol_get_name(caller));
	goto errout;
    }

    /* Disassemble the function to find the call instructions. */
    if (disasm_get_control_flow_offsets(target,INST_CF_CALL,funccode,caller_len,
					&cf_idata_list,caller_start,noabort)) {
	verror("could not disasm caller function %s!\n",
	       symbol_get_name(caller_symbol));
	goto errout;
    }

    if (caller_free)
	free(funccode);
    funccode = NULL;

    /* Now register probes for each call invocation instruction! */
    for (j = 0; j < array_list_len(cf_idata_list); ++j) {
	idata = (struct cf_inst_data *)array_list_item(cf_idata_list,j);

	if (idata->type != INST_CALL) {
	    verror("disasm instr was not CALL!\n");
	    goto errout;
	}

	if (idata->cf.target != callee_start)
	    continue;

	if (probe->pre_handler) {
	    /* Create the j-th pre-callee-call probe. */
	    snprintf(namebuf,sizeof(namebuf),"%s__pre_invoke__%s__%i",
		     symbol_get_name(caller_symbol),
		     symbol_get_name(callee_symbol),j);
	    iprobe = probe_create(target,tid,NULL,namebuf,
				  probe_do_sink_pre_handlers,NULL,NULL,1,1);
	    probeaddr = caller_start + idata->offset;
	    if (!__probe_register_addr(iprobe,probeaddr,range,
				       PROBEPOINT_BREAK,style,PROBEPOINT_EXEC,
				       PROBEPOINT_LAUTO,callee,0)) {
		verror("failed to register probe %s at 0x%"PRIxADDR
		       " (call site %d)\n",
		       probe_name(iprobe),probeaddr,j);
		probe_free(iprobe,0);
		iprobe = NULL;
		goto errout;
	    }
	    probes = g_slist_append(probes,iprobe);
	}

	if (probe->post_handler) {
	    /* Create the j-th post-callee-call probe. */
	    snprintf(namebuf,sizeof(namebuf),"%s__post_invoke__%s__%i",
		     symbol_get_name(caller_symbol),
		     symbol_get_name(callee_symbol),j);
	    iprobe = probe_create(target,tid,NULL,namebuf,
				  probe_do_sink_post_handlers,NULL,NULL,1,1);
	    probeaddr = caller_start + idata->offset + idata->size;
	    if (!__probe_register_addr(iprobe,probeaddr,range,
				       PROBEPOINT_BREAK,style,PROBEPOINT_EXEC,
				       PROBEPOINT_LAUTO,callee,0)) {
		verror("failed to register probe %s at 0x%"PRIxADDR
		       " (call site %d)\n",
		       probe_name(iprobe),probeaddr,j);
		probe_free(iprobe,0);
		iprobe = NULL;
		goto errout;
	    }
	    probes = g_slist_append(probes,iprobe);
	}

	vdebug(3,LA_PROBE,LF_PROBE,
	       "registered invocation probes around call site 0x%"PRIxADDR"\n",
	       caller_start + idata->offset);
    }

    if (cf_idata_list) {
	array_list_deep_free(cf_idata_list);
	cf_idata_list = NULL;
    }

    /* Now register probes around each inline "invocation". */
    if (callee_instances) {
	j = 0;
	v_g_slist_foreach(callee_instances,gsltmp,iii) {
	    if (probe->pre_handler) {
		/* Create the j-th pre-callee-call probe. */
		snprintf(namebuf,sizeof(namebuf),"%s__pre_inline_invoke__%s__%i",
			 symbol_get_name(caller_symbol),
			 symbol_get_name(callee_symbol),j);
		iprobe = probe_create(target,tid,NULL,namebuf,
				      probe_do_sink_pre_handlers,NULL,NULL,1,1);
		probeaddr = iii->start;
		if (!__probe_register_addr(iprobe,probeaddr,range,
					   PROBEPOINT_BREAK,style,PROBEPOINT_EXEC,
					   PROBEPOINT_LAUTO,iii->bsymbol,0)) {
		    verror("failed to register probe %s at 0x%"PRIxADDR
			   " (inline call site %d)\n",
			   probe_name(iprobe),probeaddr,j);
		    probe_free(iprobe,0);
		    iprobe = NULL;
		    goto errout;
		}
		probes = g_slist_append(probes,iprobe);
	    }

	    if (probe->post_handler) {
		/* Create the j-th post-callee-call probe. */
		snprintf(namebuf,sizeof(namebuf),"%s__post_inline_invoke__%s__%i",
			 symbol_get_name(caller_symbol),
			 symbol_get_name(callee_symbol),j);
		iprobe = probe_create(target,tid,NULL,namebuf,
				      probe_do_sink_post_handlers,NULL,NULL,1,1);
		probeaddr = iii->end;
		if (!__probe_register_addr(iprobe,probeaddr,range,
					   PROBEPOINT_BREAK,style,PROBEPOINT_EXEC,
					   PROBEPOINT_LAUTO,iii->bsymbol,0)) {
		    verror("failed to register probe %s at 0x%"PRIxADDR
			   " (call site %d)\n",
			   probe_name(iprobe),probeaddr,j);
		    probe_free(iprobe,0);
		    iprobe = NULL;
		    goto errout;
		}
		probes = g_slist_append(probes,iprobe);
	    }

	    vdebug(3,LA_PROBE,LF_PROBE,
		   "registered inline invocation probes around call site"
		   " 0x%"PRIxADDR"; return site 0x%"PRIxADDR"\n",
		   iii->start,iii->end);

	    ++j;
	}

	v_g_slist_foreach(callee_instances,gsltmp,iii) {
	    bsymbol_release(iii->bsymbol);
	    free(iii);
	}
	g_slist_free(callee_instances);
    }

    /*
     * Now register @probe on each probe in @probes!  We CANNOT fail at
     * this point, because we free would the whole probes list on errout
     * below, and freeing a probe that we have registered @probe on is
     * not desireable.  Just free the source probe in question...
     */
    v_g_slist_foreach(probes,gsltmp,iprobe) {
	if (!probe_register_source(probe,iprobe)) {
	    verror("could not register probe %s on source %s; cannot abort!\n",
		   probe_name(probe),probe_name(iprobe));
	    probe_free(iprobe,0);
	}
    }

    g_slist_free(probes);
    probes = NULL;

    /* Whewph! */
    return probe;

 errout:
    if (probes) {
	v_g_slist_foreach(probes,gsltmp,iprobe) {
	    probe_free(iprobe,0);
	}
	g_slist_free(probes);
    }
    if (callee_instances) {
	v_g_slist_foreach(callee_instances,gsltmp,iii) {
	    bsymbol_release(iii->bsymbol);
	    free(iii);
	}
	g_slist_free(callee_instances);
    }
    if (funccode && caller_free)
	free(funccode);
    if (cf_idata_list) {
	array_list_deep_free(cf_idata_list);
    }
    probe_unregister(probe,1);
    if (probe->autofree)
	probe_free(probe,1);
    return NULL;
}

struct probe *probe_register_function_instrs(struct bsymbol *bsymbol,
					     probepoint_style_t style,
					     int noabort,
					     probe_register_disasm_handler_t handler,
					     void *handler_data,
					     inst_type_t inst,
					     struct probe *probe,...) {
    va_list ap;
    struct target *target = probe->target;
    struct memrange *range;
    struct memrange *newrange;
    ADDR start;
    ADDR probeaddr;
    struct probe *source;
    int j;
    struct array_list *cflist = NULL;
    struct range *funcrange;
    unsigned char *funccode = NULL;
    unsigned int funclen;
    struct cf_inst_data *idata;
    size_t bufsiz;
    char *buf;
    GHashTable *itypes = NULL;
    inst_cf_flags_t cfflags = INST_CF_ANY;
    tid_t tid;
    struct probe *probe_alt;
    char *sname;
    int sname_created = 0;

    if (!SYMBOL_IS_FUNCTION(bsymbol->lsymbol->symbol)) {
	verror("must supply a function symbol!\n");
	goto errout;
    }
    else if (!SYMBOL_IS_FULL_FUNCTION(bsymbol->lsymbol->symbol)
	     && symbol_bytesize(bsymbol->lsymbol->symbol) <= 0) {
	verror("partial function symbols must have non-zero length!\n");
	goto errout;
    }

    sname = symbol_get_name(bsymbol->lsymbol->symbol);
    if (!sname) {
	sname = malloc(sizeof("ref0x")+12);
	snprintf(sname,sizeof("ref0x")+12,"ref0x%"PRIxSMOFFSET,
		 bsymbol->lsymbol->symbol->ref);
	sname_created = 1;
    }

    /* Resolve the base address of the function so that we can pass the
     * best information to __probe_register_addr as possible to make
     * debug output clearer.
     */
    if (location_resolve_function_base(target,bsymbol->lsymbol,
				       bsymbol->region,&start,&range)) {
	verror("could not resolve entry PC for function %s!\n",sname);
	if (sname_created)
	    free(sname);
	return NULL;
    }

    /* Process our varargs list.  There must be at least one
     * inst_type_t,probe * tuple, as shown in the fucntion prototype.
     * If inst_type_t is not INST_TYPE_NONE, we process another probe *;
     * otherwise, we abort since it's the end of the list.
     */
    itypes = g_hash_table_new(g_direct_hash,g_direct_equal);
    g_hash_table_insert(itypes,(gpointer)inst,probe);
    cfflags |= INST_TO_CF_FLAG(inst);
    va_start(ap,probe);
    while ((inst = va_arg(ap,inst_type_t)) != INST_NONE) {
	probe = va_arg(ap,struct probe *);
	g_hash_table_insert(itypes,(gpointer)inst,probe);
	cfflags |= INST_TO_CF_FLAG(inst);
    }
    va_end(ap);

    /* Disassemble the function to find the return instructions. */

    /* Disassemble the function to find the return instructions. */
    if (SYMBOL_IS_FULL_FUNCTION(bsymbol->lsymbol->symbol)) {
	funcrange = &bsymbol->lsymbol->symbol->s.ii->d.f.symtab->range;
	if (!RANGE_IS_PC(funcrange)) {
	    verror("range type for function %s was %s, not PC!\n",
		   sname,RANGE_TYPE(funcrange->rtype));
	    goto errout;
	}

	funclen = memregion_relocate(bsymbol->region,funcrange->r.a.highpc,NULL) 
	    - memregion_relocate(bsymbol->region,funcrange->r.a.lowpc,NULL);
    }
    else
	funclen = symbol_bytesize(bsymbol->lsymbol->symbol);

    /* We allocate an extra NULL byte on the back side because distorm
     * seems to have an off by one error (guessing, according to
     * valgrind!
     */
    funccode = malloc(funclen + 1);

    if (!target_read_addr(target,start,funclen,funccode)) {
	verror("could not read code before disasm of function %s!\n",sname);
	goto errout;
    }

    funccode[funclen] = 0;

    if (disasm_get_control_flow_offsets(target,cfflags,funccode,funclen,
					&cflist,start,noabort)) {
	verror("could not disasm function %s!\n",sname);
	goto errout;
    }

    free(funccode);
    funccode = NULL;

    /* Now register probes for each instruction! */
    for (j = 0; j < array_list_len(cflist); ++j) {
	idata = (struct cf_inst_data *)array_list_item(cflist,j);

	/* We should be in the same range, of course; this should never
	 * happen!
	 */
	if (0 && (!target_find_memory_real(target,start + idata->offset,
					  NULL,NULL,&newrange)
		  || range != newrange)) {
	    verror("could not find sane range!\n");
	    goto errout;
	}
	else {
	    newrange = range;
	}

	/*
	 * Call the user callback to see if they REALLY want the instr
	 * probed.  1 means yes; 0 means no.
	 */
	probe_alt = NULL;
	if (handler && handler(idata,start + idata->offset,
			       handler_data,&probe_alt) == 0) {
	    vdebug(5,LA_PROBE,LF_PROBE,"user handler skipped this inst!\n");
	    continue;
	}

	if (probe_alt) {
	    vdebug(5,LA_PROBE,LF_PROBE,"user customized the probe for inst!\n");
	    probe = probe_alt;
	}
	else 
	    probe = (struct probe *) \
		g_hash_table_lookup(itypes,(gpointer)idata->type);

	tid = probe->thread->tid;

	/* Create the j-th instruction probe.  Assume that all
	 * instruction names fit in 16 bytes.
	 */
	bufsiz = strlen(sname)+1+16+1+11+1;
	bufsiz = strlen(sname)+1+16+1+11+1;
	buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"%s_%s_%d",sname,disasm_get_inst_name(idata->type),j);
	source = probe_create(target,tid,NULL,buf,probe_do_sink_pre_handlers,
			      probe_do_sink_post_handlers,NULL,1,1);
	free(buf);

	/* Register the j-th exit probe. */
	probeaddr = start + idata->offset;
	if (!__probe_register_addr(source,probeaddr,newrange,
				   PROBEPOINT_BREAK,style,PROBEPOINT_EXEC,
				   PROBEPOINT_LAUTO,bsymbol,start)) {
	    verror("could not register probe %s at 0x%"PRIxADDR"!\n",
		   source->name,probeaddr);
	    goto errout;
	}

	if (!probe_register_source(probe,source)) {
	    verror("could not register probe %s on source %s!\n",
		   probe->name,source->name);
	    probe_free(source,1);
	    goto errout;
	}

	vdebug(3,LA_PROBE,LF_PROBE,
	       "registered %s probe at %s%+d\n",
	       disasm_get_inst_name(idata->type),sname,(int)idata->offset);
    }

    if (cflist) {
	array_list_deep_free(cflist);
	cflist = NULL;
    }
    if (itypes)
	g_hash_table_destroy(itypes);
    if (sname_created)
	free(sname);

    return probe;

 errout:
    if (itypes)
	g_hash_table_destroy(itypes);
    if (funccode)
	free(funccode);
    if (cflist) {
	array_list_deep_free(cflist);
    }
    probe_unregister(probe,1);
    if (probe->autofree)
	probe_free(probe,1);
    if (sname_created)
	free(sname);
    return NULL;

}
#endif /* ENABLE_DISTORM */

struct probe *probe_register_inlined_symbol(struct probe *probe,
					    struct bsymbol *bsymbol,
					    int do_primary,
					    probepoint_style_t style,
					    probepoint_whence_t whence,
					    probepoint_watchsize_t watchsize) {
    struct target *target = probe->target;
    int i;
    struct symbol *symbol = bsymbol->lsymbol->symbol;
    struct probe *pcprobe = NULL;
    struct probe *cprobe;
    size_t bufsiz;
    char *buf;
    struct array_list *cprobes = NULL;
    tid_t tid = probe->thread->tid;
    ADDR paddr;

    if (!SYMBOL_IS_FULL_INSTANCE(symbol)) {
	verror("cannot probe a partial symbol!\n");
	return NULL;
    }

    /* We only try to register on the primary if it has an address
     * (i.e., is not ONLY inlined).
     */
    if (do_primary
	&& !location_resolve_symbol_base(target,tid,bsymbol,&paddr,NULL)) {
	bufsiz = strlen(bsymbol_get_name(bsymbol))+sizeof("_primary")+1;
	buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"%s_primary",bsymbol_get_name(bsymbol));

	pcprobe = probe_create(target,tid,NULL,buf,probe_do_sink_pre_handlers,
			       probe_do_sink_post_handlers,NULL,1,1);
	free(buf);

	/* Register the i-th instance probe. */
	if (!probe_register_symbol(pcprobe,bsymbol,style,whence,watchsize)) {
	    verror("could not register probe %s!\n",pcprobe->name);
	    /* Probe is autofree! */
	    //probe_free(pcprobe,1);
	    pcprobe = NULL;
	    goto errout;
	}

	vdebug(3,LA_PROBE,LF_PROBE,"registered %s probe at 0x%"PRIxADDR"\n",
	       pcprobe->name,probe_addr(pcprobe));

	if (!probe_register_source(probe,pcprobe)) {
	    verror("could not register probe %s on source %s!\n",
		   probe->name,pcprobe->name);
	    probe_free(pcprobe,1);
	    pcprobe = NULL;
	    goto errout;
	}

	vdebug(3,LA_PROBE,LF_PROBE,"registered %s probe on source %s\n",
	       probe->name,pcprobe->name);
    }

    if (symbol->s.ii->inline_instances) {
	struct array_list *iilist = symbol->s.ii->inline_instances;
	cprobes = array_list_create(array_list_len(iilist));

	for (i = 0; i < array_list_len(iilist); ++i) {
	    struct symbol *isymbol = (struct symbol *) \
		array_list_item(iilist,i);
	    /* Use __int() version to not RHOLD(); bsymbol_create RHOLDS it. */
	    struct lsymbol *ilsymbol = lsymbol_create_from_symbol__int(isymbol);
	    if (!ilsymbol) {
		verror("could not create lsymbol for inline instance symbol %s!\n",
		       symbol_get_name(isymbol));
		goto errout;
	    }
	    struct bsymbol *ibsymbol = bsymbol_create(ilsymbol,bsymbol->region);

	    cprobe = probe_create(target,tid,NULL,bsymbol_get_name(ibsymbol),
				  probe_do_sink_pre_handlers,
				  probe_do_sink_post_handlers,NULL,1,1);
	    /* Register the i-th instance probe. */
	    if (!probe_register_symbol(cprobe,ibsymbol,style,whence,watchsize)) {
		verror("could not register probe %s!\n",cprobe->name);
		probe_free(cprobe,1);
		goto errout;
	    }

	    bufsiz = strlen(isymbol->name)+1+6+1+2+1+2+16+1;
	    buf = malloc(bufsiz);
	    snprintf(buf,bufsiz,"%s_inline_at_0x%"PRIxADDR,
		     bsymbol_get_name(bsymbol),
		     probe_addr(cprobe));
	    probe_rename(probe,buf);
	    free(buf);

	    vdebug(3,LA_PROBE,LF_PROBE,"registered %s probe at 0x%"PRIxADDR"\n",
		   cprobe->name,probe_addr(cprobe));

	    if (!probe_register_source(probe,cprobe)) {
		verror("could not register probe %s on source %s!\n",
		       probe->name,cprobe->name);
		probe_free(cprobe,1);
		goto errout;
	    }

	    vdebug(3,LA_PROBE,LF_PROBE,"registered %s probe on source %s\n",
		   probe->name,cprobe->name);

	    array_list_append(cprobes,cprobe);
	}
    }

    if (cprobes)
	array_list_free(cprobes);
    return probe;

 errout:
    /* If we can autofree the top-level parent probe, great, that will
     * free all the sources beneath it we might have created.  But
     * otherwise, we have to free those source probes one by one.
     */
    if (probe->autofree)
	probe_free(probe,1);
    else {
	probe_free(pcprobe,1);
	if (cprobes) {
	    for (i = 0; i < array_list_len(cprobes); ++i) {
		cprobe = (struct probe *)array_list_item(cprobes,i);
		probe_free(cprobe,1);
	    }
	}
    }
    array_list_free(cprobes);

    return NULL;
}
