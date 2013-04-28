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
    if (SYMBOL_IS_FULL_FUNCTION(bsymbol->lsymbol->symbol)) {
	funcrange = &bsymbol->lsymbol->symbol->s.ii->d.f.symtab->range;
	if (!RANGE_IS_PC(funcrange)) {
	    verror("range type for function %s was %s, not PC!\n",
		   bsymbol->lsymbol->symbol->name,RANGE_TYPE(funcrange->rtype));
	    goto errout;
	}

	funclen = funcrange->r.a.highpc - funcrange->r.a.lowpc;
	/* This should not ever happen. */

	if (start != funcrange->r.a.lowpc) {
	    vwarn("full function %s does not have matching base (0x%"PRIxADDR")"
		  " and lowpc (0x%"PRIxADDR") values!\n",
		  bsymbol_get_name(bsymbol),start,funcrange->r.a.lowpc);
	    start = funcrange->r.a.lowpc;
	    funclen = funcrange->r.a.highpc - start;
	}
    }
    else
	funclen = symbol_bytesize(bsymbol->lsymbol->symbol);

    funccode = malloc(funclen);

    if (!target_read_addr(target,start,funclen,funccode)) {
	verror("could not read code before disasm of function %s!\n",
	       bsymbol->lsymbol->symbol->name);
	goto errout;
    }

    if (disasm_get_control_flow_offsets(target,INST_CF_RET | INST_CF_IRET,
					funccode,funclen,
					&cflist,start,noabort)) {
	verror("could not disasm function %s!\n",bsymbol->lsymbol->symbol->name);
	goto errout;
    }

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
    if (funccode)
	free(funccode);
    if (cflist) {
	array_list_deep_free(cflist);
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

    if (!SYMBOL_IS_FUNCTION(bsymbol->lsymbol->symbol)) {
	verror("must supply a function symbol!\n");
	goto errout;
    }
    else if (!SYMBOL_IS_FULL_FUNCTION(bsymbol->lsymbol->symbol)
	     && symbol_bytesize(bsymbol->lsymbol->symbol) <= 0) {
	verror("partial function symbols must have non-zero length!\n");
	goto errout;
    }

    /* Resolve the base address of the function so that we can pass the
     * best information to __probe_register_addr as possible to make
     * debug output clearer.
     */
    if (location_resolve_function_base(target,bsymbol->lsymbol,
				       bsymbol->region,&start,&range)) {
	verror("could not resolve entry PC for function %s!\n",
	       bsymbol->lsymbol->symbol->name);
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
		   bsymbol->lsymbol->symbol->name,RANGE_TYPE(funcrange->rtype));
	    goto errout;
	}

	funclen = funcrange->r.a.highpc - funcrange->r.a.lowpc;
    }
    else
	funclen = symbol_bytesize(bsymbol->lsymbol->symbol);

    /* We allocate an extra NULL byte on the back side because distorm
     * seems to have an off by one error (guessing, according to
     * valgrind!
     */
    funccode = malloc(funclen + 1);

    if (!target_read_addr(target,start,funclen,funccode)) {
	verror("could not read code before disasm of function %s!\n",
	       bsymbol->lsymbol->symbol->name);
	goto errout;
    }

    funccode[funclen] = 0;

    if (disasm_get_control_flow_offsets(target,cfflags,funccode,funclen,
					&cflist,start,noabort)) {
	verror("could not disasm function %s!\n",bsymbol->lsymbol->symbol->name);
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
	bufsiz = strlen(bsymbol->lsymbol->symbol->name)+1+16+1+11+1;
	buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"%s_%s_%d",bsymbol->lsymbol->symbol->name,
		 disasm_get_inst_name(idata->type),j);
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
	       disasm_get_inst_name(idata->type),
	       bsymbol->lsymbol->symbol->name,(int)idata->offset);
    }

    if (cflist) {
	array_list_deep_free(cflist);
	cflist = NULL;
    }
    if (itypes)
	g_hash_table_destroy(itypes);

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
    return NULL;

}

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

    if (!SYMBOL_IS_FULL_INSTANCE(symbol)) {
	verror("cannot probe a partial symbol!\n");
	return NULL;
    }

    /* We only try to register on the primary if it has an address
     * (i.e., is not ONLY inlined).
     */
    if (do_primary
	&& !location_resolve_symbol_base(target,tid,bsymbol,NULL,NULL)) {
	bufsiz = strlen(symbol->name)+1+2+1+2+16+1;
	buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"%s"PRIxADDR,bsymbol_get_name(bsymbol));

	pcprobe = probe_create(target,tid,NULL,buf,probe_do_sink_pre_handlers,
			       probe_do_sink_post_handlers,NULL,1,1);
	free(buf);

	/* Register the i-th instance probe. */
	if (!probe_register_symbol(pcprobe,bsymbol,style,whence,watchsize)) {
	    verror("could not register probe %s!\n",pcprobe->name);
	    probe_free(pcprobe,1);
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
