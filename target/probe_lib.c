#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "common.h"
#include "log.h"
#include "alist.h"

#include "dwdebug.h"

#include "target_api.h"
#include "target.h"

#include "probe_api.h"
#include "probe.h"

struct probe *probe_simple(struct target *target,char *name,
			   probe_handler_t pre_handler,
			   probe_handler_t post_handler,
			   void *handler_data) {
    struct probe *probe = probe_create(target,NULL,name,pre_handler,
				       post_handler,handler_data,0);
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
    struct inst_cf_data *idata;
    size_t bufsiz;
    char *buf;

    if (!SYMBOL_IS_FULL_FUNCTION(bsymbol->lsymbol->symbol)) {
	verror("must supply a full function symbol!\n");
	goto errout;
    }

    if (location_resolve_symbol_base(target,bsymbol,&start,&range)) {
	verror("could not resolve entry PC for function %s!\n",
	       bsymbol->lsymbol->symbol->name);
	return NULL;
    }
    else 
	probeaddr = start;

    if (!force_at_entry) {
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
	source = probe_create(target,NULL,buf,probe_do_sink_pre_handlers,
			      NULL,NULL,1);
	free(buf);
	if (!__probe_register_addr(source,probeaddr,range,
				   PROBEPOINT_BREAK,style,PROBEPOINT_EXEC,
				   PROBEPOINT_LAUTO,bsymbol,start)) {
	    goto errout;
	}

	if (probe_register_source(probe,source)) {
	    probe_free(source,1);
	    goto errout;
	}

	vdebug(3,LOG_P_PROBE,
	       "registered entry addr probe at %s%+d\n",
	       bsymbol->lsymbol->symbol->name,(int)(probeaddr - start));
    }

    /* If @probe has no post_handler, don't register for the return
     * instructions.
     */
    if (!probe->post_handler)
	return probe;

    /* Disassemble the function to find the return instructions. */
    funcrange = &bsymbol->lsymbol->symbol->s.ii->d.f.symtab->range;
    if (!RANGE_IS_PC(funcrange)) {
	verror("range type for function %s was %s, not PC!\n",
	       bsymbol->lsymbol->symbol->name,RANGE_TYPE(funcrange->rtype));
	goto errout;
    }

    funclen = funcrange->r.a.highpc - funcrange->r.a.lowpc;
    funccode = malloc(funclen);

    if (!target_read_addr(target,funcrange->r.a.lowpc,
			  funclen,funccode,NULL)) {
	verror("could not read code before disasm of function %s!\n",
	       bsymbol->lsymbol->symbol->name);
	goto errout;
    }

    if (disasm_get_control_flow_offsets(target,INST_CF_RET,funccode,funclen,
					&cflist,funcrange->r.a.lowpc,noabort)) {
	verror("could not disasm function %s!\n",bsymbol->lsymbol->symbol->name);
	goto errout;
    }

    free(funccode);
    funccode = NULL;

    /* Now register probes for each return instruction! */
    for (j = 0; j < array_list_len(cflist); ++j) {
	idata = (struct inst_cf_data *)array_list_item(cflist,j);

	if (idata->type != INST_RET) {
	    verror("disasm instr was not RET!\n");
	    goto errout;
	}

	/* We should be in the same range, of course; this should never
	 * happen!
	 */
	if (0 && (!target_find_range_real(target,
					  funcrange->r.a.lowpc + idata->offset,
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
	source = probe_create(target,NULL,buf,probe_do_sink_post_handlers,NULL,
			      NULL,1);
	free(buf);

	/* Register the j-th exit probe. */
	probeaddr = funcrange->r.a.lowpc + idata->offset;
	if (!__probe_register_addr(source,probeaddr,newrange,
				   PROBEPOINT_BREAK,style,PROBEPOINT_EXEC,
				   PROBEPOINT_LAUTO,bsymbol,start)) {
	    goto errout;
	}

	if (probe_register_source(probe,source)) {
	    probe_free(source,1);
	    goto errout;
	}

	vdebug(3,LOG_P_PROBE,
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
    struct inst_cf_data *idata;
    size_t bufsiz;
    char *buf;
    GHashTable *itypes = NULL;
    inst_cf_flags_t cfflags = INST_CF_NONE;

    if (!SYMBOL_IS_FULL_FUNCTION(bsymbol->lsymbol->symbol)) {
	verror("must supply a full function symbol!\n");
	goto errout;
    }

    /* Resolve the base address of the function so that we can pass the
     * best information to __probe_register_addr as possible to make
     * debug output clearer.
     */
    if (location_resolve_symbol_base(target,bsymbol,&start,&range)) {
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
    funcrange = &bsymbol->lsymbol->symbol->s.ii->d.f.symtab->range;
    if (!RANGE_IS_PC(funcrange)) {
	verror("range type for function %s was %s, not PC!\n",
	       bsymbol->lsymbol->symbol->name,RANGE_TYPE(funcrange->rtype));
	goto errout;
    }

    /* We allocate an extra NULL byte on the back side because distorm
     * seems to have an off by one error (guessing, according to
     * valgrind!
     */
    funclen = funcrange->r.a.highpc - funcrange->r.a.lowpc;
    funccode = malloc(funclen + 1);

    if (!target_read_addr(target,funcrange->r.a.lowpc,
			  funclen,funccode,NULL)) {
	verror("could not read code before disasm of function %s!\n",
	       bsymbol->lsymbol->symbol->name);
	goto errout;
    }

    funccode[funclen] = 0;

    if (disasm_get_control_flow_offsets(target,cfflags,funccode,funclen,
					&cflist,funcrange->r.a.lowpc,noabort)) {
	verror("could not disasm function %s!\n",bsymbol->lsymbol->symbol->name);
	goto errout;
    }

    free(funccode);
    funccode = NULL;

    /* Now register probes for each instruction! */
    for (j = 0; j < array_list_len(cflist); ++j) {
	idata = (struct inst_cf_data *)array_list_item(cflist,j);

	/* We should be in the same range, of course; this should never
	 * happen!
	 */
	if (0 && (!target_find_range_real(target,
					  funcrange->r.a.lowpc + idata->offset,
					  NULL,NULL,&newrange)
		  || range != newrange)) {
	    verror("could not find sane range!\n");
	    goto errout;
	}
	else {
	    newrange = range;
	}

	probe = (struct probe *)g_hash_table_lookup(itypes,(gpointer)idata->type);

	/* Create the j-th instruction probe.  Assume that all
	 * instruction names fit in 16 bytes.
	 */
	bufsiz = strlen(bsymbol->lsymbol->symbol->name)+1+16+1+11+1;
	buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"%s_%s_%d",bsymbol->lsymbol->symbol->name,
		 disasm_get_inst_name(idata->type),j);
	source = probe_create(target,NULL,buf,probe_do_sink_pre_handlers,
			      probe_do_sink_post_handlers,NULL,1);
	free(buf);

	/* Register the j-th exit probe. */
	probeaddr = funcrange->r.a.lowpc + idata->offset;
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

	vdebug(3,LOG_P_PROBE,
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

    if (!SYMBOL_IS_FULL_INSTANCE(symbol)) {
	verror("cannot probe a partial symbol!\n");
	return NULL;
    }

    /* We only try to register on the primary if it has an address
     * (i.e., is not ONLY inlined).
     */
    if (do_primary && !location_resolve_symbol_base(target,bsymbol,NULL,NULL)) {
	bufsiz = strlen(symbol->name)+1+2+1+2+16+1;
	buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"%s"PRIxADDR,bsymbol_get_name(bsymbol));

	pcprobe = probe_create(target,NULL,buf,probe_do_sink_pre_handlers,
			       probe_do_sink_post_handlers,NULL,1);
	free(buf);

	/* Register the i-th instance probe. */
	if (!probe_register_symbol(pcprobe,bsymbol,style,whence,watchsize)) {
	    verror("could not register probe %s!\n",pcprobe->name);
	    probe_free(pcprobe,1);
	    pcprobe = NULL;
	    goto errout;
	}

	vdebug(3,LOG_P_PROBE,"registered %s probe at 0x%"PRIxADDR"\n",
	       pcprobe->name,probe_addr(pcprobe));

	if (!probe_register_source(probe,pcprobe)) {
	    verror("could not register probe %s on source %s!\n",
		   probe->name,pcprobe->name);
	    probe_free(pcprobe,1);
	    pcprobe = NULL;
	    goto errout;
	}

	vdebug(3,LOG_P_PROBE,"registered %s probe on source %s\n",
	       probe->name,pcprobe->name);
    }

    if (symbol->s.ii->inline_instances) {
	struct array_list *iilist = symbol->s.ii->inline_instances;
	cprobes = array_list_create(array_list_len(iilist));

	for (i = 0; i < array_list_len(iilist); ++i) {
	    struct symbol *isymbol = (struct symbol *) \
		array_list_item(iilist,i);
	    struct bsymbol *ibsymbol = (struct bsymbol *) \
		bsymbol_create(lsymbol_create_from_symbol(isymbol),
			       bsymbol->region,NULL);

	    cprobe = probe_create(target,NULL,bsymbol_get_name(ibsymbol),
				  probe_do_sink_pre_handlers,
				  probe_do_sink_post_handlers,NULL,1);
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

	    vdebug(3,LOG_P_PROBE,"registered %s probe at 0x%"PRIxADDR"\n",
		   cprobe->name,probe_addr(cprobe));

	    if (!probe_register_source(probe,cprobe)) {
		verror("could not register probe %s on source %s!\n",
		       probe->name,cprobe->name);
		probe_free(cprobe,1);
		goto errout;
	    }

	    vdebug(3,LOG_P_PROBE,"registered %s probe on source %s\n",
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
