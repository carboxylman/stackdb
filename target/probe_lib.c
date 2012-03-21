#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "common.h"
#include "log.h"

#include "dwdebug.h"

#include "target_api.h"
#include "target.h"

#include "probe_api.h"
#include "probe.h"

struct probe *probe_register_function(struct probe *probe,
				      probepoint_style_t style,
				      struct bsymbol *bsymbol,
				      int force_at_entry) {
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
    unsigned char *funccode;
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
	source = probe_create(target,NULL,buf,probe->pre_handler,NULL,NULL,1);
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
					&cflist,funcrange->r.a.lowpc)) {
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
	source = probe_create(target,NULL,buf,probe->post_handler,NULL,NULL,
			      1);
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
	array_list_free(cflist);
	cflist = NULL;
    }

    return probe;

 errout:
    if (funccode)
	free(funccode);
    if (cflist) {
	array_list_deep_free(cflist);
	array_list_free(cflist);
    }
    probe_unregister(probe,1);
    if (probe->autofree)
	probe_free(probe,1);
    return NULL;
}

/* Helper function used below. */
struct probe *probe_register_function_instrs(struct probe *probe,
					     probepoint_style_t style,
					     struct bsymbol *bsymbol,
					     inst_cf_flags_t flags) {
    struct target *target = probe->target;
    struct memrange *range;
    struct memrange *newrange;
    ADDR start;
    ADDR probeaddr;
    struct probe *source;
    int j;
    struct array_list *cflist = NULL;
    struct range *funcrange;
    unsigned char *funccode;
    unsigned int funclen;
    struct inst_cf_data *idata;
    size_t bufsiz;
    char *buf;

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

    if (disasm_get_control_flow_offsets(target,flags,funccode,funclen,
					&cflist,funcrange->r.a.lowpc)) {
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

	/* Create the j-th instruction probe.  Assume that all
	 * instruction names fit in 16 bytes.
	 */
	bufsiz = strlen(bsymbol->lsymbol->symbol->name)+1+16+1+11+1;
	buf = malloc(bufsiz);
	snprintf(buf,bufsiz,"%s_%s_%d",bsymbol->lsymbol->symbol->name,
		 disasm_get_inst_name(idata->type),j);
	source = probe_create(target,NULL,buf,probe->pre_handler,
			      probe->post_handler,NULL,1);
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
	       "registered %s probe at %s%+d\n",
	       disasm_get_inst_name(idata->type),
	       bsymbol->lsymbol->symbol->name,(int)idata->offset);
    }

    if (cflist) {
	array_list_deep_free(cflist);
	array_list_free(cflist);
	cflist = NULL;
    }

    return probe;

 errout:
    if (funccode)
	free(funccode);
    if (cflist) {
	array_list_deep_free(cflist);
	array_list_free(cflist);
    }
    probe_unregister(probe,1);
    if (probe->autofree)
	probe_free(probe,1);
    return NULL;

}
