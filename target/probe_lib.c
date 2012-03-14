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


struct probe *probe_register_symbol(struct target *target,struct bsymbol *bsymbol,
				    probepoint_style_t style,
				    probepoint_whence_t whence,
				    probe_handler_t pre_handler,
				    probe_handler_t post_handler) {
    struct probe *probe;
    struct memrange *range;
    ADDR start;
    ADDR prologueend;
    ADDR probeaddr;
    int ssize;

    if (!SYMBOL_IS_FULL_INSTANCE(bsymbol->lsymbol->symbol)) {
	verror("cannot probe a partial symbol!\n");
	return NULL;
    }

    if (SYMBOL_IS_FULL_FUNCTION(bsymbol->lsymbol->symbol)) {
	if (location_resolve_symbol_base(target,bsymbol,&start,&range)) {
	    verror("could not resolve entry PC for function %s!\n",
		   bsymbol->lsymbol->symbol->name);
	    return NULL;
	}
	else 
	    probeaddr = start;

	if (location_resolve_function_prologue_end(target,bsymbol,
						   &prologueend,&range)) {
	    vwarn("could not resolve prologue_end for function %s!\n",
		  bsymbol->lsymbol->symbol->name);
	}
	else 
	    probeaddr = prologueend;

	probe = probe_register_break(target,probeaddr,range,style,
				     pre_handler,post_handler,
				     bsymbol->lsymbol,start);
    }
    else if (SYMBOL_IS_FULL_LABEL(bsymbol->lsymbol->symbol)) {
	if (location_resolve_symbol_base(target,bsymbol,&probeaddr,&range)) {
	    verror("could not resolve base addr for label %s!\n",
		   bsymbol->lsymbol->symbol->name);
	    return NULL;
	}

	probe = probe_register_break(target,probeaddr,range,style,
				     pre_handler,post_handler,
				     bsymbol->lsymbol,probeaddr);
    }
    else if (SYMBOL_IS_FULL_VAR(bsymbol->lsymbol->symbol)) {
	ssize = symbol_type_full_bytesize(bsymbol->lsymbol->symbol->datatype);
	if (ssize <= 0) {
	    verror("bad size (%d) for type of %s!\n",
		   ssize,bsymbol->lsymbol->symbol->name);
	    return NULL;
	}

	if (location_resolve_symbol_base(target,bsymbol,&probeaddr,&range)) {
	    verror("could not resolve base addr for var %s!\n",
		   bsymbol->lsymbol->symbol->name);
	    return NULL;
	}

	probe = \
	    probe_register_watch(target,probeaddr,range,style,whence,
				 probepoint_closest_watchsize(ssize),
				 pre_handler,post_handler,
				 bsymbol->lsymbol,probeaddr);
    }
    else {
	verror("unknown symbol type '%s'!\n",
	       SYMBOL_TYPE(bsymbol->lsymbol->symbol->type));
	return NULL;
    }

    return probe;
}
