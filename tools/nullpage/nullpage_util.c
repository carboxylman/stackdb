/*
 * Copyright (c) 2014 The University of Utah
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
#include <argp.h>

#include "log.h"
#include "probe_api.h"
#include "probe.h"
#include "target.h"
#include "target_api.h"

#include "nullpage.h"

/**
 ** Argp parsing stuff.
 **/
error_t np_argp_parse_opt(int key,char *arg,struct argp_state *state);

#define NP_ARGP_TTCTX    30000
#define NP_ARGP_TTDETAIL 30001

struct argp_option np_argp_opts[] = {
    { "np-mode",'N',"[mprotect[,mmap[,pgfault]]]",0,"Set the mode for the NULL page usage detector.  mprotect is probably the cheapest option, because it is called less frequently than mmap, and must always be called to change protections for an mmap'd page (?).  The pgfault style will be most expensive.  To achieve certain, good coverage, choose all three!",0 },
    { "ttctx",NP_ARGP_TTCTX,"none|self|hier|all (default self)",0,"Which threads to display when an event happens.",0 },
    { "ttdetail",NP_ARGP_TTDETAIL,"-2|-1|0|1|2 (default 0)",0,"How much info to print for each thread that is printed.",0 },
    { 0,0,0,0,0,0 },
};
struct argp np_argp = {
    np_argp_opts,np_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};

error_t np_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct np_config *opts = \
	(struct np_config *)target_argp_driver_state(state);
    char *argptr;

    switch (key) {
    case ARGP_KEY_ARG:
	return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_ARGS:
	return ARGP_ERR_UNKNOWN;
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
    case NP_ARGP_TTCTX:
	if (strcmp(arg,"none") == 0)
	    opts->ttctx = 0;
	else if (strcmp(arg,"self") == 0)
	    opts->ttctx = 1;
	else if (strcmp(arg,"hier") == 0)
	    opts->ttctx = 2;
	else if (strcmp(arg,"all") == 0)
	    opts->ttctx = 3;
	else {
	    verror("invalid ttctx %s!\n",arg);
	    return EINVAL;
	}
	break;
    case NP_ARGP_TTDETAIL:
	opts->ttdetail = atoi(arg);
	if (opts->ttdetail < -2 || opts->ttdetail > 2) {
	    verror("invalid ttdetail level %d!\n",opts->ttdetail);
	    return EINVAL;
	}
	break;
    case 'N':
	argptr = arg;
	do {
	    if (strncmp("mmap",argptr,strlen("mmap")) == 0)
		opts->do_mmap = 1;
	    else if (strncmp("mprotect",argptr,strlen("mprotect")) == 0)
		opts->do_mprotect = 1;
	    else if (strncmp("pgfault",argptr,strlen("pgfault")) == 0)
		opts->do_pgfault = 1;
	    else {
		verror("bad nullpage flag spec!\n");
		return EINVAL;
	    }
	} while ((argptr = index(argptr,',')) != NULL && *++argptr != '\0');
	break;
    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

/**
 ** Probe type stuff.
 **/
const char *probe_gettype_np(struct probe *probe) {
    return "nullpage";
}

void *probe_summarize_np(struct probe *probe) {
    return probe->priv;
}

int probe_fini_np(struct probe *probe) {
    struct np_status *nps = (struct np_status *)probe->priv;

    if (nps->pgfault_probe) {
	probe_free(nps->pgfault_probe,0);
	nps->pgfault_probe = NULL;
    }
    if (nps->mprotect_probe) {
	probe_free(nps->mprotect_probe,0);
	nps->mprotect_probe = NULL;
    }
    if (nps->mmap_probe) {
	probe_free(nps->mmap_probe,0);
	nps->mmap_probe = NULL;
    }

    free(nps->config);
    free(nps);

    return 0;
}

static struct probe_ops probe_ops_np = {
    .gettype = probe_gettype_np,
    .summarize = probe_summarize_np,
    .fini = probe_fini_np,
};

/**
 ** Handlers for the subordinate probes that serve the metaprobe.
 **/

#define NP_PROT_READ       0x1
#define NP_PROT_WRITE      0x2
#define NP_PROT_EXEC       0x4

#define NP_MAP_FIXED      0x10

result_t np_mmap_handler(struct probe *probe,tid_t tid,void *data,
			 struct probe *trigger,struct probe *base) {
    struct np_status *nps = (struct np_status *)data;
    struct target_location_ctxt *tlctxt;
    ADDR addr = ADDRMAX;
    unum_t flags = 0;
    struct value *va,*vf;
    int hit = 0;

    tlctxt = target_location_ctxt_create_from_bsymbol(probe->target,TID_GLOBAL,
						      probe->bsymbol);

    va = target_load_symbol_member(probe->target,tlctxt,probe->bsymbol,"addr",
				   NULL,LOAD_FLAG_NONE);
    if (!va) {
	vwarn("could not load sys_mmap.addr!");
	return 0;
    }
    vf = target_load_symbol_member(probe->target,tlctxt,probe->bsymbol,"flags",
				   NULL,LOAD_FLAG_NONE);
    if (!vf) {
	vwarn("could not load sys_mmap.vm_flags!");
	value_free(va);
	return 0;
    }

    addr = v_addr(va);
    flags = v_unum(vf);
    if (addr == 0 && flags & NP_MAP_FIXED) {
	vdebug(3,LA_USER,1,"NULLPAGE: tid %d tried to mmap at 0x0!\n",tid);
	++nps->mmap_violations;
	++nps->total_violations;
	hit = 1;
    }
    else {
	vdebug(5,LA_USER,1,"tid %d mmap(0x%"PRIxADDR",0x%"PRIxNUM")\n",
	       tid,addr,flags);
    }

    value_free(va);
    value_free(vf);
    target_location_ctxt_free(tlctxt);

    if (hit)
	return probe_do_sink_pre_handlers(probe,tid,data,trigger,base);
    else
	return 0;
}

result_t np_mprotect_handler(struct probe *probe,tid_t tid,void *data,
			     struct probe *trigger,struct probe *base) {
    struct np_status *nps = (struct np_status *)data;
    struct target_location_ctxt *tlctxt;
    ADDR addr = ADDRMAX;
    unum_t prot = 0;
    struct value *va,*vp;
    int hit = 0;

    tlctxt = target_location_ctxt_create_from_bsymbol(probe->target,TID_GLOBAL,
						      probe->bsymbol);

    va = target_load_symbol_member(probe->target,tlctxt,probe->bsymbol,"start",
				   NULL,LOAD_FLAG_NONE);
    if (!va) {
	vwarn("could not load sys_mprotect.start!");
	return 0;
    }
    vp = target_load_symbol_member(probe->target,tlctxt,probe->bsymbol,"prot",
				   NULL,LOAD_FLAG_NONE);
    if (!vp) {
	vwarn("could not load sys_mprotect.prot!");
	value_free(va);
	return 0;
    }

    addr = v_addr(va);
    prot = v_unum(vp);

    if (addr == 0 && prot & NP_PROT_EXEC) {
	vdebug(3,LA_USER,1,"NULLPAGE: tid %d tried to mprotect(0x0,%d)!\n",
	       tid,(int)prot);
	++nps->mprotect_violations;
	++nps->total_violations;
	hit = 1;
    }
    else {
	vdebug(5,LA_USER,1,"tid %d mprotect(0x%"PRIxADDR",0x%x)\n",
	       tid,addr,(int)prot);
    }

    value_free(va);
    value_free(vp);
    target_location_ctxt_free(tlctxt);

    if (hit)
	return probe_do_sink_pre_handlers(probe,tid,data,trigger,base);
    else
	return 0;
}

result_t np_pgfault_handler(struct probe *probe,tid_t tid,void *data,
			    struct probe *trigger,struct probe *base) {
    struct np_status *nps = (struct np_status *)data;
    struct target_location_ctxt *tlctxt;
    ADDR addr = ADDRMAX;
    unum_t error_code = 0;
    struct value *va,*vec;
    REG cr2reg;
    int hit = 0;

    tlctxt = target_location_ctxt_create_from_bsymbol(probe->target,TID_GLOBAL,
						      probe->bsymbol);

    vec = target_load_symbol_member(probe->target,tlctxt,probe->bsymbol,
				    "error_code",NULL,LOAD_FLAG_NONE);
    if (!vec) {
	vwarn("could not load do_page_fault.error_code!");
	return 0;
    }
    /*
    va = target_load_symbol_member(probe->target,tlctxt,probe->bsymbol,
                                   "address",NULL,LOAD_FLAG_NONE);
    if (!va) {
	vwarn("could not load do_page_fault.address!");
	value_free(vec);
	return 0;
    }
    addr = v_addr(va);
    */

    cr2reg = target_dw_reg_no_targetname(probe->target,"cr2");
    addr = target_read_reg(probe->target,TID_GLOBAL,cr2reg);

    error_code = v_unum(vec);

    /*
     * Don't just look for instruction fetch faults; if the user tried
     * first to read or write the page, that will be the fault, almost
     * certainly. 
     */
    if (addr == 0) {// && error_code & 0x10) {
	vdebug(3,LA_USER,1,"NULLPAGE: tid %d tried to access(0x0) (0x%x!\n",
	       tid,(int)error_code);
	++nps->pgfault_violations;
	++nps->total_violations;
	hit = 1;
    }
    else {
	vdebug(5,LA_USER,1,"tid %d page_fault(0x%"PRIxADDR",0x%lx)\n",
	       tid,addr,(unsigned long)error_code);
    }

    //value_free(va);
    value_free(vec);
    target_location_ctxt_free(tlctxt);

    if (hit)
	return probe_do_sink_pre_handlers(probe,tid,data,trigger,base);
    else
	return 0;
}

/**
 ** Metaprobe instantiation: create a null-page r/w/x usage "probe".
 **/
struct probe *probe_np(struct target *target,struct np_config *npc,
		       probe_handler_t pre_handler,probe_handler_t post_handler,
		       void *handler_data) {
    struct np_status *nps;
    struct bsymbol *bs = NULL;
    char namebuf[64];
    ADDR addr;

    snprintf(namebuf,64,"nullpage(target %d)",target->id);

    nps = (struct np_status *)calloc(1,sizeof(*nps));
    nps->target = target;
    nps->config = (struct np_config *)calloc(1,sizeof(*nps->config));
    memcpy(nps->config,npc,sizeof(*nps->config));

    nps->np_probe = 
	probe_create(target,TID_GLOBAL,&probe_ops_np,namebuf,
		     pre_handler ? pre_handler : probe_do_sink_pre_handlers,
		     post_handler ? post_handler : probe_do_sink_post_handlers,
		     handler_data,0,1);
    nps->np_probe->priv = nps;

    if (nps->config->do_mmap) {
	bs = target_lookup_sym(target,"sys_mmap",NULL,NULL,
			       SYMBOL_TYPE_FLAG_NONE);
	if (!bs)
	    goto errout;
	nps->mmap_probe = probe_create(target,TID_GLOBAL,NULL,
				       bsymbol_get_name(bs),
				       np_mmap_handler,NULL,nps,0,1);
	if (!probe_register_symbol(nps->mmap_probe,bs,PROBEPOINT_SW,0,0)) {
	    verror("could not register function entry/exit probe on %s;"
		   " aborting!\n",bsymbol_get_name(bs));
	    goto errout;
	}
	if (!probe_register_source(nps->np_probe,nps->mmap_probe)) {
	    verror("could not register nullpage meta probe %s atop probe %s!\n",
		   probe_name(nps->np_probe),probe_name(nps->mmap_probe));
	    goto errout;
	}
	bsymbol_release(bs);
	bs = NULL;
    }

    if (nps->config->do_mprotect) {
	bs = target_lookup_sym(target,"sys_mprotect",NULL,NULL,
			       SYMBOL_TYPE_FLAG_NONE);
	if (!bs)
	    goto errout;
	nps->mprotect_probe = probe_create(target,TID_GLOBAL,NULL,
					   bsymbol_get_name(bs),
					   np_mprotect_handler,NULL,nps,0,1);
	if (!probe_register_symbol(nps->mprotect_probe,bs,PROBEPOINT_SW,0,0)) {
	    verror("could not register function entry/exit probe on %s;"
		   " aborting!\n",bsymbol_get_name(bs));
	    goto errout;
	}
	if (!probe_register_source(nps->np_probe,nps->mprotect_probe)) {
	    verror("could not register nullpage meta probe %s atop probe %s!\n",
		   probe_name(nps->np_probe),probe_name(nps->mprotect_probe));
	    goto errout;
	}
	bsymbol_release(bs);
	bs = NULL;
    }

    if (nps->config->do_pgfault) {
	bs = target_lookup_sym(target,"do_page_fault",NULL,NULL,
			       SYMBOL_TYPE_FLAG_NONE);
	if (!bs)
	    goto errout;
	nps->pgfault_probe = probe_create(target,TID_GLOBAL,NULL,
					  bsymbol_get_name(bs),
					  np_pgfault_handler,NULL,nps,0,1);
	if (!probe_register_symbol(nps->pgfault_probe,bs,PROBEPOINT_SW,0,0)) {
	    verror("could not register function entry/exit probe on %s;"
		   " aborting!\n",bsymbol_get_name(bs));
	    goto errout;
	}
	if (!probe_register_source(nps->np_probe,nps->pgfault_probe)) {
	    verror("could not register nullpage master probe %s atop probe %s!\n",
		   probe_name(nps->np_probe),probe_name(nps->pgfault_probe));
	    goto errout;
	}
	bsymbol_release(bs);
	bs = NULL;
    }

    return nps->np_probe;

 errout:
    if (bs)
	bsymbol_release(bs);
    if (nps->np_probe) {
	probe_free(nps->np_probe,1);
    }
    else {
	if (nps->config)
	    free(nps->config);
	if (nps)
	    free(nps);
    }

    return NULL;
}
