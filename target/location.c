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

#include "target.h"
#include "dwdebug_priv.h"

/**
 ** The interface to the dwdebug library's lsymbol_resolve* and
 ** symbol_resolve* functions.
 **/

int __target_location_ops_setcurrentframe(struct location_ctxt *lctxt,
					  int frame) {
    struct target_location_ctxt *tlctxt = 
	(struct target_location_ctxt *)lctxt->priv;
    struct target_location_ctxt_frame *tlctxtf = 
	target_location_ctxt_get_frame(tlctxt,frame);

    if (!tlctxtf) {
	errno = EBADSLT;
	return -1;
    }

    if (tlctxtf->bsymbol)
	tlctxt->region = tlctxtf->bsymbol->region;
    else if (tlctxtf->alt_bsymbol)
	tlctxt->region = tlctxtf->alt_bsymbol->region;
    lctxt->current_frame = frame;
    return 0;
}

struct symbol *__target_location_ops_getsymbol(struct location_ctxt *lctxt) {
    struct target_location_ctxt *tlctxt = 
	(struct target_location_ctxt *)lctxt->priv;
    struct target_location_ctxt_frame *tlctxtf = 
	target_location_ctxt_current_frame(tlctxt);

    if (tlctxtf->bsymbol)
	return bsymbol_get_symbol(tlctxtf->bsymbol);
    else if (tlctxtf->alt_bsymbol)
	return bsymbol_get_symbol(tlctxtf->alt_bsymbol);
    else
	return NULL;
}

struct debugfile *__target_location_ops_getdebugfile(struct location_ctxt *lctxt) {
    struct target_location_ctxt *tlctxt =
	(struct target_location_ctxt *)lctxt->priv;
    struct target *target = tlctxt->thread->target;
    struct target_location_ctxt_frame *tlctxtf =
	target_location_ctxt_current_frame(tlctxt);
    struct symbol *symbol;
    struct symbol *root;
    struct debugfile *debugfile;
    ADDR ipval;

    /* Find our debugfile. */
    if (tlctxtf->bsymbol) {
	symbol = bsymbol_get_symbol(tlctxtf->bsymbol);
	if (symbol) {
	    root = symbol_find_root(symbol);
	    SYMBOL_RX_ROOT(root,srd);
	    debugfile = srd->debugfile;
	    if (debugfile)
		return debugfile;
	}
    }
    else if (tlctxtf->alt_bsymbol) {
	symbol = bsymbol_get_symbol(tlctxtf->alt_bsymbol);
	if (symbol) {
	    root = symbol_find_root(symbol);
	    SYMBOL_RX_ROOT(root,srd);
	    debugfile = srd->debugfile;
	    if (debugfile)
		return debugfile;
	}
    }
    else {
	ipval = (ADDR)(uintptr_t) \
	    g_hash_table_lookup(tlctxtf->registers,
				(gpointer)(uintptr_t)target->ipregno);
	if (ipval != 0) {
	    debugfile = target_lookup_debugfile(target,ipval);
	    if (debugfile)
		return debugfile;
	}
    }

    vwarnopt(11,LA_DEBUG,LF_DLOC,
	     "could not find debugfile for frame %d!\n",tlctxtf->frame);
    errno = EINVAL;
    return NULL;
}

int __target_location_ops_getaddrsize(struct location_ctxt *lctxt) {
    struct target_location_ctxt *tlctxt;

    tlctxt = (struct target_location_ctxt *)lctxt->priv;
    return tlctxt->thread->target->arch->wordsize;
}

int __target_location_ops_getregno(struct location_ctxt *lctxt,
				   common_reg_t creg,REG *o_reg) {
    struct target_location_ctxt *tlctxt;
    REG reg;

    tlctxt = (struct target_location_ctxt *)lctxt->priv;
    errno = 0;
    
    if (target_cregno(tlctxt->thread->target,creg,&reg))
	return -1;

    if (o_reg)
	*o_reg = reg;
    return 0;
}

int __target_location_ops_readreg(struct location_ctxt *lctxt,
				  REG regno,REGVAL *regval) {
    struct target_location_ctxt *tlctxt;
    REGVAL retval;
    struct target_location_ctxt_frame *tlctxtf;
    gpointer v;

    tlctxt = (struct target_location_ctxt *)lctxt->priv;
    if (lctxt->current_frame == 0) {
	errno = 0;
	retval = target_read_reg(tlctxt->thread->target,tlctxt->thread->tid,
				 regno);
	if (errno) {
	    verror("could not read reg %"PRIiREG" in tid %"PRIiTID": %s!\n",
		   regno,tlctxt->thread->tid,strerror(errno));
	    return -1;
	}

	*regval = retval;
	return 0;
    }
    else {
	if (!tlctxt->frames) {
	    verror("no unwinding context for thread %"PRIiTID";"
		   " cannot read %"PRIiREG" in frame %d\n",
		   tlctxt->thread->tid,regno,lctxt->current_frame);
	    errno = EINVAL;
	    return -1;
	}
	tlctxtf = target_location_ctxt_current_frame(tlctxt);
	if (!tlctxtf) {
	    verror("frame %d not available yet for thread %"PRIiTID";"
		   " cannot read %"PRIiREG"\n",
		   lctxt->current_frame,tlctxt->thread->tid,regno);
	    errno = EINVAL;
	    return -1;
	}

	/* Check the cache. */
	if (g_hash_table_lookup_extended(tlctxtf->registers,
					 (gpointer)(uintptr_t)regno,NULL,&v) == TRUE) {
	    if (regval)
		*regval = (REGVAL)(uintptr_t)v;
	    return 0;
	}

	errno = EADDRNOTAVAIL;
	return -1;
    }
}

int __target_location_ops_writereg(struct location_ctxt *lctxt,
				   REG regno,REGVAL regval) {
    struct target_location_ctxt *tlctxt;

    tlctxt = (struct target_location_ctxt *)lctxt->priv;
    if (lctxt->current_frame == 0) {
	errno = 0;
	if (target_write_reg(tlctxt->thread->target,tlctxt->thread->tid,
			     regno,regval)) {
	    verror("could not write 0x%"PRIxREGVAL" to  reg %"PRIiREG
		   " in tid %"PRIiTID": %s!\n",
		   regval,regno,tlctxt->thread->tid,strerror(errno));
	    return -1;
	}
	return 0;
    }

    errno = EINVAL;
    return -1;
}

int __target_location_ops_cachereg(struct location_ctxt *lctxt,
				   REG regno,REGVAL regval) {
    struct target_location_ctxt *tlctxt;
    struct target_location_ctxt_frame *tlctxtf;

    tlctxt = (struct target_location_ctxt *)lctxt->priv;

    if (lctxt->current_frame == 0) {
	errno = EINVAL;
	return -1;
    }

    if (!tlctxt->frames) {
	verror("no unwinding context for thread %"PRIiTID";"
	       " cannot cache %"PRIiREG" 0x%"PRIxREGVAL" in frame %d\n",
	       tlctxt->thread->tid,regno,regval,lctxt->current_frame);
	errno = EINVAL;
	return -1;
    }
    tlctxtf = target_location_ctxt_current_frame(tlctxt);
    if (!tlctxtf) {
	verror("frame %d not available yet for thread %"PRIiTID";"
	       " cannot cache %"PRIiREG" 0x%"PRIxREGVAL"\n",
	       lctxt->current_frame,tlctxt->thread->tid,regno,regval);
	errno = EINVAL;
	return -1;
    }

    g_hash_table_insert(tlctxtf->registers,
			(gpointer)(uintptr_t)regno,(gpointer)(uintptr_t)regval);

    errno = 0;
    return 0;
}

int __target_location_ops_readipreg(struct location_ctxt *lctxt,REGVAL *regval) {
    struct target_location_ctxt *tlctxt;

    tlctxt = (struct target_location_ctxt *)lctxt->priv;

    return __target_location_ops_readreg(lctxt,
					 tlctxt->thread->target->ipregno,regval);
}

int __target_location_ops_readword(struct location_ctxt *lctxt,
				   ADDR real_addr,ADDR *pval) {
    struct target_location_ctxt *tlctxt;
    unsigned char *rc;

    tlctxt = (struct target_location_ctxt *)lctxt->priv;

    rc = target_read_addr(tlctxt->thread->target,real_addr,
			  tlctxt->thread->target->arch->ptrsize,(unsigned char *)pval);
    if (rc != (unsigned char *)pval) {
	verror("could not read 0x%"PRIxADDR": %s!\n",
	       real_addr,strerror(errno));
	return -1;
    }

    return 0;
}

int __target_location_ops_writeword(struct location_ctxt *lctxt,
				    ADDR real_addr,ADDR pval) {
    struct target_location_ctxt *tlctxt;
    unsigned long rc;

    tlctxt = (struct target_location_ctxt *)lctxt->priv;

    rc = target_write_addr(tlctxt->thread->target,real_addr,
			   tlctxt->thread->target->arch->ptrsize,
			   (unsigned char *)&pval);
    if (rc != tlctxt->thread->target->arch->ptrsize) {
	verror("could not write 0x%"PRIxADDR" to 0x%"PRIxADDR": %s!\n",
	       pval,real_addr,strerror(errno));
	return -1;
    }

    return 0;
}

int __target_location_ops_relocate(struct location_ctxt *lctxt,
				   ADDR obj_addr,ADDR *real_addr) {
    struct target_location_ctxt *tlctxt;

    tlctxt = (struct target_location_ctxt *)lctxt->priv;

    /* Relocate the obj_addr according to tlctxt->region */
    *real_addr = memregion_relocate(tlctxt->region,obj_addr,NULL);

    return 0;
}

int __target_location_ops_unrelocate(struct location_ctxt *lctxt,
				     ADDR real_addr,ADDR *obj_addr) {
    struct target_location_ctxt *tlctxt;

    tlctxt = (struct target_location_ctxt *)lctxt->priv;

    /* Relocate the obj_addr according to tlctxt->region */
    *obj_addr = memregion_unrelocate(tlctxt->region,real_addr,NULL);

    return 0;
}

struct location_ops target_location_ops = {
    .setcurrentframe = __target_location_ops_setcurrentframe,
    .getdebugfile = __target_location_ops_getdebugfile,
    .getsymbol = __target_location_ops_getsymbol,
    .readreg = __target_location_ops_readreg,
    .writereg = __target_location_ops_writereg,
    .cachereg = __target_location_ops_cachereg,
    .readipreg = __target_location_ops_readipreg,

    .readword = __target_location_ops_readword,
    .writeword = __target_location_ops_writeword,
    .relocate = __target_location_ops_relocate,
    .unrelocate = __target_location_ops_unrelocate,

    .getregno = __target_location_ops_getregno,
    .getaddrsize = __target_location_ops_getaddrsize,
};
