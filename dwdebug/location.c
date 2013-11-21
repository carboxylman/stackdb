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
#include <errno.h>

#include "dwdebug.h"
#include "dwdebug_priv.h"

static void loclistloc_free(struct loclistloc *loclist) {
    struct loclistloc *last = NULL;

    while (loclist) {
	location_free(loclist->loc);
	last = loclist;
	loclist = loclist->next;
	free(last);
    }
}

/**
 ** Locations.
 **/
struct location *location_create(void) {
    struct location *location = \
	(struct location *)calloc(1,sizeof(*location));
    location->loctype = LOCTYPE_UNKNOWN;
    return location;
}

int location_set_addr(struct location *l,ADDR addr) {
    if (LOCATION_IS_UNKNOWN(l) || LOCATION_IS_ADDR(l)) {
	l->loctype = LOCTYPE_ADDR;
	l->l.addr = addr;
	return 0;
    }
    return -1;
}

int location_set_reg(struct location *l,REG reg) {
    if (LOCATION_IS_UNKNOWN(l) || LOCATION_IS_REG(l)) {
	l->loctype = LOCTYPE_REG;
	l->l.reg = reg;
	return 0;
    }
    return -1;
}

int location_set_reg_addr(struct location *l,REG reg) {
    if (LOCATION_IS_UNKNOWN(l) || LOCATION_IS_REG_ADDR(l)) {
	l->loctype = LOCTYPE_REG_ADDR;
	l->l.reg = reg;
	return 0;
    }
    return -1;
}

int location_set_reg_offset(struct location *l,REG reg,OFFSET offset) {
    if (LOCATION_IS_UNKNOWN(l) || LOCATION_IS_REG_OFFSET(l)) {
	l->loctype = LOCTYPE_REG_OFFSET;
#if 0
	if (reg > ((1 << LOCATION_REMAINING_BITS) - 1)) {
	    verror("regoffset reg %d too big!\n",reg);
	    return -1;
	}
#endif
	l->extra = reg;
	l->l.offset = offset;
	return 0;
    }
    return -1;
}

int location_set_member_offset(struct location *l,OFFSET offset) {
    if (LOCATION_IS_UNKNOWN(l) || LOCATION_IS_M_OFFSET(l)) {
	l->loctype = LOCTYPE_MEMBER_OFFSET;
	l->l.offset = offset;
	return 0;
    }
    return -1;
}

int location_set_fbreg_offset(struct location *l,OFFSET offset) {
    if (LOCATION_IS_UNKNOWN(l) || LOCATION_IS_FB_OFFSET(l)) {
	l->loctype = LOCTYPE_FBREG_OFFSET;
	l->l.offset = offset;
	return 0;
    }
    return -1;
}

int location_set_loclist(struct location *l,struct loclistloc *list) {
    if (LOCATION_IS_UNKNOWN(l) || LOCATION_IS_LOCLIST(l)) {
	l->loctype = LOCTYPE_LOCLIST;
	if (l->l.loclist && !l->nofree)
	    loclistloc_free(l->l.loclist);
	l->nofree = 0;
	l->l.loclist = list;
	return 0;
    }
    return -1;
}

int location_set_implicit_word(struct location *loc,ADDR word) {
    if (LOCATION_IS_UNKNOWN(loc) || LOCATION_IS_IMPLICIT_WORD(loc)) {
	loc->loctype = LOCTYPE_IMPLICIT_WORD;
	loc->l.word = word;
	return 0;
    }
    return -1;
}

int location_set_implicit_data(struct location *loc,char *data,int len,
			       int nocopy) {
    if (LOCATION_IS_UNKNOWN(loc) || LOCATION_IS_RUNTIME(loc)) {
	if (len < 0)
	    return -1;
#if __WORDSIZE == 4
	if (data && len > 0 && len > ((1 << LOCATION_REMAINING_BITS) - 1)) {
	    verror("implicit data len %d too big!\n",len);
	    return -1;
	}
#endif
	loc->loctype = LOCTYPE_IMPLICIT_DATA;

	if (loc->l.data)
	    free(loc->l.data);
	if (data) {
	    if (!nocopy) {
		loc->nofree = 0;
		loc->l.data = malloc(len);
		memcpy(loc->l.data,data,len);
	    }
	    else {
		loc->nofree = 1;
		loc->l.data = data;
	    }
	    loc->extra = len;
	}
	else {
	    loc->l.data = NULL;
	    loc->extra = 0;
	}
	return 0;
    }
    return -1;
}

int location_set_runtime(struct location *l,char *data,int len,int nocopy) {
    if (LOCATION_IS_UNKNOWN(l) || LOCATION_IS_RUNTIME(l)) {
	if (len < 0)
	    return -1;
#if __WORDSIZE == 4
	if (data && len > 0 && len > ((1 << LOCATION_REMAINING_BITS) - 1)) {
	    verror("runtime data len %d too big!\n",len);
	    return -1;
	}
#endif
	l->loctype = LOCTYPE_RUNTIME;

	if (l->l.data)
	    free(l->l.data);
	if (data) {
	    if (!nocopy) {
		l->nofree = 0;
		l->l.data = malloc(len);
		memcpy(l->l.data,data,len);
	    }
	    else {
		l->nofree = 1;
		l->l.data = data;
	    }
	    l->extra = len;
	}
	else {
	    l->l.data = NULL;
	    l->extra = 0;
	}
	return 0;
    }
    return -1;
}

int location_update_loclist(struct location *loc,
			    ADDR start,ADDR end,struct location *rloc,
			    int *action) {
    struct loclistloc *l, *lastl, *newl;

    if (!(LOCATION_IS_UNKNOWN(loc) || LOCATION_IS_LOCLIST(loc))) {
	verror("location is not a loclist!\n");
	return -1;
    }

    loc->loctype = LOCTYPE_LOCLIST;

    /*
     * We maintain location->loclist as a sorted list by start.
     *
     * So we look for any items that have @start, and update end if
     * necessary; else we insert a new loclistloc at the right place.
     */
    if (!loc->l.loclist) {
	loc->l.loclist = (struct loclistloc *)calloc(1,sizeof(*loc->l.loclist));
	loc->l.loclist->start = start;
	loc->l.loclist->end = end;
	loc->l.loclist->loc = rloc;
	loc->l.loclist->next = NULL;

	if (action)
	    *action = 1;

	vdebug(8,LA_DEBUG,LF_DWARF,
	       "init loclist(0x%"PRIxADDR",0x%"PRIxADDR")\n",
	       start,end);

	return 0;
    }
    else {
	lastl = NULL;
	l = loc->l.loclist;
	while (l) {
	    if (l->start == start) {
		if (l->end != end) {
		    vwarn("inconsistent loclist range(0x%"PRIxADDR",0x%"PRIxADDR")"
			  " (new end 0x%"PRIxADDR"); updating!\n",
			  l->start,l->end,end);

		    l->end = end;

		    if (action)
			*action = 2;

		    return 0;
		}
		else {
		    vdebug(8,LA_DEBUG,LF_DWARF,
			   "loclist range(0x%"PRIxADDR",0x%"PRIxADDR") matched;"
			   " not updating; freeing \"new\" location!\n",
			   start,end);

		    location_free(rloc);

		    if (action)
			*action = 0;

		    return 0;
		}
	    }
	    else if (l->start > start) {
		/* Insert a new one between lastl and l */
		newl = (struct loclistloc *)calloc(1,sizeof(*newl));
		newl->start = start;
		newl->end = end;
		newl->loc = rloc;
		newl->next = l;
		if (lastl)
		    lastl->next = newl;
		else
		    loc->l.loclist = newl;

		if (action)
		    *action = 1;

		vdebug(8,LA_DEBUG,LF_DWARF,
		       "added loclist range (0x%"PRIxADDR",0x%"PRIxADDR")\n",
		       start,end);

		return 0;
	    }
	    else {
		lastl = l;
		l = l->next;
	    }
	}

	/* If we get here, we need to add one at the tail. */
	newl = (struct loclistloc *)calloc(1,sizeof(*newl));
	newl->start = start;
	newl->end = end;
	newl->loc = rloc;
	newl->next = NULL;
	lastl->next = newl;

	if (action)
	    *action = 1;

	vdebug(8,LA_DEBUG,LF_DWARF,
	       "added loclist range (0x%"PRIxADDR",0x%"PRIxADDR")\n",
	       start,end);

	return 0;
    }
}

/*
 * All copies are full and deep.
 */
struct location *location_copy(struct location *location) {
    struct location *retval;
    struct loclistloc *old, *new, *lastnew = NULL;

    retval = location_create();
    retval->loctype = location->loctype;
    retval->extra = location->extra;

    if (LOCATION_IS_RUNTIME(location)) {
	retval->l.data = malloc(location->extra);
	memcpy(&retval->l.data,&location->l.data,location->extra);
    }
    else if (LOCATION_IS_LOCLIST(location)) {
	old = location->l.loclist;
	while (old) {
	    new = calloc(1,sizeof(*new));
	    new->start = old->start;
	    new->end = old->end;
	    new->loc = location_copy(old->loc);
	    if (lastnew)
		lastnew = new;
	    else 
		retval->l.loclist = new;

	    lastnew = new;
	    old = old->next;
	}
    }
    else 
	memcpy(&retval->l,&location->l,sizeof(location->l));

    return retval;
}

void location_internal_free(struct location *location) {
    if (location->loctype == LOCTYPE_RUNTIME
	|| location->loctype == LOCTYPE_IMPLICIT_DATA) {
	if (location->l.data && !location->nofree) 
	    free(location->l.data);
    }
    else if (location->loctype == LOCTYPE_LOCLIST) {
	if (location->l.loclist)
	    loclistloc_free(location->l.loclist);
    }
}

void location_free(struct location *location) {
    location_internal_free(location);
    free(location);
}

void loclistloc_dump(struct loclistloc *list,struct dump_info *ud) {
    int i;
    struct dump_info udn = {
	.stream = ud->stream,
	.prefix = "",
	.detail = ud->detail,
	.meta = ud->meta,
    };

    fprintf(ud->stream,"%sLOCLIST(",ud->prefix);
    i = 0;
    while (list) {
	if (i > 0)
	    fprintf(ud->stream,",");
	fprintf(ud->stream,"[0x%" PRIxADDR ",0x%" PRIxADDR,
		list->start,list->end);
	if (list->loc) {
	    fprintf(ud->stream,"->");
	    location_dump(list->loc,&udn);
	}
	fprintf(ud->stream,"]");

	++i;
	list = list->next;
    }
    fprintf(ud->stream,")");
}

void location_dump(struct location *location,struct dump_info *ud) {
    switch(location->loctype) {
    case LOCTYPE_ADDR:
	fprintf(ud->stream,"0x%" PRIxADDR,location->l.addr);
	break;
    case LOCTYPE_REG:
	fprintf(ud->stream,"REG(%d)",location->l.reg);
	break;
    case LOCTYPE_REG_ADDR:
	fprintf(ud->stream,"REGADDR(%d)",location->l.reg);
	break;
    case LOCTYPE_REG_OFFSET:
	fprintf(ud->stream,"REGOFFSET(%hhd,%"PRIiOFFSET")",
		(REG)location->extra,location->l.offset);
	break;
    case LOCTYPE_FBREG_OFFSET:
	fprintf(ud->stream,"FBREGOFFSET(%"PRIiOFFSET")",location->l.offset);
	break;
    case LOCTYPE_MEMBER_OFFSET:
	fprintf(ud->stream,"MEMBEROFFSET(%"PRIiOFFSET")",
		location->l.offset);
	break;
    case LOCTYPE_IMPLICIT_WORD:
	fprintf(ud->stream,"IMPLICIT_WORD(0x%"PRIxADDR")",location->l.word);
	break;
    case LOCTYPE_IMPLICIT_DATA:
	fprintf(ud->stream,"IMPLICIT_DATA(%p,%d)",
		location->l.data,(int)location->extra);
	break;
    case LOCTYPE_RUNTIME:
	fprintf(ud->stream,"RUNTIME(%p,%d)",
		location->l.data,(int)location->extra);
	break;
    case LOCTYPE_LOCLIST:
	loclistloc_dump(location->l.loclist,ud);
	break;
    case LOCTYPE_UNKNOWN:
    default:
	break;
    }
}






#if 0
OFFSET location_resolve_offset(struct location *location,
			       struct array_list *symbol_chain,
			       struct symbol **top_symbol_saveptr,
			       int *chain_top_symbol_idx_saveptr) {
    int chlen;
    int i;
    OFFSET totaloffset;
    struct symbol *symbol;
    struct symbol *tdatatype;

    if (!LOCATION_IS_M_OFFSET(location)) {
	verror("location type %s is not a member offset!",
	       LOCTYPE(location->loctype));
	errno = EINVAL;
	return 0;
    }

    /*
     * XXX: the assumption is that our @location arg is the same
     * location as in the last symbol in @symbol_chain!
     */
    if (!symbol_chain) {
	verror("cannot resolve MEMBER_OFFSET without containing symbol_chain!\n");
	errno = EINVAL;
	return 0;
    }

    chlen = array_list_len(symbol_chain);
    symbol = array_list_item(symbol_chain,chlen - 1);

    if (!SYMBOL_IS_FULL_VAR(symbol) || !symbol->ismember) {
	verror("deepest symbol (%s) in chain is not member; cannot resolve"
	       " MEMBER_OFFSET location!\n",symbol_get_name(symbol));
	errno = EINVAL;
	return 0;
    }

    /*
     * Calculate the total offset, i.e. for nested S/Us.
     */
    totaloffset = 0;
    for (i = chlen - 1; i > -1; --i) {
	symbol = array_list_item(symbol_chain,i);
	tdatatype = symbol_get_datatype(symbol);
	if (i < (chlen - 1)
	    && SYMBOL_IS_VAR(symbol)
	    && tdatatype
	    && SYMBOL_IST_STUN(tdatatype)) {
	    /* In this case, when symbol is a var with a type like 
	     * const|vol *+ [typedef+] struct, we still allow this var
	     * to be our top enclosing symbol, because we're going to
	     * use the pointer in combination with the offset.
	     */
	    if (top_symbol_saveptr)
		*top_symbol_saveptr = symbol;
	    if (chain_top_symbol_idx_saveptr)
		*chain_top_symbol_idx_saveptr = i;
	    break;
	}
	else if (SYMBOL_IS_FULL_VAR(symbol)
		 && symbol_is_member(symbol)
		 && SYMBOLX_VAR_LOC(symbol)
		 && LOCATION_IS_M_OFFSET(SYMBOLX_VAR_LOC(symbol))) {
	    totaloffset += LOCATION_OFFSET(SYMBOLX_VAR_LOC(symbol));
	    continue;
	}
	else if (SYMBOL_IS_VAR(symbol)
		 && SYMBOL_IST_STUN(tdatatype)) {
	    if (top_symbol_saveptr)
		*top_symbol_saveptr = symbol;
	    if (chain_top_symbol_idx_saveptr)
		*chain_top_symbol_idx_saveptr = i;
	    break;
	}
	else if (SYMBOL_IST_STUN(symbol)) {
	    /* In this case, don't save the top symbol, because it's not
	     * a var and thus it has no address.  Callers who need that
	     * must notice an error in this case; callers who just want
	     * the offset from the top enclosing STUN type don't need it.
	     */
	    break;
	}
	else {
	    verror("invalid chain member (%s,%s) for nested S/U member (%d)!\n",
		   symbol_get_name(symbol),SYMBOL_TYPE(symbol->type),i);
	    errno = EINVAL;
	    return 0;
	}
    }

    return totaloffset;
}
#endif

loctype_t symbol_resolve_location(struct symbol *symbol,
				  struct location_ctxt *lctxt,
				  struct location *o_loc) {
    if (!SYMBOLX_VAR_LOC(symbol)) {
	vwarnopt(7,LA_DEBUG,LF_DLOC,"no location for ");
	WARNOPTDUMPSYMBOL_NL(7,LA_DEBUG,LF_DLOC,symbol);
	errno = EINVAL;
	return LOCTYPE_UNKNOWN;
    }

    return location_resolve(SYMBOLX_VAR_LOC(symbol),lctxt,symbol,o_loc);
}

int location_ctxt_read_retaddr(struct location_ctxt *lctxt,ADDR *o_retaddr) {
    struct debugfile *debugfile;
    ADDR retaddr = 0;
    struct symbol *symbol;
    struct symbol *root;

    if (!lctxt || !lctxt->ops || !lctxt->ops->getsymbol) {
	verror("no location_ops->getsymbol!\n");
	errno = EINVAL;
	return -1;
    }

    /* Find our debugfile. */
    symbol = lctxt->ops->getsymbol(lctxt);
    if (!symbol) {
	verror("could not getsymbol for frame %d!\n",lctxt->current_frame);
	errno = EINVAL;
	return -1;
    }
    root = symbol_find_root(symbol);
    if (!root) {
	vwarnopt(11,LA_DEBUG,LF_DLOC,
		 "could not find root symbol for symbol '%s'!\n",
		 symbol_get_name(symbol));
	errno = EINVAL;
	return -1;
    }
    SYMBOL_RX_ROOT(root,srd);
    debugfile = srd->debugfile;
    if (!debugfile) {
	vwarnopt(11,LA_DEBUG,LF_DLOC,
		 "could not find debugfile for root symbol '%s'!\n",
		 symbol_get_name(root));
	errno = EINVAL;
	return -1;
    }

    /* Use the CFA API function to read a register. */
    if (!debugfile->ops || !debugfile->ops->frame_read_retaddr) {
	verror("debugfile does not support unwinding!\n");
	errno = ENOTSUP;
	return -1;
    }
    else if (debugfile->ops->frame_read_retaddr(debugfile,lctxt,&retaddr)) {
	verror("failed to read return address in frame %d!\n",
	       lctxt->current_frame);
	if (!errno)
	    errno = EFAULT;
	return -1;
    }

    /*
     * The value is already "relocated" according to location_ops.
     */

    if (o_retaddr)
	*o_retaddr = retaddr;
    return 0;
}

/*
 * Read a register -- either directly via @lops->readreg if !@lctxt 
 * || @lctxt->curent_frame == 0 -- or via the register frame cache in
 * @lctxt (which is populated by interpreting CFA data).
 *
 * We want the location_ops owner to cache for frame 0.  Well, there are
 * pros and cons.  If they cache, and then another user changes values,
 * our whole location context could be messed up.  On the other hand, if
 * we want location_ctxt_writereg to make sense... hm.  Not sure what to
 * do yet. For now just don't cache.
 *
 * This function is only used internally because we provide
 * location_ctxt_read_retaddr for the location_ops owner, so that they
 * know what code owns the previous stack frame, and can then unwind it.
 */
int location_ctxt_read_reg(struct location_ctxt *lctxt,REG reg,REGVAL *o_regval) {
    struct debugfile *debugfile;
    int rc;
    REGVAL rv;
    struct symbol *symbol;
    struct symbol *root;

    if (!lctxt || !lctxt->ops || !lctxt->ops->readreg) {
	verror("no location_ops->readreg for current frame %d!\n",
	       lctxt->current_frame);
	errno = EINVAL;
	return -1;
    }

    /* First try to read it from the target (either CPU or cache). */
    rc = lctxt->ops->readreg(lctxt,reg,o_regval);
    if (rc == 0) 
	return 0;
    /*
     * If we get any other errors other than it not being in the cache
     * (EADDRNOTAVAIL) , we don't try to read CFA.
     */
    else if (errno != EADDRNOTAVAIL) {
	verror("could not read reg %d in frame %d: %s (%d)!\n",
	       reg,lctxt->current_frame,strerror(errno),errno);
	return rc;
    }

    /*
     * Otherwise, use CFA data from the *next* frame to find
     * callee-saved register values.
     */
    if (!lctxt || !lctxt->ops || !lctxt->ops->setcurrentframe) {
	verror("no location_ops->setcurrentframe!\n");
	errno = EINVAL;
	return -1;
    }
    else if (!lctxt->ops->getsymbol) {
	verror("no location_ops->getsymbol!\n");
	errno = EINVAL;
	return -1;
    }

    if (lctxt->ops->setcurrentframe(lctxt,lctxt->current_frame - 1)) {
	verror("could not set current frame from %d to %d (next)!\n",
	       lctxt->current_frame,lctxt->current_frame - 1);
	errno = EBADSLT;
	return -1;
    }

    /* Find our debugfile. */
    symbol = lctxt->ops->getsymbol(lctxt);
    root = symbol_find_root(symbol);
    if (!root) {
	verror("could not find root symbol for symbol '%s'!\n",
	       symbol_get_name(symbol));
	errno = EINVAL;
	goto prev_frame_load_err;
    }
    SYMBOL_RX_ROOT(root,srd);
    debugfile = srd->debugfile;
    if (!debugfile) {
	verror("could not find debugfile for root symbol '%s'!\n",
	       symbol_get_name(root));
	errno = EINVAL;
	goto prev_frame_load_err;
    }

    /* Use the CFA API function to read a register. */
    if (!debugfile->ops || !debugfile->ops->frame_read_saved_reg) {
	verror("debugfile does not support unwinding!\n");
	errno = ENOTSUP;
	goto prev_frame_load_err;
    }

    if (debugfile->ops->frame_read_saved_reg(debugfile,lctxt,reg,&rv)) {
	verror("could not read reg %"PRIiREG" in frame %d!\n",
	       reg,lctxt->current_frame);
	if (!errno)
	    errno = EFAULT;
	goto prev_frame_load_err;
    }

    /*
     * Stop using the current_frame - 1; re-get the current_frame so
     * that we cache the result in the correct frame.
     */
    if (lctxt->ops->setcurrentframe(lctxt,lctxt->current_frame + 1)) {
	verror("could not set current frame from %d to %d (next)!\n",
	       lctxt->current_frame,lctxt->current_frame + 1);
	errno = EBADSLT;
	return -1;
    }

    /* Put it in our cache. */
    if (lctxt->ops->cachereg) 
	lctxt->ops->cachereg(lctxt,reg,rv);

    /*
     * Return!
     */
    if (o_regval)
	*o_regval = rv;

    return 0;

 prev_frame_load_err:
    /*
     * Stop using the current_frame - 1; re-get the current_frame so
     * that we cache the result in the correct frame.
     */
    if (lctxt->ops->setcurrentframe(lctxt,lctxt->current_frame + 1)) {
	verror("could not set current frame from %d to %d (next)!\n",
	       lctxt->current_frame,lctxt->current_frame + 1);
	errno = EBADSLT;
	return -1;
    }
    return -1;
}

int location_ctxt_writereg(struct location_ctxt *lctxt,REG reg,REGVAL regval) {
    int rc;

    if (!lctxt || lctxt->current_frame == 0) {
	errno = 0;
	if (!lctxt->ops || !lctxt->ops->readreg) {
	    errno = EINVAL;
	    return -1;
	}
	rc = lctxt->ops->writereg(lctxt,reg,regval);
	if (rc) {
	    verror("could not write 0x%"PRIxREGVAL" to reg %d!\n",regval,reg);
	    return rc;
	}
    }
    else {
	/*
	 * Use CFA data to write a register.
	 */
	return -1;
    }

    /*
     * Return!
     */
    return 0;
}

struct location_ctxt *location_ctxt_create(struct location_ops *ops,void *priv) {
    struct location_ctxt *lctxt;

    lctxt = calloc(1,sizeof(*lctxt));
    lctxt->ops = ops;
    lctxt->priv = priv;

    return lctxt;
}

void location_ctxt_free(struct location_ctxt *lctxt) {
    free(lctxt);
}

/*
 * Resolves a location -- which may be as simple as a fixed address, or
 * complex as a series of operations produced by a compiler's DWARF
 * emitter.
 *
 * We need a location_ops so we can read registers, memory, and
 * relocate/unrelocate addresses (i.e., from object to real and vice
 * versa).
 */
loctype_t location_resolve(struct location *loc,struct location_ctxt *lctxt,
			   struct symbol *symbol,struct location *o_loc) {
    REGVAL regval;
    struct symbol *parent;
    ADDR ip,obj_ip;
    ADDR addr;
    REG reg;
    OFFSET offset;
    loctype_t rc;
    struct loclistloc *loclistloc;
    int found;
    char *rtbuf;
    unsigned int rtlen;
    struct location tloc;
    struct location_ops *lops = NULL;

    if (lctxt && lctxt->ops) 
	lops = lctxt->ops;

    switch (loc->loctype) {
    case LOCTYPE_UNKNOWN:
	vwarn("cannot resolve LOCTYPE_UNKNOWN");
	if (symbol) {
	    vwarnc(" for ");
	    WARNDUMPSYMBOL_NL(symbol);
	}
	else
	    vwarnc("\n");
	errno = EINVAL;
	return LOCTYPE_UNKNOWN;
    case LOCTYPE_REG:
	errno = 0;
	if (o_loc)
	    location_set_reg(o_loc,LOCATION_REG(loc));
	return LOCTYPE_REG;
    case LOCTYPE_ADDR:
	errno = 0;
	addr = LOCATION_ADDR(loc);
	if (lops && lops->relocate) {
	    if (lops->relocate(lctxt,addr,&addr)) {
		verror("failed to reclocate 0x%"PRIxADDR"!\n",addr);
		return -LOCTYPE_ADDR;
	    }
	}
	if (o_loc) 
	    location_set_addr(o_loc,LOCATION_ADDR(loc));
	return LOCTYPE_ADDR;
    case LOCTYPE_REG_ADDR:
	errno = 0;
	if (location_ctxt_read_reg(lctxt,LOCATION_REG(loc),&regval)) {
	    verror("could not read address from reg %d!\n",
		   LOCATION_REG(loc));
	    return -LOCTYPE_REG_ADDR;
	}
	else {
	    if (o_loc)
		location_set_addr(o_loc,regval);
	    return LOCTYPE_REG_ADDR;
	}
	break;
    case LOCTYPE_REG_OFFSET:
	LOCATION_GET_REGOFFSET(loc,reg,offset);
	errno = 0;
	if (location_ctxt_read_reg(lctxt,reg,&regval)) {
	    verror("could not read address from reg %d!\n",reg);
	    return -LOCTYPE_REG_OFFSET;
	}
	else {
	    if (o_loc)
		location_set_addr(o_loc,(ADDR)(regval + offset));
	    return LOCTYPE_ADDR;
	}
	break;
    case LOCTYPE_FBREG_OFFSET:
	if (!symbol) {
	    verror("cannot calc frame_base; no symbol supplied!\n");
	    errno = EINVAL;
	    return -LOCTYPE_FBREG_OFFSET;
	}
	/*
	 * To determine the value of the frame base pseudo register, we
	 * must find @symbol's containing function.
	 */
	parent = symbol;
	while ((parent = symbol_find_parent(parent))) {
	    if (SYMBOL_IS_FUNC(parent))
		break;
	}
	if (!parent || !SYMBOL_IS_FUNC(parent)) {
	    vwarnopt(8,LA_DEBUG,LF_DLOC,
		     "cannot calc frame_base; no parent function contains ");
	    WARNOPTDUMPSYMBOL_NL(8,LA_DEBUG,LF_DLOC,symbol);
	    errno = EINVAL;
	    return -LOCTYPE_FBREG_OFFSET;
	}

	SYMBOL_RX_FUNC(parent,pf);
	if (!pf || !pf->fbloc) {
	    vwarnopt(8,LA_DEBUG,LF_DLOC,
		     "cannot calc frame_base; no frame base in parent function of ");
	    WARNOPTDUMPSYMBOL_NL(8,LA_DEBUG,LF_DLOC,symbol);
	    errno = EINVAL;
	    return -LOCTYPE_FBREG_OFFSET;
	}

	/* Resolve the parent's fbloc; load it; and apply the offset! */
	memset(&tloc,0,sizeof(tloc));
	rc = location_resolve(pf->fbloc,lctxt,symbol,&tloc);
	if (rc == LOCTYPE_REG) {
	    reg = LOCATION_REG(&tloc);
	    if (location_ctxt_read_reg(lctxt,reg,&regval)) {
		verror("cannot read reg %"PRIiREG" to get frame_base value\n",
		       reg);
		return -LOCTYPE_FBREG_OFFSET;
	    }
	    else
		addr = regval;
	}
	else if (rc != LOCTYPE_ADDR) {
	    verror("cannot get frame base value: %s (%s)\n",
		   strerror(errno),LOCTYPE(rc));
	    return -LOCTYPE_FBREG_OFFSET;
	}
	else
	    addr = LOCATION_ADDR(&tloc);

	vdebug(7,LA_DEBUG,LF_DLOC,
	       "frame_base 0x%"PRIxADDR",fboffset %"PRIiOFFSET"\n",
	       addr,LOCATION_OFFSET(loc));

	if (o_loc)
	    location_set_addr(o_loc,(ADDR)(addr + LOCATION_OFFSET(loc)));

	return LOCTYPE_ADDR;
    case LOCTYPE_LOCLIST:
	if (!lops || !lops->readipreg || !lops->unrelocate) {
	    errno = EINVAL;
	    return -LOCTYPE_LOCLIST;
	}
	else if (lops->readipreg(lctxt,&ip)) {
	    verror("could not read IP reg!\n");
	    return -LOCTYPE_REG_OFFSET;
	}

	/*
	 * We load ip, convert it to obj_ip, scan the location list for
	 * a match, and run the matching location op recursively via
	 * location_resolve!
	 */
	errno = 0;
	if (lops->unrelocate(lctxt,ip,&obj_ip)) {
	    verror("could not convert IP 0x%"PRIxADDR" to obj addr!\n",ip);
	    errno = EFAULT;
	    return -LOCTYPE_LOCLIST;
	}

	vdebug(5,LA_DEBUG,LF_DLOC,"ip 0x%"PRIxADDR"; obj_ip 0x%"PRIxADDR"\n",
	       ip,obj_ip);

	loclistloc = LOCATION_LOCLIST(loc);
	found = 0;
	while (loclistloc) {
	    if (loclistloc->start <= obj_ip && obj_ip < loclistloc->end) {
		found = 1;
		break;
	    }
	    loclistloc = loclistloc->next;
	}
	if (!found) {
	    vwarnopt(8,LA_DEBUG,LF_DLOC,
		     "could not match obj_ip 0x%"PRIxADDR" in loclist!\n",
		     obj_ip);
	    return -LOCTYPE_LOCLIST;
	}

	return location_resolve(loclistloc->loc,lctxt,symbol,o_loc);
    case LOCTYPE_MEMBER_OFFSET:
	errno = 0;
	if (o_loc) 
	    location_set_member_offset(o_loc,LOCATION_OFFSET(loc));
	return LOCTYPE_MEMBER_OFFSET;
    case LOCTYPE_IMPLICIT_WORD:
	errno = 0;
	if (o_loc)
	    location_set_implicit_word(o_loc,LOCATION_WORD(loc));
	return LOCTYPE_IMPLICIT_WORD;
    case LOCTYPE_IMPLICIT_DATA:
	LOCATION_GET_DATA(loc,rtbuf,rtlen);
	errno = 0;
	if (o_loc)
	    location_set_implicit_data(o_loc,rtbuf,rtlen,!loc->nofree);
	return LOCTYPE_IMPLICIT_DATA;
    case LOCTYPE_RUNTIME:
	LOCATION_GET_DATA(loc,rtbuf,rtlen);
	return dwarf_location_resolve((const unsigned char *)rtbuf,rtlen,
				      lctxt,symbol,o_loc);
    default:
	vwarn("unknown location type %d\n",loc->loctype);
	errno = EINVAL;
	return LOCTYPE_UNKNOWN;
    }

    /* never reached */
    return -1;
}

int symbol_resolve_bounds(struct symbol *symbol,struct location_ctxt *lctxt,
			  ADDR *o_start,ADDR *o_end,int *is_noncontiguous,
			  ADDR *o_alt_start,ADDR *o_alt_end) {
    uint8_t as = 0,ae = 0;
    ADDR start = 0,end = 0,alt_start = 0,alt_end = 0;
    loctype_t rc;
    struct scope *scope;
    struct location o_loc;
    struct location_ops *lops = NULL;

    if (SYMBOL_IS_TYPE(symbol)) {
	errno = EINVAL;
	return -1;
    }

    if (!lctxt || !lctxt->ops) {
	verror("no location ops for current frame %d!\n",lctxt->current_frame);
	errno = EINVAL;
	return -1;
    }
    lops = lctxt->ops;

    memset(&o_loc,0,sizeof(o_loc));

    /*
     * Any non-type symbol should have a base address.  If a symbol has
     * a fixed base address, it is in symbol->addr, and we use that.
     * Otherwise, we error unless it's a VAR that has a location; then
     * we try to resolve that.
     *
     * Only root and function symbols have alternate bounds; for root
     * symbols, alt_start == entry_pc; for function symbols, alt_start
     * == prologue_end || alt_start == entry_pc, alt_end == epilogue_begin.
     */
    if (SYMBOL_IS_ROOT(symbol)) {
	SYMBOL_RX_ROOT(symbol,sr);
	if (sr) {
	    if (sr->scope && sr->scope->range && !sr->scope->range->next) {
		start = sr->scope->range->start;
		end = sr->scope->range->end;
	    }
	    if (sr->has_entry_pc) {
		as = 1;
		alt_start = sr->entry_pc;
	    }
	}

	if (!start || (symbol->has_addr && start != symbol->addr))
	    start = symbol->addr;
	if (!end) 
	    end = start + symbol_get_bytesize(symbol);
    }
    else if (SYMBOL_IS_FUNC(symbol)) {
	scope = symbol_read_owned_scope(symbol);
	if (scope) 
	    scope_get_overall_range(scope,&start,&end,is_noncontiguous);
	SYMBOL_RX_FUNC(symbol,sf);
	if (sf) {
	    if (sf->prologue_guessed || sf->prologue_known) {
		as = 1;
		alt_start = sf->prologue_end;
	    }
	    else if (sf->has_entry_pc) {
		as = 1;
		alt_start = sf->entry_pc;
	    }
	    if (sf->epilogue_known) {
		ae = 1;
		alt_end = sf->epilogue_begin;
	    }
	}

	if (!start || (symbol->has_addr && start != symbol->addr)) 
	    start = symbol->addr;
	if (!end)
	    end = start + symbol_get_bytesize(symbol);
    }
    else if (SYMBOL_IS_BLOCK(symbol)) {
	scope = symbol_read_owned_scope(symbol);
	if (scope) 
	    scope_get_overall_range(scope,&start,&end,is_noncontiguous);

	if (!start || (symbol->has_addr && start != symbol->addr)) 
	    start = symbol->addr;
	if (!end)
	    end = start + symbol_get_bytesize(symbol);
    }
    else if (SYMBOL_IS_LABEL(symbol)) {
	if (!symbol->has_addr)
	    return -1;
	start = symbol->addr;
	/* Labels should not have a length! */
	end = start + symbol_get_bytesize(symbol);
    }
    else if (SYMBOL_IS_VAR(symbol)) {
	/* If it doesn't have a base address, resolve its location! */
	if (symbol->has_addr) {
	    start = symbol->addr;
	    end = start + symbol_get_bytesize(symbol);
	}
	else if (SYMBOLX_VAR_LOC(symbol)) {
	    rc = location_resolve(SYMBOLX_VAR_LOC(symbol),lctxt,symbol,&o_loc);
	    if (rc != LOCTYPE_ADDR)
		return -1;
	    start = LOCATION_ADDR(&o_loc);
	    end = start + symbol_get_bytesize(symbol);
	}
    }
    else {
	errno = EINVAL;
	return -1;
    }

    if (o_start) {
	if (lops && lops->relocate)
	    lops->relocate(lctxt,start,o_start);
	else
	    *o_start = start;
    }

    if (o_end) {
	if (lops && lops->relocate)
	    lops->relocate(lctxt,end,o_end);
	else
	    *o_end = end;
    }
    if (as && o_alt_start) {
	if (lops && lops->relocate)
	    lops->relocate(lctxt,alt_start,o_alt_start);
	else
	    *o_start = start;
    }
    if (ae && o_alt_end) {
	if (lops && lops->relocate)
	    lops->relocate(lctxt,alt_end,o_alt_end);
	else
	    *o_alt_end = alt_end;
    }

    return 0;
}

ADDR __autoload_pointers(struct symbol *datatype,ADDR addr,
			 struct location_ctxt *lctxt,
			 struct symbol **datatype_saveptr) {
    ADDR paddr = addr;
    int nptrs = 0;
    struct location_ops *lops;

    lops = lctxt->ops;

    while (SYMBOL_IST_PTR(datatype)) {
	vdebug(9,LA_DEBUG,LF_DLOC,
	       "loading ptr at 0x%"PRIxADDR"\n",paddr);

	if (!lops || !lops->readword) {
	    verror("no location ops to autoload ptr 0x%"PRIxADDR
		   " for datatype %s",
		   addr,symbol_get_name(datatype));
	    errno = EINVAL;
	    return 0;
	}

	if (lops->readword(lctxt,paddr,&paddr)) {
	    verror("could not load ptr 0x%"PRIxADDR"\n",paddr);
	    if (!errno) 
		errno = EFAULT;
	    goto errout;
	}

	++nptrs;
	vdebug(9,LA_DEBUG,LF_DLOC,
	       "loaded next ptr value 0x%"PRIxADDR" (#%d)\n",
	       paddr,nptrs);

	/* Skip past the pointer we just loaded. */
	datatype = symbol_get_datatype(datatype);
    }

    errno = 0;
    if (datatype_saveptr)
	*datatype_saveptr = datatype;
    return paddr;

 errout:
    return 0;
}

/*
 * NB: perhaps following a chain of symbols is something best left in
 * the target library (because then NULL-ptr exceptions, out of bounds
 * accesses, etc, can be better handled).  But, we do it here, because
 * we defined lsymbols here.  Perhaps we shouldn't... I'm not sure any
 * more.  It's useful to have them (i.e., to lookup member functions)...
 *
 * Anyway, this function can return LOCTYPE_UNKNOWN, -LOCTYPE_X (on
 * error); or LOCTYPE_ADDR, LOCTYPE_REG, LOCTYPE_IMPLICIT_* on success.
 *
 * If the first symbol is a containing type (i.e., struct/union/class)
 * or a pointer, you must provide a base address in @base_addr.  If you
 * don't, we cannot compute the address of any further members (in this
 * case, if the type was a pointer, you will get a errno of EFAULT
 * unless there is actually something at 0x0; if the type was a
 * container, your address simply will be incorrect, and there won't be
 * an error).  If the first symbol is a namespace type, or is not a
 * type, then you need not provide a base address.
 *
 * If you provide @lops->(relocate,unrelocate), then base_addr should be
 * a real address.  Otherwise, it should be an obj address.  This should
 * be obvious after a bit of thought; it is the only way to ensure
 * address consistency between obj and real.
 */
loctype_t lsymbol_resolve_location(struct lsymbol *lsymbol,ADDR base_addr,
				   struct location_ctxt *lctxt,
				   struct location *o_loc) {

    /*
     * There are a number of special cases.  Sometimes we don't need to
     * resolve every symbol on the chain -- this is true if the final
     * symbol is not a local var nor a member.  
     */
    ADDR retval = base_addr;
    struct symbol *symbol;
    struct symbol *datatype;
    int llen;
    int i;
    loctype_t rc = LOCTYPE_UNKNOWN;
    struct symbol *tdatatype;
    REG reg = -1;
    struct location tloc;

    llen = lsymbol_len(lsymbol);

    /* 
     * If the last symbol is a function, we only want to return its
     * base address.  So shortcut, and do that.
     *
     * XXX: eventually, do we only want to do this if this function and
     * its parents are currently in scope?  Perhaps... I can see both
     * sides.  After all, in the binary form of the program, one
     * function isn't really nested in another; all functions always
     * have fixed, known code locations -- although of course the
     * compiler is free to assume that the function might not be
     * callable outside the function it was declared in (and thus do
     * optimizations that make an outside call fail).  So perhaps even a
     * debugging entity might not be able to call a nested function, if
     * that's ever meaningful.  Oh well... don't restrict for now!
     */
    symbol = lsymbol_last_symbol(lsymbol);
    if (SYMBOL_IS_FUNC(symbol) || SYMBOL_IS_LABEL(symbol) 
	|| SYMBOL_IS_BLOCK(symbol)) {
	if (symbol_resolve_bounds(symbol,lctxt,&retval,NULL,NULL,NULL,NULL)) {
	    verror("could not resolve base addr for function %s!\n",
		   symbol_get_name(symbol));
	    goto errout;
	}
	
	vdebug(12,LA_DEBUG,LF_DLOC,"function %s at 0x%"PRIxADDR"\n",
	       symbol_get_name(symbol),retval);
	/* Skip the loop, we're done. */
	i = llen;
	/* Resolve datatype just to conform to expected behavior of this
	 * function; caller might want it.
	 */
	datatype = symbol_get_datatype(symbol);
    }
    /*
     * If the final symbol on the chain is in a register, we skip
     * immediately to handling it; there is no need to handle anything
     * prior to it.
     */
    else if (SYMBOL_IS_VAR(symbol)) {
	rc = symbol_resolve_location(symbol,lctxt,NULL);
	if (rc == LOCTYPE_REG)
	    i = llen - 1;
	else
	    i = 0;
    }
    else {
	i = 0;
    }

    /*
     * We traverse through the lsymbol, loading nested chunks.  If the
     * end of the chain is a function, we return its base address.
     * Otherwise, we do nothing for functions (they may be used to
     * resolve the location of variables, however -- i.e., computing the
     * dwarf frame_base virtual register).  Otherwise, for variables, if
     * their types are pointers, we load the pointer, and keep loading
     * the chain according to the next type.  If the last var is a
     * pointer, and the AUTO_DEREF flag is set (or if the AUTO_STRING
     * flag is set, and the final type is a char type), we deref the
     * pointer(s) and return the value of the last pointer.  If it is
     * not a pointer, we return the computed address of the last var.
     */
    while (i < llen) {
	symbol = lsymbol_symbol(lsymbol,i);

	/*
	 * Skip functions; may need them in the chain, however, so that
	 * our location resolution functions can obtain the frame
	 * register info they need to resolve, if a subsequent
	 * variable's location is dependent on the frame base register.
	 *
	 * Also skip namespaces; they have no bearing on location
	 * resolution.
	 */
	if (SYMBOL_IS_FUNC(symbol) || SYMBOL_IST_NAMESPACE(symbol)) {
	    vdebug(12,LA_DEBUG,LF_DLOC,"pass %d: skipping ",i);
	    LOGDUMPSYMBOL(12,LA_DEBUG,LF_DLOC,symbol);
	    if (symbol->datatype) {
		vdebugc(12,LA_DEBUG,LF_DLOC," with datatype ");
		LOGDUMPSYMBOL(12,LA_DEBUG,LF_DLOC,
			      symbol_type_skip_qualifiers(symbol->datatype));
	    }
	    vdebugc(12,LA_DEBUG,LF_DLOC,"\n");

	    ++i;

	    continue;
	}
	else {
	    vdebug(12,LA_DEBUG,LF_DLOC,"pass %d: checking ",i);
	    LOGDUMPSYMBOL(12,LA_DEBUG,LF_DLOC,symbol);
	    if (symbol->datatype) {
		vdebugc(12,LA_DEBUG,LF_DLOC," with datatype ");
		LOGDUMPSYMBOL(12,LA_DEBUG,LF_DLOC,
			      symbol_type_skip_qualifiers(symbol->datatype));
	    }
	    vdebugc(12,LA_DEBUG,LF_DLOC,"\n");

	    ++i;
	}

	/* 
	 * If the symbol is a pointer or struct/union/class type, we
	 * support those (pointers by autoloading; S/U/C by skipping).
	 * Otherwise, it's an error -- i.e., users can't try to compute
	 * an address for 'enum foo_enum.FOO_ENUM_ONE'.
	 */
	if (SYMBOL_IS_TYPE(symbol)) {
	    /* Grab the type's datatype. */
	    tdatatype = symbol_type_skip_qualifiers(symbol);

	    if (SYMBOL_IST_PTR(tdatatype)) {
		datatype = tdatatype;
		rc = LOCTYPE_ADDR;
		goto check_pointer;
	    }
	    else if (SYMBOL_IST_STUNC(tdatatype))
		continue;
	    else {
		verror("cannot load intermediate type symbol %s!\n",
		       symbol_get_name(symbol));
		errno = EINVAL;
		goto errout;
	    }
	}

	/* We error on all other symbol types that are not variables. */
	if (!SYMBOL_IS_VAR(symbol)) {
	    verror("symbol %s of type %s is not a full variable!\n",
		   symbol_get_name(symbol),SYMBOL_TYPE(symbol->type));
	    errno = EINVAL;
	    goto errout;
	}

	/* Grab the symbol's datatype. */
	datatype = symbol_get_datatype(symbol);

	memset(&tloc,0,sizeof(tloc));
	rc = symbol_resolve_location(symbol,lctxt,&tloc);
	//                           &retval,&reg,&offset);
	if (rc == LOCTYPE_MEMBER_OFFSET) {
	    retval += LOCATION_OFFSET(&tloc);
	    vdebug(12,LA_DEBUG,LF_DLOC,
		   "member %s at offset 0x%"PRIxOFFSET"; addr 0x%"PRIxADDR"\n",
		   symbol_get_name(symbol),LOCATION_OFFSET(&tloc),retval);
	}
	else if (rc == LOCTYPE_REG) {
	    reg = LOCATION_REG(&tloc);
	    /*
	     * NB: see below inside the pointer check where we will try
	     * to load the pointer across this register.
	     */
	    vdebug(12,LA_DEBUG,LF_DLOC,"var %s in reg %"PRIiREG"\n",
		   symbol_get_name(symbol),reg);
	}
	else if (rc == LOCTYPE_ADDR) {
	    retval = LOCATION_ADDR(&tloc);
	    vdebug(12,LA_DEBUG,LF_DLOC,"var %s at 0x%"PRIxADDR"\n",
		   symbol_get_name(symbol),retval);
	}
	else if (rc == LOCTYPE_IMPLICIT_WORD) {
	    retval = LOCATION_WORD(&tloc);
	    vdebug(12,LA_DEBUG,LF_DLOC,
		   "var %s has implicit value 0x%"PRIxADDR"\n",
		   symbol_get_name(symbol),retval);
	}
	else {
	    if (errno == ENOTSUP) 
		vwarnopt(8,LA_DEBUG,LF_DLOC,
			 "could not resolve location for symbol %s: %s!\n",
			 symbol_get_name(symbol),strerror(errno));
	    else
		verror("could not resolve location for symbol %s: %s!\n",
		       symbol_get_name(symbol),strerror(errno));
	    goto errout;
	}

	/*
	 * If the symbol is a pointer, load it now.  If this is the
	 * final symbol in the chain (i == llen), don't load its
	 * pointer; just stop where we are.
	 */
    check_pointer:
	if (i < llen && SYMBOL_IST_PTR(datatype)) {
	    if (rc == LOCTYPE_REG) {
		/*
		 * Try to load the ptr value from a register; might or
		 * might not be an address; only is if the current
		 * symbol was a pointer; we handle that below.  There's
		 * a termination condition below this loop that if we
		 * end after having resolved the location to a register,
		 * we can't calculate the address for it.
		 */
		if (location_ctxt_read_reg(lctxt,reg,&retval)) {
		    verror("could not read ptr symbol %s from reg %d: %s!\n",
			   symbol_get_name(symbol),reg,strerror(errno));
		    goto errout;
		}

		vdebug(12,LA_DEBUG,LF_DLOC,
		       "ptr var (in reg %"PRIiREG") %s = 0x%"PRIxADDR"\n",
		       reg,symbol_get_name(symbol),retval);

		/* We have to skip one pointer type */
		datatype = symbol_type_skip_qualifiers(datatype->datatype);

		/*
		 * Clear the in_reg bit, since we were able to
		 * autoload the pointer!
		 */
		rc = LOCTYPE_ADDR;

		/* Do we need to keep trying to load through the pointer? */
		if (SYMBOL_IST_PTR(datatype))
		    goto check_pointer;
	    }
	    else {
		errno = 0;
		retval = __autoload_pointers(datatype,retval,lctxt,&datatype);
		if (errno) {
		    verror("could not load pointer for symbol %s\n",
			   symbol_get_name(symbol));
		    goto errout;
		}

		vdebug(12,LA_DEBUG,LF_DLOC,
		       "autoloaded pointer(s) for var %s = 0x%"PRIxADDR"\n",
		       symbol_get_name(symbol),retval);
	    }
	}
    }

    /* Return! */
    if (rc == LOCTYPE_REG) {
	if (o_loc)
	    location_set_reg(o_loc,reg);

	vdebug(12,LA_DEBUG,LF_DLOC,"regno = 0x%"PRIiREG"; datatype = ",reg);
	if (datatype) {
	    LOGDUMPSYMBOL_NL(12,LA_DEBUG,LF_DLOC,
			     symbol_type_skip_qualifiers(datatype));
	}
	else 
	    vdebugc(12,LA_DEBUG,LF_DLOC,"NULL\n");

	return LOCTYPE_REG;
    }
    else if (rc == LOCTYPE_ADDR) {
	if (o_loc)
	    location_set_addr(o_loc,retval);

	vdebug(12,LA_DEBUG,LF_DLOC,"addr = 0x%"PRIxADDR"; datatype = ",retval);
	if (datatype) {
	    LOGDUMPSYMBOL_NL(12,LA_DEBUG,LF_DLOC,
			     symbol_type_skip_qualifiers(datatype));
	}
	else 
	    vdebugc(12,LA_DEBUG,LF_DLOC,"NULL\n");

	return LOCTYPE_ADDR;
    }
    else if (rc == LOCTYPE_IMPLICIT_WORD) {
	if (o_loc)
	    location_set_implicit_word(o_loc,retval);

	vdebug(12,LA_DEBUG,LF_DLOC,
	       "implicit word = 0x%"PRIxADDR"; datatype = ",retval);
	if (datatype) {
	    LOGDUMPSYMBOL_NL(12,LA_DEBUG,LF_DLOC,
			     symbol_type_skip_qualifiers(datatype));
	}
	else 
	    vdebugc(12,LA_DEBUG,LF_DLOC,"NULL\n");

	return LOCTYPE_IMPLICIT_WORD;
    }

 errout:
    return LOCTYPE_UNKNOWN;
}

int lsymbol_resolve_bounds(struct lsymbol *lsymbol,ADDR base_addr,
			   struct location_ctxt *lctxt,
			   ADDR *start,ADDR *end,int *is_noncontiguous,
			   ADDR *alt_start,ADDR *alt_end) {
    struct symbol *symbol;
    uint32_t size = 0;
    loctype_t rc;
    struct location tloc;

    if (!lctxt) {
	verror("no location_ctxt for current frame!\n");
	errno = EINVAL;
	return -1;
    }

    symbol = lsymbol_last_symbol(lsymbol);

    if (SYMBOL_IS_TYPE(symbol)) {
	errno = EINVAL;
	return -1;
    }

    /*
     * If it's not a var, its location is independent of the lsymbol
     * chain.  Otherwise, we have to resolve its base, then update its
     * end according to its size.
     */
    if (!SYMBOL_IS_VAR(symbol))
	return symbol_resolve_bounds(symbol,lctxt,start,end,
				     is_noncontiguous,alt_start,alt_end);

    /*
     * Otherwise, work the chain to resolve the base addr, then fill in
     * the size.  No alt_* info for variables, obviously.
     */
    memset(&tloc,0,sizeof(tloc));
    rc = lsymbol_resolve_location(lsymbol,base_addr,lctxt,&tloc);
    if (rc != LOCTYPE_ADDR) {
	verror("could not resolve location for %s to addr: %s (%d) (%s)!\n",
	       symbol_get_name(symbol),strerror(errno),rc,
	       (rc > LOCTYPE_UNKNOWN) ? LOCTYPE(rc) : "");
	return -1;
    }

    vdebug(3,LA_DEBUG,LF_DLOC,
	   "found base of '%s' at 0x%"PRIxADDR"\n",
	   symbol_get_name(symbol),*start);

    /* Collect its size. */
    if (end) {
	size = symbol_get_bytesize(symbol);
	*end = *start + size;
    }

    return 0;
}
