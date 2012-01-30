/*
 * Copyright (c) 2011, 2012 The University of Utah
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
 * Foundation, 51 Franklin St, Suite 500, Boston, MA 02110-1335, USA.
 */

#include "target.h"

/*
 * These _load() functions are thin wrappers around target_read_addr
 * that basically check flags, handle loading values direct from a
 * register, and maybe handle object addresses.
 *
 * They return char * due to the semantics of target_read_addr, which
 * they share.
 */

struct mmap_entry *location_mmap(struct target *target,struct memregion *region,
				 struct location *location,
				 struct array_list *symbol_chain,
				 load_flags_t flags,char **offset) {
    struct mmap_entry *mme;

    if (!location_can_mmap(location,target))
	return NULL;

    /* XXX: fill in later. */
    return NULL;
}

char *location_load(struct target *target,struct memregion *region,
		    struct location *location,struct array_list *symbol_chain,
		    load_flags_t flags,void *buf,int bufsiz) {
    ADDR final_location = 0;
    REGVAL regval;


    if (location->loctype == LOCTYPE_REG) {
	/* They must supply a buffer if the value is in a register. */
	if (!buf) {
	    errno = EINVAL;
	    return NULL;
	}

	/* We can't mmap a value that is simply in a register. */
	if (flags & LOAD_FLAG_MUST_MMAP) {
	    errno = EINVAL;
	    return NULL;
	}

        /* just read the register directly */
        regval = target_read_reg(target,location->l.reg);
        if (errno)
            return NULL;

        if (target->wordsize == 4 && __WORDSIZE == 64) {
            /* If the target is 32-bit on 64-bit host, we have to grab
             * the lower 32 bits of the regval.
             */
            memcpy(buf,((int32_t *)&regval),bufsiz);
        }
	else if (__WORDSIZE == 32)
	    memcpy(buf,&regval,(bufsiz < 4) ? bufsiz : 4);
        else
            memcpy(buf,&regval,bufsiz);
    }
    else {
        final_location = location_resolve(target,region,location,symbol_chain);

        if (errno)
            return NULL;

        vdebug(5,LOG_T_LOC,"final_location = 0x%" PRIxADDR "\n",final_location);

        return location_addr_load(target,region,final_location,
				  flags,buf,bufsiz);
    }

    return 0;
}

char *location_addr_load(struct target *target,struct memregion *region,
			 ADDR addr,load_flags_t flags,
			 void *buf,int bufsiz) {
    if (!(flags & LOAD_FLAG_NO_CHECK_BOUNDS) 
	&& !memregion_contains(region,addr)) {
	errno = EFAULT;
	return NULL;
    }

    return (char *)target_read_addr(target,addr,bufsiz,buf);
}

char *location_obj_addr_load(struct target *target,struct memregion *region,
			     ADDR addr,load_flags_t flags,
			     void *buf,int bufsiz) {
    addr = memregion_relocate(region,addr);
    return location_addr_load(target,region,addr,flags,buf,bufsiz);
}


int location_can_mmap(struct location *location,struct target *target) {
    /* We can't mmap a value that is simply in a register. */
    if (location->loctype == LOCTYPE_REG) {
	errno = EINVAL;
	return 0;
    }
    if (target) {
	if (target->mmapable)
	    return 1;
	else 
	    return 0;
    }

    /* If they didn't supply a target, the location *might* be mmapable */
    return 1;
}

/*
 * Resolves a location -- which may be as simple as a fixed address, or
 * complex as a series of operations produced by a compiler's DWARF
 * emitter.
 *
 * We need a target so we can use the target api to read registers, and
 * we need the region so we can resolve object-relative addresses real
 * memory addresses.
 */

ADDR location_resolve(struct target *target,struct memregion *region,
		      struct location *location,
		      struct array_list *symbol_chain) {
    REGVAL regval;
    int i;
    ADDR eip;
    ADDR frame_base;
    struct location *final_fb_loc = NULL;
    int chlen;
    struct symbol *symbol;
    struct symbol *top_enclosing_symbol = NULL;
    ADDR top_addr = 0;
    OFFSET totaloffset = 0;
    struct loc_list *fblist = NULL;
    struct location *fbloc = NULL;
    struct array_list *tmp_symbol_chain = NULL;

    switch (location->loctype) {
    case LOCTYPE_UNKNOWN:
	errno = EINVAL;
	return 0;
    case LOCTYPE_ADDR:
	errno = 0;
	return memregion_relocate(region,location->l.addr);
    case LOCTYPE_REALADDR:
	errno = 0;
	return location->l.addr;
    case LOCTYPE_REG:
	errno = EINVAL;
	return 0;
    case LOCTYPE_REG_ADDR:
	/* load the register value */
	if (!target) {
	    errno = EINVAL;
	    return 0;
	}
	regval = target_read_reg(target,location->l.reg);
	if (errno)
	    return 0;
	errno = 0;
	return regval;
    case LOCTYPE_REG_OFFSET:
	if (!target) {
	    errno = EINVAL;
	    return 0;
	}
	regval = target_read_reg(target,location->l.regoffset.reg);
	if (errno)
	    return 0;
	errno = 0;
	return (ADDR)(location->l.regoffset.offset + regval);
    case LOCTYPE_FBREG_OFFSET:
	if (!target) {
	    errno = EINVAL;
	    return 0;
	}
	/*
	 * We must have a symbol_chain so we can figure out the value of
	 * the frame_base; it will be in the containing function.  So we
	 * look up the chain and find the nearest parent that is a
	 * function and has a frame base list or frame base location,
	 * and then resolve that.
	 */
	if (!symbol_chain) {
	    verror("FBREG_OFFSET, but no symbol chain!\n");
	    errno = EINVAL;
	    return 0;
	}

	chlen = array_list_len(symbol_chain);
	    
	for (i = chlen - 2; i > -1; --i) {
	    symbol = array_list_item(symbol_chain,i);
	    if (SYMBOL_IS_FUNCTION(symbol)) {
		if (symbol->s.ii.d.f.fbisloclist) {
		    fblist = symbol->s.ii.d.f.fblist;
		    break;
		}
		else if (symbol->s.ii.d.f.fbissingleloc) {
		    fbloc = symbol->s.ii.d.f.fbloc;
		}
	    }
	}

	if (!fblist && !fbloc) {
	    verror("FBREG_OFFSET, but no fblist or fbloc to calc frame base!\n");
	    errno = EINVAL;
	    return 0;
	}

	/* If we have an fblist, we load EIP - 4, scan the location list
	 * for a match, and run the frame base location op recursively
	 * via location_resolve!
	 */
	if (fblist) {
	    // XXX - 4 is intel-specific?
	    eip = target_read_reg(target,target->ipregno) - 4;
	    if (errno)
		return 0;
	    errno = 0;
	    vdebug(5,LOG_T_LOC,"eip = 0x%" PRIxADDR "\n",eip);
	    for (i = 0; i < fblist->len; ++i) {
		if (memregion_relocate(region,fblist->list[i]->start) <= eip 
		    && eip < memregion_relocate(region,fblist->list[i]->end)) {
		    final_fb_loc = fblist->list[i]->loc;
		    break;
		}
	    }
	    if (i == fblist->len) {
		verror("FBREG_OFFSET location not currently valid!\n");
		errno = EINVAL;
		return 0;
	    }
	    else if (!fblist->list[i]->loc) {
		verror("FBREG_OFFSET frame base in loclist does not have a location description!\n");
		errno = EINVAL;
		return 0;
	    }
	}
	else if (fbloc) {
	    final_fb_loc = fbloc;
	}
	else {
	    verror("FBREG_OFFSET, but no frame base loclist/loc!\n");
	    errno = EINVAL;
	    return 0;
	}

	/* now resolve the frame base value */
	if (final_fb_loc && final_fb_loc->loctype == LOCTYPE_REG) {
	    /* just read the register directly */
	    frame_base = target_read_reg(target,final_fb_loc->l.reg);
	    if (errno) {
		verror("FBREG_OFFSET frame base location description resolution failed when reading reg directly: %s\n",strerror(errno));
		errno = EINVAL;
		return 0;
	    }
	}
	else {
	    frame_base = location_resolve(target,region,final_fb_loc,NULL);
	    if (errno) {
		verror("FBREG_OFFSET frame base location description recursive resolution failed: %s\n",strerror(errno));
		errno = EINVAL;
		return 0;
	    }
	}
	vdebug(5,LOG_T_LOC,"frame_base = 0x%" PRIxADDR "\n",frame_base);
	vdebug(5,LOG_T_LOC,"fboffset = %" PRIi64 "\n",location->l.fboffset);
	if (0 && location->l.fboffset < 0)
	    return (ADDR)(frame_base - (ADDR)location->l.fboffset);
	else
	    return (ADDR)(frame_base + (ADDR)location->l.fboffset);
    case LOCTYPE_LOCLIST:
	if (!target) {
	    errno = EINVAL;
	    return 0;
	}
	/* Like the above case, we load EIP - 4, scan the location list
	 * for a match, and run the matching location op recursively
	 * via location_resolve!
	 */
	// XXX - 4 is intel-specific?
	eip = target_read_reg(target,target->ipregno) - 4;
	if (errno)
	    return 0;
	errno = 0;
	vdebug(5,LOG_T_LOC,"eip = 0x%" PRIxADDR "\n",eip);
	for (i = 0; i < location->l.loclist->len; ++i) {
	    if (memregion_relocate(region,
				   location->l.loclist->list[i]->start) <= eip 
		&& eip < memregion_relocate(region,
					    location->l.loclist->list[i]->end))
		break;
	}
	if (i == location->l.loclist->len) {
	    verror("LOCLIST location not currently valid!\n");
	    errno = EINVAL;
	    return 0;
	}
	else if (!location->l.loclist->list[i]->loc) {
	    verror("matching LOCLIST member does not have a location description!\n");
	    errno = EINVAL;
	    return 0;
	}
	return location_resolve(target,region,location->l.loclist->list[i]->loc,
				/* XXX: is this correct, or should we
				 * pass NULL?
				 */
				symbol_chain);
    case LOCTYPE_MEMBER_OFFSET:
	/*
	 * XXX: the assumption is that our @location arg is the same
	 * location as in the last symbol in @symbol_chain!
	 */

	if (!symbol_chain) {
	    vwarn("cannot process MEMBER_OFFSET without containing symbol_chain!\n");
	    errno = EINVAL;
	    return 0;
	}

	chlen = array_list_len(symbol_chain);
	symbol = array_list_item(symbol_chain,chlen - 1);

	if (!SYMBOL_IS_VAR(symbol) || !symbol->s.ii.ismember) {
	    vwarn("deepest symbol (%s) in chain is not member; cannot process MEMBER_OFFSET!\n",
		  symbol->name);
	    errno = EINVAL;
	    return 0;
	}

	/*
	 * Calculate the total offset, i.e. for nested S/Us.
	 */
	totaloffset = 0;
	for (i = chlen - 1; i > -1; --i) {
	    symbol = array_list_item(symbol_chain,i);
	    if (SYMBOL_IS_VAR(symbol)
		&& symbol->s.ii.ismember
		&& symbol->s.ii.l.loctype == LOCTYPE_MEMBER_OFFSET) {
		totaloffset += symbol->s.ii.l.l.member_offset;
		continue;
	    }
	    else if (SYMBOL_IS_VAR(symbol)
		     && SYMBOL_IST_STUN(symbol->datatype)) {
		top_enclosing_symbol = symbol;
		break;
	    }
	    else {
		verror("invalid chain member (%s,%s) for nested S/U member (%d)!\n",
		       symbol->name,SYMBOL_TYPE(symbol->type),i);
		errno = EINVAL;
		return 0;
	    }
	}
	/* reset symbol to the deepest nested */
	symbol = array_list_item(symbol_chain,chlen - 1);

	if (!top_enclosing_symbol) {
	    verror("could not find top enclosing symbol for MEMBER_OFFSET for symbol %s!\n",
		   symbol->name);
	    errno = EINVAL;
	    return 0;
	}

	/*
	 * We recalculate a new symbol chain for this call, just in case
	 * top_enclosing_symbol was not the top of the chain (i.e.,
	 * top_enclosing_symbol's location could be in terms of a frame
	 * base... so we would in that case need a new chain).
	 */
	if (i > 0) {
	    tmp_symbol_chain = array_list_create(i + 1);
	    for ( ; i > -1; --i) 
		array_list_item_set(tmp_symbol_chain,i,
				    array_list_item(symbol_chain,i));
	}
	top_addr = location_resolve(target,region,&top_enclosing_symbol->s.ii.l,
				    tmp_symbol_chain);
	if (tmp_symbol_chain)
	    array_list_free(tmp_symbol_chain);
	if (errno) {
	    verror("could not resolve location for top S/U for MEMBER_OFFSET: %s\n",
		   strerror(errno));
	    errno = EINVAL;
	    return 0;
	}

	return top_addr + totaloffset;
    case LOCTYPE_RUNTIME:
	if (!target) {
	    errno = EINVAL;
	    return 0;
	}
	vwarn("currently unsupported location type %s\n",
	      LOCTYPE(location->loctype));
	errno = EINVAL;
	return 0;
    default:
	vwarn("unknown location type %d\n",location->loctype);
	errno = EINVAL;
	return 0;
    }

    /* never reached */
    return 0;
}
