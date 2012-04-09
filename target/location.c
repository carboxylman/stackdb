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

struct mmap_entry *location_mmap(struct target *target,
				 struct memregion *region,
				 struct location *location,
				 load_flags_t flags,char **offset,
				 struct array_list *symbol_chain,
				 struct memrange **range_saveptr) {
    struct mmap_entry *mme;

    if (!location_can_mmap(location,target))
	return NULL;

    /* XXX: fill in later. */
    return NULL;
}

char *location_load(struct target *target,struct memregion *region,
		    struct location *location,load_flags_t flags,
		    void *buf,int bufsiz,
		    struct array_list *symbol_chain,
		    struct memrange **range_saveptr) {
    ADDR final_location = 0;
    REGVAL regval;
    struct memrange *range;
    struct location *loclistloc = NULL;

    if (location->loctype == LOCTYPE_REG
	|| (location->loctype == LOCTYPE_LOCLIST
	    && ((loclistloc = location_resolve_loclist(target,region,location))
		&& loclistloc->loctype == LOCTYPE_REG))) {
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
        regval = target_read_reg(target,
				 (loclistloc) ? loclistloc->l.reg : location->l.reg);
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

	if (range_saveptr) 
	    *range_saveptr = NULL;

	return buf;
    }
    else {
        final_location = location_resolve(target,region,location,symbol_chain,
					  &range);

        if (errno)
            return NULL;

	if (!range)
	    vwarn("could not resolve a range with final location!\n");
	else if (range_saveptr)
	    *range_saveptr = range;

        vdebug(5,LOG_T_LOC,"final_location = 0x%" PRIxADDR "\n",final_location);

        return (char *)__target_load_addr_real(target,range,final_location,
					       flags,buf,bufsiz);
    }
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
 * This only handles figuring out which location on a loclist is valid,
 * given the current EIP.  This is useful in case we are trying to
 * resolve a location that is a loclist, and the matching location is a
 * register (which has no address!).  So this function works in tandem
 * with the one below in location_load().
 */
struct location *location_resolve_loclist(struct target *target,
					  struct memregion *region,
					  struct location *location) {
    int i;
    ADDR obj_eip;
    REGVAL eip;
    struct memrange *range;

    if (!target) {
	errno = EINVAL;
	return 0;
    }

    /* We load EIP, scan the location list for a match, and run the
     * matching location op recursively via location_resolve!
     */
    eip = target_read_reg(target,target->ipregno);
    if (errno)
	return NULL;
    errno = 0;
    vdebug(5,LOG_T_LOC,"eip = 0x%" PRIxADDR "\n",eip);

    /*
     * Find out which range in the region this address is in,
     * then translate it into an object address and compare with
     * the loclist.
     */
    range = memregion_find_range_real(region,eip);
    if (!range) {
	verror("LOCLIST eip not in region %s!!\n",region->name);
	errno = EINVAL;
	return NULL;
    }
    obj_eip = memrange_unrelocate(range,(ADDR)eip);

    for (i = 0; i < location->l.loclist->len; ++i) {
	if (location->l.loclist->list[i]->start <= obj_eip 
	    && obj_eip < location->l.loclist->list[i]->end)
	    break;
    }
    if (i == location->l.loclist->len) {
	verror("LOCLIST location not currently valid!\n");
	errno = EINVAL;
	return NULL;
    }
    else if (!location->l.loclist->list[i]->loc) {
	verror("matching LOCLIST member does not have a location description!\n");
	errno = EINVAL;
	return NULL;
    }

    return location->l.loclist->list[i]->loc;
}

OFFSET location_resolve_member_offset(struct target *target,
				      struct location *location,
				      struct array_list *symbol_chain,
				      struct symbol **top_symbol_saveptr,
				      int *chain_top_symbol_idx_saveptr) {
    int chlen;
    int i;
    OFFSET totaloffset;
    struct symbol *symbol;

    if (location->loctype != LOCTYPE_MEMBER_OFFSET) {
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
	if (SYMBOL_IS_FULL_VAR(symbol)
	    && symbol->ismember
	    && symbol->s.ii->l.loctype == LOCTYPE_MEMBER_OFFSET) {
	    totaloffset += symbol->s.ii->l.l.member_offset;
	    continue;
	}
	else if (SYMBOL_IS_VAR(symbol)
		 && SYMBOL_IST_STUN(symbol->datatype)) {
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
		      struct array_list *symbol_chain,
		      struct memrange **range_saveptr) {
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
    struct memrange *range;

    switch (location->loctype) {
    case LOCTYPE_UNKNOWN:
	vwarn("cannot resolve LOCTYPE_UNKNOWN; invalid!\n");
	errno = EINVAL;
	return 0;
    case LOCTYPE_REG:
	vwarn("cannot resolve LOCTYPE_REG; invalid!\n");
	errno = EINVAL;
	return 0;
    case LOCTYPE_ADDR:
	errno = 0;
	range = memregion_find_range_obj(region,location->l.addr);
	/* The address should be in this region; it cannot change. */
	if (range_saveptr)
	    *range_saveptr = range;
	return memrange_relocate(range,location->l.addr);
    case LOCTYPE_REALADDR:
	errno = 0;
	range = memregion_find_range_real(region,location->l.addr);
	/* The address should be in this region; it cannot change. */
	if (range_saveptr)
	    *range_saveptr = range;
	return location->l.addr;
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
	/* The region/range may have changed; find the new range! */
	if (range_saveptr)
	    target_find_memory_real(target,regval,NULL,NULL,range_saveptr);
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
	/* The region/range may have changed; find the new range! */
	if (range_saveptr)
	    target_find_memory_real(target,location->l.regoffset.offset + regval,
				   NULL,NULL,range_saveptr);
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
		if (symbol->s.ii->d.f.fbisloclist) {
		    fblist = symbol->s.ii->d.f.fb.list;
		    break;
		}
		else if (symbol->s.ii->d.f.fbissingleloc) {
		    fbloc = symbol->s.ii->d.f.fb.loc;
		    break;
		}
	    }
	}

	if (!fblist && !fbloc) {
	    verror("FBREG_OFFSET, but no fblist or fbloc to calc frame base (%d)!\n",chlen);
	    errno = EINVAL;
	    return 0;
	}

	/* If we have an fblist, we load EIP, scan the location list
	 * for a match, and run the frame base location op recursively
	 * via location_resolve!
	 */
	if (fblist) {
	    eip = target_read_reg(target,target->ipregno);
	    if (errno)
		return 0;
	    errno = 0;
	    vdebug(5,LOG_T_LOC,"eip = 0x%" PRIxADDR "\n",eip);

	    /*
	     * Find out which range in the region this address is in,
	     * then translate it into an object address and compare with
	     * the loclist.
	     */
	    range = memregion_find_range_real(region,eip);
	    if (!range) {
		verror("FBREG_OFFSET eip not in region %s!!\n",
		       region->name);
		errno = EINVAL;
		return 0;
	    }
	    ADDR obj_eip = memrange_unrelocate(range,(ADDR)eip);

	    for (i = 0; i < fblist->len; ++i) {
		if (fblist->list[i]->start <= obj_eip 
		    && obj_eip < fblist->list[i]->end) {
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
	    frame_base = location_resolve(target,region,final_fb_loc,NULL,NULL);
	    if (errno) {
		verror("FBREG_OFFSET frame base location description recursive resolution failed: %s\n",strerror(errno));
		errno = EINVAL;
		return 0;
	    }
	}

	vdebug(5,LOG_T_LOC,"frame_base = 0x%" PRIxADDR "\n",frame_base);
	vdebug(5,LOG_T_LOC,"fboffset = %"PRIiOFFSET"\n",location->l.fboffset);

	/* The region/range may have changed; find the new range! */
	if (range_saveptr)
	    target_find_memory_real(target,
				   (ADDR)(frame_base + (ADDR)location->l.fboffset),
				   NULL,NULL,range_saveptr);

	return (ADDR)(frame_base + (ADDR)location->l.fboffset);
	//return (ADDR)(frame_base - (ADDR)location->l.fboffset);
    case LOCTYPE_LOCLIST:
	/* XXX: reuse fbloc to save a stack word */
	if (!(fbloc = location_resolve_loclist(target,region,location)))
	    return 0;

	return location_resolve(target,region,fbloc,
				/* XXX: is this correct, or should we
				 * pass NULL?
				 */
				symbol_chain,
				range_saveptr);
    case LOCTYPE_MEMBER_OFFSET:
	totaloffset = location_resolve_member_offset(target,location,
						     symbol_chain,
						     &top_enclosing_symbol,&i);
	if (errno)
	    return 0;

	chlen = array_list_len(symbol_chain);
	symbol = array_list_item(symbol_chain,chlen - 1);

	if (!top_enclosing_symbol) {
	    verror("could not find top enclosing symbol for MEMBER_OFFSET for symbol %s!\n",
		   symbol_get_name(symbol));
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
	top_addr = location_resolve(target,region,&top_enclosing_symbol->s.ii->l,
				    tmp_symbol_chain,NULL);
	if (tmp_symbol_chain)
	    array_list_free(tmp_symbol_chain);
	if (errno) {
	    verror("could not resolve location for top S/U for MEMBER_OFFSET: %s\n",
		   strerror(errno));
	    errno = EINVAL;
	    return 0;
	}

	/* The region/range may have changed; find the new range! */
	if (range_saveptr)
	    target_find_memory_real(target,top_addr + totaloffset,
				   NULL,NULL,range_saveptr);

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

int location_resolve_symbol_base(struct target *target,
				 struct bsymbol *bsymbol,ADDR *addr_saveptr,
				 struct memrange **range_saveptr) {
    struct symbol *symbol = bsymbol->lsymbol->symbol;
    int i;
    ADDR obj_addr;
    struct symtab *symtab;

    if (!addr_saveptr || !SYMBOL_IS_FULL_INSTANCE(symbol))
	return -1;

    if (SYMBOL_IS_FULL_FUNCTION(symbol)) {
	if (symbol->s.ii->d.f.hasentrypc)
	    obj_addr = symbol->s.ii->d.f.entry_pc;
	else if ((symtab = symbol->s.ii->d.f.symtab)) {
	    if (RANGE_IS_PC(&symtab->range)) 
		obj_addr = symtab->range.r.a.lowpc;
	    else if (RANGE_IS_LIST(&symtab->range)) {
		/* Find the lowest addr! */
		obj_addr = ADDRMAX;
		for (i = 0; i < symtab->range.r.rlist.len; ++i) {
		    if (symtab->range.r.rlist.list[i]->start < obj_addr)
			obj_addr = symtab->range.r.rlist.list[i]->start;
		}
		vwarn("assuming function %s entry is lowest address in list 0x%"PRIxADDR"!\n",
		      symbol->name,obj_addr);
	    }
	    else {
		vwarn("function %s range is not PC/list!\n",symbol->name);
		return -1;
	    }
	}
	else {
	    vwarn("function %s has no entry_pc nor symtab!\n",symbol->name);
	    return -1;
	}
    }
    else if (SYMBOL_IS_FULL_LABEL(symbol)) {
	if (RANGE_IS_PC(&symbol->s.ii->d.l.range)) 
	    obj_addr = symbol->s.ii->d.l.range.r.a.lowpc;
	else if (RANGE_IS_LIST(&symbol->s.ii->d.l.range)) {
	    /* Find the lowest addr! */
	    obj_addr = ADDRMAX;
	    for (i = 0; i < symbol->s.ii->d.l.range.r.rlist.len; ++i) {
		if (symbol->s.ii->d.l.range.r.rlist.list[i]->start < obj_addr)
		    obj_addr = symbol->s.ii->d.l.range.r.rlist.list[i]->start;
	    }
	    vwarn("assuming label %s entry is lowest address in list 0x%"PRIxADDR"!\n",
		  symbol->name,obj_addr);
	}
	else {
	    vwarn("label %s range is not PC/list!\n",symbol->name);
	    return -1;
	}
    }
    else if (SYMBOL_IS_FULL_VAR(symbol)) {
	obj_addr = location_resolve(target,bsymbol->region,
				    &bsymbol->lsymbol->symbol->s.ii->l,
				    bsymbol->lsymbol->chain,range_saveptr);
	if (!obj_addr && errno) {
	    verror("could not resolve location for %s!\n",
		   bsymbol->lsymbol->symbol->name);
	    return -1;
	}
    }
    else {
	/* Impossible, but clears lint. */
	verror("bad symbol type %s!\n",SYMBOL_TYPE(symbol->type));
	return -1;
    }

    /* Translate the obj address to something real in this region. */
    *addr_saveptr = memregion_relocate(bsymbol->region,obj_addr,range_saveptr);

    vdebug(3,LOG_T_LOC,"found base of '%s' 0x%"PRIxADDR" -> 0x%"PRIxADDR"\n",
	   bsymbol->lsymbol->symbol->name,obj_addr,*addr_saveptr);

    return 0;
}

int location_resolve_function_prologue_end(struct target *target,
					   struct bsymbol *bsymbol,
					   ADDR *addr_saveptr,
					   struct memrange **range_saveptr) {
    struct symbol *symbol = bsymbol->lsymbol->symbol;

    if (!addr_saveptr || !SYMBOL_IS_FULL_FUNCTION(symbol))
	return -1;

    if (!symbol->s.ii->d.f.prologue_guessed) {
	vwarn("function %s has no prologue_end!\n",symbol->name);
	return -1;
    }

    /* Translate the obj address to something real in this region. */
    *addr_saveptr = memregion_relocate(bsymbol->region,
				       symbol->s.ii->d.f.prologue_end,
				       range_saveptr);

    return 0;
}
