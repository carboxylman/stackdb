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

#include "dwdebug.h"
#include "target_api.h"
#include "target.h"

/**
 ** Globals.
 **/

/* These are the targets we know about. */
LIST_HEAD(targets);

/* These are the known, loaded (maybe partially) debuginfo files. */
LIST_HEAD(debugfiles);

extern struct target_ops linux_userspace_process_ops;

/*
 * A utility function that attaches a file containing debug symbols to a
 * region (and first looks for an existing match, if that file has
 * already been loaded).
 */
struct debugfile *target_associate_debugfile(struct target *target,
					     struct memregion *region,
					     char *filename,
					     debugfile_type_t type) {
    struct debugfile *debugfile;
    char *idstr;
    char *realname = NULL;
    char *name = NULL;
    char *version = NULL;

    if (type != DEBUGFILE_TYPE_SHAREDLIB) 
	debugfile_filename_info(filename,&realname,NULL,NULL);
    else 
	debugfile_filename_info(filename,&realname,&name,&version);

    if (!realname) 
	realname = filename;
    else 
	vdebug(2,LOG_T_TARGET,"using %s instead of symlink %s\n",
	       realname,filename);

    idstr = debugfile_build_idstr(realname,name,version);

    /* if they already loaded this debugfile into this region, error */
    if (g_hash_table_lookup(region->debugfiles,idstr)) {
	verror("debugfile(%s) already in use in region(%s) in space (%s)!\n",
	       idstr,region->name,region->space->idstr);
	errno = EBUSY;
	free(idstr);
	if (realname != filename)
	    free(realname);
	return NULL;
    }

    /* if this debugfile has already been loaded, use it */
    list_for_each_entry(debugfile,&debugfiles,debugfile) {
	if (strcmp(idstr,debugfile->idstr) == 0
	    && type == debugfile->type) {
	    ++(debugfile->refcnt);

	    vdebug(1,LOG_T_TARGET,
		   "reusing debugfile(%s,%s,%s,%d) for region(%s) in space (%s,%d,%d)\n",
		   realname,name,version,type,region->name,
		   region->space->name,region->space->id,region->space->pid);

	    g_hash_table_insert(region->debugfiles,realname,debugfile);

	    free(idstr);
	    if (realname != filename)
		free(realname);
	    return debugfile;
	}
    }

    debugfile = debugfile_create(realname,type,name,version,idstr);
    if (!debugfile) {
	free(idstr);
	if (realname != filename)
	    free(realname);
	return NULL;
    }

    /*
     * Finally, load in the debuginfo!
     */
    if (debugfile_load(debugfile)) {
	debugfile_free(debugfile);
	return NULL;
    }

    list_add_tail(&debugfile->debugfile,&debugfiles);

    g_hash_table_insert(region->debugfiles,idstr,debugfile);

    return debugfile;
}

int target_find_range_real(struct target *target,ADDR addr,
			   struct addrspace **space_saveptr,
			   struct memregion **region_saveptr,
			   struct memrange **range_saveptr) {
    struct addrspace *space;

    if (list_empty(&target->spaces))
	return 1;

    list_for_each_entry(space,&target->spaces,space) {
	if (addrspace_find_range_real(space,addr,
				      region_saveptr,range_saveptr)) {
	    if (space_saveptr) 
		*space_saveptr = space;
	    goto out;
	}
    }
    return 0;

 out:
    return 1;
}

struct symtab *target_lookup_pc(struct target *target,uint64_t pc) {
    struct addrspace *space;
    struct memregion *region;
    struct symtab *symtab;
    GHashTableIter iter, iter2;
    gpointer key, value;

    if (list_empty(&target->spaces))
	return NULL;

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if (memregion_contains_real(region,pc))
		goto found;
	}
    }

    return NULL;

 found:
    g_hash_table_iter_init(&iter,region->debugfiles);
    while (g_hash_table_iter_next(&iter,
				  (gpointer)&key,(gpointer)&value)) {
	g_hash_table_iter_init(&iter2,((struct debugfile *)value)->srcfiles);
	while (g_hash_table_iter_next(&iter2,
				      (gpointer)&key,(gpointer)&symtab)) {
	    symtab = symtab_lookup_pc(symtab,pc);
	    if (symtab)
		return symtab;
	}
    }

    return NULL;
}

struct bsymbol *target_lookup_sym_addr(struct target *target,ADDR addr) {
    struct addrspace *space;
    struct memregion *region;
    GHashTableIter iter;
    gpointer key;
    struct debugfile *debugfile;
    struct symbol *symbol;
    struct bsymbol *bsymbol;
    struct lsymbol *lsymbol;

    if (list_empty(&target->spaces))
	return NULL;

    vdebug(3,LOG_T_SYMBOL,
	   "trying to find symbol at address 0x%"PRIxADDR"\n",
	   addr);

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if (memregion_contains_real(region,addr))
		goto found;
	}
    }

    return NULL;

 found:
    g_hash_table_iter_init(&iter,region->debugfiles);
    while (g_hash_table_iter_next(&iter,
				  (gpointer)&key,(gpointer)&debugfile)) {
	if ((symbol = (struct symbol *)g_hash_table_lookup(debugfile->addresses,
							   (gpointer)addr))) {
	    lsymbol = lsymbol_create(symbol,NULL);
	    bsymbol = bsymbol_create(region,lsymbol);
	    return bsymbol;
	}
    }

    return NULL;
}

struct bsymbol *target_lookup_sym(struct target *target,
				  char *name,const char *delim,
				  char *srcfile,symbol_type_flag_t ftype) {
    struct addrspace *space;
    struct bsymbol *bsymbol;
    struct lsymbol *lsymbol = NULL;
    struct memregion *region;
    struct debugfile *debugfile;
    GHashTableIter iter;
    gpointer key;

    if (list_empty(&target->spaces))
	return NULL;

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    g_hash_table_iter_init(&iter,region->debugfiles);
	    while (g_hash_table_iter_next(&iter,(gpointer)&key,
					  (gpointer)&debugfile)) {
		lsymbol = debugfile_lookup_sym(debugfile,name,delim,srcfile,
					       ftype);
		if (lsymbol) 
		    goto out;
	    }
	}
    }
    return NULL;

 out:
    bsymbol = bsymbol_create(region,lsymbol);

    return bsymbol;
}

struct value *bsymbol_load(struct bsymbol *bsymbol,load_flags_t flags) {
    struct value *value = NULL;
    struct symbol *symbol = bsymbol->lsymbol->symbol;
    struct array_list *symbol_chain = bsymbol->lsymbol->chain;
    struct symbol *datatype;
    struct memregion *region = bsymbol->region;
    struct target *target = memregion_target(region);
    struct memrange *range;
    REGVAL ip;
    ADDR ip_addr;
    int nptrs = 0;
    ADDR ptraddr = 0;
    struct location ptrloc;
    struct memregion *ptrregion = NULL;
    struct memrange *ptrrange = NULL;

    if (!SYMBOL_IS_VAR(symbol)) {
	vwarn("symbol %s is not a variable (is %s)!\n",
	      symbol->name,SYMBOL_TYPE(symbol->type));
	errno = EINVAL;
	return NULL;
    }

    /* Get its real type. */
    datatype = symbol_type_skip_qualifiers(symbol->datatype);
    if (symbol->datatype != datatype)
	vdebug(5,LOG_T_SYMBOL,"skipped from %s to %s for symbol %s\n",
	       DATATYPE(symbol->datatype->s.ti.datatype_code),
	       DATATYPE(datatype->s.ti.datatype_code),symbol->name);
    else 
	vdebug(5,LOG_T_SYMBOL,"no skip; type for symbol %s is %s\n",
	       symbol->name,DATATYPE(symbol->datatype->s.ti.datatype_code));

    /* Check if this symbol is currently visible to us! */
    if (!(flags & LOAD_FLAG_NO_CHECK_VISIBILITY)) {
	if (sizeof(REGVAL) == sizeof(ADDR))
	    ip_addr = (ADDR)target_read_reg(target,target->ipregno);
	else if (sizeof(ADDR) < sizeof(REGVAL)) {
	    ip = target_read_reg(target,target->ipregno);
	    memcpy(&ip_addr,&ip,sizeof(ADDR));
	}
	else {
	    verror("sizeof(ADDR) > sizeof(REGVAL) -- makes no sense!\n");
	    errno = EINVAL;
	}

	if (errno)
	    return NULL;

	/*
	 * The symbol "visible" range is an object address; so, we need
	 * to check for each range in the region, if the address is
	 * visible inside one of them!
	 */
	range = memregion_find_range_real(region,ip_addr);
	if (!range)
	    verror("could not find range to check symbol visibility at IP 0x%"PRIxADDR" for symbol %s!\n",
		   ip_addr,symbol->name);
	else if (!symbol_visible_at_ip(symbol,
				       memrange_unrelocate(range,ip_addr))) {
	    verror("symbol not visible at IP 0x%"PRIxADDR" for symbol %s!\n",
		   ip_addr,symbol->name);
	    return NULL;
	}
    }

    /* If they want pointers automatically dereferenced, do it! */
    if (((flags & LOAD_FLAG_AUTO_DEREF) && SYMBOL_IST_PTR(datatype))
	|| ((flags & LOAD_FLAG_AUTO_STRING) 
	    && SYMBOL_IST_PTR(datatype) 
	    && symbol_type_is_char(datatype->s.ti.type_datatype))) {
	vdebug(5,LOG_T_SYMBOL,"auto_deref: starting ptr symbol %s\n",
	       symbol->name);

	/* First, load the symbol's primary location -- the pointer
	 * value.  Then, if there are more pointers, keep loading those
	 * addrs.
	 *
	 * Don't allow any load flags through for this!  We don't want
	 * to mmap just for pointers.
	 */
	if (!location_load(target,region,&(symbol->s.ii.l),LOAD_FLAG_NONE,
			   &ptraddr,target->ptrsize,symbol_chain,&range)) {
	    verror("auto_deref: could not load ptr for symbol %s!\n",
		   symbol->name);
	    goto errout;
	}

	vdebug(5,LOG_T_SYMBOL,"auto_deref: loaded ptr for symbol %s\n",
	       symbol->name);

	if (!range) {
	    verror("could not find range in auto_deref\n");
	    goto errout;
	}

	/* Skip past the pointer we just loaded. */
	datatype = datatype->s.ti.type_datatype;

	nptrs = 1;

	vdebug(5,LOG_T_SYMBOL,"auto_deref pointer %d\n",nptrs);

	/* Now keep loading more pointers and skipping if we need! */
	while (SYMBOL_IST_PTR(datatype)) {
	    if (ptraddr == 0) {
		vwarn("failed to autoload NULL pointer %d for symbol %s\n",
		      nptrs,symbol->name);
		errno = EFAULT;
		goto errout;
	    }

	    /*
	     * The pointer may be in another region!  We *have* to
	     * switch regions -- and thus the memrange for the value we
	     * return may not be in the bsymbol's region!
	     */
	    if (!target_find_range_real(target,ptraddr,
					NULL,&ptrregion,&ptrrange) == -1) {
		vwarn("could not auto_deref ptr not in a range: 0x%"PRIxADDR"\n",
		      ptraddr);
		errno = EFAULT;
		goto errout;
	    }

	    if (!location_addr_load(target,ptrrange,ptraddr,LOAD_FLAG_NONE,
				   &ptraddr,target->ptrsize)) {
		vwarn("failed to autoload pointer %d for symbol %s\n",
		      nptrs,symbol->name);
		goto errout;
	    }

	    datatype = datatype->s.ti.type_datatype;
	    ++nptrs;

	    vdebug(5,LOG_T_SYMBOL,"auto_deref pointer %d\n",nptrs);
	}

	/*
	 * The final pointer may be in another region and range!  So
	 * look it up one more time.
	 */
	if (!target_find_range_real(target,ptraddr,
				    NULL,&ptrregion,&ptrrange) == -1) {
	    vwarn("could not auto_deref ptr not in a range: 0x%"PRIxADDR"\n",
		  ptraddr);
	    errno = EFAULT;
	    goto errout;
	}
    }

    /*
     * Now allocate the value struct for various cases and return.
     */

    /* If we're autoloading pointers and we want to load char * pointers
     * as strings, do it!
     */
    if (ptraddr
	&& flags & LOAD_FLAG_AUTO_STRING
	&& symbol_type_is_char(datatype)) {
	/* XXX: should we use datatype, or the last pointer to datatype? */
	value = value_create_noalloc(bsymbol,datatype);

	if (!(value->buf = location_addr_load(target,ptrrange,ptraddr,flags,
					      NULL,0))) {
	    vwarn("failed to autoload last pointer for symbol %s\n",
		  symbol->name);
	    goto errout;
	}
	value->bufsiz = strlen(value->buf) + 1;
	value->isstring = 1;

	vdebug(5,LOG_T_SYMBOL,"autoloaded char * with len %d\n",value->bufsiz);

	/* success! */
	goto out;
    }
    else if (flags & LOAD_FLAG_MUST_MMAP || flags & LOAD_FLAG_SHOULD_MMAP) {
	ptrloc.loctype = LOCTYPE_REALADDR;
	ptrloc.l.addr = ptraddr;

	value = value_create_noalloc(bsymbol,datatype);
	value->mmap = location_mmap(target,(ptraddr) ? ptrregion : region,
				    (ptraddr) ? &ptrloc : &(symbol->s.ii.l),
				    flags,&value->buf,symbol_chain,NULL);
	if (!value->mmap && flags & LOAD_FLAG_MUST_MMAP) {
	    value->buf = NULL;
	    value_free(value);
	    goto errout;
	}
	else if (!value->mmap) {
	    /* fall back to regular load */
	    value->bufsiz = symbol_type_full_bytesize(datatype);
	    value->buf = malloc(value->bufsiz);
	    if (!value->buf) {
		value->bufsiz = 0;
		goto errout;
	    }

	    if (!location_load(target,(ptraddr) ? ptrregion: region,
			       (ptraddr) ? &ptrloc : &(symbol->s.ii.l),
			       flags,value->buf,value->bufsiz,symbol_chain,
			       &value->range))
		goto errout;
	}

	/* success! */
	goto out;
    }
    else {
	ptrloc.loctype = LOCTYPE_REALADDR;
	ptrloc.l.addr = ptraddr;

	value = value_create(bsymbol,datatype);

	if (!location_load(target,region,
			   (ptraddr) ? &ptrloc : &(symbol->s.ii.l),
			   flags,value->buf,value->bufsiz,symbol_chain,
			   &value->range))
	    goto errout;
    }

 out:
    if (value->range)
	value->region_stamp = value->range->region->stamp;

    return value;

 errout:
    if (value)
	value_free(value);

    return NULL;
}

struct value *target_location_load_type(struct target *target,
					struct location *location,
					load_flags_t flags,
					struct symbol *type) {
    /* XXX: fill in from above later. */
    return NULL;
}

int target_contains(struct target *target,ADDR addr) {
    struct addrspace *space;
    struct memregion *region;

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if (memregion_contains_real(region,addr))
		return 1;
	}
    }

    return 0;
}

/*
 * Load a raw value (i.e., no symbol or type info) using an object
 * file-based location (i.e., a fixed object-relative address) and a
 * specific region.
 *
 * Note: you cannot mmap raw values; they must be copied from target memory.
 */
struct value *target_load_raw_obj_location(struct target *target,
					   struct memregion *region,
					   ADDR obj_addr,load_flags_t flags,
					   int len) {
    struct location l = {
	.loctype = LOCTYPE_ADDR,
	.l.addr = obj_addr,
    };

    return target_load_raw(target,region,&l,flags,len);
}

/*
 * Load a raw value (i.e., no symbol or type info) using a real address.
 *
 * Note: you cannot mmap raw values; they must be copied from target memory.
 */
struct value *target_load_raw(struct target *target,struct memregion *region,
			      struct location *location,load_flags_t flags,
			      int len) {
    struct value *value;

    if (flags & LOAD_FLAG_MUST_MMAP) {
	errno = EINVAL;
	return NULL;
    }

    if (!(value = value_create_raw(len)))
	return NULL;

    if (!location_load(target,region,location,flags,
		       value->buf,value->bufsiz,NULL,
		       &value->range))
	goto errout;

    if (value->range)
	value->region_stamp = value->range->region->stamp;

    return value;

 errout:
    value_free(value);
    return NULL;
}
