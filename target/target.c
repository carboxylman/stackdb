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
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
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

struct debugfile_load_opts *target_get_debugfile_load_opts(struct target *target,
							   struct memregion *region,
							   char *filename,
							   debugfile_type_t type) {
    struct debugfile_load_opts *opts = NULL;
    int accept;
    int i;

    /*
     * If the target has debugfile load opts, match one of them with the
     * filename if possible, then parse or not parse it.  We set errno = 0
     * even if we return NULL in this case.
     */
    if (target->debugfile_opts_list) {
	vdebug(2,LOG_D_DFILE | LOG_T_TARGET,
	       "checking debugfile optlist\n");
	for (i = 0; target->debugfile_opts_list[i]; ++i) {
	    /* We only care if there was a match (or no match and the
	     * filter defaulted to accept) that accepted our filename
	     * for processing.
	     */
	    rfilter_check(target->debugfile_opts_list[i]->debugfile_filter,
			  filename,&accept,NULL);
	    if (accept == RF_ACCEPT) {
		opts = target->debugfile_opts_list[i];
		vdebug(2,LOG_D_DFILE | LOG_T_TARGET,
		       "using debugfile opts %p\n",opts);
		errno = 0;
		return opts;
	    }
	    vdebug(2,LOG_D_DFILE | LOG_T_TARGET,
		   "not using debugfile opts %p\n",
		   target->debugfile_opts_list[i]);
	}

	/* If we didn't find an opts that allowed us to load the file,
	 * tell the caller not to load it.
	 */
	if (!opts) {
	    errno = EINVAL;
	    return NULL;
	}
    }
    else 
	vdebug(2,LOG_D_DFILE | LOG_T_TARGET,
	       "no debugfile optlist supplied!\n");

    /* No opts to return to caller, but it's still fine to load the
     * file.
     */
    errno = 0;
    return NULL;
}

/*
 * A function that tries to find a debugfile that has already been used,
 * and if it does, it associates this region with it.
 */
struct debugfile *target_reuse_debugfile(struct target *target,
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
	    RHOLD(debugfile);

	    vdebug(1,LOG_T_TARGET,
		   "reusing debugfile(%s,%s,%s,%d) for region(%s) in space (%s,%d,%d)\n",
		   realname,name,version,type,region->name,
		   region->space->name,region->space->id,region->space->pid);

	    g_hash_table_insert(region->debugfiles,debugfile->idstr,debugfile);

	    free(idstr);
	    if (realname != filename)
		free(realname);
	    return debugfile;
	}
    }

    free(idstr);
    if (realname != filename)
	free(realname);
    return NULL;
}

/*
 * Creates a debugfile; very simple wrapper for debugfile_create.
 */
struct debugfile *target_create_debugfile(struct target *target,
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

    debugfile = debugfile_create(realname,type,name,version,idstr);
    if (!debugfile) {
	free(idstr);
	if (realname != filename)
	    free(realname);
	return NULL;
    }
    /* debugfile_create strdups its first arg */
    if (realname != filename)
	free(realname);

    return debugfile;
}

/*
 * A utility function that loads a debugfile with the given opts.
 */
int target_load_and_associate_debugfile(struct target *target,
					struct memregion *region,
					struct debugfile *debugfile,
					struct debugfile_load_opts *opts) {

    /* if they already loaded this debugfile into this region, error */
    if (g_hash_table_lookup(region->debugfiles,debugfile->idstr)) {
	verror("debugfile(%s) already in use in region(%s) in space (%s)!\n",
	       debugfile->idstr,region->name,region->space->idstr);
	errno = EBUSY;
	return -1;
    }

    if (debugfile_load(debugfile,opts))
	return -1;

    RHOLD(debugfile);

    list_add_tail(&debugfile->debugfile,&debugfiles);

    g_hash_table_insert(region->debugfiles,debugfile->idstr,debugfile);

    vdebug(1,LOG_T_TARGET,
	   "loaded and associated debugfile(%s) for region(%s,"
	   "base_phys=0x%"PRIxADDR",base_virt=0x%"PRIxADDR")"
	   " in space (%s,%d,%d)\n",
	   debugfile->idstr,region->name,
	   region->base_phys_addr,region->base_virt_addr,
	   region->space->name,region->space->id,region->space->pid);

    return 0;
}

void target_disassociate_debugfile(struct debugfile *debugfile) {
    list_del(&debugfile->debugfile);
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
    struct bsymbol *bsymbol;
    struct lsymbol *lsymbol;
    struct memrange *range;

    if (list_empty(&target->spaces))
	return NULL;

    vdebug(3,LOG_T_SYMBOL,
	   "trying to find symbol at address 0x%"PRIxADDR"\n",
	   addr);

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if ((range = memregion_find_range_real(region,addr)))
		goto found;
	}
    }

    return NULL;

 found:
    g_hash_table_iter_init(&iter,region->debugfiles);
    while (g_hash_table_iter_next(&iter,
				  (gpointer)&key,(gpointer)&debugfile)) {
	if ((lsymbol = debugfile_lookup_addr(debugfile,
					     memrange_unrelocate(range,addr)))) {
	    bsymbol = bsymbol_create(lsymbol,region,NULL);
	    /* bsymbol_create took a ref to lsymbol, so we release it! */
	    lsymbol_release(lsymbol);
	    /* Take a ref to bsymbol on the user's behalf, since this is
	     * a lookup function.
	    */
	    bsymbol_hold(bsymbol);
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
		lsymbol = debugfile_lookup_sym(debugfile,name,
					       delim,NULL,ftype);
		if (lsymbol) 
		    goto out;
	    }
	}
    }
    return NULL;

 out:
    bsymbol = bsymbol_create(lsymbol,region,NULL);
    /* bsymbol_create took a ref to lsymbol, and debugfile_lookup_sym
     * took one on our behalf, so we release one!
     */
    lsymbol_release(lsymbol);

    /* Take a ref to bsymbol on the user's behalf, since this is
     * a lookup function.
     */
    bsymbol_hold(bsymbol);

    return bsymbol;
}

struct bsymbol *target_lookup_sym_member(struct target *target,
					 struct bsymbol *bsymbol,
					 char *name,const char *delim) {
    struct bsymbol *bsymbol_new;
    struct lsymbol *lsymbol;

    lsymbol = lsymbol_lookup_member(bsymbol->lsymbol,name,delim);
    if (!lsymbol)
	return NULL;

    bsymbol_new = bsymbol_create(lsymbol,bsymbol->region,NULL);
    /* bsymbol_create took a ref to lsymbol, and debugfile_lookup_sym
     * took one on our behalf, so we release one!
     */
    lsymbol_release(lsymbol);

    /* Take a ref to bsymbol_new on the user's behalf, since this is
     * a lookup function.
     */
    bsymbol_hold(bsymbol_new);

    return bsymbol_new;
}

struct bsymbol *target_lookup_sym_line(struct target *target,
				       char *filename,int line,
				       SMOFFSET *offset,ADDR *addr) {
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
		lsymbol = debugfile_lookup_sym_line(debugfile,filename,line,
						    offset,addr);
		if (lsymbol) 
		    goto out;
	    }
	}
    }
    return NULL;

 out:
    bsymbol = bsymbol_create(lsymbol,region,NULL);
    /* bsymbol_create took a ref to lsymbol, and debugfile_lookup_sym_line
     * took one on our behalf, so we release one!
     */
    lsymbol_release(lsymbol);

    /* Take a ref to bsymbol on the user's behalf, since this is
     * a lookup function.
     */
    bsymbol_hold(bsymbol);

    return bsymbol;
}

/*
 * This function traverses a bsymbol chain and returns the address of
 * the final symbol in the chain.  If the final symbol is a function, we
 * return its base address.  Otherwise, for intermediate variables on
 * the chain, if their types are pointers, we load the pointer, and keep
 * loading the chain according to the next type.  If the last var is a
 * pointer, and the AUTO_DEREF flag is set (or if the AUTO_STRING flag
 * is set, and the next type is a char type), we deref the pointer(s)
 * and return the value of the last pointer.  If it is not a pointer, we
 * return the computed address of the last var.  We return the type of
 * the value at the address we return in @final_type_saveptr so that the
 * caller doesn't have to track whether the final pointer was autoloaded
 * or not.
 */
ADDR __target_lsymbol_compute_address(struct target *target,
				      struct lsymbol *lsymbol,
				      ADDR addr,struct memregion *region,
				      load_flags_t flags,
				      struct symbol **final_type_saveptr,
				      struct memrange **range_saveptr) {
    ADDR retval = addr;
    struct symbol *symbol;
    struct symbol *datatype;
    struct array_list *symbol_chain;
    int alen;
    int i = 0;
    int rc;
    OFFSET offset;
    struct memregion *current_region = region;
    struct memrange *current_range;
    load_flags_t tflags = flags | LOAD_FLAG_AUTO_DEREF;
    struct array_list *tchain = NULL;
    struct symbol *tdatatype;

    symbol_chain = lsymbol->chain;
    alen = array_list_len(symbol_chain);

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
     * that's ever meaningful.
     *
     * Oh well... don't restrict for now!
     */
    symbol = (struct symbol *)array_list_item(symbol_chain,alen - 1);
    if (SYMBOL_IS_FULL_FUNCTION(symbol)) {
	datatype = symbol_type_skip_qualifiers(symbol->datatype);
	if ((rc = location_resolve_lsymbol_base(target,lsymbol,current_region,
						&retval,&current_range))) {
	    verror("could not resolve base addr for function %s!\n",
		   symbol_get_name(symbol));
	    errno = rc;
	    goto errout;
	}
	vdebug(5,LOG_T_SYMBOL,"function %s at 0x%"PRIxADDR"\n",
	       symbol_get_name(symbol),retval);
	goto out;
    }

    /*
     * We maintain a "slice" of the lsymbol chain, because we only want
     * to pass the subset of it that is our current value of i -- the
     * part of the list we have traversed.
     */
    tchain = array_list_clone(symbol_chain,0);

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
    while (1) {
	symbol = (struct symbol *)array_list_item(symbol_chain,i);
	++i;
	tchain->len = i;

	/* Skip functions -- we may need them in the chain, however, so
	 * that our location resolution functions can obtain the frame
	 * register info they need to resolve, if a subsequent
	 * variable's location is dependent on the frame base register.
	 */
	if (SYMBOL_IS_FUNCTION(symbol))
	    continue;

	/* 
	 * If the symbol is a pointer or struct/union type, we support
	 * those (pointers by autoloading; S/U by skipping).  Otherwise,
	 * it's an error -- i.e., users can't try to compute an address
	 * for 'enum foo_enum.FOO_ENUM_ONE'.
	 */
	if (SYMBOL_IS_TYPE(symbol)) {
	    /* Grab the type's datatype. */
	    tdatatype = symbol_type_skip_qualifiers(symbol);

	    if (SYMBOL_IST_PTR(tdatatype)) {
		datatype = tdatatype;
		goto do_pointer;
	    }
	    else if (SYMBOL_IST_STUN(tdatatype))
		continue;
	    else {
		verror("cannot load intermediate type symbol %s!\n",
		       symbol_get_name(symbol));
		errno = EINVAL;
		goto errout;
	    }
	}

	/* We error on all other symbol types that are not variables. */
	if (!SYMBOL_IS_FULL_VAR(symbol)) {
	    verror("symbol %s of type %s is not a full variable!\n",
		   symbol_get_name(symbol),SYMBOL_TYPE(symbol->type));
	    errno = EINVAL;
	    goto errout;
	}

	/* Grab the symbol's datatype. */
	datatype = symbol_type_skip_qualifiers(symbol->datatype);

	/* If the symbol is a member variable, just add its offset to
	 * our currrent address, and continue.
	 */
	if (symbol->ismember) {
	    if (symbol_get_location_offset(symbol,&offset)) {
		verror("could not get offset for member %s in datatype %s!\n",
		       symbol_get_name(symbol),symbol_get_name(datatype));
		errno = EINVAL;
		goto errout;
	    }
	    retval += offset;
	    vdebug(5,LOG_T_SYMBOL,
		   "member %s at offset 0x%"PRIxOFFSET"; addr 0x%"PRIxADDR"\n",
		   symbol_get_name(symbol),offset,retval);
	}
	/* Otherwise, we actually need to resolve its location based on
	 * the info in the symbol.
	 */
	else {
	    if (LOCATION_IN_REG(&symbol->s.ii->l)) {
		/* If this var is in a register, and it's the last
		 * symbol on the chain, we can't provide an address for
		 * it!
		 *
		 * Actually, this situation can never happen; we could
		 * never give an address for a member of a struct inside
		 * a register; and if the value inside the register is a
		 * pointer, location_resolve handles that case for us.
		 *
		 * So, this should never happen.
		 *
		 * Well, it will happen when we're loading function.local
		 */
		if (1 || i == alen) {
		    errno = EADDRNOTAVAIL;
		    goto errout;
		}
	    }
	    else {
		retval = location_resolve(target,current_region,
					  &symbol->s.ii->l,
					  tchain,&current_range);
		if (errno) {
		    verror("could not resolve location for symbol %s\n",
			   symbol_get_name(symbol));
		    goto errout;
		}
		current_region = current_range->region;
		vdebug(5,LOG_T_SYMBOL,"var %s at 0x%"PRIxADDR"\n",
		       symbol_get_name(symbol),retval);
	    }
	}

	/*
	 * If the symbol is a pointer, load it now.  If this is the
	 * final symbol in the chain, and flags & AUTO_DEREF, also load
	 * the final pointer(s), and return the value.  Otherwise, just
	 * return the address of the final pointer.
	 */
	if (SYMBOL_IST_PTR(datatype)) {
	 do_pointer:
	    if (i < alen 
		|| (i == alen 
		    && (flags & LOAD_FLAG_AUTO_DEREF
			|| (flags & LOAD_FLAG_AUTO_STRING
			    && symbol_type_is_char(symbol_type_skip_ptrs(datatype)))))) {
		retval = target_autoload_pointers(target,datatype,retval,tflags,
						  &datatype,&current_range);
		if (errno) {
		    verror("could not load pointer for symbol %s\n",
			   symbol_get_name(symbol));
		    goto errout;
		}
		current_region = current_range->region;
		vdebug(5,LOG_T_SYMBOL,
		       "autoloaded pointer(s) for var %s now at 0x%"PRIxADDR"\n",
		       symbol_get_name(symbol),retval);
	    }

	    if (i == alen)
		goto out;
	}

	if (i >= alen) 
	    goto out;
    }

 errout:
    retval = 0;
    array_list_free(tchain);
    return retval;

 out:
    array_list_free(tchain);
    if (range_saveptr)
	*range_saveptr = current_range;
    if (final_type_saveptr)
	*final_type_saveptr = datatype;
    return retval;

}

/*
 * This function traverses a bsymbol chain and returns the address of
 * the final symbol in the chain.  If the final symbol is a function, we
 * return its base address.  Otherwise, for intermediate variables on
 * the chain, if their types are pointers, we load the pointer, and keep
 * loading the chain according to the next type.  If the last var is a
 * pointer, and the AUTO_DEREF flag is set (or if the AUTO_STRING flag
 * is set, and the next type is a char type), we deref the pointer(s)
 * and return the value of the last pointer.  If it is not a pointer, we
 * return the computed address of the last var.  We return the type of
 * the value at the address we return in @final_type_saveptr so that the
 * caller doesn't have to track whether the final pointer was autoloaded
 * or not.
 */
ADDR __target_bsymbol_compute_address(struct target *target,
				      struct bsymbol *bsymbol,
				      load_flags_t flags,
				      struct symbol **final_type_saveptr,
				      struct memrange **range_saveptr) {
    return __target_lsymbol_compute_address(target,bsymbol->lsymbol,
					    0,bsymbol->region,flags,
					    final_type_saveptr,range_saveptr);
}

struct value *target_load_type(struct target *target,struct symbol *type,
			       ADDR addr,load_flags_t flags) {
    struct symbol *datatype = type;
    struct value *value;
    struct memregion *region;
    struct memrange *range;
    ADDR ptraddr;
    struct location ptrloc;

    datatype = symbol_type_skip_qualifiers(type);

    if (!SYMBOL_IS_FULL_TYPE(datatype)) {
	verror("symbol %s is not a full type (is %s)!\n",
	       symbol_get_name(type),SYMBOL_TYPE(type->type));
	errno = EINVAL;
	return NULL;
    }

    if (datatype != type)
	vdebug(5,LOG_T_SYMBOL,"skipped from %s to %s for type %s\n",
	       DATATYPE(type->datatype_code),
	       DATATYPE(datatype->datatype_code),symbol_get_name(type));
    else 
	vdebug(5,LOG_T_SYMBOL,"no skip; type for type %s is %s\n",
	       symbol_get_name(type),DATATYPE(datatype->datatype_code));

    /* Get range/region info for the addr. */
    if (!target_find_memory_real(target,addr,NULL,NULL,&range)) {
	errno = EFAULT;
	return NULL;
    }

    /* If they want pointers automatically dereferenced, do it! */
    ptraddr = target_autoload_pointers(target,datatype,addr,flags,
				       &datatype,&range);
    if (errno) {
	verror("failed to autoload pointers for type %s at addr 0x%"PRIxADDR"\n",
	       symbol_get_name(type),addr);
	return NULL;
    }
    region = range->region;

    if (!ptraddr) {
	verror("last pointer was NULL!\n");
	errno = EFAULT;
	return NULL;
    }

    /*
     * Now allocate the value struct for various cases and return.
     */

    /* If we're autoloading pointers and we want to load char * pointers
     * as strings, do it!
     */
    if (ptraddr != addr
	&& flags & LOAD_FLAG_AUTO_STRING
	&& symbol_type_is_char(datatype)) {
	/* XXX: should we use datatype, or the last pointer to datatype? */
	value = value_create_noalloc(NULL,datatype);

	if (!(value->buf = (char *)__target_load_addr_real(target,range,
							   ptraddr,flags,
							   NULL,0))) {
	    verror("failed to autoload char * for type %s at addr 0x%"PRIxADDR"\n",
		   symbol_get_name(type),addr);
	    goto errout;
	}
	value->bufsiz = strlen(value->buf) + 1;
	value->isstring = 1;
	value->range = range;
	value->addr = ptraddr;

	vdebug(5,LOG_T_SYMBOL,"autoloaded char * with len %d\n",value->bufsiz);

	/* success! */
	goto out;
    }
    else if (flags & LOAD_FLAG_MUST_MMAP || flags & LOAD_FLAG_SHOULD_MMAP) {
	ptrloc.loctype = LOCTYPE_REALADDR;
	ptrloc.l.addr = ptraddr != addr ? ptraddr : addr;

	value = value_create_noalloc(NULL,datatype);
	value->mmap = location_mmap(target,region,&ptrloc,
				    flags,&value->buf,NULL,&range);
	if (!value->mmap && flags & LOAD_FLAG_MUST_MMAP) {
	    value->buf = NULL;
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

	    if (!__target_load_addr_real(target,range,ptraddr,flags,
					 (unsigned char *)value->buf,
					 value->bufsiz)) 
		goto errout;
	}

	value->addr = ptrloc.l.addr;
	value->range = range;

	/* success! */
	goto out;
    }
    else {
	value = value_create_type(datatype);
	if (!value) {
	    verror("could not create value for type (ptr is %p) %s\n",
		   datatype,datatype ? datatype->name : NULL);
	    goto errout;
	}

	if (!__target_load_addr_real(target,range,ptraddr,flags,
				     (unsigned char *)value->buf,
				     value->bufsiz))
	    goto errout;

	value->addr = ptraddr;
	value->range = range;
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

struct value *target_load_symbol_member(struct target *target,
					struct bsymbol *bsymbol,
					const char *member,const char *delim,
					load_flags_t flags) {
    struct bsymbol *bmember;
    struct value *retval = NULL;

    bmember = target_lookup_sym_member(target,bsymbol,member,delim);
    if (!bmember) {
	verror("could not find member '%s' in symbol %s!\n",
	       member,bsymbol_get_name(bsymbol));
	return NULL;
    }

    retval = target_load_symbol(target,bmember,flags);

    bsymbol_release(bmember);

    return retval;
}

struct value *target_load_value_member(struct target *target,
				       struct value *old_value,
				       const char *member,const char *delim,
				       load_flags_t flags) {
    struct value *value = NULL;
    struct symbol *vstartdatatype = symbol_type_skip_qualifiers(old_value->type);
    struct symbol *tdatatype = vstartdatatype;
    struct symbol *mdatatype;
    struct lsymbol *ls = NULL;
    struct memrange *range;
    struct symbol *symbol;
    struct symbol *datatype;
    struct array_list *symbol_chain;
    char *rbuf = NULL;
    ADDR addr;

    /*
     * We have to handle two levels of pointers, potentially.  Suppose
     * that the @value's type is a pointer.  Then we have to load that
     * pointer (and any others), then find the member offset inside the
     * pointed-to struct/union, and then... if THAT member is itself a
     * pointer, we read THAT pointer (and any others) until we don't
     * have any more pointers.
     *
     * Of course, that behavior is only enabled when
     * LOAD_FLAG_AUTO_DEREF is set.
     */

    /* If the value's datatype is a pointer, and we are autoloading pointers,
     * then try to find a struct/union type that is pointed to!
     */
    if (SYMBOL_IST_PTR(vstartdatatype)) {
	if (flags & LOAD_FLAG_AUTO_DEREF) {
	    tdatatype = symbol_type_skip_ptrs(vstartdatatype);
	    addr = v_addr(old_value);
	}
	else {
	    errno = EINVAL;
	    goto errout;
	}
    }
    else
	addr = old_value->addr;

    if (!SYMBOL_IST_FULL_STUN(tdatatype)) {
	vwarn("symbol %s is not a full struct/union type (is %s)!\n",
	      symbol_get_name(tdatatype),SYMBOL_TYPE(tdatatype->type));
	errno = EINVAL;
	goto errout;
    }

    /*
     * Resolve the member symbol within tdatatype, the struct/union real
     * datatype.
     */
    ls = symbol_lookup_member(tdatatype,member,delim);
    if (!ls)
	goto errout;
    if (ls->symbol->s.ii->l.loctype != LOCTYPE_MEMBER_OFFSET) {
	verror("loctype for symbol %s is %s, not MEMBER_OFFSET!\n",
	       symbol_get_name(ls->symbol),
	       LOCTYPE(ls->symbol->s.ii->l.loctype));
	errno = EINVAL;
	goto errout;
    }
    mdatatype = symbol_type_skip_qualifiers(ls->symbol->datatype);

    /*
     * First, if the final symbol has a register location, don't bother
     * trying to compute its address.  Realistically, no bsymbol chain
     * that contains intermediate pointer vars should terminate with a
     * value in a register!
     */
    symbol = ls->symbol;
    symbol_chain = ls->chain;

    if (LOCATION_IN_REG(&symbol->s.ii->l)) {
	if (flags & LOAD_FLAG_MUST_MMAP) {
	    errno = EINVAL;
	    goto errout;
	}

	datatype = symbol_type_skip_qualifiers(symbol->datatype);
	rbuf = malloc(datatype->size);
	if (!location_load(target,old_value->range->region,&(symbol->s.ii->l),
			   flags,rbuf,datatype->size,symbol_chain,NULL,&range)) {
	    verror("could not load register location for symbol %s!\n",
		   symbol_get_name(symbol));
	    goto errout;
	}
	/* This is a special case; if this symbol is a pointer and we
	 * need to auto deref, do it.
	 */
	if (SYMBOL_IST_PTR(datatype)) {
	    memcpy(&addr,rbuf,datatype->size);
	    free(rbuf);
	    rbuf = NULL;
	    addr = target_autoload_pointers(target,datatype,addr,flags,
					    &datatype,&range);
	    if (errno) {
		verror("failed to autoload pointers for symbol %s\n",
		       symbol_get_name(symbol));
		goto errout;
	    }

	    /* Actually do the load. */
	    if (flags & LOAD_FLAG_AUTO_STRING 
		&& symbol_type_is_char(datatype)) {
		/* XXX: should we use datatype, or last pointer to datatype? */
		value = value_create_noalloc(ls,datatype);

		if (!(value->buf = (char *)__target_load_addr_real(target,range,
								   addr,flags,
								   NULL,0))) {
		    verror("failed to autostring char pointer for symbol %s\n",
			   symbol_get_name(symbol));
		    goto errout;
		}
		value->bufsiz = strlen(value->buf) + 1;
		value->isstring = 1;
		value->range = range;
		value->addr = addr;

		vdebug(5,LOG_T_SYMBOL,"autoloaded char * value with len %d\n",
		       value->bufsiz);
	    }
	    else {
		value = value_create(ls,datatype);

		if (!__target_load_addr_real(target,range,addr,flags,
					     (unsigned char *)value->buf,
					     value->bufsiz)) {
		    verror("failed to load value at 0x%"PRIxADDR"\n",addr);
		    goto out;
		}
		else {
		    value->range = range;
		    value->addr = addr;

		    vdebug(5,LOG_T_SYMBOL,
			   "autoloaded pointer value with len %d\n",
			   value->bufsiz);
		}
	    }
	}
	else {
	    /* Just create the value based on the register value. */
	    value = value_create_noalloc(ls,datatype);
	    value->buf = rbuf;
	    value->bufsiz = datatype->size;
	    value->range = range;
	}
    }
    /*
     * Second, get the address for the lsymbol chain.
     */
    else {
	addr = __target_lsymbol_compute_address(target,ls,addr,
						old_value->range->region,
						flags,&datatype,&range);
	if (addr == 0 && errno)
	    goto errout;

	/*
	 * If __target_lsymbol_compute_address_at returns an address
	 * entirely contained inside of value->buf, we can just clone
	 * the value from within the old value.  Otherwise, we have to
	 * load it from the final address.
	 */
	if (addr >= old_value->addr 
	    && (addr - old_value->addr) < (unsigned)old_value->bufsiz) {
	    value = value_create_noalloc(ls,datatype);
	    value->buf = old_value->buf + (addr - old_value->addr);
	    value->parent_value = old_value;
	    value->range = range;
	    value->addr = addr;

	    goto out;
	}

	tdatatype = symbol_type_skip_qualifiers(symbol->datatype);
	if (flags & LOAD_FLAG_AUTO_STRING
	    && SYMBOL_IST_PTR(tdatatype) 
	    && symbol_type_is_char(symbol_type_skip_ptrs(tdatatype))) {
	    datatype = symbol_type_skip_ptrs(tdatatype);
	    /* XXX: should we use datatype, or the last pointer to datatype? */
	    value = value_create_noalloc(ls,datatype);

	    if (!(value->buf = (char *)__target_load_addr_real(target,range,
							       addr,flags,
							       NULL,0))) {
		vwarn("failed to autostring char pointer for symbol %s\n",
		      symbol_get_name(symbol));
		goto errout;
	    }
	    value->bufsiz = strlen(value->buf) + 1;
	    value->isstring = 1;
	    value->range = range;
	    value->addr = addr;

	    vdebug(5,LOG_T_SYMBOL,"autoloaded char * value with len %d\n",
		   value->bufsiz);
	}
	else {
	    value = value_create(ls,datatype);

	    if (!__target_load_addr_real(target,range,addr,flags,
					 (unsigned char *)value->buf,
					 value->bufsiz)) {
		verror("failed to load value at 0x%"PRIxADDR"\n",addr);
		goto errout;
	    }
	    else {
		value->range = range;
		value->addr = addr;

		vdebug(5,LOG_T_SYMBOL,"loaded value with len %d\n",
		       value->bufsiz);
	    }
	}

    }

 out:
    lsymbol_release(ls);
    return value;

 errout:
    if (ls)
	lsymbol_release(ls);
    if (rbuf)
	free(rbuf);
    if (value)
	value_free(value);
    return NULL;
}

struct value *target_load_symbol(struct target *target,struct bsymbol *bsymbol,
				 load_flags_t flags) {
    ADDR addr;
    int alen;
    struct symbol *symbol;
    struct array_list *symbol_chain;
    struct symbol *datatype;
    struct memregion *region = bsymbol->region;
    struct memrange *range = bsymbol->range;
    struct value *value = NULL;
    char *rbuf;
    struct symbol *tdatatype;

    symbol_chain = bsymbol->lsymbol->chain;
    alen = array_list_len(symbol_chain);

    symbol = (struct symbol *)array_list_item(symbol_chain,alen - 1);

    if (!SYMBOL_IS_FULL_VAR(symbol)) {
	verror("symbol %s is not a full variable (is %s)!\n",
	       symbol_get_name(symbol),SYMBOL_TYPE(symbol->type));
	errno = EINVAL;
	return NULL;
    }

    /*
     * If the final symbol has a register location, don't bother trying
     * to compute its address.  Realistically, no bsymbol chain that
     * contains intermediate pointer vars should terminate with a value
     * in a register!
     */
    if (LOCATION_IN_REG(&symbol->s.ii->l)) {
	if (flags & LOAD_FLAG_MUST_MMAP) {
	    errno = EINVAL;
	    return NULL;
	}

	datatype = symbol_type_skip_qualifiers(symbol->datatype);
	rbuf = malloc(datatype->size);
	if (!location_load(target,region,&(symbol->s.ii->l),flags,
			   rbuf,datatype->size,symbol_chain,NULL,&range)) {
	    verror("could not load register location for symbol %s!\n",
		   symbol_get_name(symbol));
	    value = NULL;
	    free(rbuf);
	    goto errout;
	}
	/* This is a special case; if this symbol is a pointer and we
	 * need to auto deref, do it.
	 */
	if (SYMBOL_IST_PTR(datatype)) {
	    memcpy(&addr,rbuf,datatype->size);
	    addr = target_autoload_pointers(target,datatype,addr,flags,&datatype,
					    &range);
	    if (errno) {
		vwarn("failed to autoload pointers for symbol %s\n",
		      symbol_get_name(symbol));
		goto errout;
	    }

	    /* Actually do the load. */
	    if (flags & LOAD_FLAG_AUTO_STRING && symbol_type_is_char(datatype)) {
		/* XXX: should we use datatype, or the last pointer to datatype? */
		value = value_create_noalloc(bsymbol->lsymbol,datatype);

		if (!(value->buf = (char *)__target_load_addr_real(target,range,
								   addr,flags,
								   NULL,0))) {
		    vwarn("failed to autostring char pointer for symbol %s\n",
			  symbol_get_name(symbol));
		    value_free(value);
		    value = NULL;
		    goto errout;
		}
		value->bufsiz = strlen(value->buf) + 1;
		value->isstring = 1;
		value->range = range;
		value->addr = addr;

		vdebug(5,LOG_T_SYMBOL,"autoloaded char * value with len %d\n",
		       value->bufsiz);
	    }
	    else {
		value = value_create(bsymbol->lsymbol,datatype);

		if (!__target_load_addr_real(target,range,addr,flags,
					     (unsigned char *)value->buf,
					     value->bufsiz)) {
		    verror("failed to load value at 0x%"PRIxADDR"\n",addr);
		    value_free(value);
		    value = NULL;
		    goto out;
		}
		else {
		    value->range = range;
		    value->addr = addr;

		    vdebug(5,LOG_T_SYMBOL,
			   "autoloaded pointer value with len %d\n",
			   value->bufsiz);
		}
	    }
	}
	else {
	    /* Just create the value based on the register value. */
	    value = value_create_noalloc(bsymbol->lsymbol,datatype);
	    value->buf = rbuf;
	    value->bufsiz = datatype->size;
	    value->range = range;
	}
    }
    /*
     * Otherwise, just compute the symbol's address and load that!
     * __target_bsymbol_compute_address handles all the AUTO_DEREF /
     * AUTO_STRING cases for us; all we have to note is the special
     * loading case for AUTO_STRING.
     */
    else {
	addr = __target_bsymbol_compute_address(target,bsymbol,flags,&datatype,
						&range);
	if (addr == 0 && errno)
	    goto errout;

	tdatatype = symbol_type_skip_qualifiers(symbol->datatype);
	if (flags & LOAD_FLAG_AUTO_STRING
	    && SYMBOL_IST_PTR(tdatatype) 
	    && symbol_type_is_char(symbol_type_skip_ptrs(tdatatype))) {
	    datatype = symbol_type_skip_ptrs(tdatatype);
	    /* XXX: should we use datatype, or the last pointer to datatype? */
	    value = value_create_noalloc(bsymbol->lsymbol,datatype);

	    if (!(value->buf = (char *)__target_load_addr_real(target,range,
							       addr,flags,
							       NULL,0))) {
		vwarn("failed to autostring char pointer for symbol %s\n",
		      symbol_get_name(symbol));
		value_free(value);
		value = NULL;
		goto errout;
	    }
	    value->bufsiz = strlen(value->buf) + 1;
	    value->isstring = 1;
	    value->range = range;
	    value->addr = addr;

	    vdebug(5,LOG_T_SYMBOL,"autoloaded char * value with len %d\n",
		   value->bufsiz);
	}
	else {
	    value = value_create(bsymbol->lsymbol,datatype);

	    if (!__target_load_addr_real(target,range,addr,flags,
					 (unsigned char *)value->buf,
					 value->bufsiz)) {
		verror("failed to load value at 0x%"PRIxADDR"\n",addr);
		value_free(value);
		value = NULL;
		goto out;
	    }
	    else {
		value->range = range;
		value->addr = addr;

		vdebug(5,LOG_T_SYMBOL,"loaded value with len %d\n",
		       value->bufsiz);
	    }
	}
    }

 out:
    if (value)
	value->region_stamp = value->range->region->stamp;
    return value;

 errout:
    if (value)
	value_free(value);
    return NULL;
}

/*
 * What we do here is traverse @bsymbol's lsymbol chain.  For each var
 * we encounter, try to resolve its address.  If the chain is
 * interrupted by pointers, load those and continue loading any
 * subsequent variables.
 */
ADDR target_addressof_bsymbol(struct target *target,struct bsymbol *bsymbol,
			      load_flags_t flags,
			      struct memrange **range_saveptr) {
    ADDR retval;
    int i = 0;
    int alen;
    int rc;
    struct symbol *symbol;
    struct array_list *symbol_chain;
    struct symbol *datatype;
    OFFSET offset;
    struct memregion *current_region = bsymbol->region;
    struct memrange *current_range = bsymbol->range;
    load_flags_t tflags = flags | LOAD_FLAG_AUTO_DEREF;
    struct array_list *tchain = NULL;

    symbol_chain = bsymbol->lsymbol->chain;
    alen = array_list_len(symbol_chain);
    symbol = (struct symbol *)array_list_item(symbol_chain,alen - 1);

    /* 
     * If the last symbol is a function, we only want to return its
     * base address.  So do that.
     */
    if (i == alen && SYMBOL_IS_FULL_FUNCTION(symbol)) {
	if ((rc = location_resolve_symbol_base(target,bsymbol,
					       &retval,&current_range))) {
	    verror("could not resolve base addr for function %s!\n",
		   symbol_get_name(symbol));
	    errno = rc;
	    goto errout;
	}
	vdebug(5,LOG_T_SYMBOL,"function %s at 0x%"PRIxADDR"\n",
	       symbol_get_name(symbol),retval);
	goto out;
    }

    /*
     * We maintain a "slice" of the lsymbol chain, because we only want
     * to pass the subset of it that is our current value of i -- the
     * part of the list we have traversed.
     */
    tchain = array_list_clone(symbol_chain,0);

    /*
     * We traverse through the lsymbol, loading nested chunks.  If the
     * end of the chain is a function, we return its base address.
     * Otherwise, we do nothing for functions (they may be used to
     * resolve the location of variables, however -- i.e., computing the
     * dwarf frame_base virtual register).  Otherwise, for variables, if
     * their types are pointers, we load the pointer, and keep loading
     * the chain according to the next type.  If the last var is a
     * pointer, and the AUTO_DEREF flag is set, we deref the pointer(s)
     * and return the value of the last pointer.  If it is not a
     * pointer, we return the computed address of the last var.
     *
     * The one weird thing is that if the var is a member that is a
     * struct/union type, we skip it because our location resolution for
     * members automatically goes back up the chain to handle nested
     * struct members.
     */
    while (1) {
	symbol = (struct symbol *)array_list_item(symbol_chain,i);
	++i;
	tchain->len = i;

	if (!SYMBOL_IS_FULL_VAR(symbol)) {
	    verror("symbol %s of type %s is not a full variable!\n",
		   symbol_get_name(symbol),SYMBOL_TYPE(symbol->type));
	    errno = EINVAL;
	    goto errout;
	}

	datatype = symbol_type_skip_qualifiers(symbol->datatype);
	if (symbol->ismember && SYMBOL_IST_STUN(datatype)) {
	    vdebug(5,LOG_T_SYMBOL,"skipping member %s in stun type %s\n",
		   symbol_get_name(symbol),symbol_get_name(datatype));
	    continue;
	}
	else if (symbol->ismember) {
	    offset = location_resolve_offset(&symbol->s.ii->l,
					     tchain,NULL,NULL);
	    if (errno) {
		verror("could not resolve offset for member %s\n",
		       symbol_get_name(symbol));
		goto errout;
	    }
	    retval += offset;
	    vdebug(5,LOG_T_SYMBOL,
		   "member %s at offset 0x%"PRIxOFFSET"; really at 0x%"PRIxADDR
		   "\n",
		   symbol_get_name(symbol),offset,retval);
	}
	else {
	    if (LOCATION_IN_REG(&symbol->s.ii->l)) {
		/* If this var is in a register, and it's the last
		 * symbol on the chain, we can't provide an address for
		 * it!
		 *
		 * Actually, this situation can never happen; we could
		 * never give an address for a member of a struct inside
		 * a register; and if the value inside the register is a
		 * pointer, location_resolve handles that case for us.
		 *
		 * So, this should never happen.
		 */
		if (1 || i == alen) {
		    errno = EADDRNOTAVAIL;
		    goto errout;
		}
	    }
	    else {
		retval = location_resolve(target,current_region,
					  &symbol->s.ii->l,
					  tchain,&current_range);
		if (errno) {
		    verror("could not resolve location for symbol %s\n",
			   symbol_get_name(symbol));
		    goto errout;
		}
		current_region = current_range->region;
		vdebug(5,LOG_T_SYMBOL,"var %s at 0x%"PRIxADDR"\n",
		       symbol_get_name(symbol),retval);
	    }
	}

	/*
	 * If the symbol is a pointer, load it now.  If this is the
	 * final symbol in the chain, and flags & AUTO_DEREF, also load
	 * the final pointer(s), and return the value.  Otherwise, just
	 * return the address of the final pointer.
	 */
	if (SYMBOL_IST_PTR(datatype)) {
	    if (i < alen || (i == alen && flags & LOAD_FLAG_AUTO_DEREF)) {
		retval = target_autoload_pointers(target,datatype,retval,tflags,
						  NULL,&current_range);
		if (errno) {
		    verror("could not load pointer for symbol %s\n",
			   symbol_get_name(symbol));
		    goto errout;
		}
		current_region = current_range->region;
		vdebug(5,LOG_T_SYMBOL,
		       "autoloaded pointer(s) for var %s now at 0x%"PRIxADDR"\n",
		       symbol_get_name(symbol),retval);
	    }

	    if (i == alen)
		goto out;
	}

	if (i >= alen) 
	    goto out;
    }

 errout:
    retval = 0;

 out:
    array_list_free(tchain);
    if (range_saveptr)
	*range_saveptr = current_range;
    return retval;
}

struct value *bsymbol_load(struct bsymbol *bsymbol,load_flags_t flags) {
    struct value *value = NULL;
    struct symbol *symbol = bsymbol->lsymbol->symbol;
    struct array_list *symbol_chain = bsymbol->lsymbol->chain;
    struct symbol *datatype;
    struct symbol *startdatatype = NULL;
    struct memregion *region = bsymbol->region;
    struct target *target = memregion_target(region);
    struct memrange *range;
    REGVAL ip;
    ADDR ip_addr;
    ADDR ptraddr = 0;
    ADDR finaladdr = 0;
    struct location ptrloc;
    struct memregion *ptrregion = NULL;
    struct memrange *ptrrange = NULL;

    if (!SYMBOL_IS_FULL_VAR(symbol)) {
	vwarn("symbol %s is not a full variable (is %s)!\n",
	      symbol->name,SYMBOL_TYPE(symbol->type));
	errno = EINVAL;
	return NULL;
    }

    /* Get its real type. */

    startdatatype = symbol_get_datatype(symbol);
    datatype = symbol_type_skip_qualifiers(startdatatype);

    if (startdatatype != datatype)
	vdebug(5,LOG_T_SYMBOL,"skipped from %s to %s for symbol %s\n",
	       DATATYPE(startdatatype->datatype_code),
	       DATATYPE(datatype->datatype_code),symbol->name);
    else 
	vdebug(5,LOG_T_SYMBOL,"no skip; type for symbol %s is %s\n",
	       symbol->name,DATATYPE(datatype->datatype_code));

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
	range = NULL;
    }

    /* If they want pointers automatically dereferenced, do it! */
    if (((flags & LOAD_FLAG_AUTO_DEREF) && SYMBOL_IST_PTR(datatype))
	|| ((flags & LOAD_FLAG_AUTO_STRING) 
	    && SYMBOL_IST_PTR(datatype) 
	    && symbol_type_is_char(datatype->datatype))) {
	vdebug(5,LOG_T_SYMBOL,"auto_deref: starting ptr symbol %s\n",
	       symbol->name);

	/* First, load the symbol's primary location -- the pointer
	 * value.  Then, if there are more pointers, keep loading those
	 * addrs.
	 *
	 * Don't allow any load flags through for this!  We don't want
	 * to mmap just for pointers.
	 */
	range = NULL;
	if (!location_load(target,region,&(symbol->s.ii->l),LOAD_FLAG_NONE,
			   &ptraddr,target->ptrsize,symbol_chain,&finaladdr,&range)) {
	    verror("auto_deref: could not load ptr for symbol %s!\n",
		   symbol->name);
	    goto errout;
	}

	vdebug(5,LOG_T_SYMBOL,"loaded ptr value 0x%"PRIxADDR"for symbol %s\n",
	       ptraddr,symbol->name);

	/* Skip past the pointer we just loaded. */
	datatype = symbol_get_datatype(datatype);

	/* Skip past any qualifiers! */
	datatype = symbol_type_skip_qualifiers(datatype);

	ptraddr = target_autoload_pointers(target,datatype,ptraddr,flags,
					   &datatype,&range);
	if (errno) {
	    vwarn("failed to autoload pointers for symbol %s\n",
		  symbol_get_name(symbol));
	    goto errout;
	}

	if (range)
	    ptrregion = range->region;
	else {
	    /* We might not have a range if the value was in a register;
	     * if we don't have one, find it!
	     */
	    if (!target_find_memory_real(target,ptraddr,NULL,NULL,&range)) {
		errno = EFAULT;
		return NULL;
	    }
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
	value = value_create_noalloc(bsymbol->lsymbol,datatype);

	if (!(value->buf = (char *)__target_load_addr_real(target,ptrrange,
							   ptraddr,flags,
							   NULL,0))) {
	    vwarn("failed to autoload last pointer for symbol %s\n",
		  symbol->name);
	    goto errout;
	}
	value->bufsiz = strlen(value->buf) + 1;
	value->isstring = 1;
	value->range = ptrrange;
	value->addr = ptraddr;

	vdebug(5,LOG_T_SYMBOL,"autoloaded char * with len %d\n",value->bufsiz);

	/* success! */
	goto out;
    }
    else if (flags & LOAD_FLAG_MUST_MMAP || flags & LOAD_FLAG_SHOULD_MMAP) {
	ptrloc.loctype = LOCTYPE_REALADDR;
	ptrloc.l.addr = ptraddr;

	value = value_create_noalloc(bsymbol->lsymbol,datatype);
	value->mmap = location_mmap(target,(ptraddr) ? ptrregion : region,
				    (ptraddr) ? &ptrloc : &(symbol->s.ii->l),
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
			       (ptraddr) ? &ptrloc : &(symbol->s.ii->l),
			       flags,value->buf,value->bufsiz,symbol_chain,
			       &finaladdr,&value->range))
		goto errout;
	}

	value->addr = finaladdr;

	/* success! */
	goto out;
    }
    else {
	ptrloc.loctype = LOCTYPE_REALADDR;
	ptrloc.l.addr = ptraddr;

	value = value_create(bsymbol->lsymbol,datatype);
	if (!value) {
	    verror("could not create value for type (ptr is %p); %s\n",
		   datatype,datatype ? datatype->name : NULL);
	    goto errout;
	}

	if (!location_load(target,region,
			   (ptraddr) ? &ptrloc : &(symbol->s.ii->l),
			   flags,value->buf,value->bufsiz,symbol_chain,
			   &finaladdr,&value->range))
	    goto errout;

	value->addr = finaladdr;
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

int target_store_value(struct target *target,struct value *value) {
    /* mmap'd values were stored whenever they were value_update_*'d */
    if (value->mmap)
	return 0;

    if (target_write_addr(target,value->addr,(unsigned long)value->bufsiz,
			  (unsigned char *)value->buf,NULL)
	!= (unsigned long)value->bufsiz)
	return -1;
    return 0;
}

int target_find_memory_real(struct target *target,ADDR addr,
			    struct addrspace **space_saveptr,
			    struct memregion **region_saveptr,
			    struct memrange **range_saveptr) {
    struct addrspace *space;

    if (list_empty(&target->spaces))
	return 0;

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

int target_contains_real(struct target *target,ADDR addr) {
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

ADDR target_autoload_pointers(struct target *target,struct symbol *datatype,
			      ADDR addr,load_flags_t flags,
			      struct symbol **datatype_saveptr,
			      struct memrange **range_saveptr) {
    load_flags_t ptrloadflags = flags;
    ADDR paddr = addr;
    struct memrange *range = NULL;
    int nptrs = 0;

    /*
     * Don't allow any load flags through for this!  We don't want
     * to mmap just for pointers.
     */
    ptrloadflags &= ~LOAD_FLAG_MUST_MMAP;
    ptrloadflags &= ~LOAD_FLAG_SHOULD_MMAP;

    while (SYMBOL_IST_PTR(datatype)) {
	if (((flags & LOAD_FLAG_AUTO_DEREF) && SYMBOL_IST_PTR(datatype))
	    || ((flags & LOAD_FLAG_AUTO_STRING) 
		&& SYMBOL_IST_PTR(datatype) 
		&& symbol_type_is_char(symbol_type_skip_ptrs(datatype)))) {
	    if (paddr == 0) {
		verror("failed to follow NULL pointer #%d\n",nptrs);
		errno = EFAULT;
		goto errout;
	    }

	    vdebug(5,LOG_T_SYMBOL,"loading ptr at 0x%"PRIxADDR"\n",paddr);

	    /*
	     * The pointer may be in another region!  We *have* to
	     * switch regions -- and thus the memrange for the value we
	     * return may not be in @addr's region/range!
	     */
	    if (!target_find_memory_real(target,addr,NULL,NULL,&range)) {
		verror("could not find range for ptr 0x%"PRIxADDR"\n",paddr);
		errno = EFAULT;
		goto errout;
	    }

	    if (!__target_load_addr_real(target,range,paddr,ptrloadflags,
					 (unsigned char *)&paddr,
					 target->ptrsize)) {
		verror("could not load ptr 0x%"PRIxADDR"\n",paddr);
		errno = EFAULT;
		goto errout;
	    }

	    ++nptrs;
	    vdebug(5,LOG_T_SYMBOL,"loaded next ptr value 0x%"PRIxADDR" (#%d)\n",
		   paddr,nptrs);

	    /* Skip past the pointer we just loaded. */
	    datatype = symbol_get_datatype(datatype);

	    /* Skip past any qualifiers! */
	    datatype = symbol_type_skip_qualifiers(datatype);
	}
	else {
	    break;
	}
    }

    if (range) {
	if (range_saveptr)
	    *range_saveptr = range;
	if (datatype_saveptr)
	    *datatype_saveptr = datatype;
    }

    errno = 0;
    return paddr;

 errout:
    return 0;
}

/*
 * Load a raw value (i.e., no symbol or type info) using an object
 * file-based location (i.e., a fixed object-relative address) and a
 * specific region.
 *
 * Note: you cannot mmap raw values; they must be copied from target memory.
 */
struct value *target_load_addr_obj(struct target *target,struct memregion *region,
				   ADDR obj_addr,load_flags_t flags,int len) {
    ADDR real;
    struct memrange *range;

    if (flags & LOAD_FLAG_MUST_MMAP) {
	errno = EINVAL;
	return NULL;
    }

    errno = 0;
    real = memregion_relocate(region,obj_addr,&range);
    if (errno)
	return NULL;

    return target_load_addr_real(target,real,flags,len);
}

/*
 * Load a raw value (i.e., no symbol or type info) using a real address.
 *
 * Note: you cannot mmap raw values; they must be copied from target memory.
 */
struct value *target_load_addr_real(struct target *target,ADDR addr,
				    load_flags_t flags,int len) {
    struct memrange *range;
    struct value *value;

    if (flags & LOAD_FLAG_MUST_MMAP) {
	errno = EINVAL;
	return NULL;
    }

    if (!target_find_memory_real(target,addr,NULL,NULL,&range)) {
	errno = EFAULT;
	return NULL;
    }

    if (!(value = value_create_raw(len))) {
	return NULL;
    }
    value->range = range;
    value->addr = addr;

    if (!__target_load_addr_real(target,range,addr,flags,
				 (unsigned char *)value->buf,value->bufsiz)) {
	value_free(value);
	return NULL;
    }

    return value;
}

unsigned char *target_load_raw_addr_real(struct target *target,ADDR addr,
					 load_flags_t flags,
					 unsigned char *buf,int bufsiz) {
    struct memrange *range;

    if (!target_find_memory_real(target,addr,NULL,NULL,&range)) {
	errno = EFAULT;
	return NULL;
    }

    return __target_load_addr_real(target,range,addr,flags,
				   (unsigned char *)buf,bufsiz);
}

unsigned char *__target_load_addr_real(struct target *target,
				       struct memrange *range,
				       ADDR addr,load_flags_t flags,
				       unsigned char *buf,int bufsiz) {
    if (!(flags & LOAD_FLAG_NO_CHECK_BOUNDS) 
	&& (!memrange_contains_real(range,addr)
	    || !memrange_contains_real(range,addr+bufsiz-1))) {
	errno = EFAULT;
	return NULL;
    }

    return target_read_addr(target,addr,bufsiz,buf,NULL);
}
