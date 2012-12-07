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
#include "probe.h"

#include <glib.h>

/**
 ** Globals.
 **/

/* These are the targets we know about. */
static GHashTable *target_tab = NULL;

static int init_done = 0;

void target_init(void) {
    if (init_done)
	return;

    dwdebug_init();

    target_tab = g_hash_table_new_full(g_str_hash,g_str_equal,NULL,NULL);

    init_done = 1;
}

void target_fini(void) {
    GHashTableIter iter;
    struct target *target;

    if (!init_done)
	return;

    g_hash_table_iter_init(&iter,target_tab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&target)) {
	target_close(target);
	target_free(target);
    }
    g_hash_table_destroy(target_tab);
    target_tab = NULL;

    dwdebug_fini();

    init_done = 0;
}

/**
 ** Target argp parsing stuff.  This loosely wraps argp.  The idea is
 ** that target library users want to write target-backend-independent
 ** programs that use the library.  So this function helps them
 ** automatically instantiate a target from standard options.
 **
 ** The reason we can't use exactly the argp style is because 1) child
 ** parsers cannot see arguments (and the Ptrace parser will eat quoted
 ** arguments (i.e., those following '--') if possible, so we want to
 ** make this work); 2) and because the top-level target argp parser
 ** will optionally only include the target backend argp children
 ** according to user choice (i.e., a program might only support ptrace,
 ** not xen) -- and we have to keep track of that state.
 **
 ** For these reasons, it ends up making more sense to use the driver
 ** program's argp parser as the top-level parser, and glue on our
 ** target argp child parsers -- but then to pass all parsers a 
 ** struct target_driver_argp_parser_state as the input.  Clients can
 ** retrieve their state via target_driver_argp_state().
 **/
error_t target_argp_parse_opt(int key,char *arg,struct argp_state *state);

struct argp_option target_argp_opts[] = {
    { "start-paused",'P',0,0,"Leave target paused after launch.",-3 },
    { "soft-breakpoints",'s',0,0,"Force software breakpoints.",-3 },
    { "debugfile-load-opts",'F',"LOAD-OPTS",0,"Add a set of debugfile load options.",-3 },
    { "breakpoint-mode",'L',"STRICT-LEVEL",0,"Set/increase the breakpoint mode level.",-3 },
    { 0,0,0,0,0,0 }
};

/*
 * The children this library will utilize.
 */
extern struct argp linux_userproc_argp;
extern char *linux_userproc_argp_header;
#ifdef ENABLE_XENACCESS
extern struct argp xen_vm_argp;
extern char *xen_vm_argp_header;
#endif

struct target_spec *target_argp_target_spec(struct argp_state *state) {
    if (!state)
	return NULL;

    return ((struct target_argp_parser_state *) \
	    state->input)->spec;
}
void *target_argp_driver_state(struct argp_state *state) {
    if (!state)
	return NULL;

    return ((struct target_argp_parser_state *) \
	    state->input)->driver_state;
}

struct target_spec *target_argp_driver_parse(struct argp *driver_parser,
					     void *driver_state,
					     int argc,char **argv,
					     target_type_t target_types,
					     int filter_quoted) {
    error_t retval;
    int i;
    struct target_argp_parser_state tstate;
    /*
     * These are our subparsers.  They are optional, so we have to build
     * them manually.
     */
    struct argp_child target_argp_children[3];
    /*
     * This is the "main" target arg parser, to be used if the caller
     * has no arguments.
     */
    struct argp target_argp = { 
	target_argp_opts,target_argp_parse_opt,
	NULL,NULL,target_argp_children,NULL,NULL
    };
    /*
     * This is the main child target arg parser, to be used if the
     * caller has its own arguments.
     */
    struct argp_child target_argp_child[] = {
	{ &target_argp,0,"Generic Target Options",0 },
	{ 0,0,0,0 },
    };

    if (!target_types) {
	return EINVAL;
    }

    memset(&tstate,0,sizeof(tstate));

    tstate.driver_state = driver_state;
    tstate.spec = target_build_spec(TARGET_TYPE_NONE,TARGET_MODE_NONE);

    if (filter_quoted) {
	for (i = 0; i < argc; ++i) {
	    if (strncmp("--",argv[i],2) == 0 && argv[i][2] == '\0') {
		argv[i] = NULL;
		if (++i < argc) {
		    tstate.quoted_start = i;
		    tstate.quoted_argc = argc - i;
		    tstate.quoted_argv = &argv[i];
		}
		argc = i - 1;
		break;
	    }
	}
    }

    tstate.num_children = 0;
    if (target_types & TARGET_TYPE_PTRACE) {
	target_argp_children[tstate.num_children].argp = &linux_userproc_argp;
	target_argp_children[tstate.num_children].flags = 0;
	target_argp_children[tstate.num_children].header = linux_userproc_argp_header;
	target_argp_children[tstate.num_children].group = 0;
	++tstate.num_children;
    }
#ifdef ENABLE_XENACCESS
    if (target_types & TARGET_TYPE_XEN) {
	target_argp_children[tstate.num_children].argp = &xen_vm_argp;
	target_argp_children[tstate.num_children].flags = 0;
	target_argp_children[tstate.num_children].header = xen_vm_argp_header;
	target_argp_children[tstate.num_children].group = 0;
	++tstate.num_children;
    }
#endif

    target_argp_children[tstate.num_children].argp = NULL;
    target_argp_children[tstate.num_children].flags = 0;
    target_argp_children[tstate.num_children].header = NULL;
    target_argp_children[tstate.num_children].group = 0;

    driver_parser->children = target_argp_child;

    retval = argp_parse(driver_parser,argc,argv,0,NULL,&tstate);

    if (retval) {
	if (tstate.spec && tstate.spec->backend_spec)
	    free(tstate.spec->backend_spec);
	if (tstate.spec)
	    free(tstate.spec);
	tstate.spec = NULL;
    }

    driver_parser->children = NULL;

    return tstate.spec;
}

void target_driver_argp_init_children(struct argp_state *state) {
    state->child_inputs[0] = state->input;
}

error_t target_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct target_argp_parser_state *tstate = \
	(struct target_argp_parser_state *)state->input;
    struct target_spec *spec = NULL;
    char *argcopy;
    struct debugfile_load_opts *opts;
    int i;

    if (tstate)
	spec = tstate->spec;

    switch (key) {
    case ARGP_KEY_ARG:
    case ARGP_KEY_ARGS:
	return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
	for (i = 0; i < tstate->num_children; ++i) 
	    state->child_inputs[i] = tstate;
	break;
    case ARGP_KEY_END:
    case ARGP_KEY_NO_ARGS:
    case ARGP_KEY_SUCCESS:
    case ARGP_KEY_ERROR:
	return 0;
    case ARGP_KEY_FINI:
	/*
	 * Check for at least *something*.
	 */
	if (spec && spec->target_type == TARGET_TYPE_NONE) {
	    verror("you must specify at least one kind of target!\n");
	    return EINVAL;
	}
	return 0;
    case 's':
	spec->style = PROBEPOINT_SW;
	break;
    case 'F':
	argcopy = strdup(arg);

	opts = debugfile_load_opts_parse(argcopy);

	if (!opts) {
	    verror("bad debugfile_load_opts '%s'!\n",argcopy);
	    free(argcopy);
	    for (i = 0; i < array_list_len(spec->debugfile_load_opts_list); ++i)
		debugfile_load_opts_free((struct debugfile_load_opts *) \
					 array_list_item(spec->debugfile_load_opts_list,i));
	    array_list_free(spec->debugfile_load_opts_list);
	    spec->debugfile_load_opts_list = NULL;

	    return EINVAL;
	}
	else {
	    if (!spec->debugfile_load_opts_list) 
		spec->debugfile_load_opts_list = array_list_create(4);
	    array_list_append(spec->debugfile_load_opts_list,opts);
	    break;
	}
    case 'L':
	++spec->bpmode;
	break;

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

/*
 * A utility function that loads a debugfile with the given opts.
 */
int target_associate_debugfile(struct target *target,
			       struct memregion *region,
			       struct debugfile *debugfile) {

    /* if they already loaded this debugfile into this region, error */
    if (g_hash_table_lookup(region->debugfiles,debugfile->idstr)) {
	verror("debugfile(%s) already in use in region(%s) in space (%s)!\n",
	       debugfile->idstr,region->name,region->space->idstr);
	errno = EBUSY;
	return -1;
    }

    RHOLD(debugfile);

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
	    bsymbol = bsymbol_create(lsymbol,region);
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
				  const char *name,const char *delim,
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
    bsymbol = bsymbol_create(lsymbol,region);
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
					 const char *name,const char *delim) {
    struct bsymbol *bsymbol_new;
    struct lsymbol *lsymbol;

    lsymbol = lsymbol_lookup_member(bsymbol->lsymbol,name,delim);
    if (!lsymbol)
	return NULL;

    bsymbol_new = bsymbol_create(lsymbol,bsymbol->region);
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
    bsymbol = bsymbol_create(lsymbol,region);
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
 *
 * @return 1 if the location is an address; 2 if the location is a
 * register; or nonzero on error.
 *
 * If an address and @addr_saveptr is set, the address is placed in
 * @addr_saveptr.  If in a register and @reg_saveptr is set, the
 * register number is placed in @reg_saveptr.
 */
int __target_lsymbol_compute_location(struct target *target,tid_t tid,
				      struct lsymbol *lsymbol,
				      ADDR addr,struct memregion *region,
				      load_flags_t flags,
				      REG *reg_saveptr,ADDR *addr_saveptr,
				      struct symbol **final_type_saveptr,
				      struct memrange **range_saveptr) {
    ADDR retval = addr;
    struct symbol *symbol;
    struct symbol *datatype;
    struct array_list *symbol_chain;
    int alen;
    int i;
    int rc;
    OFFSET offset;
    struct memregion *current_region = region;
    struct memrange *current_range;
    load_flags_t tflags = flags | LOAD_FLAG_AUTO_DEREF;
    struct array_list *tchain = NULL;
    struct symbol *tdatatype;
    REG reg;
    int in_reg = 0;

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
	if ((rc = location_resolve_lsymbol_base(target,tid,lsymbol,current_region,
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
     * If the final symbol on the chain is in a register, we skip
     * immediately to handling it; there is no need to handle anything
     * prior to it.
     */
    else if (SYMBOL_IS_FULL_VAR(symbol) 
	     && LOCATION_IN_REG(&symbol->s.ii->d.v.l)) {
	i = alen - 1;
    }
    else {
	i = 0;
    }


    /*
     * We maintain a "slice" of the lsymbol chain, because we only want
     * to pass the subset of it that is our current value of i -- the
     * part of the list we have traversed.
     */
    tchain = array_list_clone(symbol_chain,i);

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
	in_reg = 0;
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
		goto check_pointer;
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
	    vdebug(9,LOG_T_SYMBOL,
		   "member %s at offset 0x%"PRIxOFFSET"; addr 0x%"PRIxADDR"\n",
		   symbol_get_name(symbol),offset,retval);
	}
	/* Otherwise, we actually need to resolve its location based on
	 * the info in the symbol.
	 */
	else {
	    rc = location_resolve(target,tid,current_region,&symbol->s.ii->d.v.l,
				  tchain,&reg,&retval,&current_range);
	    if (rc == 2) {
		in_reg = 1;
		/* See below inside the pointer check where we will try
		 * to load the pointer across this register.
		 */
	    }
	    else if (rc == 1) {
		current_region = current_range->region;
		vdebug(9,LOG_T_SYMBOL,"var %s at 0x%"PRIxADDR"\n",
		       symbol_get_name(symbol),retval);
	    }
	    else {
		verror("could not resolve location for symbol %s: %s!\n",
		       symbol_get_name(symbol),strerror(errno));
		goto errout;
	    }
	}

	/*
	 * If the symbol is a pointer, load it now.  If this is the
	 * final symbol in the chain, and flags & AUTO_DEREF, also load
	 * the final pointer(s), and return the value.  Otherwise, just
	 * return the address of the final pointer.
	 */
    check_pointer:
	if (SYMBOL_IST_PTR(datatype)) {
	    if (i < alen 
		|| (i == alen 
		    && (flags & LOAD_FLAG_AUTO_DEREF
			|| (flags & LOAD_FLAG_AUTO_STRING
			    && symbol_type_is_char(symbol_type_skip_ptrs(datatype)))))) {

		if (in_reg) {
		    /* Try to load the ptr value from a register; might or
		     * might not be an address; only is if the current
		     * symbol was a pointer; we handle that below.  There's
		     * a termination condition below this loop that if we
		     * end after having resolved the location to a register,
		     * we can't calculate the address for it.
		     */
		    retval = target_read_reg(target,tid,reg);
		    if (errno) {
			verror("could not read reg %"PRIiREG" that ptr symbol %s"
			       " resolved to: %s!\n",
			       reg,symbol->name,strerror(errno));
			goto errout;
		    }

		    /* We might have changed ranges... */
		    target_find_memory_real(target,retval,NULL,NULL,
					    &current_range);
		    current_region = current_range->region;
		    vdebug(9,LOG_T_SYMBOL,"ptr var (in reg) %s at 0x%"PRIxADDR"\n",
			   symbol_get_name(symbol),retval);

		    /* We have to skip one pointer type */
		    datatype = symbol_type_skip_qualifiers(datatype->datatype);

		    /* Clear the in_reg bit, since we were able to
		     * autoload the pointer!
		     */
		    in_reg = 0;

		    vdebug(9,LOG_T_SYMBOL,
			   "autoloaded REG (%d) pointer(s) for var %s ="
			   " 0x%"PRIxADDR"\n",
			   reg,symbol_get_name(symbol),retval);

		    /* Do we need to keep trying to load through the pointer? */
		    if (SYMBOL_IST_PTR(datatype))
			goto check_pointer;
		}
		else {
		    retval = target_autoload_pointers(target,datatype,retval,
						      tflags,&datatype,
						      &current_range);
		    if (errno) {
			verror("could not load pointer for symbol %s\n",
			       symbol_get_name(symbol));
			goto errout;
		    }
		    current_region = current_range->region;

		    vdebug(9,LOG_T_SYMBOL,
			   "autoloaded pointer(s) for var %s = 0x%"PRIxADDR"\n",
			   symbol_get_name(symbol),retval);
		}
	    }

	    /*
	    if (i == alen) {
		if (in_reg) {
		    verror("last symbol %s was in a register; cannot compute addr!\n",
			   symbol_get_name(symbol));
		    errno = EINVAL;
		    goto errout;
		}
		goto out;
	    }
	    */
	}

	if (i >= alen) {
	    /*
	    if (in_reg
		&& (SYMBOL_IST_PTR(datatype)
		    && !(flags & LOAD_FLAG_AUTO_DEREF)
		    && !(flags & LOAD_FLAG_AUTO_STRING
			 && symbol_type_is_char(symbol_type_skip_ptrs(datatype))))) {
		verror("last symbol (ptr) %s was in a register and auto deref"
		       " not set; cannot compute addr!\n",
		       symbol_get_name(symbol));
		errno = EINVAL;
		goto errout;
	    }
	    */
	    goto out;
	}
    }

 errout:
    array_list_free(tchain);
    return -1;

 out:
    array_list_free(tchain);

    if (final_type_saveptr)
	*final_type_saveptr = datatype;

    if (in_reg) {
	if (reg_saveptr)
	    *reg_saveptr = reg;
	return 2;
    }
    else {
	if (range_saveptr)
	    *range_saveptr = current_range;
	if (addr_saveptr)
	    *addr_saveptr = retval;
	return 1;
    }

    return 0;
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
int __target_bsymbol_compute_location(struct target *target,tid_t tid,
				      struct bsymbol *bsymbol,
				      load_flags_t flags,
				      REG *reg_saveptr,ADDR *addr_saveptr,
				      struct symbol **final_type_saveptr,
				      struct memrange **range_saveptr) {
    return __target_lsymbol_compute_location(target,tid,bsymbol->lsymbol,
					     0,bsymbol->region,flags,
					     reg_saveptr,addr_saveptr,
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
    struct mmap_entry *mmap;
    char *offset_buf;

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
	value = value_create_noalloc(NULL,range,NULL,datatype);

	if (!(value->buf = (char *)__target_load_addr_real(target,range,
							   ptraddr,flags,
							   NULL,0))) {
	    verror("failed to autoload char * for type %s at addr 0x%"PRIxADDR"\n",
		   symbol_get_name(type),addr);
	    goto errout;
	}
	value_set_strlen(value,strlen(value->buf) + 1);
	value_set_addr(value,ptraddr);

	vdebug(5,LOG_T_SYMBOL,"autoloaded char * with len %d\n",value->bufsiz);

	/* success! */
	goto out;
    }
    else if (flags & LOAD_FLAG_MUST_MMAP || flags & LOAD_FLAG_SHOULD_MMAP) {
	ptrloc.loctype = LOCTYPE_REALADDR;
	ptrloc.l.addr = ptraddr != addr ? ptraddr : addr;

	mmap = location_mmap(target,region,&ptrloc,
			     flags,&offset_buf,NULL,&range);
	value = value_create_noalloc(NULL,range,NULL,datatype);
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

	    if (!__target_load_addr_real(target,range,ptrloc.l.addr,flags,
					 (unsigned char *)value->buf,
					 value->bufsiz)) 
		goto errout;

	    value_set_addr(value,ptrloc.l.addr);
	}
	else {
	    value_set_mmap(value,ptrloc.l.addr,mmap,offset_buf);
	}

	/* success! */
	goto out;
    }
    else {
	value = value_create_type(NULL,range,datatype);
	if (!value) {
	    verror("could not create value for type (ptr is %p) %s\n",
		   datatype,datatype ? datatype->name : NULL);
	    goto errout;
	}

	if (!__target_load_addr_real(target,range,ptraddr,flags,
				     (unsigned char *)value->buf,
				     value->bufsiz))
	    goto errout;


	value_set_addr(value,ptraddr);
    }

 out:
    return value;

 errout:
    if (value)
	value_free(value);

    return NULL;

}

struct value *target_load_symbol_member(struct target *target,tid_t tid,
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

    retval = target_load_symbol(target,tid,bmember,flags);

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
    char *rbuf = NULL;
    ADDR addr;
    struct target_thread *tthread = old_value->thread;
    tid_t tid = tthread->tid;
    int rc;
    REG reg;
    REGVAL regval;

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
	addr = old_value->res.addr;

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
    if (ls->symbol->s.ii->d.v.l.loctype != LOCTYPE_MEMBER_OFFSET) {
	verror("loctype for symbol %s is %s, not MEMBER_OFFSET!\n",
	       symbol_get_name(ls->symbol),
	       LOCTYPE(ls->symbol->s.ii->d.v.l.loctype));
	errno = EINVAL;
	goto errout;
    }
    mdatatype = symbol_type_skip_qualifiers(ls->symbol->datatype);

    symbol = ls->symbol;

    /*
     * Compute either an address or register location, and load!
     */

    rc = __target_lsymbol_compute_location(target,tid,ls,addr,
					   old_value->range->region,flags,
					   &reg,&addr,&datatype,&range);
    if (rc < 0) {
	verror("failed to compute location for var %s\n",
	       symbol_get_name(symbol));
	goto errout;
    }
    else if (rc == 1) {
	/*
	 * If __target_lsymbol_compute_address_at returns an address
	 * entirely contained inside of value->buf, we can just clone
	 * the value from within the old value.  Otherwise, we have to
	 * load it from the final address.
	 */
	if (addr >= old_value->res.addr 
	    && (addr - old_value->res.addr) < (unsigned)old_value->bufsiz) {
	    value = value_create_noalloc(tthread,range,ls,datatype);
	    value_set_child(value,old_value,addr);

	    goto out;
	}

	tdatatype = symbol_type_skip_qualifiers(symbol->datatype);
	if (flags & LOAD_FLAG_AUTO_STRING
	    && SYMBOL_IST_PTR(tdatatype) 
	    && symbol_type_is_char(symbol_type_skip_ptrs(tdatatype))) {
	    datatype = symbol_type_skip_ptrs(tdatatype);
	    /* XXX: should we use datatype, or the last pointer to datatype? */
	    value = value_create_noalloc(tthread,range,ls,datatype);

	    if (!(value->buf = (char *)__target_load_addr_real(target,range,
							       addr,flags,
							       NULL,0))) {
		vwarn("failed to autostring char pointer for symbol %s\n",
		      symbol_get_name(symbol));
		value_free(value);
		value = NULL;
		goto errout;
	    }
	    value_set_strlen(value,strlen(value->buf) + 1);
	    value_set_addr(value,addr);

	    vdebug(5,LOG_T_SYMBOL,"autoloaded char * value with len %d\n",
		   value->bufsiz);
	}
	else {
	    value = value_create(tthread,range,ls,datatype);

	    if (!__target_load_addr_real(target,range,addr,flags,
					 (unsigned char *)value->buf,
					 value->bufsiz)) {
		verror("failed to load value at 0x%"PRIxADDR"\n",addr);
		value_free(value);
		value = NULL;
		goto errout;
	    }
	    else {
		value_set_addr(value,addr);

		vdebug(5,LOG_T_SYMBOL,"loaded value with len %d\n",
		       value->bufsiz);
	    }
	}
    }
    else if (rc == 2) {
	if (flags & LOAD_FLAG_MUST_MMAP) {
	    verror("cannot mmap register value for var %s!\n",
		   symbol_get_name(symbol));
	    errno = EINVAL;
	    goto errout;
	}

        regval = target_read_reg(target,tid,reg);
        if (errno) {
	    verror("could not read reg %d value in tid %"PRIiTID"\n",reg,tid);
            goto errout;
	}

	datatype = symbol_type_skip_qualifiers(symbol->datatype);
	rbuf = malloc(symbol_bytesize(datatype));

        if (target->wordsize == 4 && __WORDSIZE == 64) {
            /* If the target is 32-bit on 64-bit host, we have to grab
             * the lower 32 bits of the regval.
             */
            memcpy(rbuf,((int32_t *)&regval),symbol_bytesize(datatype));
        }
	else if (__WORDSIZE == 32)
	    memcpy(rbuf,&regval,(symbol_bytesize(datatype) < 4) \
		   ? symbol_bytesize(datatype) : 4);
        else
            memcpy(rbuf,&regval,symbol_bytesize(datatype));

	/* Just create the value based on the register value. */
	value = value_create_noalloc(tthread,NULL,ls,datatype);
	value->buf = rbuf;
	value->bufsiz = symbol_bytesize(datatype);

	value_set_reg(value,symbol->s.ii->d.v.l.l.reg);
    }
    else {
	verror("computed location not register nor address (%d) -- BUG!\n",rc);
	errno = EINVAL;
	goto errout;
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

struct value *target_load_symbol(struct target *target,tid_t tid,
				 struct bsymbol *bsymbol,load_flags_t flags) {
    ADDR addr;
    REG reg;
    struct symbol *symbol;
    struct symbol *datatype;
    struct memregion *region = bsymbol->region;
    struct memrange *range;
    struct value *value = NULL;
    REGVAL regval;
    char *rbuf;
    struct symbol *tdatatype;
    struct target_thread *tthread;
    struct array_list *symbol_chain;
    int alen;
    int rc;
    struct lsymbol *ii_lsymbol;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	errno = EINVAL;
	verror("could not lookup thread %"PRIiTID"; forgot to load?\n",tid);
	return NULL;
    }

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
     * If this is an inlined symbol that has no location info, and it
     * only has one inline instance, try to autoload the inlined instance!!
     */
    if (SYMBOL_IS_FULL_VAR(symbol)
	&& symbol->s.ii->d.v.l.loctype == LOCTYPE_UNKNOWN
	&& array_list_len(symbol->s.ii->inline_instances) == 1) {
	ii_lsymbol = lsymbol_create_from_symbol((struct symbol *) \
						array_list_item(symbol->s.ii->inline_instances,0));

	if (ii_lsymbol) {
	    vwarn("trying to load inlined symbol %s with no location info;"
		  " found sole instance %s; will try to load that.\n",
		  symbol_get_name(symbol),symbol_get_name(ii_lsymbol->symbol));
	    bsymbol = bsymbol_create(ii_lsymbol,bsymbol->region);
	    
	    symbol_chain = bsymbol->lsymbol->chain;
	    alen = array_list_len(symbol_chain);
	    symbol = (struct symbol *)array_list_item(symbol_chain,alen - 1);
	}
	else {
	    vwarn("trying to load inlined symbol %s with no location info;"
		  " could not find instance; will fail!\n",
		  symbol_get_name(symbol));
	}
    }

    /*
     * Compute the symbol's location (reg or addr) and load that!
     */
    rc = __target_bsymbol_compute_location(target,tid,bsymbol,flags,
					   &reg,&addr,&datatype,&range);
    if (rc < 0) {
	verror("failed to compute location for var %s\n",
	       symbol_get_name(symbol));
	goto errout;
    }
    else if (rc == 1) {
	tdatatype = symbol_type_skip_qualifiers(symbol->datatype);
	if (flags & LOAD_FLAG_AUTO_STRING
	    && SYMBOL_IST_PTR(tdatatype) 
	    && symbol_type_is_char(symbol_type_skip_ptrs(tdatatype))) {
	    datatype = symbol_type_skip_ptrs(tdatatype);
	    /* XXX: should we use datatype, or the last pointer to datatype? */
	    value = value_create_noalloc(tthread,range,bsymbol->lsymbol,datatype);

	    if (!(value->buf = (char *)__target_load_addr_real(target,range,
							       addr,flags,
							       NULL,0))) {
		vwarn("failed to autostring char pointer for symbol %s\n",
		      symbol_get_name(symbol));
		value_free(value);
		value = NULL;
		goto errout;
	    }
	    value_set_strlen(value,strlen(value->buf) + 1);
	    value_set_addr(value,addr);

	    vdebug(5,LOG_T_SYMBOL,"autoloaded char * value with len %d\n",
		   value->bufsiz);
	}
	else {
	    value = value_create(tthread,range,bsymbol->lsymbol,datatype);

	    if (!__target_load_addr_real(target,range,addr,flags,
					 (unsigned char *)value->buf,
					 value->bufsiz)) {
		verror("failed to load value at 0x%"PRIxADDR"\n",addr);
		value_free(value);
		value = NULL;
		goto out;
	    }
	    else {
		value_set_addr(value,addr);

		vdebug(5,LOG_T_SYMBOL,"loaded value with len %d\n",
		       value->bufsiz);
	    }
	}
    }
    else if (rc == 2) {
	if (flags & LOAD_FLAG_MUST_MMAP) {
	    verror("cannot mmap register value for var %s!\n",
		   symbol_get_name(symbol));
	    errno = EINVAL;
	    goto errout;
	}

        regval = target_read_reg(target,tid,reg);
        if (errno) {
	    verror("could not read reg %d value in tid %"PRIiTID"\n",reg,tid);
            goto errout;
	}

	datatype = symbol_type_skip_qualifiers(symbol->datatype);
	rbuf = malloc(symbol_bytesize(datatype));

        if (target->wordsize == 4 && __WORDSIZE == 64) {
            /* If the target is 32-bit on 64-bit host, we have to grab
             * the lower 32 bits of the regval.
             */
            memcpy(rbuf,((int32_t *)&regval),symbol_bytesize(datatype));
        }
	else if (__WORDSIZE == 32)
	    memcpy(rbuf,&regval,(symbol_bytesize(datatype) < 4) \
		                 ? symbol_bytesize(datatype) : 4);
        else
            memcpy(rbuf,&regval,symbol_bytesize(datatype));

	/* Just create the value based on the register value. */
	value = value_create_noalloc(tthread,NULL,bsymbol->lsymbol,datatype);
	value->buf = rbuf;
	value->bufsiz = symbol_bytesize(datatype);

	value_set_reg(value,symbol->s.ii->d.v.l.l.reg);
    }
    else {
	verror("computed location not register nor address (%d) -- BUG!\n",rc);
	errno = EINVAL;
	goto errout;
    }

 out:
    return value;

 errout:
    if (value)
	value_free(value);
    return NULL;
}

int target_resolve_symbol_base(struct target *target,tid_t tid,
			       struct bsymbol *bsymbol,ADDR *addr_saveptr,
			       struct memrange **range_saveptr) {
    return location_resolve_lsymbol_base(target,tid,bsymbol->lsymbol,
					 bsymbol->region,addr_saveptr,
					 range_saveptr);
}

/*
 * What we do here is traverse @bsymbol's lsymbol chain.  For each var
 * we encounter, try to resolve its address.  If the chain is
 * interrupted by pointers, load those and continue loading any
 * subsequent variables.
 */
ADDR target_addressof_symbol(struct target *target,tid_t tid,
			     struct bsymbol *bsymbol,load_flags_t flags,
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
    struct memrange *current_range;
    load_flags_t tflags = flags | LOAD_FLAG_AUTO_DEREF;
    struct array_list *tchain = NULL;
    REG reg;
    int in_reg;

    symbol_chain = bsymbol->lsymbol->chain;
    alen = array_list_len(symbol_chain);
    symbol = (struct symbol *)array_list_item(symbol_chain,alen - 1);

    /* 
     * If the last symbol is a function, we only want to return its
     * base address.  So do that.
     */
    if (i == alen && SYMBOL_IS_FULL_FUNCTION(symbol)) {
	if ((rc = location_resolve_symbol_base(target,tid,bsymbol,
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
	in_reg = 0;
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
	    offset = location_resolve_offset(&symbol->s.ii->d.v.l,
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
	    rc = location_resolve(target,tid,current_region,&symbol->s.ii->d.v.l,
				  tchain,&reg,&retval,&current_range);
	    if (rc == 2) {
		/* Try to load some value from a register; might or
		 * might not be an address; only is if the current
		 * symbol was a pointer; we handle that below.  There's
		 * a termination condition below this loop that if we
		 * end after having resolved the location to a register,
		 * we can't calculate the address for it.
		 */
		in_reg = 1;
		if (SYMBOL_IST_PTR(datatype)) {
		    retval = target_read_reg(target,tid,reg);
		    if (errno) {
			verror("could not read reg %"PRIiREG" that ptr symbol %s"
			       " resolved to: %s!\n",
			       reg,symbol->name,strerror(errno));
			goto errout;
		    }

		    /* We might have changed ranges... */
		    target_find_memory_real(target,retval,NULL,NULL,
					    &current_range);
		    current_region = current_range->region;
		    vdebug(5,LOG_T_SYMBOL,"ptr var (in reg) %s at 0x%"PRIxADDR"\n",
			   symbol_get_name(symbol),retval);
		    /* We have to skip one pointer type */
		    datatype = symbol_type_skip_qualifiers(datatype->datatype);

		    goto check_pointer;
		}
		else {
		    /*
		     * Not sure how this could happen...
		     */
		    verror("could not handle non-ptr symbol %s being in a reg!\n",
			   symbol->name);
		    errno = EINVAL;
		    goto errout;
		}
	    }
	    else if (rc == 1) {
		current_region = current_range->region;
		vdebug(5,LOG_T_SYMBOL,"var %s at 0x%"PRIxADDR"\n",
		       symbol_get_name(symbol),retval);
	    }
	    else {
		verror("could not resolve location for symbol %s: %s!\n",
		       symbol_get_name(symbol),strerror(errno));
		goto errout;
	    }
	}

	/*
	 * If the symbol is a pointer, load it now.  If this is the
	 * final symbol in the chain, and flags & AUTO_DEREF, also load
	 * the final pointer(s), and return the value.  Otherwise, just
	 * return the address of the final pointer.
	 */
    check_pointer:
	if (SYMBOL_IST_PTR(datatype)) {
	    if (i < alen 
		|| (i == alen && (flags & LOAD_FLAG_AUTO_DEREF
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
	}

	if (i >= alen) {
	    if (in_reg
		&& (SYMBOL_IST_PTR(datatype)
		    && !(flags & LOAD_FLAG_AUTO_DEREF)
		    && !(flags & LOAD_FLAG_AUTO_STRING
			 && symbol_type_is_char(symbol_type_skip_ptrs(datatype))))) {
		verror("last symbol (ptr) %s was in a register and auto deref"
		       " not set; cannot compute addr!\n",
		       symbol_get_name(symbol));
		errno = EINVAL;
		goto errout;
	    }
	    goto out;
	}
    }

 errout:
    retval = 0;

 out:
    array_list_free(tchain);
    if (range_saveptr)
	*range_saveptr = current_range;
    return retval;
}

/*
 * This is deprecated; just keeping code around in case.
 */
#if 0
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
	    ip_addr = (ADDR)target_read_reg(target,TID_GLOBAL,target->ipregno);
	else if (sizeof(ADDR) < sizeof(REGVAL)) {
	    ip = target_read_reg(target,TID_GLOBAL,target->ipregno);
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
	value->res.addr = ptraddr;

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

	value->res.addr = finaladdr;

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

	value->res.addr = finaladdr;
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
#endif

int target_store_value(struct target *target,struct value *value) {
    /* mmap'd values were stored whenever they were value_update_*'d */
    if (value->ismmap)
	return 0;
    else if (value->isreg) {
	return target_write_reg(target,value->thread->tid,value->res.reg,
				*(REGVAL *)value->buf);
    }
    else if (target_write_addr(target,value->res.addr,
			       (unsigned long)value->bufsiz,
			       (unsigned char *)value->buf)
	     != (unsigned long)value->bufsiz) {
	return -1;
    }

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

ADDR target_load_pointers(struct target *target,ADDR addr,int count,
			  struct memrange **range_saveptr) {
    ADDR paddr = addr;
    struct memrange *range = NULL;
    int i;

    for (i = 0; i < count; ++i ) {
	if (paddr == 0) {
	    verror("failed to follow NULL pointer #%d\n",i);
	    errno = EFAULT;
	    goto errout;
	}

	vdebug(5,LOG_T_SYMBOL,"loading ptr #%d at 0x%"PRIxADDR"\n",i,paddr);

	/*
	 * The pointer may be in another region!  We *have* to
	 * switch regions -- and thus the memrange for the value we
	 * return may not be in @addr's region/range!
	 */
	if (!target_find_memory_real(target,paddr,NULL,NULL,&range)) {
	    verror("could not find range for ptr 0x%"PRIxADDR"\n",paddr);
	    errno = EFAULT;
	    goto errout;
	}

	if (!__target_load_addr_real(target,range,paddr,LOAD_FLAG_NONE,
				     (unsigned char *)&paddr,target->ptrsize)) {
	    verror("could not load ptr #%d at 0x%"PRIxADDR"\n",i,paddr);
	    errno = EFAULT;
	    goto errout;
	}

	vdebug(5,LOG_T_SYMBOL,"loaded next ptr value 0x%"PRIxADDR" (#%d)\n",
	       paddr,i);
    }

    if (i == count && range) {
	if (range_saveptr)
	    *range_saveptr = range;
    }

    errno = 0;
    return paddr;

 errout:
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
	    if (!target_find_memory_real(target,paddr,NULL,NULL,&range)) {
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

    if (!(value = value_create_raw(target,NULL,range,len))) {
	return NULL;
    }

    if (!__target_load_addr_real(target,range,addr,flags,
				 (unsigned char *)value->buf,value->bufsiz)) {
	value_free(value);
	return NULL;
    }

    value_set_addr(value,addr);

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

    return target_read_addr(target,addr,bufsiz,buf);
}

int target_lookup_safe_disasm_range(struct target *target,ADDR addr,
				    ADDR *start,ADDR *end,void **data) {
    struct addrspace *space;
    struct memregion *region;
    GHashTableIter iter;
    gpointer key;
    struct debugfile *debugfile;
    struct memrange *range = NULL;

    struct clf_range_data *crd;

    /* Find which region contains this address. */
    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if ((range = memregion_find_range_real(region,addr)))
		break;
	}
    }

    if (!range) 
	return -1;

    g_hash_table_iter_init(&iter,region->debugfiles);
    while (g_hash_table_iter_next(&iter,
				  (gpointer)&key,(gpointer)&debugfile)) {
	if ((crd = clrange_find_loosest(&debugfile->elf_ranges,
					memrange_unrelocate(range,addr),
					NULL))) {
	    if (start)
		*start = crd->start;
	    if (end)
		*end = crd->end;
	    if (data)
		*data = crd->data;

	    return 0;
	}
    }

    return -1;
}

int target_lookup_next_safe_disasm_range(struct target *target,ADDR addr,
					 ADDR *start,ADDR *end,void **data) {
    struct addrspace *space;
    struct memregion *region;
    GHashTableIter iter;
    gpointer key;
    struct debugfile *debugfile;
    struct memrange *range = NULL;

    struct clf_range_data *crd;

    /* Find which region contains this address. */
    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if ((range = memregion_find_range_real(region,addr)))
		break;
	}
    }

    if (!range)
	return -1;

    g_hash_table_iter_init(&iter,region->debugfiles);
    while (g_hash_table_iter_next(&iter,
				  (gpointer)&key,(gpointer)&debugfile)) {
	if ((crd = clrange_find_next_loosest(&debugfile->elf_ranges,
					     memrange_unrelocate(range,addr),
					     NULL))) {
	    if (start)
		*start = crd->start;
	    if (end)
		*end = crd->end;
	    if (data)
		*data = crd->data;

	    return 0;
	}
    }

    return -1;
}

/*
 * CODE_CACHE_BUF_PAD -- distorm seems to have an off by one error decoding at
 * the end of a buffer supplied to it -- so we always pad our buffers we
 * pass to it with this many NUL bytes.
 */
#define CODE_CACHE_BUF_PAD 5

struct code_cache_entry {
    Word_t start;
    unsigned int len:31,
	         isevictable:1;
    unsigned char *code;
};

unsigned char *target_load_code(struct target *target,
				ADDR start,unsigned int len,
				int nocache,int force_copy,int *caller_free) {
    unsigned char *buf = NULL;
    unsigned int llen = 0;
    struct code_cache_entry *ccd;
    ADDR nextaddr;
    ADDR cstart,cend;
    unsigned int tlen;
    unsigned char *tbuf;

    nextaddr = start;

    if (force_copy) 
	buf = calloc(1,len + CODE_CACHE_BUF_PAD);

    while (llen < len) {
	/*
	 * Check the cache first.  If we find a hit, maybe we can fill
	 * up at least part of our return buffer -- OR maybe even just
	 * return a pointer.
	 */
    checkcache:
	ccd = (struct code_cache_entry *)clrange_find(&target->code_ranges,
						      nextaddr);
	if (ccd) {
	    /* At least some of the code in this cache entry is
	     * relevant; either plop it into our current buf; return a
	     * pointer to it, or an offset of it.
	     */

	    /* If we don't have a buf (i.e., not forcing a copy, and
	     * have not needed a buf because we're not needing to load
	     * multiple segments), and if the code we need is entirely
	     * in this buf, then just return a pointer to the right
	     * place in this buf!
	     */
	    if (!buf && (nextaddr + len) <= (ccd->start + ccd->len)) {
		*caller_free = 0;
		return ccd->code + (nextaddr - ccd->start);
	    }
	    /* Otherwise, we have a buf (or we *must* create one because
	     * we are loading more code than is in this one cache entry)
	     * and we need to copy (at least some) of the data in this
	     * cache entry into it.
	     */
	    else {
		if (!buf) 
		    buf = calloc(1,len + CODE_CACHE_BUF_PAD);

		tlen = ccd->len - (nextaddr - ccd->start);
		if ((len - llen) < tlen)
		    tlen = len - llen;

		memcpy(buf + llen,ccd->code + (nextaddr - ccd->start),tlen);
		llen += tlen;
	    }
	}
	else {
	    /* If it's not in the cache, we need to load the next safe
	     * disasm chunk --- OR FILL IN THE HOLE THAT CONTAINS
	     * nextaddr.
	     */
	    if (target_lookup_safe_disasm_range(target,nextaddr,&cstart,&cend,
						NULL)) {
		verror("no safe disasm range contains 0x%"PRIxADDR"!\n",nextaddr);
		goto errout;
	    }

	    tbuf = target_load_raw_addr_real(target,cstart,
					     LOAD_FLAG_NONE,NULL,cend - cstart);
	    if (!tbuf) {
		verror("could not load code in safe disasm range" 
		       " 0x%"PRIxADDR",0x%"PRIxADDR"!\n",cstart,cend);
		goto errout;
	    }

	    /* Save it in the cache! */
	    ccd = (struct code_cache_entry *)calloc(1,sizeof(*ccd));
	    ccd->start = cstart;
	    ccd->len = cend - cstart;
	    ccd->code = tbuf;

	    clrange_add(&target->code_ranges,cstart,cend,ccd);

	    /* Just hop back to the top of the loop and let the cache
	     * check succeed this time!
	     */
	    goto checkcache;
	}
    }

    if (caller_free)
	*caller_free = 1;
    return buf;

 errout:
    if (buf)
	free(buf);
    return NULL;
    
}

struct target_thread *target_lookup_thread(struct target *target,tid_t tid) {
    vdebug(16,LOG_T_THREAD,"thread %"PRIiTID"\n",tid);
    return (struct target_thread *)g_hash_table_lookup(target->threads,
						       (gpointer)(ptr_t)tid);
}

struct target_thread *target_create_thread(struct target *target,tid_t tid,
					   void *tstate) {
    struct target_thread *t = (struct target_thread *)calloc(1,sizeof(*t));

    vdebug(3,LOG_T_THREAD,"thread %"PRIiTID"\n",tid);

    t->target = target;
    t->tid = tid;
    t->state = tstate;

    t->hard_probepoints = g_hash_table_new(g_direct_hash,g_direct_equal);
    t->probes = g_hash_table_new(g_direct_hash,g_direct_equal);
    t->autofree_probes = g_hash_table_new(g_direct_hash,g_direct_equal);

    t->tpc = NULL;
    t->tpc_stack = array_list_create(4);
    INIT_LIST_HEAD(&t->ss_actions);

    g_hash_table_insert(target->threads,(gpointer)(ptr_t)tid,t);

    return t;
}

void target_reuse_thread_as_global(struct target *target,
				   struct target_thread *thread) {
    vdebug(3,LOG_T_THREAD,"thread %"PRIiTID" as global %"PRIiTID"\n",
	   thread->tid,TID_GLOBAL);
    g_hash_table_insert(target->threads,(gpointer)TID_GLOBAL,thread);
    target->global_thread = thread;
}

void target_delete_thread(struct target *target,struct target_thread *tthread,
			  int nohashdelete) {
    GHashTableIter iter;
    gpointer key;
    struct probepoint *probepoint;
    struct thread_action_context *tac,*ttac;

    vdebug(3,LOG_T_THREAD,"thread %"PRIiTID"\n",tthread->tid);

    /* We have to free the probepoints manually, then remove all.  We
     * can't remove an element during an iteration, but we *can* free
     * the data :).
     */
    g_hash_table_iter_init(&iter,tthread->hard_probepoints);
    while (g_hash_table_iter_next(&iter,
				  (gpointer)&key,(gpointer)&probepoint)) {
	probepoint_free_ext(probepoint);
    }

    g_hash_table_destroy(tthread->hard_probepoints);
    g_hash_table_destroy(tthread->probes);
    g_hash_table_destroy(tthread->autofree_probes);

    array_list_free(tthread->tpc_stack);

    if (!list_empty(&tthread->ss_actions)) {
	list_for_each_entry_safe(tac,ttac,&tthread->ss_actions,tac) {
	    action_free(tac->action,0);
	    free(tac);
	}
    }

    if (tthread->state) {
	if (tthread->target->ops->free_thread_state) 
	    tthread->target->ops->free_thread_state(tthread->target,
						    tthread->state);
	else
	    free(tthread->state);
    }

    free(tthread);

    if (!nohashdelete) 
	g_hash_table_remove(target->threads,(gpointer)(ptr_t)tthread->tid);
}

int target_invalidate_all_threads(struct target *target) {
    GHashTableIter iter;
    struct target_thread *tthread;

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) {
	tthread->valid = 0;
	if (tthread->dirty)
	    vwarn("invalidated dirty thread %"PRIiTID"; BUG?\n",tthread->tid);
    }

    return 0;
}

int target_invalidate_thread(struct target *target,
			     struct target_thread *tthread) {
    tthread->valid = 0;
    if (tthread->dirty)
	vwarn("invalidated dirty thread %"PRIiTID"; BUG?\n",tthread->tid);

    return 0;
}
