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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <regex.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <glib.h>
#include <dwarf.h>
#ifdef DWDEBUG_MEMDEBUG
#include <malloc.h>
#endif

#include "common.h"
#include "log.h"
#include "output.h"
#include "list.h"
#include "alist.h"
#include "glib_wrapper.h"
#include "rfilter.h"
#include "binfile.h"
#include "dwdebug.h"
#include "dwdebug_priv.h"

/* These are the known, loaded (maybe partially) debuginfo files. */
/* debug filename -> struct debugfile */
static GHashTable *debugfile_tab = NULL;
static GHashTable *debugfile_id_tab = NULL;

static int debugfile_id_idx = 0;

struct debugfile_load_opts default_debugfile_load_opts = {
    .debugfile_filter = NULL,
    .srcfile_filter = NULL,
    .symbol_filter = NULL,
    .flags = DEBUGFILE_LOAD_FLAG_NONE
};

static const char *DEBUGPATHS[] = { 
    "/usr/lib/debug",
    "/usr/local/lib/debug",
    NULL
};

static int init_done = 0;

#if DWDEBUG_MEMDEBUG
static GMemVTable system_malloc_gmemvtable = {
    .malloc = malloc,
    .realloc = realloc,
    .free = free,
    .calloc = calloc,
    .try_malloc = NULL,
    .try_realloc = NULL,
};
#endif

void dwdebug_init(void) {
    if (init_done)
	return;

#ifdef DWDEBUG_MEMDEBUG
    if (getenv("G_SLICE") && strcmp(getenv("G_SLICE"),"always-malloc") == 0)
	g_mem_set_vtable(glib_mem_profiler_table);
    //g_mem_set_vtable(&system_malloc_gmemvtable);
#endif

    binfile_init();

    debugfile_tab = g_hash_table_new_full(g_str_hash,g_str_equal,
					  NULL,NULL);
    debugfile_id_tab = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					     NULL,NULL);

    init_done = 1;
}

void dwdebug_fini(void) {
    GHashTableIter iter;
    struct debugfile *df;

    if (!init_done)
	return;

    /* Double-iterate so that internal loop can remove hashtable nodes. */
    while (g_hash_table_size(debugfile_tab) > 0) {
	g_hash_table_iter_init(&iter,debugfile_tab);
	while (g_hash_table_iter_next(&iter,NULL,(gpointer)&df)) {
	    debugfile_free(df,1);
	    break;
	}
    }
    g_hash_table_destroy(debugfile_tab);
    debugfile_tab = NULL;
    g_hash_table_destroy(debugfile_id_tab);
    debugfile_id_tab = NULL;

    init_done = 0;
}

/*
 * Prototypes.
 */

/**
 ** Symbol lookup functions.
 **/

struct symbol *symbol_get_sym(struct symbol *symbol,const char *name,
			      symbol_type_flag_t flags) {
    struct scope *scope;

    if (!SYMBOL_IS_CONTAINER(symbol))
	return NULL;

    /*
     * Don't try to expand the symbol; this is not a lookup function!
     */

    scope = symbol_read_owned_scope(symbol);
    if (scope)
	return scope_get_sym(scope,name,flags);

    return NULL;
}

struct lsymbol *symbol_lookup_sym__int(struct symbol *symbol,
				       const char *name,const char *delim) {

    char *next;
    char *lname = NULL;
    char *saveptr = NULL;
    struct array_list *anonchain = NULL;
    int i;
    struct lsymbol *lsymbol = NULL;
    struct array_list *chain;

    if (!SYMBOL_IS_CONTAINER(symbol)) {
	verror("symbol %s is not a container!\n",
	       symbol_get_name(symbol));
	return NULL;
    }

    SYMBOL_EXPAND_WARN(symbol);

    lname = strdup(name);
    chain = array_list_create(0);

    /* Add the first one to our chain and start looking up members. */
    lsymbol = lsymbol_create(symbol,chain);
    lsymbol_append(lsymbol,symbol);

    vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,
	   "starting at top-level %s: checking members\n",
	   symbol_get_name(symbol));

    if (!delim)
	delim = DWDEBUG_DEF_DELIM;

    while ((next = strtok_r(!saveptr ? lname : NULL,delim,&saveptr))) {
	if (!(symbol = __symbol_get_one_member__int(symbol,next,&anonchain)))
	    goto errout;
	else if (anonchain && array_list_len(anonchain)) {
	    /* If anonchain has any members, we now have to glue those
	     * members into our overall chain, BEFORE gluing the actual
	     * found symbol onto the tail end of the chain.
	     */
	    for (i = 0; i < array_list_len(anonchain); ++i) {
		lsymbol_append(lsymbol,
			       (struct symbol *)array_list_item(anonchain,i));
	    }
	    /* free the anonchain (and its members!) and reset our pointer */
	    array_list_free(anonchain);
	    anonchain = NULL;
	}
	/* now slap the retval on, too! */
	lsymbol_append(lsymbol,symbol);
    }

    free(lname);

    /* downsize */
    array_list_compact(chain);

    return lsymbol;

 errout:
    if (lname)
	free(lname);
    if (lsymbol)
	lsymbol_free(lsymbol,0);

    return NULL;
}

struct lsymbol *symbol_lookup_sym(struct symbol *symbol,
				  const char *name,const char *delim) {
    struct lsymbol *lsymbol = symbol_lookup_sym__int(symbol,name,delim);
    if (!lsymbol)
	return NULL;

    RHOLD(lsymbol,lsymbol);

    return lsymbol;
}

struct lsymbol *lsymbol_lookup_sym__int(struct lsymbol *lsymbol,
					const char *name,const char *delim) {
    struct lsymbol *ls;
    int i;

    /*
     * Very simple -- we just lookup @name in @symbol, then, prepend the
     * first N - 1 items in @lsymbol's chain (i.e., not including
     * @symbol itself, which is at the head of @ls's chain) to @ls, and
     * RHOLD those N - 1 items.
     */
    ls = symbol_lookup_sym__int(lsymbol->symbol,name,delim);
    if (!ls)
	return NULL;

    array_list_prepend_sublist(ls->chain,lsymbol->chain,-1);

    /* We have to take refs to each symbol of the cloned chain. */
    for (i = 0; i < array_list_len(lsymbol->chain) - 1; ++i) 
	RHOLD((struct symbol *)array_list_item(ls->chain,i),ls);

    return ls;
}

struct lsymbol *lsymbol_lookup_sym(struct lsymbol *lsymbol,
				   const char *name,const char *delim) {
    struct lsymbol *ls;

    ls = lsymbol_lookup_sym__int(lsymbol,name,delim);

    /* This is a lookup function, so it has to hold a ref to its return
     * value.
     */
    if (ls)
	RHOLD(ls,ls);

    return ls;
}

OFFSET symbol_offsetof(struct symbol *symbol,
		       const char *name,const char *delim) {
    struct symbol *s;
    struct symbol *datatype;
    struct lsymbol *ls;
    OFFSET retval = 0;
    int i;
    struct location *loc;

    SYMBOL_EXPAND_WARN(symbol);

    if (SYMBOL_IST_STUN(symbol))
	datatype = symbol;
    else if (SYMBOL_IS_VAR(symbol)) {
	datatype = symbol_get_datatype(symbol);
	if (!SYMBOL_IST_STUN(datatype)) {
	    errno = EINVAL;
	    return 0;
	}
    }
    else {
	errno = EINVAL;
	return 0;
    }

    ls = symbol_lookup_sym__int(datatype,name,delim);
    if (!ls) {
	if (!errno) 
	    errno = ESRCH;
	return 0;
    }

    /*
     * Now that we have the symbol chain, just trace the offsets.
     */
    i = 1;
    array_list_foreach_continue(ls->chain,i,s) {
	loc = SYMBOLX_VAR_LOC(s);
	if (!loc || !LOCATION_IS_M_OFFSET(loc)) {
	    lsymbol_free(ls,1);
	    errno = EINVAL;
	    return 0;
	}
	retval += LOCATION_OFFSET(loc);
    }

    lsymbol_free(ls,1);
    return retval;
}

OFFSET lsymbol_offsetof(struct lsymbol *lsymbol,
			const char *name,const char *delim) {
    return symbol_offsetof(lsymbol->symbol,name,delim);
}

struct lsymbol *lsymbol_clone(struct lsymbol *lsymbol,struct symbol *newchild) {
    struct lsymbol *ls;
    struct array_list *chain;

    chain = array_list_clone(lsymbol->chain,(newchild) ? 1 : 0);
    ls = lsymbol_create(lsymbol->symbol,chain);

    if (newchild)
	lsymbol_append(ls,newchild);

    /* This is a lookup function, so it has to hold a ref to its return
     * value.
     */
    RHOLD(ls,ls);

    return ls;
}

struct array_list *debugfile_lookup_addrs_line(struct debugfile *debugfile,
					       char *filename,int line) {
    GHashTableIter iter;
    gpointer key;
    gpointer value;
    clmatch_t clf;
    char *srcfile;

    g_hash_table_iter_init(&iter,debugfile->srclines);
    while (g_hash_table_iter_next(&iter,&key,&value)) {
	srcfile = (char *)key;
	clf = (clmatch_t)value;
	vdebug(9,LA_DEBUG,LF_DLOOKUP,"checking srcfile %s for filename %s\n",
	       srcfile,filename);
	if (strstr(srcfile,filename)) {
	    vdebug(9,LA_DEBUG,LF_DLOOKUP,"found match: srcfile %s for filename %s\n",
		   srcfile,filename);
	    return clmatch_find(&clf,line);
	}
    }

    return NULL;
}

int debugfile_lookup_line_addr(struct debugfile *debugfile,
			       char *filename,ADDR addr) {
    GHashTableIter iter;
    gpointer key;
    gpointer value;
    clmatch_t clf;
    char *srcfile;
    int retval = -1;

    g_hash_table_iter_init(&iter,debugfile->srcaddrlines);
    while (g_hash_table_iter_next(&iter,&key,&value)) {
	srcfile = (char *)key;
	clf = (clmatch_t)value;
	if (filename && !strstr(srcfile,filename))
	    continue;

	vdebug(9,LA_DEBUG,LF_DLOOKUP,"checking srcfile %s for filename %s\n",
	       srcfile,filename);
	retval = (int)(uintptr_t)clmatch_find(&clf,addr);
	if (retval > 0)
	    return retval;
    }

    return -1;
}

struct lsymbol *debugfile_lookup_sym_line__int(struct debugfile *debugfile,
					       char *filename,int line,
					       SMOFFSET *offset,ADDR *addr) {
    struct array_list *addrs;
    struct lsymbol *ls = NULL;
    int i;
    ADDR iaddr;

    addrs = debugfile_lookup_addrs_line(debugfile,filename,line);
    if (!addrs)
	return NULL;

    for (i = 0; i < array_list_len(addrs); ++i) {
	iaddr = (ADDR)array_list_item(addrs,i);
	ls = debugfile_lookup_addr__int(debugfile,iaddr);
	if (ls) {
	    if (addr)
		*addr = iaddr;
	    if (offset && symbol_has_addr(ls->symbol)) {
		*offset = iaddr - symbol_get_addr(ls->symbol);
	    }
	    return ls;
	}
    }

    return NULL;
}

struct lsymbol *debugfile_lookup_sym_line(struct debugfile *debugfile,
					  char *filename,int line,
					  SMOFFSET *offset,ADDR *addr) {
    struct lsymbol *ls;

    ls = debugfile_lookup_sym_line__int(debugfile,filename,line,offset,addr);
    if (ls)
	RHOLD(ls,ls);

    return ls;
}

struct lsymbol *debugfile_lookup_addr__int(struct debugfile *debugfile,ADDR addr) {
    struct scope *scope;
    struct lsymbol *ls;
    struct symbol *s = (struct symbol *)g_hash_table_lookup(debugfile->addresses,
							    (gpointer)addr);

    if (!s) {
	/* If we didn't find it, try our scope search struct! */
	scope = (struct scope *)clrange_find(&debugfile->ranges,addr);

	/*
	 * If ALLRANGES was not set, scope will be the CU scope;
	 * otherwise it will be the absolute tightest.  So -- if it was
	 * not set, we have to call scope_lookup_addr to find the
	 * tightest bound.
	 */
	if (scope && !(debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_ALLRANGES))
	    scope = scope_lookup_addr(scope,addr);

	if (scope) {
	    if (scope->symbol) {
		vdebug(6,LA_DEBUG,LF_DLOOKUP,
		       "found scope(0x%"PRIxADDR",0x%"PRIxADDR"%s)"
		       " (symbol %s:0x%"PRIxSMOFFSET")\n",
		       scope->range->start,scope->range->end,
		       (scope->range->next != NULL) ? ";..." : "",
		       symbol_get_name(scope->symbol),scope->symbol->ref);

		/*
		 * Make sure the symbol is fully loaded; then repeat the
		 * search to be sure we have the tightest bound.
		 */
		if (!SYMBOL_IS_FULL(scope->symbol)) {
		    SYMBOL_EXPAND_WARN(scope->symbol);

		    scope = (struct scope *)clrange_find(&debugfile->ranges,addr);

		    if (scope && !(debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_ALLRANGES))
			scope = scope_lookup_addr(scope,addr);
		}
	    }
	    else {
		vdebug(6,LA_DEBUG,LF_DLOOKUP,
		       "found scope(0x%"PRIxADDR",0x%"PRIxADDR"%s)\n",
		       scope->range->start,scope->range->end,
		       (scope->range->next != NULL) ? ";..." : "");
	    }
	}

	while (scope) {
	    if (scope->symbol) {
		s = scope->symbol;
		break;
	    }
	    scope = scope->parent;
	}
    }

    /*
     * If we still didn't find it, check the binfile and
     * binfile_pointing symtabs as necessary.
     */
    if (!s && debugfile->binfile && debugfile->binfile->ranges) 
	s = (struct symbol *)clrange_find(&debugfile->binfile->ranges,addr);
    else if (!s && debugfile->binfile_pointing 
	     && debugfile->binfile_pointing->ranges) 
	s = (struct symbol *)clrange_find(&debugfile->binfile_pointing->ranges,
					  addr);

    if (s) 
	ls = lsymbol_create_from_symbol__int(s);
    else 
	ls = NULL;

    return ls;
}

struct lsymbol *debugfile_lookup_addr(struct debugfile *debugfile,ADDR addr) {
    struct lsymbol *ls;

    ls = debugfile_lookup_addr__int(debugfile,addr);
    if (ls)
	RHOLD(ls,ls);

    return ls;
}

struct lsymbol *debugfile_lookup_sym__int(struct debugfile *debugfile,
					  char *name,const char *delim,
					  struct rfilter *srcfile_filter,
					  symbol_type_flag_t flags) {
    char *next = NULL;
    char *lname = NULL;
    char *saveptr = NULL;
    struct array_list *anonchain = NULL;
    int i;
    struct lsymbol *lsymbol = NULL;
    struct lsymbol *lsymbol_tmp = NULL;
    struct symbol *symbol = NULL;
    struct symbol *root;
    struct scope *root_scope;
    struct array_list *chain = NULL;
    GHashTableIter iter;
    gpointer key;
    gpointer value;
    struct rfilter_entry *rfe;
    int accept = RF_ACCEPT;
    struct array_list *root_list;

    if (!delim)
	delim = DWDEBUG_DEF_DELIM;

    if (delim && strstr(name,delim)) {
	lname = strdup(name);
	next = strtok_r(!saveptr ? lname : NULL,delim,&saveptr);
	chain = array_list_create(1);
    }
    else
	next = name;

    /*
     * Always check globals first, then types, then srcfile tables.
     */
    if ((flags & SYMBOL_TYPE_FLAG_VAR || flags & SYMBOL_TYPE_FLAG_FUNC
	 || flags & SYMBOL_TYPE_FLAG_LABEL || flags == SYMBOL_TYPE_FLAG_NONE)
	&& (symbol = g_hash_table_lookup(debugfile->globals,next))) {
	if (srcfile_filter) {
	    rfilter_check(srcfile_filter,symbol_get_srcfile(symbol),&accept,&rfe);
	    if (accept == RF_ACCEPT) {
		vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,"found rf global %s\n",
		       symbol->name);
		goto found;
	    }
	}
	else {
	    vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,"found global %s\n",
		   symbol->name);
	    goto found;
	}
    }

    if ((flags & SYMBOL_TYPE_FLAG_TYPE || flags == SYMBOL_TYPE_FLAG_NONE)
	&& (symbol = g_hash_table_lookup(debugfile->types,next))) {
	if (srcfile_filter) {
	    rfilter_check(srcfile_filter,symbol_get_srcfile(symbol),&accept,&rfe);
	    if (accept == RF_ACCEPT) {
		vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,"found rf type %s\n",
		       symbol->name);
		goto found;
	    }
	}
	else {
	    vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,"found type %s\n",
		   symbol->name);
	    goto found;
	}
    }

    /* 
     * Check all the srcfiles, or check according to the rfilter.
     */
    g_hash_table_iter_init(&iter,debugfile->srcfiles);
    while (g_hash_table_iter_next(&iter,&key,&value)) {
	root = (struct symbol *)value;
	root_scope = symbol_read_owned_scope(root);
	if (srcfile_filter) {
	    rfilter_check(srcfile_filter,key,&accept,&rfe);
	    if (accept == RF_REJECT)
		continue;
	}
	if (!root_scope)
	    continue;

	lsymbol_tmp = scope_lookup_sym__int(root_scope,name,delim,flags);
	if (lsymbol_tmp) {
	    /* If we do find a match, and it's a type, take it! */
	    if (SYMBOL_IS_TYPE(lsymbol_tmp->symbol)) {
		lsymbol = lsymbol_tmp;
		goto found;
	    }
	    /* Or if we find a match and it is a definition (which
	     * implies it should have a location!), take it!
	     */
	    else if (!symbol_is_declaration(lsymbol_tmp->symbol)) {
		     //SYMBOL_IS_FULL(lsymbol_tmp->symbol) 
		     // && lsymbol_tmp->symbol->s.ii->l.loctype 
		     //    != LOCTYPE_UNKNOWN) {
		lsymbol = lsymbol_tmp;
		goto found;
	    }
	    /* Otherwise, if we haven't found anything else yet, save it
	     * off as our "first match", and keep looking.  If we find
	     * nothing better later on, we'll use it.
	     */
	    else if (!lsymbol) {
		lsymbol = lsymbol_tmp;
	    }
	    /* We are never going to use this match, so free it. */
	    else {
		/* Don't force free; somebody else might have a ref! */
		lsymbol_free(lsymbol_tmp,0);
	    }
	}
    }
    /*
     * There will probably never be any hits in here, but we have to check.
     */
    g_hash_table_iter_init(&iter,debugfile->srcfiles_multiuse);
    while (g_hash_table_iter_next(&iter,&key,&value)) {
	root_list = (struct array_list *)value;
	if (srcfile_filter) {
	    rfilter_check(srcfile_filter,key,&accept,&rfe);
	    if (accept == RF_REJECT)
		continue;
	}

	array_list_foreach(root_list,i,root) {
	    root_scope = symbol_read_owned_scope(root);
	    lsymbol_tmp = scope_lookup_sym__int(root_scope,name,delim,flags);
	    if (lsymbol_tmp) {
		/* If we do find a match, and it's a type, take it! */
		if (SYMBOL_IS_TYPE(lsymbol_tmp->symbol)) {
		    lsymbol = lsymbol_tmp;
		    goto found;
		}
		/* Or if we find a match and it is a definition (which
		 * implies it should have a location!), take it!
		 */
		else if (!symbol_is_declaration(lsymbol_tmp->symbol)) {
		    //SYMBOL_IS_FULL(lsymbol_tmp->symbol) 
		    // && lsymbol_tmp->symbol->s.ii->l.loctype 
		    //    != LOCTYPE_UNKNOWN) {
		    lsymbol = lsymbol_tmp;
		    goto found;
		}
		/* Otherwise, if we haven't found anything else yet, save it
		 * off as our "first match", and keep looking.  If we find
		 * nothing better later on, we'll use it.
		 */
		else if (!lsymbol) {
		    lsymbol = lsymbol_tmp;
		}
		/* We are never going to use this match, so free it. */
		else {
		    /* Don't force free; somebody else might have a ref! */
		    lsymbol_free(lsymbol_tmp,0);
		}
	    }
	}
    }

    /*
     * If we don't have a srcfile filter, check the binfile and
     * binfile_pointing symtabs.
     */
    if (!lsymbol && debugfile->binfile && debugfile->binfile->root) {
	if (srcfile_filter) {
	    rfilter_check(srcfile_filter,
			  symbol_get_srcfile(debugfile->binfile->root),
			  &accept,&rfe);
	    if (accept == RF_ACCEPT) {
		vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,
		       "matched rf binfile srcfile %s; will check it\n",
		       debugfile->binfile->root->name);
	    }
	    else {
		vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,
		       "did not match rf binfile srcfile %s; not searching\n",
		       debugfile->binfile->root->name);
		return NULL;
	    }
	}

	root_scope = symbol_read_owned_scope(debugfile->binfile->root);
	lsymbol = scope_lookup_sym__int(root_scope,name,delim,flags);
    }
    else if (!lsymbol && debugfile->binfile_pointing 
	     && debugfile->binfile_pointing->root) {
	if (srcfile_filter) {
	    rfilter_check(srcfile_filter,
			  symbol_get_srcfile(debugfile->binfile_pointing->root),
			  &accept,&rfe);
	    if (accept == RF_ACCEPT) {
		vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,
		       "matched rf binfile srcfile %s; will check it\n",
		       debugfile->binfile_pointing->root->name);
	    }
	    else {
		vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,
		       "did not match rf binfile srcfile %s; not searching\n",
		       debugfile->binfile_pointing->root->name);
		return NULL;
	    }
	}

	root_scope = symbol_read_owned_scope(debugfile->binfile_pointing->root);
	lsymbol = scope_lookup_sym__int(root_scope,name,delim,flags);
    }

    /* If we didn't find anything in our srcfiles traversal, we're
     * done.
     */
    if (!lsymbol)
	return NULL;

 found:
    /*
     * If we found a symbol match in our srcfiles, and it is not a
     * declaration, return it!  Why do we just return it?  Because 
     * symtab_lookup_sym will have *already* finished searching for any
     * children in the fully-qualified symbol name.
     *
     * XXX: this can be very wasteful!  We may search fully down a long
     * chain, only to find that the end of the chain is a type or
     * declaration, and then keep on searching!  We may never find
     * something better :).
     * 
     * So, we have to expose this to the user as a param of some sort:
     * LOOKUP_OPT_FIRST_MATCH; LOOKUP_OPT_FIND_DEFINITION; or
     * something.
     */
    if (lsymbol	&& !symbol_is_declaration(lsymbol->symbol)) {
	vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,"found best %s in symtab\n",
	       lsymbol->symbol->name);
	/* If we found a match, fully load it (and its children and
	 * dependent DIEs if it hasn't been yet!).
	 */
	if (!SYMBOL_IS_FULL(lsymbol->symbol)) {
	    vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,"expanding partial lsymbol %s\n",
		   symbol_get_name(lsymbol->symbol));
	    SYMBOL_EXPAND_WARN(lsymbol->symbol);
	    vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,"expanded partial lsymbol %s\n",
		   symbol_get_name(lsymbol->symbol));
	}

	goto out;
    }
    /* We're not going to use it; it is no better than symbol. */
    else if (symbol) {
	if (lsymbol) {
	    /* Don't force free; somebody might have a ref to it. */
	    lsymbol_free(lsymbol,0);
	    lsymbol = NULL;
	}
    }

    /* If we only have the result from types/globals search, use that! */
    if (!lsymbol) {
	/* If we found a match, fully load it (and its children and
	 * dependent DIEs if it hasn't been yet!).
	 */
	if (!SYMBOL_IS_FULL(symbol)) {
	    vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,"expanding partial symbol %s\n",
		   symbol_get_name(symbol));
	    SYMBOL_EXPAND_WARN(symbol);
	    vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,"expanded partial symbol %s\n",
		   symbol_get_name(symbol));
	}

	lsymbol = lsymbol_create(symbol,chain);

	vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,"found plain %s\n",
	       lsymbol->symbol->name);

	lsymbol_append(lsymbol,symbol);
    }
    else {
	/* If we found a match, fully load it (and its children and
	 * dependent DIEs if it hasn't been yet!).
	 */
	if (!SYMBOL_IS_FULL(lsymbol->symbol)) {
	    vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,"expanding partial lsymbol %s\n",
		   symbol_get_name(lsymbol->symbol));
	    SYMBOL_EXPAND_WARN(lsymbol->symbol);
	    vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,"expanded partial lsymbol %s\n",
		   symbol_get_name(lsymbol->symbol));
	}
    }

    /* If it's not a delimited string, stop now, successfully. */
    if (!lname) {

	goto out;
    }

    vdebug(3,LA_DEBUG,LF_DFILE | LF_DLOOKUP,
	   "found top-level %s; checking members\n",lsymbol->symbol->name);

    if (!delim)
	delim = DWDEBUG_DEF_DELIM;

    while ((next = strtok_r(!saveptr ? lname : NULL,delim,&saveptr))) {
	if (!(symbol = __symbol_get_one_member__int(symbol,next,&anonchain))) {
	    vwarnopt(3,LA_DEBUG,LF_DLOOKUP,"did not find symbol for %s\n",next);
	    goto errout;
	}
	else if (anonchain && array_list_len(anonchain)) {
	    /* If anonchain has any members, we now have to glue those
	     * members into our overall chain, BEFORE gluing the actual
	     * found symbol onto the tail end of the chain.
	     */
	    for (i = 0; i < array_list_len(anonchain); ++i) {
		lsymbol_append(lsymbol,
			       (struct symbol *)array_list_item(anonchain,i));
	    }
	    /* free the anonchain (and its members!) and reset our pointer */
	    array_list_free(anonchain);
	    anonchain = NULL;
	}
	/* now slap the retval on, too! */
	lsymbol_append(lsymbol,symbol);
    }

    free(lname);

    /* downsize */
    array_list_compact(chain);

 out:
    return lsymbol;

 errout:
    if (lname)
	free(lname);
    if (lsymbol)
	/* Don't force free; somebody might have a ref to it! */
	lsymbol_free(lsymbol,0);

    return NULL;
}

struct lsymbol *debugfile_lookup_sym(struct debugfile *debugfile,
				     char *name,const char *delim,
				     struct rfilter *srcfile_filter,
				     symbol_type_flag_t flags) {
    struct lsymbol *lsymbol = debugfile_lookup_sym__int(debugfile,name,delim,
							srcfile_filter,flags);

    if (lsymbol) 
	RHOLD(lsymbol,lsymbol);

    return lsymbol;
}

GSList *debugfile_match_syms(struct debugfile *debugfile,
			     struct rfilter *symbol_filter,
			     symbol_type_flag_t flags,
			     struct rfilter *srcfile_filter) {
    GSList *retval = NULL;
    GSList *retlist;
    GHashTableIter iter;
    char *name;
    struct symbol *symbol;
    GHashTableIter iter2;
    char *srcfile_name;
    struct symbol *root;
    struct scope *scope;
    int accept;
    gpointer key;
    gpointer value;
    struct array_list *root_list;
    int i;

    if (!symbol_filter) {
	errno = EINVAL;
	return NULL;
    }

    if (flags & SYMBOL_TYPE_FLAG_VAR_GLOBAL && !srcfile_filter) {
	if (flags == SYMBOL_TYPE_FLAG_NONE
	    || flags & SYMBOL_TYPE_FLAG_TYPE) {
	    g_hash_table_iter_init(&iter,debugfile->types);
	    while (g_hash_table_iter_next(&iter,&key,&value)) {
		name = (char *)key;
		symbol = (struct symbol *)value;
		rfilter_check(symbol_filter,name,&accept,NULL);
		if (accept == RF_ACCEPT)
		    retval = g_slist_prepend(retval,symbol);
	    }
	    g_hash_table_iter_init(&iter,debugfile->shared_types);
	    while (g_hash_table_iter_next(&iter,&key,&value)) {
		name = (char *)key;
		symbol = (struct symbol *)value;
		rfilter_check(symbol_filter,name,&accept,NULL);
		if (accept == RF_ACCEPT)
		    retval = g_slist_prepend(retval,symbol);
	    }
	}

	g_hash_table_iter_init(&iter,debugfile->globals);
	while (g_hash_table_iter_next(&iter,&key,&value)) {
	    name = (char *)key;
	    symbol = (struct symbol *)value;
	    if (SYMBOL_TYPE_FLAG_MATCHES(symbol,flags)) {
		rfilter_check(symbol_filter,name,&accept,NULL);
		if (accept == RF_ACCEPT)
		    retval = g_slist_prepend(retval,symbol);
	    }
	}
    }
    else {
	g_hash_table_iter_init(&iter2,debugfile->srcfiles);
	while (g_hash_table_iter_next(&iter2,&key,&value)) {
	    srcfile_name = (char *)key;
	    root = (struct symbol *)value;

	    if (srcfile_filter) {
		rfilter_check(srcfile_filter,srcfile_name,&accept,NULL);
		if (accept == RF_REJECT)
		    continue;
	    }

	    scope = symbol_read_owned_scope(root);
	    if (scope) {
		retlist = scope_match_syms(scope,symbol_filter,flags);
		if (retlist)
		    retval = g_slist_concat(retval,retlist);
	    }
	}
	g_hash_table_iter_init(&iter2,debugfile->srcfiles_multiuse);
	while (g_hash_table_iter_next(&iter2,&key,&value)) {
	    srcfile_name = (char *)key;
	    root_list = (struct array_list *)value;
	    if (srcfile_filter) {
		rfilter_check(srcfile_filter,srcfile_name,&accept,NULL);
		if (accept == RF_REJECT)
		    continue;
	    }

	    array_list_foreach(root_list,i,root) {
		scope = symbol_read_owned_scope(root);
		if (scope) {
		    retlist = scope_match_syms(scope,symbol_filter,flags);
		    if (retlist)
			retval = g_slist_concat(retval,retlist);
		}
	    }
	}
    }

    return retval;
}

/**
 ** Data structure management.  In general, our _free() functions do
 ** *everything* to free an object -- remove it from any lists it is on,
 ** free() the actual object itself, plus any object-internal free()s
 ** necessary.  This is a little weird, perhaps, so we make note of it.
 ** Also, it implies that if the object type in question is a sub-object
 ** of another object type, and we are in the parent's _free() function,
 ** and the object is associated with the parent on a list, that list
 ** *must* be traversed via list_for_each_entry_safe!  Please use this
 ** style of garbage collection.
 **/

/**
 ** Debugfiles.
 **/
debugfile_load_flags_t debugfile_load_flags_parse(char *flagstr,char *delim) {
    char *token2 = NULL;
    char *saveptr2;
    debugfile_load_flags_t flags = 0;

    if (!delim)
	delim = ",";

    while ((token2 = strtok_r((!token2)?flagstr:NULL,delim,&saveptr2))) {
	vdebug(7,LA_DEBUG,LF_DFILE,"token2 = '%s'\n",token2);
	if (strcmp(token2,"NONE") == 0 || strcmp(token2,"*") == 0) {
	    flags = DEBUGFILE_LOAD_FLAG_NONE;
	    return 0;
	}
	else if (strcmp(token2,"CUHEADERS") == 0)
	    flags |= DEBUGFILE_LOAD_FLAG_CUHEADERS;
	else if (strcmp(token2,"PUBNAMES") == 0)
	    flags |= DEBUGFILE_LOAD_FLAG_PUBNAMES;
	else if (strcmp(token2,"NODWARF") == 0)
	    flags |= DEBUGFILE_LOAD_FLAG_NODWARF;
	else if (strcmp(token2,"ALLRANGES") == 0)
	    flags |= DEBUGFILE_LOAD_FLAG_ALLRANGES;
	else if (strcmp(token2,"KEEPDECLS") == 0)
	    flags |= DEBUGFILE_LOAD_FLAG_KEEPDECLS;
	else if (strcmp(token2,"PARTIALSYM") == 0)
	    flags |= DEBUGFILE_LOAD_FLAG_PARTIALSYM;
	else if (strcmp(token2,"REDUCETYPES") == 0)
	    flags |= DEBUGFILE_LOAD_FLAG_REDUCETYPES;
	else if (strcmp(token2,"REDUCETYPES_FULL_EQUIV") == 0)
	    flags |= DEBUGFILE_LOAD_FLAG_REDUCETYPES_FULL_EQUIV;
	else {
	    verror("unknown flag '%s'\n",token2);
	    errno = EINVAL;
	    return 0;
	}
    }

    return flags;
}

/*
 * FLAG,FLAG,FLAG|| \
 * [<A|1|R|0>::][<A|1|R|0>:]dfn;[<A|1|R|0>:]dfn;[<A|1|R|0>:]dfn|| \
 * [<A|1|R|0>::][<A|1|R|0>:]sfn;[<A|1|R|0>:]sfn;[<A|1|R|0>:]sfn|| \
 * [<A|1|R|0>::][<A|1|R|0>:]ss;[<A|1|R|0>:]ss;[<A|1|R|0>:]ss
 */
struct debugfile_load_opts *debugfile_load_opts_parse(char *optstr) {
    int i;
    char *token;
    char *saveptr;
    struct rfilter *rf;

    struct debugfile_load_opts *opts = \
	(struct debugfile_load_opts *)malloc(sizeof(*opts));
    memset(opts,0,sizeof(*opts));

    vdebug(5,LA_DEBUG,LF_DFILE,"starting\n");

    token = NULL;
    saveptr = NULL;
    i = 0;
    /* Skip flags parse if there aren't any. */
    if (optstr && *optstr == '|' && *(optstr + 1) == '|')
	i = 1;
    while ((token = strtok_r((!token)?optstr:NULL,"||",&saveptr))) {
	vdebug(7,LA_DEBUG,LF_DFILE,"token = '%s' at %d\n",token,i);

	if (i == 0) {
	    opts->flags = debugfile_load_flags_parse(token,NULL);
	    if (errno) {
		verror("could not load flags!\n");
		goto errout;
	    }
	}
	else if (i < 4) {
	    rf = rfilter_create_parse(token);
	    if (!rf) {
		goto errout;
	    }
	    else if (i == 1)
		opts->debugfile_filter = rf;
	    else if (i == 2) 
		opts->srcfile_filter = rf;
	    else if (i == 3) 
		opts->symbol_filter = rf;
	}
	++i;
    }

    return opts;

 errout:
    debugfile_load_opts_free(opts);
    return NULL;
}

int debugfile_load_opts_checklist(struct array_list *opts_list,char *name,
				  struct debugfile_load_opts **match_saveptr) {
    struct debugfile_load_opts *opts = NULL;
    int accept = RF_REJECT;
    int i;

    vdebug(2,LA_DEBUG,LF_DFILE,"checking debugfile load opts list against '%s'\n",
	   name);
    array_list_foreach(opts_list,i,opts) {
	/* 
	 * We only care if there was a match (or no match and the
	 * filter defaulted to accept) that accepted our filename
	 * for processing.
	 */
	rfilter_check(opts->debugfile_filter,name,&accept,NULL);
	if (accept == RF_ACCEPT) {
	    vdebug(5,LA_DEBUG,LF_DFILE,
		   "debugfile opts %p matched '%s'\n",opts,name);
	    if (match_saveptr) {
		*match_saveptr = opts;
		return accept;
	    }
	}
	else 
	    vdebug(9,LA_DEBUG,LF_DFILE,
		   "not using debugfile opts %p for '%s'\n",opts,name);
    }

    return accept;
}

void debugfile_load_opts_free(struct debugfile_load_opts *opts) {
    if (opts->debugfile_filter) 
	rfilter_free(opts->debugfile_filter);
    if (opts->srcfile_filter) 
	rfilter_free(opts->srcfile_filter);
    if (opts->symbol_filter) 
	rfilter_free(opts->symbol_filter);

    free(opts);
}

char * debugfile_get_name(struct debugfile *debugfile) {
    return debugfile->filename;
}

char *debugfile_get_version(struct debugfile *debugfile) {
    if (debugfile->binfile)
	return debugfile->binfile->version;
    return NULL;
}

void debugfile_init_internal(struct debugfile *debugfile);

struct debugfile *debugfile_create_basic(debugfile_type_t dtype,
					 debugfile_type_flags_t dtflags,
					 char *filename,
					 struct debugfile_load_opts *opts) {
    struct debugfile *debugfile;

    if (!dtype) {
	verror("invalid dtype %d!\n",dtype);
	errno = EINVAL;
	return NULL;
    }

    /* create a new one */
    debugfile = (struct debugfile *)calloc(1,sizeof(*debugfile));
    if (!debugfile) {
	errno = ENOMEM;
	return NULL;
    }

    if (!opts)
	opts = &default_debugfile_load_opts;

    debugfile->type = dtype;
    debugfile->opts = opts;

    debugfile->filename = strdup(filename);
    debugfile->id = ++debugfile_id_idx;
    debugfile->flags = dtflags;
    debugfile->refcnt = 0;

    if (dtype == DEBUGFILE_TYPE_DWARF) 
	debugfile->ops = &dwarf_debugfile_ops;

    debugfile_init_internal(debugfile);

    return debugfile;
}

struct debugfile *debugfile_create(debugfile_type_t dtype,
				   debugfile_type_flags_t dtflags,
				   struct binfile *binfile,
				   struct debugfile_load_opts *opts,
				   struct binfile *binfile_pointing) {
    struct debugfile *debugfile;

    /* create a new one */
    debugfile = (struct debugfile *)calloc(1,sizeof(*debugfile));
    if (!debugfile) {
	errno = ENOMEM;
	return NULL;
    }

    if (!opts)
	opts = &default_debugfile_load_opts;

    debugfile->type = dtype;
    debugfile->opts = opts;

    if (binfile)
	debugfile->filename = strdup(binfile->filename);
    debugfile->id = ++debugfile_id_idx;
    debugfile->flags = dtflags;
    debugfile->refcnt = 0;

    if (binfile) {
	debugfile->binfile = binfile;
	RHOLD(binfile,debugfile);
    }

    if (binfile_pointing) {
	debugfile->binfile_pointing = binfile_pointing;
	RHOLD(binfile_pointing,debugfile);
    }

    /*
     * Figure out what type it was from the binfile.
     *
     * XXX: hack until we have more than DWARF.
     */
    if (!dtype && binfile) {
	if (binfile->has_debuginfo) {
	    debugfile->type = DEBUGFILE_TYPE_DWARF;
	}
	else {
	    debugfile->type = DEBUGFILE_TYPE_ELF;
	    debugfile->ops = NULL;
	}
    }
    else if (!dtype) {
	verror("no debugfile_type_t nor binfile!\n");
	errno = EINVAL;
	debugfile_free(debugfile,1);
	return NULL;
    }

    if (dtype == DEBUGFILE_TYPE_DWARF) 
	debugfile->ops = &dwarf_debugfile_ops;

    debugfile_init_internal(debugfile);

    return debugfile;
}

void debugfile_init_internal(struct debugfile *debugfile) {
    /* initialize hashtables */

    /* This is the primary symtab hashtable -- they are cleaned up in
     * debugfile_free.
     */
    debugfile->srcfiles = g_hash_table_new_full(g_str_hash,g_str_equal,
						NULL,NULL);

    debugfile->srcfiles_multiuse = g_hash_table_new_full(g_str_hash,g_str_equal,
							 NULL,NULL);

    /* This is an optimization lookup hashtable, so we don't provide
     * *any* key or value destructors since we don't want them freed
     * when the hashtable is destroyed.
     */
    debugfile->cuoffsets = g_hash_table_new(g_direct_hash,g_direct_equal);

    /* This is an optimization lookup hashtable, so we don't provide
     * *any* key or value destructors since we don't want them freed
     * when the hashtable is destroyed.
     */
    debugfile->globals = g_hash_table_new(g_str_hash,g_str_equal);

    /* This is an optimization lookup hashtable, so we don't provide
     * *any* key or value destructors since we don't want them freed
     * when the hashtable is destroyed.
     */
    debugfile->types = g_hash_table_new(g_str_hash,g_str_equal);

    debugfile->shared_types = g_hash_table_new(g_str_hash,g_str_equal);

    debugfile->decllists = g_hash_table_new_full(g_str_hash,g_str_equal,
						 free,
						 (GDestroyNotify)array_list_free);

    debugfile->decldefnsused = g_hash_table_new(g_direct_hash,g_direct_equal);

    /* This is an optimization lookup hashtable, so we don't provide
     * *any* key or value destructors since we don't want them freed
     * when the hashtable is destroyed.
     */
    debugfile->addresses = g_hash_table_new(g_direct_hash,g_direct_equal);

    /* 
     * We *do* have to strdup the keys... so free them when we destroy!
     * Also, our values are dwarf_cu_die_ref structs, so free those too!
     */
    debugfile->pubnames = g_hash_table_new_full(g_str_hash,g_str_equal,
						free,free);

    debugfile->ranges = clrange_create();

    /* 
     * We *do* have to strdup the keys... so free them when we destroy!
     */
    debugfile->srclines = g_hash_table_new_full(g_str_hash,g_str_equal,
						free,clmatch_free);
    debugfile->srcaddrlines = g_hash_table_new_full(g_str_hash,g_str_equal,
						    free,clmatchone_free);

    if (debugfile->ops && debugfile->ops->init)
	debugfile->ops->init(debugfile);

    /*
     * Add it to our global hash if the user init'd the lib!
     */
    if (debugfile_tab)
	g_hash_table_insert(debugfile_tab,debugfile->filename,debugfile);
    if (debugfile_id_tab)
	g_hash_table_insert(debugfile_id_tab,
			    (gpointer)(uintptr_t)debugfile->id,debugfile);
}

static int _debugfile_filename_info(char *filename,char **realfilename,
				    debugfile_type_flags_t *dtflags) {
    struct stat sbuf;
    char *realname;

    realname = realpath(filename,NULL);
    if (realname && strcmp(realname,filename) == 0) {
	free(realname);
	realname = filename;
    }
    else if (!realname) {
	verror("realpath(%s): %s\n",filename,strerror(errno));
	return -1;
    }

    if (stat(realname,&sbuf) < 0) {
	verror("stat(%s): %s\n",realname,strerror(errno));
	if (realname != filename)
	    free(realname);
	return -1;
    }

    if (realfilename)
	*realfilename = realname;

    return 0;
}

char *debugfile_search_path(char *filename,char *root_prefix,char *debug_postfix,
			    const char *DFPATH[],char *buf,int buflen) {
    char pbuf[PATH_MAX];
    int rc;
    int i;

    if (!debug_postfix) 
	debug_postfix = ".debug";
    if (!DFPATH) 
	DFPATH = DEBUGPATHS;

    for (i = 0; DFPATH[i]; ++i) {
	rc = 0;

	/* Prefix the prefix. */
	if (root_prefix)
	    rc += snprintf(pbuf + rc,PATH_MAX - rc,"%s",root_prefix);

	/* Add in the PATH component. */
	rc += snprintf(pbuf + rc,PATH_MAX - rc,"/%s",DFPATH[i]);

	/* Add in the filename. */
	rc += snprintf(pbuf + rc,PATH_MAX - rc,"/%s",filename);

	/* Try the filename in this part of the path. */
	if (access(pbuf,R_OK) == 0) 
	    goto out;

	/* Try the postfix. */
	rc += snprintf(pbuf + rc,PATH_MAX - rc,"%s",debug_postfix);
	if (access(pbuf,R_OK) == 0) 
	    goto out;
    }

    if (root_prefix)
	vwarnopt(9,LA_DEBUG,LF_DFILE,
		 "could not find '%s' (root_prefix='%s') in DFPATH!\n",
		 filename,root_prefix);
    else
	vwarnopt(9,LA_DEBUG,LF_DFILE,
		 "could not find '%s' (root_prefix='%s') in DFPATH!\n",
		 filename,root_prefix);

    errno = ESRCH;
    return NULL;

 out:
    if (buf) {
	strncpy(buf,pbuf,buflen);
	/* Make sure it is NULL-term. */
	buf[buflen - 1] = '\0';
    }
    else {
	buf = malloc(rc + 1);
	strncpy(buf,pbuf,rc + 1);
    }
    return buf;
}

/*
 * There are several scenarios in which we want to load a debugfile.
 *  1)  We have a filename, and we want to load the debuginfo that it
 *      contains, or that it points to (via symlink, or internal
 *      content).
 *  2a) We have a binfile_instance with a binfile associated with it.
 *      In this case, we must first open a copy of the binfile
 *      associated with the instance data, UNLESS the binfile is already
 *      associated with this exact instance (if that is true, we just
 *      return the binfile).
 *  2b) We have a binfile_instance with a filename, and no associated
 *      binfile.  We just open the filename against the instance.
 *  3)  We have a binfile; just load debuginfo from that file, or from
 *      the file that that binfile points to.
 */
struct debugfile *debugfile_from_file(char *filename,char *root_prefix,
				      struct array_list *debugfile_load_opts_list) {
    char *realname = filename;
    struct debugfile_load_opts *opts = NULL;
    struct debugfile *debugfile = NULL;
    struct binfile *binfile = NULL;
    struct binfile *binfile_debuginfo = NULL;
    debugfile_type_t dtype;
    debugfile_type_flags_t dtflags = DEBUGFILE_TYPE_FLAG_NONE;

    if (_debugfile_filename_info(filename,&realname,&dtflags)) {
	vwarnopt(1,LA_DEBUG,LF_DFILE,
		 "failed to get filename info for (%s): %s\n",
		 filename,strerror(errno));
    }

    if (debugfile_load_opts_list 
	&& debugfile_load_opts_checklist(debugfile_load_opts_list,
					 realname,&opts) == RF_REJECT) {
	vdebug(2,LA_DEBUG,LF_DFILE,
	       "opts prohibit loading of debugfile '%s'\n",realname);
	goto out;
    }
    else if ((debugfile = (struct debugfile *)			\
	      g_hash_table_lookup(debugfile_tab,realname))) {
	if ((root_prefix == NULL && debugfile->binfile->root_prefix == NULL)
	    || (root_prefix != NULL 
		&& debugfile->binfile->root_prefix != NULL
		&& strcmp(root_prefix,debugfile->binfile->root_prefix) == 0)) {
	    vdebug(2,LA_DEBUG,LF_DFILE,"reusing debugfile %s (%s)\n",
		   debugfile->filename,filename);
	    RHOLD(debugfile,debugfile);
	    goto out;
	}
	else
	    /*
	     * Cannot used cached copy; we need to load from a special
	     * @root_prefix dir.
	     */
	    debugfile = NULL;
    }

    /*
     * Load realname.  Then ask it to load a binfile with its debuginfo;
     * might be the same binfile.
     *
     * Don't take any refs to binfiles; debugfile_create will do that!
     * Also make sure to use our __int() calls so that they don't take
     * refs to those binfiles needlessly.
     */
    binfile = binfile_open__int(realname,root_prefix,NULL);
    if (!binfile)
	goto errout;
    binfile_debuginfo = binfile_open_debuginfo__int(binfile,NULL,DEBUGPATHS);
    if (!binfile_debuginfo) {
	if (errno != ENODATA) {
	    verror("could not open debuginfo for binfile %s: %s!\n",
		   binfile->filename,strerror(errno));
	    goto errout;
	}
	else {
	    /* Do the best we can. */
	    binfile_debuginfo = binfile;
	    dtype = DEBUGFILE_TYPE_ELF;
	}
    }
    else
	dtype = DEBUGFILE_TYPE_DWARF;

    /*
     * Need to create a new debugfile.
     */
    debugfile = debugfile_create(dtype,dtflags,
				 binfile_debuginfo ? binfile_debuginfo : binfile,
				 opts,
				 (binfile_debuginfo && binfile_debuginfo != binfile) \
				      ? binfile : NULL);
    if (!debugfile)
	goto errout;

    /*
     * Now, actually load its debuginfo, according to options.
     */
    if (debugfile->ops && debugfile->ops->load
	&& (!opts || !(opts->flags & DEBUGFILE_LOAD_FLAG_NODWARF)))
	debugfile->ops->load(debugfile);

    RHOLD(debugfile,debugfile);

    goto out;

 errout:
 out:
    if (realname != filename)
	free(realname);

    return debugfile;
}

struct debugfile *debugfile_from_instance(struct binfile_instance *bfinst,
					  struct array_list *debugfile_load_opts_list) {
    char *filename = bfinst->filename;
    char *realname = filename;
    struct debugfile_load_opts *opts = NULL;
    struct debugfile *debugfile = NULL;
    struct binfile *binfile = NULL;
    struct binfile *binfile_debuginfo = NULL;
    debugfile_type_t dtype;
    debugfile_type_flags_t dtflags = DEBUGFILE_TYPE_FLAG_NONE;

    if (_debugfile_filename_info(filename,&realname,&dtflags)) {
	vwarnopt(1,LA_DEBUG,LF_DFILE,
		 "failed to get filename info for (%s): %s\n",
		 filename,strerror(errno));
    }

    if (debugfile_load_opts_list 
	&& debugfile_load_opts_checklist(debugfile_load_opts_list,
					 realname,&opts) == RF_REJECT) {
	vdebug(2,LA_DEBUG,LF_DFILE,
	       "opts prohibit loading of debugfile '%s'\n",realname);
	goto out;
    }

    /*
     * Load realname.  Then ask it to load a binfile with its debuginfo;
     * might be the same binfile.
     */
    binfile = binfile_open__int(realname,bfinst->root_prefix,bfinst);
    if (!binfile)
	goto errout;
    binfile_debuginfo = binfile_open_debuginfo__int(binfile,bfinst,DEBUGPATHS);
    if (!binfile_debuginfo) {
	if (errno != ENODATA) {
	    verror("could not open debuginfo for binfile %s: %s!\n",
		   binfile->filename,strerror(errno));
	    goto errout;
	}
	else {
	    /* Do the best we can. */
	    binfile_debuginfo = binfile;
	    dtype = DEBUGFILE_TYPE_ELF;
	}
    }
    else
	dtype = DEBUGFILE_TYPE_DWARF;

    /*
     * Need to create a new debugfile.
     */
    debugfile = debugfile_create(dtype,dtflags,
				 binfile_debuginfo ? binfile_debuginfo : binfile,
				 opts,
				 (binfile_debuginfo && binfile_debuginfo != binfile) \
				      ? binfile : NULL);
    if (!debugfile)
	goto errout;

    /*
     * Now, actually load its debuginfo, according to options.
     */
    if (debugfile->ops && debugfile->ops->load
	&& (!opts || !(opts->flags & DEBUGFILE_LOAD_FLAG_NODWARF)))
	debugfile->ops->load(debugfile);

    RHOLD(debugfile,debugfile);

    goto out;

 errout:
 out:
    if (realname != filename)
	free(realname);

    return debugfile;
}

struct debugfile *debugfile_from_binfile(struct binfile *binfile,
					 struct array_list *debugfile_load_opts_list) {

}

struct array_list *debugfile_get_loaded_debugfiles(void) {
    struct array_list *retval;
    GHashTableIter iter;
    struct debugfile *df;

    if (!debugfile_tab || g_hash_table_size(debugfile_tab) == 0)
	return NULL;

    retval = array_list_create(g_hash_table_size(debugfile_tab));
    g_hash_table_iter_init(&iter,debugfile_tab);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&df)) 
	array_list_append(retval,df);

    return retval;
}

int debugfile_update_root(struct debugfile *debugfile,struct symbol *symbol) {
    struct symbol *tsymbol;
    struct array_list *symbol_list;

    if (!SYMBOL_IS_ROOT(symbol)) {
	vwarn("symbol(%s:0x%"PRIxSMOFFSET") is not a root symbol!\n",
	      symbol_get_name(symbol),symbol->ref);
	return -1;
    }
    else if (!symbol->name) {
	vwarn("symbol(%s:0x%"PRIxSMOFFSET") must have a name!\n",
	      symbol_get_name(symbol),symbol->ref);
	return -1;
    }

    symbol_list = (struct array_list *)					\
	g_hash_table_lookup(debugfile->srcfiles_multiuse,symbol->name);
    if (symbol_list) {
	if (array_list_find(symbol_list,symbol) >= 0) {
	    vwarnopt(3,LA_DEBUG,LF_DFILE | LF_SYMBOL,
		     "symbol at 0x%"PRIxSMOFFSET" already on the dup list!",
		     symbol->ref);
	}
	else {
	    array_list_append(symbol_list,symbol);
	    vdebug(3,LA_DEBUG,LF_DFILE | LF_SYMBOL,
		   "added symbol 0x%"PRIxSMOFFSET
		   " to existing duplist for srcfile name %s\n",
		   symbol->ref,symbol->name);
	}
    }
    else if ((tsymbol = g_hash_table_lookup(debugfile->srcfiles,symbol->name))
	     && tsymbol != symbol) {
	/*
	 * Since this is a symbol with a duplicate srcfile name, we
	 * have to move it, and the new one, to srcfiles_multiuse.
	 *
	 * Have to _steal() it so the hashtable's per-value
	 * destructor is not called; we don't want the symbol freed,
	 * just moved.
	 */
	g_hash_table_steal(debugfile->srcfiles,tsymbol->name);
	symbol_list = array_list_create(0);
	array_list_append(symbol_list,tsymbol);
	g_hash_table_insert(debugfile->srcfiles_multiuse,
			    strdup(tsymbol->name),symbol_list);
	array_list_append(symbol_list,symbol);

	vdebug(3,LA_DEBUG,LF_DFILE | LF_SYMBOL,
	       "moved symbols 0x%"PRIxSMOFFSET" and 0x%"PRIxSMOFFSET
	       " to new duplist for srcfile name %s\n",
	       tsymbol->ref,symbol->ref,tsymbol->name);
    }
    else if (tsymbol == symbol)
	;
    else {
	vdebug(3,LA_DEBUG,LF_DFILE | LF_SYMBOL,
	       "adding top-level symbol %s:%s\n",
	       debugfile->filename,symbol->name);
	g_hash_table_insert(debugfile->srcfiles,symbol->name,symbol);
    }

    return 0;
}

int debugfile_insert_root(struct debugfile *debugfile,struct symbol *symbol) {
    struct symbol *tsymbol;
    int rc;

    if ((tsymbol = (struct symbol *) \
	     g_hash_table_lookup(debugfile->cuoffsets,
				 (gpointer)(uintptr_t)symbol->ref))
	&& tsymbol != symbol) {
	verror("symbol(%s:0x%"PRIxSMOFFSET") is duplicate;"
	       " symbol(%s:0x%"PRIxSMOFFSET") already in debugfile %s!\n",
	       symbol->name,symbol->ref,tsymbol->name,tsymbol->ref,
	       debugfile->filename);
	return 2;
    }
    else if (tsymbol == symbol)
	;
    else {
	SYMBOL_WX_ROOT(symbol,sr,-5);
	sr->debugfile = debugfile;

	g_hash_table_insert(debugfile->cuoffsets,
			    (gpointer)(uintptr_t)symbol->ref,symbol);
	vdebug(3,LA_DEBUG,LF_DFILE | LF_SYMBOL,
	       "adding top-level symbol %s:0x%"PRIxSMOFFSET"\n",
	       debugfile->filename,symbol->ref);

	/*
	 * We hold the symbol here, because this *always* gets done at
	 * least once.  We release on it when we debugfile_free, and
	 * when we free the 
	 */
	RHOLD(symbol,debugfile);
    }

    if (symbol->name)
	rc = debugfile_update_root(debugfile,symbol);
    else
	rc = 0;

    return rc;
}

int debugfile_remove_root(struct debugfile *debugfile,struct symbol *symbol) {
    struct symbol *tsymbol;
    REFCNT trefcnt;

    if ((tsymbol = (struct symbol *) \
	     g_hash_table_lookup(debugfile->cuoffsets,
				 (gpointer)(uintptr_t)symbol->ref))
	&& tsymbol != symbol) {
	verror("symbol(%s:0x%"PRIxSMOFFSET") is not the one it should be;"
	       " symbol(%s:0x%"PRIxSMOFFSET") already in debugfile %s!\n",
	       symbol->name,symbol->ref,tsymbol->name,tsymbol->ref,
	       debugfile->filename);
	return 1;
    }
    else if (tsymbol == symbol)
	g_hash_table_remove(debugfile->cuoffsets,
			    (gpointer)(uintptr_t)symbol->ref);

    if ((tsymbol = g_hash_table_lookup(debugfile->srcfiles,symbol->name))
	&& tsymbol != symbol) {
	verror("symbol(%s:0x%"PRIxSMOFFSET") is not the one it should be;"
	       " symbol(%s:0x%"PRIxSMOFFSET") already in debugfile %s!\n",
	       symbol->name,symbol->ref,tsymbol->name,tsymbol->ref,
	       debugfile->filename);
	return 2;
    }
    else if (tsymbol == symbol) 
	g_hash_table_remove(debugfile->srcfiles,symbol->name);

    /*
     * We put the symbol here; no point in RPUTNF because nobody would
     * need to keep the symbol.  This is mostly a function for debuginfo
     * backends to call during errors.
     */
    RPUT(symbol,symbol,debugfile,trefcnt);

    return 0;
}

struct symbol *debugfile_lookup_root(struct debugfile *debugfile,
				     SMOFFSET offset) {
    return (struct symbol *)g_hash_table_lookup(debugfile->cuoffsets,
						(gpointer)(uintptr_t)offset);
}

struct symbol *debugfile_lookup_root_name(struct debugfile *debugfile,
					  char *name) {
    struct symbol *symbol;
    struct array_list *alist;

    symbol = (struct symbol *)g_hash_table_lookup(debugfile->srcfiles,name);
    if (symbol)
	return symbol;
    alist = (struct array_list *) \
	g_hash_table_lookup(debugfile->srcfiles_multiuse,name);
    if (alist)
	return (struct symbol *)array_list_item(alist,0);

    return NULL;
}

int debugfile_declaration_copy_definition(struct debugfile *debugfile,
					  struct symbol *declaration,
					  struct symbol *definition) {
    REFCNT trefcnt;

    assert(declaration->isdeclaration);
    assert(!definition->isdeclaration);
    if (declaration->type != definition->type) {
	verror("declaration %s type %s (%p) != definition %s type %s (%p)!\n",
	       symbol_get_name(declaration),SYMBOL_TYPE(declaration->type),
	       declaration,
	       symbol_get_name(definition),SYMBOL_TYPE(definition->type),
	       definition);
	return -1;
    }
    //assert(declaration->type == definition->type);

    //return 0;

    if (definition->datatype_ref 
	&& !symbol_get_datatype(definition) && !SYMBOL_IS_OWN_DATATYPE(definition))
	return -1;
    else {
	/*
	 * Free up its guts.
	 */
	symbol_free_extra(declaration);

	/*
	 * Its definition has already been loaded; take a ref to it and
	 * copy in its guts.
	 *
	 * Well, it turns out that we cannot "take a ref" to it in such
	 * a way we can just free it, because there is no space in the
	 * symbol struct to waste on a pointer to the definition -- so
	 * we don't know what to release.  Furthermore, if we stored the
	 * fact that we took the ref in the debugfile struct, we cannot
	 * guarantee during symbol_free that we can trace back to the
	 * root symbol, and thus the debugfile (the parent hierarchy may
	 * have been broken already) -- so we wouldn't be able to access
	 * the held definition.  So instead, place it in the
	 * debugfile->decldefinitions table if it's not there, and hold
	 * a ref on it there until the debugfile is destroyed.  One ref
	 * for any definition; could be used by multiple declarations;
	 * but they don't need to know it.  Could be wasteful, but it
	 * saves us from corruption, which could occur if we freed the
	 * definition symbol who owns the copied data before we freed
	 * the declaration symbol.
	 */
	if (g_hash_table_lookup_extended(debugfile->decldefnsused,definition,
					 NULL,NULL) == FALSE) {
	    g_hash_table_insert(debugfile->decldefnsused,
				definition,definition);
	    RHOLD(definition,debugfile->decldefnsused);
	}
	declaration->decldefined = 1;

	declaration->has_addr = definition->has_addr;
	declaration->addr = definition->addr;
	declaration->size_is_bits = definition->size_is_bits;
	declaration->size_is_bytes = definition->size_is_bytes;
	declaration->guessed_size = definition->guessed_size;
	memcpy(&declaration->size,&definition->size,sizeof(definition->size));

	if (declaration->datatype && declaration->usesshareddatatype) {
	    RPUT(declaration->datatype,symbol,declaration,trefcnt);
	    declaration->usesshareddatatype = 0;
	}

	if (definition->datatype) {
	    declaration->datatype = definition->datatype;
	    declaration->usesshareddatatype = definition->usesshareddatatype;
	    RHOLD(definition->datatype,declaration);
	    declaration->decltypedefined = 1;
	}

	declaration->extra.exists = definition->extra.exists;

	vdebug(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,
	       "used definition at 0x%"PRIxSMOFFSET" for declaration"
	       " %s at 0x%"PRIxSMOFFSET"\n",
	       definition->ref,symbol_get_name(declaration),declaration->ref);

	return 0;
    }
}

void debugfile_save_declaration(struct debugfile *debugfile,
				struct symbol *symbol) {
    struct array_list *decllist;

    assert(symbol->isdeclaration);

    if (!symbol->name)
	return;

    decllist = (struct array_list *)					\
	g_hash_table_lookup(debugfile->decllists,symbol->name);
    if (!decllist) {
	decllist = array_list_create(1);
	g_hash_table_insert(debugfile->decllists,
			    strdup(symbol->name),decllist);
    }
    array_list_append(decllist,symbol);
}

void debugfile_handle_declaration(struct debugfile *debugfile,
				  struct symbol *symbol) {
    struct symbol *definition;
    struct array_list *decllist;

    assert(symbol->isdeclaration);

    if (!symbol->name)
	return;

    if (!SYMBOL_IS_TYPE(symbol)) {
	definition = (struct symbol *) \
	    g_hash_table_lookup(debugfile->globals,symbol_get_name(symbol));
	if (definition)
	    vdebug(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,
		   "globals lookup found definition '%s' type %s (%p)"
		   " for declaration '%s' type %s (%p; trying to copy\n",
		   symbol_get_name(definition),SYMBOL_TYPE(definition->type),
		   definition,
		   symbol_get_name(symbol),SYMBOL_TYPE(symbol->type),symbol);
    }
    else {
	definition = debugfile_find_type(debugfile,symbol_get_name(symbol));
	if (definition)
	    vdebug(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,
		   "find_type found definition '%s' type %s (%p)"
		   " for declaration '%s' type %s (%p; trying to copy\n",
		   symbol_get_name(definition),SYMBOL_TYPE(definition->type),
		   definition,
		   symbol_get_name(symbol),SYMBOL_TYPE(symbol->type),symbol);
    }

    if (!definition 
	|| debugfile_declaration_copy_definition(debugfile,symbol,definition)) {
	/*
	 * Maybe its definition hasn't been loaded yet, or the
	 * definition's type hasn't been resolved yet; save it off and
	 * handle it later.
	 */
	decllist = (struct array_list *) \
	    g_hash_table_lookup(debugfile->decllists,symbol->name);
	if (!decllist) {
	    decllist = array_list_create(1);
	    g_hash_table_insert(debugfile->decllists,
				strdup(symbol->name),decllist);
	}
	array_list_append(decllist,symbol);
    }
}

static void __debugfile_resolve_decllist(struct debugfile *debugfile,
					 char *name,struct array_list *decllist,
					 GHashTableIter *current_iter) {
    struct symbol *type_definition;
    struct symbol *instance_definition;
    struct symbol *definition;
    struct symbol *declaration;
    int total;
    int copied;
    int mapped;
    int i;
    int rc;
    struct scope *declscope;

    type_definition = debugfile_find_type(debugfile,name);
    instance_definition = (struct symbol *) \
	g_hash_table_lookup(debugfile->globals,name);
    
    if (!type_definition && !instance_definition) {
	vwarnopt(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,
		 "could not find any definitions for declarations named '%s'\n",
		 name);
	return;
    }

    total = array_list_len(decllist);
    copied = mapped = 0;
    array_list_foreach(decllist,i,declaration) {
	if (SYMBOL_IS_TYPE(declaration))
	    definition = type_definition;
	else
	    definition = instance_definition;

	if (!definition) {
	    vwarnopt(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,
		     "could not find definition for declaration '%s'\n",
		     name);
	    continue;
	}

	if (debugfile->opts->flags & DEBUGFILE_LOAD_FLAG_KEEPDECLS) {
	    rc = debugfile_declaration_copy_definition(debugfile,declaration,
						       definition);
	    if (rc) {
		vwarnopt(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,
			 "could not copy definition for declaration '%s'\n",
			 name);
		continue;
	    }

	    ++copied;
	    /* Not optimized, but no big deal. */
	    array_list_foreach_delete(decllist,i);
	}
	else {
	    /*
	     * XXX DWARF: if partial loading, then we really should go
	     * fix up the reftab for the decl's CU!!!  It will still
	     * point to the decl, which we are deleting!
	     */
	    declscope = symbol_containing_scope(declaration);
	    scope_remove_symbol(declscope,declaration);
	    scope_hold_symbol(declscope,definition);

	    ++mapped;
	    /* Not optimized, but no big deal. */
	    array_list_foreach_delete(decllist,i);
	}
    }

    vdebug(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,
	   "resolved %d (copied %d, mapped %d) of %d declarations named '%s'\n",
	   copied+mapped,copied,mapped,total,name);

    if (array_list_len(decllist) == 0) {
	/* NB: this frees the decllist and the hashed name. */
	if (current_iter)
	    g_hash_table_iter_remove(current_iter);
	else
	    g_hash_table_remove(debugfile->decllists,name);
    }
}

void debugfile_resolve_declarations(struct debugfile *debugfile) {
    GHashTableIter iter;
    char *name = NULL;
    struct array_list *decllist = NULL;

    g_hash_table_iter_init(&iter,debugfile->decllists);
    while (g_hash_table_iter_next(&iter,
				  (gpointer *)&name,(gpointer *)&decllist)) {
	__debugfile_resolve_decllist(debugfile,name,decllist,&iter);
    }
}

/*
 * If we get a definition that specifies a declaration, we need to move
 * the @specification into the scope containing @declaration.
 * Basically, we want the definition symbol to actually move into the
 * declaration's scope, from wherever scope it is currently on.
 *
 * But then, it gets even worse.  We basically want anything useful from
 * the declaration to be incorporated into the definition (we won't
 * worry about the other way around for now -- in fact one useful thing
 * to do might be to get rid of the declaration symbol entirely!).  This
 * is tricky.  Here's an example:
 *
 *  <3><28e>: Abbrev Number: 34 (DW_TAG_subprogram)
 *     <28f>   DW_AT_external    : 1
 *     <290>   DW_AT_name        : (indirect string, offset: 0xcf): exception
 *     <294>   DW_AT_artificial  : 1
 *     <295>   DW_AT_declaration : 1
 *     <296>   DW_AT_object_pointer: <0x29a>
 *  <4><29a>: Abbrev Number: 8 (DW_TAG_formal_parameter)
 *     <29b>   DW_AT_type        : <0x2a8>
 *     <29f>   DW_AT_artificial  : 1
 *  <4><2a0>: Abbrev Number: 9 (DW_TAG_formal_parameter)
 *     <2a1>   DW_AT_type        : <0x2f6>
 *
 *
 *  <1><301>: Abbrev Number: 39 (DW_TAG_subprogram)
 *     <302>   DW_AT_specification: <0x28e>
 *     <306>   DW_AT_decl_file   : 1
 *     <307>   DW_AT_decl_line   : 61
 *     <308>   DW_AT_inline      : 2       (declared as inline but ignored)
 *     <309>   DW_AT_object_pointer: <0x311>
 *     <30d>   DW_AT_sibling     : <0x321>
 *  <2><311>: Abbrev Number: 36 (DW_TAG_formal_parameter)
 *     <312>   DW_AT_name        : (indirect string, offset: 0x72): this
 *     <316>   DW_AT_type        : <0x2c7>
 *     <31a>   DW_AT_artificial  : 1
 *  <2><31b>: Abbrev Number: 9 (DW_TAG_formal_parameter)
 *     <31c>   DW_AT_type        : <0x321>
 *
 * and another:
 *
 *  <3><368>: Abbrev Number: 41 (DW_TAG_subprogram)
 *     <369>   DW_AT_external    : 1
 *     <36a>   DW_AT_name        : (indirect string, offset: 0x18d): pushIt
 *     <36e>   DW_AT_decl_file   : 2
 *     <36f>   DW_AT_decl_line   : 10
 *     <370>   DW_AT_MIPS_linkage_name: (indirect string, offset: 0xd9): _ZN2N12N26pushItEi
 *     <374>   DW_AT_type        : <0x1e2>
 *     <378>   DW_AT_declaration : 1
 *  <4><379>: Abbrev Number: 9 (DW_TAG_formal_parameter)
 *     <37a>   DW_AT_type        : <0x1e2>
 *  <1><381>: Abbrev Number: 42 (DW_TAG_subprogram)
 *     <382>   DW_AT_specification: <0x368>
 *     <386>   DW_AT_low_pc      : 0x4009e4
 *     <38e>   DW_AT_high_pc     : 0x400a2e
 *     <396>   DW_AT_frame_base  : 0xc0    (location list)
 *     <39a>   DW_AT_sibling     : <0x3ab>
 *  <2><39e>: Abbrev Number: 43 (DW_TAG_formal_parameter)
 *     <39f>   DW_AT_name        : x
 *     <3a1>   DW_AT_decl_file   : 2
 *     <3a2>   DW_AT_decl_line   : 10
 *     <3a3>   DW_AT_type        : <0x1e2>
 *     <3a7>   DW_AT_location    : 2 byte block: 91 5c     (DW_OP_fbreg: -36)
 *
 *
 * So we can see we need to pull external, name, potentially datatype,
 * ... but that's about it.  What we should really try to do is pull all
 * the settings we don't have set already.
 */
int __specify_definition(struct symbol *spec,struct symbol *def) {

    /* Cursory check. */
    if (spec->type != def->type || spec->datatype_code != def->datatype_code)
	return -1;

    /* @name */
    if (spec->name && !def->name) {
	if (spec->name_nofree) {
	    def->name = spec->name;
	    def->name_nofree = spec->name_nofree;
	}
	else {
	    def->name = strdup(spec->name);
	    def->name_nofree = 0;
	}
	def->orig_name_offset = spec->orig_name_offset;
    }
    /* @datatype */
    if (!def->datatype && spec->datatype) {
	def->datatype = spec->datatype;
	if (spec->usesshareddatatype) {
	    def->usesshareddatatype = 1;
	    RHOLD(def->datatype,def);
	}
    }
    if (!def->datatype_ref)
	def->datatype_ref = spec->datatype_ref;
    /* @isexternal */
    if (spec->isexternal)
	def->isexternal = 1;
    /*
     * XXX: hm, don't worry about inline stuff right now.  Instances
     * would be problematic because if they ref the decl, we might not
     * have them all by the time we get here.
     */
    /* @addr */
    if (spec->has_addr && !def->has_addr) {
	def->has_addr = 1;
	def->addr = spec->addr;
    }
    /* @size */
    if ((spec->size_is_bits || spec->size_is_bytes) 
	&& !def->size_is_bits && !def->size_is_bytes) {
	def->size_is_bits = spec->size_is_bits;
	def->size_is_bytes = spec->size_is_bytes;
	memcpy(&def->size,&spec->size,sizeof(spec->size));
    }

    /*
     * That's it for the core stuff.  Now, don't copy any member info,
     * BUT do check the per-symbol extra info.
     */
    if (SYMBOL_HAS_EXTRA(spec)) {
	if (SYMBOL_IS_FUNC(spec)) {
	    SYMBOL_RX_FUNC(spec,sfr);
	    SYMBOL_WX_FUNC(def,sfw,-1);

	    if (sfr->fbloc && !sfw->fbloc) 
		sfw->fbloc = location_copy(sfr->fbloc);
	    if (sfr->has_entry_pc && !sfw->has_entry_pc) {
		sfw->has_entry_pc = 1;
		sfw->entry_pc = sfr->entry_pc;
	    }
	    if ((sfr->prologue_known || sfr->prologue_guessed) 
		&& !sfw->prologue_known && !sfw->prologue_guessed) {
		sfw->prologue_known = 1;
		sfw->prologue_end = sfr->prologue_end;
	    }
	    if (sfr->epilogue_known && !sfw->epilogue_known) {
		sfw->epilogue_known = 1;
		sfw->epilogue_begin = sfr->epilogue_begin;
	    }
	}
	else if (SYMBOL_IS_VAR(spec)) {
	    SYMBOL_RX_VAR(spec,svr);
	    SYMBOL_WX_VAR(def,svw,-1);

	    if (svr->loc && !svw->loc) 
		svw->loc = location_copy(svr->loc);
	    /*
	     * We should never have to worry about constval copying; if
	     * the specifying "declaration" has a constval, how can
	     * there ever be a "definition" of it?  :)  Hopefully DWARF
	     * generators will honor my reasoning here.
	     */
	}
	else if (SYMBOL_IST_ARRAY(spec)) {
	    if (SYMBOLX_SUBRANGES(spec) && !SYMBOLX_SUBRANGES(def)) {
		SYMBOLX_SUBRANGES(def) = g_slist_copy(SYMBOLX_SUBRANGES(spec));
	    }
	}
	/*
	 * Should not have to worry about any other type information.
	 */
    }

    return 0;
}

int debugfile_define_by_specification(struct debugfile *debugfile,
				      struct symbol *specification,
				      struct symbol *definition) {
    int rc;
    GSList *m1_mlist,*m2_mlist;
    GSList *gsl1,*gsl2;
    struct symbol *m1,*m2;

    rc = __specify_definition(specification,definition);
    if (rc) 
	return rc;

    /* Check all members. */
    m1_mlist = SYMBOLX_MEMBERS(specification);
    m2_mlist = SYMBOLX_MEMBERS(definition);
    v_g_slist_foreach_dual(m1_mlist,m2_mlist,gsl1,gsl2,m1,m2) {
	rc = __specify_definition(m1,m2);
    }

    vdebug(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,
	   "used specification ");
    LOGDUMPSYMBOL(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,specification);
    vdebugc(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,
	    " to complete definition ");
    LOGDUMPSYMBOL_NL(8,LA_DEBUG,LF_DFILE | LF_SYMBOL,definition);

    return 0;
}

int debugfile_add_global(struct debugfile *debugfile,struct symbol *symbol) {
    assert(SYMBOL_IS_INSTANCE(symbol));

    if (unlikely(g_hash_table_lookup(debugfile->globals,symbol->name)))
	return 1;
    g_hash_table_insert(debugfile->globals,symbol->name,symbol);

    vdebug(8,LA_DEBUG,LF_SYMBOL,"added global '%s' type %s (%p)\n",
	   symbol_get_name(symbol),SYMBOL_TYPE(symbol->type),symbol);

#if 0
    if (!symbol->isdeclaration) {
	/*
	 * Also check if there were declarations pending on this global;
	 * link those symbols up if so!
	 */
	decllist = (struct array_list *)			\
	    g_hash_table_lookup(debugfile->decllists,symbol->name);
	if (decllist) 
	    __debugfile_resolve_decllist(debugfile,symbol->name,decllist,NULL);
    }
#endif

    return 0;
}

struct symbol *debugfile_find_type(struct debugfile *debugfile,
				   char *typename) {
    struct symbol *s;

    s = (struct symbol *)g_hash_table_lookup(debugfile->shared_types,typename);

    if (!s)
	s = (struct symbol *)g_hash_table_lookup(debugfile->types,typename);

    return s;
}

int debugfile_add_type(struct debugfile *debugfile,struct symbol *symbol) {
    char *name;

    assert(SYMBOL_IS_TYPE(symbol));

    name = symbol_get_name(symbol);

    /*
     * If it exists, fail (see debugfile_replace_type).
     */
    if (unlikely(g_hash_table_lookup(debugfile->types,name)))
	return 1;
    g_hash_table_insert(debugfile->types,name,symbol);
    RHOLD(symbol,debugfile->types);

    vdebug(8,LA_DEBUG,LF_SYMBOL,"added global type '%s' type %s (%p)\n",
	   symbol_get_name(symbol),SYMBOL_TYPE(symbol->type),symbol);

#if 0
    if (!symbol->isdeclaration) {
	/*
	 * Also check if there were declarations pending on this global;
	 * link those symbols up if so!
	 */
	decllist = (struct array_list *)			\
	    g_hash_table_lookup(debugfile->decllists,symbol->name);
	if (decllist) 
	    __debugfile_resolve_decllist(debugfile,symbol->name,decllist,NULL);
    }
#endif

    return 0;
}

int debugfile_replace_type(struct debugfile *debugfile,struct symbol *symbol) {
    char *name;
    struct symbol *existing;
    REFCNT trefcnt;

    assert(SYMBOL_IS_TYPE(symbol));

    name = symbol_get_name(symbol);

    /*
     * If it exists, unhold the previous type and use this one.  We use
     * this to make sure shared types replace other global types.
     */
    existing = (struct symbol *)g_hash_table_lookup(debugfile->types,name);
    if (existing == symbol)
	return 0;
    if (existing) {
	RPUT(existing,symbol,debugfile->types,trefcnt);
    }
    g_hash_table_insert(debugfile->types,name,symbol);
    RHOLD(symbol,debugfile->types);

    vdebug(8,LA_DEBUG,LF_SYMBOL,"%s global type '%s' type %s (%p)\n",
	   existing ? "replaced" : "added",symbol_get_name(symbol),
	   SYMBOL_TYPE(symbol->type),symbol);

#if 0
    if (!symbol->isdeclaration) {
	/*
	 * Also check if there were declarations pending on this global;
	 * link those symbols up if so!
	 */
	decllist = (struct array_list *)			\
	    g_hash_table_lookup(debugfile->decllists,symbol->name);
	if (decllist) 
	    __debugfile_resolve_decllist(debugfile,symbol->name,decllist,NULL);
    }
#endif

    return 0;
}

REFCNT debugfile_release(struct debugfile *debugfile) {
    REFCNT refcnt;
    RPUT(debugfile,debugfile,debugfile,refcnt);
    return refcnt;
}

REFCNT debugfile_free(struct debugfile *debugfile,int force) {
    int retval = debugfile->refcnt;
    REFCNT trefcnt;
    GHashTableIter iter;
    struct symbol *symbol;
    struct array_list *symbol_list;
    int i;
    gpointer kp, vp;

    vdebug(5,LA_DEBUG,LF_DFILE,"freeing debugfile(%s)\n",debugfile->filename);
#ifdef DWDEBUG_MEMDEBUG
    vdebug(5,LA_DEBUG,LF_DFILE,"dumping current VM usage:\n");
    if (vdebug_is_on(5,LA_DEBUG,LF_DFILE)) {
	char cmd[128];
	unsigned long *x;

	/*
	 * Force sbrk() so that stats are good.
	 */
	mallopt(M_TRIM_THRESHOLD,8);
	x = malloc(sizeof(*x));
	free(x);
	/* man mallopt says 128*1024 is the default, ok. */
	mallopt(M_TRIM_THRESHOLD,128*1024);

	fflush(stdout);
	fflush(stderr);
	vdebug(5,LA_DEBUG,LF_DFILE,"malloc:\n");
	malloc_stats();
	vdebug(5,LA_DEBUG,LF_DFILE,"glib:\n");
	g_mem_profile();
	vdebug(5,LA_DEBUG,LF_DFILE,"procfs:\n");
	snprintf(cmd,sizeof(cmd),"cat /proc/%d/status | grep Vm",getpid());
	if (system(cmd)) {
	    /* gcc */;
	}
	fflush(stdout);
	fflush(stderr);
    }
    vdebug(5,LA_DEBUG,LF_DFILE,"finished dumping current VM usage\n");
#endif

    if (debugfile->refcnt) {
	if (!force) {
	    verror("cannot free (%d refs) debugfile(%s)\n",
		   debugfile->refcnt,debugfile->filename);
	    return debugfile->refcnt;
	}
	else {
	    vwarn("forced free (%d refs) debugfile(%s)\n",
		  debugfile->refcnt,debugfile->filename);
	}
    }

    if (debugfile->ops && debugfile->ops->fini)
	debugfile->ops->fini(debugfile);

    /*
     * Only remove it if the value matches us.  This is necessary
     * because if we loaded debugfile against a binfile_instance, and
     * there were relocations, this debugfile will not be in the
     * hashtable -- but another debugfile (that was NOT relocated!)
     * could still be in the hashtable.  :)
     */
    if (g_hash_table_lookup(debugfile_tab,debugfile->filename) == debugfile)
	g_hash_table_remove(debugfile_tab,debugfile->filename);
    if (g_hash_table_lookup(debugfile_id_tab,(gpointer)(uintptr_t)debugfile->id) 
	== debugfile)
	g_hash_table_remove(debugfile_id_tab,(gpointer)(uintptr_t)debugfile->id);

    g_hash_table_destroy(debugfile->pubnames);
    g_hash_table_destroy(debugfile->addresses);
    g_hash_table_destroy(debugfile->globals);
    g_hash_table_iter_init(&iter,debugfile->types);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&symbol)) {
	RPUT(symbol,symbol,debugfile->types,trefcnt);
    }
    g_hash_table_destroy(debugfile->types);
    g_hash_table_destroy(debugfile->cuoffsets);

    /*
     * We remove all the CU symbols in these hashtables manually so we
     * can release our refs to them!
     */
    g_hash_table_iter_init(&iter,debugfile->srcfiles);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&symbol)) {
	vdebug(5,LA_DEBUG,LF_DFILE | LF_SYMBOL,
	       "releasing symbol(%s:0x%"PRIxSMOFFSET")\n",
	       symbol->name,symbol->ref);
	RPUT(symbol,symbol,debugfile,trefcnt);
	g_hash_table_iter_remove(&iter);
    }
    g_hash_table_destroy(debugfile->srcfiles);
    g_hash_table_iter_init(&iter,debugfile->srcfiles_multiuse);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&symbol_list)) {
	array_list_foreach(symbol_list,i,symbol) {
	    vdebug(5,LA_DEBUG,LF_DFILE | LF_SYMBOL,
		   "releasing symbol(%s:0x%"PRIxSMOFFSET")\n",
		   symbol->name,symbol->ref);
	    RPUT(symbol,symbol,debugfile,trefcnt);
	}
	array_list_free(symbol_list);
	g_hash_table_iter_remove(&iter);
    }
    g_hash_table_destroy(debugfile->srcfiles_multiuse);

    /*
     * RPUT all the shared type symbols.
     */
    g_hash_table_iter_init(&iter,debugfile->shared_types);
    while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	symbol = (struct symbol *)vp;
	RPUT(symbol,symbol,debugfile,trefcnt);
    }
    g_hash_table_destroy(debugfile->shared_types);

    g_hash_table_destroy(debugfile->decllists);

    /*
     * RPUT all the definitions whose parts were copied to fill in
     * declarations.
     */
    g_hash_table_iter_init(&iter,debugfile->decldefnsused);
    while (g_hash_table_iter_next(&iter,&kp,NULL)) {
	symbol = (struct symbol *)kp;
	vdebug(5,LA_DEBUG,LF_DFILE | LF_SYMBOL,
	       "releasing definition symbol(%s:0x%"PRIxSMOFFSET")"
	       " held by declaration symbols\n",
	       symbol_get_name(symbol),symbol->ref);
	RPUT(symbol,symbol,debugfile->decldefnsused,trefcnt);
	g_hash_table_iter_remove(&iter);
    }
    g_hash_table_destroy(debugfile->decldefnsused);

    clrange_free(debugfile->ranges);

    g_hash_table_destroy(debugfile->srclines);
    g_hash_table_destroy(debugfile->srcaddrlines);

    if (debugfile->dbg_strtab)
	free(debugfile->dbg_strtab);
    if (debugfile->loctab)
	free(debugfile->loctab);
    if (debugfile->rangetab)
	free(debugfile->rangetab);
    if (debugfile->linetab)
	free(debugfile->linetab);

    if (debugfile->binfile)
	RPUT(debugfile->binfile,binfile,debugfile,trefcnt);
    if (debugfile->binfile_pointing) 
	RPUT(debugfile->binfile_pointing,binfile,debugfile,trefcnt);

    free(debugfile->filename);
    free(debugfile);

    vdebug(5,LA_DEBUG,LF_DFILE,"freed debugfile\n");

    return retval;
}

/**
 ** Symbols.
 **/
struct symbol *symbol_create(symbol_type_t symtype,symbol_source_t source,
			     char *name,int name_copy,SMOFFSET offset,
			     load_type_t loadtype,struct scope *scope) {
    struct symbol *symbol;

    symbol = (struct symbol *)malloc(sizeof(*symbol));
    if (!symbol)
	return NULL;
    memset(symbol,0,sizeof(*symbol));

    symbol->type = symtype;
    symbol->source = source;
    symbol->loadtag = loadtype;
    symbol->ref = offset;

    /* Comparison functions in dwarf_debuginfo need this set nonzero! */
    symbol->addr = ADDRMAX;
    symbol->has_addr = 0;

    if (name)
	symbol_set_name(symbol,name,name_copy);

    symbol->refcnt = 0;

    /* This must be set before the call to symbol_link_owned_scope()! */
    symbol->scope = scope;

    vdebug(LA_DEBUG,LF_SYMBOL,5,"offset %"PRIxSMOFFSET"\n",offset);

    return symbol;
}

/*
 * Getters/Setters.  Internal versions don't hold; the external wrappers do.
 */

/* @name */
char *symbol_get_name(struct symbol *symbol) {
    return symbol->name;
}
char *symbol_get_name_inline(struct symbol *symbol) {
    struct symbol *origin;

    if (!symbol->isinlineinstance)
	return symbol_get_name(symbol);

    origin = symbol_get_inline_origin(symbol);
    if (!origin)
	return symbol_get_name(symbol);
    else
	return symbol_get_name(origin);
}
char *symbol_get_name_orig(struct symbol *symbol) {
    return symbol->name + symbol->orig_name_offset;
}
void symbol_set_name(struct symbol *symbol,char *name,int copy) {
    if (!copy && symbol->name && strcmp(symbol->name,name) == 0)
	return;

    if (copy) {
	symbol->name = strdup(name);
	symbol->name_nofree = 0;
    }
    else {
	symbol->name = name;
	symbol->name_nofree = 1;
    }
}
void symbol_build_extname(struct symbol *symbol) {
    char *symbol_name = symbol_get_name_orig(symbol);
    char *insert_name;
    int foffset = 0;

    if (SYMBOL_IST_ENUM(symbol)) {
	foffset = 5;
	insert_name = malloc(strlen(symbol_name)+6);
	sprintf(insert_name,"enum %s",symbol_name);
    }
    else if (SYMBOL_IST_STRUCT(symbol)) {
	foffset = 7;
	insert_name = malloc(strlen(symbol_name)+8);
	sprintf(insert_name,"struct %s",symbol_name);
    }
    else if (SYMBOL_IST_UNION(symbol)) {
	foffset = 6;
	insert_name = malloc(strlen(symbol_name)+7);
	sprintf(insert_name,"union %s",symbol_name);
    }
    else if (SYMBOL_IS_TYPE(symbol)) {
	verror("cannot build extname for datatype %s!\n",
	       DATATYPE(symbol->datatype_code));
	return;
    }
    else {
	verror("cannot build extname for type %s!\n",
	       SYMBOL_TYPE(symbol->type));
	return;
    }

    if (symbol_name && !symbol->name_nofree)
	free(symbol_name);

    symbol->name = insert_name;
    symbol->name_nofree = 0;

    symbol->orig_name_offset = foffset;
}
int symbol_has_ext_name(struct symbol *symbol) {
    return (symbol->orig_name_offset > 0) ? 1 : 0;
}
/* @scope */
struct scope *symbol_containing_scope(struct symbol *symbol) {
    return symbol->scope;
}
struct scope *symbol_read_owned_scope(struct symbol *symbol) {
    if (!SYMBOL_HAS_EXTRA(symbol))
	return NULL;

    if (SYMBOL_IST_CONTAINER(symbol))
	return symbol->extra.container->scope;
    else if (SYMBOL_IS_ROOT(symbol))
	return symbol->extra.root->scope;
    else if (SYMBOL_IS_FUNC(symbol))
	return symbol->extra.function->scope;
    else if (SYMBOL_IS_BLOCK(symbol))
	return symbol->extra.block->scope;
    else 
	return NULL;
}
struct scope *symbol_write_owned_scope(struct symbol *symbol) {
    struct scope **scope = NULL;

    if (!symbol->scope && !SYMBOL_IS_ROOT(symbol)) {
	verror("symbol(%s:0x%"PRIxSMOFFSET") is not root but has no"
	       " containing scope!\n",
	       symbol_get_name(symbol),symbol->ref);
    }

    if (SYMBOL_IST_CONTAINER(symbol)) {
	SYMBOL_WX_CONTAINER(symbol,sc,NULL);
	scope = &sc->scope;
    }
    else if (SYMBOL_IS_ROOT(symbol)) {
	SYMBOL_WX_ROOT(symbol,sr,NULL);
	scope = &sr->scope;
    }
    else if (SYMBOL_IS_FUNC(symbol)) {
	SYMBOL_WX_FUNC(symbol,sf,NULL);
	scope = &sf->scope;
    }
    else if (SYMBOL_IS_BLOCK(symbol)) {
	SYMBOL_WX_BLOCK(symbol,sb,NULL);
	scope = &sb->scope;
    }
    else 
	return NULL;

    if (*scope)
	/* We already created one. */
	return *scope;
    else {
	*scope = scope_create(symbol,symbol->ref);
	RHOLD(*scope,symbol);
	return *scope;
    }
}
struct scope *symbol_link_owned_scope(struct symbol *symbol,
				      struct scope *new_parent) {
    struct scope *scope = NULL;

    scope = symbol_write_owned_scope(symbol);

    /*
     * Make sure it is linked to its parent!  This accomplishes a
     * ton of magic.  The scope is only linked in when it is
     * actually built.  It might not be built until it is used; that
     * is the most efficient way!
     *
     * So -- *anything* that wants to write to a symbol's owned
     * scope *must* get the scope this way!!!
     */
    if (scope && (symbol->scope || new_parent) && !scope->parent) {
	if (new_parent && new_parent != symbol->scope)
	    symbol->scope = new_parent;
	scope_insert_scope(symbol->scope,scope);
    }
    return scope;
}

/*
 * @parent must be SYMBOL_IS_CONTAINER() (i.e., it must own a scope).
 * @child->scope should already be set to symbol_read_owned_scope(@parent);
 * @child->scope was preset so that any calls to
 * symbol_write_owned_scope (i.e., to update a function's range info or
 * something) could succeed, even if we weren't yet ready to insert
 * @child into @parent's owned scope yet.  So just check and warn on
 * that.
 */
int symbol_insert_symbol(struct symbol *parent,struct symbol *child) {
    struct scope *scope;

    if (!SYMBOL_HAS_MEMBERS(parent)) {
	verror("");
	ERRORDUMPSYMBOL(parent);
	verrorc(" not a container; cannot insert child ");
	ERRORDUMPSYMBOL_NL(child);
	return -1;
    }
    if (SYMBOL_IST_ENUM(parent) 
	&& symbol_containing_scope(child) != symbol_containing_scope(parent)) {
	verror("enum child ");
	ERRORDUMPSYMBOL(child);
	verrorc(" not set to go on containing scope of parent enum type ");
	ERRORDUMPSYMBOL(parent);
	verrorc("; cannot insert!\n");
	return -1;
    }
    else if (!SYMBOL_IST_ENUM(parent)
	     && symbol_containing_scope(child)
	     && symbol_containing_scope(child) != symbol_read_owned_scope(parent)) {
	verror("child ");
	ERRORDUMPSYMBOL(child);
	verrorc(" not set to go on owned scope of parent ");
	ERRORDUMPSYMBOL(parent);
	verrorc("; cannot insert!\n");
	return -1;
    }

    /*
     * For any type container that is not an ENUM, we insert it into the
     * members list, and into the scope.  For ENUM, just into the member
     * list (ENUMs do not have scope of their own).
     */
    if (SYMBOL_IST_ENUM(parent) && child->isenumval) {
	parent->extra.members = g_slist_append(parent->extra.members,child);
	RHOLD(child,parent);
    }
    else if ((SYMBOL_IST_FUNC(parent) && child->isparam)
	     || (SYMBOL_IST_STUNC(parent) 
		 && (child->ismember || SYMBOL_IS_FUNC(child)))) {
	SYMBOL_WX_CONTAINER(parent,sc,-1);
	sc->members = g_slist_append(sc->members,child);
	RHOLD(child,parent);
    }
    else if (SYMBOL_IS_FUNC(parent) && child->isparam)  {
	SYMBOL_WX_FUNC(parent,sf,-1);
	sf->members = g_slist_append(sf->members,child);
	RHOLD(child,parent);
    }
    else if (SYMBOL_IS_BLOCK(parent) && child->isparam)  {
	SYMBOL_WX_FUNC(parent,sb,-1);
	sb->members = g_slist_append(sb->members,child);
	RHOLD(child,parent);
    }

    /*
     * Now add it to the scope if we have one.
     */
    if (SYMBOL_IST_ENUM(parent)) {
	scope = symbol_containing_scope(parent);
	if (!scope) {
	    verror("BUG? parent ");
	    ERRORDUMPSYMBOL(parent);
	    verrorc(" does not have containing scope??\n");
	    return -1;
	}
    }
    else {
	/*
	 * This must be _link_, not _write_!!!  It is possible to arrive
	 * here and for @parent's scope to not have been created.  So if
	 * we create one, we have to link it too.
	 */
	scope = symbol_link_owned_scope(parent,NULL);
	if (!scope) {
	    verror("BUG? parent ");
	    ERRORDUMPSYMBOL(parent);
	    verrorc(" does not have owned scope??\n");
	    return -1;
	}
    }

    return scope_insert_symbol(scope,child);
}

/* @srcline */
int symbol_get_srcline(struct symbol *symbol) {
    return symbol->srcline;
}
/* @srcfile */
char *symbol_get_srcfile(struct symbol *symbol) {
    symbol = symbol_find_root(symbol);
    if (!symbol)
	return NULL;

    return symbol->name;
}
/* @compdirname */
char *symbol_get_compdirname(struct symbol *symbol) {
    struct symbol_root *root;

    symbol = symbol_find_root(symbol);
    if (!symbol)
	return NULL;
    root = SYMBOLX_ROOT(symbol);
    if (!root)
	return NULL;

    return root->compdirname;
}
/* @type */
symbol_type_t symbol_get_type(struct symbol *symbol) {
    return symbol->type;
}
/* @source */
symbol_source_t symbol_get_source(struct symbol *symbol) {
    return symbol->source;
}
/* @datatype -- not all symbols have it of course. */
struct symbol *symbol_get_datatype_real(struct symbol *symbol) {
    /*
     * Since we automatically turn declarations into definitions, and
     * because we copy datatype for inline instances, it really is this
     * simple!
     */
    if (symbol->datatype)
	SYMBOL_EXPAND_WARN(symbol->datatype);
    return symbol->datatype;
}
struct symbol *symbol_get_datatype(struct symbol *symbol) {
    struct symbol *retval;

    if (!SYMBOL_IS_TYPE(symbol)) 
	retval = symbol->datatype;
    else if (symbol->datatype) {
	retval = symbol_type_skip_qualifiers(symbol->datatype);
    }
    else {
	retval = symbol;
    }

    if (retval)
	SYMBOL_EXPAND_WARN(retval);

    return retval;
}

/* Various flags. */
int symbol_is_synthetic(struct symbol *symbol) {
    return symbol->issynthetic;
}
int symbol_is_external(struct symbol *symbol) {
    return symbol->isexternal;
}
int symbol_is_definition(struct symbol *symbol) {
    if (!symbol->isdeclaration || symbol->decldefined)
	return 1;
    return 0;
}
int symbol_is_declaration(struct symbol *symbol) {
    return symbol->isdeclaration;
}
int symbol_is_decldefined(struct symbol *symbol) {
    return symbol->decldefined;
}
int symbol_is_prototyped(struct symbol *symbol) {
    return symbol->isprototyped;
}
int symbol_is_parameter(struct symbol *symbol) {
    return symbol->isparam;
}
int symbol_is_member(struct symbol *symbol) {
    return symbol->ismember;
}
int symbol_is_enumerator(struct symbol *symbol) {
    return symbol->isenumval;
}
int symbol_is_inlineinstance(struct symbol *symbol) {
    return symbol->isinlineinstance;
}
int symbol_has_addr(struct symbol *symbol) {
    return symbol->has_addr;
}
int symbol_has_unspecified_parameters(struct symbol *symbol) {
    return symbol->has_unspec_params;
}
int symbol_is_inlined(struct symbol *symbol) {
    return symbol->isinlined;
}
int symbol_is_declinline(struct symbol *symbol) {
    return symbol->isdeclinline;
}
int symbol_is_bitsize(struct symbol *symbol) {
    return symbol->size_is_bits;
}
int symbol_is_bytesize(struct symbol *symbol) {
    return symbol->size_is_bytes;
}
uint32_t symbol_get_bytesize(struct symbol *symbol) {
    if (symbol->size_is_bytes)
	return symbol->size.bytes;
    else if (symbol->size_is_bits) {
	if (symbol->size.bits % 8)
	    /* Overestimate. */
	    return symbol->size.bits / 8 + 1;
	else
	    return symbol->size.bits / 8;
    }

    return 0;
}

uint32_t symbol_get_bitsize(struct symbol *symbol) {
    if (symbol->size_is_bytes)
	return symbol->size.bytes * 8;

    return symbol->size.bits;
}
uint32_t symbol_get_bitoffset(struct symbol *symbol) {
    if (!symbol->size_is_bits)
	return 0;
    return symbol->size.offset;
}
uint32_t symbol_get_bitctbytes(struct symbol *symbol) {
    if (!symbol->size_is_bits)
	return 0;
    return symbol->size.ctbytes;
}
/* @addr */
ADDR symbol_get_addr(struct symbol *symbol) {
    return symbol->addr;
}
/*
 * Utility functions.
 */
int symbol_type_flags_match(struct symbol *symbol,symbol_type_flag_t flags) {
    return SYMBOL_TYPE_FLAG_MATCHES(symbol,flags);
}

struct symbol *symbol_find_parent(struct symbol *symbol) {
    struct scope *scope;

    scope = symbol->scope;
    while (scope) {
	if (scope->symbol)
	    return scope->symbol;
	scope = scope->parent;
    }

    return NULL;
}

struct symbol *symbol_find_root(struct symbol *symbol) {
    if (SYMBOL_IS_ROOT(symbol))
	return symbol;
    while ((symbol = symbol_find_parent(symbol)))
	if (SYMBOL_IS_ROOT(symbol))
	    return symbol;
    return NULL;
}

GSList *symbol_get_ordered_members(struct symbol *symbol,
				   symbol_type_flag_t flags) {
    GSList *retval = NULL;
    GSList *gsltmp;
    struct symbol *s;

    /*
     * Only search through the ordered members list.
     */
    v_g_slist_foreach(SYMBOLX_MEMBERS(symbol),gsltmp,s) {
	if (SYMBOL_TYPE_FLAG_MATCHES(s,flags)) {
	    retval = g_slist_append(retval,s);
	}
    }

    return retval;
}

GSList *symbol_get_members(struct symbol *symbol,
			   symbol_type_flag_t flags) {
    struct scope *scope;

    /*
     * NB: we only search the scope's primary symdict -- not its
     * duplicates/anonymous symbols.
     */
    scope = SYMBOLX_SCOPE(symbol);
    if (!scope || !scope->symdict)
	return NULL;

    return symdict_match_syms(scope->symdict,NULL,flags);
}

int symbol_expand(struct symbol *symbol) {
    struct symbol *root;

    if (SYMBOL_IS_FULL(symbol) || SYMBOL_IS_ELF(symbol))
	return 0;

    if (SYMBOL_IS_ROOT(symbol)) {
	SYMBOL_RX_ROOT(symbol,sr);
	if (!sr || !sr->debugfile 
	    || !sr->debugfile->ops || !sr->debugfile->ops->symbol_root_expand) {
	    errno = ENOTSUP;
	    return -1;
	}
	return sr->debugfile->ops->symbol_root_expand(sr->debugfile,symbol);
    }

    root = symbol_find_root(symbol);
    if (!root) {
	verror("could not find root for symbol(%s:0x%"PRIxSMOFFSET")!\n",
	       symbol_get_name(symbol),symbol->ref);
	return -1;
    }

    SYMBOL_RX_ROOT(root,sr);
    if (!sr || !sr->debugfile 
	|| !sr->debugfile->ops || !sr->debugfile->ops->symbol_expand) {
	errno = ENOTSUP;
	return -1;
    }

    return sr->debugfile->ops->symbol_expand(sr->debugfile,root,symbol);
}

void symbol_set_srcline(struct symbol *s,int sl) {
    if (sl > ((1 << SRCLINE_BITS) - 1)) {
        vwarn("symbol %s at srcline %d: line too large (max %d)!\n",
	      symbol_get_name((s)),(sl),(1 << SRCLINE_BITS) - 1);
	s->srcline = 0xffff;
    }
    else {
	s->srcline = sl;
    }
}

/*
 * Setting sizes is a bit complicated.
 *
 * If a type or variable has both a byte_size and a bit_size (gcc does
 * this for bitfields -- in its DWARF output, byte_size is the size of
 * the type containing the bitfield; bit_size is the actual size of the
 * bitfield), and byte_size is moved into ctbytes (size of containing
 * integral type).
 *
 * We handle these situations automatically.  So if the debuginfo
 * parser sees a bytesize first, we set it as a byte size.  Then if it
 * sees bitfield info, we convert the size to a bit size and move the
 * bytes into the ctbytes field.
 */
void symbol_set_bytesize(struct symbol *s,uint32_t b) {
    if (s->size_is_bits) {
        if (b > ((1UL << SIZE_CTBYTES_SIZE) - 1))
	    vwarn("ctbytes %"PRIu32" too big for field size!\n",b);
	s->size.ctbytes = b;
    }
    else {
        s->size_is_bytes = 1;
	s->size_is_bits = 0;
	s->size.bytes = b;
    }
}

void symbol_set_bitsize(struct symbol *s,uint32_t b) {
    if (s->size_is_bytes) {
        uint32_t tmpbytes = s->size.bytes;
	if (tmpbytes > ((1 << SIZE_CTBYTES_SIZE) - 1))
	    vwarn("ctbytes %"PRIu32" too big for field size!\n",tmpbytes);
	s->size.bytes = 0;
	s->size_is_bytes = 0;
	s->size.ctbytes = (uint32_t)tmpbytes;
    }
    s->size_is_bits = 1;
    if (b > ((1 << SIZE_BITS_SIZE) - 1))
	vwarn("bits %"PRIu32" too big for field size!\n",b);
    s->size.bits = b;
}

void symbol_set_bitoffset(struct symbol *s,uint32_t bo) {
    if (s->size_is_bytes) {
        uint32_t tmpbytes = (uint32_t)s->size.bytes;
	if (tmpbytes > ((1 << SIZE_CTBYTES_SIZE) - 1))
	    vwarn("ctbytes %"PRIu32" too big for field size!\n",tmpbytes);
	s->size.bytes = 0;
	s->size_is_bytes = 0;
	s->size.ctbytes = (uint32_t)tmpbytes;
    }
    s->size_is_bits = 1;
    if (bo > ((1 << SIZE_OFFSET_SIZE) - 1))
	vwarn("offset %"PRIu32" too big for field size!\n",bo);
    s->size.offset = bo;
}

void symbol_set_bitsize_all(struct symbol *s,uint32_t b,uint32_t bo,uint32_t ctb) {
    if (b > ((1 << SIZE_BITS_SIZE) - 1))
	vwarn("bits %"PRIu32" too big for field size!\n",b);
    if (bo > ((1 << SIZE_OFFSET_SIZE) - 1))
	vwarn("offset %"PRIu32" too big for field size!\n",bo);
    if (ctb > ((1 << SIZE_CTBYTES_SIZE) - 1))
	vwarn("ctbytes %"PRIu32" too big for field size!\n",ctb);
    s->size_is_bytes = 0;
    s->size_is_bits = 1;
    s->size.bits = b;
    s->size.offset = bo;
    s->size.ctbytes = ctb;
}

void symbol_set_addr(struct symbol *s,ADDR a) {
    if (s->has_addr && s->addr < (a)) {
        vwarn("symbol(%s:0x%"PRIxSMOFFSET") has existing addr 0x%"PRIxADDR
	      " lower than new addr 0x%"PRIxADDR"; not updating!\n",
	      symbol_get_name(s),s->ref,s->addr,a);
    }
    else {
	s->addr = a;
	s->has_addr = 1;
    }
}

int symbol_set_root_priv(struct symbol *symbol,void *priv) {
    SYMBOL_WX_ROOT(symbol,sr,-1);
    sr->priv = priv;
    return 0;
}

int symbol_set_root_compdir(struct symbol *symbol,char *compdirname,int copy) {
    SYMBOL_WX_ROOT(symbol,sr,-1);
    if (sr->compdirname && !sr->compdirname_nofree)
	free(sr->compdirname);
    if (compdirname && copy)
	sr->compdirname = strdup(compdirname);
    else 
	sr->compdirname = compdirname;
    sr->compdirname_nofree = !copy;
    return 0;
}

int symbol_set_root_producer(struct symbol *symbol,char *producer,int copy) {
    SYMBOL_WX_ROOT(symbol,sr,-1);
    if (sr->producer && !sr->producer_nofree)
	free(sr->producer);
    if (producer && copy)
	sr->producer = strdup(producer);
    else 
	sr->producer = producer;
    sr->producer_nofree = !copy;
    return 0;
}

int symbol_set_root_language(struct symbol *symbol,char *language,int copy,
			     short int lang_code) {
    SYMBOL_WX_ROOT(symbol,sr,-1);
    if (sr->language && !sr->language_nofree)
	free(sr->language);
    if (language && copy)
	sr->language = strdup(language);
    else 
	sr->language = language;
    sr->language_nofree = !copy;
    sr->lang_code = lang_code;
    return 0;
}

int symbol_set_encoding(struct symbol *symbol,encoding_t num) {
    if (!SYMBOL_IST_BASE(symbol)) 
	return -1;

    SYMBOLX_ENCODING_V(symbol) = num;
    return 0;
}

int symbol_set_entry_pc(struct symbol *symbol,ADDR entry_pc) {
    if (SYMBOL_IS_FUNC(symbol)) {
	SYMBOL_WX_FUNC(symbol,sf,-1);
	sf->entry_pc = entry_pc;
	sf->has_entry_pc = 1;
    }
    else if (SYMBOL_IS_ROOT(symbol)) {
	SYMBOL_WX_ROOT(symbol,sr,-1);
	sr->entry_pc = entry_pc;
	sr->has_entry_pc = 1;
    }
    else
	goto errout;

    if (entry_pc < symbol->addr) { 
	symbol->addr = entry_pc;
	symbol->has_addr = 1;
    }

    return 0;

 errout:
    return -1;
}

int symbol_set_location(struct symbol *symbol,struct location *loc) {
    SYMBOL_WX_VAR(symbol,sv,-1);

    if (sv->loc) {
	vwarnopt(6,LA_DEBUG,LF_SYMBOL,
		 "replacing existing location for symbol(%s:0x%"PRIxADDR")!\n",
		 symbol_get_name(symbol),symbol->ref);
	location_free(sv->loc);
    }
    sv->loc = loc;

    /*
     * NB: we also try to update symbol->addr!
     */
    if (LOCATION_IS_ADDR(sv->loc)) {
	if (!symbol->has_addr || LOCATION_ADDR(sv->loc) < symbol->addr) {
	    symbol->addr = LOCATION_ADDR(sv->loc);
	    symbol->has_addr = 1;
	}
    }

    return 0;
}

int symbol_set_inline_info(struct symbol *symbol,int isinlined,int isdeclinline) {
    symbol->isinlined = isinlined;
    symbol->isdeclinline = isdeclinline;
    return 0;
}

int symbol_set_inline_origin(struct symbol *symbol,
			     SMOFFSET ref,struct symbol *origin) {
    SYMBOL_WX_INLINE(symbol,sii,-1);

    symbol->isinlineinstance = 1;

    sii->origin_ref = ref;
    sii->origin = origin;

    return 0;
}

static int symbol_set_inline_instances(struct symbol *symbol,GSList *instances) {
    GSList *gsltmp;
    struct symbol *instance;
    SYMBOL_WX_INLINE(symbol,sii,-1);

    v_g_slist_foreach(instances,gsltmp,instance) 
	RHOLD(instance,symbol);
    sii->inline_instances = g_slist_concat(sii->inline_instances,instances);

    return 0;
}

/* NB: for now, don't check if the instance is already on our list. */
int symbol_add_inline_instance(struct symbol *symbol,struct symbol *instance) {
    SYMBOL_WX_INLINE(symbol,sii,-1);

    sii->inline_instances = g_slist_append(sii->inline_instances,instance);
    RHOLD(instance,symbol);

    return 0;
}

int symbol_set_constval(struct symbol *symbol,void *value,int len,int copy) {
    SYMBOL_WX_VAR(symbol,sv,-1);

    if (sv->constval && !symbol->constval_nofree)
	free(sv->constval);

    if (!copy) {
	sv->constval = value;
	symbol->constval_nofree = 1;
    }
    else {
	sv->constval = malloc(len);
	memcpy(sv->constval,value,len);
	symbol->constval_nofree = 0;
    }

    return 0;
}

int symbol_add_subrange(struct symbol *symbol,int subrange) {
    if (!SYMBOL_IST_ARRAY(symbol)) 
	return -1;

    SYMBOLX_SUBRANGES(symbol) = g_slist_append(SYMBOLX_SUBRANGES(symbol),
					       (gpointer)(uintptr_t)subrange);
    return 0;
}

#if 0
int symbol_change_scope(struct symbol *symbol,struct scope *scope) {

    if (symbol->scope == scope)
	return 0;

    /* If it's a member, don't insert OR remove it! */
    if (!symbol->ismember) {
	/* Remove it from what it might be currently on, but don't free it! */
	symtab_steal_symbol(symbol->symtab,symbol);

	/* Add it to the new thing. */
	symbol->symtab = NULL;
	symtab_insert_symbol(symtab,symbol);
    }

    /* Change our immediate children if necessary.  For instance
     * symbols, we only recurse on their types if we were told to.  In
     * general, we are saved from crazy recursion loops (i.e., on nested
     * struct types) because we check to see if we already changed the
     * symtab.
    if (typerecurse && symbol->datatype)
	symbol_change_scope(symbol->datatype,symtab,typerecurse);
     */

    if (!SYMBOL_IS_FULL(symbol))
	return 0;

    if (SYMBOL_IS_TYPE(symbol)) {
	if (SYMBOL_IST_STUN(symbol)) {
	    list_for_each_entry(tmpi,&symbol->s.ti->d.su.members,d.v.member) 
		symbol_change_symtab(tmpi->d.v.member_symbol,symtab);
	}
	else if (SYMBOL_IST_ENUM(symbol)) {
	    list_for_each_entry(tmpi,&symbol->s.ti->d.e.members,d.v.member) 
		symbol_change_symtab(tmpi->d.v.member_symbol,symtab);
	}
    }
    else if (SYMBOL_IS_FUNC(symbol)) {
	/* We don't need to recurse on this symtab; any children already
	 * point to d.f.symtab.
	 */
	if (SYMTAB_HAS_PARENT(symbol->s.ii->d.f.symtab))
	    list_del(&symbol->s.ii->d.f.symtab->member);
	symbol->s.ii->d.f.symtab->hierarchy->parent = symtab;
	symtab->hierarchy->subtabs = g_slist_append(symtab->hierarchy->subtabs,
						    symbol->s.ii->d.f.symtab);

	/* We also don't need to do it for any of our args or variables;
	 * they are on this function's symtab, which we just reparented.
	 */
    }
    /* Nothing to do for labels. */

    return 0;
}
#endif

static inline int __check_type_in_list(struct symbol *type,
				       struct array_list *list) {
    if (!list)
	return 0;

    if (array_list_find(list,type) > -1)
	return 1;

    return 0;
}

static int __symbol_type_equiv(struct symbol *t1,struct symbol *t2,
			       struct array_list **t1ss,
			       struct array_list **t2ss,
			       GHashTable *eqcache,
			       GHashTable *updated_datatype_refs) {
    GSList *m1_mlist;
    GSList *m2_mlist;
    struct symbol *m1;
    struct symbol *m2;
    struct symbol *t1d;
    struct symbol *t2d;
    int retval = 0;
    int rc1 = 0,rc2 = 0;
    int t1created = 0;
    int t2created = 0;
    GSList *gsltmp1,*gsltmp2;
    char *sn1,*sn2;

    if (t1 == t2)
	return 0;
    if (eqcache && g_hash_table_lookup(eqcache,t1) == t2)
	return 0;

    /* Check if we've already been examining this type (for nested
     * structs/unions); if we have, just return equiv so that the
     * recursion will return!  Equivalence is decided further up the
     * stack.
     */
    if (t1ss && *t1ss)
	rc1 = __check_type_in_list(t1,*t1ss);
    if (t2ss && *t2ss)
	rc2 = __check_type_in_list(t2,*t2ss);
    if ((rc1 || rc2) && rc1 == rc2) {
	vdebug(8,LA_DEBUG,LF_SYMBOL,"t1 = %p t2 = %p -> 0\n",t1,t2);
	return 0;
    }
    else if (rc1 || rc2) {
	vdebug(8,LA_DEBUG,LF_SYMBOL,"t1 = %p t2 = %p -> 1\n",t1,t2);
	return 1;
    }

    vdebug(8,LA_DEBUG,LF_SYMBOL,"t1 = %p t2 = %p -> ?\n",t1,t2);

    if (t1->datatype_code != t2->datatype_code)
	return 1;

    if (t1->loadtag != t2->loadtag)
	return 1;

    sn1 = symbol_get_name(t1);
    sn2 = symbol_get_name(t2);
    if ((!sn1 || !sn2) && sn1 != sn2)
	return 1;
    else if (!((sn1 == NULL && sn2 == NULL)
	       || strcmp(sn1,sn2) == 0))
	return 1;

    /* Cheat bad -- the t1->size union is a uint32_t! */
    if (*(uint32_t *)&t1->size != *(uint32_t *)&t2->size 
	|| t1->size_is_bytes != t2->size_is_bytes
	|| t1->size_is_bits != t2->size_is_bits)
	return 1;

    if (!SYMBOL_HAS_EXTRA(t1))
	goto datatype_check;

    /*
     * Check details that are in symbol->extra.* .
     */
    switch (t1->datatype_code) {
    case DATATYPE_VOID:
	break;
    case DATATYPE_ARRAY:
	m1_mlist = SYMBOLX_SUBRANGES(t1);
	m2_mlist = SYMBOLX_SUBRANGES(t2);
	/* The list values are really int, but just compare the pointers. */
	v_g_slist_foreach_dual(m1_mlist,m2_mlist,gsltmp1,gsltmp2,m1,m2) {
	    if (m1 != m2)
		return 1;
	}
	if (gsltmp1 || gsltmp2)
	    return 1;
	break;
    case DATATYPE_FUNC:
	if (t1->has_unspec_params != t2->has_unspec_params)
	    return 1;
	/* NB: fall through to check members! */
    case DATATYPE_STRUCT:
    case DATATYPE_UNION:
	m1_mlist = SYMBOLX_MEMBERS(t1);
	m2_mlist = SYMBOLX_MEMBERS(t2);

	if (m1_mlist == NULL && m2_mlist == NULL)
	    break;
	else if (!m1_mlist || !m2_mlist)
	    return 1;

	/*
	 * Before we check member types, push ourselves as "already
	 * being checked".  Then, if a recursive call to this function
	 * sees these symbols on their respective lists again, it just
	 * returns 0 (equivalent) and we finish the checking further up
	 * the recursion stack.
	 *
	 * NB: we don't really need to do this for functions, so we don't.
	 */
	if (t1->datatype_code != DATATYPE_FUNC) {
	    if (!*t1ss) {
		*t1ss = array_list_create(4);
		t1created = 1;
	    }
	    if (!*t2ss) {
		*t2ss = array_list_create(4);
		t2created = 1;
	    }
	    array_list_append(*t1ss,t1);
	    array_list_append(*t2ss,t2);
	}

	/* Then check all the names/types of the members! */
	while (m1_mlist && m2_mlist) {
	    m1 = m1_mlist->data;
	    m2 = m2_mlist->data;

	    m1_mlist = m1_mlist->next;
	    m2_mlist = m2_mlist->next;

	    //vwarn("i = %d %p %p %p %p %p %p\n",i,ti1,ti2,mi1,mi2,m1,m2);
	    if ((m1 == NULL && m2 == NULL)
		|| (symbol_get_name(m1) == NULL && symbol_get_name(m2) == NULL))
		/* name can be NULL for function params, of course */
		;
	    else if ((m1 == NULL && m2 != NULL)
		|| (m1 != NULL && m2 == NULL)
		|| (symbol_get_name(m1) == NULL && symbol_get_name(m2) != NULL)
		|| (symbol_get_name(m1) != NULL && symbol_get_name(m2) == NULL)
		|| strcmp(symbol_get_name(m1),symbol_get_name(m2))) {
		retval = 1;
		break;
	    }

	    t1d = m1->datatype;
	    t2d = m2->datatype;

	    if (updated_datatype_refs) {
		t1d = (struct symbol *) \
		    g_hash_table_lookup(updated_datatype_refs,
					(gpointer)(uintptr_t)m1->datatype_ref);
		if (!t1d)
		    t1d = m1->datatype;
		t2d = (struct symbol *) \
		    g_hash_table_lookup(updated_datatype_refs,
					(gpointer)(uintptr_t)m2->datatype_ref);
		if (!t2d)
		    t2d = m2->datatype;
	    }

	    if (t1d == t2d)
		continue;

	    if ((rc1 = __symbol_type_equiv(t1d,t2d,t1ss,t2ss,eqcache,
					   updated_datatype_refs))) {
		retval = rc1;
		break;
	    }
	}

	if (t1->datatype_code != DATATYPE_FUNC) {
	    array_list_remove(*t1ss);
	    array_list_remove(*t2ss);
	}

	if (t1->datatype_code != DATATYPE_FUNC) {
	    if (t1created) {
		array_list_free(*t1ss);
		*t1ss = NULL;
	    }
	    if (t2created) {
		array_list_free(*t2ss);
		*t2ss = NULL;
	    }
	}

	if (retval)
	    return retval;

	/* If we have an uneven number members, they can't be equivalent. */
	if (m1_mlist != NULL || m2_mlist != NULL)
	    return 1;

	break;
    case DATATYPE_ENUM:
	;
	m1_mlist = SYMBOLX_MEMBERS(t1);
	m2_mlist = SYMBOLX_MEMBERS(t2);

	/*
	 * Life is good if the names are equiv.
	 */
	if (m1_mlist == NULL && m2_mlist == NULL)
	    break;
	else if (!m1_mlist || !m2_mlist)
	    return 1;

	while (m1_mlist && m2_mlist) {
	    m1 = m1_mlist->data;
	    m2 = m2_mlist->data;

	    m1_mlist = m1_mlist->next;
	    m2_mlist = m2_mlist->next;

	    if ((m1 == NULL && m2 != NULL)
		|| (m1 != NULL && m2 == NULL)
		|| (symbol_get_name(m1) == NULL && symbol_get_name(m2) != NULL)
		|| (symbol_get_name(m1) != NULL && symbol_get_name(m2) == NULL)
		|| strcmp(symbol_get_name(m1),symbol_get_name(m2))) {
		retval = 1;
		break;
	    }
	}
	/* If we have an uneven number members, they can't be equivalent. */
	if (!retval && (m1_mlist != NULL || m2_mlist != NULL))
	    return 1;

	break;
    case DATATYPE_PTR:
    case DATATYPE_REF:
    case DATATYPE_TYPEDEF:
    case DATATYPE_CONST:
    case DATATYPE_VOL:
	break;
    case DATATYPE_BASE:
	if (SYMBOLX_ENCODING_V(t1) != SYMBOLX_ENCODING_V(t2))
	    return 1;
	break;
    default:
	return -1;
    }

 datatype_check:
    /*
     * For types that use the datatype field to point to another type,
     * check that type's equiv.
     */
    if (SYMBOL_IST_ARRAY(t1) || SYMBOL_IST_FUNC(t1) || SYMBOL_IST_PTR(t1)
	|| SYMBOL_IST_TYPEDEF(t1) || SYMBOL_IST_CONST(t1) || SYMBOL_IST_VOL(t1)) {
	if (!t1->datatype || !t2->datatype)
	    return 1;

	t1d = t1->datatype;
	t2d = t2->datatype;
	if (updated_datatype_refs) {
	    t1d = (struct symbol *)g_hash_table_lookup(updated_datatype_refs,
						       (gpointer)(uintptr_t)t1->datatype_ref);
	    if (!t1d)
		t1d = t1->datatype;
	    t2d = (struct symbol *)g_hash_table_lookup(updated_datatype_refs,
						       (gpointer)(uintptr_t)t2->datatype_ref);
	    if (!t2d)
		t2d = t2->datatype;
	}
	if (t1d == t2d)
	    return 0;
	retval = __symbol_type_equiv(t1d,t2d,t1ss,t2ss,eqcache,updated_datatype_refs);
	return retval;
    }

    /*
     * If we got here, everything's good!
     */
    if (eqcache) 
	g_hash_table_insert(eqcache,t1,t2);
    return 0;
}

int symbol_type_equal(struct symbol *t1,struct symbol *t2,
		      GHashTable *eqcache,GHashTable *updated_datatype_refs) {
    struct array_list *t1ss = NULL;
    struct array_list *t2ss = NULL;
    int retval;

    if (!SYMBOL_IS_TYPE(t1) || !SYMBOL_IS_TYPE(t2))
	return -1;

    retval = __symbol_type_equiv(t1,t2,&t1ss,&t2ss,eqcache,updated_datatype_refs);

    return retval;
}

struct symbol *__symbol_get_one_member__int(struct symbol *symbol,char *member,
					    struct array_list **chainptr) {
    struct symbol *retval = NULL;
    struct symbol **anonstack = NULL;
    int *parentstack = NULL;
    struct symbol **tmpstack = NULL;
    int *tmpparentstack = NULL;
    int stacklen = 0;
    int stackalen = 0;
    int i = 0;
    /* Set type to symbol to seed the while loop in the SYMBOL_IST_STUN
     * case.
     */
    struct symbol *type;
    int j, k;
    struct lsymbol *lsymbol;
    struct symbol *tsymbol;
    GSList *gsltmp;
    
    struct dump_info udn = {
	.stream = stderr,
	.prefix = "",
	.detail = 0,
	.meta = 0,
    };
    vdebug(4,LA_DEBUG,LF_DLOOKUP,"symbol: ");
    if (vdebug_is_on(4,LA_DEBUG,LF_DLOOKUP))
	symbol_dump(symbol,&udn);
    vdebugc(4,LA_DEBUG,LF_DLOOKUP,"\n");

    type = symbol;

    /* This doesn't look safe, but it is!  If it's a type, we skip
     * const/vol or typedefs, before testing.  If it's not one of those
     * types, this function is an identity function, so we just operate
     * on @symbol.
     */
    if (SYMBOL_IS_TYPE(symbol)) {
	tsymbol = symbol_type_skip_qualifiers(symbol);
	if (tsymbol != symbol) {
	    vdebug(4,LA_DEBUG,LF_DLOOKUP,"skipped type symbol %s, now: ",
		   symbol_get_name(symbol));
	    if (vdebug_is_on(4,LA_DEBUG,LF_DLOOKUP))
		symbol_dump(tsymbol,&udn);

	    symbol = tsymbol;
	    type = symbol;
	}
    }

    /* Make sure the datatype is fully loaded before we search it. */
    SYMBOL_EXPAND_WARN(type);

    if (!SYMBOL_HAS_EXTRA(symbol))
	return NULL;

    if (SYMBOL_IST_CONTAINER(symbol)) {
	/*
	 * First, check our internal symbol table.
	 */
	if (symbol_read_owned_scope(symbol)) {
	    lsymbol = scope_lookup_sym__int(symbol_read_owned_scope(symbol),
					    member,NULL,SYMBOL_TYPE_FLAG_NONE);
	    if (lsymbol) {
		symbol = lsymbol->symbol;
		/* Don't force free; somebody might have a reference */
		lsymbol_free(lsymbol,0);
		return symbol;
	    }
	}

	/*
	 * Check all our members.  It's too bad that we cannot just
	 * lookup in the symbol's scope, but that only looks up named
	 * symbols.  If we come across an unnamed struct/class/union
	 * member, push it onto our anon stack and come back to it.
	 * This avoids non-tail recursion.
	 *
	 * Also, we push variables, not types, as we go through the
	 * list.  We also keep a parent index list; each time we push an
	 * anonymous S/U member variable, we push the anonstack index of
	 * its parent member variable.  Then we can build a symbol_chain
	 * if the caller needs it.
	 *
	 * We need a symbol chain for summing up member offsets for
	 * nested structs.  Note, however, that this chain only consists
	 * of parent variables that were unnamed!!  That is the case
	 * because this function only returns one member.  It is the
	 * caller's job to build up the complete symbol chain consisting
	 * of more than one nested variable/function.
	 */
	while (1) {
	    v_g_slist_foreach(SYMBOLX_MEMBERS(type),gsltmp,retval) {
		vdebug(5,LA_DEBUG,LF_SYMBOL,"checking symbol: ");
		if (vdebug_is_on(4,LA_DEBUG,LF_SYMBOL))
		    symbol_dump(retval,&udn);

		if (!retval->name && SYMBOL_IST_STUNC(retval->datatype)) {
		    /* push this one for later examination. */
		    if (stacklen == stackalen) {
			stackalen += 4;
			tmpstack = (struct symbol **) \
			    realloc(anonstack,sizeof(struct symbol *)*stackalen);
			if (!tmpstack) {
			    verror("realloc anonstack: %s\n",strerror(errno));
			    goto errout;
			}
			anonstack = tmpstack;

			tmpparentstack = (int *) \
			    realloc(parentstack,sizeof(int)*stackalen);
			if (!tmpparentstack) {
			    verror("realloc parentstack: %s\n",
				   strerror(errno));
			    goto errout;
			}
			parentstack = tmpparentstack;
		    }
		    anonstack[stacklen] = retval;
		    /* the parent is always the anonstack idx we're
		     * working on.  Since we want the parent, we need i - 1.
		     */
		    parentstack[stacklen] = i - 1;
		    ++stacklen;
		}
		else if (retval->name && strcmp(retval->name,member) == 0) {
		    //free(anonstack);
		    goto out;
		}
	    }
	    if (stackalen > 8) 
		vwarnopt(4,LA_DEBUG,LF_DLOOKUP,"big stackalen=%d, stack=%d\n",
			 stackalen,stacklen);
	    else 
		vdebug(4,LA_DEBUG,LF_SYMBOL,"stackalen=%d, stack=%d\n",
		       stackalen,stacklen);
	    /* If we're out of stuff on our stack, bail. */
	    if (i == stacklen) {
		free(anonstack);
		free(parentstack);
		anonstack = NULL;
		parentstack = NULL;
		break;
	    }
	    /* Otherwise process the next thing on the stack. */
	    else
		type = anonstack[i++]->datatype;
	}
    }
    else if (SYMBOL_IS_FUNC(symbol)) {
	/* Just check our internal symbol table; the args are there too. */
	if (symbol_read_owned_scope(symbol)) {
	    lsymbol = scope_lookup_sym__int(symbol_read_owned_scope(symbol),
					    member,NULL,SYMBOL_TYPE_FLAG_NONE);
	    if (lsymbol) {
		symbol = lsymbol->symbol;
		/* Don't force free; somebody might have a reference */
		lsymbol_free(lsymbol,0);
		return symbol;
	    }
	}

	return NULL;
    }
    else if (SYMBOL_IS_VAR(symbol)) {
	/* This doesn't look safe, but it is!  If it's a type, we skip
	 * const/vol or typedefs, before testing.  If it's not one of those
	 * types, this function is an identity function, so we just operate
	 * on @symbol.
	 */
	tsymbol = symbol_type_skip_qualifiers(symbol->datatype);
	if (tsymbol != symbol->datatype) {
	    vdebug(4,LA_DEBUG,LF_DLOOKUP,"skipped type symbol for %s, now: ",
		   symbol_get_name(symbol->datatype));
	    if (vdebug_is_on(4,LA_DEBUG,LF_DLOOKUP))
		symbol_dump(tsymbol,&udn);
	}

	/* Make sure the datatype is fully loaded before we search it. */
	SYMBOL_EXPAND_WARN(tsymbol);

	if (SYMBOL_IST_STUN(tsymbol)) {
	    vdebug(4,LA_DEBUG,LF_SYMBOL,
		   "returning result of searching S/U type symbol: ");
	    if (vdebug_is_on(4,LA_DEBUG,LF_SYMBOL))
		symbol_dump(tsymbol,&udn);

	    return __symbol_get_one_member__int(tsymbol,member,chainptr);
	}
	else if (SYMBOL_IST_PTR(tsymbol)) {
	    /*
	     * We keep looking inside the pointed-to type, autoexpanding it
	     * if necessary.
	     */
	    return __symbol_get_one_member__int(symbol_type_skip_ptrs(tsymbol),
					      member,chainptr);
	}
	else 
	    goto errout;
    }

 errout:
    if (anonstack)
	free(anonstack);
    if (parentstack)
	free(parentstack);
    return NULL;

 out:
    vdebug(3,LA_DEBUG,LF_SYMBOL | LF_DLOOKUP,"returning symbol: ");
    if (vdebug_is_on(3,LA_DEBUG,LF_DLOOKUP))
	symbol_dump(retval,&udn);
    /*
     * If type points to something other than the top-level symbol, that
     * means we explored anon structs, and we must return an anon symbol
     * chain that includes the anon variables between @symbol and @retval.
     */
    if (chainptr && type != symbol) {
	int count;
	/* Always includes the anon struct we found, and any anon struct
	 * parents.
	 */
	/* First count up how many anon parents we have in this chain; 
	 * then malloc it; then fill it up in reverse order.
	 */
	count = 1;
	for (j = i - 1; parentstack[j] != -1; j = parentstack[j]) 
	    ++count;
	*chainptr = array_list_create(count);
	for (j = i - 1,k = count; k > 0; --k, j = parentstack[j]) {
	    array_list_item_set(*chainptr,k-1,anonstack[j]);
	}
    }

    if (anonstack) 
	free(anonstack);
    if (parentstack)
	free(parentstack);

    return retval;
}


int symbol_contains_addr(struct symbol *symbol,ADDR obj_addr) {
    struct scope *scope;

    scope = symbol_read_owned_scope(symbol);
    if (!scope)
	return 0;

    return scope_contains_addr(scope,obj_addr);
}

/*
 * Given an IP (as an object-relative address), check and see if this
 * symbol is currently visible (in scope).  To do this we, check if the
 * IP is in the symtab's range; or if it is in any child symtab's range
 * where no symbol in that symtab overrides the primary symbol name!
 */
/*
int symbol_visible_at_ip(struct symbol *symbol,ADDR ip) {
    struct symtab *symtab = symbol->symtab;
    struct range *range;
    int retval = 0;
    int i;
    gpointer data = NULL;

    if (SYMBOL_IS_TYPE(symbol)) {
	return 0;
    }

    // XXX: global check and return 1 if so?

    while (1) {
	data = g_hash_table_lookup(symtab->tab,symbol->name);
	range = &symtab->range;
	if (RANGE_IS_PC(range)) {
	    if (range->r.a.lowpc <= ip && ip < range->r.a.highpc
		&& (symtab == symbol->symtab || !data)) {
		retval = 1;
		break;
	    }
	}
	else if (RANGE_IS_LIST(range)) {
	    for (i = 0; i < range->r.rlist.len; ++i) {
		if (range->r.rlist.list[i]->start <= ip 
		    && ip < range->r.rlist.list[i]->end
		    && (symtab == symbol->symtab || !data)) {
		    retval = 1;
		    break;
		}
	    }
	    if (retval)
		break;
	}
	else
	    break;
    }

    return retval;
}
*/

struct symbol *symbol_get_one_member__int(struct symbol *symbol,char *member) {
    return __symbol_get_one_member__int(symbol,member,NULL);
}

struct symbol *symbol_get_one_member(struct symbol *symbol,char *member) {
    struct symbol *retval = __symbol_get_one_member__int(symbol,member,NULL);

    if (retval) 
	RHOLD(retval,retval);

    return retval;
}

struct symbol *symbol_get_member(struct symbol *symbol,char *memberlist,
				 const char *delim) {
    char *saveptr = NULL;
    struct symbol *retval = NULL;
    char *member;
    char *mlist = strdup(memberlist);

    retval = symbol;

    if (!delim)
	delim = DWDEBUG_DEF_DELIM;

    while ((member = strtok_r(!saveptr ? mlist : NULL,delim,&saveptr))) {
	retval = __symbol_get_one_member__int(retval,member,NULL);
	if (!retval)
	    break;
    }

    free(mlist);

    if (retval)
	RHOLD(retval,retval);

    return retval;
}

struct symbol *symbol_get_inline_origin(struct symbol *symbol) {
    struct symbol *origin;
    struct symbol_inline *ii;

    ii = SYMBOLX_INLINE(symbol);
    if (!ii || !ii->origin)
	return NULL;

    origin = ii->origin;

    /*
     * There may be a chain of abstract origins, so we have to follow them!
     */
    while (1) {
	ii = SYMBOLX_INLINE(origin);
	/* If it is not abstract, then stop looking. */
	if (!ii || !ii->origin)
	    break;

	/* Otherwise, if its origin's origin is abstract, keep going. */
	origin = ii->origin;
    }

    return origin;
}

/*
 * Skips const and volatile types, for now.  Ok, skip typedefs too!
 */
struct symbol *symbol_type_skip_qualifiers(struct symbol *type) {
    if (!SYMBOL_IS_TYPE(type))
	return NULL;

    while (type && type->type == SYMBOL_TYPE_TYPE
	   && (SYMBOL_IST_VOL(type)
	       || SYMBOL_IST_CONST(type)
	       || SYMBOL_IST_TYPEDEF(type))) {
	type = type->datatype;
    }

    return type;
}

struct symbol *symbol_type_skip_ptrs(struct symbol *type) {
    if (!SYMBOL_IS_TYPE(type))
	return NULL;

    while (type->type == SYMBOL_TYPE_TYPE && SYMBOL_IST_PTR(type)) {
	type = type->datatype;
    }

    return type;
}

int symbol_type_is_char(struct symbol *type) {
    if (!SYMBOL_IS_TYPE(type))
	return 0;

    type = symbol_type_skip_qualifiers(type);

    if (SYMBOL_IST_BASE(type)
	&& symbol_get_bytesize(type) == 1
	&& (SYMBOLX_ENCODING_V(type) == ENCODING_SIGNED_CHAR
	    || SYMBOLX_ENCODING_V(type) == ENCODING_UNSIGNED_CHAR)) 
	return 1;

    return 0;
}

unsigned int symbol_type_array_bytesize(struct symbol *type) {
    int size;
    GSList *gsltmp;
    void *elm;

    if (!SYMBOL_IS_TYPE(type))
	return 0;

    type = symbol_type_skip_qualifiers(type);
    if (!SYMBOL_IST_ARRAY(type))
	return 0;
    if (!SYMBOL_HAS_EXTRA(type))
	return 0;

    size = symbol_get_bytesize(symbol_get_datatype(type));

    v_g_slist_foreach(SYMBOLX_SUBRANGES(type),gsltmp,elm) {
	vdebug(5,LA_DEBUG,LF_SYMBOL,"subrange length is %d\n",
	       ((int)(uintptr_t)elm) + 1);
	size = size * (((int)(uintptr_t)elm) + 1);
    }

    vdebug(5,LA_DEBUG,LF_SYMBOL,"full array size is %d for array type %s\n",
	   size,symbol_get_name(type));

    return size;
}

unsigned int symbol_type_full_bytesize(struct symbol *type) {
    if (!SYMBOL_IS_TYPE(type))
	return 0;

    type = symbol_type_skip_qualifiers(type);

    if (SYMBOL_IST_ARRAY(type))
	return symbol_type_array_bytesize(type);
    return symbol_get_bytesize(type);
}

#if 0
int symbol_get_location_offset(struct symbol *symbol,OFFSET *offset_saveptr) {
    struct location *loc;

    if (!SYMBOL_IS_VAR(symbol))
	return -1;

    loc = SYMBOLX_VAR_LOC(symbol);
    if (loc && LOCATION_IS_M_OFFSET(loc)) {
	if (offset_saveptr)
	    *offset_saveptr = LOCATION_OFFSET(loc);
	return 0;
    }
    return -1;
}

int symbol_get_location_addr(struct symbol *symbol,ADDR *addr_saveptr) {
    ADDR addr;
    struct location *loc;

    if (symbol->has_addr) {
	addr = symbol->addr;
    }
    else if (SYMBOL_IS_VAR(symbol)) {
	loc = SYMBOLX_VAR_LOC(symbol);
	if (!loc)
	    return -1;
	addr = LOCATION_ADDR(loc);
    }
    else {
	return -1;
    }

    if (addr_saveptr)
	*addr_saveptr = addr;

    return 0;
}
#endif

REFCNT symbol_release(struct symbol *symbol) {
    REFCNT retval;
    char *name = NULL;
    if (symbol_get_name(symbol)) 
	name = strdup(symbol_get_name(symbol));
    /*
     * WE DO NOT FREE symbols on release; our debugfile garbage
     * collector has to do this for us according to some policy!
     *
     * Actually, we only free dynamic symbols automatically on release!
     */
    if (symbol->issynthetic || symbol->isshared) {
	vdebug(10,LA_DEBUG,LF_SYMBOL,
	       "dynamic/shared symbol %s//%s at %"PRIxSMOFFSET":     ",
	       SYMBOL_TYPE(symbol->type),symbol_get_name(symbol),symbol->ref);
	RPUT(symbol,symbol,symbol,retval);
	if (retval)
	    vdebugc(10,LA_DEBUG,LF_SYMBOL,"  refcnt %d\n",retval);
	else 
	    vdebug(10,LA_DEBUG,LF_SYMBOL,"dynamic/shared symbol %s refcnt 0\n",name);
    }
    else {
	vdebug(10,LA_DEBUG,LF_SYMBOL,"symbol %s//%s at %"PRIxSMOFFSET":     ",
	       SYMBOL_TYPE(symbol->type),symbol_get_name(symbol),symbol->ref);
	RPUT(symbol,symbol,symbol,retval);
	//RPUTNF(symbol,symbol,retval);
	//retval = RPUT(symbol,symbol,symbol);
	if (retval)
	    vdebugc(10,LA_DEBUG,LF_SYMBOL,"  refcnt %d\n",retval);
	else 
	    vdebug(10,LA_DEBUG,LF_SYMBOL,"symbol %s refcnt 0\n",name);
    }
    if (name)
	free(name);

    return retval;
}

void symbol_free_inline(struct symbol *symbol) {
    GSList *gsltmp;
    struct symbol *iisymbol;
    REFCNT trefcnt;

    SYMBOL_RX_INLINE(symbol,sii);

    if (!sii)
	return;

    /*
     * Also have to free any inline instance list.
     */
    if (sii->inline_instances) {
	v_g_slist_foreach(sii->inline_instances,gsltmp,iisymbol) {
	    RPUT(iisymbol,symbol,symbol,trefcnt);
	}
	g_slist_free(sii->inline_instances);
	sii->inline_instances = NULL;
    }

    /*
     * Also have to free any inline instance's origin info that we copied.
     */
    if (symbol->isinlineinstance && sii->origin) {
	/*
	 * NB NB NB: we cannot have objects referencing each other;
	 * such objects might not get deleted.
	 *
	 * (See comments in common.h about ref usage.)
	 */
	//RPUT(symbol->s.ii->origin,symbol,symbol,trefcnt);

	sii->origin = NULL;

	/*
	if (symbol->datatype) {
	    RPUT(symbol->datatype,symbol,symbol,trefcnt);
	    symbol->datatype = NULL;
	}
	*/
    }

    free(sii);
}

void symbol_free_extra(struct symbol *symbol) {
    REFCNT trefcnt;
    GSList *gsltmp;
    struct symbol *m;

    if (!SYMBOL_HAS_EXTRA(symbol))
	return;

    if (SYMBOL_IS_ROOT(symbol)) {
	SYMBOL_RX_ROOT(symbol,sr);
	if (sr->compdirname && !sr->compdirname_nofree)
	    free(sr->compdirname);
	if (sr->producer && !sr->producer_nofree)
	    free(sr->producer);
	if (sr->language && !sr->language_nofree)
	    free(sr->language);
	if (sr->scope) {
	    if (sr->scope->symbol == symbol)
		sr->scope->symbol = NULL;
	    RPUT(sr->scope,scope,symbol,trefcnt);
	}

	if (sr->priv) {
	    if (sr->debugfile 
		&& sr->debugfile->ops 
		&& sr->debugfile->ops->symbol_root_priv_free)
		sr->debugfile->ops->symbol_root_priv_free(sr->debugfile,symbol);
	    else
		free(sr->priv);
	}
	free(sr);
    }
    /* NB: remember to RPUT on all members, not just on the scopes. */
    else if (SYMBOL_IS_FUNC(symbol)) {
	SYMBOL_RX_FUNC(symbol,sf);
	if (sf->members) {
	    v_g_slist_foreach(sf->members,gsltmp,m) {
		RPUT(m,symbol,symbol,trefcnt);
	    }
	    g_slist_free(sf->members);
	}
	if (sf->scope) {
	    if (sf->scope->symbol == symbol)
		sf->scope->symbol = NULL;
	    RPUT(sf->scope,scope,symbol,trefcnt);
	}
	if (sf->fbloc)
	    location_free(sf->fbloc);
	if (sf->ii)
	    symbol_free_inline(symbol);
	free(sf);
    }
    else if (SYMBOL_IS_VAR(symbol)) {
	SYMBOL_RX_VAR(symbol,sv);
	if (sv->loc)
	    location_free(sv->loc);
	if (sv->constval && !symbol->constval_nofree)
	    free(sv->constval);
	if (sv->ii)
	    symbol_free_inline(symbol);
	free(sv);
    }
    else if (SYMBOL_IS_LABEL(symbol)) {
	SYMBOL_RX_LABEL(symbol,sl);
	if (sl->ii)
	    symbol_free_inline(symbol);
	free(sl);
    }
    else if (SYMBOL_IS_BLOCK(symbol)) {
	SYMBOL_RX_BLOCK(symbol,sb);
	if (sb->members) {
	    v_g_slist_foreach(sb->members,gsltmp,m) {
		RPUT(m,symbol,symbol,trefcnt);
	    }
	    g_slist_free(sb->members);
	}
	if (sb->scope) {
	    if (sb->scope->symbol == symbol)
		sb->scope->symbol = NULL;
	    RPUT(sb->scope,scope,symbol,trefcnt);
	}
	if (sb->ii)
	    symbol_free_inline(symbol);
	free(sb);
    }
    else if (SYMBOL_IST_ARRAY(symbol)) {
	if (SYMBOLX_SUBRANGES(symbol))
	    g_slist_free(SYMBOLX_SUBRANGES(symbol));
    }
    else if (SYMBOL_IST_ENUM(symbol)) {
	if (symbol->extra.members) {
	    v_g_slist_foreach(symbol->extra.members,gsltmp,m) {
		RPUT(m,symbol,symbol,trefcnt);
	    }
	    g_slist_free(symbol->extra.members);
	}
    }
    else if (SYMBOL_IST_CONTAINER(symbol)) {
	SYMBOL_RX_CONTAINER(symbol,sc);
	if (sc->members) {
	    v_g_slist_foreach(sc->members,gsltmp,m) {
		RPUT(m,symbol,symbol,trefcnt);
	    }
	    g_slist_free(sc->members);
	}
	if (sc->scope) {
	    if (sc->scope->symbol == symbol)
		sc->scope->symbol = NULL;
	    RPUT(sc->scope,scope,symbol,trefcnt);
	}
	free(sc);
    }
}

REFCNT symbol_free(struct symbol *symbol,int force) {
    int retval = symbol->refcnt;
    REFCNT trefcnt;

    if (symbol->refcnt) {
	if (!force) {
	    verror("cannot free (%d refs) ",symbol->refcnt);
	    ERRORDUMPSYMBOL_NL(symbol);
	    return symbol->refcnt;
	}
	else {
	    vwarn("forced free (%d refs) ",symbol->refcnt);
	    ERRORDUMPSYMBOL_NL(symbol);
	}
    }

    if (symbol->name)
	vdebug(5,LA_DEBUG,LF_SYMBOL,"freeing symbol %s//%s at %"PRIxSMOFFSET"\n",
	       SYMBOL_TYPE(symbol->type),symbol->name,symbol->ref);
    else 
	vdebug(5,LA_DEBUG,LF_SYMBOL,"freeing symbol %s//(null) at %"PRIxSMOFFSET"\n",
	       SYMBOL_TYPE(symbol->type),symbol->ref);

    /*
     * If this symbol refers to a type from some other CU, release on
     * that type.
     */
    if (symbol->usesshareddatatype && symbol->datatype) {
	RPUT(symbol->datatype,symbol,symbol,trefcnt);
	symbol->usesshareddatatype = 0;
	symbol->datatype = NULL;
    }
    /* If this is a dynamic symbol, we have to recursively release any
     * dynamic symbols it points to.
     */
    else if (symbol->issynthetic && symbol->datatype) {
	RPUT(symbol->datatype,symbol,symbol,trefcnt);
	symbol->datatype = NULL;
    }

    /*
     * If we copied definition info from some other symbol, release that
     * stuff before we do anything else.
     */
    if (symbol->decldefined) {
	if (symbol->decltypedefined && symbol->datatype) {
	    symbol->decltypedefined = 0;
	    RPUT(symbol->datatype,symbol,symbol,trefcnt);
	    symbol->datatype = NULL;
	}

	symbol->decldefined = 0;
	/*
	 * See the comments in struct debugfile::decldefnsused ; thus,
	 * we just NULL this out.  The definition symbol "owns" this
	 * pointer, and it will be freed at the conclusion of
	 * debugfile_free.
	 */
	symbol->extra.exists = NULL;
    }

    if (SYMBOL_HAS_EXTRA(symbol))
	symbol_free_extra(symbol);

    if (symbol->name && !symbol->name_nofree) {
	vdebug(5,LA_DEBUG,LF_SYMBOL,"freeing name %s\n",symbol->name);
	free(symbol->name);
    }
    symbol->name = NULL;

    vdebug(5,LA_DEBUG,LF_SYMBOL,"freeing %p\n",symbol);
    free(symbol);

    return retval;
}

/**
 ** Lookup symbols.  Badly named!
 **/
struct lsymbol *lsymbol_create(struct symbol *symbol,
			       struct array_list *chain) {
    struct lsymbol *lsymbol = (struct lsymbol *)malloc(sizeof(struct lsymbol));

    memset(lsymbol,0,sizeof(struct lsymbol));
    lsymbol->symbol = symbol;
    lsymbol->chain = chain;
    lsymbol->refcnt = 0;

    if (chain)
	lsymbol_hold_int(lsymbol);

    return lsymbol;
}

void lsymbol_append(struct lsymbol *lsymbol,struct symbol *symbol) {
    if (!lsymbol->chain)
	lsymbol->chain = array_list_create(1);

    /* Add the symbol to the end of the chain, and ... */
    array_list_append(lsymbol->chain,symbol);

    /* Update the "deepest nested symbol" pointer to point to it. */
    lsymbol->symbol = symbol;

    RHOLD(symbol,lsymbol);
}

void lsymbol_prepend(struct lsymbol *lsymbol,struct symbol *symbol) {
    if (!lsymbol->chain)
	lsymbol->chain = array_list_create(1);

    array_list_prepend(lsymbol->chain,symbol);

    RHOLD(symbol,lsymbol);
}

struct lsymbol *lsymbol_create_from_member__int(struct lsymbol *parent,
						struct symbol *member) {
    struct array_list *chain;
    struct lsymbol *ls;

    chain = array_list_clone(parent->chain,1);
    array_list_append(chain,member);
    ls = lsymbol_create(member,chain);

    lsymbol_hold_int(ls);

    return ls;
}

struct lsymbol *lsymbol_create_from_member(struct lsymbol *parent,
					   struct symbol *member) {
    struct lsymbol *retval;

    retval = lsymbol_create_from_member__int(parent,member);
    if (retval)
	RHOLD(retval,retval);

    return retval;
}

struct lsymbol *lsymbol_create_from_symbol__int(struct symbol *symbol) {
    struct array_list *chain;
    struct lsymbol *ls;
    struct symbol *s = symbol;
    struct symbol *parent;

    if (!s) 
	return NULL;

    chain = array_list_create(1);
    ls = lsymbol_create(s,chain);

 again:
    lsymbol_prepend(ls,s);
    if (SYMBOL_IS_TYPE(s)) {
	goto out;
    }
    else if (SYMBOL_IS_VAR(s)
	     && (symbol->isenumval || symbol->isparam || symbol->ismember)) {
	if (symbol->isenumval) {
	    s = s->datatype;
	    goto again;
	}
	else if (s->isparam || s->ismember) {
	    parent = symbol_find_parent(s);
	    if (s->isparam && SYMBOL_IS_FUNC(parent)) {
		s = parent;
		goto again;
	    }
	    else if (s->ismember && SYMBOL_IST_STUN(parent)) {
		s = parent;
		goto again;
	    }
	    else {
		/* if (!SYMBOL_IS_FULL(s)
		 *  || (s->isparam && SYMBOL_IST_FUNC(parent))
		 *  || (s->ismember)) {
		 */
		goto out;
	    }
	}
	goto out;
    }
    else if (SYMBOL_IS_VAR(s) || SYMBOL_IS_FUNC(s)) {
	/* If the symtab the var/function is on is not the root, trace
	 * up until we find either the root symtab, or a function
	 * symtab.  If we find a function's symtab, we keep going up and
	 * look for more functions.  When we hit the root symtab, we're
	 * done, of course.
	 */
	parent = symbol_find_parent(s);
	if (parent && !SYMBOL_IS_ROOT(parent)) {
	    s = parent;
	    goto again;
	}
	else {
	    goto out;
	}
    }
    /* Just fall out */

 out:
    return ls;
}

struct lsymbol *lsymbol_create_from_symbol(struct symbol *symbol) {
    struct lsymbol *retval;

    retval = lsymbol_create_from_symbol__int(symbol);
    if (retval)
	RHOLD(retval,retval);

    return retval;
}

char *lsymbol_get_name(struct lsymbol *lsymbol) {
    if (lsymbol->symbol)
	return symbol_get_name(lsymbol->symbol);
    return NULL;
}

struct symbol *lsymbol_get_symbol(struct lsymbol *lsymbol) {
    return lsymbol->symbol;
}

struct symbol *lsymbol_get_noninline_parent_symbol(struct lsymbol *lsymbol) {
    int i = array_list_len(lsymbol->chain) - 1;
    struct symbol *s = lsymbol->symbol;

    for ( ; i >= 0; --i) {
	s = (struct symbol *)array_list_item(lsymbol->chain,i);
	if (!s->isinlineinstance)
	    break;
    }
    if (s->isinlineinstance)
	return NULL;

    return s;
}

struct lsymbol *lsymbol_create_noninline__int(struct lsymbol *lsymbol) {
    int i;
    struct symbol *s = NULL;
    struct symbol *ps = NULL;
    struct lsymbol *ls;
    struct array_list *chain;

    if (!lsymbol->symbol->isinlineinstance)
	return NULL;

    chain = array_list_create(array_list_len(lsymbol->chain) - 1);

    for (i = 0; i < array_list_len(lsymbol->chain); ++i) {
	s = (struct symbol *)array_list_item(lsymbol->chain,i);
	if (!s->isinlineinstance)
	    array_list_append(chain,s);
	else
	    break;
	ps = s;
    }

    if (i == 0) {
	array_list_free(chain);
	return NULL;
    }

    ls = lsymbol_create(ps,chain);

    return ls;
}

struct lsymbol *lsymbol_create_noninline(struct lsymbol *lsymbol) {
    struct lsymbol *retval;

    retval = lsymbol_create_noninline__int(lsymbol);
    if (retval)
	RHOLD(retval,retval);

    return retval;
}

void lsymbol_hold_int(struct lsymbol *lsymbol) {
    int i;
    for (i = 0; i < array_list_len(lsymbol->chain); ++i) {
	RHOLD((struct symbol *)array_list_item(lsymbol->chain,i),lsymbol);
    }
}

REFCNT lsymbol_release(struct lsymbol *lsymbol) {
    REFCNT refcnt;
    RPUT(lsymbol,lsymbol,lsymbol,refcnt);
    return refcnt;
}

REFCNT lsymbol_free(struct lsymbol *lsymbol,int force) {
    int retval = lsymbol->refcnt;
    int i;
    REFCNT trefcnt;

    if (lsymbol->refcnt) {
	if (!force) {
	    vwarn("cannot free (%d refs) ",lsymbol->refcnt);
	    ERRORDUMPLSYMBOL_NL(lsymbol);
	    return lsymbol->refcnt;
	}
	else {
	    verror("forced free (%d refs) ",lsymbol->refcnt);
	    ERRORDUMPLSYMBOL(lsymbol);
	}
    }

    if (lsymbol->chain) {
	for (i = 0; i < array_list_len(lsymbol->chain); ++i) {
	    RPUT((struct symbol *)array_list_item(lsymbol->chain,i),symbol,
		 lsymbol,trefcnt);
	}
	array_list_free(lsymbol->chain);
    }
    else if (lsymbol->symbol) {
	RPUT(lsymbol->symbol,symbol,lsymbol,trefcnt);
    }
    free(lsymbol);

    return retval;
}

/**
 ** Data structure dumping functions.
 **/

void g_hash_foreach_dump_symbol_list(gpointer key __attribute__((unused)),
				     gpointer value,gpointer userdata) {
    struct dump_info *ud = (struct dump_info *)userdata;
    struct array_list *list = (struct array_list *)value;
    struct symbol *symbol;
    int i;

    array_list_foreach(list,i,symbol) {
	symbol_dump(symbol,ud);
	fprintf(ud->stream,"\n");
    }
}

void g_hash_foreach_dump_symbol(gpointer key __attribute__((unused)),
				gpointer value,gpointer userdata) {
    struct dump_info *ud = (struct dump_info *)userdata;
    symbol_dump((struct symbol *)value,ud);
    fprintf(ud->stream,"\n");
}

#if 0
void g_hash_foreach_dump_duplist(gpointer key,gpointer value,gpointer userdata) {
    struct dump_info *ud = (struct dump_info *)userdata;
    struct array_list *duplist = (struct array_list *)value;
    char *name = (char *)key;
    int i;
    struct dump_info udn;

    udn.prefix = malloc(strlen(ud->prefix)+2+1);
    sprintf(udn.prefix,"%s%s",ud->prefix,"  ");
    udn.stream = ud->stream;
    udn.meta = ud->meta;
    udn.detail = ud->detail;

    fprintf(ud->stream,"%sduplist(%s):\n",ud->prefix,name);
    for (i = 0; i < array_list_len(duplist); ++i) {
	 symbol_dump((struct symbol *)array_list_item(duplist,i),&udn);
	 fprintf(ud->stream,"\n");
    }
    fprintf(ud->stream,"\n");
    free(udn.prefix);
}
#endif

void debugfile_dump(struct debugfile *debugfile,struct dump_info *ud,
		    int types,int globals,int symtabs,int elfsymtab) {
    char *p = "";
    char *np1, *np2;
    struct dump_info udn;
    int s1,s2,s3,s4;

    if (ud->prefix) {
	p = ud->prefix;
	np1 = malloc(strlen(p) + 1 + 2);
	np2 = malloc(strlen(p) + 1 + 4);
	sprintf(np1,"%s%s",p,"  ");
	sprintf(np2,"%s%s",p,"    ");
    }
    else {
	np1 = "  ";
	np2 = "    ";
    }
    udn.prefix = np2;
    udn.stream = ud->stream;
    udn.meta = ud->meta;
    udn.detail = ud->detail;

    fprintf(ud->stream,"%sdebugfile(%s):\n",p,debugfile->filename);
    fprintf(ud->stream,"%s    flags:  0x%x\n",p,
	    debugfile->flags);
    fprintf(ud->stream,"%s    refcnt:   %d\n",p,debugfile->refcnt);
    fprintf(ud->stream,"%s  types: (%d)\n",p,g_hash_table_size(debugfile->types));
    if (types) 
	g_hash_table_foreach(debugfile->types,g_hash_foreach_dump_symbol,&udn);
    fprintf(ud->stream,"%s  shared_types: (%d)\n",
	    p,g_hash_table_size(debugfile->shared_types));
    if (types) 
	g_hash_table_foreach(debugfile->shared_types,
			     g_hash_foreach_dump_symbol,&udn);
    fprintf(ud->stream,"%s  globals: (%d)\n",
	    p,g_hash_table_size(debugfile->globals));
    if (globals) 
	g_hash_table_foreach(debugfile->globals,g_hash_foreach_dump_symbol,&udn);
    fprintf(ud->stream,"%s  root srcfiles: (%d)\n",
	    p,g_hash_table_size(debugfile->srcfiles));
    //ud->prefix = np1;
    if (symtabs) {
	g_hash_table_foreach(debugfile->srcfiles,g_hash_foreach_dump_symbol,&udn);
	if (g_hash_table_size(debugfile->srcfiles))
	    fprintf(ud->stream,"\n");
    }
    fprintf(ud->stream,"%s  multi-use srcfile symtabs: (%d)\n",
	    p,g_hash_table_size(debugfile->srcfiles_multiuse));
    if (symtabs) {
	g_hash_table_foreach(debugfile->srcfiles_multiuse,
			     g_hash_foreach_dump_symbol_list,&udn);
	if (g_hash_table_size(debugfile->srcfiles_multiuse))
	    fprintf(ud->stream,"\n");
    }
    if (debugfile->binfile 
	&& debugfile->binfile->root
	&& symbol_read_owned_scope(debugfile->binfile->root)) {
	scope_get_sizes(symbol_read_owned_scope(debugfile->binfile->root),
			&s1,&s2,&s3,&s4);
	fprintf(ud->stream,
		"%s  binfile root: (tab=%d,anon=%d,dup=%d,subscopes=%d)\n",
		p,s1,s2,s3,s4);
	if (elfsymtab) {
	    symbol_dump(debugfile->binfile->root,&udn);
	    fprintf(ud->stream,"\n");
	}
    }
    else 
	fprintf(ud->stream,
		"%s  binfile root: (tab=%d,anon=%d,dup=%d)\n",
		p,0,0,0);
    if (debugfile->binfile_pointing 
	&& debugfile->binfile_pointing->root
	&& symbol_read_owned_scope(debugfile->binfile->root)) {
	scope_get_sizes(symbol_read_owned_scope(debugfile->binfile_pointing->root),
			&s1,&s2,&s3,&s4);
	fprintf(ud->stream,
		"%s  binfile_pointing root: (tab=%d,anon=%d,dup=%d,subscopes=%d)\n",
		p,s1,s2,s3,s4);
	if (elfsymtab) {
	    symbol_dump(debugfile->binfile_pointing->root,&udn);
	    fprintf(ud->stream,"\n");
	}
    }
    else
	fprintf(ud->stream,
		"%s  binfile_pointing root: (tab=%d,anon=%d,dup=%d)\n",
		p,0,0,0);

    if (ud->prefix) {
	free(np1);
	free(np2);
    }
}

void symbol_root_dump(struct symbol *symbol,struct dump_info *ud) {
    SYMBOL_RX_ROOT(symbol,sr);

    fprintf(ud->stream,"%s",symbol_get_name(symbol));

    fprintf(ud->stream," (compdirname=%s,producer=%s,language=%s (%d))",
	    sr->compdirname,sr->producer,sr->language,sr->lang_code);

    if (ud->detail && sr->scope) {
	fprintf(ud->stream," {\n");
	scope_dump(sr->scope,ud);
	fprintf(ud->stream,"%s}\n",ud->prefix);
    }
    else 
	fprintf(ud->stream," { }\n");
}

void symbol_label_dump(struct symbol *symbol,struct dump_info *ud) {
    fprintf(ud->stream,"%s @@ 0x%"PRIxADDR,
	    symbol_get_name(symbol),symbol_get_addr(symbol));
}

void symbol_block_dump(struct symbol *symbol,struct dump_info *ud) {
    struct scope *scope;
    struct dump_info udn = {
	.stream = ud->stream,
	.prefix = "",
	.detail = ud->detail,
	.meta = ud->meta,
    };

    fprintf(ud->stream,"%s (@@ 0x%"PRIxADDR")",
	    symbol_get_name(symbol),symbol_get_addr(symbol));
    if (ud->detail) {
	scope = symbol_read_owned_scope(symbol);
	if (scope)
	    scope_dump(scope,&udn);
    }
}

void symbol_var_dump(struct symbol *symbol,struct dump_info *ud) {
    GSList *gsltmp;
    struct symbol *iisymbol;
    struct symbol *datatype;
    struct dump_info udn = {
	.stream = ud->stream,
	.prefix = ud->prefix,
	.detail = 0,
	.meta = 0,
    };

    datatype = symbol_get_datatype_real(symbol);

    if (ud->detail) {
	if (datatype) {
	    symbol_type_dump(datatype,&udn);
	}
	else if (symbol->datatype_ref) 
	    fprintf(ud->stream,"ref%"PRIxSMOFFSET,symbol->datatype_ref);
    }
    /* all variables are named, but not all members of structs/unions! */
    /* well, inlined params aren't named either. */
    SYMBOL_RX_INLINE(symbol,sii);
    if (symbol->isinlineinstance && symbol->isparam) {
	/* Only print a space if we printed the var's type above! */
	if (ud->detail)
	    fprintf(ud->stream," ");

	if (sii) {
	    if (sii->origin) {
		fprintf(ud->stream,"INLINED_PARAM(");
		symbol_var_dump(sii->origin,&udn);
		fprintf(ud->stream,")");
	    }
	    else
		fprintf(ud->stream,"INLINED_ANON_PARAM()");
	}
	else {
	    fprintf(ud->stream,"INLINED_PARAM(<UNK>)");
	}
    }
    else if (symbol->isinlineinstance) {
	/* Only print a space if we printed the var's type above! */
	if (ud->detail)
	    fprintf(ud->stream," ");

	if (sii) {
	    if (sii->origin) {
		fprintf(ud->stream,"INLINED_INSTANCE(");
		symbol_var_dump(sii->origin,&udn);
		fprintf(ud->stream,") (%s)",symbol_get_name_orig(symbol));
	    }
	    else
		fprintf(ud->stream,"INLINED_ANON_INSTANCE(%s)",
			symbol_get_name(symbol));
	}
	else {
	    fprintf(ud->stream,"INLINED_INSTANCE(%s)",
		    symbol_get_name_orig(symbol));
	}
    }
    else if (symbol->name) {
	/* Only print a space if we printed the var's type above! */
	if (ud->detail)
	    fprintf(ud->stream," ");

	fprintf(ud->stream,"%s",symbol_get_name(symbol));
    }

    if (symbol->size_is_bits) {
	/* this is a bitfield */
	fprintf(ud->stream,":%hd(%hd)(ct %d B)",
		symbol_get_bitsize(symbol),symbol_get_bitoffset(symbol),
		symbol_get_bitctbytes(symbol));
    }
    if (symbol->isenumval && SYMBOLX_VAR_CONSTVAL(symbol)) {
	// XXX fix type printing -- this *is* a malloc'd constval
	fprintf(ud->stream," = %d",*((int *)SYMBOLX_VAR_CONSTVAL(symbol)));
    }

    if (ud->meta) {
	fprintf(ud->stream," (");
	if (!symbol->isparam && !symbol->ismember) {
	    fprintf(ud->stream,
		    "external=%d,isdecl=%d,decldefined=%d,"
		    "declinline=%d,inlined=%d",
		    symbol->isexternal,symbol->isdeclaration,symbol->decldefined,
		    symbol->isdeclinline,symbol->isinlined);
	}
	if (sii && sii->inline_instances) {
	    fprintf(ud->stream,",inlineinstances=(");
	    v_g_slist_foreach(sii->inline_instances,gsltmp,iisymbol) {
		fprintf(ud->stream,"0x%"PRIxADDR",",
			symbol_get_addr(iisymbol));
	    }
	    fprintf(ud->stream,")");
	}
	fprintf(ud->stream,")");
    }

    if (ud->detail) {
	if (SYMBOLX_VAR_LOC(symbol)) {
	    fprintf(ud->stream," @@ ");
	    location_dump(SYMBOLX_VAR_LOC(symbol),ud);
	}

	if (SYMBOLX_VAR_CONSTVAL(symbol)) 
	    fprintf(ud->stream," @@ CONST(%p)",SYMBOLX_VAR_CONSTVAL(symbol));

	if (symbol->has_addr)
	    fprintf(ud->stream," @@ 0x%"PRIxADDR,symbol_get_addr(symbol));

	if (symbol->size_is_bytes)
	    fprintf(ud->stream," (size=%d B)",symbol_get_bytesize(symbol));
	else if (symbol->size_is_bits)
	    fprintf(ud->stream," (size=%d b)",symbol_get_bitsize(symbol));
    }
}

void symbol_function_dump(struct symbol *symbol,struct dump_info *ud) {
    struct symbol *datatype;
    GSList *members;
    GSList *gsltmp;
    struct symbol *member;
    struct symbol *iisymbol;
    int i = 0;
    struct dump_info udn = {
	.stream = ud->stream,
	.prefix = ud->prefix,
	.detail = 0,
	.meta = 0,
    };
    struct dump_info udn2 = {
	.stream = ud->stream,
	.prefix = "",
	.detail = ud->detail,
	.meta = ud->meta,
    };

    SYMBOL_RX_INLINE(symbol,sii);
    SYMBOL_RX_FUNC(symbol,sf);

    datatype = symbol_get_datatype_real(symbol);

    if (ud->detail) {
	if (datatype) {
	    symbol_type_dump(datatype,&udn);
	    fprintf(ud->stream," ");
	}
	else if (symbol->datatype_ref)
	    fprintf(ud->stream,"ref%"PRIxSMOFFSET" ",symbol->datatype_ref);
    }
    if (symbol->isinlineinstance) {
	if (sii) {
	    if (sii->origin) {
		fprintf(ud->stream,"INLINED_FUNC(");
		symbol_var_dump(sii->origin,&udn);
		fprintf(ud->stream,") (%s)",symbol_get_name_orig(symbol));
	    }
	    else
		fprintf(ud->stream,"INLINED_ANON_FUNC() (%s)",
			symbol_get_name_orig(symbol));
	}
	else {
	    fprintf(ud->stream,"INLINED_FUNC(<UNK>)");
	}
    }
    else 
	fprintf(ud->stream,"%s",symbol_get_name(symbol));
    if (ud->detail) {
	fprintf(ud->stream," (");

	members = SYMBOLX_MEMBERS(symbol);
	i = 0;
	v_g_slist_foreach(members,gsltmp,member) {
	    if (likely(i > 0))
		fprintf(ud->stream,", ");
	    symbol_var_dump(member,ud);
	    ++i;
	}
	if (symbol->has_unspec_params) 
	    fprintf(ud->stream,"...");

	fprintf(ud->stream,")");

	if (SYMBOLX_VAR_CONSTVAL(symbol))
	    fprintf(ud->stream," @@ CONST(%p)",SYMBOLX_VAR_CONSTVAL(symbol));
    }

    if (ud->meta) {
	fputs(" (",ud->stream);
	if (symbol->has_addr)
	    fprintf(ud->stream,"addr=0x%"PRIxADDR",",symbol_get_addr(symbol));
	if (symbol->isexternal)
	    fputs("external,",ud->stream);
	if (symbol->isexternal)
	    fputs("prototyped,",ud->stream);
	if (symbol->isdeclaration)
	    fputs("decl,",ud->stream);
	if (symbol->decldefined)
	    fputs("decldefined,",ud->stream);
	if (symbol->isdeclinline)
	    fputs("declinline,",ud->stream);
	if (symbol->isinlined)
	    fputs("inlined,",ud->stream);
	if (sf && sf->fbloc) {
	    fputs("frame_base=",ud->stream);
	    location_dump(sf->fbloc,&udn2);
	    fputs(",",ud->stream);
	}

	if (sii && sii->inline_instances) {
	    fputs("inlineinstances=(",ud->stream);
	    v_g_slist_foreach(sii->inline_instances,gsltmp,iisymbol) {
		if (iisymbol->has_addr) 
		    fprintf(ud->stream,"0x%"PRIxADDR",",
			    symbol_get_addr(iisymbol));
		else
		    fprintf(ud->stream,"REF(%"PRIxSMOFFSET"),",iisymbol->ref);
	    }
	    fputs(")",ud->stream);
	}
	fputs(")",ud->stream);
    }

    if (ud->detail) {
	if (symbol->has_addr)
	    fprintf(ud->stream," @@ 0x%"PRIxADDR,symbol_get_addr(symbol));
	if (symbol->size_is_bytes)
	    fprintf(ud->stream," (size=%d B)",symbol_get_bytesize(symbol));
	else if (symbol->size_is_bits)
	    fprintf(ud->stream," (size=%d b)",symbol_get_bitsize(symbol));

	if (sf && sf->scope)
	    scope_dump(sf->scope,&udn);
    }
}

void symbol_type_dump(struct symbol *symbol,struct dump_info *ud) {
    struct symbol *tmp;
    GSList *members;
    struct symbol *member;
    struct symbol *member_datatype;
    GSList *gsltmp;
    void *elm;
    int i = 0;
    char *ss;
    struct dump_info udn = {
	.stream = ud->stream,
	.prefix = ud->prefix,
	.detail = 0,
	.meta = 0,
    };

    if (!symbol) {
	fprintf(ud->stream,"<UNK>");
	return;
    }

    switch (symbol->datatype_code) {
    case DATATYPE_VOID:
	fprintf(ud->stream,"void");
	break;
    case DATATYPE_ARRAY:
	symbol_type_dump(symbol_get_datatype_real(symbol),&udn);
	if (SYMBOLX_SUBRANGES(symbol)) {
	    fprintf(ud->stream," ");
	    v_g_slist_foreach(SYMBOLX_SUBRANGES(symbol),gsltmp,elm) {
		fprintf(ud->stream,"[%d]",((int)(uintptr_t)elm) + 1);
	    }
	}
	else {
	    fprintf(ud->stream,"[<UNK>]");
	}
	break;
    case DATATYPE_CONST:
	fprintf(ud->stream,"const ");
	symbol_type_dump(symbol_get_datatype_real(symbol),ud);
	break;
    case DATATYPE_VOL:
	fprintf(ud->stream,"volatile ");
	symbol_type_dump(symbol_get_datatype_real(symbol),ud);
	break;
    case DATATYPE_STRUCT:
    case DATATYPE_UNION:
    case DATATYPE_CLASS:
    case DATATYPE_NAMESPACE:
	ss = "struct";
	if (SYMBOL_IST_UNION(symbol))
	    ss = "union";
	else if (SYMBOL_IST_CLASS(symbol))
	    ss = "class";
	else if (SYMBOL_IST_NAMESPACE(symbol))
	    ss = "namespace";
	if (!symbol->name)
	    fprintf(ud->stream,"%s",ss);
	else
	    fprintf(ud->stream,"%s",symbol->name);
	if (ud->meta) {
	    if (symbol->size_is_bytes)
		fprintf(ud->stream," (size=%d B)",symbol->size.bytes);
	    else if (symbol->size_is_bits)
		fprintf(ud->stream," (size=%d b)",symbol->size.bits);
	}
	if (ud->detail && SYMBOL_HAS_EXTRA(symbol)) {
	    fprintf(ud->stream," { ");

	    members = SYMBOLX_MEMBERS(symbol);
	    i = 0;
	    v_g_slist_foreach(members,gsltmp,member) {
		if (likely(i > 0))
		    fprintf(ud->stream,"; ");

		/* NOTE: C structs/unions can have members of the same
		 * type as the parent struct -- so don't recurse if this
		 * is true! -- OR if it's a pointer chain back to the struct.
		 */
		member_datatype = symbol_get_datatype_real(member);
		if (member_datatype == symbol) {
		    symbol_var_dump(member,&udn);
		}
		else if (member_datatype 
			 && SYMBOL_IST_STUN(member_datatype) 
			 && !member_datatype->name) {
		    symbol_type_dump(member_datatype,ud);

		    if (ud->detail && SYMBOLX_VAR_LOC(member)) {
			fprintf(ud->stream," @@ ");
			location_dump(SYMBOLX_VAR_LOC(member),ud);
		    }

		    if (SYMBOLX_VAR_CONSTVAL(member))
			fprintf(ud->stream," @@ CONST(%p)",
				SYMBOLX_VAR_CONSTVAL(member));
		}
		else 
		    symbol_var_dump(member,ud);

		++i;
	    }
	    fprintf(ud->stream," }");
	}
	break;
    case DATATYPE_ENUM:
	if (!symbol_get_name(symbol))
	    fprintf(ud->stream,"enum");
	else
	    fprintf(ud->stream,"%s",symbol_get_name(symbol));
	if (ud->meta) {
	    if (symbol->size_is_bytes)
		fprintf(ud->stream," (size=%d B)",symbol_get_bytesize(symbol));
	    else if (symbol->size_is_bits)
		fprintf(ud->stream," (size=%d b)",symbol_get_bitsize(symbol));
	}
	if (ud->detail && SYMBOL_HAS_EXTRA(symbol)) {
	    fprintf(ud->stream," { ");

	    members = SYMBOLX_MEMBERS(symbol);
	    i = 0;
	    v_g_slist_foreach(members,gsltmp,member) {
		if (likely(i > 0))
		    fprintf(ud->stream,", ");
		symbol_var_dump(member,&udn);
		++i;
	    }
	    fprintf(ud->stream," }");
	}
	break;
    case DATATYPE_PTR:
	/* NOTE: C structs/unions can have members of the same
	 * type as the parent struct -- so don't recurse if this
	 * is true! -- OR if it's a pointer chain back to the struct.
	 * So for the pointer chain, allow the detail flag set to 1 as
	 * long as the next type is a pointer.  Otherwise, halt the
	 * recursion of detail since for pointers we never want detail
	 * of the pointer-to type, just the name --- AND since we might
	 * be pointing back to a type that we're already printing, like
	 * a struct member var that is a pointer to the struct type
	 * itself.
	 *
	 * Basically, if the pointed-to type will not recurse in this
	 * function, it's safe to print details for it; otherwise, it's
	 * not... I think!
	 */
	tmp = symbol_get_datatype_real(symbol);
	if (tmp) {
	    if (SYMBOL_IST_PTR(tmp) || SYMBOL_IST_VOID(tmp) || SYMBOL_IST_BASE(tmp)) 
		symbol_type_dump(tmp,ud);
	    else 
		symbol_type_dump(tmp,&udn);
	    fprintf(ud->stream,"*");
	}
	else
	    fprintf(ud->stream,"ref%"PRIxSMOFFSET" *",
		    symbol->datatype_ref);
	break;
    case DATATYPE_REF:
	/*
	 * Same as DATATYPE_PTR case above, basically.  Just & instead of * .
	 */
	tmp = symbol_get_datatype_real(symbol);
	if (tmp) {
	    if (SYMBOL_IST_PTR(tmp) || SYMBOL_IST_VOID(tmp) || SYMBOL_IST_BASE(tmp)) 
		symbol_type_dump(tmp,ud);
	    else 
		symbol_type_dump(tmp,&udn);
	    fprintf(ud->stream,"&");
	}
	else
	    fprintf(ud->stream,"ref%"PRIxSMOFFSET" &",
		    symbol->datatype_ref);
	break;
    case DATATYPE_FUNC:
	if (ud->detail)
	    symbol_type_dump(symbol_get_datatype_real(symbol),ud);

	if (!symbol->name) 
	    fprintf(ud->stream,"()");
	else
	    fprintf(ud->stream,"(%s)",symbol_get_name(symbol));

	if (ud->meta)
	    fprintf(ud->stream," (prototyped=%d,external=%d) ",
		    symbol->isprototyped,symbol->isexternal);

	if (ud->detail && SYMBOL_HAS_EXTRA(symbol)) {
	    fprintf(ud->stream,"(");

	    members = SYMBOLX_MEMBERS(symbol);
	    i = 0;
	    v_g_slist_foreach(members,gsltmp,member) {
		if (likely(i > 0))
		    fprintf(ud->stream,", ");
		symbol_var_dump(member,ud);
		++i;
	    }
	    if (symbol->has_unspec_params) 
		fprintf(ud->stream,"...");

	    fprintf(ud->stream,")");
	}
	break;
    case DATATYPE_TYPEDEF:
	if (!ud->detail)
	    fprintf(ud->stream,"%s",symbol_get_name(symbol));
	else if (symbol_get_datatype_real(symbol)) {
	    fprintf(ud->stream,"typedef ");
	    symbol_type_dump(symbol_get_datatype_real(symbol),ud);
	    fprintf(ud->stream," %s",symbol_get_name_orig(symbol));
	}
	else 
	    fprintf(ud->stream,"typedef ref%"PRIxSMOFFSET" %s",
		    symbol->datatype_ref,symbol_get_name(symbol));
	break;
    case DATATYPE_BASE:
	if (!ud->meta)
	    fprintf(ud->stream,"%s",symbol->name);
	else  {
	    if (symbol->size_is_bytes)
		fprintf(ud->stream," (size=%d B)",symbol_get_bytesize(symbol));
	    else if (symbol->size_is_bits)
		fprintf(ud->stream," (size=%d b)",symbol_get_bitsize(symbol));
	    fprintf(ud->stream," (encoding=%d)",SYMBOLX_ENCODING_V(symbol));
	}
	break;
    default:
	vwarn("unknown datatype_code %d!\n",symbol->datatype_code);
    }
}

void symbol_dump(struct symbol *symbol,struct dump_info *ud) {
    char *p = "";
    char *np;
    struct dump_info udn;

    if (ud->prefix) {
	p = ud->prefix;
	np = malloc(strlen(p) + 1 + 2);
	sprintf(np,"%s%s",p,"  ");
    }
    else {
	np = "  ";
    }
    udn.prefix = np;
    udn.stream = ud->stream;
    udn.meta = ud->meta;
    udn.detail = ud->detail;

    if (symbol->type == SYMBOL_TYPE_TYPE) {
	fprintf(ud->stream,"%stype(%s,line=%d): ",
		p,symbol->name,
		symbol->srcline);
	symbol_type_dump(symbol,&udn);
    }
    else if (symbol->type == SYMBOL_TYPE_ROOT) {
	fprintf(ud->stream,"%sroot(%s,line=%d): ",
		p,symbol->name,symbol->srcline);
	symbol_root_dump(symbol,&udn);
    }
    else if (symbol->type == SYMBOL_TYPE_VAR) {
	fprintf(ud->stream,"%svar(%s,line=%d): ",
		p,symbol->name,symbol->srcline);
	symbol_var_dump(symbol,&udn);
    }
    else if (symbol->type == SYMBOL_TYPE_FUNC) {
	fprintf(ud->stream,"%sfunction(%s,line=%d): ",
		p,symbol->name,symbol->srcline);
	symbol_function_dump(symbol,&udn);
    }
    else if (symbol->type == SYMBOL_TYPE_LABEL) {
	fprintf(ud->stream,"%slabel(%s,line=%d): ",
		p,symbol->name,symbol->srcline);
	symbol_label_dump(symbol,&udn);
    }
    else if (symbol->type == SYMBOL_TYPE_BLOCK) {
	fprintf(ud->stream,"%sblock(%s,line=%d): ",
		p,symbol->name ? symbol->name : "",symbol->srcline);
	symbol_block_dump(symbol,&udn);
    }
    else {
	fprintf(ud->stream,"unknown symbol type %d!\n",symbol->type);
    }

    if (ud->prefix)
	free(np);
}

void lsymbol_dump(struct lsymbol *lsymbol,struct dump_info *ud) {
    int i = 0;
    int len;
    struct dump_info udn = {
	.stream = ud->stream,
	.detail = ud->detail,
	.meta = ud->meta,
    };
    char *prefixbuf = NULL;
	
    fprintf(ud->stream,"%slsymbol:\n",ud->prefix);

    if (lsymbol->chain && array_list_len(lsymbol->chain)) {
	prefixbuf = malloc(strlen(ud->prefix) + (array_list_len(lsymbol->chain) + 1) * 2 + 1);
	sprintf(prefixbuf,"%s  ",ud->prefix);
	len = strlen(prefixbuf);

	udn.prefix = prefixbuf;

	while (1) {
	    symbol_dump((struct symbol *)array_list_item(lsymbol->chain,i),&udn);
	    if (++i == array_list_len(lsymbol->chain))
		break;
	    fprintf(ud->stream,"\n");
	    prefixbuf[len++] = ' ';
	    prefixbuf[len++] = ' ';
	    prefixbuf[len] = '\0';
	}
    }
    else if (lsymbol->symbol) {
	prefixbuf = malloc(strlen(ud->prefix) + 2 + 1);
	sprintf(prefixbuf,"%s  ",ud->prefix);
	udn.prefix = prefixbuf;
	symbol_dump(lsymbol->symbol,&udn);
    }

    if (prefixbuf)
	free(prefixbuf);
}
