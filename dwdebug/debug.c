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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <regex.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <glib.h>

#include "log.h"
#include "output.h"
#include "list.h"
#include "alist.h"
#include "rfilter.h"
#include "dwdebug.h"

static char *LIBFORMAT1 = "([\\w\\d_\\.\\-]+[\\w\\d]).so.([\\d\\.]+)";
static char *LIBFORMAT2 = "([\\w\\d_\\.\\-]+[\\w\\d]).so";
static regex_t LIBREGEX1;
static regex_t LIBREGEX2;

void dwdebug_init(void) {
    regcomp(&LIBREGEX1,LIBFORMAT1,REG_EXTENDED);
    regcomp(&LIBREGEX2,LIBFORMAT2,REG_EXTENDED);
}

void dwdebug_fini(void) {
    regfree(&LIBREGEX1);
    regfree(&LIBREGEX2);
}

/*
 * Some generic GHashTable util functions for freeing hashtables.
 */
gboolean always_remove(gpointer key __attribute__((unused)),
		       gpointer value __attribute__((unused)),
		       gpointer user_data __attribute__((unused))) {
    return TRUE;
}

static void ghash_symtab_free(gpointer data) {
    struct symtab *symtab = (struct symtab *)data;

    vdebug(5,LOG_D_SYMTAB,"freeing symtab(%s:%s)\n",
	   symtab->debugfile->idstr,symtab->name);
    symtab_free(symtab);
}

static void ghash_symbol_free(gpointer data) {
    struct symbol *symbol = (struct symbol *)data;

    vdebug(5,LOG_D_SYMBOL,"freeing symbol(%s:%s:%s) %p\n",
	   symbol->symtab->debugfile->idstr,symbol->symtab->name,
	   symbol->name,data);
    /* We force-free the symbol; this function is only called if its
     * symtab is going away.  All symbols have to be on a symtab, so
     * we're inconsistent if we don't force it to be freed!
     *
     * If anybody is still holding a ref at this point, that's their
     * fault and they have to fix it.
     *
     * Wait, now that we share symbols between CUs, we cannot force free
     * anymore!
     */
    if (symbol->isshared)
	symbol_release(symbol);
    else 
	symbol_free(symbol,0);
}

/**
 ** Local prototypes.
 **/
static struct symbol *__symbol_get_one_member(struct symbol *symbol,char *member,
					      struct array_list **chainptr);

/**
 ** PC lookup functions.
 **/
/*
 * NOTE: this function returns the tightest bounding symtab -- which may
 * be the symtab that was passed in!!
 */
struct symtab *symtab_lookup_pc(struct symtab *symtab,ADDR pc) {
    struct symtab *tmp;
    struct symtab *retval;
    int i;

    /*
     * It is tempting to think we can just check the lowpc and
     * highpc vals for this symtab before checking its children, but
     * we can't do that.  Some symtabs may have children whose
     * ranges are outside the parent -- i.e., a function defined in
     * another.  So we can't even check the parent ranges before doing
     * DFS!
     *
     * In other words, we need the tightest bound.
     */
    list_for_each_entry(tmp,&symtab->subtabs,member) {
	retval = symtab_lookup_pc(tmp,pc);
	if (retval)
	    return retval;
    }

    /*
     * Then check our symtab.
     *
     * XXX: check range list ranges too!!!
     */
    if (RANGE_IS_PC(&symtab->range)
	&& symtab->range.r.a.lowpc <= pc && pc < symtab->range.r.a.highpc) {
	return symtab;
    }
    else if (RANGE_IS_LIST(&symtab->range)) {
	for (i = 0; i < symtab->range.r.rlist.len; ++i) {
	    if (symtab->range.r.rlist.list[i]->start <= pc 
		&& pc < symtab->range.r.rlist.list[i]->end)
		return symtab;
	}
    }

    return NULL;
}

/**
 ** Symbol lookup functions.
 **/
static struct lsymbol *__symtab_lookup_sym(struct symtab *symtab,
					   const char *name,const char *delim,
					   symbol_type_flag_t ftype) {
    char *next = NULL;
    char *lname = NULL;
    char *saveptr = NULL;
    struct array_list *anonchain = NULL;
    int i;
    struct lsymbol *lsymbol = NULL;
    struct lsymbol *lsymbol_tmp = NULL;
    struct symbol *symbol = NULL;
    struct array_list *chain = NULL;
    struct symbol *svalue;
    struct symtab *subtab;
    struct array_list *duplist;

    if (delim && strstr(name,delim)) {
	lname = strdup(name);
	next = strtok_r(!saveptr ? lname : NULL,delim,&saveptr);
	chain = array_list_create(1);
    }
    else
	next = (char *)name;

    /* 
     * Do the first token by looking up in this symtab, or its duptab
     * table.
     */
    if ((svalue = (struct symbol *)g_hash_table_lookup(symtab->tab,next))
	&& (ftype == SYMBOL_TYPE_FLAG_NONE
	    || ((ftype & SYMBOL_TYPE_FLAG_TYPE && SYMBOL_IS_TYPE(svalue))
		|| (ftype & SYMBOL_TYPE_FLAG_VAR && SYMBOL_IS_VAR(svalue))
		|| (ftype & SYMBOL_TYPE_FLAG_FUNCTION 
		    && SYMBOL_IS_FUNCTION(svalue))
		|| (ftype & SYMBOL_TYPE_FLAG_LABEL 
		    && SYMBOL_IS_LABEL(svalue))))) {
	    /* If this is a type symbol, or a symbol with a location,
	     * allow it to match right away; else, save it off if we
	     * haven't already saved off a "first match"; else, save it
	     * off and return it if we don't find anything better!
	     */
	symbol = svalue;
	if (SYMBOL_IS_TYPE(svalue)) 
	    vdebug(3,LOG_D_LOOKUP,
		   "found top-level symtab type %s\n",symbol->name);
	else if (!svalue->isdeclaration) 
	    vdebug(3,LOG_D_LOOKUP,
		   "found top-level symtab definition %s\n",symbol->name);
	else 
	    vdebug(3,LOG_D_LOOKUP,
		   "found top-level symtab non-type, non-definition %s; saving\n",
		   symbol->name);
    }
    /* If it's in the duptab table, figure out which match is best; we
     * prefer the first non-type definition, unless they're looking for
     * a type.
     */
    else if ((duplist = (struct array_list *) \
	      g_hash_table_lookup(symtab->duptab,next))) {
	for (i = 0; i < array_list_len(duplist); ++i) {
	    svalue = (struct symbol *)array_list_item(duplist,i);
	    if (ftype == SYMBOL_TYPE_FLAG_NONE
		|| ((ftype & SYMBOL_TYPE_FLAG_TYPE && SYMBOL_IS_TYPE(svalue))
		    || (ftype & SYMBOL_TYPE_FLAG_VAR && SYMBOL_IS_VAR(svalue))
		    || (ftype & SYMBOL_TYPE_FLAG_FUNCTION 
			&& SYMBOL_IS_FUNCTION(svalue))
		    || (ftype & SYMBOL_TYPE_FLAG_LABEL 
			&& SYMBOL_IS_LABEL(svalue)))) {
		/* If this is a type symbol, or a symbol with a location,
		 * allow it to match right away; else, save it off if we
		 * haven't already saved off a "first match"; else, save it
		 * off and return it if we don't find anything better!
		 */
		if (SYMBOL_IS_TYPE(svalue)) {
		    symbol = svalue;
		    vdebug(3,LOG_D_LOOKUP,
			   "found top-level dup symtab type %s\n",symbol->name);
		    break;
		}
		else if (!svalue->isdeclaration) {
		    symbol = svalue;
		    vdebug(3,LOG_D_LOOKUP,
			   "found top-level dup symtab definition %s\n",symbol->name);
		    break;
		}
		else if (!symbol) {
		    symbol = svalue;
		    vdebug(3,LOG_D_LOOKUP,
			   "found top-level dup symtab non-type, non-definition"
			   " %s; saving and continuing search\n",
			   symbol->name);
		}
	    }
	}
    }

    /*
     * If we didn't find a match in our symtab, OR if the symbol was
     * a non-type declaration, keep looking for a type or definition in our
     * subtabs.
     */
    if ((!symbol || (symbol && !SYMBOL_IS_TYPE(symbol) 
		     && symbol->isdeclaration))
	&& !list_empty(&symtab->subtabs)) {
	vdebug(3,LOG_D_LOOKUP,
	       "checking symtab anon subtabs\n");
	//!SYMBOL_IS_FULL(symbol) || symbol->s.ii->l.loctype == LOCTYPE_UNKNOWN)
	list_for_each_entry(subtab,&symtab->subtabs,member) {
	    /*
	     * We only search anonymous subtabs, because if the user is
	     * looking for something nested, we need them to actually
	     * specify a fully-qualified string.
	     *
	     * We could relax this constraint later on, but only if they
	     * give us a flag, because otherwise if you look for `i',
	     * your result will have very little meaning.
	     *
	     * XXX: what about inlined instances of variables or
	     * functions?  How can we let users search for these?
	     */
	    if (!subtab->name) {
		lsymbol_tmp = __symtab_lookup_sym(subtab,name,delim,ftype);
		if (lsymbol_tmp) {
		    if (SYMBOL_IS_TYPE(lsymbol_tmp->symbol)) {
			lsymbol = lsymbol_tmp;
			vdebug(3,LOG_D_LOOKUP,
			       "found anon symtab type %s\n",
			       lsymbol->symbol->name);
			goto recout;
		    }
		    else if (!lsymbol_tmp->symbol->isdeclaration) {
			     //SYMBOL_IS_FULL(lsymbol_tmp->symbol) 
			     // && lsymbol_tmp->symbol->s.ii->l.loctype 
			     //    != LOCTYPE_UNKNOWN) {
			lsymbol = lsymbol_tmp;
			vdebug(3,LOG_D_LOOKUP,
			       "found anon symtab definition %s\n",
			       lsymbol->symbol->name);
			goto recout;
		    }
		    else if (!lsymbol) {
			lsymbol = lsymbol_tmp;
			vdebug(3,LOG_D_LOOKUP,
			       "found anon symtab non-type, non-definition %s; saving\n",
			       lsymbol->symbol->name);
		    }
		    else {
			/* Don't force free; somebody else might be
			 * holding a ref!
			 */
			lsymbol_free(lsymbol_tmp,0);
		    }
		}
	    }
	}

    recout:
	if (lsymbol) {
	    if (lname) {
		free(lname);
		lname = NULL;
	    }
	    if (chain) {
		array_list_free(chain);
		chain = NULL;
	    }

	    vdebug(3,LOG_D_LOOKUP,
		   "returning best subtab symbol %s\n",
		   lsymbol->symbol->name);

	    return lsymbol;
	}
    }

    if (!symbol)
	goto errout;

    lsymbol = lsymbol_create(symbol,chain);

    /* If it's not a delimited string, stop now, successfully. */
    if (!lname) {
	vdebug(3,LOG_D_LOOKUP,"found plain %s\n",
	       lsymbol->symbol->name);

	/* Make sure the chain is not NULL and that we take a ref to
	 * symbol.
	 */
	lsymbol_append(lsymbol,symbol);

	return lsymbol;
    }

    vdebug(3,LOG_D_LOOKUP,
	   "found top-level %s; checking members\n",lsymbol->symbol->name);

    /* Otherwise, add the first one to our chain and start looking up
     * members.
     */
    lsymbol_append(lsymbol,symbol);

    if (!delim)
	delim = DWDEBUG_DEF_DELIM;

    while ((next = strtok_r(!saveptr ? lname : NULL,delim,&saveptr))) {
	if (!(symbol = __symbol_get_one_member(symbol,next,&anonchain)))
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
	/* Don't force free; somebody else might have a ref! */
	lsymbol_free(lsymbol,0);

    return NULL;
}

struct lsymbol *symtab_lookup_sym(struct symtab *symtab,
				  const char *name,const char *delim,
				  symbol_type_flag_t ftype) {
    struct lsymbol *ls = __symtab_lookup_sym(symtab,name,delim,ftype);

    /* __symtab_lookup_sym already held refs to all the symbols on our
     * chain.
     */
    if (ls)
	lsymbol_hold(ls);

    return ls;
}
static struct symbol *__symtab_get_sym(struct symtab *symtab,const char *name) {
    struct symbol *symbol = NULL;
    struct symtab *subtab;
    struct array_list *duplist;

    /* 
     * Do the first token by looking up in this symtab.
     */
    if ((symbol = (struct symbol *)g_hash_table_lookup(symtab->tab,name)))
	return symbol;
    else if ((duplist = (struct array_list *) \
	      g_hash_table_lookup(symtab->duptab,name)))
	/* Just return the first duplicate for now. */
	return (struct symbol *)array_list_item(duplist,0);

    /*
     * If we didn't find a match in our symtab, keep looking in our subtabs.
     */
    list_for_each_entry(subtab,&symtab->subtabs,member) {
	/*
	 * We only search anonymous subtabs, because if the user is
	 * looking for something nested, we need them to actually
	 * specify a fully-qualified string.
	 *
	 * We could relax this constraint later on, but only if they
	 * give us a flag, because otherwise if you look for `i',
	 * your result will have very little meaning.
	 *
	 * XXX: what about inlined instances of variables or
	 * functions?  How can we let users search for these?
	 */
	if (!subtab->name) {
	    if ((symbol = __symtab_get_sym(subtab,name)))
		return symbol;
	}
    }

    return NULL;
}

struct symbol *symtab_get_sym(struct symtab *symtab,const char *name) {
    return __symtab_get_sym(symtab,name);
}

static struct lsymbol *__symbol_lookup_sym(struct symbol *symbol,
					   const char *name,const char *delim) {

    char *next;
    char *lname = NULL;
    char *saveptr = NULL;
    struct array_list *anonchain = NULL;
    int i;
    struct lsymbol *lsymbol = NULL;
    struct array_list *chain = array_list_create(0);

    if (!SYMBOL_IS_FULL_TYPE(symbol) && !SYMBOL_IS_FULL_FUNCTION(symbol)) {
	verror("symbol %s is not a full type nor a full function!\n",
	       symbol_get_name(symbol));
	return NULL;
    }

    lname = strdup(name);

    /* Add the first one to our chain and start looking up members. */
    lsymbol = lsymbol_create(symbol,chain);
    lsymbol_append(lsymbol,symbol);

    vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,
	   "starting at top-level %s: checking members\n",
	   symbol_get_name(symbol));

    if (!delim)
	delim = DWDEBUG_DEF_DELIM;

    while ((next = strtok_r(!saveptr ? lname : NULL,delim,&saveptr))) {
	if (!(symbol = __symbol_get_one_member(symbol,next,&anonchain)))
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
	lsymbol_release(lsymbol);

    return NULL;
}

struct lsymbol *lsymbol_lookup_member(struct lsymbol *lsymbol,
				      const char *name,const char *delim) {
    struct lsymbol *ls;
    struct array_list *chain;
    int i;

    /* Very simple -- we just create a new lsymbol by cloning @lsymbol,
     * then appending to its anon chain as we lookup members!
     */
    ls = __symbol_lookup_sym(lsymbol->symbol,name,delim);
    if (!ls)
	return NULL;
    chain = array_list_clone(lsymbol->chain,array_list_len(lsymbol->chain));
    /* We have to take refs to each symbol of the cloned chain. */
    for (i = 0; i < array_list_len(chain); ++i)
	symbol_hold((struct symbol *)array_list_item(chain,i));

    /* Now we're going to actually use the new chain, append the old
     * chain, replace the old chain on lsymbol, and free the old chain.
     */
    array_list_concat(chain,lsymbol->chain);
    array_list_free(lsymbol->chain);
    lsymbol->chain = chain;

    /* This is a lookup function, so it has to hold a ref to its return
     * value.
     */
    lsymbol_hold(lsymbol);

    return lsymbol;
}

struct lsymbol *symbol_lookup_member(struct symbol *symbol,
				     const char *name,const char *delim) {
    struct lsymbol *lsymbol = __symbol_lookup_sym(symbol,name,delim);
    if (!lsymbol)
	return NULL;

    lsymbol_hold(lsymbol);

    return lsymbol;
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
	if (strstr(srcfile,filename)) {
	    return clmatch_find(&clf,line);
	}
    }

    return NULL;
}

struct lsymbol *debugfile_lookup_sym_line(struct debugfile *debugfile,
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
	ls = debugfile_lookup_addr(debugfile,iaddr);
	if (ls) {
	    if (addr)
		*addr = iaddr;
	    if (offset && ls->symbol->base_addr != ADDRMAX) {
		*offset = iaddr - ls->symbol->base_addr;
	    }
	    return ls;
	}
    }

    return NULL;
}

struct lsymbol *debugfile_lookup_addr(struct debugfile *debugfile,ADDR addr) {
    struct symtab *symtab;
    struct lsymbol *ls;
    struct symbol *s = (struct symbol *)g_hash_table_lookup(debugfile->addresses,
							    (gpointer)addr);

    if (!s) {
	/* If we didn't find it, try our symtab search struct! */
	symtab = (struct symtab *)clrange_find(&debugfile->ranges,addr);

	if (symtab) 
	    vdebug(6,LOG_D_LOOKUP,
		   "found symtab %s 0x%"PRIxSMOFFSET"\n",
		   symtab->name,symtab->ref);

	/* If the symtab is a top-level, unloaded (or partially loaded)
	 * symtab, finish loading it first.  Then redo the lookup.
	 */
	if (symtab && 
	    ((SYMTAB_IS_CU(symtab) 
	      && (symtab->meta->loadtag == LOADTYPE_UNLOADED 
		  || symtab->meta->loadtag == LOADTYPE_PARTIAL))
	     || (SYMTAB_IS_ROOT(symtab)
		 && symtab->meta && symtab->meta->loadtag != LOADTYPE_FULL))) {
	    debugfile_expand_cu(debugfile,symtab,NULL,1);

	    symtab = (struct symtab *)clrange_find(&debugfile->ranges,addr);
	}

	if (symtab) {
	    while (1) {
		if (symtab->symtab_symbol) {
		    s = symtab->symtab_symbol;
		    break;
		}
		else if (symtab->parent) 
		    symtab = symtab->parent;
		else 
		    break;
	    }
	}
    }

    if (s) {
	ls = lsymbol_create_from_symbol(s);

	if (ls)
	    lsymbol_hold(ls);

	return ls;
    }

    return NULL;
}

static struct lsymbol *__debugfile_lookup_sym(struct debugfile *debugfile,
					      char *name,const char *delim,
					      struct rfilter *srcfile_filter,
					      symbol_type_flag_t ftype) {
    char *next = NULL;
    char *lname = NULL;
    char *saveptr = NULL;
    struct array_list *anonchain = NULL;
    int i;
    struct lsymbol *lsymbol = NULL;
    struct lsymbol *lsymbol_tmp = NULL;
    struct symbol *symbol = NULL;
    struct array_list *chain = NULL;
    struct symtab *symtab;
    GHashTableIter iter;
    gpointer key;
    gpointer value;
    struct rfilter_entry *rfe;
    int accept = RF_ACCEPT;

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
    if ((ftype & SYMBOL_TYPE_FLAG_VAR || ftype & SYMBOL_TYPE_FLAG_FUNCTION
	 || ftype & SYMBOL_TYPE_FLAG_LABEL || ftype == SYMBOL_TYPE_FLAG_NONE)
	&& (symbol = g_hash_table_lookup(debugfile->globals,next))) {
	if (srcfile_filter) {
	    rfilter_check(srcfile_filter,symbol->symtab->name,&accept,&rfe);
	    if (accept == RF_ACCEPT) {
		vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,"found rf global %s\n",
		       symbol->name);
		goto found;
	    }
	}
	else {
	    vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,"found global %s\n",
		   symbol->name);
	    goto found;
	}
    }

    if ((ftype & SYMBOL_TYPE_FLAG_TYPE || ftype == SYMBOL_TYPE_FLAG_NONE)
	&& (symbol = g_hash_table_lookup(debugfile->types,next))) {
	if (srcfile_filter) {
	    rfilter_check(srcfile_filter,symbol->symtab->name,&accept,&rfe);
	    if (accept == RF_ACCEPT) {
		vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,"found rf type %s\n",
		       symbol->name);
		goto found;
	    }
	}
	else {
	    vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,"found type %s\n",
		   symbol->name);
	    goto found;
	}
    }

    /* 
     * Check all the srcfiles, or check according to the rfilter.
     */
    g_hash_table_iter_init(&iter,debugfile->srcfiles);
    while (g_hash_table_iter_next(&iter,&key,&value)) {
	symtab = (struct symtab *)value;
	if (srcfile_filter) {
	    rfilter_check(srcfile_filter,key,&accept,&rfe);
	    if (accept == RF_REJECT)
		continue;
	}

	lsymbol_tmp = __symtab_lookup_sym(symtab,name,delim,ftype);
	if (lsymbol_tmp) {
	    /* If we do find a match, and it's a type, take it! */
	    if (SYMBOL_IS_TYPE(lsymbol_tmp->symbol)) {
		lsymbol = lsymbol_tmp;
		break;
	    }
	    /* Or if we find a match and it is a definition (which
	     * implies it should have a location!), take it!
	     */
	    else if (!lsymbol_tmp->symbol->isdeclaration) {
		     //SYMBOL_IS_FULL(lsymbol_tmp->symbol) 
		     // && lsymbol_tmp->symbol->s.ii->l.loctype 
		     //    != LOCTYPE_UNKNOWN) {
		lsymbol = lsymbol_tmp;
		break;
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
    if (lsymbol	&& !lsymbol->symbol->isdeclaration) {
	vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,"found best %s in symtab\n",
	       lsymbol->symbol->name);
	/* If we found a match, fully load it (and its children and
	 * dependent DIEs if it hasn't been yet!).
	 */
	if (lsymbol->symbol->loadtag == LOADTYPE_PARTIAL) {
	    vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,"expanding partial lsymbol %s\n",
		   symbol_get_name(lsymbol->symbol));
	    debugfile_expand_symbol(debugfile,lsymbol->symbol);
	    vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,"expanded partial lsymbol %s\n",
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
	if (symbol->loadtag == LOADTYPE_PARTIAL) {
	    vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,"expanding partial symbol %s\n",
		   symbol_get_name(symbol));
	    debugfile_expand_symbol(debugfile,symbol);
	    vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,"expanded partial symbol %s\n",
		   symbol_get_name(symbol));
	}

	lsymbol = lsymbol_create(symbol,chain);

	vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,"found plain %s\n",
	       lsymbol->symbol->name);

	lsymbol_append(lsymbol,symbol);
    }
    else {
	/* If we found a match, fully load it (and its children and
	 * dependent DIEs if it hasn't been yet!).
	 */
	if (lsymbol->symbol->loadtag == LOADTYPE_PARTIAL) {
	    vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,"expanding partial lsymbol %s\n",
		   symbol_get_name(lsymbol->symbol));
	    debugfile_expand_symbol(debugfile,lsymbol->symbol);
	    vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,"expanded partial lsymbol %s\n",
		   symbol_get_name(lsymbol->symbol));
	}
    }

    /* If it's not a delimited string, stop now, successfully. */
    if (!lname) {

	goto out;
    }

    vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,
	   "found top-level %s; checking members\n",lsymbol->symbol->name);

    if (!delim)
	delim = DWDEBUG_DEF_DELIM;

    while ((next = strtok_r(!saveptr ? lname : NULL,delim,&saveptr))) {
	if (!(symbol = __symbol_get_one_member(symbol,next,&anonchain))) {
	    vwarn("did not find symbol for %s\n",next);
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
				     symbol_type_flag_t ftype) {
    struct lsymbol *lsymbol = __debugfile_lookup_sym(debugfile,name,delim,
						     srcfile_filter,ftype);

    if (lsymbol) 
	lsymbol_hold(lsymbol);

    return lsymbol;
}

GList *debugfile_match_syms_as_lsymbols(struct debugfile *debugfile,
				       struct rfilter *symbol_filter,
				       symbol_type_flag_t ftype,
				       struct rfilter *srcfile_filter,
				       int globals_only) {
    GList *retval = debugfile_match_syms(debugfile,symbol_filter,ftype,
					 srcfile_filter,globals_only);
    GList *tlist;
    if (retval) {
	tlist = g_list_first(retval);
	while ((tlist = g_list_next(retval))) {
	    tlist->data = lsymbol_create_from_symbol((struct symbol *) \
						     tlist->data);
	}
    }

    return retval;
}

GList *debugfile_match_syms(struct debugfile *debugfile,
			    struct rfilter *symbol_filter,
			    symbol_type_flag_t ftype,
			    struct rfilter *srcfile_filter,
			    int globals_only) {
    GList *retval = NULL;
    GHashTableIter iter;
    char *name;
    struct symbol *symbol;
    GHashTableIter iter2;
    char *srcfile_name;
    struct symtab *cu_symtab;
    int accept;
    gpointer key;
    gpointer value;
    struct array_list *duplist;
    int i;

    if (!symbol_filter) {
	errno = EINVAL;
	return NULL;
    }

    if (globals_only && !srcfile_filter) {
	if (ftype == SYMBOL_TYPE_FLAG_NONE
	    || ftype & SYMBOL_TYPE_FLAG_TYPE) {
	    g_hash_table_iter_init(&iter,debugfile->types);
	    while (g_hash_table_iter_next(&iter,&key,
					  &value)) {
		name = (char *)key;
		symbol = (struct symbol *)value;
		rfilter_check(symbol_filter,name,&accept,NULL);
		if (accept == RF_ACCEPT)
		    retval = g_list_prepend(retval,symbol);
	    }
	    g_hash_table_iter_init(&iter,debugfile->shared_types->tab);
	    while (g_hash_table_iter_next(&iter,&key,
					  &value)) {
		name = (char *)key;
		symbol = (struct symbol *)value;
		rfilter_check(symbol_filter,name,&accept,NULL);
		if (accept == RF_ACCEPT)
		    retval = g_list_prepend(retval,symbol);
	    }
	}

	if (ftype == SYMBOL_TYPE_FLAG_NONE
	    || ftype & SYMBOL_TYPE_FLAG_VAR
	    || ftype & SYMBOL_TYPE_FLAG_FUNCTION
	    || ftype & SYMBOL_TYPE_FLAG_LABEL) {
	    g_hash_table_iter_init(&iter,debugfile->globals);
	    while (g_hash_table_iter_next(&iter,&key,
					  &value)) {
		name = (char *)key;
		symbol = (struct symbol *)value;
		if (ftype == SYMBOL_TYPE_FLAG_NONE
		    || (ftype & SYMBOL_TYPE_FLAG_VAR && SYMBOL_IS_VAR(symbol))
		    || (ftype & SYMBOL_TYPE_FLAG_FUNCTION 
			&& SYMBOL_IS_FUNCTION(symbol))
		    || (ftype & SYMBOL_TYPE_FLAG_LABEL 
			&& SYMBOL_IS_LABEL(symbol))) {
		    rfilter_check(symbol_filter,name,&accept,NULL);
		    if (accept == RF_ACCEPT)
			retval = g_list_prepend(retval,symbol);
		}
	    }
	}
    }
    else {
	g_hash_table_iter_init(&iter2,debugfile->srcfiles);
	while (g_hash_table_iter_next(&iter2,&key,
				      &value)) {
	    srcfile_name = (char *)key;
	    cu_symtab = (struct symtab *)value;
	    if (srcfile_filter) {
		rfilter_check(srcfile_filter,srcfile_name,&accept,NULL);
		if (accept == RF_REJECT)
		    continue;
	    }

	    g_hash_table_iter_init(&iter,cu_symtab->tab);
	    while (g_hash_table_iter_next(&iter,&key,
					  &value)) {
		name = (char *)key;
		symbol = (struct symbol *)value;
		if ((ftype == SYMBOL_TYPE_FLAG_NONE
		     || (ftype & SYMBOL_TYPE_FLAG_VAR && SYMBOL_IS_VAR(symbol))
		     || (ftype & SYMBOL_TYPE_FLAG_FUNCTION 
			 && SYMBOL_IS_FUNCTION(symbol))
		     || (ftype & SYMBOL_TYPE_FLAG_LABEL 
			 && SYMBOL_IS_LABEL(symbol)))) {
		    rfilter_check(symbol_filter,name,&accept,NULL);
		    if (accept == RF_ACCEPT)
			retval = g_list_prepend(retval,symbol);
		}
	    }

	    g_hash_table_iter_init(&iter,cu_symtab->duptab);
	    while (g_hash_table_iter_next(&iter,&key,&value)) {
		name = (char *)key;
		duplist = (struct array_list *)value;

		/* Like the above ->tab search, but this time check the
		 * name first, and then only check the symbol flags if
		 * the name matched.
		 */
		rfilter_check(symbol_filter,name,&accept,NULL);
		if (accept == RF_ACCEPT) {
		    for (i = 0; i < array_list_len(duplist); ++i) {
			symbol = (struct symbol *)array_list_item(duplist,i);
			if ((ftype == SYMBOL_TYPE_FLAG_NONE
			     || (ftype & SYMBOL_TYPE_FLAG_VAR 
				 && SYMBOL_IS_VAR(symbol))
			     || (ftype & SYMBOL_TYPE_FLAG_FUNCTION 
				 && SYMBOL_IS_FUNCTION(symbol))
			     || (ftype & SYMBOL_TYPE_FLAG_LABEL 
				 && SYMBOL_IS_LABEL(symbol)))) {
			    retval = g_list_prepend(retval,symbol);
			}
		    }
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
	vdebug(7,LOG_D_DFILE,"token2 = '%s'\n",token2);
	if (strcmp(token2,"NONE") == 0 || strcmp(token2,"*") == 0) {
	    flags = DEBUGFILE_LOAD_FLAG_NONE;
	    return 0;
	}
	else if (strcmp(token2,"CUHEADERS") == 0)
	    flags |= DEBUGFILE_LOAD_FLAG_CUHEADERS;
	else if (strcmp(token2,"PUBNAMES") == 0)
	    flags |= DEBUGFILE_LOAD_FLAG_PUBNAMES;
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

    vdebug(5,LOG_D_DFILE,"starting\n");

    token = NULL;
    saveptr = NULL;
    i = 0;
    while ((token = strtok_r((!token)?optstr:NULL,"||",&saveptr))) {
	vdebug(7,LOG_D_DFILE,"token = '%s' at %d\n",token,i);

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

void debugfile_load_opts_free(struct debugfile_load_opts *opts) {
    if (opts->debugfile_filter) 
	rfilter_free(opts->debugfile_filter);
    if (opts->srcfile_filter) 
	rfilter_free(opts->srcfile_filter);
    if (opts->symbol_filter) 
	rfilter_free(opts->symbol_filter);

    free(opts);
}

char *debugfile_build_idstr(char *filename,char *name,char *version) {
    char *idstr;
    int idstrlen;

    idstrlen = strlen(filename) + 1;
    if (!name)
	idstrlen += strlen("__NULLNAME__") + 1;
    else 
	idstrlen += strlen(name) + 1;
    if (!version)
	idstrlen += strlen("__NULLVERS__") + 1;
    else 
	idstrlen += strlen(version) + 1;
    idstr = (char *)malloc(idstrlen);
    if (!idstr)
	return NULL;
    snprintf(idstr,idstrlen,"%s:%s:%s",filename,name ? name : "__NULLNAME__",
	     version ? version : "__NULLVERS__");

    return idstr;
}

int debugfile_filename_info(char *filename,char **realfilename,
			    char **name,char **version) {
    size_t rc;
    char buf[PATH_MAX];
    regmatch_t matches[2];
    int match_len;
    char *realname;
    struct stat sbuf;

    if (stat(filename,&sbuf) < 0) {
	verror("stat(%s): %s\n",filename,strerror(errno));
	return -1;
    }
    else if (!S_ISLNK(sbuf.st_mode)) {
	realname = NULL;
	return 0;
    }

    if ((rc = readlink(filename,buf,PATH_MAX - 1)) == (size_t)-1) {
	vwarn("readlink(%s): %s\n",filename,strerror(errno));
	realname = NULL;
	return -1;
    }
    else {
	buf[rc] = '\0';
	*realfilename = strdup(buf);
	realname = *realfilename;
    }

    if (!name && !version) {
	return 0;
    }

    if (regexec(&LIBREGEX1,realname,2,matches,0) == 0) {
	if (name) {
	    match_len = matches[0].rm_eo - matches[0].rm_so;
	    *name = malloc(match_len + 1);
	    memcpy(*name,realname + matches[0].rm_so,match_len);
	    *name[match_len] = '\0';
	}

	if (version) {
	    match_len = matches[1].rm_eo - matches[1].rm_so;
	    *version = malloc(match_len + 1);
	    memcpy(*name,realname + matches[1].rm_so,match_len);
	    *version[match_len] = '\0';
	}
    }
    else if (regexec(&LIBREGEX2,realname,1,matches,0) == 0) {
	if (name) {
	    match_len = matches[0].rm_eo - matches[0].rm_so;
	    *name = malloc(match_len + 1);
	    memcpy(*name,realname + matches[0].rm_so,match_len);
	    *name[match_len] = '\0';
	}

	if (version) {
	    *version = NULL;
	    vwarn("cannot extract version from %s!\n",realname);
	}
    }
    else {
	vwarn("cannot extract name and version from %s!\n",realname);
    }

    return 0;
}

struct debugfile *debugfile_create(char *filename,debugfile_type_t type,
				   char *name,char *version,char *idstr) {
    struct debugfile *debugfile;

    /* create a new one */
    debugfile = (struct debugfile *)malloc(sizeof(*debugfile));
    if (!debugfile) {
	errno = ENOMEM;
	return NULL;
    }

    memset(debugfile,0,sizeof(*debugfile));

    debugfile->idstr = idstr;
    debugfile->filename = strdup(filename);
    debugfile->type = type;
    if (name)
	debugfile->name = strdup(name);
    if (version)
	debugfile->version = strdup(version);
    debugfile->refcnt = 0;

    debugfile->debugfile.next = NULL;
    debugfile->debugfile.prev = NULL;

    /* Create the ELF symtab. */
    debugfile->elf_symtab = symtab_create(debugfile,0,".symtab",NULL,1);

    debugfile->elf_ranges = clrange_create();

    /* initialize hashtables */

    /* This is the primary symtab hashtable -- so we provide key and
     * value destructors so that we can call g_hash_table_remove_all to
     * clean it.
     */
    debugfile->srcfiles = g_hash_table_new_full(g_str_hash,g_str_equal,
						NULL,
						ghash_symtab_free);

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

    debugfile->shared_types = symtab_create(debugfile,0,"__sharedtypes__",
					    NULL,1);

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

    return debugfile;
}

struct debugfile *debugfile_filename_create(char *filename,debugfile_type_t type) {
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
	vdebug(2,LOG_D_DFILE,"using %s instead of symlink %s\n",realname,filename);

    idstr = debugfile_build_idstr(realname,name,version);

    debugfile = debugfile_create(realname,type,name,version,idstr);
    if (!debugfile) {
	free(idstr);
	if (realname != filename)
	    free(realname);
    }

    return debugfile;
}

int debugfile_add_cu_symtab(struct debugfile *debugfile,struct symtab *symtab) {
    gpointer retp;

    /* Assume it is a root symtab! */
    if (symtab->name) {
	if ((retp = g_hash_table_lookup(debugfile->srcfiles,
					symtab->name)) != NULL
	    && retp != symtab)
		return 1;
	else if (retp == symtab)
	    return 0;
	else {
	    vdebug(3,LOG_D_DFILE,"adding top-level symtab %s:%s\n",
		   debugfile->idstr,symtab->name);
	    g_hash_table_insert(debugfile->srcfiles,symtab->name,symtab);
	}
    }

    if ((retp = g_hash_table_lookup(debugfile->cuoffsets,
				    (gpointer)(uintptr_t)symtab->ref)) != NULL
	&& retp != symtab)
	return 2;
    else if (retp == symtab)
	return 0;
    else {
	g_hash_table_insert(debugfile->cuoffsets,
			    (gpointer)(uintptr_t)symtab->ref,symtab);
	vdebug(3,LOG_D_DFILE,"adding top-level symtab %s:0x%"PRIxSMOFFSET"\n",
	       debugfile->idstr,symtab->ref);
    }

    return 0;
}

int debugfile_add_global(struct debugfile *debugfile,struct symbol *symbol) {
    if (unlikely(g_hash_table_lookup(debugfile->globals,symbol->name)))
	return 1;
    g_hash_table_insert(debugfile->globals,symbol->name,symbol);
    return 0;
}

struct symbol *debugfile_find_type(struct debugfile *debugfile,
				   char *typename) {
    struct symbol *s = (struct symbol *) \
	symtab_get_sym(debugfile->shared_types,typename);
    if (!s)
	s = (struct symbol *)g_hash_table_lookup(debugfile->types,typename);
    return s;
}

int debugfile_add_type_name(struct debugfile *debugfile,
			    char *name,struct symbol *symbol) {
    if (unlikely(g_hash_table_lookup(debugfile->types,name)))
	return 1;
    g_hash_table_insert(debugfile->types,name,symbol);
    return 0;
}

REFCNT debugfile_free(struct debugfile *debugfile,int force) {
    int retval = debugfile->refcnt;

    if (debugfile->refcnt) {
	if (!force) {
	    verror("cannot free (%d refs) debugfile(%s)",
		   debugfile->refcnt,debugfile->idstr);
	    return debugfile->refcnt;
	}
	else {
	    vwarn("forced free (%d refs) debugfile(%s)",
		  debugfile->refcnt,debugfile->idstr);
	}
    }

    vdebug(5,LOG_D_DFILE,"freeing debugfile(%s)\n",debugfile->idstr);

    if (debugfile->kernel_debugfile)
	--(debugfile->kernel_debugfile->refcnt);

    if (debugfile->debugfile.prev != NULL || debugfile->debugfile.next != NULL)
	list_del(&debugfile->debugfile);

    g_hash_table_destroy(debugfile->pubnames);
    g_hash_table_destroy(debugfile->addresses);
    g_hash_table_destroy(debugfile->globals);
    g_hash_table_destroy(debugfile->types);
    g_hash_table_destroy(debugfile->cuoffsets);
    /* All the per-debugfile-per-srcfile symtabs (and their symbols) are
     * destroyed as a result of this.
     */
    g_hash_table_destroy(debugfile->srcfiles);

    /* This has to be called last, of all the things that might hold
     * symbols.
     */
    symtab_free(debugfile->shared_types);

    clrange_free(debugfile->ranges);

    g_hash_table_destroy(debugfile->srclines);

    symtab_free(debugfile->elf_symtab);

    clrange_free(debugfile->elf_ranges);

    if (debugfile->elf_strtab)
	free(debugfile->elf_strtab);
    if (debugfile->dbg_strtab)
	free(debugfile->dbg_strtab);
    if (debugfile->loctab)
	free(debugfile->loctab);
    if (debugfile->rangetab)
	free(debugfile->rangetab);
    if (debugfile->linetab)
	free(debugfile->linetab);

    if (debugfile->ebl) {
	ebl_closebackend(debugfile->ebl);
	debugfile->ebl = NULL;
    }
    if (debugfile->dwfl) {
	dwfl_end(debugfile->dwfl);
	debugfile->dwfl = NULL;
    }
    if (debugfile->fd) {
	close(debugfile->fd);
	debugfile->fd = 0;
    }

    if (debugfile->version)
	free(debugfile->version);
    free(debugfile->name);
    free(debugfile->filename);
    free(debugfile->idstr);
    free(debugfile);

    vdebug(5,LOG_D_DFILE,"freed debugfile\n");

    return retval;
}

/**
 ** Symtabs.
 **/
struct symtab *symtab_create(struct debugfile *debugfile,SMOFFSET offset,
			     char *name,struct symbol *symtab_symbol,
			     int noautoinsert) {
    struct symtab *symtab;

    symtab = (struct symtab *)malloc(sizeof(*symtab));
    if (!symtab)
	return NULL;
    memset(symtab,0,sizeof(*symtab));

    symtab->debugfile = debugfile;

    symtab_set_name(symtab,name,noautoinsert);

    symtab->range.rtype = RANGE_TYPE_NONE;

    symtab->ref = offset;

    symtab->symtab_symbol = symtab_symbol;

    INIT_LIST_HEAD(&symtab->subtabs);

    symtab->tab = g_hash_table_new_full(g_str_hash,g_str_equal,
					/* Don't free the symbol names;
					 * symbol_free will do that!
					 */
					NULL,
					ghash_symbol_free);

    symtab->duptab = g_hash_table_new_full(g_str_hash,g_str_equal,
					   /* Don't free the symbol names;
					    * symbol_free will do that!
					    */
					   NULL,
					   /* Values are just ints. */
					   NULL);

    symtab->anontab = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					    /* No symbol names to free!
					     */
					    NULL,
					    ghash_symbol_free);

    return symtab;
}

int symtab_get_size_simple(struct symtab *symtab) {
    return (g_hash_table_size(symtab->tab)
	    + g_hash_table_size(symtab->anontab)
	    + g_hash_table_size(symtab->duptab));
}

void symtab_set_name(struct symtab *symtab,char *name,int noautoinsert) {
    if (symtab->name && strcmp(symtab->name,name) == 0)
	return;

    /* If this top-level symtab is being renamed, remove it from our
     * debugfile!
     */
    if (name && SYMTAB_IS_CU(symtab) && symtab->debugfile && symtab->name)
	g_hash_table_remove(symtab->debugfile->srcfiles,symtab->name);

    if (name 
#ifdef DWDEBUG_USE_STRTAB
	&& (!symtab->debugfile 
	    || (!symtab_str_in_dbg_strtab(symtab,name)
		&& !symtab_str_in_elf_strtab(symtab,name)))
#endif
	)
	symtab->name = strdup(name);
    else 
	symtab->name = name;

    /* If this top-level symtab wasn't in our debugfile srcfiles
     * hash, add it!
     */
    if (name && !noautoinsert && SYMTAB_IS_CU(symtab) && symtab->debugfile 
	&& !g_hash_table_lookup(symtab->debugfile->srcfiles,symtab->name)) 
	g_hash_table_insert(symtab->debugfile->srcfiles,symtab->name,symtab);
}

char *symtab_get_name(struct symtab *symtab) {
    return symtab->name;
}

void symtab_set_compdirname(struct symtab *symtab,char *compdirname) {
    if (!SYMTAB_IS_CU(symtab))
	return;

    if (symtab->meta->compdirname 
	&& strcmp(symtab->meta->compdirname,compdirname) == 0)
	return;

    if (compdirname
#ifdef DWDEBUG_USE_STRTAB
	&& (!symtab->debugfile || !symtab_str_in_dbg_strtab(symtab,compdirname))
#endif
	)
	symtab->meta->compdirname = strdup(compdirname);
    else
	symtab->meta->compdirname = compdirname;
}

void symtab_set_producer(struct symtab *symtab,char *producer) {
    if (!SYMTAB_IS_CU(symtab))
	return;

    if (symtab->meta->producer && strcmp(symtab->meta->producer,producer) == 0)
	return;

    if (producer 
#ifdef DWDEBUG_USE_STRTAB
	&& (!symtab->debugfile || !symtab_str_in_dbg_strtab(symtab,producer))
#endif
	)
	symtab->meta->producer = strdup(producer);
    else
	symtab->meta->producer = producer;
}

void symtab_set_language(struct symtab *symtab,int language) {
    if (!SYMTAB_IS_CU(symtab))
	return;

    symtab->meta->language = language;
}

int symtab_insert(struct symtab *symtab,struct symbol *symbol,OFFSET anonaddr) {
    char *name = symbol_get_name(symbol);
    struct symbol *exsym = NULL;
    struct array_list *exlist = NULL;

    if (name) {
	if (unlikely((exlist = (struct array_list *) \
		      g_hash_table_lookup(symtab->duptab,name)))) {
	    array_list_append(exlist,symbol);

	    vdebug(5,LOG_D_DWARF | LOG_D_SYMBOL,
		   "duplicate symbol %s (%d)\n",
		   symbol->name,array_list_len(exlist));
	}
	else if (unlikely((exsym = (struct symbol *) \
			   g_hash_table_lookup(symtab->tab,name)))) {
	    exlist = array_list_create(2);
	    array_list_append(exlist,exsym);
	    array_list_append(exlist,symbol);
	    g_hash_table_steal(symtab->tab,name);
	    g_hash_table_insert(symtab->duptab,name,exlist);

	    vdebug(5,LOG_D_DWARF | LOG_D_SYMBOL,
		   "duplicate symbol %s (2)\n",symbol->name);
	}
	else {
	    g_hash_table_insert(symtab->tab,name,symbol);
	}
	return 0;
    }

    if (anonaddr) {
	if (unlikely(g_hash_table_lookup(symtab->anontab,(gpointer)anonaddr))) {
	    verror("BAD -- tried to insert a duplicate anonymous symbol"
		   " at 0x%"PRIxOFFSET"!\n",anonaddr);
	    return 1;
	}
	g_hash_table_insert(symtab->anontab,(gpointer)anonaddr,symbol);
	return 0;
    }

    verror("VERY BAD -- tried to insert a non-anonymous symbol with no name!\n");
    return 1;
}

void symtab_remove(struct symtab *symtab,struct symbol *symbol) {
    char *name = symbol_get_name(symbol);
    struct symbol *exsym = NULL;
    struct array_list *exlist = NULL;

    if (name) {
	if (unlikely((exlist = (struct array_list *) \
		      g_hash_table_lookup(symtab->duptab,name)))) {
	    array_list_remove_item(exlist,symbol);
	    if (array_list_len(exlist) == 1) {
		g_hash_table_steal(symtab->duptab,name);
		exsym = (struct symbol *)array_list_item(exlist,0);
		array_list_free(exlist);
		g_hash_table_insert(symtab->tab,name,exsym);
	    }
	    symbol_free(symbol,0);
	}
	else if (g_hash_table_lookup(symtab->tab,name))
	    g_hash_table_remove(symtab->tab,name);
	else 
	    vwarn("symbol %s not on symtab %s!\n",name,symtab->name);
    }
    else if (g_hash_table_lookup(symtab->anontab,
				 (gpointer)(uintptr_t)symbol->ref)) {
	g_hash_table_remove(symtab->anontab,(gpointer)(uintptr_t)symbol->ref);
	symbol_free(symbol,0);
    }
    else
	vwarn("anon symbol 0x%"PRIxSMOFFSET" not on symtab %s!\n",
	      symbol->ref,symtab->name);
}

void symtab_steal(struct symtab *symtab,struct symbol *symbol) {
    char *name = symbol_get_name(symbol);
    struct symbol *exsym = NULL;
    struct array_list *exlist = NULL;

    if (name) {
	if (unlikely((exlist = (struct array_list *) \
		      g_hash_table_lookup(symtab->duptab,name)))) {
	    array_list_remove_item(exlist,symbol);
	    if (array_list_len(exlist) == 1) {
		g_hash_table_steal(symtab->duptab,name);
		exsym = (struct symbol *)array_list_item(exlist,0);
		array_list_free(exlist);
		g_hash_table_insert(symtab->tab,name,exsym);
	    }
	}
	else if (g_hash_table_lookup(symtab->tab,name))
	    g_hash_table_steal(symtab->tab,name);
    }
    else if (g_hash_table_lookup(symtab->anontab,
				 (gpointer)(uintptr_t)symbol->ref))
	g_hash_table_steal(symtab->anontab,(gpointer)(uintptr_t)symbol->ref);
    else 
	vwarn("anon symbol 0x%"PRIxSMOFFSET" not on symtab %s!\n",
	      symbol->ref,symtab->name);
}

void symtab_update_range(struct symtab *symtab,ADDR start,ADDR end,
			 range_type_t rt_hint) {
    struct range *r = &symtab->range;
    int i;

    if (r->rtype == RANGE_TYPE_NONE) {
	if (rt_hint == RANGE_TYPE_LIST) {
	    r->rtype = RANGE_TYPE_LIST;
	    /* Reset it -- it's a union, so we need to clear what's there! */
	    memset(&r->r.rlist,0,sizeof(struct range_list));

	    /* And the new thing. */
	    range_list_add(&r->r.rlist,start,end);

	    if (symtab->debugfile)
		clrange_add(&symtab->debugfile->ranges,start,end,symtab);

	    vdebug(8,LOG_D_DWARF,
		   "init RANGE_LIST(0x%"PRIxADDR",0x%"PRIxADDR")"
		   " for symtab 0x%"PRIxSMOFFSET"\n",start,end,symtab->ref);
	}
	else {
	    r->rtype = RANGE_TYPE_PC;

	    r->r.a.lowpc = start;
	    r->r.a.highpc = end;

	    if (symtab->debugfile)
		clrange_add(&symtab->debugfile->ranges,start,end,symtab);

	    vdebug(8,LOG_D_DWARF,
		   "init RANGE_PC(0x%"PRIxADDR",0x%"PRIxADDR")"
		   " for symtab 0x%"PRIxSMOFFSET"\n",start,end,symtab->ref);
	}
    }
    else if (r->rtype == RANGE_TYPE_PC) {
	ADDR olowpc = r->r.a.lowpc;
	ADDR ohighpc = r->r.a.highpc;

	/* If the start/end range matches the current thing, do nothing! */
	if (olowpc == start && ohighpc == end) {
	    vdebug(8,LOG_D_DWARF,
		   "RANGE_PC(0x%"PRIxADDR",0x%"PRIxADDR") matched for symtab"
		   " %s at 0x%"PRIxSMOFFSET"; not updating\n",start,end,
		   symtab->name,symtab->ref);
	    return;
	}
	/* If the start address is equal, but the end is not, warn about
	 * inconsistent DWARF, but update the range -- both here and in
	 * the debugfile->ranges clrange struct!
	 */
	else if (olowpc == start && ohighpc != end) {
	    r->r.a.highpc = end;

	    if (symtab->debugfile) 
		clrange_update_end(&symtab->debugfile->ranges,start,end,symtab);

	    verror("inconsistent RANGE_PC end: 0x%"PRIxADDR",0x%"PRIxADDR
		   " (new end 0x%"PRIxADDR") for symtab 0x%"PRIxSMOFFSET
		   "; updating!\n",start,ohighpc,end,symtab->ref);
	}
	/* If the start addrs don't match, or neither start nor end
	 * match, this symtab was of RANGE_TYPE_PC, but now we must
	 * convert it to a RANGE_TYPE_LIST.
	 */
	else {
	    r->rtype = RANGE_TYPE_LIST;
	    /* Reset it -- it's a union, so we need to clear what's there! */
	    memset(&r->r.rlist,0,sizeof(struct range_list));

	    /* Add the old thing. */
	    range_list_add(&r->r.rlist,olowpc,ohighpc);

	    /* And the new thing. */
	    range_list_add(&r->r.rlist,start,end);
	    vdebug(5,LOG_D_DWARF,
		   "converted RANGE_PC to LIST with new entry (0x%"PRIxADDR
		   ",0x%"PRIxADDR")\n",start,end);

	    if (symtab->debugfile)
		clrange_add(&symtab->debugfile->ranges,start,end,symtab);

	    vdebug(7,LOG_D_DWARF,
		   "converting RANGE_PC to LIST; new entry (0x%"PRIxADDR
		   ",0x%"PRIxADDR") for symtab 0x%"PRIxSMOFFSET"\n",
		   start,end,symtab->ref);
	}
    }
    else if (r->rtype == RANGE_TYPE_LIST) {
	/* Look through the list and see if any of the start addrs match
	 * this one; if so, and the end doesn't match, update that one.
	 * Otherwise, add a new one.
	 */
	for (i = 0; i < r->r.rlist.len; ++i) {
	    if (r->r.rlist.list[i]->start == start
		&& r->r.rlist.list[i]->end != end) {
		verror("inconsistent RANGE_LIST entry end: 0x%"PRIxADDR
		       ",0x%"PRIxADDR" (new end 0x%"PRIxADDR
		       ") for symtab 0x%"PRIxSMOFFSET"; updating!\n",
		       start,r->r.rlist.list[i]->end,end,symtab->ref);

		r->r.rlist.list[i]->end = end;
		
		if (symtab->debugfile) 
		    clrange_update_end(&symtab->debugfile->ranges,start,end,
				       symtab);

		break;
	    }
	}

	if (i == r->r.rlist.len) {
	    range_list_add(&r->r.rlist,start,end);

	    if (symtab->debugfile)
		clrange_add(&symtab->debugfile->ranges,start,end,symtab);

	    vdebug(8,LOG_D_DWARF,
		   "added RANGE_LIST entry (0x%"PRIxADDR",0x%"PRIxADDR
		   ") for symtab 0x%"PRIxSMOFFSET")\n",start,end,symtab->ref);
	}
    }

    return;
}

void symtab_free(struct symtab *symtab) {
    struct symtab *tmp;
    struct symtab *tmp2;
    GHashTableIter iter;
    struct array_list *exlist = NULL;
    int i;
    struct symbol *exsym;
    gpointer key, value;

    vdebug(5,LOG_D_SYMTAB,"freeing symtab(%s:%s)\n",
	   symtab->debugfile->idstr,symtab->name);

    if (!list_empty(&symtab->subtabs))
	list_for_each_entry_safe(tmp,tmp2,&symtab->subtabs,member) 
	    //if (!tmp->symtab_symbol || !tmp->symtab_symbol->isshared)
	    symtab_free(tmp);
    if (RANGE_IS_LIST(&symtab->range))
	range_list_internal_free(&symtab->range.r.rlist);

    /* Release the duplicates first. */
    g_hash_table_iter_init(&iter,symtab->duptab);
    while (g_hash_table_iter_next(&iter,
				  (gpointer *)&key,(gpointer *)&value)) {
	exlist = (struct array_list *)value;
	for (i = 0; i < array_list_len(exlist); ++i) {
	    exsym = (struct symbol *)array_list_item(exlist,i);
	    symbol_free(exsym,0);
	}
	array_list_free(exlist);
	/* This should not be necessary, but just so the hash lib
	 * doesn't try to reuse the freed list pointer...
	 */
	g_hash_table_iter_replace(&iter,NULL);
    }
    g_hash_table_destroy(symtab->duptab);

    g_hash_table_destroy(symtab->tab);
    g_hash_table_destroy(symtab->anontab);

    if (symtab->name
#ifdef DWDEBUG_USE_STRTAB
	&& !symtab_str_in_dbg_strtab(symtab,symtab->name)
	&& !symtab_str_in_elf_strtab(symtab,symtab->name)
#endif
	)
	free(symtab->name);
    if (SYMTAB_IS_CU(symtab)) {
	if (symtab->meta->compdirname
#ifdef DWDEBUG_USE_STRTAB
	    && !symtab_str_in_dbg_strtab(symtab,symtab->meta->compdirname)
#endif
	    )
	    free(symtab->meta->compdirname);
	if (symtab->meta->producer
#ifdef DWDEBUG_USE_STRTAB
	    && !symtab_str_in_dbg_strtab(symtab,symtab->meta->producer)
#endif
	    )
	    free(symtab->meta->producer);
	free(symtab->meta);
    }
    free(symtab);
}

#ifdef DWDEBUG_USE_STRTAB
/* Returns 1 if string is in elf_strtab; else 0 */
int symtab_str_in_elf_strtab(struct symtab *symtab,char *strp) {
    if (symtab->debugfile && symtab->debugfile->elf_strtab
	&& strp >= symtab->debugfile->elf_strtab
	&& strp < (symtab->debugfile->elf_strtab + symtab->debugfile->elf_strtablen))
	return 1;
    return 0;
}
/* Returns 1 if string is in debuginfo strtab; else 0 */
int symtab_str_in_dbg_strtab(struct symtab *symtab,char *strp) {
    if (symtab->debugfile && symtab->debugfile->dbg_strtab
	&& strp >= symtab->debugfile->dbg_strtab
	&& strp < (symtab->debugfile->dbg_strtab + symtab->debugfile->dbg_strtablen))
	return 1;
    return 0;
}
#endif

/**
 ** Functions for symbols.
 **/
struct symbol *symbol_create(struct symtab *symtab,SMOFFSET offset,
			     char *name,symbol_type_t symtype,
			     symbol_source_t source,int full) {
    struct symbol *symbol;

    symbol = (struct symbol *)malloc(sizeof(*symbol));
    if (!symbol)
	return NULL;
    memset(symbol,0,sizeof(*symbol));

    if (full)
	symbol->loadtag = LOADTYPE_FULL;
    else
	symbol->loadtag = LOADTYPE_PARTIAL;

    symbol->ref = offset;

    /* Comparison functions in dwarf_debuginfo need this set nonzero! */
    symbol->base_addr = ADDRMAX;

    if (full) {
	switch (symtype) {
	case SYMBOL_TYPE_TYPE:
	    symbol->s.ti = (struct symbol_type *)malloc(sizeof(*symbol->s.ti));
	    if (!symbol->s.ti) {
		free(symbol);
		return NULL;
	    }
	    memset(symbol->s.ti,0,sizeof(*symbol->s.ti));
	    break;
	case SYMBOL_TYPE_VAR:
	    symbol->s.ii = (struct symbol_instance *)malloc(sizeof(*symbol->s.ii));
	    if (!symbol->s.ii) {
		free(symbol);
		return NULL;
	    }
	    memset(symbol->s.ii,0,sizeof(*symbol->s.ii));
	    break;
	case SYMBOL_TYPE_FUNCTION:
	    symbol->s.ii = (struct symbol_instance *)malloc(sizeof(*symbol->s.ii));
	    if (!symbol->s.ii) {
		free(symbol);
		return NULL;
	    }
	    memset(symbol->s.ii,0,sizeof(*symbol->s.ii));
	    break;
	case SYMBOL_TYPE_LABEL:
	    symbol->s.ii = (struct symbol_instance *)malloc(sizeof(*symbol->s.ii));
	    if (!symbol->s.ii) {
		free(symbol);
		return NULL;
	    }
	    memset(symbol->s.ii,0,sizeof(*symbol->s.ii));
	    break;
	default:
	    verror("bad symbol type %d!\n",symtype);
	    free(symbol);
	    return NULL;
	}
    }

    symbol->symtab = symtab;
    symbol_set_name(symbol,name);
    symbol_set_type(symbol,symtype);

    symbol->refcnt = 0;

    /* Only insert the symbol automatically if we have a name.  This
     * won't be true for our dwarf parser, for instance.
     */
    if (0 && name)
	g_hash_table_insert(symtab->tab,name,symbol);

    vdebug(LOG_D_SYMBOL,5,"offset %"PRIxSMOFFSET"\n",offset);

    return symbol;
}

char *symbol_get_name(struct symbol *symbol) {
    return symbol->name;
}

char *symbol_get_name_orig(struct symbol *symbol) {
    return symbol->name + symbol->orig_name_offset;
}

void symbol_set_name(struct symbol *symbol,char *name) {
    if (symbol->name && strcmp(symbol->name,name) == 0)
	return;

    if (name 
#ifdef DWDEBUG_USE_STRTAB
	&& (!symbol->symtab || !symbol->symtab->debugfile 
	    || (!symtab_str_in_dbg_strtab(symbol->symtab,name)
		&& !symtab_str_in_elf_strtab(symbol->symtab,name)))
#endif
	) {
	symbol->name = strdup(name);
    }
    else {
	symbol->name = name;
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

    symbol->name = insert_name;
    if (symbol_name
#ifdef DWDEBUG_USE_STRTAB
	&& (!symbol->symtab 
	    || (!symtab_str_in_dbg_strtab(symbol->symtab,symbol_name)
		&& !symtab_str_in_elf_strtab(symbol->symtab,symbol_name)))
#endif
	)
	free(symbol_name);
    symbol->orig_name_offset = foffset;
}

struct symtab *symbol_get_root_symtab(struct symbol *symbol) {
    struct symtab *st = symbol->symtab;

    while (st && st->parent)
	st = st->parent;

    return st;
}

void symbol_change_symtab(struct symbol *symbol,struct symtab *symtab,
			  int noinsert,int typerecurse) {
    struct symbol_instance *tmpi;

    if (!symtab)
	return;

    if (symbol->symtab == symtab)
	return;

    /* If it's a member, don't insert OR remove it! */
    if (!symbol->ismember) {

	//vwarn("symbol %s symtab %s %d %d\n",symbol_get_name(symbol),symtab->name,
	//    noinsert,typerecurse);

	/* Remove it from what it might be currently on, but don't free it! */
	symtab_steal(symbol->symtab,symbol);

	/* Add it to the new thing. */
	symbol->symtab = symtab;
	if (!noinsert) {
	    if (symtab_insert(symbol->symtab,symbol,0))
		symtab_insert(symbol->symtab,symbol,symbol->ref);
	}
    }

    /* Change our immediate children if necessary.  For instance
     * symbols, we only recurse on their types if we were told to.  In
     * general, we are saved from crazy recursion loops (i.e., on nested
     * struct types) because we check to see if we already changed the
     * symtab.
     */
    if (typerecurse && symbol->datatype)
	symbol_change_symtab(symbol->datatype,symtab,noinsert,typerecurse);

    if (!SYMBOL_IS_FULL(symbol))
	return;

    if (SYMBOL_IS_TYPE(symbol)) {
	if (SYMBOL_IST_STUN(symbol)) {
	    list_for_each_entry(tmpi,&symbol->s.ti->d.su.members,d.v.member) 
		symbol_change_symtab(tmpi->d.v.member_symbol,symtab,noinsert,
				     typerecurse);
	}
	else if (SYMBOL_IST_ENUM(symbol)) {
	    list_for_each_entry(tmpi,&symbol->s.ti->d.e.members,d.v.member) 
		symbol_change_symtab(tmpi->d.v.member_symbol,symtab,noinsert,
				     typerecurse);
	}
    }
    /* NOTE: for instance, we don't yet change the *origin symbol's
     * symtab!  Perhaps we should hold it if symbol->symtab != symtab???
     */
    else if (SYMBOL_IS_VAR(symbol)) {
	/* XXX: we don't change upwards, i.e., *parent_symbol!  I think
	 * this is correct...
	 */
	symbol->symtab = symtab;
    }
    else if (SYMBOL_IS_FUNCTION(symbol)) {
	/* We don't need to recurse on this symtab; any children already
	 * point to d.f.symtab.
	 */
	if (symbol->s.ii->d.f.symtab->parent) 
	    list_del(&symbol->s.ii->d.f.symtab->member);
	symbol->s.ii->d.f.symtab->parent = symtab;
	list_add_tail(&symbol->s.ii->d.f.symtab->member,&symtab->subtabs);

	/* We also don't need to do it for any of our args or variables;
	 * they are on this function's symtab, which we just reparented.
	 */
    }
    /* Nothing to do for labels. */

    return;
}

void symbol_set_type(struct symbol *symbol,symbol_type_t symtype) {
    symbol->type = symtype;
}

void symbol_set_srcline(struct symbol *symbol,int srcline) {
    if (srcline > ((1 << SRCLINE_BITS) - 1)) {
	vwarn("symbol %s at srcline %d: line too large (max %d)!\n",
	      symbol_get_name(symbol),srcline,(1 << SRCLINE_BITS) - 1);
	symbol->srcline = 0xffff;
	return;
    }

    symbol->srcline = srcline;
}

int symbol_type_bytesize(struct symbol *symbol) {
    return symbol->size;
}

static inline int __check_type_in_list(struct symbol *type,
				       struct array_list *list) {
    int i;

    if (!list)
	return 0;

    for (i = 0; i < list->len; ++i)
	if (array_list_item(list,i) == type)
	    return 1;
    return 0;
}

static int __symbol_type_equiv(struct symbol *t1,struct symbol *t2,
			       struct array_list **t1ss,
			       struct array_list **t2ss,
			       GHashTable *updated_datatype_refs) {
    struct symbol_type *ti1;
    struct symbol_type *ti2;
    struct symbol *m1;
    struct symbol *m2;
    struct symbol_instance *mi1;
    struct symbol_instance *mi2;
    struct symbol *t1d;
    struct symbol *t2d;
    int retval = 0;
    int rc;
    int i;

    if (t1 == t2)
	return 0;

    //vwarn("t1 = %p t2 = %p\n",t1,t2);

    /* Check if we've already been examining this type (for nested
     * structs/unions); if we have, just return equiv so that the
     * recursion will return!  Equivalence is decided further up the
     * stack.
     */
    if ((rc = __check_type_in_list(t1,*t1ss)) 
	== __check_type_in_list(t2,*t2ss)) {
	if (rc == 1)
	    return 0;
    }
    else {
	return 1;
    }

    if (t1->datatype_code != t2->datatype_code)
	return 1;

    if (t1->loadtag != t2->loadtag)
	return 1;

    if (!((symbol_get_name(t1) == NULL && symbol_get_name(t2) == NULL)
	  || strcmp(symbol_get_name(t1),symbol_get_name(t2)) == 0))
	return 1;

    if (t1->loadtag == LOADTYPE_PARTIAL)
	/* They are equivalent, as far as we can tell! */
	return 0;

    ti1 = t1->s.ti;
    ti2 = t2->s.ti;

    if (t1->size != t2->size)
	return 1;

    if (ti1->d.t.encoding != ti2->d.t.encoding)
	return 1;

    switch (t1->datatype_code) {
    case DATATYPE_VOID:
	return 0;
    case DATATYPE_ARRAY:
	/* Check the ranges first; then check the types. */
	if (ti1->d.a.count != ti2->d.a.count)
	    return 1;
	for (i = 0; i < ti1->d.a.count; ++i)
	    if (ti1->d.a.subranges[i] != ti2->d.a.subranges[i])
		return 1;
	t1d = t1->datatype;
	t2d = t2->datatype;
	if (updated_datatype_refs) {
	    if (!(t1d = (struct symbol *)g_hash_table_lookup(updated_datatype_refs,
							     (gpointer)(uintptr_t)t1->datatype_ref))) 
		t1d = t1->datatype;
	    if (!(t2d = (struct symbol *)g_hash_table_lookup(updated_datatype_refs,
							     (gpointer)(uintptr_t)t2->datatype_ref)))
		t2d = t2->datatype;
	}
	return __symbol_type_equiv(t1d,t2d,t1ss,t2ss,updated_datatype_refs);
    case DATATYPE_STRUCT:
    case DATATYPE_UNION:
	if (ti1->d.su.count != ti2->d.su.count)
	    return 1;

	/* Before we check member types, push ourselves as "already
	 * being checked".  Then, if a recursive call to this function
	 * sees these symbols on their respective lists again, it just
	 * returns 0 (equivalent) and we finish the checking further up
	 * the recursion stack.
	 */
	int t1created = 0;
	int t2created = 0;
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

	/* Then check all the names/types of the members! */
	i = 0;
	list_for_each_entry_dual(mi1,mi2,&ti1->d.su.members,&ti2->d.su.members,
				 d.v.member,d.v.member) {
	    m1 = mi1->d.v.member_symbol;
	    m2 = mi2->d.v.member_symbol;
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
		t1d = (struct symbol *)g_hash_table_lookup(updated_datatype_refs,
							   (gpointer)(uintptr_t) \
							   m1->datatype_ref);
		if (!t1d)
		    t1d = m1->datatype;
		t2d = (struct symbol *)g_hash_table_lookup(updated_datatype_refs,
							   (gpointer)(uintptr_t) \
							   m2->datatype_ref);
		if (!t2d)
		    t2d = m2->datatype;
	    }

	    if (t1d == t2d)
		continue;

	    if ((rc = __symbol_type_equiv(t1d,t2d,t1ss,t2ss,
					  updated_datatype_refs))) {
		retval = rc;
		break;
	    }
	    ++i;
	};

	if (t1created) {
	    array_list_free(*t1ss);
	    *t1ss = NULL;
	}
	else 
	    array_list_remove(*t1ss);
	if (t2created) {
	    array_list_free(*t2ss);
	    *t2ss = NULL;
	}
	else 
	    array_list_remove(*t2ss);

	return retval;
    case DATATYPE_PTR:
    case DATATYPE_TYPEDEF:
	t1d = t1->datatype;
	t2d = t2->datatype;
	if (updated_datatype_refs) {
	    t1d = (struct symbol *)g_hash_table_lookup(updated_datatype_refs,
						       (gpointer)(uintptr_t) \
						       t1->datatype_ref);
	    if (!t1d)
		t1d = t1->datatype;
	    t2d = (struct symbol *)g_hash_table_lookup(updated_datatype_refs,
						       (gpointer)(uintptr_t) \
						       t2->datatype_ref);
	    if (!t2d)
		t2d = t2->datatype;
	}

	if (t1d == t2d)
	    return 0;

	return __symbol_type_equiv(t1d,t2d,t1ss,t2ss,updated_datatype_refs);
    case DATATYPE_FUNCTION:
	if (ti1->d.f.count != ti2->d.f.count)
	    return 1;

	/* Check all the names/types of the members! */
	list_for_each_entry_dual(mi1,mi2,&ti1->d.f.args,&ti2->d.f.args,
				 d.v.member,d.v.member) {
	    m1 = mi1->d.v.member_symbol;
	    m2 = mi2->d.v.member_symbol;
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
		t1d = (struct symbol *)g_hash_table_lookup(updated_datatype_refs,
							   (gpointer)(uintptr_t) \
							   m1->datatype_ref);
		if (!t1d)
		    t1d = m1->datatype;
		t2d = (struct symbol *)g_hash_table_lookup(updated_datatype_refs,
							   (gpointer)(uintptr_t) \
							   m2->datatype_ref);
		if (!t2d)
		    t2d = m2->datatype;
	    }

	    if (t1d == t2d)
		continue;

	    if ((rc = __symbol_type_equiv(t1d,t2d,t1ss,t2ss,
					  updated_datatype_refs))) {
		retval = rc;
		break;
	    }
	};

	return retval;
    case DATATYPE_ENUM:
	/* XXX: just assume that life is good if the names are equiv. */
	return 0;
    case DATATYPE_BASE:
	return 0;
    case DATATYPE_CONST:
    case DATATYPE_VOL:
	return 0;
    case DATATYPE_BITFIELD:
	if (ti1->d.t.bit_size != ti2->d.t.bit_size)
	    return 1;
	return 0;
    default:
	return -1;
    }
}

int symbol_type_equal(struct symbol *t1,struct symbol *t2,
		      GHashTable *updated_datatype_refs) {
    struct array_list *t1ss = NULL;
    struct array_list *t2ss = NULL;
    int retval;

    if (!SYMBOL_IS_TYPE(t1) || !SYMBOL_IS_TYPE(t2))
	return -1;

    retval = __symbol_type_equiv(t1,t2,&t1ss,&t2ss,updated_datatype_refs);

    return retval;
}

static struct symbol *__symbol_get_one_member(struct symbol *symbol,char *member,
					      struct array_list **chainptr) {
    struct symbol *retval = NULL;
    struct symbol_instance *retval_instance;
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
    struct symbol *type = symbol;
    int j, k;
    struct lsymbol *lsymbol;
    struct symtab *subtab;
    struct symbol *tsymbol;
    
    struct dump_info udn = {
	.stream = stderr,
	.prefix = "",
	.detail = 1,
	.meta = 1
    };
    vdebug(4,LOG_D_LOOKUP,"symbol: ");
    symbol_dump(symbol,&udn);
    

    if (!SYMBOL_IS_FULL(symbol))
	return NULL;

    /* This doesn't look safe, but it is!  If it's a type, we skip
     * const/vol or typedefs, before testing.  If it's not one of those
     * types, this function is an identity function, so we just operate
     * on @symbol.
     */
    if (SYMBOL_IS_TYPE(symbol)) {
	tsymbol = symbol_type_skip_qualifiers(symbol);
	if (tsymbol != symbol) {
	    vdebug(4,LOG_D_LOOKUP,"skipped type symbol %s, now: ",
		   symbol_get_name(symbol));
	    symbol_dump(tsymbol,&udn);
	    symbol = tsymbol;
	}
    }

    if (SYMBOL_IST_FUNCTION(symbol)
	&& symbol->s.ti->d.f.count) {
	list_for_each_entry(retval_instance,&symbol->s.ti->d.f.args,
			    d.v.member) {
	    retval = retval_instance->d.v.member_symbol;
	    if (retval->name && strcmp(retval->name,member) == 0)
		goto out;
	}
    }
    else if (SYMBOL_IST_ENUM(symbol)) {
	list_for_each_entry(retval_instance,&symbol->s.ti->d.e.members,
			    d.v.member) {
	    retval = retval_instance->d.v.member_symbol;
	    if (retval->name && strcmp(retval->name,member) == 0)
		goto out;
	}
    }
    else if (SYMBOL_IST_STUN(symbol)) {
	/*
	 * Check all our members.  If we come across an unnamed struct
	 * or union member, push it onto our anon stack and come back to
	 * it.  This avoids non-tail recursion.
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
	    list_for_each_entry(retval_instance,&type->s.ti->d.su.members,
				d.v.member) {
		retval = retval_instance->d.v.member_symbol;
		//vdebug(4,LOG_D_SYMBOL,"checking symbol: ");
		//symbol_dump(retval,&udn);

		if (SYMBOL_IST_STUN(retval->datatype) 
		    && !retval->name) {
		    /* push this one for later examination. */
		    if (stacklen == stackalen) {
			stackalen += 4;
			if (!(tmpstack = (struct symbol **)realloc(anonstack,
								   sizeof(struct symbol *)*stackalen))) {
			    verror("realloc anonstack: %s\n",strerror(errno));
			    goto errout;
			}
			anonstack = tmpstack;

			if (!(tmpparentstack = (int *)realloc(parentstack,
							      sizeof(int)*stackalen))) {
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
		vwarn("big stackalen=%d, stack=%d\n",stackalen,stacklen);
	    else 
		vdebug(4,LOG_D_SYMBOL,"stackalen=%d, stack=%d\n",
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
    else if (SYMBOL_IS_FULL_FUNCTION(symbol)) {
	/* First, check our args. */
	list_for_each_entry(retval_instance,&symbol->s.ii->d.f.args,
			    d.v.member) {
	    retval = retval_instance->d.v.member_symbol;
	    if (retval->name && strcmp(retval->name,member) == 0)
		goto out;
	}

	/* Second, check our internal symbol table.  Wait a sec, the
	 * args are in the internal symtab too!  Hmmm.
	 */
	lsymbol = __symtab_lookup_sym(symbol->s.ii->d.f.symtab,member,NULL,
				      SYMBOL_TYPE_FLAG_VAR 
				      | SYMBOL_TYPE_FLAG_FUNCTION
				      | SYMBOL_TYPE_FLAG_LABEL);
	if (lsymbol) {
	    symbol = lsymbol->symbol;
	    /* Don't force free; somebody might have a reference */
	    lsymbol_free(lsymbol,0);
	    return symbol;
	}

	/* Third, check any anonymous subtabs.
	 * 
	 * NOTE: for now, only check one level; if the debuginfo emitter
	 * has added more anonymous lexical scopes, or whatever, we
	 * don't support them yet.
	 */
	list_for_each_entry(subtab,&symbol->s.ii->d.f.symtab->subtabs,member) {
	    if (subtab->name)
		continue;

	    lsymbol = __symtab_lookup_sym(subtab,member,NULL,
					  SYMBOL_TYPE_FLAG_VAR 
					  | SYMBOL_TYPE_FLAG_FUNCTION
					  | SYMBOL_TYPE_FLAG_FUNCTION);
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
	    vdebug(4,LOG_D_LOOKUP,"skipped type symbol for %s, now: ",
		   symbol_get_name(symbol->datatype));
	    symbol_dump(tsymbol,&udn);
	}

	/* Make sure the datatype is fully loaded before we search it. */
	if (tsymbol->loadtag == LOADTYPE_PARTIAL) {
	    vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,
		   "expanding partial type symbol %s\n",
		   symbol_get_name(tsymbol));
	    debugfile_expand_symbol(tsymbol->symtab->debugfile,tsymbol);
	    vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,
		   "expanded partial type symbol %s\n",
		   symbol_get_name(tsymbol));
	}

	if (SYMBOL_IST_STUN(tsymbol)) {
	    //vdebug(3,LOG_D_SYMBOL,"returning result of searching S/U type symbol: ");
	    //symbol_dump(tsymbol,&udn);

	    return __symbol_get_one_member(tsymbol,member,chainptr);
	}
	else if (SYMBOL_IST_PTR(tsymbol)) {
	    /*
	     * We keep looking inside the pointed-to type, autoexpanding it
	     * if necessary.
	     */
	    return __symbol_get_one_member(symbol_type_skip_ptrs(tsymbol),
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
    //vdebug(3,LOG_D_SYMBOL,"returning symbol: ");
    //symbol_dump(retval,&udn);
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
    struct symtab *symtab;
    int i;

    if (!SYMBOL_IS_FULL_FUNCTION(symbol))
	return 0;

    if ((symtab = symbol->s.ii->d.f.symtab)) {
	if (RANGE_IS_PC(&symtab->range)) {
	    if (symtab->range.r.a.lowpc <= obj_addr 
		&& obj_addr < symtab->range.r.a.highpc) 
		return 1;
	    else 
		return 0;
	}
	else if (RANGE_IS_LIST(&symtab->range)) {
	    for (i = 0; i < symtab->range.r.rlist.len; ++i) {
		if (symtab->range.r.rlist.list[i]->start <= obj_addr
		    && obj_addr < symtab->range.r.rlist.list[i]->end) {
		    return 1;
		}
	    }
	}
	else {
	    vwarn("function %s range is not PC/list!\n",symbol->name);
	}
    }
    else
	vwarn("function %s does not have symtab!\n",symbol->name);

    return 0;
}

/*
 * Given an IP (as an object-relative address), check and see if this
 * symbol is currently visible (in scope).  To do this we, check if the
 * IP is in the symtab's range; or if it is in any child symtab's range
 * where no symbol in that symtab overrides the primary symbol name!
 */
int symbol_visible_at_ip(struct symbol *symbol,ADDR ip) {
    struct symtab *symtab = symbol->symtab;
    struct range *range;
    int retval = 0;
    int i;
    gpointer data = NULL;

    if (SYMBOL_IS_TYPE(symbol)) {
	return 0;
    }

    /* XXX: global check and return 1 if so? */

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

struct symbol *symbol_get_one_member(struct symbol *symbol,char *member) {
    struct symbol *retval = __symbol_get_one_member(symbol,member,NULL);

    if (retval) 
	RHOLD(retval);

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
	retval = __symbol_get_one_member(retval,member,NULL);
	if (!retval)
	    break;
    }

    free(mlist);

    if (retval)
	RHOLD(retval);

    return retval;
}

struct symbol *symbol_get_datatype(struct symbol *symbol) {
    struct symbol *datatype = symbol->datatype;

    if (SYMBOL_IS_FULL_INSTANCE(symbol) && symbol->s.ii->origin) {
	/* If it has an abstract origin, use the abstract origin's
	 * type!  And there may be a chain of abstract origins, so we have
	 * to follow them!
	 */
	while (1) {
	    /* If it is not abstract, then stop looking. */
	    if (!symbol->s.ii->origin)
		break;

	    /* Otherwise, if its origin's origin is abstract, keep going. */
	    if (symbol->s.ii->origin->s.ii->origin) 
		symbol = symbol->s.ii->origin;
	    /* If the origin's origin is not abstract, it's the real origin
	     * -- so if it doesn't have a datatype...
	     */
	    else if (symbol->s.ii->origin->datatype) {
		datatype = symbol->s.ii->origin->datatype;
		break;
	    }
	    /* Error out! */
	    else {
		verror("abstract origin %s of inline instance %s has no datatype!\n",
		       symbol_get_name(symbol->s.ii->origin),
		       symbol_get_name(symbol));
		errno = EINVAL;
		return NULL;
	    }
	}
    }

    return datatype;
}

/*
 * Skips const and volatile types, for now.  Ok, skip typedefs too!
 */
struct symbol *symbol_type_skip_qualifiers(struct symbol *type) {
    if (!SYMBOL_IS_TYPE(type))
	return NULL;

    while (type->type == SYMBOL_TYPE_TYPE
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

int symbol_is_inlined(struct symbol *symbol) {
    if (SYMBOL_IS_FULL_INSTANCE(symbol)
	&& symbol->s.ii->inline_instances)
	return 1;
    return 0;
}

int symbol_type_is_char(struct symbol *type) {
    if (!SYMBOL_IS_TYPE(type))
	return 0;

    type = symbol_type_skip_qualifiers(type);

    /* If this type is not full, don't attempt to deref full info! */
    if (!SYMBOL_IS_FULL_TYPE(type))
	return 0;

    if (type->datatype_code == DATATYPE_BASE
	&& type->size == 1
	&& (type->s.ti->d.t.encoding == ENCODING_SIGNED_CHAR
	    || type->s.ti->d.t.encoding == ENCODING_UNSIGNED_CHAR)) 
	return 1;

    return 0;
}

unsigned int symbol_type_array_bytesize(struct symbol *type) {
    int i;
    int size;

    if (!SYMBOL_IS_TYPE(type))
	return 0;

    type = symbol_type_skip_qualifiers(type);

    if (type->datatype_code != DATATYPE_ARRAY)
	return 0;

    if (!SYMBOL_IS_FULL(type) || !SYMBOL_IS_FULL(type->datatype))
	return 0;

    size = type->datatype->size;

    for (i = 0; i < type->s.ti->d.a.count; ++i) {
	vdebug(5,LOG_D_SYMBOL,"subrange length is %d\n",
	       type->s.ti->d.a.subranges[i] + 1);
	size = size * (type->s.ti->d.a.subranges[i] + 1);
    }

    vdebug(5,LOG_D_SYMBOL,"full array size is %d for array type %s\n",size,
	   type->name);

    return size;
}

unsigned int symbol_type_full_bytesize(struct symbol *type) {
    if (!SYMBOL_IS_TYPE(type))
	return 0;

    type = symbol_type_skip_qualifiers(type);

    if (type->datatype_code == DATATYPE_ARRAY)
	return symbol_type_array_bytesize(type);
    return symbol_type_bytesize(type);
}

REFCNT symbol_hold(struct symbol *symbol) {
    vdebug(10,LOG_D_SYMBOL,"holding symbol %s//%s at %"PRIxSMOFFSET"\n",
	   SYMBOL_TYPE(symbol->type),symbol_get_name(symbol),symbol->ref);
    return RHOLD(symbol);
}

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
	vdebug(10,LOG_D_SYMBOL,
	       "dynamic/shared symbol %s//%s at %"PRIxSMOFFSET":     ",
	       SYMBOL_TYPE(symbol->type),symbol_get_name(symbol),symbol->ref);
	retval = RPUT(symbol,symbol);
	if (retval)
	    vdebugc(10,LOG_D_SYMBOL,"  refcnt %d\n",retval);
	else 
	    vdebug(10,LOG_D_SYMBOL,"dynamic/shared symbol %s refcnt 0\n",name);
    }
    else {
	vdebug(10,LOG_D_SYMBOL,"symbol %s//%s at %"PRIxSMOFFSET":     ",
	       SYMBOL_TYPE(symbol->type),symbol_get_name(symbol),symbol->ref);
	retval = RPUTNF(symbol);
	retval = RPUT(symbol,symbol);
	if (retval)
	    vdebugc(10,LOG_D_SYMBOL,"  refcnt %d\n",retval);
	else 
	    vdebug(10,LOG_D_SYMBOL,"symbol %s refcnt 0\n",name);
    }
    if (name)
	free(name);

    return retval;
}

REFCNT symbol_free(struct symbol *symbol,int force) {
    struct symbol_instance *tmp;
    struct symbol_instance *tmp2;
    struct symbol *tmp_symbol;
    int retval = symbol->refcnt;

    if (symbol->freenextpass) 
	return symbol->refcnt;

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
	vdebug(5,LOG_D_SYMBOL,"freeing symbol %s//%s at %"PRIxSMOFFSET"\n",
	       SYMBOL_TYPE(symbol->type),symbol->name,symbol->ref);
    else 
	vdebug(5,LOG_D_SYMBOL,"freeing symbol %s//(null) at %"PRIxSMOFFSET"\n",
	       SYMBOL_TYPE(symbol->type),symbol->ref);

    /*
     * If this symbol refers to a type from some other CU, release on
     * that type.
     */
    if (symbol->usesshareddatatype && symbol->datatype) {
	symbol_release(symbol->datatype);
	symbol->usesshareddatatype = 0;
	symbol->datatype = NULL;
    }
    /* If this is a dynamic symbol, we have to recursively release any
     * dynamic symbols it points to.
     */
    else if (symbol->issynthetic && symbol->datatype) {
	symbol_release(symbol->datatype);
	symbol->datatype = NULL;
    }

    /*
     * We have to recurse through any symbol that has members, because
     * those members are not in any symbol tables, so they won't be freed.
     */
    if (SYMBOL_IS_FULL_FUNCTION(symbol)) {
	if (symbol->s.ii->d.f.fbisloclist
	    && symbol->s.ii->d.f.fb.list)
	    loc_list_free(symbol->s.ii->d.f.fb.list);
	else if (symbol->s.ii->d.f.fbissingleloc
		 && symbol->s.ii->d.f.fb.loc)
	    location_free(symbol->s.ii->d.f.fb.loc);

	/*
	 * Don't free the function's symtab -- it is freed in in
	 * symtab_free since all functions will have a parent symtab.
	 */
	//if (symbol->isshared && symbol->s.ii->d.f.symtab)
	//    symtab_free(symbol->s.ii->d.f.symtab);
    }
    else if (SYMBOL_IS_FULL_LABEL(symbol)) {
	/*
	 * Free the range list for a label.
	 */
	if (symbol->s.ii->d.l.range.r.rlist.list)
	    range_list_internal_free(&symbol->s.ii->d.l.range.r.rlist);
    }
    else if (SYMBOL_IST_FULL_ARRAY(symbol)) {
	if (symbol->s.ti->d.a.subranges)
	    free(symbol->s.ti->d.a.subranges);
    }
    else if (SYMBOL_IST_FULL_STUN(symbol)) {
	list_for_each_entry_safe(tmp,tmp2,&symbol->s.ti->d.su.members,
				 d.v.member) {
	    tmp_symbol = tmp->d.v.member_symbol;
	    symbol_free(tmp_symbol,force);
	}
    }
    else if (SYMBOL_IST_FULL_FUNCTION(symbol)) {
	list_for_each_entry_safe(tmp,tmp2,&symbol->s.ti->d.f.args,
				 d.v.member) {
	    tmp_symbol = tmp->d.v.member_symbol;
	    symbol_free(tmp_symbol,force);
	}
    }

    /*
     * Also have to free any constant data allocated.
     */
    if (SYMBOL_IS_FULL_INSTANCE(symbol)
	&& symbol->s.ii->constval
#ifdef DWDEBUG_USE_STRTAB
	&& (!symbol->symtab || !symtab_str_in_dbg_strtab(symbol->symtab,
						     symbol->s.ii->constval))
#endif
	)
	free(symbol->s.ii->constval);

    /*
     * Also have to free any inline instance list.
     */
    if (SYMBOL_IS_FULL_INSTANCE(symbol) && symbol->s.ii->inline_instances) 
	array_list_free(symbol->s.ii->inline_instances);

    /*
     * Also have to free location data, potentially.
     */
    if (SYMBOL_IS_FULL_INSTANCE(symbol))
	location_internal_free(&symbol->s.ii->l);
    
    if (symbol->name
#ifdef DWDEBUG_USE_STRTAB
	     && (!symbol->symtab 
		 || (!symtab_str_in_dbg_strtab(symbol->symtab,symbol->name)
		     && !symtab_str_in_elf_strtab(symbol->symtab,symbol->name)))
#endif
	     ) {
	vdebug(5,LOG_D_SYMBOL,"freeing name %s\n",symbol->name);
	free(symbol->name);
    }

    if (symbol->s.ti) {
	free(symbol->s.ti);
    }
    else if (symbol->s.ii) {
	free(symbol->s.ii);
    }

    vdebug(5,LOG_D_SYMBOL,"freeing %p\n",symbol);
    free(symbol);

    return retval;
}

void symbol_type_mark_members_free_next_pass(struct symbol *symbol,int force) {
    struct symbol_instance *tmp;

    /*
     * We have to recurse through any symbol that has members, because
     * those members are not in any symbol tables, so they won't be freed.
     */
    if (SYMBOL_IST_FULL_STUN(symbol)) {
	list_for_each_entry(tmp,&symbol->s.ti->d.su.members,
				 d.v.member) 
	    tmp->d.v.member_symbol->freenextpass = 1;
    }
    else if (SYMBOL_IST_FULL_FUNCTION(symbol)) {
	list_for_each_entry(tmp,&symbol->s.ti->d.f.args,
				 d.v.member) 
	    tmp->d.v.member_symbol->freenextpass = 1;
    }

    return;
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

    RHOLD(symbol);
}

void lsymbol_prepend(struct lsymbol *lsymbol,struct symbol *symbol) {
    if (!lsymbol->chain)
	lsymbol->chain = array_list_create(1);

    array_list_prepend(lsymbol->chain,symbol);

    RHOLD(symbol);
}

struct lsymbol *lsymbol_create_from_member(struct lsymbol *parent,
					   struct symbol *member) {
    struct array_list *chain;
    struct lsymbol *ls;

    chain = array_list_clone(parent->chain,1);
    array_list_append(chain,member);
    ls = lsymbol_create(member,chain);

    lsymbol_hold_int(ls);

    return ls;
}

struct lsymbol *lsymbol_create_from_symbol(struct symbol *symbol) {
    struct array_list *chain;
    struct lsymbol *ls;
    struct symbol *s = symbol;
    struct symtab *st;

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
	    if (s->isparam && SYMBOL_IS_FUNCTION(s->s.ii->d.v.parent_symbol)) {
		s = s->s.ii->d.v.parent_symbol;
		goto again;
	    }
	    else if (s->ismember 
		     && SYMBOL_IST_STUN(s->s.ii->d.v.parent_symbol)) {
		s = s->s.ii->d.v.parent_symbol;
		goto again;
	    }
	    else {
		/* if (!SYMBOL_IS_FULL(s)
		 *  || (s->isparam && SYMBOL_IST_FUNCTION(s->s.ii->d.v.parent_symbol))
		 *  || (s->ismember)) {
		 */
		goto out;
	    }
	}
	goto out;
    }
    else if (SYMBOL_IS_VAR(s) || SYMBOL_IS_FUNCTION(s)) {
	/* If the symtab the var/function is on is not the root, trace
	 * up until we find either the root symtab, or a function
	 * symtab.  If we find a function's symtab, we keep going up and
	 * look for more functions.  When we hit the root symtab, we're
	 * done, of course.
	 */
	st = s->symtab;
	while (st && !SYMTAB_IS_ROOT(st) && !st->symtab_symbol)
	    st = st->parent;
	if (st->symtab_symbol) {
	    s = st->symtab_symbol;
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

char *lsymbol_get_name(struct lsymbol *lsymbol) {
    if (lsymbol->symbol)
	return symbol_get_name(lsymbol->symbol);
    return NULL;
}

struct symbol *lsymbol_get_symbol(struct lsymbol *lsymbol) {
    return lsymbol->symbol;
}

void lsymbol_hold_int(struct lsymbol *lsymbol) {
    int i;
    for (i = 0; i < array_list_len(lsymbol->chain); ++i) {
	RHOLD((struct symbol *)array_list_item(lsymbol->chain,i));
    }
}

void lsymbol_hold(struct lsymbol *lsymbol) {
    RHOLD(lsymbol);
}

void lsymbol_release(struct lsymbol *lsymbol) {
    RPUT(lsymbol,lsymbol);
}

REFCNT lsymbol_free(struct lsymbol *lsymbol,int force) {
    int retval = lsymbol->refcnt;
    int i;

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
	    RPUTNF((struct symbol *)array_list_item(lsymbol->chain,i));
	}
	array_list_free(lsymbol->chain);
    }
    else if (lsymbol->symbol) {
	RPUTNF(lsymbol->symbol);
    }
    free(lsymbol);

    return retval;
}

/**
 ** Location functions that do not require a live target.  Operations on
 ** locations that *do* require a live target (i.e., location resolution
 ** into a real address) are found in target/location.c .
 **/

struct location *location_create(void) {
    struct location *location = \
	(struct location *)malloc(sizeof(struct location));
    memset(location,0,sizeof(struct location));
    location->loctype = LOCTYPE_UNKNOWN;
    return location;
}

OFFSET location_resolve_offset(struct location *location,
			       struct array_list *symbol_chain,
			       struct symbol **top_symbol_saveptr,
			       int *chain_top_symbol_idx_saveptr) {
    int chlen;
    int i;
    OFFSET totaloffset;
    struct symbol *symbol;
    struct symbol *tdatatype;

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
	if (i < (chlen - 1) && SYMBOL_IS_VAR(symbol)
	    && (SYMBOL_IST_PTR(symbol->datatype)
		|| SYMBOL_IST_CONST(symbol->datatype)
		|| SYMBOL_IST_VOL(symbol->datatype)
		|| SYMBOL_IST_TYPEDEF(symbol->datatype))
	    && (tdatatype = symbol_type_skip_qualifiers(symbol_type_skip_ptrs(symbol_type_skip_qualifiers(symbol->datatype))))
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

void location_internal_free(struct location *location) {
    if (location->loctype == LOCTYPE_RUNTIME) {
	if (location->l.runtime.data) 
	    free(location->l.runtime.data);
    }
    else if (location->loctype == LOCTYPE_LOCLIST) {
	if (location->l.loclist)
	    loc_list_free(location->l.loclist);
    }
}

void location_free(struct location *location) {
    location_internal_free(location);
    free(location);
}

/**
 ** Range lists and loc lists.
 ** XXX: probably shouldn't expose this to the user?
 **/
struct range_list *range_list_create(int initsize) {
    struct range_list *list = \
	(struct range_list *)malloc(sizeof(struct range_list));
    memset(list,0,sizeof(struct range_list));
    if (initsize) {
	list->alen = initsize;
	list->list = (struct range_list_entry **)malloc(sizeof(struct range_list_entry *)*initsize);
    }
    return list;
}

int range_list_add(struct range_list *list,ADDR start,ADDR end) {
    struct range_list_entry **lltmp;

    /* allocate space for another entry if necessary */
    if (list->len == list->alen) {
	if (!(lltmp = (struct range_list_entry **)realloc(list->list,
							  (list->len+1)*sizeof(struct range_list_entry *)))) {
	    verror("realloc: %s\n",strerror(errno));
	    return -1;
	}
	list->list = lltmp;
	list->alen += 1;
    }

    list->list[list->len] = (struct range_list_entry *)malloc(sizeof(struct range_list_entry));
    if (!list->list[list->len]) {
	verror("range_list_entry malloc: %s\n",strerror(errno));
	return -1;
    }

    list->list[list->len]->start = start;
    list->list[list->len]->end = end;

    list->len += 1;

    return 0;
}

void range_list_internal_free(struct range_list *list) {
    int i;

    if (list->list) {
	for (i = 0; i < list->len; ++i) {
	    free(list->list[i]);
	}
	free(list->list);
    }
}

void range_list_free(struct range_list *list) {
    range_list_internal_free(list);
    free(list);
}

struct loc_list *loc_list_create(int initsize) {
    struct loc_list *list = \
	(struct loc_list *)malloc(sizeof(struct loc_list));
    memset(list,0,sizeof(struct loc_list));
    if (initsize) {
	list->alen = initsize;
	list->list = (struct loc_list_entry **)malloc(sizeof(struct loc_list_entry *)*initsize);
    }
    return list;
}

int loc_list_add(struct loc_list *list,ADDR start,ADDR end,struct location *loc) {
    struct loc_list_entry **lltmp;

    /* allocate space for another entry if necessary */
    if (list->len == list->alen) {
	if (!(lltmp = (struct loc_list_entry **)realloc(list->list,
							(list->len+1)*sizeof(struct loc_list_entry *)))) {
	    verror("realloc: %s\n",strerror(errno));
	    return -1;
	}
	list->list = lltmp;
	list->alen += 1;
    }

    list->list[list->len] = (struct loc_list_entry *)malloc(sizeof(struct loc_list_entry));
    if (!list->list[list->len]) {
	verror("loc_list_entry malloc: %s\n",strerror(errno));
	return -1;
    }

    list->list[list->len]->start = start;
    list->list[list->len]->end = end;
    list->list[list->len]->loc = loc;

    list->len += 1;

    return 0;
}

void loc_list_free(struct loc_list *list) {
    int i;

    for (i = 0; i < list->len; ++i) {
	if (list->list[i]->loc)
	    location_free(list->list[i]->loc);
	free(list->list[i]);
    }

    free(list->list);
    free(list);
}

/**
 ** Data structure dumping functions.
 **/

void g_hash_foreach_dump_symtab(gpointer key __attribute__((unused)),
				gpointer value,gpointer userdata) {
    struct dump_info *ud = (struct dump_info *)userdata;
    symtab_dump((struct symtab *)value,ud);
    fprintf(ud->stream,"\n");
}

void g_hash_foreach_dump_symbol(gpointer key __attribute__((unused)),
				gpointer value,gpointer userdata) {
    struct dump_info *ud = (struct dump_info *)userdata;
    symbol_dump((struct symbol *)value,ud);
    fprintf(ud->stream,"\n");
}

void g_hash_foreach_dump_duplist(gpointer key,gpointer value,gpointer userdata) {
    struct dump_info *ud = (struct dump_info *)userdata;
    struct array_list *duplist = (struct array_list *)value;
    char *name = (char *)key;
    int i;
    struct dump_info udn;

    udn.prefix = malloc(strlen(ud->prefix)+2);
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
}

void debugfile_dump(struct debugfile *debugfile,struct dump_info *ud,
		    int types,int globals,int symtabs,int elfsymtab) {
    char *p = "";
    char *np1, *np2;
    struct dump_info udn;

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

    fprintf(ud->stream,"%sdebugfile(%s):\n",p,debugfile->idstr);
    fprintf(ud->stream,"%s    filename: %s\n",p,debugfile->filename);
    fprintf(ud->stream,"%s    type:     %s (%d)\n",p,
	    DEBUGFILE_TYPE(debugfile->type),debugfile->type);
    fprintf(ud->stream,"%s    name:     %s\n",p,debugfile->name);
    fprintf(ud->stream,"%s    version:  %s\n",p,debugfile->version);
    fprintf(ud->stream,"%s    refcnt:   %d\n",p,debugfile->refcnt);
    fprintf(ud->stream,"%s  types: (%d)\n",p,g_hash_table_size(debugfile->types));
    if (types) 
	g_hash_table_foreach(debugfile->types,g_hash_foreach_dump_symbol,&udn);
    fprintf(ud->stream,"%s  shared types: (%d+%d+%d)\n",p,
	    g_hash_table_size(debugfile->shared_types->tab),
	    g_hash_table_size(debugfile->shared_types->anontab),
	    g_hash_table_size(debugfile->shared_types->duptab));
    if (types) {
	g_hash_table_foreach(debugfile->shared_types->tab,
			     g_hash_foreach_dump_symbol,&udn);
	g_hash_table_foreach(debugfile->shared_types->anontab,
			     g_hash_foreach_dump_symbol,&udn);
	g_hash_table_foreach(debugfile->shared_types->duptab,
			     g_hash_foreach_dump_duplist,&udn);
    }
    fprintf(ud->stream,"%s  globals: (%d)\n",
	    p,g_hash_table_size(debugfile->globals));
    if (globals) 
	g_hash_table_foreach(debugfile->globals,g_hash_foreach_dump_symbol,&udn);
    fprintf(ud->stream,"%s  symtabs: (%d)\n",
	    p,g_hash_table_size(debugfile->srcfiles));
    //ud->prefix = np1;
    if (symtabs) {
	g_hash_table_foreach(debugfile->srcfiles,g_hash_foreach_dump_symtab,&udn);
	if (g_hash_table_size(debugfile->srcfiles))
	    fprintf(ud->stream,"\n");
    }
    fprintf(ud->stream,"%s  ELF symtab: (tab=%d,anontab=%d,duptab=%d)\n",p,
	    g_hash_table_size(debugfile->elf_symtab->tab),
	    g_hash_table_size(debugfile->elf_symtab->anontab),
	    g_hash_table_size(debugfile->elf_symtab->duptab));
    if (elfsymtab) {
	symtab_dump(debugfile->elf_symtab,&udn);
	fprintf(ud->stream,"\n");
    }

    if (ud->prefix) {
	free(np1);
	free(np2);
    }
}

void range_dump(struct range *range,struct dump_info *ud) {
    int i;

    if (RANGE_IS_PC(range))
	fprintf(ud->stream,"%sRANGE(pc): low=0x%" PRIxADDR ", high=0x%" PRIxADDR,
		ud->prefix,range->r.a.lowpc,range->r.a.highpc);
    else if (RANGE_IS_LIST(range)) {
	if (range->r.rlist.len == 0) {
	    fprintf(ud->stream,"%sRANGE(list): ()",ud->prefix);
	    return;
	}

	fprintf(ud->stream,"%sRANGE(list): (",ud->prefix);
	for (i = 0; i < range->r.rlist.len; ++i) {
	    if (i > 0)
		fprintf(ud->stream,",");

	    fprintf(ud->stream,"[0x%" PRIxADDR ",0x%" PRIxADDR "]",
		    range->r.rlist.list[i]->start,range->r.rlist.list[i]->end);
	}
	fprintf(ud->stream,")");
    }
}

void loc_list_dump(struct loc_list *list,struct dump_info *ud) {
    int i;
    struct dump_info udn = {
	.stream = ud->stream,
	.prefix = "",
	.detail = ud->detail,
	.meta = ud->meta,
    };

    fprintf(ud->stream,"%sLOCLIST(",ud->prefix);
    for (i = 0; i < list->len; ++i) {
	if (i > 0)
	    fprintf(ud->stream,",");

	fprintf(ud->stream,"[0x%" PRIxADDR ",0x%" PRIxADDR,
		list->list[i]->start,list->list[i]->end);
	if (list->list[i]->loc) {
	    fprintf(ud->stream,"->");
	    location_dump(list->list[i]->loc,&udn);
	}
	fprintf(ud->stream,"]");
    }
    fprintf(ud->stream,")");
}

void symtab_dump(struct symtab *symtab,struct dump_info *ud) {
    struct symtab *csymtab;
    char *p = "";
    char *np;
    char *np2;
    struct dump_info udn;
    struct dump_info udn2;
    struct dump_info udn3 = {
	.stream = ud->stream,
	.prefix = "",
	.detail = ud->detail,
	.meta = ud->meta,
    };

    if (ud->prefix) {
	p = ud->prefix;
	np = malloc(strlen(p) + 1 + 2);
	np2 = malloc(strlen(p) + 1 + 4);
	sprintf(np,"%s%s",p,"  ");
	sprintf(np2,"%s%s",p,"    ");
    }
    else {
	np = "  ";
	np2 = "    ";
    }
    udn.prefix = np;
    udn.stream = ud->stream;
    udn.meta = ud->meta;
    udn.detail = ud->detail;
    udn2.prefix = np2;
    udn2.stream = ud->stream;
    udn2.meta = ud->meta;
    udn2.detail = ud->detail;

    if (symtab->name)
	fprintf(ud->stream,"%ssymtab(%s) (",p,symtab->name);
    else
	fprintf(ud->stream,"%ssymtab() (",p);
    if (SYMTAB_IS_CU(symtab)) {
	if (symtab->meta->compdirname)
	    fprintf(ud->stream,"compdirname=%s ",symtab->meta->compdirname);
	if (symtab->meta->producer)
	    fprintf(ud->stream,"producer=%s ",symtab->meta->producer);
	if (symtab->meta->language)
	    fprintf(ud->stream,"language=%d ",symtab->meta->language);
    }
    range_dump(&symtab->range,&udn3);
    fprintf(ud->stream,")");
    if (g_hash_table_size(symtab->tab) > 0 || !list_empty(&symtab->subtabs)
	|| g_hash_table_size(symtab->duptab) > 0) {
	fprintf(ud->stream," {\n");
	g_hash_table_foreach(symtab->tab,g_hash_foreach_dump_symbol,&udn);
	g_hash_table_foreach(symtab->duptab,g_hash_foreach_dump_duplist,&udn);

	if (!list_empty(&symtab->subtabs)) {
	    fprintf(ud->stream,"%s  subscopes:\n",p);
	    list_for_each_entry(csymtab,&(symtab->subtabs),member) {
		symtab_dump(csymtab,&udn2);
		fprintf(ud->stream,"\n");
	    }
	}

	fprintf(ud->stream,"%s}",p);
    }
    else 
	fprintf(ud->stream," { }");

    if (ud->prefix) {
	free(np);
	free(np2);
    }
}

void location_dump(struct location *location,struct dump_info *ud) {
    switch(location->loctype) {
    case LOCTYPE_ADDR:
    case LOCTYPE_REALADDR:
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
		location->l.regoffset.reg,location->l.regoffset.offset);
	break;
    case LOCTYPE_FBREG_OFFSET:
	fprintf(ud->stream,"FBREGOFFSET(%"PRIiOFFSET")",location->l.fboffset);
	break;
    case LOCTYPE_MEMBER_OFFSET:
	fprintf(ud->stream,"MEMBEROFFSET(%"PRIiOFFSET")",
		location->l.member_offset);
	break;
    case LOCTYPE_RUNTIME:
	fprintf(ud->stream,"RUNTIMEDWOP (%p,%d)",
		location->l.runtime.data,location->l.runtime.len);
	break;
    case LOCTYPE_LOCLIST:
	loc_list_dump(location->l.loclist,ud);
	break;
    case LOCTYPE_UNKNOWN:
    case __LOCTYPE_MAX:
	break;
    }
}

void symbol_label_dump(struct symbol *symbol,struct dump_info *ud) {
    struct dump_info udn = {
	.stream = ud->stream,
	.prefix = "",
	.detail = ud->detail,
	.meta = ud->meta,
    };

    fprintf(ud->stream,"%s",symbol->name);
    if (ud->meta && SYMBOL_IS_FULL(symbol)) 
	range_dump(&symbol->s.ii->d.l.range,&udn);
}

void symbol_var_dump(struct symbol *symbol,struct dump_info *ud) {
    struct symbol *datatype = symbol_get_datatype(symbol);
    struct dump_info udn = {
	.stream = ud->stream,
	.prefix = ud->prefix,
	.detail = 0,
	.meta = 0,
    };
    struct dump_info udn2 = {
	.stream = ud->stream,
	.prefix = "",
	.detail = 0,
	.meta = 0,
    };

    if (ud->detail) {
	//if (1 || !(symbol->type == SYMBOL_TYPE_VAR
	//    && symbol->isenumval)) {
	    if (datatype) {
		symbol_type_dump(datatype,&udn);
	    }
	    else if (symbol->datatype_ref) 
		fprintf(ud->stream,"tref%"PRIxSMOFFSET,symbol->datatype_ref);
	//}
    }
    /* all variables are named, but not all members of structs/unions! */
    /* well, inlined params aren't named either. */
    if (symbol->isinlineinstance && symbol->isparam) {
	/* Only print a space if we printed the var's type above! */
	if (ud->detail)
	    fprintf(ud->stream," ");

	if (SYMBOL_IS_FULL(symbol)) {
	    if (symbol->s.ii->origin) {
		fprintf(ud->stream,"INLINED_PARAM(");
		symbol_var_dump(symbol->s.ii->origin,&udn);
		fprintf(ud->stream,")");
	    }
	    else
		fprintf(ud->stream,"INLINED_ANON_PARAM()");
	}
	else {
	    fprintf(ud->stream,"INLINED_PARAM(<PUNKNOWN>)");
	}
    }
    else if (symbol->name) {
	/* Only print a space if we printed the var's type above! */
	if (ud->detail)
	    fprintf(ud->stream," ");

	fprintf(ud->stream,"%s",symbol->name);
    }

    if (SYMBOL_IS_FULL_VAR(symbol)
	&& symbol->s.ii->d.v.bit_size > 0) {
	/* this is a bitfield */
	fprintf(ud->stream,":%hd(%hd)",symbol->s.ii->d.v.bit_size,
		symbol->s.ii->d.v.bit_offset);
    }
    if (SYMBOL_IS_FULL_VAR(symbol)
	&& symbol->isenumval) {
	// XXX fix type printing -- this *is* a malloc'd constval
	fprintf(ud->stream," = %d",*((int *)symbol->s.ii->constval));
    }

    if (ud->meta && !symbol->isparam && !symbol->ismember) {
	fprintf(ud->stream," (external=%d,declaration=%d)",
		symbol->isexternal,symbol->isdeclaration);
    }

    if (ud->detail && SYMBOL_IS_FULL_INSTANCE(symbol) 
	&& symbol->s.ii->l.loctype != LOCTYPE_UNKNOWN) {
	fprintf(ud->stream," @@ ");
	location_dump(&symbol->s.ii->l,&udn2);

	if (symbol->s.ii->constval)
	    fprintf(ud->stream," @@ CONST(%p)",symbol->s.ii->constval);
    }
    else if (ud->detail)
	fprintf(ud->stream," @@ 0x%"PRIxADDR" (size=%d)",
		symbol->base_addr,symbol->size);
}

void symbol_function_dump(struct symbol *symbol,struct dump_info *ud) {
    struct symbol *datatype = symbol_get_datatype(symbol);
    struct symbol_instance *arg_instance;
    struct symbol *arg;
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

    if (ud->detail) {
	if (datatype) {
	    symbol_type_dump(datatype,&udn);
	    fprintf(ud->stream," ");
	}
	else if (symbol->datatype_ref)
	    fprintf(ud->stream,"ftref%" PRIxSMOFFSET " ",symbol->datatype_ref);
    }
    if (symbol->isinlineinstance) {
	if (SYMBOL_IS_FULL_INSTANCE(symbol)) {
	    if (symbol->s.ii->origin) {
		fprintf(ud->stream,"INLINED_FUNC(");
		symbol_var_dump(symbol->s.ii->origin,&udn);
		fprintf(ud->stream,")");
	    }
	    else
		fprintf(ud->stream,"INLINED_ANON_FUNC()");
	}
	else {
	    fprintf(ud->stream,"INLINED_FUNC(<PUNKNOWN>)");
	}
    }
    else 
	fprintf(ud->stream,"%s",symbol->name);
    if (ud->detail && SYMBOL_IS_FULL_INSTANCE(symbol)) {
	fprintf(ud->stream," (");
	list_for_each_entry(arg_instance,&(symbol->s.ii->d.f.args),d.v.member) {
	    arg = arg_instance->d.v.member_symbol;
	    ++i;
	    symbol_var_dump(arg,ud);
	    if (i != symbol->s.ii->d.f.count)
		fprintf(ud->stream,",");
	}
	if (symbol->s.ti->d.f.hasunspec) {
	    if (i)
		fprintf(ud->stream,",");
	    fprintf(ud->stream,"...");
	}
	fprintf(ud->stream,")");

	if (symbol->s.ii->constval)
	    fprintf(ud->stream," @@ CONST(%p)",symbol->s.ii->constval);
    }

    if (ud->meta) {
	fprintf(ud->stream," (external=%d,declaration=%d,prototyped=%d",
		symbol->isexternal,symbol->isdeclaration,symbol->isprototyped);
	if (SYMBOL_IS_FULL(symbol)) {
	    fprintf(ud->stream,",declinline=%d,inlined=%d",
		    symbol->s.ii->isdeclinline,symbol->s.ii->isinlined);
	    if (symbol->s.ii->d.f.fbisloclist && symbol->s.ii->d.f.fb.list 
		&& symbol->s.ii->d.f.fb.list->len) {
		fprintf(ud->stream,",frame_base=");
		loc_list_dump(symbol->s.ii->d.f.fb.list,&udn2);
	    }
	    else if (symbol->s.ii->d.f.fbissingleloc 
		     && symbol->s.ii->d.f.fb.loc) { 
		fprintf(ud->stream,",frame_base=");
		location_dump(symbol->s.ii->d.f.fb.loc,&udn2);
	    }

	    if (symbol->s.ii->inline_instances) {
		fprintf(ud->stream,",inlineinstances=(");
		for (i = 0; i < array_list_len(symbol->s.ii->inline_instances); ++i) {
		    fprintf(ud->stream,"0x%"PRIxADDR",",
			    ((struct symbol *)(array_list_item(symbol->s.ii->inline_instances,i)))->base_addr);
		}
		fprintf(ud->stream,")");
	    }
	}
	fprintf(ud->stream,")");
    }

    if (ud->detail && SYMBOL_IS_FULL_INSTANCE(symbol)) {
	fprintf(ud->stream,"\n");

	symtab_dump(symbol->s.ii->d.f.symtab,&udn);
    }
    else if (ud->detail)
	fprintf(ud->stream," @@ 0x%"PRIxADDR" (size=%d)",
		symbol->base_addr,symbol->size);
}

void symbol_type_dump(struct symbol *symbol,struct dump_info *ud) {
    struct symbol_instance *member_instance;
    struct symbol *member;
    int i = 0;
    char *ss;
    struct dump_info udn = {
	.stream = ud->stream,
	.prefix = ud->prefix,
	.detail = 0,
	.meta = 0,
    };

    if (!symbol) {
	fprintf(ud->stream,"NULLTYPESYM!");
	return;
    }

    switch (symbol->datatype_code) {
    case DATATYPE_VOID:
	fprintf(ud->stream,"void");
	break;
    case DATATYPE_ARRAY:
	symbol_type_dump(symbol->datatype,&udn);
	if (SYMBOL_IS_FULL(symbol)) {
	    fprintf(ud->stream," ");
	    for (i = 0; i < symbol->s.ti->d.a.count; ++i) {
		fprintf(ud->stream,"[%d]",symbol->s.ti->d.a.subranges[i] + 1);
	    }
	}
	else {
	    fprintf(ud->stream,"[<PUNKNOWN>]");
	}
	break;
    case DATATYPE_CONST:
	fprintf(ud->stream,"const ");
	symbol_type_dump(symbol->datatype,ud);
	break;
    case DATATYPE_VOL:
	fprintf(ud->stream,"volatile ");
	symbol_type_dump(symbol->datatype,ud);
	break;
    case DATATYPE_STRUCT:
    case DATATYPE_UNION:
	ss = "struct";
	if (symbol->datatype_code == DATATYPE_UNION)
	    ss = "union";
	if (!symbol->name)
	    fprintf(ud->stream,"%s",ss);
	else
	    fprintf(ud->stream,"%s",symbol->name);
	if (ud->meta && SYMBOL_IS_FULL(symbol)) 
	    fprintf(ud->stream," (byte_size=%d)",symbol->size);
	if (ud->detail && SYMBOL_IS_FULL(symbol)) {
	    fprintf(ud->stream," { ");
	    list_for_each_entry(member_instance,&(symbol->s.ti->d.su.members),
				d.v.member) {
		member = member_instance->d.v.member_symbol;
		/* NOTE: C structs/unions can have members of the same
		 * type as the parent struct -- so don't recurse if this
		 * is true! -- OR if it's a pointer chain back to the struct.
		 */
		if (member->datatype == symbol) {
		    symbol_var_dump(member,&udn);
		}
		else if (SYMBOL_IST_STUN(member->datatype) 
			 && !member->datatype->name) {
		    symbol_type_dump(member->datatype,ud);

		    if (ud->detail && member->s.ii->l.loctype != LOCTYPE_UNKNOWN) {
			fprintf(ud->stream," @@ ");
			location_dump(&member->s.ii->l,ud);

			if (member->s.ii->constval)
			    fprintf(ud->stream," @@ CONST(%p)",
				    member->s.ii->constval);
		    }
		}
		else 
		    symbol_var_dump(member,ud);
		if (likely(++i != symbol->s.ti->d.su.count))
		    fprintf(ud->stream,"; ");
	    }
	    fprintf(ud->stream," }");
	}
	break;
    case DATATYPE_ENUM:
	if (!symbol_get_name(symbol))
	    fprintf(ud->stream,"enum");
	else
	    fprintf(ud->stream,"%s",symbol_get_name(symbol));
	if (ud->meta && SYMBOL_IS_FULL(symbol)) 
	    fprintf(ud->stream," (byte_size=%d)",symbol->size);
	if (ud->detail && SYMBOL_IS_FULL(symbol)) {
	    fprintf(ud->stream," { ");
	    list_for_each_entry(member_instance,&(symbol->s.ti->d.e.members),
				d.v.member) {
		member = member_instance->d.v.member_symbol;
		symbol_var_dump(member,&udn);
		//symbol_var_dump(member,ud);
		if (likely(++i != symbol->s.ti->d.su.count))
		    fprintf(ud->stream,", ");
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
	if (symbol->datatype) {
	    if (symbol->datatype->type == SYMBOL_TYPE_TYPE
		&& (symbol->datatype->datatype_code == DATATYPE_PTR
		    || symbol->datatype->datatype_code == DATATYPE_VOID 
		    || symbol->datatype->datatype_code == DATATYPE_BASE))
		symbol_type_dump(symbol->datatype,ud);
	    else {
		symbol_type_dump(symbol->datatype,&udn);
	    }
	    fprintf(ud->stream,"*");
	}
	else
	    fprintf(ud->stream,"ptref%"PRIxSMOFFSET" *",
		    symbol->datatype_ref);
	break;
    case DATATYPE_FUNCTION:
	if (ud->detail)
	    symbol_type_dump(symbol->datatype,ud);

	if (SYMBOL_IS_FULL(symbol) && !symbol->name) 
	    fprintf(ud->stream,"()");
	else if (symbol->name)
	    fprintf(ud->stream,"(%s)",symbol->name);

	if (ud->meta)
	    fprintf(ud->stream," (prototyped=%d,external=%d) ",
		    symbol->isprototyped,symbol->isexternal);

	if (ud->detail && SYMBOL_IS_FULL(symbol)) {
	    fprintf(ud->stream,"(");
	    i = 0;
	    list_for_each_entry(member_instance,&(symbol->s.ti->d.f.args),
				d.v.member) {
		member = member_instance->d.v.member_symbol;
		symbol_var_dump(member,ud);
		if (likely(++i != symbol->s.ti->d.f.count))
		    fprintf(ud->stream,", ");
	    }
	    if (symbol->s.ti->d.f.hasunspec) {
		if (i)
		    fprintf(ud->stream,",");
		fprintf(ud->stream,"...");
	    }
		    
	    fprintf(ud->stream,")");
	}
	break;
    case DATATYPE_TYPEDEF:
	if (!ud->detail)
	    fprintf(ud->stream,"%s",symbol->name);
	else if (symbol->datatype) {
	    fprintf(ud->stream,"typedef ");
	    symbol_type_dump(symbol->datatype,ud);
	    fprintf(ud->stream," %s",symbol_get_name_orig(symbol));
	}
	else 
	    fprintf(ud->stream,"typedef tdtref%"PRIxSMOFFSET" %s",
		    symbol->datatype_ref,symbol->name);
	break;
    case DATATYPE_BASE:
	if (!ud->meta || !SYMBOL_IS_FULL(symbol))
	    fprintf(ud->stream,"%s",symbol->name);
	else 
	    fprintf(ud->stream,"%s (byte_size=%d,encoding=%d)",symbol->name,
		    symbol->size,symbol->s.ti->d.t.encoding);
	break;
    case DATATYPE_BITFIELD:
	fprintf(ud->stream,"bitfield %s",symbol->name);
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
    else if (symbol->type == SYMBOL_TYPE_VAR) {
	fprintf(ud->stream,"%svar(%s,line=%d): ",
		p,symbol->name,symbol->srcline);
	symbol_var_dump(symbol,&udn);
    }
    else if (symbol->type == SYMBOL_TYPE_FUNCTION) {
	fprintf(ud->stream,"%sfunction(%s,line=%d): ",
		p,symbol->name,symbol->srcline);
	symbol_function_dump(symbol,&udn);
    }
    else if (symbol->type == SYMBOL_TYPE_LABEL) {
	fprintf(ud->stream,"%slabel(%s,line=%d): ",
		p,symbol->name,symbol->srcline);
	symbol_label_dump(symbol,&udn);
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

char *STATUS_STRINGS[] = {
    "unknown",
    "running",
    "paused",
    "dead",
    "stopped",
    "error",
    "done"
};

char *REGION_TYPE_STRINGS[] = {
    "heap",
    "stack",
    "vdso",
    "vsyscall",
    "anon",
    "main",
    "lib"
};

char *DEBUGFILE_TYPE_STRINGS[] = {
    "kernel",
    "kmod",
    "main",
    "sharedlib"
};

char *SYMBOL_TYPE_STRINGS[] = {
    "none",
    "type",
    "var",
    "function",
    "label"
};

char *SYMBOL_SOURCE_STRINGS[] = {
    [SYMBOL_SOURCE_DWARF] = "DWARF",
    [SYMBOL_SOURCE_ELF] = "ELF"
};

char *DATATYPE_STRINGS[] = {
    "void",
    "array",
    "struct",
    "enum",
    "ptr",
    "function",
    "typedef",
    "union",
    "base",
    "const",
    "volatile",
    "bitfield"
};

char *LOCTYPE_STRINGS[] = {
    "unknown",
    "addr",
    "reg",
    "regaddr",
    "regoffset",
    "memberoffset",
    "fbregoffset",
    "loclist",
    "realaddr",
    "runtime"
};

char *RANGE_TYPE_STRINGS[] = {
    "none",
    "pc",
    "list"
};
