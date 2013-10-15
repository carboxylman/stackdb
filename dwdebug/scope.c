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
#include <glib.h>

#include "config.h"
#include "common.h"
#include "log.h"
#include "list.h"
#include "alist.h"

#include "dwdebug_priv.h"
#include "dwdebug.h"

#include "glib_wrapper.h"

/**
 ** Scopes.
 **/
struct scope *scope_create(struct symbol *symbol) {
    struct scope *retval;

    retval = (struct scope *)calloc(1,sizeof(*retval));
    if (!retval)
	return NULL;

    retval->symbol = symbol;

    return retval;
}

int scope_insert_symbol(struct scope *scope,struct symbol *symbol) {
    int rc;

    if (!scope->symdict)
	scope->symdict = symdict_create();

    rc = symdict_insert_symbol(scope->symdict,symbol);
    if (rc)
	return rc;

    symbol->scope = scope;
    RHOLD(symbol,scope);

    return 0;
}

int scope_insert_scope(struct scope *parent,struct scope *child) {
    if (parent->subscopes && g_slist_find(parent->subscopes,child))
	return -1;

    parent->subscopes = g_slist_append(parent->subscopes,child);

    child->parent = parent;
    RHOLD(child,parent);

    return 0;
}

int scope_remove_scope(struct scope *parent,struct scope *child) {
    REFCNT trefcnt;

    if (!parent->subscopes)
	return -1;
    if (child->parent != parent)
	return -1;

    if (!g_slist_remove(parent->subscopes,child)) 
	return -1;

    child->parent = NULL;
    RPUT(child,scope,parent,trefcnt);

    return 0;
}

int scope_remove_symbol(struct scope *scope,struct symbol *symbol) {
    int rc;
    REFCNT trefcnt;

    if (!scope->symdict)
	return -1;

    rc = symdict_remove_symbol(scope->symdict,symbol);
    if (rc)
	return rc;

    symbol->scope = NULL;
    RPUT(symbol,symbol,scope,trefcnt);

    return 0;
}

void scope_update_range(struct scope *scope,ADDR start,ADDR end,int *action) {
    struct range *r, *lastr, *newr;

    /*
     * We maintain scope->range as a sorted list by start.
     *
     * So we look for any items that have @start, and update end if
     * necessary; else we insert a new range at the right place.
     */
    if (!scope->range) {
	scope->range = (struct range *)calloc(1,sizeof(*scope->range));
	scope->range->start = start;
	scope->range->end = end;
	scope->range->next = NULL;

	if (action)
	    *action = 1;

	vdebug(8,LA_DEBUG,LF_DWARF,
	       "init scope RANGE(0x%"PRIxADDR",0x%"PRIxADDR")\n",
	       start,end);

	return;
    }
    else {
	lastr = NULL;
	r = scope->range;
	while (r) {
	    if (r->start == start) {
		if (r->end != end) {
		    vwarn("inconsistent scope range(0x%"PRIxADDR",0x%"PRIxADDR")"
			  " (new end 0x%"PRIxADDR"); updating!\n",
			  start,r->end,end);

		    r->end = end;

		    if (action)
			*action = 2;

		    return;
		}
		else {
		    vdebug(8,LA_DEBUG,LF_DWARF,
			   "scope range(0x%"PRIxADDR",0x%"PRIxADDR") matched;"
			   " not updating\n",
			   start,end);

		    if (action)
			*action = 0;

		    return;
		}
	    }
	    else if (r->start > start) {
		/* Insert a new one between lastr and r */
		newr = (struct range *)calloc(1,sizeof(*newr));
		newr->start = start;
		newr->end = end;
		newr->next = r;
		if (lastr)
		    lastr->next = newr;
		else
		    scope->range = newr;

		if (action)
		    *action = 1;

		vdebug(8,LA_DEBUG,LF_DWARF,
		       "added scope range (0x%"PRIxADDR",0x%"PRIxADDR")\n",
		       start,end);

		return;
	    }
	    else {
		lastr = r;
		r = r->next;
	    }
	}

	/* If we get here, we need to add one at the tail. */
	newr = (struct range *)calloc(1,sizeof(*newr));
	newr->start = start;
	newr->end = end;
	newr->next = NULL;
	lastr->next = newr;

	if (action)
	    *action = 1;

	vdebug(8,LA_DEBUG,LF_DWARF,
	       "added scope range (0x%"PRIxADDR",0x%"PRIxADDR")\n",
	       start,end);

	return;
    }
}

int scope_get_sizes(struct scope *scope,int *named,int *duplicated,int *anon,
		    int *numscopes) {
    int rc = 0;

    if (scope->symdict) 
	rc = symdict_get_sizes(scope->symdict,named,duplicated,anon);

    if (scope->subscopes)
	if (numscopes)
	    *numscopes = g_slist_length(scope->subscopes);

    return rc;
}

int scope_get_overall_range(struct scope *scope,ADDR *low_addr_saveptr,
			    ADDR *high_addr_saveptr,int *is_noncontiguous) {
    ADDR lowaddr = ADDRMAX;
    ADDR highaddr = 0;
    unsigned int len = 0;
    struct range *range;

    /*
     * We keep an ordered range list, so this is easy. But just in case
     * there is a bug in the sort, and because we have to traverse the
     * whole list anyway, check it all.
     */
    range = scope->range;
    if (range) {
	while (range) {
	    if (range->start < lowaddr)
		lowaddr = range->start;

	    if (range->end > highaddr)
		highaddr = range->end;

	    len += range->end - range->start;
	    range = range->next;
	}

	if (low_addr_saveptr)
	    *low_addr_saveptr = lowaddr;
	if (high_addr_saveptr)
	    *high_addr_saveptr = highaddr;
	if (len != (highaddr - lowaddr) && is_noncontiguous)
	    *is_noncontiguous = 1;

	return 0;
    }
    else {
	errno = EINVAL;
	return -1;
    }
}

/*
 * Since we held on symbols inserted into this scope, we now must RPUT
 * them.  BUT -- if we RPUT and it is not freed, we must clear the
 * symbol->scope field, because scope is being destroyed.  This function
 * must only be called from scope_free().
 */
static void scope_symdict_symbol_dtor(struct symbol *symbol) {
    REFCNT trefcnt;
    RPUT(symbol,symbol,symbol->scope,trefcnt);
    if (trefcnt > 0)
	symbol->scope = NULL;
    return;
}

REFCNT scope_free(struct scope *scope,int force) {
    REFCNT retval = scope->refcnt;
    struct scope *tmp;
    struct range *range, *lastrange;
    REFCNT trefcnt;
    GSList *gsltmp;

    if (retval) {
	if (!force) {
	    verror("cannot free (%d refs) ",retval);
	    ERRORDUMPSCOPE_NL(scope);
	    return retval;
	}
	else {
	    vwarn("forced free (%d refs) ",retval);
	    WARNDUMPSCOPE_NL(scope);
	}
    }

    vdebug(5,LA_DEBUG,LF_SCOPE,"freeing");
    LOGDUMPSCOPE_NL(5,LA_DEBUG,LF_SCOPE,scope);

    /*
     * RPUT on all our subscopes.  If the subscope was not associated
     * with a symbol, this will free that scope, because we'll be the
     * only ones holding it.  If it is associated with a symbol, it
     * won't be freed until that symbol is, when we RPUT on the
     * symdict.
     *
     * One thing we need to do, though, is unset symbol->scope when we
     * release symbols from our dict!  This means that if the symbol is
     * not freed when we RPUT it, we have to unset symbol->scope.  Careful.
     */
    v_g_slist_foreach(scope->subscopes,gsltmp,tmp) {
	RPUT(tmp,scope,scope,trefcnt);
    }
    g_slist_free(scope->subscopes);
    scope->subscopes = NULL;

    range = scope->range;
    while (range) {
	lastrange = range;
	range = range->next;
	free(lastrange);
    }
    scope->range = NULL;

    if (scope->symdict)
	symdict_free(scope->symdict,scope_symdict_symbol_dtor);

    free(scope);

    return retval;
}

void scope_dump(struct scope *scope,struct dump_info *ud) {
    struct scope *cscope;
    GSList *gsltmp;
    int i;
    struct range *range;
    char *p = "";
    char *np;
    char *np2;
    struct dump_info udn;
    struct dump_info udn2;

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

    if (scope->symbol) {
	if (scope->symbol->isinlineinstance) 
	    fprintf(ud->stream,
		    "%sscope(%s (inline instance: %s,baseaddr=0x%"PRIxADDR")) (",
		    p,symbol_get_name_inline(scope->symbol),
		    symbol_get_name(scope->symbol),
		    symbol_get_addr(scope->symbol));
	else 
	    fprintf(ud->stream,"%sscope(%s (baseaddr=0x%"PRIxADDR")) (",
		    p,symbol_get_name(scope->symbol),
		    symbol_get_addr(scope->symbol));
    }
    else
	fprintf(ud->stream,"%sscope()",p);

    fprintf(ud->stream," RANGES(");
    i = 0;
    range = scope->range;
    while (range) {
	if (i > 0)
	    fprintf(ud->stream,",");

	fprintf(ud->stream,"[0x%"PRIxADDR",0x%"PRIxADDR"]",
		range->start,range->end);
	range = range->next;
    }
    fprintf(ud->stream,")");

    if (ud->detail) {
	fprintf(ud->stream," {");
	if (scope->symdict && symdict_get_size_named(scope->symdict)) {
	    fprintf(ud->stream,"\n%s  symbols: {\n",p);
	    symdict_dump(scope->symdict,&udn2);
	    fprintf(ud->stream,"%s  }\n",p);
	}
	if (scope->subscopes) {
	    if (!scope->symdict)
		fprintf(ud->stream,"\n");
	    fprintf(ud->stream,"%s  subscopes: {\n",p);
	    v_g_slist_foreach(scope->subscopes,gsltmp,cscope) {
		scope_dump(cscope,&udn2);
	    }
	    fprintf(ud->stream,"%s  }\n",p);
	}
	fprintf(ud->stream,"%s}\n",p);
    }
    else 
	fprintf(ud->stream," { }");

    if (ud->prefix) {
	free(np);
	free(np2);
    }
}

int scope_contains_addr(struct scope *scope,ADDR addr) {
    struct range *range;
    int found = 0;

    /*
     * Check to see if the addr is in our scope; if not, return NULL
     * without searching subtabs.
     */
    range = scope->range;
    while (range) {
	if (addr >= range->start && addr < range->end) {
	    found = 1;
	    break;
	}
	range = range->next;
    }

    return found;
}

/*
 * NOTE: this function returns the tightest bounding scope -- which may
 * be the scope that was passed in!!
 */
struct scope *scope_lookup_addr(struct scope *scope,ADDR addr) {
    struct range *range;
    struct scope *retval = NULL;
    struct scope *tmp;
    GSList *gsltmp;

    /*
     * Check to see if the addr is in our scope; if not, return NULL
     * without searching subtabs.
     */
    range = scope->range;
    while (range) {
	if (addr >= range->start && addr < range->end) {
	    retval = scope;
	    break;
	}
	range = range->next;
    }

    if (!retval)
	return NULL;

    /*
     * It is tempting to think we can just check the start and
     * end vals for this scope before checking its children, but
     * we can't do that.  Some scopes may have children whose
     * ranges are outside the parent -- i.e., a function defined in
     * another.  So we can't even check the parent ranges before doing
     * DFS!
     *
     * In other words, we need the tightest bound.
     */
    v_g_slist_foreach(scope->subscopes,gsltmp,tmp) {
	retval = scope_lookup_addr(tmp,addr);
	if (retval)
	    return retval;
    }

    /*
     * If we didn't find a deeper tab containing the addr, return
     * ourself.
     */
    return scope;
}

struct lsymbol *scope_lookup_sym__int(struct scope *scope,
				      const char *name,const char *delim,
				      symbol_type_flag_t flags) {
    char *next = NULL;
    char *lname = NULL;
    char *saveptr = NULL;
    struct array_list *anonchain = NULL;
    int i;
    struct lsymbol *lsymbol = NULL;
    struct lsymbol *lsymbol_tmp = NULL;
    struct symbol *symbol = NULL;
    struct array_list *chain = NULL;
    struct scope *subscope;
    GSList *gsltmp;

    if (delim && strstr(name,delim)) {
	lname = strdup(name);
	next = strtok_r(!saveptr ? lname : NULL,delim,&saveptr);
	chain = array_list_create(1);
    }
    else
	next = (char *)name;

    /* 
     * Do the first token by looking up in this scope's symdict.
     */
    if (scope->symdict)
	symbol = symdict_get_sym(scope->symdict,next,flags);

    if (symbol) {
	if (SYMBOL_IS_TYPE(symbol)) 
	    vdebug(3,LA_DEBUG,LF_DLOOKUP,
		   "found top-level symtab type %s\n",symbol->name);
	else if (!symbol->isdeclaration) 
	    vdebug(3,LA_DEBUG,LF_DLOOKUP,
		   "found top-level symtab definition %s\n",symbol->name);
	else 
	    vdebug(3,LA_DEBUG,LF_DLOOKUP,
		   "found top-level symtab non-type, non-definition %s; saving\n",
		   symbol->name);
    }

    /*
     * If we didn't find a match in our symdict, OR if the symbol was
     * a non-type declaration, keep looking for a type or definition in our
     * subtabs.
     */
    if ((!symbol || (symbol && !SYMBOL_IS_TYPE(symbol) 
		     && symbol->isdeclaration))) {
	vdebug(3,LA_DEBUG,LF_DLOOKUP,
	       "checking scope subscopes\n");
	v_g_slist_foreach(scope->subscopes,gsltmp,subscope) {
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
	    if (!subscope->symbol) {
		lsymbol_tmp = scope_lookup_sym__int(subscope,name,delim,flags);
		if (lsymbol_tmp) {
		    if (SYMBOL_IS_TYPE(lsymbol_tmp->symbol)) {
			lsymbol = lsymbol_tmp;
			vdebug(3,LA_DEBUG,LF_DLOOKUP,
			       "found anon symtab type %s\n",
			       lsymbol->symbol->name);
			goto recout;
		    }
		    else if (!lsymbol_tmp->symbol->isdeclaration) {
			     //SYMBOL_IS_FULL(lsymbol_tmp->symbol) 
			     // && lsymbol_tmp->symbol->s.ii->l.loctype 
			     //    != LOCTYPE_UNKNOWN) {
			lsymbol = lsymbol_tmp;
			vdebug(3,LA_DEBUG,LF_DLOOKUP,
			       "found anon symtab definition %s\n",
			       lsymbol->symbol->name);
			goto recout;
		    }
		    else if (!lsymbol) {
			lsymbol = lsymbol_tmp;
			vdebug(3,LA_DEBUG,LF_DLOOKUP,
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

	    vdebug(3,LA_DEBUG,LF_DLOOKUP,
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
	vdebug(3,LA_DEBUG,LF_DLOOKUP,"found plain %s\n",
	       lsymbol->symbol->name);

	/* Make sure the chain is not NULL and that we take a ref to
	 * symbol.
	 */
	lsymbol_append(lsymbol,symbol);

	return lsymbol;
    }

    vdebug(3,LA_DEBUG,LF_DLOOKUP,
	   "found top-level %s; checking members\n",lsymbol->symbol->name);

    /* Otherwise, add the first one to our chain and start looking up
     * members.
     */
    lsymbol_append(lsymbol,symbol);

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
	/* Don't force free; somebody else might have a ref! */
	lsymbol_free(lsymbol,0);

    return NULL;
}

struct lsymbol *scope_lookup_sym(struct scope *scope,
				 const char *name,const char *delim,
				 symbol_type_flag_t flags) {
    struct lsymbol *ls = scope_lookup_sym__int(scope,name,delim,flags);

    /* __scope_lookup_sym already held refs to all the symbols on our
     * chain.
     */
    if (ls)
	RHOLD(ls,ls);

    return ls;
}
struct symbol *scope_get_sym(struct scope *scope,const char *name,
			     symbol_type_flag_t flags) {
    struct symbol *symbol = NULL;
    struct scope *subscope;
    GSList *gsltmp;

    /* 
     * Lookup in this scope first.
     */
    if (scope->symdict) {
	symbol = symdict_get_sym(scope->symdict,name,flags);
	if (symbol)
	    return symbol;
    }

    /*
     * If we didn't find a match in our symtab, keep looking in our subtabs.
     */
    v_g_slist_foreach(scope->subscopes,gsltmp,subscope) {
	/*
	 * We only search anonymous subscopes, because if the user is
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
	if (!subscope->symbol) {
	    if ((symbol = scope_get_sym(subscope,name,flags)))
		return symbol;
	}
    }

    return NULL;
}

GSList *scope_match_syms(struct scope *scope,
			 struct rfilter *symbol_filter,
			 symbol_type_flag_t flags) {
    if (!scope->symdict) 
	return NULL;

    return symdict_match_syms(scope->symdict,symbol_filter,flags);
}
