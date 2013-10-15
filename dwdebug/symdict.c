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

/**
 ** Symdicts.
 **/
struct symdict *symdict_create(void) {
    struct symdict *symdict;

    symdict = (struct symdict *)calloc(1,sizeof(*symdict));
    if (!symdict)
	return NULL;

    /*
     * Don't initialize these until they are actually used, in
     * symdict_insert_symbol -- try to save memory.
     *
     * Don't provide key/value destructors; symbol_free does that!
     */
    symdict->tab = NULL;
    symdict->duptab = NULL;
    symdict->anontab = NULL;

    return symdict;
}

int symdict_get_size_simple(struct symdict *symdict) {
    int retval = 0;

    if (symdict->tab)
	retval += g_hash_table_size(symdict->tab);
    if (symdict->duptab)
	retval += g_hash_table_size(symdict->duptab);
    if (symdict->anontab)
	retval += g_hash_table_size(symdict->anontab);

    return retval;
}

int symdict_get_size(struct symdict *symdict) {
    int retval = 0;
    GHashTableIter iter;
    gpointer value;
    struct array_list *duplist;

    if (symdict->tab)
	retval += g_hash_table_size(symdict->tab);
    if (symdict->duptab) {
	g_hash_table_iter_init(&iter,symdict->duptab);
	while (g_hash_table_iter_next(&iter,NULL,&value)) {
	    duplist = (struct array_list *)value;
	    retval += array_list_len(duplist);
	}
    }
    if (symdict->anontab)
	retval += g_hash_table_size(symdict->anontab);

    return retval;
}

int symdict_get_size_named(struct symdict *symdict) {
    int retval = 0;
    GHashTableIter iter;
    gpointer value;
    struct array_list *duplist;

    if (symdict->tab)
	retval += g_hash_table_size(symdict->tab);
    if (symdict->duptab) {
	g_hash_table_iter_init(&iter,symdict->duptab);
	while (g_hash_table_iter_next(&iter,NULL,&value)) {
	    duplist = (struct array_list *)value;
	    retval += array_list_len(duplist);
	}
    }

    return retval;
}

int symdict_get_sizes(struct symdict *symdict,int *named,int *duplicated,int *anon) {
    GHashTableIter iter;
    gpointer value;
    struct array_list *duplist;

    if (named) {
	if (symdict->tab)
	    *named = g_hash_table_size(symdict->tab);
	else
	    *named = 0;
    }
    if (duplicated) {
	if (symdict->duptab) {
	    *duplicated = 0;
	    g_hash_table_iter_init(&iter,symdict->duptab);
	    while (g_hash_table_iter_next(&iter,NULL,&value)) {
		duplist = (struct array_list *)value;
		*duplicated += array_list_len(duplist);
	    }
	}
	else
	    *duplicated = 0;
    }
    if (anon) {
	if (symdict->anontab)
	    *anon = g_hash_table_size(symdict->anontab);
	else
	    *anon = 0;
    }

    return 0;
}

int symdict_insert_symbol(struct symdict *symdict,struct symbol *symbol) {
    char *name = symbol_get_name(symbol);
    struct symbol *exsym = NULL;
    struct array_list *exlist = NULL;

    if (name) {
	if (unlikely(symdict->duptab)
	    && unlikely((exlist = (struct array_list *)			\
			 g_hash_table_lookup(symdict->duptab,name)))) {
	    array_list_append(exlist,symbol);

	    vdebug(5,LA_DEBUG,LF_DWARF | LF_SYMBOL,
		   "duplicate symbol(%s:0x%"PRIxSMOFFSET") (%d)\n",
		   symbol_get_name(symbol),symbol->ref,array_list_len(exlist));
	}
	else if (symdict->tab 
		 && unlikely((exsym = (struct symbol *)			\
			      g_hash_table_lookup(symdict->tab,name)))) {
	    exlist = array_list_create(2);
	    array_list_append(exlist,exsym);
	    array_list_append(exlist,symbol);
	    g_hash_table_steal(symdict->tab,name);
	    if (!symdict->duptab) 
		symdict->duptab = g_hash_table_new(g_str_hash,g_str_equal);
	    g_hash_table_insert(symdict->duptab,name,exlist);

	    vdebug(5,LA_DEBUG,LF_DWARF | LF_SYMBOL,
		   "duplicate symbol(%s:0x%"PRIxSMOFFSET") (2)\n",
		   symbol_get_name(symbol),symbol->ref);
	}
	else {
	    if (!symdict->tab) 
		symdict->tab = g_hash_table_new(g_str_hash,g_str_equal);
	    g_hash_table_insert(symdict->tab,name,symbol);
	}

	return 0;
    }
    else if (symbol->ref) {
	if (symdict->anontab 
	    && unlikely(g_hash_table_lookup(symdict->anontab,
					    (gpointer)(uintptr_t)symbol->ref))) {
	    verror("tried to insert duplicate anonymous symbol"
		   " at 0x%"PRIxSMOFFSET" -- BUG!\n",symbol->ref);
	    return 1;
	}
	if (!symdict->anontab) 
	    symdict->anontab = g_hash_table_new(g_direct_hash,g_direct_equal);
	g_hash_table_insert(symdict->anontab,
			    (gpointer)(uintptr_t)symbol->ref,symbol);

	return 0;
    }
    else {
	verror("tried to insert non-anonymous symbol with no name/ref"
	       " -- BUG!\n");
	return 1;
    }
}

int symdict_insert_symbol_anon(struct symdict *symdict,struct symbol *symbol) {
    if (!symbol->ref) {
	verror("tried to insert anonymous symbol with no ref -- BUG!\n");
	return 1;
    }

    if (symdict->anontab 
	&& unlikely(g_hash_table_lookup(symdict->anontab,
					(gpointer)(uintptr_t)symbol->ref))) {
	verror("tried to insert duplicate anonymous symbol"
	       " at 0x%"PRIxSMOFFSET" -- BUG!\n",symbol->ref);
	return 1;
    }
    if (!symdict->anontab) 
	symdict->anontab = g_hash_table_new(g_direct_hash,g_direct_equal);

    g_hash_table_insert(symdict->anontab,
			(gpointer)(uintptr_t)symbol->ref,symbol);

    return 0;
}

int symdict_remove_symbol(struct symdict *symdict,struct symbol *symbol) {
    char *name = symbol_get_name(symbol);
    struct symbol *exsym = NULL;
    struct array_list *exlist = NULL;
    REFCNT trefcnt;

    if (name) {
	if (unlikely(symdict->duptab) 
	    && unlikely((exlist = (struct array_list *)			\
			 g_hash_table_lookup(symdict->duptab,name)))) {
	    array_list_remove_item(exlist,symbol);
	    if (array_list_len(exlist) == 1) {
		g_hash_table_remove(symdict->duptab,name);
		exsym = (struct symbol *)array_list_item(exlist,0);
		array_list_free(exlist);
		g_hash_table_insert(symdict->tab,name,exsym);
	    }
	}
	else if (symdict->tab && g_hash_table_lookup(symdict->tab,name)) {
	    g_hash_table_remove(symdict->tab,name);
	}
	else {
	    verror("symbol(%s:0x%"PRIxSMOFFSET") not on symdict(%p)!\n",
		   name,symbol->ref,symdict);
	    return -1;
	}
    }
    else if (unlikely(symdict->anontab)
	     && g_hash_table_lookup(symdict->anontab,
				    (gpointer)(uintptr_t)symbol->ref)) {
	g_hash_table_remove(symdict->anontab,(gpointer)(uintptr_t)symbol->ref);
    }
    else {
	verror("anon symbol(%s:0x%"PRIxSMOFFSET") not on symdict(%p)!\n",
	       name,symbol->ref,symdict);
	return -1;
    }

    return 0;
}

static void _symdict_symbol_dtor(struct symbol *symbol) {
    symbol_free(symbol,1);
}

symdict_symbol_dtor_t default_symdict_symbol_dtor = \
    _symdict_symbol_dtor;

void symdict_free(struct symdict *symdict,symdict_symbol_dtor_t ssd) {
    GHashTableIter iter;
    gpointer vp;
    struct symbol *symbol;
    struct array_list *list;
    int i;

    if (!ssd)
	ssd = default_symdict_symbol_dtor;

    if (symdict->tab) {
	g_hash_table_iter_init(&iter,symdict->tab);
	while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	    symbol = (struct symbol *)vp;
	    ssd(symbol);
	    g_hash_table_iter_remove(&iter);
	}
	g_hash_table_destroy(symdict->tab);
    }

    if (symdict->duptab) {
	g_hash_table_iter_init(&iter,symdict->duptab);
	while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	    list = (struct array_list *)vp;
	    array_list_foreach(list,i,symbol) {
		ssd(symbol);
	    }
	    array_list_free(list);
	    g_hash_table_iter_remove(&iter);
	}
	g_hash_table_destroy(symdict->duptab);
    }

    if (symdict->anontab) {
	g_hash_table_iter_init(&iter,symdict->anontab);
	while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	    symbol = (struct symbol *)vp;
	    ssd(symbol);
	    g_hash_table_iter_remove(&iter);
	}
	g_hash_table_destroy(symdict->anontab);
    }

    free(symdict);
}

void symdict_dump(struct symdict *symdict,struct dump_info *ud) {
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

    if (symdict->tab)
	g_hash_table_foreach(symdict->tab,g_hash_foreach_dump_symbol,&udn);
    if (symdict->duptab)
	g_hash_table_foreach(symdict->duptab,g_hash_foreach_dump_symbol_list,&udn);

    if (ud->prefix) {
	free(np);
    }
}

/**
 ** Symdict lookup functions.
 **/
struct symbol *symdict_get_sym(struct symdict *symdict,const char *name,
			       symbol_type_flag_t flags) {
    int i;
    struct symbol *symbol = NULL;
    struct symbol *svalue;
    struct array_list *duplist;

    if (symdict->tab 
	&& (svalue = (struct symbol *)g_hash_table_lookup(symdict->tab,name))
	&& SYMBOL_TYPE_FLAG_MATCHES(svalue,flags)) {
	    /* If this is a type symbol, or a symbol with a location,
	     * allow it to match right away; else, save it off if we
	     * haven't already saved off a "first match"; else, save it
	     * off and return it if we don't find anything better!
	     */
	symbol = svalue;
	if (vdebug_is_on(8,LA_DEBUG,LF_DLOOKUP)) {
	    if (SYMBOL_IS_TYPE(svalue)) 
		vdebug(8,LA_DEBUG,LF_DLOOKUP,
		       "found type %s\n",symbol_get_name(symbol));
	    else if (!svalue->isdeclaration) 
		vdebug(8,LA_DEBUG,LF_DLOOKUP,
		       "found definition %s\n",symbol_get_name(symbol));
	    else 
		vdebug(8,LA_DEBUG,LF_DLOOKUP,
		       "found non-type, non-definition %s\n",
		       symbol_get_name(symbol));
	}
    }
    /* If it's in the duptab table, figure out which match is best; we
     * prefer the first non-type definition, unless they're looking for
     * a type.
     */
    else if (symdict->duptab 
	     && (duplist = (struct array_list *)			\
		 g_hash_table_lookup(symdict->duptab,name))) {
	for (i = 0; i < array_list_len(duplist); ++i) {
	    svalue = (struct symbol *)array_list_item(duplist,i);
	    if (SYMBOL_TYPE_FLAG_MATCHES(svalue,flags)) {
		/* If this is a type symbol, or a symbol with a location,
		 * allow it to match right away; else, save it off if we
		 * haven't already saved off a "first match"; else, save it
		 * off and return it if we don't find anything better!
		 */
		if (symbol_is_definition(svalue)) {
		    symbol = svalue;
		    vdebug(8,LA_DEBUG,LF_DLOOKUP,
			   "found dup definition %s\n",symbol_get_name(symbol));
		    break;
		}
		else if (SYMBOL_IS_TYPE(svalue)) {
		    symbol = svalue;
		    vdebug(8,LA_DEBUG,LF_DLOOKUP,
			   "found dup type %s; saving and continuing search\n",
			   symbol_get_name(symbol));
		    //break;
		}
		else if (!symbol) {
		    symbol = svalue;
		    vdebug(8,LA_DEBUG,LF_DLOOKUP,
			   "found dup non-type, non-definition %s;"
			   " saving and continuing search\n",
			   symbol_get_name(symbol));
		}
	    }
	}
    }

    return symbol;
}

GSList *symdict_match_syms(struct symdict *symdict,struct rfilter *symbol_filter,
			   symbol_type_flag_t flags) {
    GHashTableIter iter;
    char *name;
    struct symbol *symbol;
    int accept;
    gpointer key;
    gpointer value;
    struct array_list *duplist;
    int i;
    GSList *retval = NULL;

    if (symdict->tab) {
	g_hash_table_iter_init(&iter,symdict->tab);
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

    if (symdict->duptab) {
	g_hash_table_iter_init(&iter,symdict->duptab);
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
		    if (SYMBOL_TYPE_FLAG_MATCHES(symbol,flags)) {
			retval = g_slist_prepend(retval,symbol);
		    }
		}
	    }
	}
    }

    if (!symbol_filter && symdict->anontab) {
	g_hash_table_iter_init(&iter,symdict->anontab);
	while (g_hash_table_iter_next(&iter,NULL,&value)) {
	    symbol = (struct symbol *)value;
	    if (SYMBOL_TYPE_FLAG_MATCHES(symbol,flags)) {
		retval = g_slist_prepend(retval,symbol);
	    }
	}
    }

    return retval;
}
