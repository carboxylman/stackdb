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

    vdebug(5,LOG_D_SYMBOL,"freeing symbol(%s:%s:%s)\n",
	   symbol->symtab->debugfile->idstr,symbol->symtab->name,
	   symbol->name);
    symbol_free(symbol);
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
	&& symtab->range.lowpc <= pc && pc < symtab->range.highpc) {
	return symtab;
    }
    else if (RANGE_IS_LIST(&symtab->range)) {
	for (i = 0; i < symtab->range.rlist.len; ++i) {
	    if (symtab->range.rlist.list[i]->start <= pc 
		&& pc < symtab->range.rlist.list[i]->end)
		return symtab;
	}
    }

    return NULL;
}

/**
 ** Symbol lookup functions.
 **/
struct lsymbol *symtab_lookup_sym(struct symtab *symtab,
				  char *name,const char *delim,
				  symbol_type_flag_t ftype) {
    char *next = NULL;
    char *lname = NULL;
    char *saveptr = NULL;
    struct array_list *anonchain = NULL;
    int i;
    struct lsymbol *lsymbol = NULL;
    struct symbol *symbol = NULL;
    struct array_list *chain = NULL;
    GHashTableIter iter;
    gpointer key;
    struct symbol *svalue;
    struct symtab *subtab;

    if (delim && strstr(name,delim)) {
	lname = strdup(name);
	next = strtok_r(!saveptr ? lname : NULL,delim,&saveptr);
	chain = array_list_create(1);
    }
    else
	next = name;

    /* Do the first token by looking up in this symtab, or its subtabs.
     * For the rest, lookup in the parent symbol.
     */
    g_hash_table_iter_init(&iter,symtab->tab);
    while (g_hash_table_iter_next(&iter,
				  (gpointer)&key,(gpointer)&svalue)) {
	if (((ftype != SYMBOL_TYPE_FLAG_NONE
	      && ((ftype & SYMBOL_TYPE_FLAG_TYPE && SYMBOL_IS_TYPE(svalue))
		  || (ftype & SYMBOL_TYPE_FLAG_VAR && SYMBOL_IS_VAR(svalue))
		  || (ftype & SYMBOL_TYPE_FLAG_FUNCTION 
		      && SYMBOL_IS_FUNCTION(svalue))
		  || (ftype & SYMBOL_TYPE_FLAG_LABEL 
		      && SYMBOL_IS_LABEL(svalue))))
	     || ftype == SYMBOL_TYPE_FLAG_NONE)
	    && strcmp(next,(char *)key) == 0) {
	    symbol = svalue;
	    break;
	}
    }

    if (!symbol) {
	/*
	 * Free all our local data, since we'll be returning from
	 * recursion.
	 */
	if (lname) {
	    free(lname);
	    lname = NULL;
	}
	if (chain) {
	    array_list_free(chain);
	    chain = NULL;
	}

	list_for_each_entry(subtab,&symtab->subtabs,member) {
	    /*
	     * We only search anonymous subtabs!
	     *
	     * XXX: what about inlined instances of variables or
	     * functions?  How can we let users search for these?
	     */
	    if (subtab->name) {
		lsymbol = symtab_lookup_sym(subtab,name,delim,ftype);
		if (lsymbol)
		    return lsymbol;
	    }
	}
    }

    if (!symbol)
	goto errout;

    lsymbol = lsymbol_create(symbol,chain);

    /* If it's not a delimited string, stop now, successfully. */
    if (!lname)
	return lsymbol;

    /* Otherwise, add the first one to our chain and start looking up
     * members.
     */
    array_list_add(chain,symbol);

    while ((next = strtok_r(!saveptr ? lname : NULL,delim,&saveptr))) {
	if (!(symbol = __symbol_get_one_member(symbol,next,&anonchain)))
	    goto errout;
	else if (anonchain && array_list_len(anonchain)) {
	    /* If anonchain has any members, we now have to glue those
	     * members into our overall chain, BEFORE gluing the actual
	     * found symbol onto the tail end of the chain.
	     */
	    //asm("int $3");
	    for (i = 0; i < array_list_len(anonchain); ++i) {
		array_list_add(chain,array_list_item(anonchain,i));
	    }
	    /* now slap the retval on, too! */
	    array_list_add(chain,symbol);
	    /* free the anonchain (and its members!) and reset our pointer */
	    //asm("int $3");
	    array_list_free(anonchain);
	    anonchain = NULL;
	}
    }

    free(lname);

    /* downsize */
    array_list_compact(chain);

    return lsymbol;

 errout:
    if (lname)
	free(lname);
    if (lsymbol)
	lsymbol_free(lsymbol);

    return NULL;
}

struct lsymbol *debugfile_lookup_sym(struct debugfile *debugfile,
				     char *name,const char *delim,
				     char *srcfile,symbol_type_flag_t ftype) {
    char *next = NULL;
    char *lname = NULL;
    char *saveptr = NULL;
    struct array_list *anonchain = NULL;
    int i;
    struct lsymbol *lsymbol = NULL;
    struct symbol *symbol;
    struct array_list *chain = NULL;
    struct symtab *symtab;
    GHashTableIter iter;
    gpointer key;

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
    if (!(ftype & SYMBOL_TYPE_FLAG_TYPE)
	&& (symbol = g_hash_table_lookup(debugfile->globals,next)))
	goto found;

    if ((ftype & SYMBOL_TYPE_FLAG_TYPE || ftype & SYMBOL_TYPE_FLAG_NONE)
	&& (symbol = g_hash_table_lookup(debugfile->types,next)))
	goto found;

    if (srcfile) {
	if ((symtab = (struct symtab *)g_hash_table_lookup(debugfile->srcfiles,
							   srcfile))) {
	    if (lname)
		free(lname);
	    return symtab_lookup_sym(symtab,name,delim,ftype);
	}
	else {
	    if (lname)
		free(lname);
	    return NULL;
	}
    }

    g_hash_table_iter_init(&iter,debugfile->srcfiles);
    while (g_hash_table_iter_next(&iter,(gpointer)&key,(gpointer)&symtab)) {
	lsymbol = symtab_lookup_sym(symtab,name,delim,ftype);
	if (lsymbol)
	    return lsymbol;
    }
    if (!lsymbol)
	return NULL;

 found:
    lsymbol = lsymbol_create(symbol,chain);

    /* If it's not a delimited string, stop now, successfully. */
    if (!lname)
	return lsymbol;

    vdebug(3,LOG_D_DFILE | LOG_D_LOOKUP,"found %s\n",lsymbol->symbol->name);

    /* Otherwise, add the first one to our chain and start looking up
     * members.
     */
    array_list_add(chain,symbol);

    while ((next = strtok_r(!saveptr ? lname : NULL,delim,&saveptr))) {
	if (!(symbol = __symbol_get_one_member(symbol,next,&anonchain)))
	    goto errout;
	else if (anonchain && array_list_len(anonchain)) {
	    /* If anonchain has any members, we now have to glue those
	     * members into our overall chain, BEFORE gluing the actual
	     * found symbol onto the tail end of the chain.
	     */
	    //asm("int $3");
	    for (i = 0; i < array_list_len(anonchain); ++i) {
		array_list_add(chain,array_list_item(anonchain,i));
	    }
	    /* free the anonchain (and its members!) and reset our pointer */
	    array_list_free(anonchain);
	    anonchain = NULL;
	}
	/* now slap the retval on, too! */
	array_list_add(chain,symbol);
    }

    free(lname);

    /* downsize */
    array_list_compact(chain);

    /* set the primary symbol in lsymbol to the *end* of the chain */
    lsymbol->symbol = (struct symbol *)array_list_item(lsymbol->chain,
						       array_list_len(lsymbol->chain) - 1);

    return lsymbol;

 errout:
    free(lname);
    lsymbol_free(lsymbol);

    return NULL;
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
    debugfile->globals = g_hash_table_new(g_str_hash,g_str_equal);

    /* This is an optimization lookup hashtable, so we don't provide
     * *any* key or value destructors since we don't want them freed
     * when the hashtable is destroyed.
     */
    debugfile->types = g_hash_table_new(g_str_hash,g_str_equal);

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

int debugfile_add_symtab(struct debugfile *debugfile,struct symtab *symtab) {
    if (unlikely(g_hash_table_lookup(debugfile->srcfiles,symtab->name)))
	return 1;
    vdebug(3,LOG_D_DFILE,"adding symtab %s:%s\n",debugfile->idstr,symtab->name);
    g_hash_table_insert(debugfile->srcfiles,symtab->name,symtab);
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
    return (struct symbol *)g_hash_table_lookup(debugfile->types,typename);
}

int debugfile_add_type(struct debugfile *debugfile,struct symbol *symbol) {
    if (unlikely(g_hash_table_lookup(debugfile->types,symbol->name)))
	return 1;
    g_hash_table_insert(debugfile->types,symbol->name,symbol);
    return 0;
}

int debugfile_add_type_fakename(struct debugfile *debugfile,
				char *fakename,struct symbol *symbol) {
    if (unlikely(g_hash_table_lookup(debugfile->types,fakename)))
	return 1;
    g_hash_table_insert(debugfile->types,fakename,symbol);
    return 0;
}

void debugfile_free(struct debugfile *debugfile) {
    if (debugfile->refcnt) {
	vwarn("debugfile(%s) still has refcnt %d, not freeing!\n",
	      debugfile->idstr,debugfile->refcnt);
	return;
    }

    vdebug(5,LOG_D_DFILE,"freeing debugfile(%s)\n",debugfile->idstr);

    if (debugfile->kernel_debugfile)
	--(debugfile->kernel_debugfile->refcnt);

    if (debugfile->debugfile.prev != NULL || debugfile->debugfile.next != NULL)
	list_del(&debugfile->debugfile);

    g_hash_table_destroy(debugfile->globals);
    g_hash_table_destroy(debugfile->types);
    /* All the per-debugfile-per-srcfile symtabs (and their symbols) are
     * destroyed as a result of this.
     */
    g_hash_table_destroy(debugfile->srcfiles);

    if (debugfile->strtab)
	free(debugfile->strtab);
    if (debugfile->loctab)
	free(debugfile->loctab);
    if (debugfile->rangetab)
	free(debugfile->rangetab);

    if (debugfile->version)
	free(debugfile->version);
    free(debugfile->name);
    free(debugfile->filename);
    free(debugfile->idstr);
    free(debugfile);

    vdebug(5,LOG_D_DFILE,"freed debugfile\n");
}

/**
 ** Symtabs.
 **/
struct symtab *symtab_create(struct debugfile *debugfile,
			     char *name,char *compdirname,
			     int language,char *producer) {
    struct symtab *symtab;

    symtab = (struct symtab *)malloc(sizeof(*symtab));
    if (!symtab)
	return NULL;
    memset(symtab,0,sizeof(*symtab));

    symtab->debugfile = debugfile;

    symtab_set_name(symtab,name);
    symtab_set_compdirname(symtab,compdirname);
    symtab_set_producer(symtab,producer);

    symtab->language = language;
    symtab->range.rtype = RANGE_TYPE_NONE;

    INIT_LIST_HEAD(&symtab->subtabs);

    symtab->tab = g_hash_table_new_full(g_str_hash,g_str_equal,
					/* Don't free the symbol names;
					 * symbol_free will do that!
					 */
					NULL,
					ghash_symbol_free);

    symtab->anontab = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					    /* No symbol names to free!
					     */
					    NULL,
					    ghash_symbol_free);

    return symtab;
}

void symtab_set_name(struct symtab *symtab,char *name) {
    if (name 
#ifdef DWDEBUG_USE_STRTAB
	&& (!symtab->debugfile || !symtab_str_in_strtab(symtab,name))
#endif
	)
	symtab->name = strdup(name);
    else 
	symtab->name = name;
}

void symtab_set_compdirname(struct symtab *symtab,char *compdirname) {
    if (compdirname
#ifdef DWDEBUG_USE_STRTAB
	&& (!symtab->debugfile || !symtab_str_in_strtab(symtab,compdirname))
#endif
	)
	symtab->compdirname = strdup(compdirname);
    else
	symtab->compdirname = compdirname;
}

void symtab_set_producer(struct symtab *symtab,char *producer) {
    if (producer 
#ifdef DWDEBUG_USE_STRTAB
	&& (!symtab->debugfile || !symtab_str_in_strtab(symtab,producer))
#endif
	)
	symtab->producer = strdup(producer);
    else
	symtab->producer = producer;
}

int symtab_insert_fakename(struct symtab *symtab,char *fakename,
			   struct symbol *symbol,OFFSET anonaddr) {
    if (!anonaddr) {
	if (unlikely(g_hash_table_lookup(symtab->tab,fakename)))
	    return 1;
	g_hash_table_insert(symtab->tab,fakename,symbol);
	return 0;
    }
    else if (anonaddr) {
	if (unlikely(g_hash_table_lookup(symtab->anontab,(gpointer)anonaddr)))
	    return 1;
	g_hash_table_insert(symtab->anontab,(gpointer)anonaddr,symbol);
	return 0;
    }

    verror("VERY BAD -- tried to insert a non-anonymous symbol with no name!\n");
    return 1;
}

int symtab_insert(struct symtab *symtab,struct symbol *symbol,OFFSET anonaddr) {
    if (!anonaddr && symbol->name) {
	if (unlikely(g_hash_table_lookup(symtab->tab,symbol->name)))
	    return 1;
	g_hash_table_insert(symtab->tab,symbol->name,symbol);
	return 0;
    }
    else if (anonaddr) {
	if (unlikely(g_hash_table_lookup(symtab->anontab,(gpointer)anonaddr)))
	    return 1;
	g_hash_table_insert(symtab->anontab,(gpointer)anonaddr,symbol);
	return 0;
    }

    verror("VERY BAD -- tried to insert a non-anonymous symbol with no name!\n");
    return 1;
}

void symtab_free(struct symtab *symtab) {
    struct symtab *tmp;
    struct symtab *tmp2;

    vdebug(5,LOG_D_SYMTAB,"freeing symtab(%s:%s)\n",
	   symtab->debugfile->idstr,symtab->name);

    if (!list_empty(&symtab->subtabs))
	list_for_each_entry_safe(tmp,tmp2,&symtab->subtabs,member) 
	    symtab_free(tmp);
    if (RANGE_IS_LIST(&symtab->range))
	range_list_internal_free(&symtab->range.rlist);
    g_hash_table_destroy(symtab->tab);
    g_hash_table_destroy(symtab->anontab);

    if (symtab->name
#ifdef DWDEBUG_USE_STRTAB
	&& !symtab_str_in_strtab(symtab,symtab->name)
#endif
	)
	free(symtab->name);
    if (symtab->compdirname
#ifdef DWDEBUG_USE_STRTAB
	&& !symtab_str_in_strtab(symtab,symtab->compdirname)
#endif
	)
	free(symtab->compdirname);
    if (symtab->producer
#ifdef DWDEBUG_USE_STRTAB
	&& !symtab_str_in_strtab(symtab,symtab->producer)
#endif
	)
	free(symtab->producer);

    free(symtab);
}

#ifdef DWDEBUG_USE_STRTAB
/* Returns 1 if string is in symtab; else 0 */
int symtab_str_in_strtab(struct symtab *symtab,char *strp) {
    if (symtab->debugfile && symtab->debugfile->strtab
	&& strp >= symtab->debugfile->strtab
	&& strp < (symtab->debugfile->strtab + symtab->debugfile->strtablen))
	return 1;
    return 0;
}
#endif

/**
 ** Functions for symbols.
 **/
struct symbol *symbol_create(struct symtab *symtab,
			     char *name,symbol_type_t symtype) {
    struct symbol *symbol;

    symbol = (struct symbol *)malloc(sizeof(*symbol));
    if (!symbol)
	return NULL;
    memset(symbol,0,sizeof(*symbol));

    symbol->symtab = symtab;
    symbol_set_name(symbol,name);
    symbol_set_type(symbol,symtype);

    /* Only insert the symbol automatically if we have a name.  This
     * won't be true for our dwarf parser, for instance.
     */
    if (name)
	g_hash_table_insert(symtab->tab,name,symbol);

    return symbol;
}

void symbol_set_name(struct symbol *symbol,char *name) {
    if (name 
#ifdef DWDEBUG_USE_STRTAB
	&& (!symbol->symtab || !symbol->symtab->debugfile 
	    || !symtab_str_in_strtab(symbol->symtab,name))
#endif
	) {
	symbol->name = strdup(name);
    }
    else {
	symbol->name = name;
    }
}

void symbol_set_type(struct symbol *symbol,symbol_type_t symtype) {
    symbol->type = symtype;
}

void symbol_set_srcline(struct symbol *symbol,int srcline) {
    symbol->srcline = srcline;
}

int symbol_type_bytesize(struct symbol *symbol) {
    if (symbol->type == SYMBOL_TYPE_TYPE)
	return symbol->s.ti.byte_size;
    else 
	return -1;
}

static struct symbol *__symbol_get_one_member(struct symbol *symbol,char *member,
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
    struct symbol *type = symbol;
    int j, k;
    struct lsymbol *lsymbol;
    struct symtab *subtab;
    
    /*
    struct dump_info udn = {
	.stream = stderr,
	.prefix = "",
	.detail = 1,
	.meta = 1
    };
    */

    if (SYMBOL_IST_FUNCTION(symbol)
	&& symbol->s.ti.d.f.count) {
	list_for_each_entry(retval,&symbol->s.ti.d.f.args,member) {
	    if (retval->name && strcmp(retval->name,member) == 0)
		goto out;
	}
    }
    else if (SYMBOL_IST_ENUM(symbol)) {
	list_for_each_entry(retval,&symbol->s.ti.d.e.members,member) {
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
	    list_for_each_entry(retval,&type->s.ti.d.su.members,member) {
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
    else if (SYMBOL_IS_FUNCTION(symbol)) {
	/* First, check our args. */
	list_for_each_entry(retval,&symbol->s.ii.d.f.args,member) {
	    if (retval->name && strcmp(retval->name,member) == 0)
		goto out;
	}

	/* Second, check our internal symbol table.  Wait a sec, the
	 * args are in the internal symtab too!  Hmmm.
	 */
	lsymbol = symtab_lookup_sym(symbol->s.ii.d.f.symtab,member,NULL,
				    SYMBOL_TYPE_FLAG_VAR | SYMBOL_TYPE_FLAG_FUNCTION);
	if (lsymbol) {
	    symbol = lsymbol->symbol;
	    lsymbol_free(lsymbol);
	    return symbol;
	}

	/* Third, check any anonymous subtabs.
	 * 
	 * NOTE: for now, only check one level; if the debuginfo emitter
	 * has added more anonymous lexical scopes, or whatever, we
	 * don't support them yet.
	 */
	list_for_each_entry(subtab,&symbol->s.ii.d.f.symtab->subtabs,member) {
	    if (subtab->name)
		continue;

	    lsymbol = symtab_lookup_sym(subtab,member,NULL,
					SYMBOL_TYPE_FLAG_VAR | SYMBOL_TYPE_FLAG_FUNCTION);
	    if (lsymbol) {
		symbol = lsymbol->symbol;
		lsymbol_free(lsymbol);
		return symbol;
	    }
	}

	return NULL;
    }
    else if (SYMBOL_IS_VAR(symbol) && SYMBOL_IST_STUN(symbol->datatype)) {
	//vdebug(3,LOG_D_SYMBOL,"returning result of searching S/U type symbol: ");
	//symbol_dump(symbol->datatype,&udn);
	return __symbol_get_one_member(symbol->datatype,member,chainptr);
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

    //asm("int $3");

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
    //asm("int $3");
    if (anonstack) 
	free(anonstack);
    if (parentstack)
	free(parentstack);
    return retval;
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
	    if (range->lowpc <= ip && ip < range->highpc
		&& (symtab == symbol->symtab || !data)) {
		retval = 1;
		break;
	    }
	}
	else if (RANGE_IS_LIST(range)) {
	    for (i = 0; i < range->rlist.len; ++i) {
		if (range->rlist.list[i]->start <= ip 
		    && ip < range->rlist.list[i]->end
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
    return __symbol_get_one_member(symbol,member,NULL);
}

struct symbol *symbol_get_member(struct symbol *symbol,char *memberlist,
				 const char *delim) {
    char *saveptr = NULL;
    struct symbol *retval = NULL;
    char *member;
    char *mlist = strdup(memberlist);

    retval = symbol;
    while ((member = strtok_r(!saveptr ? mlist : NULL,".",&saveptr))) {
	retval = symbol_get_one_member(retval,member);
	if (!retval)
	    break;
    }

    free(mlist);
    return retval;
}

/*
 * Skips const and volatile types, for now.
 */
struct symbol *symbol_type_skip_qualifiers(struct symbol *type) {
    if (!SYMBOL_IS_TYPE(type))
	return NULL;

    while (type->type == SYMBOL_TYPE_TYPE
	   && (SYMBOL_IST_VOL(type)
	       || SYMBOL_IST_CONST(type))) {
	type = type->s.ti.type_datatype;
    }

    return type;
}

struct symbol *symbol_type_skip_ptrs(struct symbol *type) {
    if (!SYMBOL_IS_TYPE(type))
	return NULL;

    while (type->type == SYMBOL_TYPE_TYPE && SYMBOL_IST_PTR(type)) {
	type = type->s.ti.type_datatype;
    }

    return type;
}

int symbol_type_is_char(struct symbol *type) {
    if (!SYMBOL_IS_TYPE(type))
	return 0;

    type = symbol_type_skip_qualifiers(type);

    if (type->s.ti.datatype_code == DATATYPE_BASE
	&& type->s.ti.byte_size == 1
	&& (type->s.ti.d.v.encoding == ENCODING_SIGNED_CHAR
	    || type->s.ti.d.v.encoding == ENCODING_UNSIGNED_CHAR)) 
	return 1;

    return 0;
}

unsigned int symbol_type_array_bytesize(struct symbol *type) {
    int i;
    int size;

    if (!SYMBOL_IS_TYPE(type))
	return 0;

    type = symbol_type_skip_qualifiers(type);

    if (type->s.ti.datatype_code != DATATYPE_ARRAY)
	return 0;

    size = type->s.ti.type_datatype->s.ti.byte_size;

    for (i = 0; i < type->s.ti.d.a.count; ++i) {
	vdebug(5,LOG_D_SYMBOL,"subrange length is %d\n",
	       type->s.ti.d.a.subranges[i] + 1);
	size = size * (type->s.ti.d.a.subranges[i] + 1);
    }

    vdebug(5,LOG_D_SYMBOL,"full array size is %d for array type %s\n",size,
	   type->name);

    return size;
}

unsigned int symbol_type_full_bytesize(struct symbol *type) {
    if (!SYMBOL_IS_TYPE(type))
	return 0;

    type = symbol_type_skip_qualifiers(type);

    if (type->s.ti.datatype_code == DATATYPE_ARRAY)
	return symbol_type_array_bytesize(type);
    return symbol_type_bytesize(type);
}

void symbol_free(struct symbol *symbol) {
    struct symbol *tmp;
    struct symbol *tmp2;

    if (symbol->name)
	vdebug(5,LOG_D_SYMBOL,"freeing symbol %s//%s\n",
	       SYMBOL_TYPE(symbol->type),symbol->name);
    else 
	vdebug(5,LOG_D_SYMBOL,"freeing symbol %s//(null)\n",
	       SYMBOL_TYPE(symbol->type));

    /*
     * We have to recurse through any symbol that has members, because
     * those members are not in any symbol tables, so they won't be freed.
     */
    if (symbol->type == SYMBOL_TYPE_FUNCTION) {
	if (symbol->s.ii.d.f.fbisloclist
	    && symbol->s.ii.d.f.fblist)
	    loc_list_free(symbol->s.ii.d.f.fblist);
	else if (symbol->s.ii.d.f.fbissingleloc
		 && symbol->s.ii.d.f.fbloc)
	    location_free(symbol->s.ii.d.f.fbloc);

	/*
	 * Don't free the function's symtab -- it is freed in in
	 * symtab_free since all functions will have a parent symtab.
	 */
	//if (symbol->s.ii.d.f.symtab)
	//    symtab_free(symbol->s.ii.d.f.symtab);
    }
    else if (symbol->type == SYMBOL_TYPE_LABEL) {
	/*
	 * Free the range list for a label.
	 */
	if (symbol->s.ii.d.l.range.rlist.list)
	    range_list_internal_free(&symbol->s.ii.d.l.range.rlist);
    }
    else if (SYMBOL_IST_ARRAY(symbol)) {
	if (symbol->s.ti.d.a.subranges)
	    free(symbol->s.ti.d.a.subranges);
    }
    else if (SYMBOL_IST_STUN(symbol)) {
	list_for_each_entry_safe(tmp,tmp2,&symbol->s.ti.d.su.members,member)
	    symbol_free(tmp);
    }
    else if (SYMBOL_IST_FUNCTION(symbol)) {
	list_for_each_entry_safe(tmp,tmp2,&symbol->s.ti.d.f.args,member)
	    symbol_free(tmp);
    }

    /*
     * Also have to free any constant data allocated.
     */
    if (symbol->type != SYMBOL_TYPE_TYPE
	&& symbol->s.ii.constval
#ifdef DWDEBUG_USE_STRTAB
	&& (!symbol->symtab || !symtab_str_in_strtab(symbol->symtab,
						     symbol->s.ii.constval))
#endif
	)
	free(symbol->s.ii.constval);

    /*
     * Also have to free location data, potentially.
     */
    if (symbol->type != SYMBOL_TYPE_TYPE)
	location_internal_free(&symbol->s.ii.l);

    if (symbol->type == SYMBOL_TYPE_TYPE && symbol->s.ti.extname) {
	vdebug(5,LOG_D_SYMBOL,"freeing extname %s\n",symbol->s.ti.extname);
	free(symbol->s.ti.extname);
    }
    else if (symbol->name
#ifdef DWDEBUG_USE_STRTAB
	     && (!symbol->symtab || !symtab_str_in_strtab(symbol->symtab,symbol->name))
#endif
	     ) {
	vdebug(5,LOG_D_SYMBOL,"freeing name %s\n",symbol->name);
	free(symbol->name);
    }

    free(symbol);
}

/**
 ** Lookup symbols.  Badly named!
 **/
struct lsymbol *lsymbol_create(struct symbol *symbol,
			       struct array_list *chain) {
    struct lsymbol *lsymbol = (struct lsymbol *)malloc(sizeof(struct lsymbol));
    memset(lsymbol,0,sizeof(struct lsymbol *));
    lsymbol->symbol = symbol;
    lsymbol->chain = chain;
    return lsymbol;
}

void lsymbol_free(struct lsymbol *lsymbol) {
    if (lsymbol->chain)
	array_list_free(lsymbol->chain);
    free(lsymbol);
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


int location_is_conditional(struct location *location) {
    switch (location->loctype) {
	/*
	 * Technically, in some cases, FBREG_OFFSET and MEMBER_OFFSET
	 * could also be unconditional.  But that gets nearly as
	 * expensive to compute as actually resolving the location
	 * against the current IP would be!
	 *
	 * So for now, we only do this for fixed addresses.
	 */
    case LOCTYPE_ADDR:
    case LOCTYPE_REALADDR:
	return 0;
    default:
	return 1;
    }
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

    for (i = 0; i < list->len; ++i) {
	free(list->list[i]);
    }
    free(list->list);
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
}

void g_hash_foreach_dump_symbol(gpointer key __attribute__((unused)),
				gpointer value,gpointer userdata) {
    struct dump_info *ud = (struct dump_info *)userdata;
    symbol_dump((struct symbol *)value,ud);
}

void debugfile_dump(struct debugfile *debugfile,struct dump_info *ud) {
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
    fprintf(ud->stream,"%s  types:\n",p);
    g_hash_table_foreach(debugfile->types,g_hash_foreach_dump_symbol,&udn);
    fprintf(ud->stream,"%s  globals:\n",p);
    g_hash_table_foreach(debugfile->globals,g_hash_foreach_dump_symbol,&udn);
    fprintf(ud->stream,"%s  symtabs:\n",p);
    //ud->prefix = np1;
    g_hash_table_foreach(debugfile->srcfiles,g_hash_foreach_dump_symtab,&udn);

    if (ud->prefix) {
	free(np1);
	free(np2);
    }
}

void range_dump(struct range *range,struct dump_info *ud) {
    int i;

    if (RANGE_IS_PC(range))
	fprintf(ud->stream,"%sRANGE(pc): low=0x%" PRIxADDR ", high=0x%" PRIxADDR,
		ud->prefix,range->lowpc,range->highpc);
    else if (RANGE_IS_LIST(range)) {
	if (range->rlist.len == 0) {
	    fprintf(ud->stream,"%sRANGE(list): ()",ud->prefix);
	    return;
	}

	fprintf(ud->stream,"%sRANGE(list): (",ud->prefix);
	for (i = 0; i < range->rlist.len; ++i) {
	    if (i > 0)
		fprintf(ud->stream,",");

	    fprintf(ud->stream,"[0x%" PRIxADDR ",0x%" PRIxADDR "]",
		    range->rlist.list[i]->start,range->rlist.list[i]->end);
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
    if (symtab->compdirname)
	fprintf(ud->stream,"compdirname=%s ",symtab->compdirname);
    if (symtab->producer)
	fprintf(ud->stream,"producer=%s ",symtab->producer);
    if (symtab->language)
	fprintf(ud->stream,"language=%d ",symtab->language);
    range_dump(&symtab->range,&udn3);
    fprintf(ud->stream,") {\n");
    g_hash_table_foreach(symtab->tab,g_hash_foreach_dump_symbol,&udn);

    if (!list_empty(&symtab->subtabs)) {
	fprintf(ud->stream,"%s  subscopes:\n",p);
	list_for_each_entry(csymtab,&(symtab->subtabs),member) {
	    symtab_dump(csymtab,&udn2);
	    fprintf(ud->stream,"\n");
	}
    }

    fprintf(ud->stream,"%s}",p);

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
    if (ud->meta) 
	range_dump(&symbol->s.ii.d.l.range,&udn);
}

void symbol_var_dump(struct symbol *symbol,struct dump_info *ud) {
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
	//    && symbol->s.ii.isenumval)) {
	    if (symbol->datatype) {
		symbol_type_dump(symbol->datatype,&udn);
	    }
	    else if (symbol->datatype_addr_ref) 
		fprintf(ud->stream,"tref%"PRIxOFFSET,symbol->datatype_addr_ref);
	//}
    }
    /* all variables are named, but not all members of structs/unions! */
    /* well, inlined params aren't named either. */
    if (symbol->s.ii.isinlineinstance && symbol->s.ii.isparam) {
	/* Only print a space if we printed the var's type above! */
	if (ud->detail)
	    fprintf(ud->stream," ");

	if (symbol->s.ii.origin) {
	    fprintf(ud->stream,"INLINED_PARAM(");
	    symbol_var_dump(symbol->s.ii.origin,&udn);
	    fprintf(ud->stream,")");
	}
	else
	    fprintf(ud->stream,"INLINED_ANON_PARAM()");
    }
    else if (symbol->name) {
	/* Only print a space if we printed the var's type above! */
	if (ud->detail)
	    fprintf(ud->stream," ");

	fprintf(ud->stream,"%s",symbol->name);
    }

    if (symbol->type == SYMBOL_TYPE_VAR 
	&& symbol->s.ii.d.v.bit_size > 0) {
	/* this is a bitfield */
	fprintf(ud->stream,":%hd(%hd)",symbol->s.ii.d.v.bit_size,
		symbol->s.ii.d.v.bit_offset);
    }
    if (symbol->type == SYMBOL_TYPE_VAR
	&& symbol->s.ii.isenumval) {
	// XXX fix type printing -- this *is* a malloc'd constval
	fprintf(ud->stream," = %d",*((int *)symbol->s.ii.constval));
    }

    if (ud->detail && symbol->s.ii.l.loctype != LOCTYPE_UNKNOWN) {
	fprintf(ud->stream," @@ ");
	location_dump(&symbol->s.ii.l,&udn2);

	if (symbol->s.ii.constval)
	    fprintf(ud->stream," @@ CONST(%p)",symbol->s.ii.constval);
    }
}

void symbol_function_dump(struct symbol *symbol,struct dump_info *ud) {
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
	if (symbol->datatype) {
	    symbol_type_dump(symbol->datatype,&udn);
	    fprintf(ud->stream," ");
	}
	else if (symbol->datatype_addr_ref)
	    fprintf(ud->stream,"ftref%" PRIxOFFSET " ",symbol->datatype_addr_ref);
    }
    if (symbol->s.ii.isinlineinstance) {
	if (symbol->s.ii.origin) {
	    fprintf(ud->stream,"INLINED_FUNC(");
	    symbol_var_dump(symbol->s.ii.origin,&udn);
	    fprintf(ud->stream,")");
	}
	else
	    fprintf(ud->stream,"INLINED_ANON_PARAM()");
    }
    else 
	fprintf(ud->stream,"%s",symbol->name);
    if (ud->detail) {
	fprintf(ud->stream," (");
	list_for_each_entry(arg,&(symbol->s.ii.d.f.args),member) {
	    ++i;
	    symbol_var_dump(arg,ud);
	    if (i != symbol->s.ii.d.f.count)
		fprintf(ud->stream,",");
	}
	if (symbol->s.ti.d.f.hasunspec) {
	    if (i)
		fprintf(ud->stream,",");
	    fprintf(ud->stream,"...");
	}
	fprintf(ud->stream,")");

	if (symbol->s.ii.constval)
	    fprintf(ud->stream," @@ CONST(%p)",symbol->s.ii.constval);
    }
    if (ud->meta) {
	if (symbol->s.ii.d.f.fbisloclist && symbol->s.ii.d.f.fblist 
	    && symbol->s.ii.d.f.fblist->len) {
	    fprintf(ud->stream," (frame_base=");
	    loc_list_dump(symbol->s.ii.d.f.fblist,&udn2);
	    fprintf(ud->stream,",");
	}
	else if (symbol->s.ii.d.f.fbissingleloc && symbol->s.ii.d.f.fbloc) { 
	    fprintf(ud->stream," (frame_base=");
	    location_dump(symbol->s.ii.d.f.fbloc,&udn2);
	    fprintf(ud->stream,",");
	}
	else 
	    fprintf(ud->stream," (");

	fprintf(ud->stream,"external=%d,prototyped=%d,declinline=%d,inlined=%d) ",
		symbol->s.ii.isexternal,symbol->s.ii.isprototyped,
		symbol->s.ii.isdeclinline,symbol->s.ii.isinlined);
    }
    if (ud->detail) {
	fprintf(ud->stream,"\n");

	symtab_dump(symbol->s.ii.d.f.symtab,&udn);
    }
}

void symbol_type_dump(struct symbol *symbol,struct dump_info *ud) {
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

    switch (symbol->s.ti.datatype_code) {
    case DATATYPE_VOID:
	fprintf(ud->stream,"void");
	break;
    case DATATYPE_ARRAY:
	symbol_type_dump(symbol->s.ti.type_datatype,&udn);
	fprintf(ud->stream," ");
	for (i = 0; i < symbol->s.ti.d.a.count; ++i) {
	    fprintf(ud->stream,"[%d]",symbol->s.ti.d.a.subranges[i] + 1);
	}
	break;
    case DATATYPE_CONST:
	fprintf(ud->stream,"const ");
	symbol_type_dump(symbol->s.ti.type_datatype,ud);
	break;
    case DATATYPE_VOL:
	fprintf(ud->stream,"volatile ");
	symbol_type_dump(symbol->s.ti.type_datatype,ud);
	break;
    case DATATYPE_STRUCT:
    case DATATYPE_UNION:
	ss = "struct";
	if (symbol->s.ti.datatype_code == DATATYPE_UNION)
	    ss = "union";
	if (symbol->s.ti.isanon && ud->detail)
	    fprintf(ud->stream,"%s",ss);
	else
	    fprintf(ud->stream,"%s %s",ss,symbol->name);
	if (ud->meta) 
	    fprintf(ud->stream," (byte_size=%d)",symbol->s.ti.byte_size);
	if (ud->detail) {
	    fprintf(ud->stream," { ");
	    list_for_each_entry(member,&(symbol->s.ti.d.su.members),member) {
		/* NOTE: C structs/unions can have members of the same
		 * type as the parent struct -- so don't recurse if this
		 * is true! -- OR if it's a pointer chain back to the struct.
		 */
		if (member->datatype == symbol) {
		    symbol_var_dump(member,&udn);
		}
		else if (SYMBOL_IST_STUN(member->datatype) 
			 && member->datatype->s.ti.isanon) {
		    symbol_type_dump(member->datatype,ud);

		    if (ud->detail && member->s.ii.l.loctype != LOCTYPE_UNKNOWN) {
			fprintf(ud->stream," @@ ");
			location_dump(&member->s.ii.l,ud);

			if (member->s.ii.constval)
			    fprintf(ud->stream," @@ CONST(%p)",
				    member->s.ii.constval);
		    }
		}
		else 
		    symbol_var_dump(member,ud);
		if (likely(++i != symbol->s.ti.d.su.count))
		    fprintf(ud->stream,"; ");
	    }
	    fprintf(ud->stream," }");
	}
	break;
    case DATATYPE_ENUM:
	fprintf(ud->stream,"enum %s",symbol->name);
	if (ud->meta) 
	    fprintf(ud->stream," (byte_size=%d)",symbol->s.ti.byte_size);
	if (ud->detail) {
	    fprintf(ud->stream," { ");
	    list_for_each_entry(member,&(symbol->s.ti.d.e.members),member) {
		symbol_var_dump(member,&udn);
		//symbol_var_dump(member,ud);
		if (likely(++i != symbol->s.ti.d.su.count))
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
	if (symbol->s.ti.type_datatype) {
	    if (symbol->s.ti.type_datatype->type == SYMBOL_TYPE_TYPE
		&& (symbol->s.ti.type_datatype->s.ti.datatype_code == DATATYPE_PTR
		    || symbol->s.ti.type_datatype->s.ti.datatype_code == DATATYPE_VOID 
		    || symbol->s.ti.type_datatype->s.ti.datatype_code == DATATYPE_BASE))
		symbol_type_dump(symbol->s.ti.type_datatype,ud);
	    else {
		symbol_type_dump(symbol->s.ti.type_datatype,&udn);
	    }
	    fprintf(ud->stream,"*");
	}
	else
	    fprintf(ud->stream,"ptref%"PRIxOFFSET" *",
		    symbol->s.ti.type_datatype_ref);
	break;
    case DATATYPE_FUNCTION:
	if (ud->detail)
	    symbol_type_dump(symbol->s.ti.type_datatype,ud);

	if (symbol->s.ti.isanon) 
	    fprintf(ud->stream,"()");
	else if (symbol->name)
	    fprintf(ud->stream,"(%s)",symbol->name);

	if (ud->meta)
	    fprintf(ud->stream," (prototyped=%d,external=%d) ",
		    symbol->s.ti.isprototyped,symbol->s.ti.isexternal);

	if (ud->detail) {
	    fprintf(ud->stream,"(");
	    i = 0;
	    list_for_each_entry(member,&(symbol->s.ti.d.f.args),member) {
		symbol_var_dump(member,ud);
		if (likely(++i != symbol->s.ti.d.f.count))
		    fprintf(ud->stream,", ");
	    }
	    if (symbol->s.ti.d.f.hasunspec) {
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
	else if (symbol->s.ti.type_datatype) {
	    fprintf(ud->stream,"typedef ");
	    symbol_type_dump(symbol->s.ti.type_datatype,ud);
	    fprintf(ud->stream," %s",symbol->name);
	}
	else 
	    fprintf(ud->stream,"typedef tdtref%"PRIxOFFSET" %s",
		    symbol->s.ti.type_datatype_ref,symbol->name);
	break;
    case DATATYPE_BASE:
	if (!ud->meta)
	    fprintf(ud->stream,"%s",symbol->name);
	else 
	    fprintf(ud->stream,"%s (byte_size=%d,encoding=%d)",symbol->name,
		    symbol->s.ti.byte_size,symbol->s.ti.d.v.encoding);
	break;
    case DATATYPE_BITFIELD:
	fprintf(ud->stream,"bitfield %s",symbol->name);
	break;
    default:
	vwarn("unknown datatype_code %d!\n",symbol->s.ti.datatype_code);
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

    fprintf(ud->stream,"%ssymbol(",p);
    if (SYMBOL_IS_TYPE(symbol) && symbol->s.ti.extname)
	fprintf(ud->stream,"%s",symbol->s.ti.extname);
    else
	fprintf(ud->stream,"%s",symbol->name);
    fprintf(ud->stream,",%s,line=%d): ",
	    SYMBOL_TYPE(symbol->type),symbol->srcline);

    if (symbol->type == SYMBOL_TYPE_TYPE) 
	symbol_type_dump(symbol,&udn);
    else if (symbol->type == SYMBOL_TYPE_VAR) 
	symbol_var_dump(symbol,&udn);
    else if (symbol->type == SYMBOL_TYPE_FUNCTION) 
	symbol_function_dump(symbol,&udn);
    else if (symbol->type == SYMBOL_TYPE_LABEL) 
	symbol_label_dump(symbol,&udn);
    else 
	fprintf(ud->stream,"unknown symbol type %d!",symbol->type);
    fprintf(ud->stream,"\n");

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
