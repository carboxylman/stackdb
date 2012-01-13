#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

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

#include "libdwdebug.h"

/*
 * Debug stuff.
 */
static int libdwdebug_debug_level = -1;

void libdwdebug_set_debug_level(int level) {
    libdwdebug_debug_level = level;
}

#ifdef LIBDWDEBUG_DEBUG
void _libdwdebug_debug(int level,char *format,...) {
    va_list args;
    if (libdwdebug_debug_level < level)
	return;
    va_start(args, format);
    vfprintf(stderr, format, args);
    fflush(stderr);
    va_end(args);
}
#endif

static char *LIBFORMAT1 = "([\\w\\d_\\.\\-]+[\\w\\d]).so.([\\d\\.]+)";
static char *LIBFORMAT2 = "([\\w\\d_\\.\\-]+[\\w\\d]).so";
static regex_t LIBREGEX1;
static regex_t LIBREGEX2;

void libdwdebug_init(void) {
    regcomp(&LIBREGEX1,LIBFORMAT1,REG_EXTENDED);
    regcomp(&LIBREGEX2,LIBFORMAT2,REG_EXTENDED);
}

/*
 * Globals.
 */

/* These are the address spaces we know about. */
LIST_HEAD(spaces);

/* These are the known, loaded (maybe partially) debuginfo files. */
LIST_HEAD(debugfiles);

/*
 * Some generic GHashTable util functions for freeing hashtables.
 */
gboolean always_remove(gpointer key __attribute__((unused)),
		       gpointer value __attribute__((unused)),
		       gpointer user_data __attribute__((unused))) {
    return TRUE;
}

void ghash_str_free(gpointer data) {
    free((void *)data);
}

static void ghash_debugfile_free(gpointer data) {
    struct debugfile *debugfile = (struct debugfile *)data;
    if (--(debugfile->refcnt) == 0 && !debugfile->infinite) {
	ldebug(5,"freeing debugfile(%s)\n",debugfile->idstr);
	debugfile_free(debugfile);
    }
}

static void ghash_symtab_free(gpointer data) {
    struct symtab *symtab = (struct symtab *)data;

    // XXX more?
    ldebug(5,"freeing symtab(%s:%s)\n",
	   symtab->debugfile->idstr,symtab->name);
    symtab_free(symtab);
}

static void ghash_symbol_free(gpointer data) {
    struct symbol *symbol = (struct symbol *)data;

    // XXX more?
    ldebug(5,"freeing symbol(%s:%s:%s)\n",
	   symbol->symtab->debugfile->idstr,symbol->symtab->name,
	   symbol->name);
    symbol_free(symbol);
}

/**
 ** Local prototypes.
 **/
static struct symbol *__symbol_get_one_member(struct symbol *symbol,char *member,
					      struct symbol_chain **chainptr);

/**
 ** PC lookup functions.
 **/
/*
 * NOTE: this function returns the tightest bounding symtab -- which may
 * be the symtab that was passed in!!
 */
struct symtab *symtab_lookup_pc(struct symtab *symtab,uint64_t pc) {
    struct symtab *tmp;
    struct symtab *retval;

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
	lwarn("no range list support yet!\n");
    }

    return NULL;
}

struct symtab *addrspace_lookup_pc(struct addrspace *space,uint64_t pc) {
    struct memregion *region;
    struct symtab *symtab;
    int found = 0;
    GHashTableIter iter, iter2;
    gpointer key, value;
    
    list_for_each_entry(region,&space->regions,region) {
	if (region->start <= pc && pc <= region->end)
	    found = 1;
	break;
    }

    if (!found)
	return NULL;

    g_hash_table_iter_init(&iter,region->debugfiles);
    while (g_hash_table_iter_next(&iter,
				  (gpointer *)&key,(gpointer *)&value)) {
	g_hash_table_iter_init(&iter2,((struct debugfile *)value)->srcfiles);
	while (g_hash_table_iter_next(&iter2,
				      (gpointer *)&key,(gpointer *)&symtab)) {
	    symtab = symtab_lookup_pc(symtab,pc);
	    if (symtab)
		return symtab;
	}
    }

    return NULL;
}

/**
 ** Symbol lookup functions.
 **/
struct symbol *symtab_lookup_sym(struct symtab *symtab,char *name,
				 symbol_type_flag_t ftype) {
    struct symbol *value;
    GHashTableIter iter;
    gpointer key;

    /*
     * Check our symbols first.
     */
    g_hash_table_iter_init(&iter,symtab->tab);
    while (g_hash_table_iter_next(&iter,
				  (gpointer *)&key,(gpointer *)&value)) {
	if (((ftype != SYMBOL_TYPE_FLAG_NONE
	      && ((ftype & SYMBOL_TYPE_FLAG_TYPE && SYMBOL_IS_TYPE(value))
		  || (ftype & SYMBOL_TYPE_FLAG_VAR && SYMBOL_IS_VAR(value))
		  || (ftype & SYMBOL_TYPE_FLAG_FUNCTION 
		      && SYMBOL_IS_FUNCTION(value))
		  || (ftype & SYMBOL_TYPE_FLAG_LABEL 
		      && SYMBOL_IS_LABEL(value))))
	     || ftype == SYMBOL_TYPE_FLAG_NONE)
	    && strcmp(name,key) == 0)
	    return (struct symbol *)value;
    }

    return NULL;
}
struct symbol_chain *symtab_lookup_nested_sym(struct symtab *symtab,char *name,
					      const char *delim,
					      symbol_type_flag_t ftype) {
    struct symtab *tmp;
    struct symbol *value;
    GHashTableIter iter;
    gpointer key;

    //struct symbol_chain *chain = (struct symbol_chain *)malloc(sizeof(struct symbol_chain));

    return NULL;

    /*
     * Check our symbols first.
     */
    g_hash_table_iter_init(&iter,symtab->tab);
    while (g_hash_table_iter_next(&iter,
				  (gpointer *)&key,(gpointer *)&value)) {
	if (((ftype != SYMBOL_TYPE_FLAG_NONE
	      && ((ftype & SYMBOL_TYPE_FLAG_TYPE && SYMBOL_IS_TYPE(value))
		  || (ftype & SYMBOL_TYPE_FLAG_VAR && SYMBOL_IS_VAR(value))
		  || (ftype & SYMBOL_TYPE_FLAG_FUNCTION 
		      && SYMBOL_IS_FUNCTION(value))
		  || (ftype & SYMBOL_TYPE_FLAG_LABEL 
		      && SYMBOL_IS_LABEL(value))))
	     || ftype == SYMBOL_TYPE_FLAG_NONE)
	    && strcmp(name,key) == 0)
	    //return (struct symbol *)value;
	    break;
    }

    /* 
     * If no match, start checking children symtabs; DFS; first wins.
     * BUT, we only check anonymous subtables (i.e., lexical blocks).
     */
    list_for_each_entry(tmp,&symtab->subtabs,member) {
	if (tmp->name && strcmp(name,tmp->name) == 0) {
	    //return symtab_lookup_sym(tmp,namei,ftype);
	}
    }

    return NULL;
}

struct symbol *target_lookup_sym(struct target *target,char *name,
				 char *srcfile,symbol_type_flag_t ftype,
				 struct memregion **retregion) {
    struct memregion *region;
    struct symbol *retval;
    struct debugfile *debugfile;
    GHashTableIter iter;
    gpointer key;

    if (!target->space)
	return NULL;

    list_for_each_entry(region,&target->space->regions,region) {
	g_hash_table_iter_init(&iter,region->debugfiles);
	while (g_hash_table_iter_next(&iter,(gpointer *)&key,
				      (gpointer *)&debugfile)) {
	    retval = debugfile_lookup_sym(debugfile,name,srcfile,ftype);
	    if (retval) {
		if (retregion)
		    *retregion = region;
		return retval;
	    }
	}
    }

    return NULL;
}

struct symbol_chain *target_lookup_nested_sym(struct target *target,
					      char *name,const char *delim,
					      char *srcfile,
					      symbol_type_flag_t ftype,
					      struct memregion **retregion) {
    int len, alen;
    struct symbol *member;
    struct symbol_chain *chain;
    char *next;
    char *lname;
    char *saveptr = NULL;
    struct symbol_chain *anonchain = NULL;
    struct symbol **tmpsc = NULL;
    int i;

    chain = (struct symbol_chain *)malloc(sizeof(struct symbol_chain));

    /* assume that most chains will only have 2 members :) */
    alen = 2;
    chain->chain = (struct symbol **)malloc(sizeof(struct symbol *)*alen);
    len = 0;

    lname = strdup(name);
    while ((next = strtok_r(!saveptr ? lname : NULL,delim,&saveptr))) {
	/* Do the first token by looking up in the target.  For the
	 * rest, lookup in the parent symbol.
	 */
	if (len == 0) {
	    if (!(chain->chain[len] = target_lookup_sym(target,next,
							srcfile,ftype,retregion)))
		goto errout;

	    ++len;
	    continue;
	}

	if (!(member = __symbol_get_one_member(chain->chain[len-1],
					       next,&anonchain)))
	    goto errout;
	else if (anonchain && anonchain->count) {
	    /* If anonchain has any members, we now have to glue those
	     * members into our overall chain, BEFORE gluing the actual
	     * found symbol onto the tail end of the chain.
	     */
	    //asm("int $3");
	    if ((alen - len) < (anonchain->count + 1)) {
		alen += (anonchain->count + 1) - (alen - len);
		if (!(tmpsc = realloc(chain->chain,
				      alen*sizeof(struct symbol *)))) {
		    /* free the anonchain */
		    free(anonchain->chain);
		    free(anonchain);
		    goto errout;
		}
		chain->chain = tmpsc;
	    }
	    for (i = 0; i < anonchain->count; ++i)
		chain->chain[len++] = anonchain->chain[i];
	    /* now slap the retval on, too! */
	    chain->chain[len++] = member;
	    /* free the anonchain and reset our pointer */
	    //asm("int $3");
	    free(anonchain->chain);
	    free(anonchain);
	    anonchain = NULL;
	}
	else {
	    if (alen == len) {
		alen += 2;
		if (!realloc(chain->chain,alen*sizeof(struct symbol *)))
		    goto errout;
	    }
	    chain->chain[len++] = member;
	}
    }
    chain->count = len;
    //asm("int $3");
    free(lname);
    /* downsize */
    if (!realloc(chain->chain,chain->count*(sizeof(struct symbol *))))
	lwarn("failed to downsize after succeeding: realloc: %s\n",
	      strerror(errno));
    //asm("int $3");

    return chain;

 errout:
    *retregion = NULL;
    free(lname);
    free(chain->chain);
    free(chain);

    return NULL;
}

struct symbol *debugfile_lookup_sym(struct debugfile *debugfile,
				    char *name,char *srcfile,
				    symbol_type_flag_t ftype) {
    struct symbol *retval;
    struct symtab *symtab;
    GHashTableIter iter;
    gpointer key;

    /*
     * Always check globals first, then types, then srcfile tables.
     */
    if (!(ftype & SYMBOL_TYPE_FLAG_TYPE)
	&& (retval = g_hash_table_lookup(debugfile->globals,name)))
	return retval;

    if ((ftype & SYMBOL_TYPE_FLAG_TYPE || ftype & SYMBOL_TYPE_FLAG_NONE)
	&& (retval = g_hash_table_lookup(debugfile->types,name)))
	return retval;

    if (srcfile) {
	if ((symtab = (struct symtab *)g_hash_table_lookup(debugfile->srcfiles,
							   srcfile)))
	    return symtab_lookup_sym(symtab,name,ftype);
	else
	    return NULL;
    }

    g_hash_table_iter_init(&iter,debugfile->srcfiles);
    while (g_hash_table_iter_next(&iter,(gpointer *)&key,(gpointer *)&symtab)) {
	retval = symtab_lookup_sym(symtab,name,ftype);
	if (retval)
	    return retval;
    }

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

/*
 * Address spaces.
 */
/*
 * Creates an address space.
 *
 * You must supply some sort of unique combo of name:id:pid -- these
 * values form the unique internal ID for an address space.  They don't
 * actually have to mean anything, unless you are using a target that
 * cares about those values.
 *
 * For instance, a linux_userproc target requires the pid field.  The
 * linux_corefile target doesn't require any of the fields.  The
 * linux_vmprobes target requires both id (the xen guest domain id) and
 * pid (0 means kernel; > 0 means a userspace process in the guest).
 */
struct addrspace *addrspace_create(char *name,int id,int pid) {
    struct addrspace *retval;
    struct addrspace *lpc;
    char *idstr;
    int idstrlen;

    assert(name);
    assert(pid > 0);

    /* make sure this space doesn't already exist: */
    list_for_each_entry(lpc,&spaces,space) {
	if (strcmp(name,lpc->name) == 0
	    && id == lpc->id && pid == lpc->pid) {
	    ++(lpc->refcnt);
	    return lpc;
	}
    }

    idstrlen = strlen(name) + 1 + 64;
    idstr = (char *)malloc(idstrlen);
    if (!idstr) {
	errno = ENOMEM;
	return NULL;
    }
    snprintf(idstr,idstrlen,"%s:%d:%d",name,id,pid);

    retval = (struct addrspace *)malloc(sizeof(struct addrspace));
    if (!retval) {
	errno = ENOMEM;
	free(idstr);
	return NULL;
    }

    memset(retval,0,sizeof(*retval));

    retval->idstr = idstr;
    retval->name = strdup(name);
    retval->id = id;
    retval->pid = pid;
    retval->refcnt = 1;

    INIT_LIST_HEAD(&retval->regions);

    list_add_tail(&(retval->space),&spaces);

    ldebug(5,"built addrspace(%s)\n",idstr);

    return retval;
}

void addrspace_free(struct addrspace *space) {
    struct memregion *lpc;
    struct memregion *tmp;

    assert(space);

    if (--(space->refcnt))
	return;

    ldebug(5,"freeing addrspace(%s)\n",space->idstr);

    /* cleanup */
    list_del(&space->space);

    list_for_each_entry_safe(lpc,tmp,&space->regions,region) {
	memregion_free(lpc);
    }

    free(space->name);
    free(space->idstr);
    free(space);
}

/*
 * Memory regions.
 */
struct memregion *memregion_create(struct addrspace *space,region_type_t type,
				   char *filename) {
    struct memregion *retval;

    retval = (struct memregion *)malloc(sizeof(*retval));
    if (!retval) 
	return NULL;

    memset(retval,0,sizeof(*retval));

    retval->space = space;

    if (filename) 
	retval->filename = strdup(filename);
    retval->type = type;

    retval->debugfiles = g_hash_table_new_full(g_str_hash,g_str_equal,
					       ghash_str_free,
					       ghash_debugfile_free);
    if (!retval->debugfiles) {
	if (retval->filename)
	    free(retval->filename);
	free(retval);
	return NULL;
    }

    list_add_tail(&retval->region,&space->regions);

    ldebug(5,"built memregion(%s:%s:%d)\n",space->idstr,retval->filename,
	   retval->type);

    return retval;
}

struct target *memregion_target(struct memregion *region) {
    return (region->space ? region->space->target : NULL);
}

int memregion_contains(struct memregion *region,ADDR addr) {
    return (region->start <= addr && addr <= region->end ? 1 : 0);
}

void memregion_free(struct memregion *region) {
    ldebug(5,"freeing memregion(%s:%s:%d)\n",region->space->idstr,
	   region->filename,region->type);

    list_del(&region->region);

    if (region->debugfiles) {
	/* NOTE: the ghash_debugfile_free value destructor handles
	   destroying the debugfile if its refcnt is 0 and it is not an
	   infinite debugfile. */
	g_hash_table_remove_all(region->debugfiles);
    }
    if (region->filename)
	free(region->filename);
    free(region);
}

/*
 * Debugfiles.
 */
static char *debugfile_build_idstr(char *filename,char *name,char *version) {
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

static int debugfile_filename_info(char *filename,char **realfilename,
				   char **name,char **version) {
    size_t rc;
    char buf[PATH_MAX];
    regmatch_t matches[2];
    int match_len;
    char *realname;
    struct stat sbuf;

    if (stat(filename,&sbuf) < 0) {
	lerror("stat(%s): %s\n",filename,strerror(errno));
	return -1;
    }
    else if (!S_ISLNK(sbuf.st_mode)) {
	realname = NULL;
	return 0;
    }

    if ((rc = readlink(filename,buf,PATH_MAX - 1)) < 0) {
	lwarn("readlink(%s): %s\n",filename,strerror(errno));
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
	    lwarn("cannot extract version from %s!\n",realname);
	}
    }
    else {
	lwarn("cannot extract name and version from %s!\n",realname);
    }

    return 0;
}

static struct debugfile *__debugfile_create(char *filename,
					    debugfile_type_t type,
					    char *name,char *version,
					    char *idstr) {
    struct debugfile *debugfile;
    struct debugfile *tmp;

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
    debugfile->refcnt = 1;

    debugfile->debugfile.next = NULL;
    debugfile->debugfile.prev = NULL;

    /* initialize hashtables */

    /* This is the primary symtab hashtable -- so we provide key and
     * value destructors so that we can call g_hash_table_remove_all to
     * clean it.
     */
    debugfile->srcfiles = g_hash_table_new_full(g_str_hash,g_str_equal,
						ghash_str_free,
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

    /* Now, if this is a debugfile for a kernel module, check and see if
     * the debugfile for the kernel (for this version) exists; if it
     * does, set our kernel_debugfile pointer to that and use that
     * debugfile's types table in preference to our own.
     */
    if (debugfile->type == DEBUGFILE_TYPE_KMOD) {
	list_for_each_entry(tmp,&debugfiles,debugfile) {
	    if (tmp->type == DEBUGFILE_TYPE_KERNEL
		&& tmp->version && debugfile->version 
		&& strcmp(tmp->version,debugfile->version) == 0) {
		debugfile->kernel_debugfile = tmp;
		++(tmp->refcnt);
		ldebug(1,"set kernel_debugfile for %s to %s\n",
		       debugfile->idstr,tmp->idstr);
		break;
	    }
	}
    }

    return debugfile;
}

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
	fprintf(ud->stream,"%sRANGE(pc): low=0x%" PRIx64 ", high=0x%" PRIx64,
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

    fprintf(ud->stream,"%sLOCLIST: (",ud->prefix);
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
	fprintf(ud->stream,"%ssymtab(%s):\n",p,symtab->name);
    else
	fprintf(ud->stream,"%ssymtab:\n",p);
    if (symtab->compdirname)
	fprintf(ud->stream,"%s    compdirname: %s\n",p,symtab->compdirname);
    range_dump(&symtab->range,&udn3);
    fprintf(ud->stream,"\n");
    if (symtab->producer)
	fprintf(ud->stream,"%s    producer: %s\n",p,symtab->producer);
    if (symtab->language)
	fprintf(ud->stream,"%s    language: %d\n",p,symtab->language);
    g_hash_table_foreach(symtab->tab,g_hash_foreach_dump_symbol,&udn);

    if (!list_empty(&symtab->subtabs)) {
	fprintf(ud->stream,"%s  subscopes:\n",p);
	list_for_each_entry(csymtab,&(symtab->subtabs),member) {
	    symtab_dump(csymtab,&udn2);
	}
    }

    if (symtab->name)
	fprintf(ud->stream,"%send symtab(%s)\n",p,symtab->name);
    else
	fprintf(ud->stream,"%send symtab\n",p);

    if (ud->prefix) {
	free(np);
	free(np2);
    }
}

void location_dump(struct location *location,struct dump_info *ud) {
    switch(location->loctype) {
    case LOCTYPE_ADDR:
	fprintf(ud->stream,"0x%" PRIx64,location->l.addr);
	break;
    case LOCTYPE_REG:
	fprintf(ud->stream,"REG(%d)",location->l.reg);
	break;
    case LOCTYPE_REG_ADDR:
	fprintf(ud->stream,"REGADDR(%d)",location->l.reg);
	break;
    case LOCTYPE_REG_OFFSET:
	fprintf(ud->stream,"REGOFFSET(%hhd,%ld)",location->l.regoffset.reg,
		location->l.regoffset.offset);
	break;
    case LOCTYPE_FBREG_OFFSET:
	fprintf(ud->stream,"FBREGOFFSET(%ld)",location->l.fboffset);
	break;
    case LOCTYPE_MEMBER_OFFSET:
	fprintf(ud->stream,"MEMBEROFFSET(%d)",location->l.member_offset);
	break;
    case LOCTYPE_RUNTIME:
	fprintf(ud->stream,"RUNTIMEDWOP (%p,%d)",
		location->l.runtime.data,location->l.runtime.len);
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

    if (ud->detail) {
	//if (1 || !(symbol->type == SYMBOL_TYPE_VAR
	//    && symbol->s.ii.isenumval)) {
	    if (symbol->datatype) {
		symbol_type_dump(symbol->datatype,&udn);
	    }
	    else if (symbol->datatype_addr_ref) 
		fprintf(ud->stream,"tref%" PRIx64,symbol->datatype_addr_ref);
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
	location_dump(&symbol->s.ii.l,ud);

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
	    fprintf(ud->stream,"ftref%" PRIx64 " ",symbol->datatype_addr_ref);
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
    if (ud->meta) {
	if (symbol->s.ii.d.f.fblist && symbol->s.ii.d.f.fblist->len) {
	    loc_list_dump(symbol->s.ii.d.f.fblist,&udn2);
	}
	fprintf(ud->stream," (external=%d,prototyped=%d,declinline=%d,inlined=%d) ",
		symbol->s.ii.isexternal,symbol->s.ii.isprototyped,
		symbol->s.ii.isdeclinline,symbol->s.ii.isinlined);
    }
    if (ud->detail) {
	fprintf(ud->stream,"(");
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
	    fprintf(ud->stream,"ptref%" PRIx64 " *",symbol->s.ti.type_datatype_ref);
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
	    fprintf(ud->stream,"typedef tdtref%" PRIx64 " %s",
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
	lwarn("unknown datatype_code %d!\n",symbol->s.ti.datatype_code);
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

    fprintf(ud->stream,"%ssymbol(%s,%s,line=%d): ",
	    p,symbol->name,SYMBOL_TYPE(symbol->type),symbol->srcline);
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

void symbol_chain_dump(struct symbol_chain *chain,struct dump_info *ud) {
    int i = 0;
    struct dump_info udn = {
	.stream = ud->stream,
	.detail = ud->detail,
	.meta = ud->meta,
    };
    char *prefixbuf = malloc(strlen(ud->prefix) + chain->count * 2 + 1);
    strcpy(prefixbuf,ud->prefix);
    int len = strlen(prefixbuf);

    udn.prefix = prefixbuf;

    while (1) {
	symbol_dump(chain->chain[i],&udn);
	if (++i == chain->count)
	    break;
	fprintf(ud->stream,"\n");
	prefixbuf[len++] = ' ';
	prefixbuf[len++] = ' ';
	prefixbuf[len] = '\0';
    }
}

struct debugfile *debugfile_create(char *filename,debugfile_type_t type) {
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
	ldebug(2,"using %s instead of symlink %s\n",realname,filename);

    idstr = debugfile_build_idstr(realname,name,version);

    debugfile = __debugfile_create(realname,type,name,version,idstr);
    if (!debugfile) {
	free(idstr);
	if (realname != filename)
	    free(realname);
    }

    return debugfile;
}

struct debugfile *debugfile_attach(struct memregion *region,
				   char *filename,debugfile_type_t type) {
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
	ldebug(2,"using %s instead of symlink %s\n",realname,filename);

    idstr = debugfile_build_idstr(realname,name,version);

    /* if they already loaded this debugfile into this region, error */
    if (g_hash_table_lookup(region->debugfiles,idstr)) {
	lerror("debugfile(%s) already in use in region(%s) in space (%s)!\n",
	       idstr,region->filename,region->space->idstr);
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

	    ldebug(1,"reusing debugfile(%s,%s,%s,%d) for region(%s) in space (%s,%d,%d)\n",
		   realname,name,version,type,region->filename,
		   region->space->name,region->space->id,region->space->pid);

	    g_hash_table_insert(region->debugfiles,realname,debugfile);

	    free(idstr);
	    if (realname != filename)
		free(realname);
	    return debugfile;
	}
    }

    debugfile = __debugfile_create(realname,type,name,version,idstr);
    if (!debugfile) {
	free(idstr);
	if (realname != filename)
	    free(realname);
	return NULL;
    }

    /*
     * Finally, load in the debuginfo!
     */
    if (load_debug_info(debugfile)) {
	debugfile_free(debugfile);
	return NULL;
    }

    list_add_tail(&debugfile->debugfile,&debugfiles);

    g_hash_table_insert(region->debugfiles,idstr,debugfile);

    return debugfile;
}

int debugfile_add_symtab(struct debugfile *debugfile,struct symtab *symtab) {
    if (unlikely(g_hash_table_lookup(debugfile->srcfiles,symtab->name)))
	return 1;
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

void debugfile_free(struct debugfile *debugfile) {
    char *idstr = debugfile->idstr;

    if (debugfile->refcnt)
	return;

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

    ldebug(1,"freed debugfile(%s)\n",idstr);
}

/*
 * Symtabs.
 */
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
					ghash_str_free,
					ghash_symbol_free);

    return symtab;
}

void symtab_set_name(struct symtab *symtab,char *name) {
    symtab->name = name;
    if (name && (!symtab->debugfile 
			|| !symtab_str_in_strtab(symtab,name)))
	symtab->name = strdup(name);
}

void symtab_set_compdirname(struct symtab *symtab,char *compdirname) {
    symtab->compdirname = compdirname;
    if (compdirname && (!symtab->debugfile 
			|| !symtab_str_in_strtab(symtab,compdirname)))
	symtab->compdirname = strdup(compdirname);
}

void symtab_set_producer(struct symtab *symtab,char *producer) {
    symtab->producer = producer;
    if (producer && (!symtab->debugfile 
		     || !symtab_str_in_strtab(symtab,producer)))
	symtab->producer = strdup(producer);
}

void symtab_free(struct symtab *symtab) {
    g_hash_table_destroy(symtab->tab);
    if (symtab->name && !symtab_str_in_strtab(symtab,symtab->name))
	free(symtab->name);
    if (symtab->compdirname && !symtab_str_in_strtab(symtab,symtab->compdirname))
	free(symtab->compdirname);
    if (symtab->producer && !symtab_str_in_strtab(symtab,symtab->producer))
	free(symtab->producer);
    free(symtab);
}

/* Returns 1 if string is in symtab; else 0 */
int symtab_str_in_strtab(struct symtab *symtab,char *strp) {
    if (symtab->debugfile && symtab->debugfile->strtab
	&& strp >= symtab->debugfile->strtab
	&& strp < (symtab->debugfile->strtab + symtab->debugfile->strtablen))
	return 1;
    return 0;
}

/*
 * Symbols.
 */
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

int symbol_insert(struct symbol *symbol) {
    if (!symbol->name) {
	lerror("VERY BAD -- tried to insert a symbol with no name!\n");
	return 1;
    }

    if (unlikely(g_hash_table_lookup(symbol->symtab->tab,symbol->name)))
	return 1;
    g_hash_table_insert(symbol->symtab->tab,symbol->name,symbol);
    return 0;
}

void symbol_set_name(struct symbol *symbol,char *name) {
    symbol->name = name;
    if (name && (!symbol->symtab || !symbol->symtab->debugfile 
		 || !symtab_str_in_strtab(symbol->symtab,name)))
	symbol->name = strdup(name);
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
					      struct symbol_chain **chainptr) {
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
    int startstacklen;
    
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
		//ldebug(1,"checking symbol: ");
		//symbol_dump(retval,&udn);

		if (SYMBOL_IST_STUN(retval->datatype) 
		    && !retval->name) {
		    /* push this one for later examination. */
		    if (stacklen == stackalen) {
			stackalen += 4;
			if (!(tmpstack = (struct symbol **)realloc(anonstack,
								   sizeof(struct symbol *)*stackalen))) {
			    lerror("realloc anonstack: %s\n",strerror(errno));
			    goto errout;
			}
			anonstack = tmpstack;

			if (!(tmpparentstack = (int *)realloc(parentstack,
							      sizeof(int)*stackalen))) {
			    lerror("realloc parentstack: %s\n",
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
		lwarn("big stackalen=%d, stack=%d\n",stackalen,stacklen);
	    else 
		ldebug(4,"stackalen=%d, stack=%d\n",stackalen,stacklen);
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
	return symtab_lookup_sym(symbol->s.ii.d.f.symtab,member,
				 SYMBOL_TYPE_FLAG_VAR | SYMBOL_TYPE_FLAG_FUNCTION);

	/*
	GHashTableIter iter;
	char *localname;
	struct symbol *localsymbol;

	g_hash_table_iter_init(&iter,&symbol->s.ii.d.f.symtab->tab);
	while (g_hash_table_iter_next(&iter,(gpointer *)&symname,
				      (gpointer *)&localsymbol)) {
	*/
    }
    else if (SYMBOL_IS_VAR(symbol) && SYMBOL_IST_STUN(symbol->datatype)) {
	//ldebug(1,"returning result of searching S/U type symbol: ");
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
    //ldebug(1,"returning symbol: ");
    //symbol_dump(retval,&udn);

    //asm("int $3");

    /*
     * If type points to something other than the top-level symbol, that
     * means we explored anon structs, and we must return an anon symbol
     * chain that includes the anon variables between @symbol and @retval.
     */
    if (chainptr && type != symbol) {
	*chainptr = (struct symbol_chain *)malloc(sizeof(struct symbol_chain));
	/* Always includes the anon struct we found, and any anon struct
	 * parents.
	 */
	/* First count up how many anon parents we have in this chain; 
	 * then malloc it; then fill it up in reverse order.
	 */
	(*chainptr)->count = 1;
	for (j = i - 1; parentstack[j] != -1; j = parentstack[j]) {
	    ++((*chainptr)->count);
	}
	(*chainptr)->chain = (struct symbol **)malloc(sizeof(struct symbol *)*(*chainptr)->count);
	for (j = i - 1,k = (*chainptr)->count; k > 0; --k, j = parentstack[j]) {
	    (*chainptr)->chain[k-1] = anonstack[j];
	}
    }
    //asm("int $3");
    if (anonstack) 
	free(anonstack);
    if (parentstack)
	free(parentstack);
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

ADDR location_resolve(struct memregion *region,struct location *location,
		      struct loc_list *fblist) {
    struct target *target = memregion_target(region);
    REGVAL regval;
    int i;
    ADDR eip;
    ADDR frame_base;

    switch (location->loctype) {
    case LOCTYPE_UNKNOWN:
	errno = EINVAL;
	return 0;
    case LOCTYPE_ADDR:
	errno = 0;
	return location->l.addr;
    case LOCTYPE_REG:
	errno = EINVAL;
	return 0;
    case LOCTYPE_REG_ADDR:
	/* load the register value */
	regval = target_read_reg(target,location->l.reg);
	if (errno)
	    return 0;
	errno = 0;
	return regval;
    case LOCTYPE_REG_OFFSET:
	regval = target_read_reg(target,location->l.regoffset.reg);
	if (errno)
	    return 0;
	errno = 0;
	return (ADDR)(location->l.regoffset.offset + regval);
    case LOCTYPE_FBREG_OFFSET:
	/* If we have an fblist, we load EIP - 4, scan the location list
	 * for a match, and run the frame base location op recursively
	 * via location_resolve!
	 */
	if (!fblist) {
	    lerror("FBREG_OFFSET, but no frame base loclist!\n");
	    errno = EINVAL;
	    return 0;
	}
	// XXX - 4 is intel-specific?
	eip = target_read_reg(target,target->ipregno) - 4;
	if (errno)
	    return 0;
	errno = 0;
	ldebug(5,"eip = 0x%" PRIxADDR "\n",eip);
	for (i = 0; i < fblist->len; ++i) {
	    if (fblist->list[i]->start <= eip && eip < fblist->list[i]->end)
		break;
	}
	if (i == fblist->len) {
	    lerror("FBREG_OFFSET location not currently valid!\n");
	    errno = EINVAL;
	    return 0;
	}
	else if (!fblist->list[i]->loc) {
	    lerror("FBREG_OFFSET frame base in loclist does not have a location description!\n");
	    errno = EINVAL;
	    return 0;
	}
	/* now resolve the frame base value */
	frame_base = location_resolve(region,fblist->list[i]->loc,NULL);
	if (errno) {
	    lerror("FBREG_OFFSET frame base location description recursive resolution failed: %s\n",strerror(errno));
	    errno = EINVAL;
	    return 0;
	}
	ldebug(5,"frame_base = 0x%" PRIxADDR "\n",frame_base);
	ldebug(5,"fboffset = %" PRIi64 "\n",location->l.fboffset);
	if (0 && location->l.fboffset < 0)
	    return (ADDR)(frame_base - (ADDR)location->l.fboffset);
	else
	    return (ADDR)(frame_base + (ADDR)location->l.fboffset);
    case LOCTYPE_MEMBER_OFFSET:
    case LOCTYPE_RUNTIME:
	lwarn("currently unsupported location type %s\n",LOCTYPE(location->loctype));
	errno = EINVAL;
	return 0;
    default:
	lwarn("unknown location type %d\n",location->loctype);
	errno = EINVAL;
	return 0;
    }

    /* never reached */
    return 0;
}

int location_load(struct memregion *region,struct location *location,
		  struct loc_list *fblist,
		  load_flags_t flags,void *buf,int bufsiz) {
    ADDR final_location = 0;
    REGVAL regval;

    /* We can't mmap a value that is simply in a register. */
    if (flags & LOAD_FLAG_MMAP && location->loctype == LOCTYPE_REG) {
	errno = EINVAL;
	return -1;
    }

    if (location->loctype == LOCTYPE_REG) {
	/* just read the register directly */
	regval = target_read_reg(memregion_target(region),location->l.reg);
	if (errno)
	    return -1;
	if (memregion_target(region)->wordsize == 4 && __WORDSIZE == 64) {
	    /* If the target is 32-bit on 64-bit host, we have to grab
	     * the lower 32 bits of the regval.
	     */
	    memcpy(buf,((int32_t *)&regval)+1,bufsiz);
	}
	else
	    memcpy(buf,&regval,bufsiz);
    }
    else {
	final_location = location_resolve(region,location,fblist);

	if (errno)
	    return -1;

	ldebug(5,"final_location = 0x%" PRIxADDR "\n",final_location);

	if (flags & LOAD_FLAG_CHECK_VISIBILITY
	    && !memregion_contains(region,final_location)) {
	    errno = EFAULT;
	    return -1;
	}

	if (!target_read_addr(memregion_target(region),final_location,bufsiz,buf))
	    return -1;
    }

    return 0;
}

/*
 * Skips const and volatile types, for now.
 */
struct symbol *symbol_skip_types(struct symbol *type) {
    if (!SYMBOL_IS_TYPE(type))
	return NULL;

    while (type->type == SYMBOL_TYPE_TYPE
	   && (SYMBOL_IST_VOL(type)
	       || SYMBOL_IST_CONST(type))) {
	type = type->s.ti.type_datatype;
    }

    return type;
}

int symbol_load(struct memregion *region,struct symbol *symbol,
		load_flags_t flags,void **buf,int *bufsiz) {
    int didalloc = 0;
    struct symbol *datatype;

    if (!SYMBOL_IS_VAR(symbol)) {
	lwarn("symbol %s is not a variable (is %s)!\n",
	      symbol->name,SYMBOL_TYPE(symbol->type));
	errno = EINVAL;
	return -1;
    }

    datatype = symbol_skip_types(symbol->datatype);
    if (symbol->datatype != datatype)
	ldebug(5,"skipped from %s to %s for symbol %s\n",
	       DATATYPE(symbol->datatype->s.ti.datatype_code),
	       DATATYPE(datatype->s.ti.datatype_code),symbol->name);
    else 
	ldebug(5,"no skip; type for symbol %s is %s\n",
	       symbol->name,DATATYPE(symbol->datatype->s.ti.datatype_code));


    /* Alloc a buffer if they didn't. */
    if (!*buf) {
	*bufsiz = symbol_type_bytesize(datatype);
	*buf = malloc(*bufsiz);
	if (!*buf) {
	    lerror("malloc: %s\n",strerror(errno));
	    return -1;
	}
	didalloc = 1;
	ldebug(5,"malloc(%d) for symbol %s\n",*bufsiz,symbol->name);
    }

    if (location_load(region,&(symbol->s.ii.l),NULL,flags,*buf,*bufsiz)) {
	if (didalloc) {
	    free(*buf);
	    *buf = NULL;
	    *bufsiz = 0;
	}
	return -1;
    }

    return 0;
}

int symbol_nested_load(struct memregion *region,struct symbol_chain *chain,
		       load_flags_t flags,void **buf,int *bufsiz) {
    int didalloc = 0;
    int len = chain->count;
    struct symbol *symbol = chain->chain[len - 1];
    struct symbol *datatype;
    struct symbol *top_enclosing_symbol = NULL;
    int i;
    ADDR top_addr;
    OFFSET totaloffset;
    struct loc_list *fblist;

    if (!SYMBOL_IS_VAR(symbol)) {
	lwarn("symbol %s is not a variable (is %s)!\n",
	      symbol->name,SYMBOL_TYPE(symbol->type));
	errno = EINVAL;
	return -1;
    }

    /*
     * If the nested symbol is a struct member, we need the chain.
     * ALSO, if the nested symbol has a location type of FBREG or
     * RUNTIME, we need to extract the next highest up frame base
     * location list (probably the containing function or inlined
     * subroutine).  Otherwise, just load the last member in the chain.
     */
    if (!symbol->s.ii.ismember 
	&& symbol->s.ii.l.loctype != LOCTYPE_FBREG_OFFSET
	&& symbol->s.ii.l.loctype != LOCTYPE_RUNTIME) {
	return symbol_load(region,symbol,flags,buf,bufsiz);
    }
    /* Otherwise... */

    /* Grab the "real" datatype -- skipping things like const,
     * volatile.
     */
    datatype = symbol_skip_types(symbol->datatype);
    if (symbol->datatype != datatype)
	ldebug(5,"skipped from %s to %s for symbol %s\n",
	       DATATYPE(symbol->datatype->s.ti.datatype_code),
	       DATATYPE(datatype->s.ti.datatype_code),symbol->name);
    else 
	ldebug(5,"no skip; type for symbol %s is %s\n",
	       symbol->name,DATATYPE(symbol->datatype->s.ti.datatype_code));

    /* Alloc a buffer if they didn't. */
    if (!*buf) {
	*bufsiz = symbol_type_bytesize(datatype);
	*buf = malloc(*bufsiz);
	if (!*buf) {
	    lerror("malloc: %s\n",strerror(errno));
	    return -1;
	}
	didalloc = 1;
	ldebug(5,"malloc(%d) for symbol %s\n",*bufsiz,symbol->name);
    }

    if (symbol->s.ii.ismember) {
	/* Now assemble our member offset from the top enclosing struct,
	 * and resolve the location for that struct.  Then add our
	 * offset and load!
	 */
	totaloffset = symbol->s.ii.l.l.member_offset;
	for (i = len - 1; i > -1; --i) {
	    if (SYMBOL_IS_VAR(chain->chain[i])
		&& chain->chain[i]->s.ii.ismember) {
		totaloffset += chain->chain[i]->s.ii.l.l.member_offset;
		continue;
	    }
	    else if (SYMBOL_IS_VAR(chain->chain[i])
		     && SYMBOL_IST_STUN(chain->chain[i]->datatype)) {
		top_enclosing_symbol = chain->chain[i];
		break;
	    }
	    else {
		lerror("invalid chain member (%s,%s) for nested S/U member (%d)!\n",
		       chain->chain[i]->name,SYMBOL_TYPE(chain->chain[i]->type),i);
		goto errout;
	    }
	}

	top_addr = location_resolve(region,&top_enclosing_symbol->s.ii.l,NULL);
	if (errno) {
	    lerror("could not resolve location for top S/U in nested load: %s\n",
		   strerror(errno));
	    goto errout;
	}

	if (flags & LOAD_FLAG_CHECK_VISIBILITY
	    && !memregion_contains(region,top_addr + totaloffset)) {
	    lerror("memregion does not contain address 0x%" PRIxADDR "\n",
		   top_addr + totaloffset);
	    errno = EFAULT;
	    goto errout;
	}

	if (!target_read_addr(memregion_target(region),top_addr + totaloffset,
			      *bufsiz,*buf))
	    goto errout;

	return 0;
    }
    else {
	/* Find the deepest valid frame base listlocptr and pass that
	 * along. 
	 */
	for (i = len - 2; i > -1; --i) {
	    if (SYMBOL_IS_FUNCTION(chain->chain[i])
		&& chain->chain[i]->s.ii.d.f.fblist) {
		fblist = chain->chain[i]->s.ii.d.f.fblist;
		break;
	    }
	}

	if (!fblist && symbol->s.ii.l.loctype == LOCTYPE_FBREG_OFFSET) {
	    lerror("symbol %s had an FBREG_OFFSET location, but no containing frame base list!\n",
		   symbol->name);
	}
	else if (!fblist) {
	    ldebug(5,"symbol %s had a RUNTIME location, but no containing frame base list; bad things may happen!\n");
	}
	return location_load(region,&symbol->s.ii.l,fblist,flags,*buf,*bufsiz);
    }

 errout:
    if (didalloc) 
	free(*buf);
    return -1;
}

signed char      rvalue_c(void *buf)   { return *((signed char *)buf); }
unsigned char    rvalue_uc(void *buf)  { return *((unsigned char *)buf); }
wchar_t          rvalue_wc(void *buf)  { return *((wchar_t *)buf); }
uint8_t          rvalue_u8(void *buf)  { return *((uint8_t *)buf); }
uint16_t         rvalue_u16(void *buf) { return *((uint16_t *)buf); }
uint32_t         rvalue_u32(void *buf) { return *((uint32_t *)buf); }
uint64_t         rvalue_u64(void *buf) { return *((uint64_t *)buf); }
int8_t           rvalue_i8(void *buf)  { return *((int8_t *)buf); }
int16_t          rvalue_i16(void *buf) { return *((int16_t *)buf); }
int32_t          rvalue_i32(void *buf) { return *((int32_t *)buf); }
int64_t          rvalue_i64(void *buf) { return *((int64_t *)buf); }

void symbol_rvalue_print(FILE *stream,struct memregion *region,
			 struct symbol *symbol,void *buf,int bufsiz) {
    int i;
    int size;
    struct symbol *type;
    struct target *target = memregion_target(region);

    if (!SYMBOL_IS_VAR(symbol))
	return;

    type = symbol_skip_types(symbol->datatype);

    switch (type->s.ti.datatype_code) {
    case DATATYPE_BASE:
	if (type->s.ti.byte_size == 1) {
	    if (type->s.ti.d.v.encoding == ENCODING_SIGNED_CHAR)
		fprintf(stream,"%c",rvalue_c(buf));
	    else if (type->s.ti.d.v.encoding == ENCODING_UNSIGNED_CHAR)
		fprintf(stream,"%uc",rvalue_uc(buf));
	    else if (type->s.ti.d.v.encoding == ENCODING_SIGNED)
		fprintf(stream,"%" PRIi8,rvalue_i8(buf));
	    else if (type->s.ti.d.v.encoding == ENCODING_SIGNED)
		fprintf(stream,"%" PRIu8,rvalue_u8(buf));
	    else 
		fprintf(stream,"<BASE_%d>",type->s.ti.byte_size);
	}
	else if (type->s.ti.byte_size == 2) {
	    if (strstr(type->name,"char"))
		fprintf(stream,"%lc",rvalue_wc(buf));
	    else if (type->s.ti.d.v.encoding == ENCODING_SIGNED)
		fprintf(stream,"%" PRIi16,rvalue_i16(buf));
	    else if (type->s.ti.d.v.encoding == ENCODING_UNSIGNED)
		fprintf(stream,"%" PRIu16,rvalue_u16(buf));
	    else 
		fprintf(stream,"<BASE_%d>",type->s.ti.byte_size);
	}
	else if (type->s.ti.byte_size == 4) {
	    if (type->s.ti.d.v.encoding == ENCODING_SIGNED)
		fprintf(stream,"%" PRIi32,rvalue_i32(buf));
	    else if (type->s.ti.d.v.encoding == ENCODING_UNSIGNED)
		fprintf(stream,"%" PRIu32,rvalue_u32(buf));
	    else 
		fprintf(stream,"<BASE_%d>",type->s.ti.byte_size);
	}
	else if (type->s.ti.byte_size == 8) {
	    if (type->s.ti.d.v.encoding == ENCODING_SIGNED)
		fprintf(stream,"%" PRIi64,rvalue_i64(buf));
	    else if (type->s.ti.d.v.encoding == ENCODING_UNSIGNED)
		fprintf(stream,"%" PRIu64,rvalue_u64(buf));
	    else 
		fprintf(stream,"<BASE_%d>",type->s.ti.byte_size);
	}
	else {
	    fprintf(stream,"<BASE_%d>",type->s.ti.byte_size);
	}
	return;
    case DATATYPE_VOID:
	fprintf(stream,"<VOID>");
	return;
    case DATATYPE_ARRAY:
	fprintf(stream,"<ARRAY>");
	return;
    case DATATYPE_STRUCT:
	fprintf(stream,"<STRUCT>");
	return;
    case DATATYPE_UNION:
	fprintf(stream,"<UNION>");
	return;
    case DATATYPE_PTR:
	fprintf(stream,"0x");
	for (i = 0; i < target->ptrsize; ++i) {
	    fprintf(stream,"%02hhx",*(((uint8_t *)buf)+i));
	}
	return;
    case DATATYPE_FUNCTION:
	fprintf(stream,"<FUNCTION>");
	return;
    case DATATYPE_TYPEDEF:
	fprintf(stream,"<TYPEDEF>");
	return;
    case DATATYPE_CONST:
	fprintf(stream,"<CONST>");
	return;
    case DATATYPE_VOL:
	fprintf(stream,"<VOL>");
	return;
    case DATATYPE_BITFIELD:
	fprintf(stream,"<BITFIELD>");
	return;
    default:
	return;
    }
}

void symbol_rvalue_tostring(struct symbol *symbol,char **buf,int *bufsiz,
			    char *cur) {
    return;
}

struct value *symbol_load_fat(struct memregion *region,struct symbol *symbol,
			      load_flags_t flags,void *buf) {
    return NULL;
}

void symbol_free(struct symbol *symbol) {
    if (!symbol->symtab || !symtab_str_in_strtab(symbol->symtab,symbol->name))
	free(symbol->name);

    // XXX fill
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

char *REGION_STRINGS[] = {
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
    "runtime"
};

char *RANGE_TYPE_STRINGS[] = {
    "none",
    "pc",
    "list"
};
