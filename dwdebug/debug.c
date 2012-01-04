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
#include <inttypes.h>

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
gboolean always_remove(gpointer key,gpointer value,gpointer user_data) {
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
 ** Symbol lookup functions.
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
     */
    if (symtab->lowpc <= pc && pc <= symtab->highpc) {
	return symtab;
    }

    return NULL;
}

struct symtab *space_lookup_symtab_pc(struct addrspace *space,uint64_t pc) {
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

struct symbol *lookup_sym(struct addrspace *space,char *name,
			  char *df_filename,char *df_name,char *df_version,
			  char *srcfile) {
    return NULL;
}

struct symbol *debugfile_lookup_var(struct debugfile *debugfile,char *name,
				    char *srcfile) {
    return NULL;
}

struct symbol *debugfile_lookup_func(struct debugfile *debugfile,char *name,
				     char *srcfile) {
    return NULL;
}

struct symbol *debugfile_lookup_type(struct debugfile *debugfile,char *name,
				     char *srcfile) {
    return NULL;
}

struct symbol *symtab_lookup_sym(struct symtab *symtab,char *name) {
    struct symtab *tmp;
    struct symbol *value;
    int namelen;
    char *namei;
    GHashTableIter iter;
    gpointer key;

    if ((namei = index(name,':'))) {
	namelen = namei - name;
	namei++;
    }
    else {
	namelen = strlen(name);
	namei = NULL;
    }

    /*
     * Check our symbols first, IF we're not looking for subtables.
     */
    if (!namei) {
	g_hash_table_iter_init(&iter,symtab->tab);
	while (g_hash_table_iter_next(&iter,
				      (gpointer *)&key,(gpointer *)&value)) {
	    if (strncmp(name,key,namelen) == 0)
		return (struct symbol *)value;
	}
    }

    /* 
     * Else, start checking children symtabs; DFS; first wins.  If they
     * sent a delimited string to us, only match successive subtabs
     * named with that string!
     */
    if (namei) {
	list_for_each_entry(tmp,&symtab->subtabs,member) {
	    if (tmp->name && strncmp(name,tmp->name,namelen) == 0) {
		return symtab_lookup_sym(tmp,namei);
	    }
	}
    }

    return NULL;
}

struct symbol *debugfile_lookup_sym(struct debugfile *debugfile,
				    char *srcfile,char *name) {
    struct symbol *retval;
    struct symtab *symtab;
    GHashTableIter iter;
    gpointer key;

    /*
     * Always check globals first, then types, then srcfile tables.
     */
    if ((retval = g_hash_table_lookup(debugfile->globals,name)))
	return retval;

    if ((retval = g_hash_table_lookup(debugfile->types,name)))
	return retval;

    if (srcfile) {
	if ((symtab = (struct symtab *)g_hash_table_lookup(debugfile->srcfiles,
							   srcfile)))
	    return symtab_lookup_sym(symtab,name);
	else
	    return NULL;
    }

    g_hash_table_iter_init(&iter,debugfile->srcfiles);
    while (g_hash_table_iter_next(&iter,(gpointer *)&key,(gpointer *)&symtab)) {
	retval = symtab_lookup_sym(symtab,name);
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

void g_hash_foreach_dump_symtab(gpointer key,gpointer value,gpointer userdata) {
    struct dump_info *ud = (struct dump_info *)userdata;
    symtab_dump((struct symtab *)value,ud);
}

void g_hash_foreach_dump_symbol(gpointer key,gpointer value,gpointer userdata) {
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

void symtab_dump(struct symtab *symtab,struct dump_info *ud) {
    struct symtab *csymtab;
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

    if (symtab->name)
	fprintf(ud->stream,"%ssymtab(%s):\n",p,symtab->name);
    else
	fprintf(ud->stream,"%ssymtab:\n",p);
    if (symtab->compdirname)
	fprintf(ud->stream,"%s    compdirname: %s\n",p,symtab->compdirname);
    fprintf(ud->stream,"%s    low pc: 0x%x, high pc: 0x%x\n",p,symtab->lowpc,symtab->highpc);
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
		fprintf(ud->stream," ");
	    }
	    else if (symbol->datatype_addr_ref) 
		fprintf(ud->stream,"tref%Lx ",symbol->datatype_addr_ref);
	//}
    }
    /* all variables are named, but not all members of structs/unions! */
    /* well, inlined params aren't named either. */
    if (symbol->s.ii.isinlineinstance && symbol->s.ii.isparam) {
	if (symbol->s.ii.origin) {
	    fprintf(ud->stream,"INLINED_PARAM(");
	    symbol_var_dump(symbol->s.ii.origin,&udn);
	    fprintf(ud->stream,")");
	}
	else
	    fprintf(ud->stream,"INLINED_ANON_PARAM()");
    }
    else if (symbol->name) 
	fprintf(ud->stream,"%s",symbol->name);

    if (symbol->type == SYMBOL_TYPE_VAR 
	&& symbol->s.ii.d.v.bit_size > 0) {
	/* this is a bitfield */
	fprintf(ud->stream,":%hd(%hd)",symbol->s.ii.d.v.bit_size,
		symbol->s.ii.d.v.bit_offset);
    }
    if (symbol->type == SYMBOL_TYPE_VAR
	&& symbol->s.ii.isenumval) {
	// XXX fix type printing -- this *is* a malloc'd constval
	fprintf(ud->stream," = %d",*((int *)symbol->s.ii.d.constval));
    }

    if (ud->detail && symbol->s.ii.l.loctype != LOCTYPE_UNKNOWN) {
	fprintf(ud->stream," @@ ");
	location_dump(&symbol->s.ii.l,ud);
    }
}

void symbol_function_dump(struct symbol *symbol,struct dump_info *ud) {
    struct symbol *arg;
    struct symtab *csymtab;
    int i = 0;
    struct dump_info udn = {
	.stream = ud->stream,
	.prefix = ud->prefix,
	.detail = 0,
	.meta = 0,
    };

    if (ud->detail) {
	if (symbol->datatype) {
	    symbol_type_dump(symbol->datatype,&udn);
	    fprintf(ud->stream," ");
	}
	else if (symbol->datatype_addr_ref)
	    fprintf(ud->stream,"ftref%Lx ",symbol->datatype_addr_ref);
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
    if (ud->meta) 
	fprintf(ud->stream," (lowpc=0x%Lx,highpc=0x%Lx,external=%d,prototyped=%d,declinline=%d,inlined=%d) ",
		symbol->s.ii.d.f.lowpc,symbol->s.ii.d.f.highpc,
		symbol->s.ii.d.f.external,symbol->s.ii.d.f.prototyped,
		symbol->s.ii.isdeclinline,symbol->s.ii.isinlined);
    if (ud->detail) {
	fprintf(ud->stream,"(");
	list_for_each_entry(arg,&(symbol->s.ii.d.f.args),member) {
	    ++i;
	    symbol_var_dump(arg,ud);
	    if (i != symbol->s.ii.d.f.count)
		fprintf(ud->stream,",");
	}
	fprintf(ud->stream,")");
	fprintf(ud->stream," @@ 0x%" PRIx64 " 0x%" PRIx64,
		symbol->s.ii.d.f.lowpc,symbol->s.ii.d.f.highpc);
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
	symbol_type_dump(symbol->s.ti.d.a.array_datatype,&udn);
	fprintf(ud->stream," ");
	for (i = 0; i < symbol->s.ti.d.a.count; ++i) {
	    fprintf(ud->stream,"[%d]",symbol->s.ti.d.a.subranges[i] + 1);
	}
	break;
    case DATATYPE_CONST:
	fprintf(ud->stream,"const ");
	symbol_type_dump(symbol->s.ti.d.cq.const_datatype,ud);
	break;
    case DATATYPE_VOL:
	fprintf(ud->stream,"volatile ");
	symbol_type_dump(symbol->s.ti.d.vq.vol_datatype,ud);
	break;
    case DATATYPE_STRUCT:
    case DATATYPE_UNION:
	ss = "struct";
	if (symbol->s.ti.datatype_code == DATATYPE_UNION)
	    ss = "union";
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
	if (symbol->s.ti.d.p.ptr_datatype) {
	    if (symbol->s.ti.d.p.ptr_datatype->type == SYMBOL_TYPE_TYPE
		&& (symbol->s.ti.d.p.ptr_datatype->s.ti.datatype_code == DATATYPE_PTR
		    || symbol->s.ti.d.p.ptr_datatype->s.ti.datatype_code == DATATYPE_VOID 
		    || symbol->s.ti.d.p.ptr_datatype->s.ti.datatype_code == DATATYPE_BASE))
		symbol_type_dump(symbol->s.ti.d.p.ptr_datatype,ud);
	    else {
		symbol_type_dump(symbol->s.ti.d.p.ptr_datatype,&udn);
	    }
	    fprintf(ud->stream,"*");
	}
	else
	    fprintf(ud->stream,"ptref%Lx *",symbol->s.ti.d.p.ptr_datatype_addr_ref);
	break;
    case DATATYPE_TYPEDEF:
	if (!ud->detail)
	    fprintf(ud->stream,"%s",symbol->name);
	else if (symbol->s.ti.d.td.td_datatype) {
	    fprintf(ud->stream,"typedef ");
	    symbol_type_dump(symbol->s.ti.d.td.td_datatype,ud);
	    fprintf(ud->stream," %s",symbol->name);
	}
	else 
	    fprintf(ud->stream,"typedef tdtref%Lx %s",
		    symbol->s.ti.d.td.td_datatype_addr_ref,symbol->name);
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
    else 
	fprintf(ud->stream,"unknown symbol type %d!",symbol->type);
    fprintf(ud->stream,"\n");

    if (ud->prefix)
	free(np);
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
			     int language,char *producer,
			     unsigned long lowpc,unsigned long highpc) {
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
    symtab->lowpc = lowpc;
    symtab->highpc = highpc;

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

void symbol_desc_function(struct symbol *symbol,uint64_t lowpc,uint64_t highpc,
			  uint8_t inlined) {

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
    "type",
    "var",
    "function"
};

char *DATATYPE_STRINGS[] = {
    "array",
    "struct",
    "enum",
    "ptr",
    "function",
    "typedef",
    "union",
    "base",
    "const",
    "bitfield"
};

char *LOCTYPE_STRINGS[] = {
    "addr",
    "reg",
    "regaddr"
};
