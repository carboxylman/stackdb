/*
 * Copyright (c) 2013 The University of Utah
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "config.h"
#include "log.h"
#include "output.h"
#include "dwdebug.h"

#include <dwarf.h>
#include <gelf.h>
#include <elfutils/libebl.h>
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>

#include "memory-access.h"


/* binary filename to debug filename */
static GHashTable *binfile_tab = NULL;

/*
 * For now, only an ELF backend.
 */
extern struct binfile_ops elf_binfile_ops;

struct binfile_ops *binfile_types[] = {
    &elf_binfile_ops,
    NULL,
};

static char *LIBFORMAT1 = "([\\w\\d_\\.\\-]+[\\w\\d]).so.([\\d\\.]+)";
static char *LIBFORMAT2 = "([\\w\\d_\\.\\-]+[\\w\\d]).so";
static regex_t LIBREGEX1;
static regex_t LIBREGEX2;

static int init_done = 0;

/*
 * Helpers.
 */
static int _filename_info(char *filename,
			  char **realfilename,char **name,char **version);

/*
 * Lib init/fini stuff.
 */
void binfile_init(void) {
    if (init_done)
	return;

    regcomp(&LIBREGEX1,LIBFORMAT1,REG_EXTENDED);
    regcomp(&LIBREGEX2,LIBFORMAT2,REG_EXTENDED);

    binfile_tab = g_hash_table_new_full(g_str_hash,g_str_equal,
					NULL,NULL);

    init_done = 1;
}

void binfile_fini(void) {
    GHashTableIter iter;
    struct binfile *binfile;

    if (!init_done)
	return;

    while (g_hash_table_size(binfile_tab)) {
	g_hash_table_iter_init(&iter,binfile_tab);
	while (g_hash_table_iter_next(&iter,NULL,(gpointer)&binfile)) {
	    binfile_free(binfile,1);
	    break;
	}
    }
    g_hash_table_destroy(binfile_tab);
    binfile_tab = NULL;

    regfree(&LIBREGEX1);
    regfree(&LIBREGEX2);

    init_done = 0;
}

struct binfile *binfile_create(char *filename,struct binfile_ops *bfops,
			       void *priv) {
    struct binfile *binfile;

    binfile = (struct binfile *)calloc(1,sizeof(*binfile));
    binfile->fd = -1;
    binfile->type = BINFILE_TYPE_NONE;
    binfile->ops = bfops;
    binfile->priv = priv;

    /*
     * Try to resolve the realpath, and extract some infor from the
     * filename.  Use the real path as @binfile->filename if it is
     * different than @filename.
     */
    if (_filename_info(filename,&binfile->filename,
		       &binfile->name,&binfile->version)) {
	free(binfile);
	return NULL;
    }
    else if (binfile->filename == filename)
	binfile->filename = strdup(filename);

    binfile->symtab = symtab_create(binfile,NULL,0,"symtab",NULL,0);
    binfile->ranges = clrange_create();

    return binfile;
}

struct binfile *binfile_lookup(char *filename) {
    char *realname = filename;
    struct binfile *retval = NULL;
    
    if (_filename_info(filename,&realname,NULL,NULL)) {
	/*
	 * Just fail silently for now; the binfile_create will fail too!
	 */
	return NULL;
    }

    retval = (struct binfile *)g_hash_table_lookup(binfile_tab,realname);
    if (realname != filename)
	free(realname);

    return retval;
}

int binfile_cache(struct binfile *binfile) {
    if (g_hash_table_lookup(binfile_tab,binfile->filename)) {
	vwarn("binfile %s already cached; not caching!\n",binfile->filename);
	return -1;
    }
    g_hash_table_insert(binfile_tab,(gpointer)binfile->filename,(gpointer)binfile);
    return 0;
}

int binfile_uncache(struct binfile *binfile) {
    if (g_hash_table_lookup(binfile_tab,binfile->filename) != binfile)
	return 0;
    g_hash_table_remove(binfile_tab,(gpointer)binfile->filename);

    return 0;
}

int binfile_cache_clean(void) {
    GHashTableIter iter;
    struct binfile *binfile;
    int retval = 0;

    /*
     * One binfile_free may invoke another, so loop this way so we don't
     * mess up the iterator.  Ugh.
     */
    while (g_hash_table_size(binfile_tab)) {
	g_hash_table_iter_init(&iter,binfile_tab);
	while (g_hash_table_iter_next(&iter,NULL,(gpointer)&binfile)) {
	    if (binfile->refcnt <= 0) {
		++retval;
		binfile_free(binfile,0);
	    }
	}
    }

    return retval;
}

struct binfile_instance *binfile_infer_instance(char *filename,ADDR base) {
    struct binfile *bf;
    struct binfile_instance *bfi;

    /*
     * We cache a shareable version of the binfile, and then create the
     * private, per-instance copy with the next call.
     */
    if (!(bf = binfile_open(filename,NULL))) {
	verror("could not build instance from %s!\n",filename);
	return NULL;
    }

    if (!(bfi = bf->ops->infer_instance(bf,base))) {
	verror("could not build instance from binfile %s!\n",bf->filename);
	return NULL;
    }

    return bfi;
}

struct binfile *binfile_open(char *filename,struct binfile_instance *bfinst) {
    struct binfile *retval = NULL;
    struct binfile_ops **ops;

    if (bfinst) {
	vdebug(2,LA_DEBUG,LF_BFILE,
	       "using %s backend (from instance) for file %s\n",
	       bfinst->ops->get_backend_name(),filename);
	return bfinst->ops->open(filename,bfinst);
    }
    else if ((retval = binfile_lookup(filename))) {
	RHOLD(retval);
	return retval;
    }

    ops = &binfile_types[0];
    while (*ops) {
	vdebug(2,LA_DEBUG,LF_BFILE,"trying %s backend for file %s\n",
	       (*ops)->get_backend_name(),filename);
	retval = (*ops)->open(filename,bfinst);
	if (retval) {
	    if (!retval->instance) {
		binfile_cache(retval);
		RHOLD(retval);
	    }
	    return retval;
	}
	++ops;
    }

    return NULL;
}

struct binfile *binfile_open_debuginfo(struct binfile *binfile,
				       struct binfile_instance *bfinst,
				       const char *DFPATH[]) {
    if (binfile->ops->open_debuginfo)
	return binfile->ops->open_debuginfo(binfile,bfinst,DFPATH);
    return NULL;
}

const char *binfile_get_backend_name(struct binfile *binfile) {
    return binfile->ops->get_backend_name();
}

binfile_type_t binfile_get_binfile_type(struct binfile *binfile) {
    return binfile->type;
}

int binfile_close(struct binfile *binfile) {
    int retval;

    if (binfile->fd < 0 && !binfile->image) {
	errno = EINVAL;
	return -1;
    }

    retval = binfile->ops->close(binfile);

    return retval;
}

REFCNT binfile_free(struct binfile *binfile,int force) {
    REFCNT retval = binfile->refcnt;

    if (retval) {
	if (!force) {
	    verror("cannot free (%d refs) binfile(%s)\n",
		   retval,binfile->filename);
	    return retval;
	}
	else {
	    vwarn("forced free (%d refs) binfile(%s)\n",
		  retval,binfile->filename);
	}
    }

    vdebug(5,LA_DEBUG,LF_BFILE,"freeing binfile(%s)\n",binfile->filename);

    /*
     * Only remove it if the value matches us.  This is necessary
     * because if we loaded binfile against an instance, and there were
     * relocations, this binfile will not be in the hashtable -- but
     * another binfile (that was NOT relocated!) could still be in the
     * hashtable.  :)
     */
    if (g_hash_table_lookup(binfile_tab,binfile->filename) == binfile)
	g_hash_table_remove(binfile_tab,binfile->filename);

    if (binfile->fd > -1 || binfile->image) 
	binfile_close(binfile);

    binfile->ops->free(binfile);

    if (binfile->ranges) {
	clrange_free(binfile->ranges);
	binfile->ranges = NULL;
    }
    if (binfile->symtab) {
	symtab_free(binfile->symtab);
	binfile->symtab = NULL;
    }
    if (binfile->strtab) {
	free(binfile->strtab);
	binfile->strtab = NULL;
	binfile->strtablen = 0;
    }
    if (binfile->name) {
	free(binfile->name);
	binfile->name = NULL;
    }
    if (binfile->version) {
	free(binfile->version);
	binfile->version = NULL;
    }
    if (binfile->filename) {
	free(binfile->filename);
	binfile->filename = NULL;
    }

    free(binfile);

    return retval;
}

static int _filename_info(char *filename,
			  char **realfilename,char **name,char **version) {
    regmatch_t matches[2];
    int match_len;
    char *realname;
    struct stat sbuf;

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

    if (!name && !version) 
	return 0;

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

    return 0;
}
