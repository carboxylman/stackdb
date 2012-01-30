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

#include <assert.h>

#include "target.h"

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
struct addrspace *addrspace_create(struct target *target,
				   char *name,int id,int pid) {
    struct addrspace *retval;
    struct addrspace *lpc;
    char *idstr;
    int idstrlen;

    assert(name);
    assert(pid > 0);

    /* make sure this space doesn't already exist: */
    if (target) {
	list_for_each_entry(lpc,&target->spaces,space) {
	    if (((name && strcmp(name,lpc->name) == 0)
		 || (name == NULL && lpc->name == NULL))
		&& id == lpc->id && pid == lpc->pid) {
		++(lpc->refcnt);
		return lpc;
	    }
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
    retval->refcnt = 0;

    INIT_LIST_HEAD(&retval->regions);

    vdebug(5,LOG_T_SPACE,"built addrspace(%s)\n",idstr);

    return retval;
}

void addrspace_free(struct addrspace *space) {
    struct memregion *lpc;
    struct memregion *tmp;

    assert(space);

    if (--(space->refcnt))
	return;

    vdebug(5,LOG_T_SPACE,"freeing addrspace(%s)\n",space->idstr);

    /* cleanup */
    list_del(&space->space);

    list_for_each_entry_safe(lpc,tmp,&space->regions,region) {
	memregion_free(lpc);
    }

    free(space->name);
    free(space->idstr);
    free(space);
}

static void ghash_str_free(gpointer data) {
    free((void *)data);
}

static void ghash_debugfile_free(gpointer data) {
    debugfile_free((struct debugfile *)data);
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

    vdebug(5,LOG_T_REGION,"built memregion(%s:%s:%d)\n",
	   space->idstr,retval->filename,retval->type);

    return retval;
}

struct target *memregion_target(struct memregion *region) {
    return (region->space ? region->space->target : NULL);
}

struct addrspace *memregion_space(struct memregion *region) {
    return region->space;
}

int memregion_contains(struct memregion *region,ADDR addr) {
    return (region->start <= addr && addr <= region->end ? 1 : 0);
}

void memregion_dump(struct memregion *region,struct dump_info *ud) {
    fprintf(ud->stream,"%sregion(%s:%s:0x%llx,0x%llx,%lld)",
	    ud->prefix,REGION_TYPE(region->type),region->filename,
	    region->start,region->end,region->offset);
}

ADDR memregion_unrelocate(struct memregion *region,ADDR real) {
    //return real - (region->start - region->offset);
    return real;
}

ADDR memregion_relocate(struct memregion *region,ADDR obj) {
    //return (region->start - region->offset) + obj;
    return obj;
}

void memregion_free(struct memregion *region) {
    vdebug(5,LOG_T_SPACE,"freeing memregion(%s:%s:%d)\n",region->space->idstr,
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
