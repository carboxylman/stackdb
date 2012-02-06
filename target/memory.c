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

struct memregion *addrspace_find_region(struct addrspace *space,char *name) {
    struct memregion *region;

    list_for_each_entry(region,&space->regions,region) {
	if (strcmp(name,region->name) == 0)
	    goto out;
    }
    return NULL;
 out:
    return region;
}

int addrspace_find_range_real(struct addrspace *space,ADDR addr,
			      struct memregion **region_saveptr,
			      struct memrange **range_saveptr) {
    struct memregion *region;
    struct memrange *range;

    list_for_each_entry(region,&space->regions,region) {
	if ((range = memregion_find_range_real(region,addr))) {
	    if (region_saveptr)
		*region_saveptr = region;
	    if (range_saveptr)
		*range_saveptr = range;
	    goto out;
	}
    }
    return 0;
 out:
    return 1;
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
 * Memory regions and ranges.
 */
struct memregion *memregion_create(struct addrspace *space,
				   region_type_t type,char *name) {
    struct memregion *retval;

    retval = (struct memregion *)malloc(sizeof(*retval));
    if (!retval) 
	return NULL;

    memset(retval,0,sizeof(*retval));

    retval->space = space;

    if (name) 
	retval->name = strdup(name);
    retval->type = type;

    retval->debugfiles = g_hash_table_new_full(g_str_hash,g_str_equal,
					       ghash_str_free,
					       ghash_debugfile_free);
    if (!retval->debugfiles) {
	if (retval->name)
	    free(retval->name);
	free(retval);
	return NULL;
    }

    list_add_tail(&retval->region,&space->regions);

    INIT_LIST_HEAD(&retval->ranges);

    vdebug(5,LOG_T_REGION,"built memregion(%s:%s:%s)\n",
	   space->idstr,retval->name,REGION_TYPE(retval->type));

    return retval;
}

struct target *memregion_target(struct memregion *region) {
    return (region->space) ? region->space->target : NULL;
}

int memregion_contains_real(struct memregion *region,ADDR addr) {
    struct memrange *range;
    list_for_each_entry(range,&region->ranges,range) {
	if (memrange_contains_real(range,addr))
	    return 1;
    }
    return 0;
}

struct memrange *memregion_find_range_real(struct memregion *region,
					   ADDR real_addr) {
    struct memrange *range;
    list_for_each_entry(range,&region->ranges,range) {
	if (memrange_contains_real(range,real_addr)) {
	    vdebug(3,LOG_T_REGION,"lookup real(0x%"PRIxADDR") found memrange"
		   " (%s:%s:0x%"PRIxADDR",0x%"PRIxADDR",%"PRIiOFFSET",%u)\n",
		   real_addr,range->region->name,REGION_TYPE(range->region->type),
		   range->start,range->end,range->offset,range->prot_flags);
	    return range;
	}
    }
    return NULL;
}

struct memrange *memregion_find_range_obj(struct memregion *region,
					  ADDR obj_addr) {
    struct memrange *range;
    list_for_each_entry(range,&region->ranges,range) {
	if (memrange_contains_obj(range,obj_addr)) {
	    vdebug(3,LOG_T_REGION,"lookup obj(0x%"PRIxADDR") found memrange"
		   " (%s:%s:0x%"PRIxADDR",0x%"PRIxADDR",%"PRIiOFFSET",%u)\n",
		   obj_addr,range->region->name,REGION_TYPE(range->region->type),
		   range->start,range->end,range->offset,range->prot_flags);
	    return range;
	}
    }
    return NULL;
}

ADDR memregion_relocate(struct memregion *region,ADDR obj_addr,
			struct memrange **range_saveptr) {
    struct memrange *range;
    list_for_each_entry(range,&region->ranges,range) {
	if (memrange_contains_obj(range,obj_addr)) {
	    vdebug(3,LOG_T_REGION,"relocate obj(0x%"PRIxADDR") found memrange"
		   " (%s:%s:0x%"PRIxADDR",0x%"PRIxADDR",%"PRIiOFFSET",%u)\n",
		   obj_addr,range->region->name,REGION_TYPE(range->region->type),
		   range->start,range->end,range->offset,range->prot_flags);
	    if (range_saveptr)
		*range_saveptr = range;
	    return memrange_relocate(range,obj_addr);
	}
    }
    errno = ESRCH;
    return 0;
}

void memregion_dump(struct memregion *region,struct dump_info *ud) {
    fprintf(ud->stream,"%sregion(%s:%s)",
	    ud->prefix,REGION_TYPE(region->type),region->name);
}

void memregion_free(struct memregion *region) {
    struct memrange *range;
    struct memrange *tmp;

    vdebug(5,LOG_T_REGION,"freeing memregion(%s:%s:%s)\n",
	   region->space->idstr,
	   region->name,REGION_TYPE(region->type));

    list_for_each_entry_safe(range,tmp,&region->ranges,range) {
	memrange_free(range);
    }

    list_del(&region->region);

    if (region->debugfiles) {
	/* NOTE: the ghash_debugfile_free value destructor handles
	   destroying the debugfile if its refcnt is 0 and it is not an
	   infinite debugfile. */
	g_hash_table_remove_all(region->debugfiles);
    }
    if (region->name)
	free(region->name);
    free(region);
}

struct memrange *memrange_create(struct memregion *region,
				 ADDR start,ADDR end,OFFSET offset,
				 unsigned int prot_flags) {
    struct memrange *retval;

    retval = (struct memrange *)malloc(sizeof(*retval));
    if (!retval) 
	return NULL;

    memset(retval,0,sizeof(*retval));

    retval->region = region;
    retval->start = start;
    retval->end = end;
    retval->offset = offset;
    retval->prot_flags = prot_flags;

    list_add_tail(&retval->range,&region->ranges);

    vdebug(5,LOG_T_REGION,
	   "built memregion(%s:%s:0x%"PRIxADDR",0x%"PRIxADDR",%"PRIiOFFSET",%u)\n",
	   region->name,REGION_TYPE(region->type),start,end,offset,prot_flags);

    return retval;
}

struct memregion *memrange_region(struct memrange *range) {
    return range->region;
}

struct addrspace *memrange_space(struct memrange *range) {
    return (range->region) ? range->region->space : NULL;
}

struct target *memrange_target(struct memrange *range) {
    return (range->region 
	    && range->region->space) ? range->region->space->target : NULL;
}

int memrange_contains_real(struct memrange *range,ADDR real_addr) {
    return (range->start <= real_addr && real_addr < range->end ? 1 : 0);
}

int memrange_contains_obj(struct memrange *range,ADDR obj_addr) {
    if (range->base_obj_addr) {
	/* XXX: fill in based on relocated sections. */
	return 0;
    }
    else {
	return memrange_contains_real(range,obj_addr);
    }
}

void memrange_dump(struct memrange *range,struct dump_info *ud) {
    fprintf(ud->stream,
	    "%srange(%s:%s:0x%"PRIxADDR",0x%"PRIxADDR",%"PRIiOFFSET")",
	    ud->prefix,REGION_TYPE(range->region->type),range->region->name,
	    range->start,range->end,range->offset);
}

ADDR memrange_unrelocate(struct memrange *range,ADDR real) {
    if (range->base_obj_addr) {
	/* XXX: fill in based on relocated sections. */
	return real;
    }
    else {
	return real;
    }
}

ADDR memrange_relocate(struct memrange *range,ADDR obj) {
    if (range->base_obj_addr) {
	/* XXX: fill in based on relocated sections. */
	return obj;
    }
    else {
	return obj;
    }
}

void memrange_free(struct memrange *range) {
    vdebug(5,LOG_T_REGION,
	   "freeing memrange(%s:%s:0x%"PRIxADDR",0x%"PRIxADDR",%"PRIiOFFSET",%u)\n",
	   range->region->name,REGION_TYPE(range->region->type),
	   range->start,range->end,range->offset,range->prot_flags);

    list_del(&range->range);

    free(range);
}
