/*
 * Copyright (c) 2011, 2012, 2013, 2014 The University of Utah
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

#include "common.h"
#include "glib_wrapper.h"
#include "target.h"
#include "binfile.h"
#include <assert.h>

/*
 * Address spaces.
 */
/*
 * Creates an address space.
 *
 * You must supply some sort of unique combo of name:id -- these
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
				   char *name,ADDR tag) {
    struct addrspace *retval;

    assert(name);

    retval = (struct addrspace *)malloc(sizeof(struct addrspace));
    if (!retval) {
	errno = ENOMEM;
	return NULL;
    }

    memset(retval,0,sizeof(*retval));

    retval->name = strdup(name);
    retval->tag = tag;

    if (target) {
	target_attach_space(target,retval);
	retval->target = target;
	RHOLDW(target,retval);
    }

    vdebug(5,LA_TARGET,LF_SPACE,"built addrspace(%s:0x%"PRIxADDR")\n",name,tag);

    return retval;
}

struct memregion *addrspace_find_region(struct addrspace *space,char *name) {
    GList *tmp;
    struct memregion *region;

    tmp = NULL;
    v_g_list_foreach(space->regions,tmp,region) {
	if (region->name && strcmp(name,region->name) == 0)
	    goto out;
    }
    return NULL;
 out:
    return region;
}

int addrspace_attach_region(struct addrspace *space,struct memregion *region) {
    RHOLD(region,space);
    space->regions = g_list_append(space->regions,region);
    return 0;
}

int addrspace_detach_region(struct addrspace *space,struct memregion *region) {
    GList *t1;
    REFCNT trefcnt;

    if (region->space != space) {
	errno = EINVAL;
	return -1;
    }

    t1 = g_list_find(space->regions,region);
    if (!t1) {
	errno = ESRCH;
	return -1;
    }

    space->regions = g_list_remove_link(space->regions,t1);

    RPUT(region,memregion,space,trefcnt);

    return 0;
}

struct memregion *addrspace_match_region_name(struct addrspace *space,
					      region_type_t rtype,char *name) {
    GList *tmp;
    struct memregion *region;

    tmp = NULL;
    v_g_list_foreach(space->regions,tmp,region) {
	if (region->type == rtype && strcmp(name,region->name) == 0)
	    goto out;
    }
    return NULL;
 out:
    return region;
}

struct memregion *addrspace_match_region_start(struct addrspace *space,
					       region_type_t rtype,ADDR start) {
    GList *tmp;
    struct memregion *region;

    tmp = NULL;
    v_g_list_foreach(space->regions,tmp,region) {
	if (region->type == rtype && region->base_load_addr == start)
	    goto out;
    }
    return NULL;
 out:
    return region;
}

int addrspace_find_range_real(struct addrspace *space,ADDR addr,
			      struct memregion **region_saveptr,
			      struct memrange **range_saveptr) {
    GList *tmp;
    struct memregion *region;
    struct memrange *range;

    v_g_list_foreach(space->regions,tmp,region) {
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

void addrspace_obj_flags_propagate(struct addrspace *space,
				   obj_flags_t orf,obj_flags_t nandf) {
    struct memregion *region;
    GList *t1;

    /* Ranges have no children, so stop here. */
    v_g_list_foreach(space->regions,t1,region) {
	region->obj_flags |= orf;
	region->obj_flags &= ~nandf;
	memregion_obj_flags_propagate(region,orf,nandf);
    }
}

REFCNT addrspace_free(struct addrspace *space,int force) {
    GList *t1,*t2;
    struct memregion *lpc;
    REFCNT retval = space->refcnt;
    REFCNT trefcnt;

    assert(space);

    if (space->refcnt) {
	if (!force) {
	    verror("cannot free (%d refs) space(%s:0x%"PRIxADDR")\n",
		   space->refcnt,space->name,space->tag);
	    return space->refcnt;
	}
	else {
	    vwarn("forced free (%d refs) space(%s:0x%"PRIxADDR")\n",
		  space->refcnt,space->name,space->tag);
	}
    }

    /* NB: take a temp ref so that any RPUTWs don't double-call; see common.h */
    RWGUARD(space);

    vdebug(5,LA_TARGET,LF_SPACE,
	   "freeing space(%s:0x%"PRIxADDR")\n",space->name,space->tag);

    v_g_list_foreach_safe(space->regions,t1,t2,lpc) {
	RPUT(lpc,memregion,space,trefcnt);
	if (trefcnt == 0) {
	    v_g_list_foreach_remove(space->regions,t1,t2);
	}
    }

    if (space->refcntw) {
	if (!force) {
	    verror("cannot free (%d wrefs) space(%s:0x%"PRIxADDR")\n",
		   space->refcntw,space->name,space->tag);
	    return space->refcntw;
	}
	else {
	    vwarn("forced free (%d wrefs) space(%s:0x%"PRIxADDR")\n",
		  space->refcntw,space->name,space->tag);

	    v_g_list_foreach_safe(space->regions,t1,t2,lpc) {
		lpc->space = NULL;
	    }
	}

	if (retval <= 0)
	    retval = space->refcntw;
    }

    if (space->target) {
	RPUTW(space->target,target,space,trefcnt);
    }

    g_list_free(space->regions);
    space->regions = NULL;
    free(space->name);
    free(space);

    return retval;
}

/*
 * Memory regions and ranges.
 */
struct memregion *memregion_create(struct addrspace *space,
				   region_type_t type,char *name) {
    struct memregion *retval;

    retval = (struct memregion *)calloc(1,sizeof(*retval));
    if (!retval) 
	return NULL;

    memset(retval,0,sizeof(*retval));

    if (name) 
	retval->name = strdup(name);
    retval->type = type;

    retval->debugfiles = g_hash_table_new(g_str_hash,g_str_equal);

    if (!retval->debugfiles) {
	if (retval->name)
	    free(retval->name);
	free(retval);
	return NULL;
    }

    if (space) {
	addrspace_attach_region(space,retval);
	retval->space = space;
	RHOLDW(space,retval);
    }

    /* Set this to ADDRMAX so when we add ranges, we can find the lowest
     * range start addr.
     */
    retval->base_load_addr = ADDRMAX;
    /* Set these to 0; default case; when we load debugfiles for
     * regions, we can update them.
     */
    retval->base_phys_addr = 0;
    retval->base_virt_addr = 0;

    vdebug(5,LA_TARGET,LF_REGION,"built memregion(%s:0x%"PRIxADDR":%s:%s)\n",
	   space->name,space->tag,retval->name,REGION_TYPE(retval->type));

    return retval;
}

int memregion_attach_range(struct memregion *region,struct memrange *range) {
    RHOLD(range,region);
    region->ranges = g_list_append(region->ranges,range);
    return 0;
}

int memregion_detach_range(struct memregion *region,struct memrange *range) {
    GList *t1;
    REFCNT trefcnt;

    if (range->region != region) {
	errno = EINVAL;
	return -1;
    }

    t1 = g_list_find(region->ranges,range);
    if (!t1) {
	errno = ESRCH;
	return -1;
    }

    region->ranges = g_list_remove_link(region->ranges,t1);

    RPUT(range,memrange,region,trefcnt);

    return 0;
}

struct memrange *memregion_match_range(struct memregion *region,ADDR start) {
    GList *t1;
    struct memrange *range;

    v_g_list_foreach(region->ranges,t1,range) {
	if (range->start == start)
	    return range;
    }

    return NULL;
}

int memregion_contains_real(struct memregion *region,ADDR addr) {
    GList *t1;
    struct memrange *range;

    v_g_list_foreach(region->ranges,t1,range) {
	if (memrange_contains_real(range,addr))
	    return 1;
    }

    return 0;
}

struct memrange *memregion_find_range_real(struct memregion *region,
					   ADDR real_addr) {
    GList *t1;
    struct memrange *range;

    v_g_list_foreach(region->ranges,t1,range) {
	if (memrange_contains_real(range,real_addr)) {
	    vdebug(9,LA_TARGET,LF_REGION,"lookup real(0x%"PRIxADDR") found memrange"
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
    GList *t1;
    struct memrange *range;

    v_g_list_foreach(region->ranges,t1,range) {
	if (memrange_contains_obj(range,obj_addr)) {
	    vdebug(9,LA_TARGET,LF_REGION,"lookup obj(0x%"PRIxADDR") found memrange"
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
    GList *t1;
    struct memrange *range;

    v_g_list_foreach(region->ranges,t1,range) {
	if (memrange_contains_obj(range,obj_addr)) {
	    vdebug(9,LA_TARGET,LF_REGION,"relocate obj(0x%"PRIxADDR") found memrange"
		   " (%s:%s:0x%"PRIxADDR",0x%"PRIxADDR",%"PRIiOFFSET",%u)\n",
		   obj_addr,range->region->name,REGION_TYPE(range->region->type),
		   range->start,range->end,range->offset,range->prot_flags);
	    if (range_saveptr)
		*range_saveptr = range;
	    return memrange_relocate(range,obj_addr);
	}
	else {
	    vdebug(9,LA_TARGET,LF_REGION,"obj(0x%"PRIxADDR") not found in memrange"
		   " (%s:%s:0x%"PRIxADDR",0x%"PRIxADDR",%"PRIiOFFSET",%u)\n",
		   obj_addr,range->region->name,REGION_TYPE(range->region->type),
		   range->start,range->end,range->offset,range->prot_flags);
	}
    }

    errno = ESRCH;
    return 0;
}

ADDR memregion_unrelocate(struct memregion *region,ADDR real_addr,
			  struct memrange **range_saveptr) {
    GList *t1;
    struct memrange *range;

    v_g_list_foreach(region->ranges,t1,range) {
	if (memrange_contains_real(range,real_addr)) {
	    vdebug(9,LA_TARGET,LF_REGION,"unrelocate real(0x%"PRIxADDR") found memrange"
		   " (%s:%s:0x%"PRIxADDR",0x%"PRIxADDR",%"PRIiOFFSET",%u)\n",
		   real_addr,range->region->name,REGION_TYPE(range->region->type),
		   range->start,range->end,range->offset,range->prot_flags);
	    if (range_saveptr)
		*range_saveptr = range;
	    return memrange_unrelocate(range,real_addr);
	}
	else {
	    vdebug(9,LA_TARGET,LF_REGION,"real(0x%"PRIxADDR") not found in memrange"
		   " (%s:%s:0x%"PRIxADDR",0x%"PRIxADDR",%"PRIiOFFSET",%u)\n",
		   real_addr,range->region->name,REGION_TYPE(range->region->type),
		   range->start,range->end,range->offset,range->prot_flags);
	}
    }
    errno = ESRCH;
    return 0;
}

void memregion_dump(struct memregion *region,struct dump_info *ud) {
    fprintf(ud->stream,"%sregion(%s:%s)",
	    ud->prefix,REGION_TYPE(region->type),region->name);
}

void memregion_obj_flags_propagate(struct memregion *region,
				   obj_flags_t orf,obj_flags_t nandf) {
    struct memrange *range;
    GList *t1;

    /* Ranges have no children, so stop here. */
    v_g_list_foreach(region->ranges,t1,range) {
	range->obj_flags |= orf;
	range->obj_flags &= ~nandf;
    }
}

REFCNT memregion_free(struct memregion *region,int force) {
    struct memrange *range;
    GHashTableIter iter;
    gpointer key;
    struct debugfile *debugfile;
    REFCNT trefcnt;
    REFCNT retval = region->refcnt;
    GList *t1,*t2;

    assert(region);

    if (region->refcnt) {
	if (!force) {
	    verror("cannot free (%d refs) memregion(%s:0x%"PRIxADDR":%s:%s)\n",
		   region->refcnt,region->space->name,region->space->tag,
		   region->name,REGION_TYPE(region->type));
	    return region->refcnt;
	}
	else {
	    vwarn("forced free (%d refs) memregion(%s:0x%"PRIxADDR":%s:%s)\n",
		  region->refcnt,region->space->name,region->space->tag,
		  region->name,REGION_TYPE(region->type));
	}
    }

    /* NB: take a temp ref so that any RPUTWs don't double-call; see common.h */
    RWGUARD(region);

    vdebug(5,LA_TARGET,LF_REGION,"freeing memregion(%s:0x%"PRIxADDR":%s:%s)\n",
	   region->space->name,region->space->tag,
	   region->name,REGION_TYPE(region->type));

    v_g_list_foreach_safe(region->ranges,t1,t2,range) {
	RPUT(range,memrange,region,trefcnt);
	if (trefcnt == 0) {
	    v_g_list_foreach_remove(region->ranges,t1,t2);
	}
    }

    if (region->refcntw) {
	if (!force) {
	    verror("cannot free (%d wrefs) memregion(%s:0x%"PRIxADDR":%s:%s)\n",
		   region->refcntw,region->space->name,region->space->tag,
		   region->name,REGION_TYPE(region->type));
	    return region->refcntw;
	}
	else {
	    vwarn("forced free (%d wrefs) memregion(%s:0x%"PRIxADDR":%s:%s)\n",
		  region->refcntw,region->space->name,region->space->tag,
		  region->name,REGION_TYPE(region->type));

	    v_g_list_foreach_safe(region->ranges,t1,t2,range) {
		range->region = NULL;
	    }
	}

	if (retval <= 0)
	    retval = region->refcntw;
    }

    if (region->binfile) {
	RPUT(region->binfile,binfile,region,trefcnt);
	region->binfile = NULL;
    }

    if (region->debugfiles) {
	g_hash_table_iter_init(&iter,region->debugfiles);
	while (g_hash_table_iter_next(&iter,
				      (gpointer)&key,(gpointer)&debugfile)) {
	    RPUT(debugfile,debugfile,region,trefcnt);
	    /* This is probably a violation of the hashtable usage
	     * principles, but oh well!
	     */
	    //free(key);
	}
	g_hash_table_destroy(region->debugfiles);
	region->debugfiles = NULL;
    }

    if (region->space) {
	RPUTW(region->space,addrspace,region,trefcnt);
	region->space = NULL;
    }

    if (region->name) {
	free(region->name);
	region->name = NULL;
    }
    free(region);

    return retval;
}

struct memrange *memrange_create(struct memregion *region,
				 ADDR start,ADDR end,OFFSET offset,
				 unsigned int prot_flags) {
    struct memrange *retval;

    retval = (struct memrange *)malloc(sizeof(*retval));
    if (!retval) 
	return NULL;

    memset(retval,0,sizeof(*retval));

    retval->start = start;
    retval->end = end;
    retval->offset = offset;
    retval->prot_flags = prot_flags;

    if (start < region->base_load_addr)
	region->base_load_addr = start;

    if (region) {
	memregion_attach_range(region,retval);
	RHOLDW(region,retval);
	retval->region = region;
    }

    vdebug(5,LA_TARGET,LF_REGION,
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
    return memrange_contains_real(range,obj_addr + range->region->phys_offset);
}

void memrange_dump(struct memrange *range,struct dump_info *ud) {
    fprintf(ud->stream,
	    "%srange(%s:%s:0x%"PRIxADDR",0x%"PRIxADDR",%"PRIiOFFSET")",
	    ud->prefix,REGION_TYPE(range->region->type),range->region->name,
	    range->start,range->end,range->offset);
}

ADDR memrange_unrelocate(struct memrange *range,ADDR real) {
    return real - range->region->phys_offset;
}

ADDR memrange_relocate(struct memrange *range,ADDR obj) {
    return obj + range->region->phys_offset;
}

void memrange_obj_flags_propagate(struct memrange *range,
				  obj_flags_t orf,obj_flags_t nandf) {
    /* We have no children. */
    return;
}

REFCNT memrange_free(struct memrange *range,int force) {
    REFCNT retval = range->refcnt;
    REFCNT trefcnt;

    assert(range);

    if (range->refcnt) {
	if (!force) {
	    verror("cannot free (%d refs) memrange(%s:%s:0x%"PRIxADDR","
		   "0x%"PRIxADDR",%"PRIiOFFSET",%u)\n",
		   range->refcnt,range->region->name,
		   REGION_TYPE(range->region->type),range->start,range->end,
		   range->offset,range->prot_flags);
	    return range->refcnt;
	}
	else {
	    vwarn("forced free (%d refs) memrange(%s:%s:0x%"PRIxADDR","
		  "0x%"PRIxADDR",%"PRIiOFFSET",%u)\n",
		  range->refcnt,range->region->name,
		  REGION_TYPE(range->region->type),range->start,range->end,
		  range->offset,range->prot_flags);
	}
    }

    /* NB: take a temp ref so that any RPUTWs don't double-call; see common.h */
    RWGUARD(range);

    vdebug(5,LA_TARGET,LF_REGION,
	   "freeing memrange(%s:%s:0x%"PRIxADDR",0x%"PRIxADDR",%"PRIiOFFSET",%u)\n",
	   range->region->name,REGION_TYPE(range->region->type),
	   range->start,range->end,range->offset,range->prot_flags);

    if (range->region) {
	RPUTW(range->region,memregion,range,trefcnt);
    }

    retval = range->refcnt;

    free(range);

    return retval;
}
