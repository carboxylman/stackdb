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

#include "target_api.h"
#include "target.h"

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/**
 ** The generic target API!
 **/

int target_open(struct target *target) {
    int rc;
    struct addrspace *space;
    struct memregion *region;

    vdebug(5,LOG_T_TARGET,"opening target type %s\n",target->type);

    vdebug(6,LOG_T_TARGET,"target type %s: init\n",target->type);
    if ((rc = target->ops->init(target))) {
	return rc;
    }

    vdebug(6,LOG_T_TARGET,"target type %s: loadspaces\n",target->type);
    if ((rc = target->ops->loadspaces(target))) {
	return rc;
    }

    list_for_each_entry(space,&target->spaces,space) {
	vdebug(6,LOG_T_TARGET,"target type %s: loadregions\n",target->type);
	if ((rc = target->ops->loadregions(target,space))) {
	    return rc;
	}
    }

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if (region->type != REGION_TYPE_MAIN)
		continue;

	    vdebug(6,LOG_T_TARGET,
		   "loaddebugfiles target(%s:%s):region(%s:%s)\n",
		   target->type,space->idstr,
		   region->name,REGION_TYPE(region->type));
	    if ((rc = target->ops->loaddebugfiles(target,space,region))) {
		vwarn("could not open debuginfo for region %s (%d)\n",
		      region->name,rc);
	    }
	}
    }

    vdebug(6,LOG_T_TARGET,"attach target(%s)\n",target->type);
    if ((rc = target->ops->attach(target))) {
	return rc;
    }

    return 0;
}
    
target_status_t target_monitor(struct target *target) {
    vdebug(5,LOG_T_TARGET,"monitoring target(%s)\n",target->type);
    return target->ops->monitor(target);
}
    
int target_resume(struct target *target) {
    vdebug(5,LOG_T_TARGET,"resuming target(%s)\n",target->type);
    return target->ops->resume(target);
}

unsigned char *target_read_addr(struct target *target,
				unsigned long long addr,
				unsigned long length,
				unsigned char *buf) {
    vdebug(5,LOG_T_TARGET,"reading target(%s) at %16llx into %p (%d)\n",
	   target->type,addr,buf,length);
    return target->ops->read(target,addr,length,buf);
}

int target_write_addr(struct target *target,unsigned long long addr,
		      unsigned long length,unsigned char *buf) {
    vdebug(5,LOG_T_TARGET,"writing target(%s) at %16llx (%d)\n",
	   target->type,addr,length);
    return target->ops->write(target,addr,length,buf);
}

struct value *target_read(struct target *target,struct symbol *symbol) {
    

    return 0;
}

int target_write(struct target *target,struct symbol *symbol,
		 struct value *value) {
    

    return 0;
}

char *target_reg_name(struct target *target,REG reg) {
    vdebug(5,LOG_T_TARGET,"target(%s) reg name %d)\n",target->type,reg);
    return target->ops->regname(target,reg);
}

REGVAL target_read_reg(struct target *target,REG reg) {
    vdebug(5,LOG_T_TARGET,"reading target(%s) reg %d)\n",target->type,reg);
    return target->ops->readreg(target,reg);
}

int target_write_reg(struct target *target,REG reg,REGVAL value) {
    vdebug(5,LOG_T_TARGET,"writing target(%s) reg %d %" PRIx64 ")\n",
	   target->type,reg);
    return target->ops->writereg(target,reg,value);
}

int target_close(struct target *target) {
    int rc;

    vdebug(5,LOG_T_TARGET,"closing target(%s)\n",target->type);

    vdebug(6,LOG_T_TARGET,"detach target(%s)\n",target->type);
    if ((rc = target->ops->detach(target))) {
	return rc;
    }

    vdebug(6,LOG_T_TARGET,"fini target(%s)\n",target->type);
    if ((rc = target->ops->fini(target))) {
	return rc;
    }

    return 0;
}

void target_free(struct target *target) {
    g_hash_table_destroy(target->mmaps);
    free(target);
}

void ghash_mmap_entry_free(gpointer data) {
    struct mmap_entry *mme = (struct mmap_entry *)data;

    free(mme);
}

struct target *target_create(char *type,void *state,struct target_ops *ops) {
    struct target *retval = malloc(sizeof(struct target));
    memset(retval,0,sizeof(struct target));

    retval->type = type;
    retval->state = state;
    retval->ops = ops;

    INIT_LIST_HEAD(&retval->spaces);

    retval->mmaps = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					  /* No names to free! */
					  NULL,ghash_mmap_entry_free);

    return retval;
}

struct mmap_entry *target_lookup_mmap_entry(struct target *target,
					    ADDR base_addr) {
    /* XXX: fill later. */
    return NULL;
}

void target_attach_mmap_entry(struct target *target,
			      struct mmap_entry *mme) {
    /* XXX: fill later. */
    return;
}

void target_release_mmap_entry(struct target *target,
			       struct mmap_entry *mme) {
    /* XXX: fill later. */
    return;
}
