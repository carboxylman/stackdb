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

#include "target.h"
#include "dwdebug_priv.h"

struct mmap_entry *location_mmap(struct target *target,
				 struct memregion *region,
				 struct location *location,
				 load_flags_t flags,char **offset,
				 struct array_list *symbol_chain,
				 struct memrange **range_saveptr) {
    struct mmap_entry *mme;

    /* XXX: fill in later. */
    return NULL;
}

/**
 ** The interface to the dwdebug library's lsymbol_resolve* and
 ** symbol_resolve* functions.
 **/

int __target_location_ops_readreg(REGVAL *regval,REG regno,void *priv) {
    struct target_location_ops_data *tlod;
    REGVAL retval;

    tlod = (struct target_location_ops_data *)priv;
    errno = 0;
    retval = target_read_reg(tlod->target,tlod->tid,regno);
    if (errno) {
	verror("could not read reg %"PRIiREG" in tid %"PRIiTID": %s!\n",
	       regno,tlod->tid,strerror(errno));
	return -1;
    }

    *regval = retval;

    return 0;
}

int __target_location_ops_readipreg(REGVAL *regval,void *priv) {
    struct target_location_ops_data *tlod;
    REGVAL retval;

    tlod = (struct target_location_ops_data *)priv;
    errno = 0;
    retval = target_read_reg(tlod->target,tlod->tid,tlod->target->ipregno);
    if (errno) {
	verror("could not read ip reg in tid %"PRIiTID": %s!\n",
	       tlod->tid,strerror(errno));
	return -1;
    }

    *regval = retval;

    return 0;
}

int __target_location_ops_readptr(ADDR *pval,ADDR real_addr,void *priv) {
    struct target_location_ops_data *tlod;
    unsigned char *rc;

    tlod = (struct target_location_ops_data *)priv;

    rc = target_read_addr(tlod->target,real_addr,
			  tlod->target->ptrsize,(unsigned char *)pval);
    if (rc != (unsigned char *)pval) {
	verror("could not read 0x%"PRIxADDR": %s!\n",
	       real_addr,strerror(errno));
	return -1;
    }

    return 0;
}

int __target_location_ops_relocate(ADDR *real_addr,ADDR obj_addr,void *priv) {
    struct target_location_ops_data *tlod;

    tlod = (struct target_location_ops_data *)priv;

    /* Relocate the obj_addr according to tlod->region */
    *real_addr = memregion_relocate(tlod->region,obj_addr,NULL);

    return 0;
}

int __target_location_ops_unrelocate(ADDR *obj_addr,ADDR real_addr,void *priv) {
    struct target_location_ops_data *tlod;

    tlod = (struct target_location_ops_data *)priv;

    /* Relocate the obj_addr according to tlod->region */
    *obj_addr = memregion_unrelocate(tlod->region,real_addr,NULL);

    return 0;
}

struct location_ops target_location_ops = {
    .readreg = __target_location_ops_readreg,
    .readipreg = __target_location_ops_readipreg,
    .readptr = __target_location_ops_readptr,
    .relocate = __target_location_ops_relocate,
    .unrelocate = __target_location_ops_unrelocate,
};
