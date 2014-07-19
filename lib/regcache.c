/*
 * Copyright (c) 2014 The University of Utah
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

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include "common.h"
#include "log.h"
#include "arch.h"
#include "regcache.h"

struct regcache *regcache_create(struct arch *arch) {
    struct regcache *retval;

    retval = (struct regcache *)calloc(1,sizeof(*retval));
    retval->arch = arch;
    retval->values = (REGVAL *)calloc(arch->regcount,sizeof(REGVAL));
    retval->values_len = arch->regcount;
    retval->flags = (uint8_t *)calloc(arch->regcount,sizeof(uint8_t));
    retval->flags_len = arch->regcount;

    return retval;
}

void regcache_destroy(struct regcache *regcache) {
    int i;

    /* Free any large values. */
    for (i = 0; i < regcache->values_len; ++i) {
	// arch_regsize(regcache->arch,i) != sizeof(*regcache->values)
	if (regcache->flags[i] & REGCACHE_ALLOC) {
	    free((void *)regcache->values[i]);
	    regcache->values[i] = 0;
	    regcache->flags[i] &= ~(uint8_t)REGCACHE_ALLOC;
	}
    }

    free(regcache);
}

int regcache_copy_all(struct regcache *sregcache,struct regcache *dregcache) {
    int i;

    /* copy any set values. */
    for (i = 0; i < sregcache->values_len; ++i) {
	if (!(sregcache->flags[i] & REGCACHE_VALID))
	    continue;
	else if (sregcache->flags[i] & REGCACHE_ALLOC)
	    regcache_init_reg_len(dregcache,i,(void *)sregcache->values[i],
				  arch_regsize(sregcache->arch,i));
	else
	    regcache_init_reg(dregcache,i,sregcache->values[i]);
    }

    return 0;
}

void regcache_zero(struct regcache *regcache) {
    int i;

    /* zero out any set values; memset any large, allocated values. */
    for (i = 0; i < regcache->values_len; ++i) {
	if (!(regcache->flags[i] & REGCACHE_VALID))
	    continue;
	else if (regcache->flags[i] & REGCACHE_ALLOC)
	    memset((void *)regcache->values[i],0,arch_regsize(regcache->arch,i));
	else
	    regcache->values[i] = 0;
    }

    //regcache->valid = 0;
    //regcache->dirty = 0;
}

void regcache_mark_flushed(struct regcache *regcache) {
    int i;

    for (i = 0; i < regcache->flags_len; ++i)
	regcache->flags[i] &= ~(uint8_t)REGCACHE_DIRTY;

    regcache->dirty = 0;
}

void regcache_invalidate(struct regcache *regcache) {
    int i;

    if (regcache->dirty) {
	vwarnopt(5,LA_LIB,LF_REGCACHE,"cache still dirty!\n");
    }

    for (i = 0; i < regcache->flags_len; ++i) {
	if (regcache->flags[i] & REGCACHE_DIRTY) {
	    vwarnopt(5,LA_LIB,LF_REGCACHE,"cache reg %d still dirty!\n",i);
	}
	regcache->flags[i] = 0;
    }

    regcache->valid = 0;
    regcache->dirty = 0;
    regcache->done_loading = 0;
}

#define CHECKREG()							\
    if (!arch_has_reg(regcache->arch,reg)) {				\
	vwarnopt(LA_LIB,LF_REGCACHE,8,"reg %d not supported\n",reg);	\
	errno = EINVAL;							\
	return -1;							\
    }

int regcache_init_reg(struct regcache *regcache,REG reg,REGVAL regval) {
    CHECKREG();

    unsigned int sz = arch_regsize(regcache->arch,reg);

    if (regcache->done_loading) {
	vwarn("called on fully-loaded regcache; BUG!!!\n");
    }

    if (sz > sizeof(*regcache->values)
	&& !(regcache->flags[reg] & REGCACHE_ALLOC)) {
	regcache->values[reg] = (REGVAL)malloc(sz);
	regcache->flags[reg] |= REGCACHE_ALLOC;
    }

    if (regcache->flags[reg] & REGCACHE_ALLOC) {
	if (sizeof(regval) < sz) {
	    memset((void *)regcache->values[reg],0,sz);
	    memcpy((void *)regcache->values[reg],&regval,sizeof(regval));
	}
	else
	    memcpy((void *)regcache->values[reg],&regval,sz);
    }
    else {
	regcache->values[reg] = regval;
    }

    if (!(regcache->flags[reg] & REGCACHE_VALID))
	++regcache->valid;
    regcache->flags[reg] |= REGCACHE_VALID;

    vdebug(9,LA_LIB,LF_REGCACHE,"%"PRIiREG" = 0x%"PRIxREGVAL"\n",reg,regval);

    return 0;
}

int regcache_init_done(struct regcache *regcache) {
    if (regcache->dirty) {
	vwarn("called on dirty regcache; BUG!!!\n");
    }
    else if (!regcache->valid) {
	vwarn("called on regcache with no registers loaded\n");
    }

    regcache->done_loading = 1;

    return 0;
}

int regcache_isdirty_reg(struct regcache *regcache,REG reg) {
    CHECKREG();

    if (regcache->flags[reg] & REGCACHE_VALID
	&& regcache->flags[reg] & REGCACHE_DIRTY)
	return 1;
    else
	return 0;
}

int regcache_isdirty_reg_range(struct regcache *regcache,REG start,REG end) {
    int i;
    int retval = 0;

    if (!arch_has_reg(regcache->arch,start)) {
	verror("reg %d not supported\n",start);
	errno = EINVAL;
	return -1;
    }
    else if (!arch_has_reg(regcache->arch,end)) {
	verror("reg %d not supported\n",end);
	errno = EINVAL;
	return -1;
    }

    for (i = start; i <= end; ++i) {
	if (regcache->flags[i] & REGCACHE_VALID
	    && regcache->flags[i] & REGCACHE_DIRTY)
	    ++retval;
    }

    return retval;
}

int regcache_write_reg(struct regcache *regcache,REG reg,REGVAL regval) {
    CHECKREG();

    /* XXX: should we insist it's init'd first?  Yes. */
    if (!(regcache->flags[reg] & REGCACHE_VALID)) {
	vwarnopt(5,LA_LIB,LF_REGCACHE,
		 "reg %d not valid; cannot write unless loaded first!\n",reg);
	errno = EINVAL;
	return -1;
    }

    if (regcache->flags[reg] & REGCACHE_ALLOC) {
	unsigned int sz = arch_regsize(regcache->arch,reg);

	if (sizeof(regval) < sz) {
	    memset((void *)regcache->values[reg],0,sz);
	    memcpy((void *)regcache->values[reg],&regval,sizeof(regval));
	}
	else
	    memcpy((void *)regcache->values[reg],&regval,sz);
    }
    else {
	regcache->values[reg] = regval;
    }

    regcache->flags[reg] |= REGCACHE_DIRTY;
    ++regcache->dirty;

    return 0;
}

int regcache_read_reg(struct regcache *regcache,REG reg,REGVAL *regval) {
    CHECKREG();

    /* XXX: should we insist it's init'd first?  Yes. */
    if (!(regcache->flags[reg] & REGCACHE_VALID)) {
	vwarnopt(5,LA_LIB,LF_REGCACHE,
		 "reg %d not valid; cannot read unless loaded first!\n",reg);
	errno = EINVAL;
	return -1;
    }

    if (regcache->flags[reg] & REGCACHE_ALLOC) {
	unsigned int sz = arch_regsize(regcache->arch,reg);

	if (sizeof(*regval) > sz) {
	    memset((void *)regval,0,sizeof(*regval));
	    memcpy((void *)regval,(void *)regcache->values[reg],sz);
	}
	else
	    memcpy((void *)regval,(void *)regcache->values[reg],sizeof(regval));
    }
    else {
	*regval = regcache->values[reg];
    }

    return 0;
}

int regcache_read_reg_ifdirty(struct regcache *regcache,REG reg,REGVAL *regval) {
    CHECKREG();

    if (!(regcache->flags[reg] & REGCACHE_VALID)
	|| !(regcache->flags[reg] & REGCACHE_DIRTY))
	return 1;

    if (regcache->flags[reg] & REGCACHE_ALLOC) {
	unsigned int sz = arch_regsize(regcache->arch,reg);

	if (sizeof(*regval) > sz) {
	    memset((void *)regval,0,sizeof(*regval));
	    memcpy((void *)regval,(void *)regcache->values[reg],sz);
	}
	else
	    memcpy((void *)regval,(void *)regcache->values[reg],sizeof(regval));
    }
    else {
	*regval = regcache->values[reg];
    }

    return 0;
}

int regcache_init_reg_len(struct regcache *regcache,REG reg,
			  void *regdata,unsigned int reglen) {
    CHECKREG();

    unsigned int sz = arch_regsize(regcache->arch,reg);

    if (sz > sizeof(*regcache->values)
	&& !(regcache->flags[reg] & REGCACHE_ALLOC)) {
	regcache->values[reg] = (REGVAL)malloc(sz);
	regcache->flags[reg] |= REGCACHE_ALLOC;
    }

    if (regcache->flags[reg] & REGCACHE_ALLOC) {
	if (reglen < sz) {
	    memset((void *)regcache->values[reg],0,sz);
	    memcpy((void *)regcache->values[reg],regdata,reglen);
	}
	else
	    memcpy((void *)regcache->values[reg],regdata,sz);
    }
    else {
	if (reglen < sizeof(*regcache->values)) {
	    memset(&regcache->values[reg],0,sizeof(*regcache->values));
	    memcpy(regdata,&regcache->values[reg],reglen);
	}
	else 
	    regcache->values[reg] = *(REGVAL *)regdata;
    }

    if (!(regcache->flags[reg] & REGCACHE_VALID))
	++regcache->valid;
    regcache->flags[reg] |= REGCACHE_VALID;

    return 0;
}

int regcache_write_reg_len(struct regcache *regcache,REG reg,
			   void *regdata,unsigned int reglen) {
    CHECKREG();

    /* XXX: should we insist it's init'd first?  Yes. */
    if (regcache->flags[reg] & REGCACHE_VALID) {
	vwarnopt(5,LA_LIB,LF_REGCACHE,
		 "reg %d not valid; cannot write unless loaded first!\n",reg);
	errno = EINVAL;
	return -1;
    }

    if (regcache->flags[reg] & REGCACHE_ALLOC) {
	unsigned int sz = arch_regsize(regcache->arch,reg);

	if (reglen < sz) {
	    memset((void *)regcache->values[reg],0,sz);
	    memcpy((void *)regcache->values[reg],regdata,reglen);
	}
	else
	    memcpy((void *)regcache->values[reg],regdata,sz);
    }
    else {
	if (reglen < sizeof(*regcache->values)) {
	    memset(&regcache->values[reg],0,sizeof(*regcache->values));
	    memcpy(regdata,&regcache->values[reg],reglen);
	}
	else 
	    regcache->values[reg] = *(REGVAL *)regdata;
    }

    regcache->flags[reg] |= REGCACHE_DIRTY;
    ++regcache->dirty;

    return 0;
}

int regcache_read_reg_len(struct regcache *regcache,REG reg,
			   void **regdata,unsigned int *reglen) {
    CHECKREG();

    /* XXX: should we insist it's init'd first?  Yes. */
    if (regcache->flags[reg] & REGCACHE_VALID) {
	vwarnopt(5,LA_LIB,LF_REGCACHE,
		 "reg %d not valid; cannot read unless loaded first!\n",reg);
	errno = EINVAL;
	return -1;
    }

    if (regcache->flags[reg] & REGCACHE_ALLOC) {
	unsigned int sz = arch_regsize(regcache->arch,reg);

	*regdata = (void **)&regcache->values[reg];
	*reglen = sz;
    }
    else {
	*regdata = &regcache->values[reg];
	*reglen = sizeof(*regcache->values);
    }

    return 0;
}

GHashTable *regcache_copy_registers(struct regcache *regcache) {
    GHashTable *retval = NULL;
    int j;
    int sz;
    void *copy;

    retval = g_hash_table_new_full(g_str_hash,g_str_equal,NULL,free);

    for (j = 0; j < regcache->arch->regcount; ++j) {
	if (!(regcache->flags[j] & REGCACHE_VALID)) {
	    if (regcache->flags[j] & REGCACHE_PRINT_DEFAULTS) {
		g_hash_table_insert(retval,
				    (gpointer)arch_regname(regcache->arch,j),
				    calloc(1,sizeof(REGVAL)));
	    }
	    else {
		continue;
	    }
	}
	else {
	    sz = arch_regsize(regcache->arch,j);
	    if (sz > (int)sizeof(REGVAL)) {
		copy = malloc(sz);
		memcpy(copy,(void *)regcache->values[j],sz);
	    }
	    else {
		copy = malloc(sizeof(REGVAL));
		memcpy(copy,(void *)&regcache->values[j],sizeof(REGVAL));
	    }
	    g_hash_table_insert(retval,
				(gpointer)arch_regname(regcache->arch,j),copy);
	}
    }

    return retval;
}

int regcache_snprintf(struct regcache *regcache,char *buf,int bufsiz,
		      int detail,char *sep,char *kvsep,int flags) {
    int rc = 0;
    int i,j,k;
    int sz;
    int has_levels = 0;
    REG reg;

    if (detail < 0)
	return 0;

    for (i = 0; i < ARCH_SNPRINTF_DETAIL_LEVELS; ++i) {
	if (regcache->arch->snprintf_ordering[i])
	    ++has_levels;
    }

    if (has_levels) {
	if (bufsiz > 0)
	    buf[0] = '\0';
	for (i = 0;
	     i <= regcache->arch->max_snprintf_ordering && detail >= i;
	     ++i) {
	    for (j = 0; regcache->arch->snprintf_ordering[i][j] > -1; ++j) {
		reg = regcache->arch->snprintf_ordering[i][j];

		if (!(regcache->flags[reg] & REGCACHE_VALID)
		    && !(flags & REGCACHE_PRINT_DEFAULTS))
		    continue;

		sz = arch_regsize(regcache->arch,reg);
		if (regcache->flags[reg] & REGCACHE_ALLOC) {
		    rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				   (rc >= bufsiz) ? 0 :bufsiz - rc,
				   "%s%s%s0x",
				   sep,arch_regname(regcache->arch,reg),kvsep);
		    uint8_t *data = (uint8_t *)regcache->values[reg];
		    for (k = 0; k < sz; ++k) {
			rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				       (rc >= bufsiz) ? 0 :bufsiz - rc,
				       "%02hhx",data[k]);
		    }
		}
		else if (sz == 1) {
		    if (flags & REGCACHE_PRINT_PADDING)
			rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				       (rc >= bufsiz) ? 0 :bufsiz - rc,
				       "%s%s%s0x%02hhx",
				       sep,arch_regname(regcache->arch,reg),
				       kvsep,(uint8_t)regcache->values[reg]);
		    else
			rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				       (rc >= bufsiz) ? 0 :bufsiz - rc,
				       "%s%s%s0x%hhx",
				       sep,arch_regname(regcache->arch,reg),
				       kvsep,(uint8_t)regcache->values[reg]);
		}
		else if (sz == 2) {
		    if (flags & REGCACHE_PRINT_PADDING)
			rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				       (rc >= bufsiz) ? 0 :bufsiz - rc,
				       "%s%s%s0x%04hx",
				       sep,arch_regname(regcache->arch,reg),
				       kvsep,(uint16_t)regcache->values[reg]);
		    else
			rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				       (rc >= bufsiz) ? 0 :bufsiz - rc,
				       "%s%s%s0x%hx",
				       sep,arch_regname(regcache->arch,reg),
				       kvsep,(uint16_t)regcache->values[reg]);
		}
		else if (sz == 4) {
		    if (flags & REGCACHE_PRINT_PADDING)
			rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				       (rc >= bufsiz) ? 0 :bufsiz - rc,
				       "%s%s%s0x%08x",
				       sep,arch_regname(regcache->arch,reg),
				       kvsep,(uint32_t)regcache->values[reg]);
		    else
			rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				       (rc >= bufsiz) ? 0 :bufsiz - rc,
				       "%s%s%s0x%x",
				       sep,arch_regname(regcache->arch,reg),
				       kvsep,(uint32_t)regcache->values[reg]);
		}
		else if (sz == 8) {
		    if (flags & REGCACHE_PRINT_PADDING)
			rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				       (rc >= bufsiz) ? 0 :bufsiz - rc,
				       "%s%s%s0x%16lx",
				       sep,arch_regname(regcache->arch,reg),
				       kvsep,(uint64_t)regcache->values[reg]);
		    else
			rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				       (rc >= bufsiz) ? 0 :bufsiz - rc,
				       "%s%s%s0x%lx",
				       sep,arch_regname(regcache->arch,reg),
				       kvsep,(uint64_t)regcache->values[reg]);
		}
	    }
	}
    }
    else {
	if (bufsiz > 0)
	    buf[0] = '\0';
	/* Just print them all in arch order. */
	for (j = 0; j < regcache->arch->regcount; ++j) {
	    if (!(regcache->flags[j] & REGCACHE_VALID)
		&& !(flags & REGCACHE_PRINT_DEFAULTS))
		continue;

	    sz = arch_regsize(regcache->arch,j);
	    if (sz <= 0)
		continue;

	    if (regcache->flags[j] & REGCACHE_ALLOC) {
		rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
			       (rc >= bufsiz) ? 0 :bufsiz - rc,
			       "%s%s%s0x",
			       sep,arch_regname(regcache->arch,j),kvsep);
		uint8_t *data = (uint8_t *)regcache->values[j];
		for (k = 0; k < sz; ++k) {
		    rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				   (rc >= bufsiz) ? 0 :bufsiz - rc,
				   "%02hhx",data[k]);
		}
	    }
	    else if (sz == 1) {
		if (flags & REGCACHE_PRINT_PADDING)
		    rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				   (rc >= bufsiz) ? 0 :bufsiz - rc,
				   "%s%s%s0x%02hhx",
				   sep,arch_regname(regcache->arch,j),kvsep,
				   (uint8_t)regcache->values[j]);
		else
		    rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				   (rc >= bufsiz) ? 0 :bufsiz - rc,
				   "%s%s%s0x%hhx",
				   sep,arch_regname(regcache->arch,j),kvsep,
				   (uint8_t)regcache->values[j]);
	    }
	    else if (sz == 2) {
		if (flags & REGCACHE_PRINT_PADDING)
		    rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				   (rc >= bufsiz) ? 0 :bufsiz - rc,
				   "%s%s%s0x%04hx",
				   sep,arch_regname(regcache->arch,j),kvsep,
				   (uint16_t)regcache->values[j]);
		else
		    rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				   (rc >= bufsiz) ? 0 :bufsiz - rc,
				   "%s%s%s0x%hx",
				   sep,arch_regname(regcache->arch,j),kvsep,
				   (uint16_t)regcache->values[j]);
	    }
	    else if (sz == 4) {
		if (flags & REGCACHE_PRINT_PADDING)
		    rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				   (rc >= bufsiz) ? 0 :bufsiz - rc,
				   "%s%s%s0x%08x",
				   sep,arch_regname(regcache->arch,j),kvsep,
				   (uint32_t)regcache->values[j]);
		else
		    rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				   (rc >= bufsiz) ? 0 :bufsiz - rc,
				   "%s%s%s0x%x",
				   sep,arch_regname(regcache->arch,j),kvsep,
				   (uint32_t)regcache->values[j]);
	    }
	    else if (sz == 8) {
		if (flags & REGCACHE_PRINT_PADDING)
		    rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				   (rc >= bufsiz) ? 0 :bufsiz - rc,
				   "%s%s%s0x%16lx",
				   sep,arch_regname(regcache->arch,j),kvsep,
				   (uint64_t)regcache->values[j]);
		else
		    rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
				   (rc >= bufsiz) ? 0 :bufsiz - rc,
				   "%s%s%s0x%lx",
				   sep,arch_regname(regcache->arch,j),kvsep,
				   (uint64_t)regcache->values[j]);
	    }
	}
    }

    return rc;
}
