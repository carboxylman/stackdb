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

#ifndef __REGCACHE_H__
#define __REGCACHE_H__

/*
 * A simple register cache.  Most usable in combination with an arch
 * (and maybe arch_config) structs describing an architecture.
 */

#include "config.h"
#include "common.h"
#include <glib.h>

#define REGCACHE_DIRTY (1 << 0)
#define REGCACHE_VALID (1 << 1)
#define REGCACHE_ALLOC (1 << 2)

struct regcache {
    struct arch *arch;

    /*
     * The caller of regcache_init_reg and regcache_init_done has loaded
     * all the registers it can.  This may NOT mean that
     * @valid == arch_regcount(@arch) -- IN FACT, it is here
     * deliberately so that some targets can declare that they have
     * loaded as many registers as they ever can -- the others just
     * aren't supported by the target backend.  That's one case, anyway.
     */
    int done_loading;
    /*
     * A global valid count; increment when init_reg|init_reg_len called
     * on a non-valid reg.
     */
    int valid;
    /* A global dirty bit; has anything been written? */
    int dirty;

    /*
     * If values are larger than sizeof(void *), they point to memory
     * that is the specified size of the register in struct arch.  It
     * helps that sizeof(void *) === sizeof(REGVAL) on any host platform
     * we'll be compiled on, doh!
     *
     * This should be length arch->regcount.
     */
    REGVAL *values;
    int values_len;

    /*
     * Flags:
     */
    int flags_len;
    uint8_t *flags;
};

struct regcache *regcache_create(struct arch *arch);
void regcache_destroy(struct regcache *regcache);

int regcache_copy_all(struct regcache *sregcache,struct regcache *dregcache);
void regcache_zero(struct regcache *regcache);
void regcache_mark_flushed(struct regcache *regcache);
void regcache_invalidate(struct regcache *regcache);

int regcache_init_reg(struct regcache *regcache,REG reg,REGVAL regval);
int regcache_init_done(struct regcache *regcache);
int regcache_isdirty_reg_range(struct regcache *regcache,REG start,REG end);
int regcache_isdirty_reg(struct regcache *regcache,REG reg);
int regcache_write_reg(struct regcache *regcache,REG reg,REGVAL regval);
int regcache_read_reg(struct regcache *regcache,REG reg,REGVAL *regval);
int regcache_read_reg_ifdirty(struct regcache *regcache,REG reg,REGVAL *regval);

int regcache_init_reg_len(struct regcache *regcache,REG reg,
			  void *regdata,unsigned int reglen);
int regcache_write_reg_len(struct regcache *regcache,REG reg,
			   void *regdata,unsigned int reglen);
int regcache_read_reg_len(struct regcache *regcache,REG reg,
			   void **regdata,unsigned int *reglen);

GHashTable *regcache_copy_registers(struct regcache *regcache);

/*
 * snprintfs the current register values to a string.  It prints each
 * register as a key-value pair; only printing the valid ones unless
 * @flags includes REGCACHE_PRINT_DEFAULTS.  It tries to grab
 * register-printing info from regcache->arch; otherwise it will just
 * dump them all as hex values.
 */
#define REGCACHE_PRINT_DEFAULTS (1 << 0)
#define REGCACHE_PRINT_PADDING  (1 << 1)
//#define REGCACHE_PRINT_LEADSEP  (1 << 2)
int regcache_snprintf(struct regcache *regcache,char *buf,int bufsiz,
		      int detail,char *sep,char *kvsep,int flags);

//#define regcache_foreach_dirty(regcache,regno)	
//    for (int _i = 0; _i < (regcache)->flags_len; ++_i


#endif /* __REGCACHE_H__ */
