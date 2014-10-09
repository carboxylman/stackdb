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

#include <stdio.h>
#include "common.h"
#include "arch.h"
#include "arch_x86.h"
#include "regcache.h"
#include "log.h"

int main(int argc,char **argv) {
    char *retval;
    int failures = 0;
    struct regcache *regcache;
    struct arch *arch;
    char buf[1024];

    vmi_set_log_level(20);
    vmi_set_log_area_flags(LA_LIB,LF_REGCACHE);

    arch = arch_get(ARCH_X86);
    regcache = regcache_create(arch);

    printf("initializing 1...\n");

    regcache_init_reg(regcache,REG_X86_EAX,11);
    regcache_init_reg(regcache,REG_X86_EBX,12);
    regcache_init_reg(regcache,REG_X86_ECX,13);
    regcache_init_reg(regcache,REG_X86_EDX,14);
    regcache_init_reg(regcache,REG_X86_EDI,15);
    regcache_init_reg(regcache,REG_X86_ESI,16);
    regcache_init_reg(regcache,REG_X86_EIP,1);
    regcache_init_reg(regcache,REG_X86_EBP,2);
    regcache_init_reg(regcache,REG_X86_ESP,3);
    regcache_init_reg(regcache,REG_X86_EFLAGS,0xdeadbeef);

    regcache_init_done(regcache);

    regcache_snprintf(regcache,buf,sizeof(buf),10,",","=",0);
    printf("regcache: %s\n",buf);
    regcache_snprintf(regcache,buf,sizeof(buf),10,",","=",
		      REGCACHE_PRINT_PADDING);
    printf("regcache: %s\n",buf);

    printf("zeroing 1...\n");
    regcache_zero(regcache);

    regcache_snprintf(regcache,buf,sizeof(buf),10,",","=",0);
    printf("regcache: %s\n",buf);

    printf("invalidating 1...\n");
    regcache_invalidate(regcache);

    regcache_snprintf(regcache,buf,sizeof(buf),10,",","=",0);
    printf("regcache: %s\n",buf);

    printf("initializing 2...\n");

    regcache_init_reg(regcache,REG_X86_EAX,11);
    regcache_init_reg(regcache,REG_X86_EBX,12);
    regcache_init_reg(regcache,REG_X86_ECX,13);
    regcache_init_reg(regcache,REG_X86_EDX,14);
    regcache_init_reg(regcache,REG_X86_EDI,15);
    regcache_init_reg(regcache,REG_X86_ESI,16);
    regcache_init_reg(regcache,REG_X86_EIP,1);
    regcache_init_reg(regcache,REG_X86_EBP,2);
    regcache_init_reg(regcache,REG_X86_ESP,3);
    regcache_init_reg(regcache,REG_X86_EFLAGS,0xdeadbeef);

    regcache_init_done(regcache);

    regcache_snprintf(regcache,buf,sizeof(buf),10,",","=",0);
    printf("regcache: %s\n",buf);

    printf("writing EFLAGS and EIP...\n");

    regcache_write_reg(regcache,REG_X86_EFLAGS,0xbeefdead);
    REGVAL regval;
    regcache_read_reg(regcache,REG_X86_EIP,&regval);
    regcache_write_reg(regcache,REG_X86_EIP,regval+1);

    regcache_snprintf(regcache,buf,sizeof(buf),10,",","=",0);
    printf("regcache: %s\n",buf);

    return failures;
}
