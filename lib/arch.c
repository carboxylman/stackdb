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

#include "log.h"
#include "arch.h"

extern struct arch arch_x86;
extern struct arch arch_x86_64;

struct arch *arch_get(arch_type_t at) {
    if (at == ARCH_X86)
	return &arch_x86;
    else if (at == ARCH_X86_64)
	return &arch_x86_64;
    else {
	verror("unsupported arch %d!\n",at);
	return NULL;
    }
}

int arch_has_reg(struct arch *arch,REG reg) {
    if (reg < 0 || reg >= arch->regcount
	|| !arch->reg_names[reg] || arch->reg_sizes[reg] == 0)
	return 0;
    else
	return 1;
}

unsigned int arch_regsize(struct arch *arch,REG reg) {
    if (!arch_has_reg(arch,reg))
	return 0;
    else
	return arch->reg_sizes[reg];
}

const char *arch_regname(struct arch *arch,REG reg) {
    if (!arch_has_reg(arch,reg))
	return 0;
    else
	return arch->reg_names[reg];
}

int arch_regno(struct arch *arch,char *name,REG *reg) {
    int i;

    for (i = 0; i <= arch->regcount; ++i) {
	if (!arch->reg_names[i])
	    continue;
	else if (strcmp(name,arch->reg_names[i]) == 0) {
	    *reg = i;
	    return 0;
	}
    }

    return 1;
}

int arch_cregno(struct arch *arch,common_reg_t creg,REG *reg) {
    if (creg >= COMMON_REG_COUNT)
	return -1;
    else if (arch->common_to_arch[creg] == -1)
	return -1;
    else {
	if (reg)
	    *reg = arch->common_to_arch[creg];
	return 0;
    }
}
