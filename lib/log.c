/*
 * Copyright (c) 2012 The University of Utah
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
#include <stdarg.h>
#include <string.h>

#include "log.h"

static int vmi_log_level = -1;
static int vmi_warn_level = -1;
static log_flags_t vmi_log_flags = 0;

void vmi_set_log_level(int level) {
    vmi_log_level = level;
}

void vmi_set_warn_level(int level) {
    vmi_warn_level = level;
}

void vmi_set_log_flags(log_flags_t flags) {
    vmi_log_flags = flags;
}

static char *log_flag_stringmap[] = {
    "NONE", 
    "D_DFILE", "D_SYMBOL", "D_SYMTAB", "D_LOC", "D_LOOKUP",
        "D_DWARF", "D_DWARFATTR", "D_DWARFOPS", "D_OTHER",  "D_ELF",
    "T_TARGET", "T_SPACE", "T_REGION", "T_LOOKUP", "T_LOC", "T_OTHER",
        "T_SYMBOL", "T_LUP", "T_XV", "T_DISASM",
    "C_CTX", "C_FUNC", "C_VAR", "C_DISASM", "C_WARN",
};

static enum log_flag_bits log_flag_map[] = {
    LOG_NONE,
    LOG_D_DFILE, LOG_D_SYMBOL, LOG_D_SYMTAB, LOG_D_LOC, LOG_D_LOOKUP,
        LOG_D_DWARF, LOG_D_DWARFATTR, LOG_D_DWARFOPS, LOG_D_OTHER, LOG_D_ELF, 
    LOG_T_TARGET, LOG_T_SPACE, LOG_T_REGION, LOG_T_LOOKUP, LOG_T_LOC, 
        LOG_T_OTHER, LOG_T_SYMBOL, LOG_T_LUP, LOG_T_XV, LOG_T_DISASM, 
    LOG_C_CTX, LOG_C_FUNC, LOG_C_VAR, LOG_C_DISASM, LOG_C_WARN,
};

int vmi_log_get_flag_val(char *flag,log_flags_t *flagval) {
    unsigned int i;

    /* Check the LOG_*_ALL flags first. */
    if (strcmp("D_ALL",flag) == 0) {
	*flagval = LOG_D_ALL;
	return 0;
    }
    else if (strcmp("T_ALL",flag) == 0) {
	*flagval = LOG_T_ALL;
	return 0;
    }
    else if (strcmp("P_ALL",flag) == 0) {
	*flagval = LOG_P_ALL;
	return 0;
    }
    else if (strcmp("C_ALL",flag) == 0) {
	*flagval = LOG_C_ALL;
	return 0;
    }

    for (i = 0; i < sizeof(log_flag_stringmap) / sizeof(char *); ++i) {
	if (!strcmp(log_flag_stringmap[i],flag))
	    break;
    }

    if (i < sizeof(log_flag_stringmap) / sizeof(char *)) {
	*flagval = log_flag_map[i];
	return 0;
    }

    verror("Unknown log flag string '%s'!\n",flag);
    return -1;
}

int vmi_log_get_flag_mask(char *flaglist,log_flags_t *flagmask) {
    char *flag = NULL;
    char *saveptr = NULL;
    log_flags_t retval = LOG_NONE;
    log_flags_t tmp;

    while ((flag = strtok_r(!saveptr ? flaglist : NULL,",",&saveptr))) {
	if (vmi_log_get_flag_val(flag,&tmp))
	    return -1;
	retval |= tmp;
    }

    *flagmask = retval;
    return 0;
}

void _vmi_debug(int level,log_flags_t flags,char *format,...) {
    va_list args;
    if (vmi_log_level < level || !(flags & vmi_log_flags))
	return;
    va_start(args, format);
    vfprintf(stderr, format, args);
    fflush(stderr);
    va_end(args);
}

void _vmi_warn(int level,log_flags_t flags,char *format,...) {
    va_list args;
    if (vmi_warn_level < level || !(flags & vmi_log_flags))
	return;
    va_start(args, format);
    vfprintf(stderr, format, args);
    fflush(stderr);
    va_end(args);
}
