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

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

#define verror(format,...) fprintf(stderr, "VERROR:   %s:%d: "format, \
				   __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define vwarn(format,...)  fprintf(stderr, "VWARNING: %s:%d: "format, \
				   __FUNCTION__, __LINE__, ## __VA_ARGS__)

/*
 * If you change these flags and bits, make really sure to update
 * lib/log.c!
 */
typedef enum log_flag_bits {
    LOG_FB_NONE        = 0,
    LOG_FB_D_DFILE     = 1,
    LOG_FB_D_SYMBOL    = 2,
    LOG_FB_D_SYMTAB    = 3,
    LOG_FB_D_LOC       = 4,
    LOG_FB_D_LOOKUP    = 5,
    LOG_FB_D_DWARF     = 6,
    LOG_FB_D_OTHER     = 7,
    LOG_FB_T_TARGET    = 8,
    LOG_FB_T_SPACE     = 9,
    LOG_FB_T_REGION    = 10,
    LOG_FB_T_LOOKUP    = 11,
    LOG_FB_T_LOC       = 12,
    LOG_FB_T_OTHER     = 13,
    LOG_FB_T_SYMBOL    = 14,
    LOG_FB_T_LUP       = 15,
} log_flag_bits_t;

typedef enum log_flags {
    LOG_NONE           = 0,
    LOG_D_DFILE        = 1 << LOG_FB_D_DFILE,
    LOG_D_SYMBOL       = 1 << LOG_FB_D_SYMBOL,
    LOG_D_SYMTAB       = 1 << LOG_FB_D_SYMTAB,
    LOG_D_LOC          = 1 << LOG_FB_D_LOC,
    LOG_D_LOOKUP       = 1 << LOG_FB_D_LOOKUP,
    LOG_D_DWARF        = 1 << LOG_FB_D_DWARF,
    LOG_D_OTHER        = 1 << LOG_FB_D_OTHER,
    LOG_T_TARGET       = 1 << LOG_FB_T_TARGET,
    LOG_T_SPACE        = 1 << LOG_FB_T_SPACE,
    LOG_T_REGION       = 1 << LOG_FB_T_REGION,
    LOG_T_LOOKUP       = 1 << LOG_FB_T_LOOKUP,
    LOG_T_LOC          = 1 << LOG_FB_T_LOC,
    LOG_T_OTHER        = 1 << LOG_FB_T_OTHER,
    LOG_T_SYMBOL       = 1 << LOG_FB_T_SYMBOL,
    LOG_T_LUP          = 1 << LOG_FB_T_LUP,
} log_flags_t;

#define LOG_D_ALL (LOG_D_DFILE | LOG_D_SYMBOL | LOG_D_SYMTAB | LOG_D_LOC \
		   | LOG_D_LOOKUP | LOG_D_DWARF | LOG_D_OTHER)
#define LOG_T_ALL (LOG_T_TARGET | LOG_T_SPACE | LOG_T_REGION | LOG_T_LOOKUP \
		   | LOG_T_LOC | LOG_T_OTHER)

void vmi_set_log_level(int level);
void vmi_set_log_flags(log_flags_t flags);

int vmi_log_get_flag_val(char *flag,log_flags_t *flagval);
int vmi_log_get_flag_mask(char *flaglist,log_flags_t *flagmask);

void _vmi_debug(int level,log_flags_t flags,char *format,...);

#ifdef VMI_DEBUG
#define vdebug(level,flags,format,...) _vmi_debug(level,flags,"VDEBUG: %s:%d: "format, __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define vdebugc(level,flags,format,...) _vmi_debug(level,flags,format, ## __VA_ARGS__)

#else

#define vdebug(devel,flags,format,...) ((void)0)
#define vdebugc(devel,flags,format,...) ((void)0)

#endif

#endif /* __LOG_H__ */