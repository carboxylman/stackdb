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
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include <error.h>
#include <stdlib.h>
#include <argp.h>

#define verror(format,...) fprintf(stderr, "VERROR:   %s:%d: "format, \
				   __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define verrorc(format,...) fprintf(stderr,format, ## __VA_ARGS__)
#define vwarn(format,...)  fprintf(stderr, "VWARNING: %s:%d: "format, \
				   __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define vwarnc(format,...) fprintf(stderr,format, ## __VA_ARGS__)

#define vwarnopt(level,flags,format,...) _vmi_warn(level,flags, \
						   "VWARNING: %s:%d: "format, \
						   __FUNCTION__, __LINE__, \
						   ## __VA_ARGS__)
#define vwarnoptc(level,flags,format,...) _vmi_warn(level,flags,format, \
						    ## __VA_ARGS__)

/*
 * If you change these flags and bits, make really sure to update
 * lib/log.c!
 */
typedef enum log_flag_bits {
    LOG_FB_NONE        = 0,

    LOG_FB_OTHER       = 1,

    LOG_FB_D_DFILE     = 2,
    LOG_FB_D_SYMBOL    = 3,
    LOG_FB_D_SYMTAB    = 4,
    LOG_FB_D_LOC       = 5,
    LOG_FB_D_LOOKUP    = 6,
    LOG_FB_D_DWARF     = 7,
    LOG_FB_D_DWARFATTR = 8,
    LOG_FB_D_DWARFOPS  = 9,
    LOG_FB_D_OTHER     = 10,
    LOG_FB_D_ELF       = 11,

    LOG_FB_T_TARGET    = 12,
    LOG_FB_T_SPACE     = 13,
    LOG_FB_T_REGION    = 14,
    LOG_FB_T_LOOKUP    = 15,
    LOG_FB_T_LOC       = 16,
    LOG_FB_T_OTHER     = 17,
    LOG_FB_T_SYMBOL    = 18,
    LOG_FB_T_LUP       = 19,
    LOG_FB_T_XV        = 20,
    LOG_FB_T_DISASM    = 21,
    LOG_FB_T_THREAD    = 22,

    LOG_FB_P_PROBE     = 23,
    LOG_FB_P_PROBEPOINT= 24,
    LOG_FB_P_ACTION    = 25,

    LOG_FB_X_XML       = 26,
    LOG_FB_X_RPC       = 27,
} log_flag_bits_t;

typedef enum log_flags {
    LOG_NONE           = 0,
    LOG_OTHER          = 1 << LOG_FB_OTHER,
    LOG_D_DFILE        = 1 << LOG_FB_D_DFILE,
    LOG_D_SYMBOL       = 1 << LOG_FB_D_SYMBOL,
    LOG_D_SYMTAB       = 1 << LOG_FB_D_SYMTAB,
    LOG_D_LOC          = 1 << LOG_FB_D_LOC,
    LOG_D_LOOKUP       = 1 << LOG_FB_D_LOOKUP,
    LOG_D_DWARF        = 1 << LOG_FB_D_DWARF,
    LOG_D_DWARFATTR    = 1 << LOG_FB_D_DWARFATTR,
    LOG_D_DWARFOPS     = 1 << LOG_FB_D_DWARFOPS,
    LOG_D_OTHER        = 1 << LOG_FB_D_OTHER,
    LOG_D_ELF        = 1 << LOG_FB_D_ELF,
    LOG_T_TARGET       = 1 << LOG_FB_T_TARGET,
    LOG_T_SPACE        = 1 << LOG_FB_T_SPACE,
    LOG_T_REGION       = 1 << LOG_FB_T_REGION,
    LOG_T_LOOKUP       = 1 << LOG_FB_T_LOOKUP,
    LOG_T_LOC          = 1 << LOG_FB_T_LOC,
    LOG_T_OTHER        = 1 << LOG_FB_T_OTHER,
    LOG_T_SYMBOL       = 1 << LOG_FB_T_SYMBOL,
    LOG_T_LUP          = 1 << LOG_FB_T_LUP,
    LOG_T_XV           = 1 << LOG_FB_T_XV,
    LOG_T_DISASM       = 1 << LOG_FB_T_DISASM,
    LOG_T_THREAD       = 1 << LOG_FB_T_THREAD,
    LOG_P_PROBE        = 1 << LOG_FB_P_PROBE,
    LOG_P_PROBEPOINT   = 1 << LOG_FB_P_PROBEPOINT,
    LOG_P_ACTION       = 1 << LOG_FB_P_ACTION,
    LOG_X_XML          = 1 << LOG_FB_X_XML,
    LOG_X_RPC          = 1 << LOG_FB_X_RPC,
} log_flags_t;

#define LOG_D_ALL (LOG_D_DFILE | LOG_D_SYMBOL | LOG_D_SYMTAB | LOG_D_LOC \
		   | LOG_D_LOOKUP | LOG_D_DWARF | LOG_D_DWARFATTR \
		   | LOG_D_DWARFOPS | LOG_D_OTHER| LOG_D_ELF )
#define LOG_T_ALL (LOG_T_TARGET | LOG_T_SPACE | LOG_T_REGION | LOG_T_LOOKUP \
		   | LOG_T_LOC | LOG_T_OTHER | LOG_T_SYMBOL | LOG_T_DISASM \
		   | LOG_T_THREAD)
#define LOG_P_ALL (LOG_P_PROBE | LOG_P_PROBEPOINT | LOG_P_ACTION)
#define LOG_X_ALL (LOG_X_XML | LOG_X_RPC)

void vmi_set_log_level(int level);
void vmi_set_warn_level(int level);
void vmi_set_log_flags(log_flags_t flags);

int vmi_log_get_flag_val(char *flag,log_flags_t *flagval);
int vmi_log_get_flag_mask(char *flaglist,log_flags_t *flagmask);

void _vmi_debug(int level,log_flags_t flags,char *format,...);
void _vmi_warn(int level,log_flags_t flags,char *format,...);

int vdebug_is_on(int level,log_flags_t flags);

error_t log_argp_parse_opt(int key,char *arg,struct argp_state *state);

#ifdef VMI_DEBUG
#define vdebug(level,flags,format,...) _vmi_debug(level,flags,"VDEBUG: %s:%d: "format, __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define vdebugc(level,flags,format,...) _vmi_debug(level,flags,format, ## __VA_ARGS__)

#else

#define vdebug(devel,flags,format,...) ((void)0)
#define vdebugc(devel,flags,format,...) ((void)0)

#endif

#endif /* __LOG_H__ */
