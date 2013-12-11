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

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include <error.h>
#include <stdlib.h>
#include <argp.h>

extern struct argp log_argp;
#define log_argp_header "Log/Debug Options"

#define verror(format,...) fprintf(stderr, "VERROR:   %s:%d: "format, \
				   __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define verrorc(format,...) fprintf(stderr,format, ## __VA_ARGS__)
#define vwarn(format,...)  fprintf(stderr, "VWARNING: %s:%d: "format, \
				   __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define vwarnc(format,...) fprintf(stderr,format, ## __VA_ARGS__)

#define vwarnopt(level,area,flags,format,...) _vmi_warn(level,area,flags, \
						   "VWARNING: %s:%d: "format, \
						   __FUNCTION__, __LINE__, \
						   ## __VA_ARGS__)
#define vwarnoptc(level,area,flags,format,...) _vmi_warn(level,area,flags,format, \
						    ## __VA_ARGS__)

/*
 * If you change these flags and bits, make really sure to update
 * lib/log.c!
 *
 * Rule for names: areas and flags must each be an alphanumeric string.
 */

/* Do something for all areas. */
#define LA_ALL        INT_MAX

typedef enum log_area_bits {
    LAB_NONE          = 0,
    LAB_LIB           = 1,
    LAB_DEBUG         = 2,
    LAB_TARGET        = 3,
    LAB_PROBE         = 4,
    LAB_XML           = 5,
    LAB_TEST          = 6,
    LAB_ANL           = 7,

    LAB_USER          = 31,
} log_area_bits_t;
typedef enum log_areas {
    LA_NONE           = 0,
    LA_LIB            = 1 << LAB_LIB,
    LA_DEBUG          = 1 << LAB_DEBUG,
    LA_TARGET         = 1 << LAB_TARGET,
    LA_PROBE          = 1 << LAB_PROBE,
    LA_XML            = 1 << LAB_XML,
    LA_TEST           = 1 << LAB_TEST,
    LA_ANL            = 1 << LAB_ANL,

    LA_USER           = 1 << LAB_USER,
} log_areas_t;

/*
 * Per-area flags.
 */
/* Mask all the per-area enums below :) */
typedef int log_flags_t;

typedef enum log_flag_bits_lib {
    LFB_CLMATCH       = 0,
    LFB_CLRANGE       = 1,
    LFB_RFILTER       = 2,
    LFB_WAITPIPE      = 3,
    LFB_EVLOOP        = 4,
    LFB_MONITOR       = 5,
    LFB_ROP           = 6,
    LFB_CFI           = 7,
} log_flag_bits_lib_t;
typedef enum log_flags_lib {
    LF_CLMATCH        = 1 << LFB_CLMATCH,
    LF_CLRANGE        = 1 << LFB_CLRANGE,
    LF_RFILTER        = 1 << LFB_RFILTER,
    LF_WAITPIPE       = 1 << LFB_WAITPIPE,
    LF_EVLOOP         = 1 << LFB_EVLOOP,
    LF_MONITOR        = 1 << LFB_MONITOR,
    LF_ROP            = 1 << LFB_ROP,
    LF_CFI            = 1 << LFB_CFI,
} log_flags_lib_t;

typedef enum log_flag_bits_debug {
    LFB_DFILE         = 0,
    LFB_SYMBOL        = 1,
    LFB_SCOPE         = 2,
    LFB_DLOC          = 3,
    LFB_DLOOKUP       = 4,
    LFB_DWARF         = 5,
    LFB_DWARFATTR     = 6,
    LFB_DWARFSOPS     = 7,
    LFB_DWARFOPS      = 8,
    LFB_DCFA          = 9,
    LFB_DOTHER        = 10,
    LFB_ELF           = 11,
    LFB_BFILE         = 12,
} log_flag_bits_debug_t;
typedef enum log_flags_debug {
    LF_DFILE          = 1 << LFB_DFILE,
    LF_SYMBOL         = 1 << LFB_SYMBOL,
    LF_SCOPE          = 1 << LFB_SCOPE,
    LF_DLOC           = 1 << LFB_DLOC,
    LF_DLOOKUP        = 1 << LFB_DLOOKUP,
    LF_DWARF          = 1 << LFB_DWARF,
    LF_DWARFATTR      = 1 << LFB_DWARFATTR,
    LF_DWARFSOPS      = 1 << LFB_DWARFSOPS,
    LF_DWARFOPS       = 1 << LFB_DWARFOPS,
    LF_DCFA           = 1 << LFB_DCFA,
    LF_DOTHER         = 1 << LFB_DOTHER,
    LF_ELF            = 1 << LFB_ELF,
    LF_BFILE          = 1 << LFB_BFILE,
} log_flags_debug_t;

typedef enum log_flag_bits_target {
    LFB_TARGET        = 0,
    LFB_SPACE         = 1,
    LFB_REGION        = 2,
    LFB_TLOOKUP       = 3,
    LFB_TLOC          = 4,
    LFB_TOTHER        = 5,
    LFB_TSYMBOL       = 6,
    LFB_TUNW          = 7,
    LFB_LUP           = 8,
    LFB_XV            = 9,
    LFB_XVP           = 10,
    LFB_DISASM        = 11,
    LFB_THREAD        = 12,
    LFB_OS            = 13,
    LFB_PROCESS       = 14,
} log_flag_bits_target_t;
typedef enum log_flags_target {
    LF_TARGET         = 1 << LFB_TARGET,
    LF_SPACE          = 1 << LFB_SPACE,
    LF_REGION         = 1 << LFB_REGION,
    LF_TLOOKUP        = 1 << LFB_TLOOKUP,
    LF_TLOC           = 1 << LFB_TLOC,
    LF_TOTHER         = 1 << LFB_TOTHER,
    LF_TSYMBOL        = 1 << LFB_TSYMBOL,
    LF_TUNW           = 1 << LFB_TUNW,
    LF_LUP            = 1 << LFB_LUP,
    LF_XV             = 1 << LFB_XV,
    LF_XVP            = 1 << LFB_XVP,
    LF_DISASM         = 1 << LFB_DISASM,
    LF_THREAD         = 1 << LFB_THREAD,
    LF_OS             = 1 << LFB_OS,
    LF_PROCESS        = 1 << LFB_PROCESS,
} log_flags_target_t;

typedef enum log_flag_bits_probe {
    LFB_PROBE         = 0,
    LFB_PROBEPOINT    = 1,
    LFB_ACTION        = 2,
} log_flag_bits_probe_t;
typedef enum log_flags_probe {
    LF_PROBE          = 1 << LFB_PROBE,
    LF_PROBEPOINT     = 1 << LFB_PROBEPOINT,
    LF_ACTION         = 1 << LFB_ACTION,
} log_flags_probe_t;

typedef enum log_flag_bits_xml {
    LFB_XML           = 0,
    LFB_RPC           = 1,
    LFB_SVC           = 2,
    LFB_PROXYREQ      = 3,
} log_flag_bits_xml_t;
typedef enum log_flags_xml {
    LF_XML            = 1 << LFB_XML,
    LF_RPC            = 1 << LFB_RPC,
    LF_SVC            = 1 << LFB_SVC,
    LF_PROXYREQ       = 1 << LFB_PROXYREQ,
} log_flags_xml_t;

typedef enum log_flag_bits_anl {
    LFB_ANL           = 0,
} log_flag_bits_anl_t;
typedef enum log_flags_anl {
    LF_ANL            = 1 << LFB_ANL,
} log_flags_anl_t;

/*
typedef enum log_flag_bits_ {
    LFB_         = 0,
    LFB_         = 1,
    LFB_         = 2,
} log_flag_bits__t;
typedef enum log_flags_ {
    LF_          = 1 << LFB_,
    LF_          = 1 << LFB_,
    LF_          = 1 << LFB_,
} log_flags__t;
*/

/*
 * Some special per-area masks.
 */
/* Set every last bit for a specific area. */
#define LF_ALL        INT_MAX
#define LF_L_ALL (LF_CLMATCH | LF_CLRANGE | LF_RFILTER | LF_WAITPIPE | LF_EVLOOP | LF_MONITOR | LF_ROP | LF_CFI)
#define LF_D_ALL (LF_DFILE | LF_SYMBOL | LF_SCOPE | LF_DLOC \
		  | LF_DLOOKUP | LF_DWARF | LF_DWARFATTR	\
		  | LF_DWARFSOPS | LF_DWARFOPS | LF_DCFA | LF_DOTHER \
		  | LF_ELF | LF_BFILE )
#define LF_T_ALL (LF_TARGET | LF_SPACE | LF_REGION | LF_TLOOKUP \
		  | LF_TLOC | LF_TOTHER | LF_TSYMBOL | LF_TUNW | LF_DISASM \
		  | LF_THREAD | LF_OS | LF_PROCESS)
#define LF_P_ALL (LF_PROBE | LF_PROBEPOINT | LF_ACTION)
#define LF_X_ALL (LF_XML | LF_RPC | LF_SVC | LF_PROXYREQ)
#define LF_A_ALL (LF_ANL)
/* Set every last bit for the user area. */
#define LF_U_ALL        INT_MAX

/*
 * Set the debug log level.
 */
void vmi_set_log_level(int level);
/*
 * Increase the debug log level by 1.
 */
void vmi_inc_log_level(void);
/*
 * Set the warn log level.
 */
void vmi_set_warn_level(int level);
/*
 * Increase the warn level by 1.
 */
void vmi_inc_warn_level(void);
/*
 * Reinitialize the flags for one or more areas.
 */
void vmi_set_log_area_flags(log_areas_t area,log_flags_t flags);
int vmi_set_log_area_flaglist(char *flaglist,char *separator);
/*
 * Additively (OR) change the flags for one or more areas.
 */
void vmi_add_log_area_flags(log_areas_t areas,log_flags_t flags);
int vmi_add_log_area_flaglist(char *flaglist,char *separator);
/*
 * Users should set this before calling any argp parsing routines we
 * provide if they want the -l standard argument to accept their debug
 * flags.
 *
 * @names must be a NULL-terminated list of names.
 */
void vmi_set_user_area_flags(char **names);

/*
 * Users should not need to call this.
 */
int vmi_log_get_flag_val(char *flag,log_areas_t *areaval,log_flags_t *flagval);

void _vmi_debug(int level,log_areas_t areas,log_flags_t flags,char *format,...);
void _vmi_warn(int level,log_areas_t areas,log_flags_t flags,char *format,...);

int vdebug_is_on(int level,log_areas_t areas,log_flags_t flags);
int vwarn_is_on(int level,log_areas_t areas,log_flags_t flags);

error_t log_argp_parse_opt(int key,char *arg,struct argp_state *state);

#ifdef VMI_DEBUG
#define vdebug(level,areas,flags,format,...) _vmi_debug(level,areas,flags,"VDEBUG: %s:%d: "format, __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define vdebugc(level,areas,flags,format,...) _vmi_debug(level,areas,flags,format, ## __VA_ARGS__)

#else

#define vdebug(devel,areas,flags,format,...) ((void)0)
#define vdebugc(devel,areas,flags,format,...) ((void)0)

#endif

#endif /* __LOG_H__ */
