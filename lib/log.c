;/*
 * Copyright (c) 2012, 2013 The University of Utah
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
#include <unistd.h>
#include <error.h>
#include <argp.h>

#include "log.h"

static int vmi_log_level = -1;
static int vmi_warn_level = -1;
static log_flags_t vmi_log_flags[32] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

void vmi_set_log_level(int level) {
    vmi_log_level = level;
}

void vmi_inc_log_level(void) {
    ++vmi_log_level;
}

void vmi_set_warn_level(int level) {
    vmi_warn_level = level;
}

void vmi_inc_warn_level(void) {
    ++vmi_warn_level;
}

void vmi_set_log_area_flags(log_areas_t areas,log_flags_t flags) {
    if (areas & LA_LIB)
	vmi_log_flags[LAB_LIB] = flags;
    if (areas & LA_DEBUG)
	vmi_log_flags[LAB_DEBUG] = flags;
    if (areas & LA_TARGET)
	vmi_log_flags[LAB_TARGET] = flags;
    if (areas & LA_PROBE)
	vmi_log_flags[LAB_PROBE] = flags;
    if (areas & LA_XML)
	vmi_log_flags[LAB_XML] = flags;
    if (areas & LA_ANL)
	vmi_log_flags[LAB_ANL] = flags;
    if (areas & LA_USER)
	vmi_log_flags[LAB_USER] = flags;
}

void vmi_add_log_area_flags(log_areas_t areas,log_flags_t flags) {
    if (areas & LA_LIB)
	vmi_log_flags[LAB_LIB] |= flags;
    if (areas & LA_DEBUG)
	vmi_log_flags[LAB_DEBUG] |= flags;
    if (areas & LA_TARGET)
	vmi_log_flags[LAB_TARGET] |= flags;
    if (areas & LA_PROBE)
	vmi_log_flags[LAB_PROBE] |= flags;
    if (areas & LA_XML)
	vmi_log_flags[LAB_XML] |= flags;
    if (areas & LA_ANL)
	vmi_log_flags[LAB_ANL] |= flags;
    if (areas & LA_USER)
	vmi_log_flags[LAB_USER] |= flags;
}

int vmi_set_log_area_flaglist(char *flaglist,char *separator) {
    char *flag = NULL;
    char *saveptr = NULL;
    log_areas_t areas;
    log_flags_t flags;

    if (!separator)
	separator = ",";

    while ((flag = strtok_r(!saveptr ? flaglist : NULL,separator,&saveptr))) {
	if (vmi_log_get_flag_val(flag,&areas,&flags)) 
	    return -1;
	else 
	    vmi_set_log_area_flags(areas,flags);
    }

    return 0;
}

int vmi_add_log_area_flaglist(char *flaglist,char *separator) {
    char *flag = NULL;
    char *saveptr = NULL;
    log_areas_t areas;
    log_flags_t flags;

    if (!separator)
	separator = ",";

    while ((flag = strtok_r(!saveptr ? flaglist : NULL,separator,&saveptr))) {
	areas = 0;
	flags = 0;
	if (vmi_log_get_flag_val(flag,&areas,&flags)) 
	    return -1;
	else 
	    vmi_add_log_area_flags(areas,flags);
    }

    return 0;
}

static char *log_flag_stringmap_none[] = { "NONE",NULL };
static char *log_flag_stringmap_lib[] = {
    "CLMATCH","CLRANGE","RFILTER","WAITPIPE","EVLOOP","MONITOR","ROP","CFI",NULL
};
static char *log_flag_stringmap_debug[] = { 
    "DFILE","SYMBOL","SYMTAB","LOC","LOOKUP","DWARF","DWARFATTR",
    "DWARFOPS","OTHER","ELF","BFILE",NULL
};
static char *log_flag_stringmap_target[] = { 
    "TARGET","SPACE","REGION","LOOKUP","LOC","OTHER","SYMBOL",
    "LUP","XV","XVP","DISASM","THREAD","OS","PROCESS",NULL
};
static char *log_flag_stringmap_probe[] = { 
    "PROBE","PROBEPOINT","ACTION",NULL
};
static char *log_flag_stringmap_xml[] = { 
    "XML","RPC","SVC","PROXYREQ",NULL
};
static char *log_flag_stringmap_anl[] = { 
    "ANL",NULL
};

static char **log_flag_stringmap[32] = {
    log_flag_stringmap_none,
    log_flag_stringmap_lib,
    log_flag_stringmap_debug,
    log_flag_stringmap_target,
    log_flag_stringmap_probe,
    log_flag_stringmap_xml,
    log_flag_stringmap_anl,
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
    /* Will get set to an array of user flags if they call
     * vmi_set_user_area_flags().
     */
    NULL,
};

void vmi_set_user_area_flags(char **names) {
    log_flag_stringmap[LAB_USER] = names;
}

int vmi_log_get_flag_val(char *flag,log_areas_t *areaval,log_flags_t *flagval) {
    unsigned int i;
    int found;
    int _len;
    char *_dup = NULL;
    char *_area;
    char *_flag;
    char **_rflag;
    char *_idx;
    char **subarray = NULL;
    log_area_bits_t areabits = 0;

    /* Check the LOG_*_ALL flags first. */
    if (strcmp("ALL",flag) == 0) {
	if (flagval)
	    *flagval = LF_ALL;
	if (areaval)
	    *areaval = LA_ALL;
	return 0;
    }
    else if (strcmp("L_ALL",flag) == 0) {
	if (flagval)
	    *flagval = LF_L_ALL;
	if (areaval)
	    *areaval = LA_LIB;
	return 0;
    }
    else if (strcmp("D_ALL",flag) == 0) {
	if (flagval)
	    *flagval = LF_D_ALL;
	if (areaval)
	    *areaval = LA_DEBUG;
	return 0;
    }
    else if (strcmp("T_ALL",flag) == 0) {
	if (flagval)
	    *flagval = LF_T_ALL;
	if (areaval)
	    *areaval = LA_TARGET;
	return 0;
    }
    else if (strcmp("P_ALL",flag) == 0) {
	if (flagval)
	    *flagval = LF_P_ALL;
	if (areaval)
	    *areaval = LA_PROBE;
	return 0;
    }
    else if (strcmp("X_ALL",flag) == 0) {
	if (flagval)
	    *flagval = LF_X_ALL;
	if (areaval)
	    *areaval = LA_XML;
	return 0;
    }
    else if (strcmp("A_ALL",flag) == 0) {
	if (flagval)
	    *flagval = LF_A_ALL;
	if (areaval)
	    *areaval = LA_ANL;
	return 0;
    }
    else if (strcmp("U_ALL",flag) == 0) {
	if (flagval)
	    *flagval = LF_U_ALL;
	if (areaval)
	    *areaval = LA_USER;
	return 0;
    }

    if ((_idx = index(flag,'_'))) {
	_dup = strdup(flag);
	_len = strlen(_dup);

	*_idx = '\0';
	_area = _dup;
	_flag = _idx + 1;

	if (*_area == 'L') 
	    areabits = LAB_LIB;
	else if (*_area == 'D') 
	    areabits = LAB_DEBUG;
	else if (*_area == 'T') 
	    areabits = LAB_TARGET;
	else if (*_area == 'P') 
	    areabits = LAB_PROBE;
	else if (*_area == 'X') 
	    areabits = LAB_XML;
	else if (*_area == 'A') 
	    areabits = LAB_ANL;
	else if (*_area == 'U') 
	    areabits = LAB_USER;
	else {
	    verror("bad flag '%s': no such area prefix '%s'!\n",flag,_area);
	    free(_dup);
	    return -1;
	}

	subarray = log_flag_stringmap[areabits];

	if (!subarray) {
	    verror("bad flag '%s': area '%s' has no flags!\n",flag,_area);
	    free(_dup);
	    return -1;
	}

	i = 0;
	found = 0;
	while ((_rflag = subarray++) && *_rflag) {
	    if (strcmp(_flag,*_rflag) == 0) {
		found = 1;
		break;
	    }
	    ++i;
	}

	if (!found) {
	    verror("area '%s' has no flag '%s'!\n",_area,_flag);
	    free(_dup);
	    return -1;
	}
	else {
	    if (areaval)
		*areaval = 1 << areabits;
	    if (flagval)
		*flagval = 1 << i;
	    free(_dup);
	    return 0;
	}
    }
    else {
	/* Assume it is a user-specific flag. */
	areabits = LAB_USER;
	subarray = log_flag_stringmap[areabits];
	_area = "U";
	_flag = flag;

	i = 0;
	found = 0;
	while ((_rflag = ++subarray) && *_rflag) {
	    if (strcmp(_flag,*_rflag) == 0) {
		found = 1;
		break;
	    }
	    ++i;
	}

	if (!found) {
	    verror("area '%s' has no flag '%s'!\n",_area,_flag);
	    free(_dup);
	    return -1;
	}
	else {
	    if (areaval)
		*areaval = 1 << areabits;
	    if (flagval)
		*flagval = 1 << i;
	    free(_dup);
	    return 0;
	}
    }
}

int vdebug_is_on(int level,log_areas_t areas,log_flags_t flags) {
    if (vmi_log_level < level)
	return 0;
    else {
	if (areas & LA_LIB && vmi_log_flags[LAB_LIB] & flags)
	    return 1;
	else if (areas & LA_DEBUG && vmi_log_flags[LAB_DEBUG] & flags)
	    return 1;
	else if (areas & LA_TARGET && vmi_log_flags[LAB_TARGET] & flags)
	    return 1;
	else if (areas & LA_PROBE && vmi_log_flags[LAB_PROBE] & flags)
	    return 1;
	else if (areas & LA_XML && vmi_log_flags[LAB_XML] & flags)
	    return 1;
	else if (areas & LA_ANL && vmi_log_flags[LAB_ANL] & flags)
	    return 1;
	else if (areas & LA_USER && vmi_log_flags[LAB_USER] & flags)
	    return 1;
    }
    return 0;
}

int vwarn_is_on(int level,log_areas_t areas,log_flags_t flags) {
    if (vmi_warn_level < level)
	return 0;
    else {
	if (areas & LA_LIB && vmi_log_flags[LAB_LIB] & flags)
	    return 1;
	else if (areas & LA_DEBUG && vmi_log_flags[LAB_DEBUG] & flags)
	    return 1;
	else if (areas & LA_TARGET && vmi_log_flags[LAB_TARGET] & flags)
	    return 1;
	else if (areas & LA_PROBE && vmi_log_flags[LAB_PROBE] & flags)
	    return 1;
	else if (areas & LA_XML && vmi_log_flags[LAB_XML] & flags)
	    return 1;
	else if (areas & LA_ANL && vmi_log_flags[LAB_ANL] & flags)
	    return 1;
	else if (areas & LA_USER && vmi_log_flags[LAB_USER] & flags)
	    return 1;
    }
    return 0;
}

void _vmi_debug(int level,log_areas_t areas,log_flags_t flags,char *format,...) {
    va_list args;
    if (!vdebug_is_on(level,areas,flags))
	return;
    va_start(args, format);
    vfprintf(stderr, format, args);
    fflush(stderr);
    va_end(args);
}

void _vmi_warn(int level,log_areas_t areas,log_flags_t flags,char *format,...) {
    va_list args;
    if (!vwarn_is_on(level,areas,flags))
	return;
    va_start(args, format);
    vfprintf(stderr, format, args);
    fflush(stderr);
    va_end(args);
}

/*
 * Log arg parsing stuff.
 */
struct argp_option log_argp_opts[] = {
    { "debug",'d',"LEVEL",OPTION_ARG_OPTIONAL,
      "Set/increase the debugging level.",-2 },
    //{ "debug",'d',0,0,"Increase the debugging level.",-2 },
    { "log-flags",'l',"FLAG,FLAG,...",0,"Set the debugging flags",-2 },
    { "warn",'w',"LEVEL",OPTION_ARG_OPTIONAL,
      "Set/increase the warning level.",-2 },
    //{ "warn",'w',0,0,"Increase the warning level.",-2 },
    { 0,0,0,0,0,0 }
};

struct argp log_argp = { log_argp_opts,log_argp_parse_opt,
			 NULL,NULL,NULL,NULL,NULL };

error_t log_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    char *endptr = NULL;

    switch (key) {
    case ARGP_KEY_ARG:
    case ARGP_KEY_ARGS:
	return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_END:
    case ARGP_KEY_NO_ARGS:
    case ARGP_KEY_SUCCESS:
    case ARGP_KEY_ERROR:
    case ARGP_KEY_FINI:
	return 0;
    case ARGP_KEY_INIT:
	/* No child state to initialize. */
	return 0;

    case 'd':
	if (arg) {
	    errno = 0;
	    vmi_log_level = (int)strtol(arg,&endptr,0);
	    if (errno || endptr == arg) {
		/*
		 * Try to count up any 'd' chars.  Grab the one that got
		 * us here too.
		 */
		++vmi_log_level;
		while (*arg != '\0') {
		    if (*arg == 'd')
			++vmi_log_level;
		    ++arg;
		}
	    }
	}
	else
	    ++vmi_log_level;
	break;
    case 'w':
	if (arg) {
	    errno = 0;
	    vmi_warn_level = (int)strtol(arg,&endptr,0);
	    if (errno || endptr == arg) {
		/*
		 * Try to count up any 'w' chars.  Grab the one that got
		 * us here too.
		 */
		++vmi_warn_level;
		while (*arg != '\0') {
		    if (*arg == 'w')
			++vmi_warn_level;
		    ++arg;
		}
	    }
	}
	else
	    ++vmi_warn_level;
	break;
    case 'l':
	if (vmi_add_log_area_flaglist(arg,NULL)) {
	    verror("bad log level flag in '%s'!\n",arg);
	    return EINVAL;
	}
	break;

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}
