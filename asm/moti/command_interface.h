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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <argp.h>
#include <inttypes.h>
#include "log.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"
#include "target_xen_vm.h"
#include "probe_api.h"
#include "probe.h"
#include "alist.h"
#include "list.h"
#include "target_os.h"

/* struct to store the parsed command */
struct TOKEN {
    char cmd[128];
    int argc;
    char argv[128][128];
};

/* command structure similar to the one used in the repair drivers */
struct cmd_rec {
    unsigned int cmd_id;       /* unique identifier for each command */
    unsigned int submodule_id; /* submodule in which the command is implemented*/
    int argc;                  /* command argument count */
    unsigned long argv[128];             /* array to store the arguments*/
};

/* acknowledgment struct similar to the one s used in the repair driver */
struct ack_rec {
    unsigned int submodule_id; /* submodule in which the command is implemented*/
    unsigned int cmd_id;       /* unique identifier for each command */
    int exec_status;           /* 1 = success , 0 = error */
    int argc;                  /* result argument count */
    unsigned long argv[128];             /* array to store result data*/
};

/* Standard set of error codes for the command interface */
typedef enum ci_error_codes {
    CI_SUCCESS     = 0,
    CI_ERROR       = 1,   /* Generic error */
    CI_LOOKUP_ERR  = 2,  /* Failed to lookup symbols */
    CI_LOAD_ERR    = 3,  /* Failed to load vales of symbols */
    CI_UPDATE_ERR  = 4,  /* Failed to update values */
    CI_STORE_ERR   = 5,  /* Failed to store values */
    CI_TPAUSE_ERR  = 6,  /* Failed to pause the target */
    CI_TRESUME_ERR = 7,  /* Failed to resume target */
    CI_EXIT        = 8,
} ci_error_t;

