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

/*
 *  examples/local-dos-analysis/local-dos-process.c
 *
 *  PASS-1: Find out in which process the kernel panic occured.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#ifndef CONFIG_DETERMINISTIC_TIMETRAVEL
#error "Program runs only on Time Travel enabled Xen"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <log.h>
#include <ctxprobes.h>

#include "debug.h"

extern char *optarg;
extern int optind, opterr, optopt;

static char *domain_name = NULL; 
static int debug_level = -1; 
static char *sysmap_file = NULL;

void probe_task_switch(ctxprobes_task_t *prev, ctxprobes_task_t *next)
{
    unsigned long long brctr = ctxprobes_get_brctr();
    if (!brctr)
    {
        ERR("Failed to get branch counter\n");
        return;
    }
    
    LOG("%d (%s) -> %d (%s): brctr = %lld\n", 
        prev->pid, prev->comm, next->pid, next->comm, brctr);
}

void parse_opt(int argc, char *argv[])
{
    char ch;
    log_flags_t debug_flags;
    
    while ((ch = getopt(argc, argv, "dl:m:b:p:")) != -1)
    {
        switch(ch)
        {
            case 'd':
                ++debug_level;
                break;

            case 'l':
                if (vmi_log_get_flag_mask(optarg, &debug_flags))
                {
                    ERR("Bad debug flag in '%s'!\n", optarg);
                    exit(-1);
                }
                vmi_set_log_flags(debug_flags);
                break;

            case 'm':
                sysmap_file = optarg;
                break;

            default:
                ERR("Unknown option %c!\n", ch);
                exit(-1);
        }
    }

    if (argc <= optind)
    {
        printf("Usage: %s [option] <domain>\n", argv[0]);
        exit(-1);
    }

    domain_name = argv[optind];
}

int main(int argc, char *argv[])
{
    int ret;
    
    parse_opt(argc, argv);

    ret = ctxprobes_init(domain_name, 
                         sysmap_file, 
                         debug_level);
    if (ret)
    {
        ERR("Could not initialize context-aware probes\n");
        exit(ret);
    }

    ret = ctxprobes_track(probe_task_switch, 
                          NULL, /* context change handler */
                          NULL, /* page fault handler */
                          NULL);
    if (ret)
    {
        ERR("Could not start tracking contexts\n");
        exit(ret);
    }

    ctxprobes_wait();

    ctxprobes_cleanup();

    return 0;
}

