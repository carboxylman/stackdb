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
 * 
 *  examples/ctrl-flow-analysis/ctrl-flow-passwd.c
 *
 *  Determine where the process of the given pid became root.
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

static unsigned int pid_passwd;
static unsigned long long brctr_passwd;

void task_switch(ctxprobes_task_t *prev, ctxprobes_task_t *next)
{
    if (next->pid == pid_passwd)
    {
        unsigned long long brctr = ctxprobes_get_brctr();
        if (!brctr)
        {
            ERR("Failed to get branch counter\n");
            return;
        }

        fflush(stderr);
        printf("%d (%s): uid = %d, euid = %d\n",
               next->pid, next->comm, next->uid, next->euid);
        fflush(stdout);

        if (brctr > brctr_passwd)
        {
            fflush(stderr);
            printf("/etc/passwd accessed!\n");
            fflush(stdout);
        }
    }
}

void parse_opt(int argc, char *argv[])
{
    char ch;
    log_flags_t debug_flags;
    
    while ((ch = getopt(argc, argv, "dl:m:p:b:")) != -1)
    {
        switch(ch)
        {
            case 'd':
                ++debug_level;
                break;

            case 'l':
                if (vmi_log_get_flag_mask(optarg, &debug_flags))
                {
                    fprintf(stderr, "ERROR: bad debug flag in '%s'!\n", 
                            optarg);
                    exit(-1);
                }
                vmi_set_log_flags(debug_flags);
                break;

            case 'm':
                sysmap_file = optarg;
                break;

            case 'p':
                pid_passwd = atoi(optarg);
                break;

            case 'b':
                brctr_passwd = atoll(optarg);
                break;

            default:
                fprintf(stderr, "ERROR: unknown option %c!\n", ch);
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
                         task_switch, 
                         NULL, 
                         debug_level);
    if (ret)
    {
        ERR("Failed to init ctxprobes\n");
        exit(ret);
    }
/*
    ret = ctxprobes_reg_func_return("sys_fork", probe_fork_return);
    if (ret)
    {
        ERR("Failed to register probe on sys_fork return\n");
        ctxprobes_cleanup();
        exit(ret);
    } 
*/
    ctxprobes_wait();

    ctxprobes_cleanup();
    return 0;
}

