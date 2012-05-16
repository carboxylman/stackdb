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
 *  examples/null-deref-analysis/null-deref-pagefault.c
 *
 *  Find out who wrote the kernel page zero.
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
#include "util.h"

extern char *optarg;
extern int optind, opterr, optopt;

static char *domain_name = NULL; 
static int debug_level = -1; 
static char *sysmap_file = NULL;
static int concise = 0;

static unsigned long long brctr_root;
static unsigned int pid_root;
static unsigned long addr_root;

void probe_pagefault(unsigned long address,
                     int protection_fault,
                     int write_access,
                     int user_mode,
                     int reserved_bit,
                     int instr_fetch,
                     ctxprobes_task_t *task)
{
    unsigned long long brctr = ctxprobes_get_brctr();
    if (!brctr)
    {
        ERR("Failed to get branch counter\n");
        return;
    }

    if (brctr >= brctr_root)
        kill_everything(domain_name);

    if (task->pid == pid_root)
    {
        if (!instr_fetch)
        {
            char desc[128] = {0,};
            strcat(desc, protection_fault ?
                    "protection-fault, " : "no-page-found, ");
            strcat(desc, write_access ?
                    "write-access, " : "read-access, ");
            strcat(desc, user_mode ?
                    "user-mode, " : "kernel-mode, ");
            desc[strlen(desc)-2] = '\0';

            if (concise)
            {
                fflush(stderr);
                printf("brctr=%lld, address=0x%08lx, "
                       "protection=%d, write=%d, user=%d\n", 
                       brctr, address, 
                       protection_fault, write_access, user_mode);
                fflush(stdout);
            }

            if (address == addr_root && write_access)
            {
                if (!concise)
                {
                    capitalize(desc);
                    
                    fflush(stderr);
                    printf("PAGE FAULT AT 0x%08lX (%s, BRCTR = %lld)\n", 
                            address, desc, brctr);
                    fflush(stdout);
                }
                
                kill_everything(domain_name);
            }
            else
            {
                if (!concise)
                {
                    fflush(stderr);
                    printf("Page fault at 0x%08lx (%s)\n", address, desc);
                    fflush(stdout);
                }
            }
        }
    }
}

void parse_opt(int argc, char *argv[])
{
    char ch;
    log_flags_t debug_flags;
    
    while ((ch = getopt(argc, argv, "dl:m:p:b:a:c")) != -1)
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

            case 'p':
                pid_root = atoi(optarg);
                break;

            case 'b':
                brctr_root = atoll(optarg);
                break;

            case 'a':
                sscanf(optarg, "%lx", &addr_root);
                break;

            case 'c':
                concise = 1;
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
                         NULL, 
                         NULL, 
                         probe_pagefault, 
                         debug_level);
    if (ret)
    {
        ERR("Failed to init ctxprobes\n");
        exit(ret);
    }

    ctxprobes_wait();

    ctxprobes_cleanup();
    return 0;
}

