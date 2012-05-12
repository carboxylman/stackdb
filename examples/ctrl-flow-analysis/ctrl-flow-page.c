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
 *  examples/ctrl-flow-analysis/ctrl-flow-page.c
 *
 *  Find out who wrote the kernel page zero.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */
#ifndef CONFIG_DETERMINISTIC_TIMETRAVEL
#error "Program runs only on Time Travel enabled Xen"
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <log.h>

#include <ctxprobes.h>
#include "debug.h"

extern char *optarg;
extern int optind, opterr, optopt;

static char *domain_name = NULL; 
static int debug_level = -1; 
static char *sysmap_file = NULL;

char context_ch(ctxprobes_context_t context)
{
    char c;
    switch (context) {
        case CTXPROBES_CONTEXT_NORMAL:
            c = 'N';
            break;
        case CTXPROBES_CONTEXT_TRAP:
            c = 'T';
            break;
        case CTXPROBES_CONTEXT_INTERRUPT:
            c = 'I';
            break;
        default:
            c = 'X';
            ERR("Invalid context identifier %d!\n", context);
            break;
    }
    return c;
}

void kill_everything(char *domain_name)
{
    char cmd[128];

    sprintf(cmd, "sudo xm destroy %s", domain_name);
    system(cmd);

    system("sudo killall -9 ttd-deviced");

    kill(getpid(), SIGINT);
}

void probe_pagefault(unsigned long address,
                     int protection_fault,
                     int write_access,
                     int user_mode,
                     int reserved_bit,
                     int instr_fetch,
                     ctxprobes_task_t *task)
{
    unsigned long error_code;
    char error_str[128] = {0,};

    unsigned long long brctr = ctxprobes_get_brctr();
    if (!brctr)
    {
        ERR("Failed to get branch counter\n");
        return;
    }
                
    strcat(error_str, protection_fault ?
           "protection-fault, " : "no-page-found, ");
    strcat(error_str, write_access ?
           "write-access, " : "read-access, ");
    strcat(error_str, user_mode ?
           "user-mode, " : "kernel-mode, ");
    strcat(error_str, reserved_bit ?
           "reserved-bit, " : "");
    strcat(error_str, instr_fetch ?
           "instr-fetch, " : "");
    error_str[strlen(error_str)-2] = '\0';
    
    fflush(stderr);

    printf("%d (%s): Page fault: address = 0x%08lx, brctr = %lld, error = (%s)\n", 
           task->pid, task->comm, address, brctr, error_str);

    fflush(stdout);
}

void parse_opt(int argc, char *argv[])
{
    char ch;
    log_flags_t debug_flags;
    
    while ((ch = getopt(argc, argv, "dl:m:")) != -1)
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

