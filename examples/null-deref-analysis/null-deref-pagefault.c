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
 *  PASS-5: List page faults raised by the process of the given pid.
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
static int interactive = 0;

static unsigned long long brctr_root;
static unsigned int pid_root;
static unsigned long addr_root;

void probe_pagefault(unsigned long ip,
                     unsigned long address,
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
                printf("brctr=%lld, pid=%d, address=0x%08lx, ip=0x%08lx"
                       "protection=%d, write=%d, user=%d\n", 
                       brctr, task->pid, address, ip,
                       protection_fault, write_access, user_mode);
                fflush(stdout);
            }

            if (address == addr_root && write_access)
            {
                if (!concise)
                {
                    capitalize(desc);
                    
                    fflush(stderr);
                    printf("PAGE FAULT AT 0x%08lX "
                           "(%s, PID = %d, IP = 0x%08lX, BRCTR = %lld)\n", 
                           address, desc, task->pid, ip, brctr);
                    fflush(stdout);
                }
                
                if (interactive)
                {
                    fflush(stderr);
                    printf("Analysis completed, press enter to end replay session: ");
                    fflush(stdout);
                    
                    getchar();
                }

                kill_everything(domain_name);
            }
            else
            {
                if (!concise)
                {
                    fflush(stderr);
                    printf("Page fault at 0x%08lx (%s, pid = %d, ip = 0x%08lx)\n", 
                           address, desc, task->pid, ip);
                    fflush(stdout);
                }
            }
        }
    }
}

void probe_execve(char *symbol,
                  ctxprobes_var_t *args,
                  int argcount,
                  ctxprobes_task_t *task,
                  ctxprobes_context_t context)
{
    static int booted = 0;
    int ret;
    char *filename = args[0].buf;
    
    if (!booted && strcmp(filename, "/sbin/getty") == 0)
    {
        fflush(stderr);
        printf("Replay session booted, press enter to run analysis: ");
        fflush(stdout);

        getchar();

        booted = 1;
   }
}

void parse_opt(int argc, char *argv[])
{
    char ch;
    log_flags_t debug_flags;
    
    while ((ch = getopt(argc, argv, "dl:m:cib:p:a:")) != -1)
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

            case 'c':
                concise = 1;
                break;

            case 'i':
                interactive = 1;
                break;

            case 'b':
                brctr_root = atoll(optarg);
                break;

            case 'p':
                pid_root = atoi(optarg);
                break;

            case 'a':
                sscanf(optarg, "%lx", &addr_root);
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

    if (interactive)
    {
        fflush(stderr);
        printf("Initializing VMI...\n");
        fflush(stdout);
    }

    ret = ctxprobes_init(domain_name, 
                         sysmap_file, 
                         debug_level);
    if (ret)
    {
        ERR("Could not initialize context-aware probes\n");
        exit(ret);
    }

    ret = ctxprobes_track(NULL, /* task switch handler */
                          NULL, /* context change handler */
                          probe_pagefault,
                          NULL); /* pid list */
    if (ret)
    {
        ERR("Could not start tracking contexts\n");
        exit(ret);
    }

    if (interactive)
    {
        ret = ctxprobes_reg_func_call("do_execve", probe_execve);
        if (ret)
        {
            ERR("Failed to register probe on sys_execve.call\n");
            return ret;
        }

        fflush(stderr);
        printf("VMI initialized.\n");
        printf("Waiting for replay session to be booted...\n");
        fflush(stdout);
    }

    ctxprobes_wait();

    ctxprobes_cleanup();
    return 0;
}

