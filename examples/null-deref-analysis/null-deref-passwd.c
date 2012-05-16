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
 *  examples/null-deref-analysis/null-deref-passwd.c
 *
 *  Detect write access to /etc/passwd and return the task uid and
 *  the branch counter.
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

#define O_WRONLY (00000001)
#define O_RDWR   (00000002)

extern char *optarg;
extern int optind, opterr, optopt;

static char *domain_name = NULL; 
static int debug_level = -1; 
static char *sysmap_file = NULL;
static int concise = 0;
static int interactive = 0;

void probe_fileopen(char *symbol, 
                    ctxprobes_var_t *args,
                    int argcount,
                    ctxprobes_task_t *task,
                    ctxprobes_context_t context)
{
    if (!args || argcount < 3)
    {
        ERR("Something wrong with argument loading!\n");
        return;
    }

    char *filename = args[0].buf;
    int flags = *(int *)args[1].buf;

    if (context == CTXPROBES_CONTEXT_NORMAL)
    {
        if (strcmp(filename, "/etc/passwd") == 0)
        {
            if ((flags & O_WRONLY) || (flags & O_RDWR))
            {
                unsigned long long brctr = ctxprobes_get_brctr();
                if (!brctr)
                {
                    ERR("Failed to get branch counter\n");
                    return;
                }
                
                char pids_str[256] = {0,};
                while (task)
                {
                    sprintf(pids_str+strlen(pids_str), "%d,", 
                            task->pid);
                    task = task->parent;
                }
                pids_str[strlen(pids_str)-1] = '\0';

                fflush(stderr);
                if (concise)
                {
                    printf("brctr=%lld\n", brctr);
                    printf("pids=%s\n", pids_str);
                }
                else
                {
                    printf("PASSWORD FILE OPENED WITH WRITE ACCESS "
                           "(BRCTR = %lld, PIDS = %s).\n", brctr, pids_str);
                }
                fflush(stdout);

                if (interactive)
                {
                    fflush(stderr);
                    printf("Analysis completed, press enter to end replay session: ");
                    fflush(stdout);
                    
                    getchar();
                }

                kill_everything(domain_name);
            }
        }
    }
}

int register_probes(void)
{
    int ret;

    ret = ctxprobes_reg_func_call("sys_open", probe_fileopen);
    if (ret)
    {
        ERR("Failed to register probe on sys_open.call\n");
        return ret;
    } 

    return 0;
}

void probe_task_switch(ctxprobes_task_t *prev, ctxprobes_task_t *next)
{
    static int logged_in = 0;
    int ret;

    if (!logged_in && strcmp(next->comm, "getty") == 0)
    {
        fflush(stderr);
        printf("Replay session booted, press enter to run analysis: ");
        fflush(stdout);

        getchar();

        ret = register_probes();
        if (ret)
            kill_everything(domain_name);

        logged_in = 1;
   }
}

void parse_opt(int argc, char *argv[])
{
    char ch;
    log_flags_t debug_flags;
    
    while ((ch = getopt(argc, argv, "dl:m:ci")) != -1)
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

            case 'c':
                concise = 1;
                break;
            
            case 'i':
                interactive = 1;
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
    ctxprobes_task_switch_handler_t task_switch_handler = NULL;
    
    parse_opt(argc, argv);

    if (interactive)
    {
        task_switch_handler = probe_task_switch;
    
        fflush(stderr);
        printf("Initializing VMI...\n");
        fflush(stdout);
    }

    ret = ctxprobes_init(domain_name, 
                         sysmap_file, 
                         task_switch_handler,
                         NULL, /* context change handler */
                         NULL, /* page fault handler */
                         debug_level);
    if (ret)
    {
        ERR("Could not initialize context-aware probes\n");
        exit(ret);
    }

    if (interactive)
    {
        fflush(stderr);
        printf("VMI initialized.\n");
        printf("Waiting for replay session to be booted...\n");
        fflush(stdout);
    }
    else
    {
        ret = register_probes();
        if (ret)
        {
            ctxprobes_cleanup();
            exit(ret);
        }
    }

    ctxprobes_wait();

    ctxprobes_cleanup();
    return 0;
}

