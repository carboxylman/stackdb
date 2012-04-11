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
 *  examples/ctrl-flow-analysis/ctrl-flow-dynamic.c
 *
 *  Dynamic security analysis to detect abnormal control flows of Linux 
 *  kernel instrumenting suspected kernel function on the fly.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

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
static char *funclist_file = NULL;

static char *proc_name = "linux-sendpage-static";
static unsigned long oldretaddr;

void probe_func_call(char *symbol, 
                     unsigned long retaddr,
                     ctxprobes_task_t *task,
                     ctxprobes_context_t context)
{
    if (strcmp(task->comm, proc_name) == 0)
    {
        printf("%d (%s): 0x%08lx -> %s\n", 
               task->pid, task->comm, retaddr, symbol);
        oldretaddr = retaddr;
    }
}

void probe_func_return(char *symbol, 
                       ctxprobes_var_t *args, 
                       int argcount, 
                       ctxprobes_var_t *retval,
                       unsigned long retaddr,
                       ctxprobes_task_t *task,
                       ctxprobes_context_t context)
{
    if (strcmp(task->comm, proc_name) == 0)
    {
        printf("%d (%s): %s -> 0x%08lx\n", 
               task->pid, task->comm, symbol, retaddr);
        if (oldretaddr != retaddr)
            printf("Abnormal control flow!: oldaddr=0x%08lx, newaddr=0x%08lx\n",
                   oldretaddr, retaddr);
    }
}

void parse_opt(int argc, char *argv[])
{
    char ch;
    log_flags_t debug_flags;
    
    while ((ch = getopt(argc, argv, "dl:m:f:")) != -1)
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

            case 'f':
                funclist_file = optarg;
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
    static FILE *fp;
    char funcname[256];
    int count, ret;
    
    parse_opt(argc, argv);

    fp = fopen(funclist_file, "r");
    if (!fp)
    {
        ERR("Could not open function list file\n");
        return -2;
    }

    ret = ctxprobes_init(domain_name, sysmap_file, debug_level);
    if (ret)
    {
        fprintf(stderr, "failed to init ctxprobes\n");
        exit(1);
    }

    /*
     * Start analysis by observing all system calls called by a process 
     * named as "linux-sendpage-static".
     */

    count = 0;
    while (fgets(funcname, 255, fp))
    {
        funcname[strlen(funcname)-1] = '\0';

        ret = ctxprobes_reg_func_prologue(funcname, probe_func_call);
        if (ret)
        {
            WARN("Failed to register probe on %s call. Skipping...\n", 
                 funcname);
            continue;
        }

        ret = ctxprobes_reg_func_return(funcname, probe_func_return);
        if (ret)
        {
            WARN("Failed to register probe on %s return. Skipping...\n", 
                 funcname);
            ctxprobes_unreg_func_prologue(funcname, probe_func_call);
            continue;
        }

        count++;
    } 

    printf("Total %d functions registered. Starting instrumentation...\n",
           count);
    ctxprobes_wait();

    ctxprobes_cleanup();
    fclose(fp);
    return 0;
}

