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
 *  examples/ctrl-flow-analysis/ctrl-flow-static.c
 *
 *  Static security analysis to detect abnormal control flows of Linux 
 *  kernel instrumenting all sys_* functions.
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

void probe_func_call(char *symbol, 
                     unsigned long retaddr,
                     ctxprobes_task_t *task,
                     ctxprobes_context_t context)
{
    printf("[%c] %d (%s): %s proloque invoked\n", 
           context_ch(context), task->pid, task->comm, symbol);
    
    printf("- Return address: 0x%08lx\n", retaddr);

    printf("- Parent task chain: \n");
    while (task->parent)
    {
        printf("  %d (%s)\n", task->parent->pid, task->parent->comm);
        task = task->parent;
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
    if (!retval)
        printf("[%c] %d (%s): %s returned, but failed to load retval\n", 
               context_ch(context), task->pid, task->comm, symbol);
    else
        printf("[%c] %d (%s): %s returned %d (0x%x)\n", 
               context_ch(context), task->pid, task->comm, symbol,
               *(int *)retval->buf, *(int *)retval->buf);

    printf("- Return address: 0x%08lx\n", retaddr);

    printf("- Parent task chain: \n");
    while (task->parent)
    {
        printf("  %d (%s)\n", task->parent->pid, task->parent->comm);
        task = task->parent;
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
            ctxprobes_unreg_func_return(funcname, probe_func_return);
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

