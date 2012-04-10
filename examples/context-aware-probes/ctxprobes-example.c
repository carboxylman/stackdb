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
 *  examples/context-aware-probes/ctxprobes-example.c
 *
 *  An example code to demonstrate how to use context-aware probes.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <log.h>

#include "ctxprobes.h"
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

void sys_open_prologue(char *symbol, 
                       unsigned long retaddr,
                       ctxprobes_task_t *task,
                       ctxprobes_context_t context)
{
    printf("[%c] %d (%s): %s proloque invoked\n", 
           context_ch(context), task->pid, task->comm, symbol);
    
    printf("- Return address: 0x%08x\n", retaddr);
/*
    printf("- Parent task chain: \n");
    while (task->parent)
    {
        printf("  %d (%s)\n", task->parent->pid, task->parent->comm);
        task = task->parent;
    }*/
}

void sys_open_call(char *symbol, 
                   ctxprobes_var_t *args, 
                   int argcount, 
                   ctxprobes_task_t *task,
                   ctxprobes_context_t context)
{
    if (!args || argcount < 3)
        printf("[%c] %d (%s): %s called, but failed to load args\n", 
               context_ch(context), task->pid, task->comm, symbol);
    else
        printf("[%c] %d (%s): %s(%s=%s, %s=0x%x, %s=0x%x)\n", 
               context_ch(context), task->pid, task->comm, symbol,
               args[0].name, args[0].buf,
               args[1].name, *(int *)args[1].buf,
               args[2].name, *(int *)args[2].buf);
/*    
    printf("- Parent task chain: \n");
    while (task->parent)
    {
        printf("  %d (%s)\n", task->parent->pid, task->parent->comm);
        task = task->parent;
    }*/
}

void sys_open_return(char *symbol, 
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

    printf("- Return address: 0x%08x\n", retaddr);
/*
    printf("- Parent task chain: \n");
    while (task->parent)
    {
        printf("  %d (%s)\n", task->parent->pid, task->parent->comm);
        task = task->parent;
    }*/
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
                    fprintf(stderr, "ERROR: bad debug flag in '%s'!\n", optarg);
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

    ret = ctxprobes_init(domain_name, sysmap_file, debug_level);
    if (ret)
    {
        fprintf(stderr, "failed to init ctxprobes\n");
        exit(1);
    }

    ret = ctxprobes_func_prologue("sys_open", sys_open_prologue);
    if (ret)
    {
        fprintf(stderr, "failed to register probe on sys_open prologue\n");
        exit(1);
    }

    ret = ctxprobes_func_call("sys_open", sys_open_call);
    if (ret)
    {
        fprintf(stderr, "failed to register probe on sys_open call\n");
        exit(1);
    }

    ret = ctxprobes_func_return("sys_open", sys_open_return);
    if (ret)
    {
        fprintf(stderr, "failed to register probe on sys_open return\n");
        exit(1);
    }

    printf("Starting instrumentation ...\n");
    ctxprobes_wait();

    ctxprobes_cleanup();
    return 0;
}

