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

extern char *optarg;
extern int optind, opterr, optopt;

static char *domain_name = NULL; 
static int debug_level = -1; 
static char *sysmap_file = NULL;

void sys_open_call(char *symbol, 
                   var_t *args, 
                   int argcount, 
                   task_t *task)
{
    if (!args || argcount < 3)
        printf("%d (%s): %s called, but failed to load args\n", 
               task->pid, task->comm, symbol);
    else
        printf("%d (%s): %s(%s=%s, %s=0x%x, %s=0x%x)\n", 
               task->pid, task->comm,
               symbol,
               args[0].name, args[0].buf,
               args[1].name, *(int *)args[1].buf,
               args[2].name, *(int *)args[2].buf);
    
    printf("- Parent task chain: \n");
    while (task->parent)
    {
        printf("  %d (%s)\n", task->parent->pid, task->parent->comm);
        task = task->parent;
    }
}

void sys_open_return(char *symbol, 
                     var_t *args, 
                     int argcount, 
                     var_t retval,
                     task_t *task)
{
    printf("%d (%s): %s returned\n", task->pid, task->comm, symbol);
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

    ret = ctxprobes_func_call("sys_open", sys_open_call);
    if (ret)
    {
        fprintf(stderr, "failed to register probe on sys_open call\n");
        exit(1);
    }

    //ret = ctxprobes_func_return("sys_open", sys_open_return);
    //if (ret)
    //{
    //    fprintf(stderr, "failed to register probe on sys_open return\n");
    //    exit(1);
    //}

    printf("Starting instrumentation ...\n");
    ctxprobes_wait();

    ctxprobes_cleanup();
    return 0;
}

