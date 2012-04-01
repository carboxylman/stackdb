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

#include <argp.h>
#include <stdio.h>
#include <stdlib.h>

#include "ctxprobes.h"

char *domain_name = NULL; 
int verbose = 0; 

void sys_open_call(task_t *task, var_t *args, int argcount)
{
    if (argcount != 3)
        fprintf(stderr, "%d (%s):\tsys_open args are not three but %d!\n", 
               task->pid, task->comm, argcount);
    else
        printf("%d (%s):\tsys_open(%s=%s, %s=0x%08x, %s=0x%08x)\n", 
               task->pid, task->comm,
               args[0].name, args[0].buf,
               args[1].name, *(int *)args[1].buf,
               args[2].name, *(int *)args[2].buf);
}

void sys_open_return(task_t *task, var_t *args, int argcount, var_t retval)
{
    printf("sys_open returned\n");
}

/* command parser for GNU argp - see  GNU docs for more info */
error_t cmd_parser(int key, char *arg, struct argp_state *state)
{
    /*settings_t *setup = (settings_t *)state->input;*/

    switch (key)
    {
        case 'm': 
            domain_name = arg;
            break;

        case 'v': 
            verbose = 1; 
            break;

        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

const struct argp_option cmd_opts[] =
{
    { .name = "domain-name",  .key = 'm', .arg = "FILE",  .flags = 0,
      .doc = "Domain name" },

    { .name = "verbose",  .key = 'v', .arg = 0, .flags = 0, 
      .doc = "Verbose" },

    {0,}
};

const struct argp parser_def =
{
    .options = cmd_opts,
    .parser = cmd_parser,
    .doc = "An example program to show how to use context-aware probes"
};

const char *argp_program_version     = "ctxprobes-example v0.1";
const char *argp_program_bug_address = "<chunghwn@cs.utah.edu>";

int main(int argc, char *argv[])
{
    int ret, debug_level = -1;

    argp_parse(&parser_def, argc, argv, 0, 0, NULL);
    if (verbose) debug_level = 8;

    ret = ctxprobes_init(domain_name, debug_level);
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
#if 0
    ret = ctxprobes_func_return("sys_open", sys_open_return);
    if (ret)
    {
        fprintf(stderr, "failed to register probe on sys_open return\n");
        exit(1);
    }
#endif
    ctxprobes_wait();

    ctxprobes_cleanup();
    return 0;
}

