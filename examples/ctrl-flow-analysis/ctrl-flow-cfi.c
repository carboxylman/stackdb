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
 *  examples/ctrl-flow-analysis/ctrl-flow-cfi.c
 *
 *  CFI check on syscall in question.
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

static char *syscall_name = NULL;
static unsigned long long brctr_begin;
static unsigned long long brctr_end;

void probe_disfunc_return(char *symbol,
        unsigned long ip,
        ctxprobes_task_t *task,
        ctxprobes_context_t context)
{
    unsigned long long brctr = ctxprobes_get_brctr();
    if (!brctr)
    {
        ERR("Failed to get branch counter\n");
        return;
    }

    fflush(stderr);
    printf("%d (%s): disfunc %s (0x%08lx) called, uid: %d\n",
            task->pid, task->comm, symbol, ip, task->uid);
    fflush(stdout);
}

void probe_disfunc_call(char *symbol,
        unsigned long ip,
        ctxprobes_task_t *task,
        ctxprobes_context_t context)
{
    unsigned long long brctr = ctxprobes_get_brctr();
    if (!brctr)
    {
        ERR("Failed to get branch counter\n");
        return;
    }

    fflush(stderr);
    printf("%d (%s): disfunc %s (0x%08lx) returned, uid: %d\n",
            task->pid, task->comm, symbol, ip, task->uid);
    fflush(stdout);
}

void probe_syscall_call(char *symbol, 
                        ctxprobes_var_t *args,
                        int argcount,
                        ctxprobes_task_t *task,
                        ctxprobes_context_t context)
{
    unsigned long long brctr = ctxprobes_get_brctr();
    if (!brctr)
    {
        ERR("Failed to get branch counter\n");
        return;
    }

    if (brctr == brctr_begin)
    {
        fflush(stderr);
        printf("%s called at brctr %d: start checking CFI\n: ", syscall_name, brctr);
        fflush(stdout);

        ret = ctxprobes_instrument_func(syscall_name, disfunc_call, disfunc_return);
        if (ret)
        {
            ERR("Failed to instrument function %s\n", syscall_name);
            exit(1);
        }
    }

}

void probe_syscall_return(char *symbol,
                          ctxprobes_var_t *args,
                          int argcount,
                          ctxprobes_var_t *retval,
                          unsigned long retaddr,
                          ctxprobes_task_t *task,
                          ctxprobes_context_t context)
{
    unsigned long long brctr = ctxprobes_get_brctr();
    if (!brctr)
    {
        ERR("Failed to get branch counter\n");
        return;
    }

    if (brctr == brctr_end)
    {
        fflush(stderr);
        printf("%s returned at brctr %d: end of analysis\n", syscall_name, brctr);
        fflush(stdout);
    }
}

void parse_opt(int argc, char *argv[])
{
    char ch;
    log_flags_t debug_flags;
    
    while ((ch = getopt(argc, argv, "dl:m:s:b:e:")) != -1)
    {
        switch(ch)
        {
            case 'd':
                ++debug_level;
                break;

            case 'l':
                if (vmi_log_get_flag_mask(optarg, &debug_flags))
                {
                    printf(stderr, "ERROR: bad debug flag in '%s'!\n", 
                            optarg);
                    exit(-1);
                }
                vmi_set_log_flags(debug_flags);
                break;

            case 'm':
                sysmap_file = optarg;
                break;

            case 's':
                syscall_name = optarg;
                break;

            case 'b':
                brctr_begin = atoll(optarg);
                break;

            case 'e':
                brctr_end = atoll(optarg);
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

    ret = ctxprobes_init(domain_name, sysmap_file, NULL, NULL, debug_level);
    if (ret)
    {
        ERR("Failed to init ctxprobes\n");
        exit(ret);
    }

    ret = ctxprobes_reg_func_call(syscall_name, probe_syscall_call);
    if (ret)
    {
        ERR("Failed to register probe on %s call\n", syscall_name);
        ctxprobes_cleanup();
        exit(ret);
    } 

    ret = ctxprobes_reg_func_return(syscall_name, probe_syscall_return);
    if (ret)
    {
        ERR("Failed to register probe on %s return\n", syscall_name);
        exit(1);
    }

    ctxprobes_wait();

    ctxprobes_cleanup();
    return 0;
}

