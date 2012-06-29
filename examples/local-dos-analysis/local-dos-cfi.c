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
 *  examples/local-dos-analysis/local-dos-cfi.c
 *
 *  PASS-3: Check CFI of the given system call, called by the process
 *  of the given pid.
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
#include <list.h>
#include <alist.h>
#include <ctxprobes.h>

#include "debug.h"
#include "util.h"

extern char *optarg;
extern int optind, opterr, optopt;

static char *domain_name = NULL; 
static int debug_level = -1; 
static char *sysmap_file = NULL;

static char *syscall_name = NULL;
static unsigned long long brctr_begin;
//static unsigned long long brctr_end;
static unsigned int pid_panic;

typedef struct funcinfo {
    char symbol[128];
    unsigned long ip;
    unsigned long startaddr;
    int task_uid;
    unsigned long long brctr;
} funcinfo_t;

static struct array_list *funcinfo_stack;

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

    if (task->pid == pid_panic)
    {
        unsigned long funcstart = 0;
        if (symbol)
            funcstart = ctxprobes_funcstart(symbol);

        char pad[128];
        int i, depth;

        while (1)
        {
            funcinfo_t *fi = (funcinfo_t *)array_list_remove(funcinfo_stack);
            if (!fi)
            {
                ERR("Call and return do not match!: %s (0x%08lx)\n", 
                    symbol, funcstart);
                //kill_everything(domain_name);
            }

            memset(pad, 0, sizeof(pad));
            depth = array_list_len(funcinfo_stack)+1;
            for (i = 0; i < depth; i++)
                strcat(pad, "  ");

            if (fi->startaddr == funcstart)
            {
                free(fi);
                break;
            }
            free(fi);
        }
        
        LOG("%s%s returned (ip = 0x%08lx)\n", pad, symbol, ip);
    }

    //if (brctr > brctr_end)
    //    kill_everything(domain_name);
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

    if (task->pid == pid_panic)
    {
        char pad[128] = {0,};
        int i, depth = array_list_len(funcinfo_stack)+1;
        for (i = 0; i < depth; i++)
            strcat(pad, "  ");

        funcinfo_t *fi = (funcinfo_t *)malloc(sizeof(funcinfo_t));
        memset(fi, 0, sizeof(funcinfo_t));
        fi->ip = ip;
        fi->brctr = brctr;

        if (symbol)
        {
            strcpy(fi->symbol, symbol);
            fi->startaddr = ctxprobes_funcstart(symbol);
        
            LOG("%s%s called (ip = 0x%08lx)\n", pad, symbol, ip);
        }
        else
        {
            LOG("%sUNKNOWN FUNCTION (0x%08lX) CALLED (BRCTR = %lld)\n", 
                   pad, ip, brctr);

            //kill_everything(domain_name);
        }
        array_list_add(funcinfo_stack, fi);
    }
}

void probe_suspected_syscall(char *symbol, 
                             ctxprobes_var_t *args,
                             int argcount,
                             ctxprobes_task_t *task,
                             ctxprobes_context_t context)
{
    int ret;

    unsigned long long brctr = ctxprobes_get_brctr();
    if (!brctr)
    {
        ERR("Failed to get branch counter\n");
        return;
    }

    if (brctr == brctr_begin)
    {
        LOG("%s called (brctr = %lld)\n", syscall_name, brctr);

        ret = ctxprobes_instrument_func(syscall_name, 
                                        probe_disfunc_call, 
                                        probe_disfunc_return);
        if (ret)
        {
            ERR("Failed to instrument function %s\n", syscall_name);
            exit(1);
        }
    }
}

int start_analysis(void)
{
    int ret;

    ret = ctxprobes_track(NULL, /* task switch handler */
                          NULL, /* context change handler */
                          NULL, /* page fault handler */
                          NULL); /* pid list */
    if (ret)
    {
        ERR("Could not start tracking contexts\n");
        return ret;
    }

    ret = ctxprobes_reg_func_call(syscall_name, probe_suspected_syscall);
    if (ret)
    {
        ERR("Failed to register probe on %s call\n", syscall_name);
        return ret;
    } 
    
    return 0;
}

void parse_opt(int argc, char *argv[])
{
    char ch;
    log_flags_t debug_flags;
    
    while ((ch = getopt(argc, argv, "dl:m:cib:e:p:s:")) != -1)
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

            case 'b':
                brctr_begin = atoll(optarg);
                break;

            //case 'e':
            //    brctr_end = atoll(optarg);
            //    break;

            case 'p':
                pid_panic = atoi(optarg);
                break;

            case 's':
                syscall_name = optarg;
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

    funcinfo_stack = array_list_create(64);

    ret = ctxprobes_init(domain_name, 
                         sysmap_file, 
                         debug_level);
    if (ret)
    {
        ERR("Could not initialize context-aware probes\n");
        exit(ret);
    }

    ret = start_analysis();
    if (ret)
    {
        ctxprobes_cleanup();
        exit(ret);
    }

    ctxprobes_wait();

    ctxprobes_cleanup();

    array_list_deep_free(funcinfo_stack);
    return 0;
}

