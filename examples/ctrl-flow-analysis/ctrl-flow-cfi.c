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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>

#include <log.h>
#include <list.h>
#include <alist.h>

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
static unsigned int pid_root;

typedef struct funcinfo {
    char symbol[128];
    unsigned long ip;
    unsigned long startaddr;
    int task_uid;
} funcinfo_t;

static struct array_list *funcinfo_stack;

void kill_everything(char *domain_name)
{
    char cmd[128];

    sprintf(cmd, "sudo xm destroy %s", domain_name);
    system(cmd);

    system("sudo killall -9 ttd-deviced");

    kill(getpid(), SIGINT);
}

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

    if (task->pid == pid_root)
    {
        unsigned long funcstart = 0;
        if (symbol)
            funcstart = ctxprobes_funcstart(symbol);
        else
            symbol = "unknown function";

        char pad[128];
        int i, len;

        while (1)
        {
            funcinfo_t *fi = (funcinfo_t *)array_list_remove(funcinfo_stack);
            if (!fi)
            {
                ERR("Call and return do not match!: %s (0x%08lx)\n", 
                    symbol, funcstart);
                kill_everything(domain_name);
            }

            memset(pad, 0, sizeof(pad));
            len = array_list_len(funcinfo_stack);
            for (i = 0; i < len; i++)
                strcat(pad, "  ");

            if (fi->startaddr == funcstart)
            {
                free(fi);
                break;
            }
            else
            {
                fflush(stderr);
                printf("%s%s (0x%08lx) virtually returned (uid = ?)\n",
                       pad, fi->symbol, fi->startaddr);
                fflush(stdout);

                free(fi);
            }
        }
        
        fflush(stderr);
        printf("%s%s (0x%08lx) returned (uid = %d)\n",
               pad, symbol, funcstart, task->uid);
        fflush(stdout);
    }
    
    if (brctr > brctr_end)
        kill_everything(domain_name);
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

    if (task->pid == pid_root)
    {
        char pad[128] = {0,};
        int i, len = array_list_len(funcinfo_stack);
        for (i = 0; i < len; i++)
            strcat(pad, "  ");

        funcinfo_t *fi = (funcinfo_t *)malloc(sizeof(funcinfo_t));
        memset(fi, 0, sizeof(funcinfo_t));
        fi->ip = ip;
        fi->task_uid = task->uid;
        if (symbol)
        {
            strcpy(fi->symbol, symbol);
            fi->startaddr = ctxprobes_funcstart(symbol);
        }
        else
            strcpy(fi->symbol, "unknown function");
        array_list_add(funcinfo_stack, fi);

        fflush(stderr);
        printf("%s%s (0x%08lx) called (uid = %d)\n",
               pad, fi->symbol, fi->startaddr, fi->task_uid);
        fflush(stdout);
    }
}

void probe_syscall_call(char *symbol, 
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
        fflush(stderr);
        printf("%s called at brctr %lld. Start checking CFI!\n", 
               syscall_name, brctr);
        fflush(stdout);

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

void parse_opt(int argc, char *argv[])
{
    char ch;
    log_flags_t debug_flags;
    
    while ((ch = getopt(argc, argv, "dl:m:s:p:b:e:")) != -1)
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

            case 's':
                syscall_name = optarg;
                break;

            case 'p':
                pid_root = atoi(optarg);
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

    funcinfo_stack = array_list_create(64);

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

    ctxprobes_wait();

    ctxprobes_cleanup();

    array_list_deep_free(funcinfo_stack);
    return 0;
}

