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
 *  examples/null-deref-analysis/null-deref-syscall.c
 *
 *  Record control flow for the process that changed the uid field at
 *  the granularity of a system call.
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

static char *syscall_file = NULL;
static unsigned long long brctr_root;
static unsigned int pid_root;

static unsigned int uid_at_call = 0;
static unsigned long long brctr_at_call;

void probe_syscall_call(char *symbol, 
                        ctxprobes_var_t *args,
                        int argcount,
                        ctxprobes_task_t *task,
                        ctxprobes_context_t context)
{
    DBG("%d (%s): call = %s, uid = %d, brctr = %lld\n", 
        task->pid, task->comm, symbol, task->uid, ctxprobes_get_brctr());
        
    if (task->pid == pid_root)
    {
        unsigned long long brctr = ctxprobes_get_brctr();
        if (!brctr)
        {
            ERR("Failed to get branch counter\n");
            return;
        }

        if (brctr < brctr_root)
        {
            uid_at_call = task->uid;
            brctr_at_call = brctr;
        }
        else
        {
            uid_at_call = 0;
            kill_everything(domain_name);
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
    DBG("%d (%s): return = %s, uid = %d, brctr = %lld\n", 
        task->pid, task->comm, symbol, task->uid, ctxprobes_get_brctr());

    if (task->pid == pid_root)
    {
        unsigned long long brctr = ctxprobes_get_brctr();
        if (!brctr)
        {
            ERR("Failed to get branch counter\n");
            return;
        }

        if (brctr >= brctr_root)
        {
            if (uid_at_call != task->uid)
            {
                fflush(stderr);
                if (concise)
                    printf("brctr=%lld, pid=%d, syscall=%s, olduid=%d, newuid=%d\n", 
                           brctr_at_call, task->pid, symbol, uid_at_call, task->uid);
                else
                    printf("TASK UID MODIFIED: %d -> %d "
                           "(BRCTR = %lld, PID = %d, SYSCALL = %s).\n",
                           uid_at_call, task->uid, 
                           brctr_at_call, task->pid, symbol);
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

int start_analysis(void)
{
    int ret;
    FILE *fp;
    char syscall[256];
    int count;

    fp = fopen(syscall_file, "r");
    if (!fp)
    {
        ERR("Could not open system call list file\n");
        return -2;
    }

    count = 0;
    while (fgets(syscall, 255, fp))
    {
        syscall[strlen(syscall)-1] = '\0';

        ret = ctxprobes_reg_func_call(syscall, probe_syscall_call);
        if (ret)
        {
            WARN("Failed to register probe on %s call. Skipping...\n",
                 syscall);
            continue;
        }

        ret = ctxprobes_reg_func_return(syscall, probe_syscall_return);
        if (ret)
        {
            WARN("Failed to register probe on %s return. Skipping...\n",
                 syscall);
            ctxprobes_unreg_func_call(syscall, probe_syscall_call);
            continue;
        }

        count++;
    }

    DBG("Total %d system calls instrumented\n", count);
    
    fclose(fp);
    return 0;
}

void probe_task_switch(ctxprobes_task_t *prev, ctxprobes_task_t *next)
{
    static int booted = 0;
    int ret;

    if (!booted && strcmp(next->comm, "getty") == 0)
    {
        fflush(stderr);
        printf("Replay session booted, press enter to run analysis: ");
        fflush(stdout);

        getchar();

        ret = start_analysis();
        if (ret)
            kill_everything(domain_name);

        booted = 1;
   }
}

void parse_opt(int argc, char *argv[])
{
    char ch;
    log_flags_t debug_flags;
    
    while ((ch = getopt(argc, argv, "dl:m:cib:p:s:")) != -1)
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

            case 's':
                syscall_file = optarg;
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
        ret = start_analysis();
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

