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
 *  examples/null-deref-analysis/null-deref-process.c
 *
 *  PASS-2: Find out which process of the given suspected pids
 *  modified the uid bit.
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

// FIXME: hard-coded task_struct offsets will be removed later.
#define TASK_UID_OFFSET (336)

extern char *optarg;
extern int optind, opterr, optopt;

static char *domain_name = NULL; 
static int debug_level = -1; 
static char *sysmap_file = NULL;
static int concise = 0;
static int interactive = 0;

static unsigned long long brctr_pwd;
static struct array_list *pidlist;
static struct array_list *tracklist;
static int old_uid;

void probe_task_uid_write(unsigned long addr,
                          char *ame,
                          ctxprobes_var_t *var,
                          ctxprobes_task_t *task,
                          ctxprobes_context_t context)
{
    int uid;

    unsigned long long brctr = ctxprobes_get_brctr();
    if (!brctr)
    {
        ERR("Failed to get branch counter\n");
        return;
    }

    if (brctr >= brctr_pwd)
    {
        kill_everything(domain_name);
        return;
    }

    uid = *(int *)var->buf;
    if (uid != old_uid)
    {
        fflush(stderr);
        if (concise)
            printf("brctr=%lld, pid=%d, olduid=%d, newuid=%d\n", 
                   brctr, task->pid, old_uid, uid);
        else
            printf("TASK UID MODIFIED: %d -> %d (PID = %d, BRCTR = %lld).\n", 
                   old_uid, uid, task->pid, brctr);
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

void probe_task_switch(ctxprobes_task_t *prev, ctxprobes_task_t *next)
{
    static int booted = 0;
    int ret;
    unsigned long addr;
    char *name;

    unsigned long long brctr = ctxprobes_get_brctr();
    if (!brctr)
    {
        ERR("Failed to get branch counter\n");
        return;
    }

    if (brctr >= brctr_pwd)
        kill_everything(domain_name);

    if (!booted && strcmp(next->comm, "getty") == 0)
    {
        fflush(stderr);
        printf("Replay session booted, press enter to proceed: ");
        fflush(stdout);

        getchar();

        booted = 1;
    }

    if (array_list_contains(pidlist, (void *)next->pid))
    {
        if (!array_list_contains(tracklist, (void *)next->pid))
        {
            /* 
             * First task switch to a suspected process, put it in the tracked
             * process list if it is with non-root uid. 
             */

            if (next->uid != 0)
            {
                if (interactive)
                {
                    fflush(stderr);
                    printf("Process %d (%s) is non-root, setting up a watchpoint...\n", 
                           next->pid, next->comm);
                    fflush(stdout);
                }

                old_uid = next->uid;

                addr = next->vaddr + TASK_UID_OFFSET;
                name = "schedule.next->uid";

                ret = ctxprobes_reg_var(addr, name, probe_task_uid_write, 0);
                if (ret)
                {
                    printf("Failed to register probe on %s\n", name);
                    return;
                }

                if (interactive)
                {
                    fflush(stderr);
                    printf("Watchpoint set up.\n");
                    fflush(stdout);
                }
            }
            
            array_list_add(tracklist, (void *)next->pid);
        }
    }
}

void parse_opt(int argc, char *argv[])
{
    char ch;
    log_flags_t debug_flags;
    
    while ((ch = getopt(argc, argv, "dl:m:cib:p:")) != -1)
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
                brctr_pwd = atoll(optarg);
                break;

            case 'p':
                array_list_parse(pidlist, optarg);
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
    
    pidlist = array_list_create(10);
    tracklist = array_list_create(10);

    parse_opt(argc, argv);

    if (interactive)
    {
        fflush(stderr);
        printf("Initializing VMI...\n");
        fflush(stdout);
    }

    ret = ctxprobes_init(domain_name, 
                         sysmap_file, 
                         probe_task_switch, 
                         NULL, /* context change handler */
                         NULL, /* page fault handler */
                         pidlist,
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
        printf("Running analysis while replay session is booting...\n");
        fflush(stdout);
    }

    ctxprobes_wait();

    ctxprobes_cleanup();

    if (pidlist)
        array_list_free(pidlist);
    if (tracklist)
        array_list_free(tracklist);
    return 0;
}

