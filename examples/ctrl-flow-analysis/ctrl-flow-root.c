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
 *  examples/ctrl-flow-analysis/ctrl-flow-passwd.c
 *
 *  Determine where the process of the given pid became root.
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

static struct array_list *pidlist;
static unsigned long long brctr_pwd;

static struct array_list *tracklist;

int alist_contains(struct array_list *list, unsigned int pid)
{
    int i;
    unsigned int tmp;

    for (i = 0; i < array_list_len(list); i++)
    {
        tmp = (unsigned int)array_list_item(list, i);
        if (tmp == pid)
            return 1;
    }

    return 0;
}

void task_switch(ctxprobes_task_t *prev, ctxprobes_task_t *next)
{
    unsigned long long brctr = ctxprobes_get_brctr();
    if (!brctr)
    {
        ERR("Failed to get branch counter\n");
        return;
    }

    if (brctr >= brctr_pwd)
    {
        fflush(stderr);
        printf("End of analysis: /etc/passwd accessed\n");
        fflush(stdout);
            
        //kill(getpid(), SIGINT);
        return;
    }

    if (alist_contains(pidlist, next->pid))
    {
        if (!alist_contains(tracklist, next->pid))
        {
            /* 
             * First task switch to a suspected process, put it in the tracked
             * process list if it is with non-root uid. 
             */
            array_list_add(tracklist, (void *)next->pid);
            fflush(stderr);
            printf("First task switch to %d (%s): uid = %d\n",
                   next->pid, next->comm, next->uid);
            fflush(stdout);

            if (next->uid != 0)
            {
                /* Put a watch-point at next->uid. */
                fflush(stderr);
                printf("Put a watch-point at uid of %d (%s)\n", 
                       next->pid, next->comm);

                fflush(stdout);
            }
        }
    }
}

void parse_pidlist(char *pidlist_str)
{
    char *pid_str = NULL;
    char *ptr = NULL;
    unsigned int pid;

    while ((pid_str = strtok_r(!ptr ? pidlist_str : NULL, ",", &ptr))) 
    {
        pid = atoi(pid_str);
        array_list_prepend(pidlist, (void *)pid);
    }
}

void parse_opt(int argc, char *argv[])
{
    char ch;
    log_flags_t debug_flags;
    
    while ((ch = getopt(argc, argv, "dl:m:p:b:")) != -1)
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

            case 'p':
                parse_pidlist(optarg);
                break;

            case 'b':
                brctr_pwd = atoll(optarg);
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
    
    pidlist = array_list_create(10);
    tracklist = array_list_create(10);

    parse_opt(argc, argv);

    ret = ctxprobes_init(domain_name, 
                         sysmap_file, 
                         task_switch, 
                         NULL, 
                         debug_level);
    if (ret)
    {
        ERR("Failed to init ctxprobes\n");
        exit(ret);
    }
/*
    ret = ctxprobes_reg_func_return("sys_fork", probe_fork_return);
    if (ret)
    {
        ERR("Failed to register probe on sys_fork return\n");
        ctxprobes_cleanup();
        exit(ret);
    } 
*/
    ctxprobes_wait();

    ctxprobes_cleanup();

    if (pidlist)
        array_list_free(pidlist);
    if (tracklist)
        array_list_free(tracklist);
    return 0;
}

