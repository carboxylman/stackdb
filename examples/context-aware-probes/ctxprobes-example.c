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
#include <list.h>
#include <alist.h>

#include "ctxprobes.h"

#define TASK_UID_OFFSET (336)

extern char *optarg;
extern int optind, opterr, optopt;

static char *domain_name = NULL; 
static int debug_level = -1; 
static int xa_debug_level = -1; 
static char *sysmap_file = NULL;

static struct array_list *tasklist;

int array_list_contains(struct array_list *list, void *item)
{
    int i;
    void *tmp;

    for (i = 0; i < array_list_len(list); i++)
    {
        tmp = array_list_item(list, i);
        if (tmp == item)
            return 1;
    }

    return 0;
}

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
            verror("Invalid context identifier %d!\n", context);
            break;
    }
    return c;
}

char *context_str(ctxprobes_context_t context)
{
    char *str;
    switch (context) {
        case CTXPROBES_CONTEXT_NORMAL:
            str = "Normal";
            break;
        case CTXPROBES_CONTEXT_TRAP:
            str = "Trap";
            break;
        case CTXPROBES_CONTEXT_INTERRUPT:
            str = "Interrupt";
            break;
        default:
            str = "Unknown";
            verror("Invalid context identifier %d!\n", context);
            break;
    }
    return str;
}

void task_uid_modified(unsigned long addr,
                       char *name,
                       ctxprobes_var_t *var,
                       ctxprobes_task_t *task,
                       ctxprobes_context_t context)
{
    fflush(stderr);
    printf("Task uid modified: new value = %d\n", *(int *)var->buf);
}

void task_switch(ctxprobes_task_t *prev, ctxprobes_task_t *next)
{
    //int ret;
    //unsigned long addr;
    //char *name;

    fflush(stderr);
    
    printf("Task switch: %d (%s) -> %d (%s)\n",
           prev->pid, prev->comm, next->pid, next->comm);
/*
    if (!array_list_contains(tasklist, (void *)next->vaddr))
    {
        addr = next->vaddr + TASK_UID_OFFSET;
        name = "schedule.next->uid"; 

        ret = ctxprobes_reg_var(addr,
                                name, 
                                task_uid_modified, 
                                0);
        if (ret)
        {
            verror("Failed to register probe on %s\n", name);
            return;
        }
        
        array_list_add(tasklist, (void *)next->vaddr);
        
        printf("Probe registered on %s (0x%08lx)\n", name, addr);
    }
*/    
    fflush(stdout);
}

void context_change(ctxprobes_context_t prev, 
                    ctxprobes_context_t next,
                    ctxprobes_task_t *task)
{
    fflush(stderr);
    
    printf("%d (%s): Context change: %s -> %s\n",
           task->pid, task->comm, context_str(prev), context_str(next));
    
    fflush(stdout);
}

void page_fault(unsigned long ip,
                unsigned long address,
                int protection_fault,
                int write_access,
                int user_mode,
                int reserved_bit,
                int instr_fetch,
                ctxprobes_task_t *task)
{
    char error_str[128] = {0,};
    
    strcat(error_str, protection_fault ?
           "protection-fault, " : "no-page-found, ");
    strcat(error_str, write_access ?
           "write-access, " : "read-access, ");
    strcat(error_str, user_mode ?
           "user-mode, " : "kernel-mode, ");
    strcat(error_str, reserved_bit ?
           "reserved-bit, " : "");
    strcat(error_str, instr_fetch ?
           "instr-fetch, " : "");
    error_str[strlen(error_str)-2] = '\0';
    
    fflush(stderr);

    printf("%d (%s): Page fault: ip = 0x%08lx, address = 0x%08lx, error = (%s)\n", 
           task->pid, task->comm, ip, address, error_str);

    fflush(stdout);
}

void sys_open_prologue(char *symbol, 
                       unsigned long retaddr,
                       ctxprobes_task_t *task,
                       ctxprobes_context_t context)
{
    fflush(stderr);
    
    printf("[%c] %d (%s): %s proloque invoked\n", 
           context_ch(context), task->pid, task->comm, symbol);
    
    printf("- Return address: 0x%08lx\n", retaddr);

    printf("- Parent task chain: \n");
    while (task->parent)
    {
        printf("  %d (%s)\n", task->parent->pid, task->parent->comm);
        task = task->parent;
    }
    
    fflush(stdout);
}

void sys_open_call(char *symbol, 
                   ctxprobes_var_t *args, 
                   int argcount, 
                   ctxprobes_task_t *task,
                   ctxprobes_context_t context)
{
    fflush(stderr);
    
    if (!args || argcount < 3)
        printf("[%c] %d (%s): %s called, but failed to load args\n", 
               context_ch(context), task->pid, task->comm, symbol);
    else
        printf("[%c] %d (%s): %s(%s=%s, %s=0x%x, %s=0x%x)\n", 
               context_ch(context), task->pid, task->comm, symbol,
               args[0].name, args[0].buf,
               args[1].name, *(int *)args[1].buf,
               args[2].name, *(int *)args[2].buf);
    
    printf("- Parent task chain: \n");
    while (task->parent)
    {
        printf("  %d (%s)\n", task->parent->pid, task->parent->comm);
        task = task->parent;
    }
    
    fflush(stdout);
}

void sys_open_return(char *symbol, 
                     ctxprobes_var_t *args, 
                     int argcount, 
                     ctxprobes_var_t *retval,
                     unsigned long retaddr,
                     ctxprobes_task_t *task,
                     ctxprobes_context_t context)
{
    fflush(stderr);

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

    fflush(stdout);
}

void disfunc_return(char *symbol,
                    unsigned long ip,
                    ctxprobes_task_t *task,
                    ctxprobes_context_t context)
{
    fflush(stderr);
    
    printf("%d (%s): disfunc %s (0x%08lx) called\n", 
           task->pid, task->comm, symbol, ip);    

    fflush(stdout);
}

void disfunc_call(char *symbol,
                  unsigned long ip,
                  ctxprobes_task_t *task,
                  ctxprobes_context_t context)
{
    fflush(stderr);

    printf("%d (%s): disfunc %s (0x%08lx) returned\n", 
           task->pid, task->comm, symbol, ip);    
    
    fflush(stdout);
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

            case 'x':
                ++xa_debug_level;
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

    tasklist = array_list_create(100);

    parse_opt(argc, argv);

    ret = ctxprobes_init(domain_name, 
                         sysmap_file, 
                         debug_level,
			 xa_debug_level);
    if (ret)
    {
        fprintf(stderr, "failed to init ctxprobes\n");
        exit(ret);
    }

    ret = ctxprobes_track(NULL,//task_switch, 
                          NULL,//context_change,
                          page_fault,
                          NULL); /* pidlist */
    if (ret)
    {
        fprintf(stderr, "failed to start tracking contexts\n");
        exit(ret);
    }
/*
    ret = ctxprobes_reg_func_prologue("sys_open", sys_open_prologue);
    if (ret)
    {
        fprintf(stderr, "failed to register probe on sys_open prologue\n");
        exit(1);
    }
*/
    ret = ctxprobes_reg_func_call("sys_open", sys_open_call);
    if (ret)
    {
        fprintf(stderr, "failed to register probe on sys_open call\n");
        exit(1);
    }

    ret = ctxprobes_reg_func_return("sys_open", sys_open_return);
    if (ret)
    {
        fprintf(stderr, "failed to register probe on sys_open return\n");
        exit(1);
    }
/*
    ret = ctxprobes_instrument_func("sys_open", disfunc_call, disfunc_return);
    if (ret)
    {
        fprintf(stderr, "failed to instrument function sys_open\n");
        exit(1);
    }
*/
    printf("Starting instrumentation...\n");
    ctxprobes_wait();

    ctxprobes_cleanup();

    if (tasklist)
        array_list_free(tasklist);
    return 0;
}

