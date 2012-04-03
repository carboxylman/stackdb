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
 *  examples/context-aware-probes/ctxprobes.c
 *
 *  Probes aware of guest's context changes -- task switches, traps, 
 *  and interrupts.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#include <stdio.h>
#include <stdlib.h>

#include <log.h>
#include <dwdebug.h>
#include <target_api.h>
#include <target.h>
#include <target_xen_vm.h>

#include <probe_api.h>
#include <probe.h>

#include "ctxprobes.h"
#include "private.h"
#include "debug.h"

char *dom_name = NULL;
FILE *sysmap_handle = NULL;
struct target *t = NULL;
GHashTable *probes = NULL;

task_t *task_current = NULL;

struct bsymbol *bsymbol_task_prev = NULL;
struct bsymbol *bsymbol_task_next = NULL;

static int probe_func_call(struct probe *probe,
                           void *data,
                           struct probe *trigger)
{
    char *symbol;
    var_t *arg_list = NULL;
    int arg_count = 0;
    //int ret;

    ctxprobes_func_call_handler_t handler 
        = (ctxprobes_func_call_handler_t) data;

    symbol = probe->name;

    DBG("%d (%s): Function %s called\n", 
        task_current->pid, task_current->comm, 
        symbol);
  
    //ret = load_func_args(&arg_list, &arg_count, probe);
    //if (ret)
    //    ERR("Failed to load function args\n");

    DBG("Calling user probe handler 0x%08x\n", (uint32_t)handler);
    handler(symbol, arg_list, arg_count, task_current);
    DBG("Returned from user probe handler 0x%08x\n", (uint32_t)handler);

    //unload_func_args(arg_list, arg_count);

    return 0;
}

static int probe_func_return(struct probe *probe,
                             void *data,
                             struct probe *trigger)
{
    char *symbol;
    var_t *arg_list = NULL;
    var_t retval;
    int arg_count = 0;
    int ret;

    ctxprobes_func_return_handler_t handler 
        = (ctxprobes_func_return_handler_t) data;

    symbol = probe->name;

    DBG("%d (%s): Function %s returned\n", 
        task_current->pid, task_current->comm, 
        symbol);
 
    //ret = load_func_args(&arg_list, &arg_count, probe);
    //if (ret)
    //    ERR("Failed to load function args\n");

    ret = load_func_retval(&retval, probe);
    if (ret)
        ERR("Failed to load function retval\n");

    DBG("Calling user probe handler 0x%08x\n", (uint32_t)handler);
    handler(symbol, arg_list, arg_count, retval, task_current);
    DBG("Returned from user probe handler 0x%08x\n", (uint32_t)handler);

    //unload_func_args(arg_list, arg_count);

    return 0;
}

static int probe_trap_call(struct probe *probe, 
                           void *data, 
                           struct probe *trigger)
{
    DBG("%d (%s): Trap %s called\n", 
        task_current->pid, task_current->comm, 
        probe->name);
    return 0;
}

static int probe_trap_return(struct probe *probe, 
                             void *data, 
                             struct probe *trigger)
{
    DBG("%d (%s): Trap %s returned\n", 
        task_current->pid, task_current->comm, 
        probe->name);
    return 0;
}

static int probe_syscall_call(struct probe *probe, 
                              void *data, 
                              struct probe *trigger)
{
    unsigned int eax = target_read_reg(t, 0);
    DBG("%d (%s): System call %d (0x%02x) called\n", 
        task_current->pid, task_current->comm,
        eax, eax);
    return 0;
}

static int probe_syscall_return(struct probe *probe,
                                void *data,
                                struct probe *trigger)
{
    unsigned int eax = target_read_reg(t, 0);
    DBG("%d (%s): System call %d (0x%02x) returned\n", 
        task_current->pid, task_current->comm,
        eax, eax);
    return 0;
}

static int probe_interrupt_call(struct probe *probe, 
                                void *data, 
                                struct probe *trigger)
{
    int irq;
    //struct pt_regs *regs;

    //value = get_function_arg(0, probe, t);
    //if (!value)
    //{
    //    ERR("Could not read IRQ\n");
    //    return 1;
    //}

    //regs = (struct pt_regs *)value->buf;
    //irq = ~regs->orig_eax & 0xff;
    unsigned int eax = target_read_reg(t, 0);
    irq = ~eax & 0xff;

    DBG("%d (%s): Interrupt %d (0x%02x) called\n",
        task_current->pid, task_current->comm, 
        irq, irq);
    return 0;
}

static int probe_interrupt_return(struct probe *probe, 
                                  void *data, 
                                  struct probe *trigger)
{
    int irq;
    //struct pt_regs *regs;

    //value = get_function_arg(0, probe, t);
    //if (!value)
    //{
    //    ERR("Could not read IRQ\n");
    //    return 1;
    //}

    //regs = (struct pt_regs *)value->buf;
    //irq = ~regs->orig_eax & 0xff;
    unsigned int eax = target_read_reg(t, 0);
    irq = ~eax & 0xff;

    DBG("%d (%s): Interrupt %d (0x%02x) returned\n",
        task_current->pid, task_current->comm, 
        irq, irq);
    return 0;
}

static int probe_task_switch(struct probe *probe, 
                             void *data, 
                             struct probe *trigger)
{
    struct value *lvalue_task_prev, *lvalue_task_next;
    task_t *task_prev, *task_next;
    int ret;

    lvalue_task_prev = bsymbol_load(bsymbol_task_prev, LOAD_FLAG_NONE);
    if (!lvalue_task_prev)
    {
        ERR("Cannot access value of schedule.prev\n");
        return -1;
    }

    lvalue_task_next = bsymbol_load(bsymbol_task_next, LOAD_FLAG_NONE);
    if (!lvalue_task_next)
    {
        ERR("Cannot access value of schedule.next\n");
        return -1;
    }

    ret = load_task_info(&task_prev, *(unsigned long *)lvalue_task_prev->buf);
    if (ret)
    {
        ERR("Cannot load task info of schedule.prev\n");
        return -1;
    }

    ret = load_task_info(&task_next, *(unsigned long *)lvalue_task_next->buf);
    if (ret)
    {
        ERR("Cannot load task info of schedule.next\n");
        return -1;
    }

    if (task_prev->vaddr != task_next->vaddr)
    {
        DBG("Task switch: %d (%s) -> %d (%s)\n", 
            task_prev->pid, task_prev->comm,
            task_next->pid, task_next->comm);
    }
    
    unload_task_info(task_prev);

    if (task_prev->vaddr != task_next->vaddr)
    {
        unload_task_info(task_current);
        task_current = task_next;
    }
    else
        unload_task_info(task_next);

    return 0;
}

static int probe_task_switch_init(struct probe *probe)
{
    DBG("Task switch init\n");
    
    bsymbol_task_prev = target_lookup_sym(probe->target, 
                                          "schedule.prev",
                                          ".",
                                          NULL,
                                          SYMBOL_TYPE_NONE);
    if (!bsymbol_task_prev)
    {
        ERR("Failed to create a bsymbol for schedule.prev\n");
        return -1;
    }

    bsymbol_task_next = target_lookup_sym(probe->target, 
                                          "schedule.next",
                                          ".",
                                          NULL,
                                          SYMBOL_TYPE_NONE);
    if (!bsymbol_task_next)
    {
        ERR("Failed to create a bsymbol for schedule.next\n");
        return -1;
    }

    return 0;
}

typedef struct probe_entry {
    char *symbol;
    probe_handler_t call_handler;
    probe_handler_t return_handler;
    struct probe_ops ops;
} probe_entry_t;

/* 
 * FIXME: read raw addresses of assembly functions from System.map --
 * we are currently using hard-coded addresses.
 */
static const probe_entry_t probe_list[] = 
{
    { "do_divide_error",                probe_trap_call,        
      NULL/*probe_trap_return*/,                { .init = NULL } },
    { "do_debug",                       probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    { "do_nmi",                         probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    { "do_int3",                        probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    { "do_overflow",                    probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    { "do_bounds",                      probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    { "do_invalid_op",                  probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    //{ "device_not_available",           probe_trap_call, 
    //  probe_trap_return,                { .init = NULL } },
    //{ "double_fault",                   probe_trap_call, 
    //  probe_trap_return,                { .init = NULL } },
    { "do_coprocessor_segment_overrun", probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    { "do_invalid_TSS",                 probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    { "do_segment_not_present",         probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    { "do_stack_segment",               probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    { "do_general_protection",          probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    { "do_page_fault",                  probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    //{ "spurious_interrupt_bug",         probe_trap_call, 
    //  probe_trap_return,                { .init = NULL } },
    { "do_coprocessor_error",           probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    { "do_alignment_check",             probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    //{ "intel_machine_check",            probe_trap_call, 
    //  probe_trap_return,                { .init = NULL } },
    { "do_simd_coprocessor_error",      probe_trap_call, 
      NULL/*probe_trap_return*/,                { .init = NULL } },
    { "system_call",                    probe_syscall_call, 
      NULL/*probe_syscall_return*/,             { .init = NULL } },
    //{ "do_IRQ",                         probe_interrupt_call, 
    //  probe_interrupt_return,           { .init = NULL } },
    { "schedule.switch_tasks",          probe_task_switch, 
      NULL,                             { .init = probe_task_switch_init } },
};

static void sigh(int signo)
{
    ctxprobes_cleanup();
    exit(0);
}

int ctxprobes_init(char *domain_name, 
                   char *sysmap_file, 
                   int debug_level)
{
    unsigned task_struct_addr;
    int i, probe_count;
    int ret;

    if (t)
    {
        ERR("Target already initialized\n");
        return -1;
    }

    dom_name = domain_name;

    sysmap_handle = fopen(sysmap_file, "r");
    if (!sysmap_handle)
    {
        ERR("Could not open file %s\n", sysmap_file);
        return -2;
    }

    dwdebug_init();
    vmi_set_log_level(debug_level);
    xa_set_debug_level(debug_level);

    t = xen_vm_attach(dom_name);
    if (!t)
    {
        ERR("Can't attach to domain %s!\n", dom_name);
        ctxprobes_cleanup();
        return -3;
    }

    if (target_open(t))
    {
        ERR("Can't open target %s!\n", dom_name);
        ctxprobes_cleanup();
        return -4;
    }

    probes = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (!probes)
    {
        ERR("Can't create probe table for target %s\n", dom_name);
        ctxprobes_cleanup();
        return -5;
    }

    /*
     * Register probes to detect context changes; traps, interrupts, and
     * task switches.
     */
    probe_count = sizeof(probe_list) / sizeof(probe_list[0]);    
    for (i = 0; i < probe_count; i++)
    {
        if (probe_list[i].call_handler)
        {
            ret = register_call_probe(probe_list[i].symbol, 
                                      probe_list[i].call_handler,
                                      (struct probe_ops *)&probe_list[i].ops,
                                      PROBEPOINT_EXEC,
                                      SYMBOL_TYPE_FLAG_NONE,
                                      NULL); /* data */
            if (ret)
            {
                ERR("Failed to register call probe on '%s'\n", 
                    probe_list[i].symbol);
                ctxprobes_cleanup();
                return -1;
            }
        }

        if (probe_list[i].return_handler)
        {
            ret = register_return_probe(probe_list[i].symbol, 
                                        probe_list[i].return_handler,
                                        NULL,
                                        PROBEPOINT_EXEC,
                                        SYMBOL_TYPE_FLAG_NONE,
                                        NULL); /* data */
            if (ret)
            {
                ERR("Failed to register return probe on '%s'\n", 
                    probe_list[i].symbol);
                ctxprobes_cleanup();
                return -1;
            }
        }
    }

    /*
     * Obtain current task info -- task info will be updated on detecting
     * task switches later on.
     */
    task_struct_addr = current_task_addr();
    ret = load_task_info(&task_current, task_struct_addr);
    if (ret)
    {
        ERR("Cannot load current task info\n");
        return -1;
    }
    DBG("Current task: %d (%s)\n", task_current->pid, task_current->comm);

    signal(SIGHUP, sigh);
    signal(SIGINT, sigh);
    signal(SIGQUIT, sigh);
    signal(SIGABRT, sigh);
    signal(SIGKILL, sigh);
    signal(SIGSEGV, sigh);
    signal(SIGPIPE, sigh);
    signal(SIGALRM, sigh);
    signal(SIGTERM, sigh);
    signal(SIGUSR1, sigh);
    signal(SIGUSR2, sigh);

    return 0;
}

void ctxprobes_cleanup(void)
{
    if (t)
    {
        target_pause(t);
        
        DBG("Ending trace.\n");
     
        unregister_probes(probes);
        unload_task_info(task_current);
        target_close(t);

        DBG("Ended trace.\n");
        
        fclose(sysmap_handle);

        task_current = NULL;
        probes = NULL;
        t = NULL;
        sysmap_handle = NULL;
        dom_name = NULL;
    }
}

int ctxprobes_wait(void)
{
    target_status_t tstat;

    if (!t)
    {
        ERR("Target not initialized\n");
        return -1;
    }

    /* 
     * The target is paused after the attach; we have to resume it now
     * that we've registered probes.
     */
    target_resume(t);

    DBG("Starting main debugging loop!\n");

    while (1)
    {
        tstat = target_monitor(t);
        if (tstat == TSTATUS_PAUSED)
        {
            DBG("Domain %s interrupted at 0x%" PRIxREGVAL "\n",
                dom_name, target_read_reg(t, t->ipregno));
            if (target_resume(t))
            {
                ERR("Can't resume target domain %s\n", dom_name);
                target_close(t);
                return -16;
            }
        }
        else
        {
            //unregister_probes(probes);
            //target_close(t);
            if (tstat == TSTATUS_DONE)
                break;
            else if (tstat == TSTATUS_ERROR)
                return -9;
            else
                return -10;
        }
    }

    return 0;
}

int ctxprobes_func_call(char *symbol,
                        ctxprobes_func_call_handler_t handler)
{
    int ret;

    if (!t)
    {
        ERR("Target not initialized\n");
        return -1;
    }

    ret = register_call_probe(symbol, 
                              probe_func_call,
                              NULL, /* ops */
                              PROBEPOINT_EXEC,
                              SYMBOL_TYPE_FLAG_FUNCTION,
                              handler); /* data <- ctxprobes handler */
    if (ret)
    {
        ERR("Failed to register context-aware call probe on '%s'\n", symbol);
        return -1;
    }

    return 0;
}

int ctxprobes_func_return(char *symbol,
                          ctxprobes_func_return_handler_t handler)
{
    int ret;

    if (!t)
    {
        ERR("Target not initialized\n");
        return -1;
    }

    ret = register_return_probe(symbol, 
                                probe_func_return,
                                NULL, /* ops */
                                PROBEPOINT_EXEC,
                                SYMBOL_TYPE_FLAG_FUNCTION,
                                handler); /* data <- ctxprobes handler */
    if (ret)
    {
        ERR("Failed to register context-aware return probe on '%s'\n", symbol);
        return -1;
    }

    return 0;
}
/*
int ctxprobes_var(char *symbol,
                  ctxprobes_var_handler_t handler)
{
    if (!t)
    {
        ERR("Target not initialized\n");
        return -1;
    }

    return 0;
}
*/
