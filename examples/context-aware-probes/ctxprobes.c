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
 *  ctxprobes/ctxprobes.c
 *
 *  Probes aware of guest's context changes -- task switches, traps, 
 *  and interrupts.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#include <log.h>
#include <dwdebug.h>
#include <target_api.h>
#include <target.h>
#include <target_xen_vm.h>

#include <probe_api.h>
#include <probe.h>
#include <alist.h>

#include "ctxprobes.h"
#include "debug.h"

static char *dom_name = NULL;
static struct target *t = NULL;
static GHashTable *probes = NULL; /* lower-level probes */
static GHashTable *ctxprobes = NULL; /* context-aware probes */

typedef struct probe_entry
{
    int raw; /* 0:use symbol, 1:use addr (raw address) */
    char *symbol;
    ADDR addr;
    probe_handler_t handler;

} probe_entry_t;

static int probe_trap(struct probe *probe, 
                      void *data, 
                      struct probe *trigger)
{
    DBG("Trap: %s\n", probe->name);
    return 0;
}

static int probe_syscall(struct probe *probe, 
                         void *data, 
                         struct probe *trigger)
{
    DBG("System call: %s\n", probe->name);
    return 0;
}

static int probe_interrupt(struct probe *probe, 
                           void *data, 
                           struct probe *trigger)
{
    DBG("Interrupt: %s\n", probe->name);
    return 0;
}

static int probe_task_switch(struct probe *probe, 
                             void *data, 
                             struct probe *trigger)
{
    DBG("Task switch: %s\n", probe->name);
    return 0;
}

/* 
 * FIXME: read raw addresses of assembly functions from System.map --
 * we are currently using hard-coded addresses.
 */
const probe_entry_t probe_list[] = 
{
    { 0, "do_divide_error",                0x0,        probe_trap },
    { 0, "do_debug",                       0x0,        probe_trap },
    { 0, "do_nmi",                         0x0,        probe_trap },
    { 0, "do_int3",                        0x0,        probe_trap },
    { 0, "do_overflow",                    0x0,        probe_trap },
    { 0, "do_bounds",                      0x0,        probe_trap },
    { 0, "do_invalid_op",                  0x0,        probe_trap },
    //{ 1, "device_not_available",           0xc01055a8, probe_trap },
    //{ 0, "double_fault",                   0x0,        probe_trap },
    { 0, "do_coprocessor_segment_overrun", 0x0,        probe_trap },
    { 0, "do_invalid_TSS",                 0x0,        probe_trap },
    { 0, "do_segment_not_present",         0x0,        probe_trap },
    { 0, "do_stack_segment",               0x0,        probe_trap },
    { 0, "do_general_protection",          0x0,        probe_trap },
    { 0, "do_page_fault",                  0x0,        probe_trap },
    //{ 0, "spurious_interrupt_bug",         0x0,        probe_trap },
    { 0, "do_coprocessor_error",           0x0,        probe_trap },
    { 0, "do_alignment_check",             0x0,        probe_trap },
    //{ 0, "intel_machine_check",            0x0,        probe_trap },
    { 0, "do_simd_coprocessor_error",      0x0,        probe_trap },
    //{ 1, "system_call",                    0xc01052e8, probe_syscall },
    { 0, "do_IRQ",                         0x0,        probe_interrupt },
    { 0, "schedule.switch_tasks",          0x0,        probe_task_switch },
};

static void sigh(int signo)
{
    ctxprobes_cleanup();
    exit(0);
}

static int register_probe(int raw, /* 0:use symbol, 1:use addr (raw address) */
                          char *symbol, 
                          ADDR addr, 
                          probe_handler_t handler,
                          struct probe_ops *ops,
                          probepoint_whence_t whence,
                          symbol_type_flag_t ftype,
                          void *data)
{
    struct bsymbol *bsymbol = NULL;
    struct probe *probe;

    if (!raw)
    {
        bsymbol = target_lookup_sym(t, symbol, ".", NULL, ftype);
        if (!bsymbol)
        {
            ERR("Could not find symbol %s!\n", symbol);
            return -1;
        }
    }

    //bsymbol_dump(bsymbol, &udn);

    probe = probe_create(t, ops,
                         (raw) ? symbol : bsymbol->lsymbol->symbol->name,
                         handler, 
                         NULL, /* post_handler */
                         data, 
                         0); /* autofree */
    if (!probe)
    {
        ERR("Could not create probe on '%s'\n",
            (raw) ? symbol : bsymbol->lsymbol->symbol->name);
        return -1;
    }

    if (raw)
    {
        if (!probe_register_addr(probe,
                                 addr, PROBEPOINT_BREAK, PROBEPOINT_FASTEST,
                                 whence, PROBEPOINT_LAUTO, 
                                 NULL)) /* bsymbol */
        {
            ERR("Could not register probe on 0x%08x\n", addr);
            probe_free(probe, 1);
            return -1;
        }
    }
    else
    {
        if (!probe_register_symbol(probe,
                                   bsymbol, PROBEPOINT_FASTEST,
                                   whence, PROBEPOINT_LAUTO))
        {
            ERR("Could not register probe on '%s'\n",
                bsymbol->lsymbol->symbol->name);
            probe_free(probe, 1);
            return -1;
        }
    }

    g_hash_table_insert(probes,
                        (gpointer)probe->probepoint->addr,
                        (gpointer)probe);

    return 0;
}

static void unregister_probes()
{
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;

    g_hash_table_iter_init(&iter, probes);
    while (g_hash_table_iter_next(&iter,
                                  (gpointer)&key,
                                  (gpointer)&probe))
    {
        probe_unregister(probe, 1);
    }
}


int ctxprobes_init(char *domain_name, int debug_level)
{
    int i, probe_count;
    int ret;

    if (t)
    {
        ERR("Target already initialized\n");
        return -1;
    }

    dom_name = domain_name;

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
        ret = register_probe(probe_list[i].raw,
                             probe_list[i].symbol, 
                             probe_list[i].addr,
                             probe_list[i].handler,
                             NULL, /* ops */
                             PROBEPOINT_EXEC,
                             SYMBOL_TYPE_FLAG_NONE,
                             NULL); /* data */
        if (ret)
        {
            ERR("Failed to register probe on '%s'\n", probe_list[i].symbol);
            ctxprobes_cleanup();
            return -1;
        }
    }

    ctxprobes = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (!ctxprobes)
    {
        ERR("Can't create context-aware probe table for target %s\n", 
            dom_name);
        ctxprobes_cleanup();
        return -5;
    }

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
        target_close(t);

        DBG("Ended trace.\n");
        
        ctxprobes = NULL;
        probes = NULL;
        t = NULL;
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

int ctxprobes_function_call(char *symbol,
                            ctxprobes_function_call_handler_t handler)
{
    if (!t)
    {
        ERR("Target not initialized\n");
        return -1;
    }

    return 0;
}

int ctxprobes_function_return(char *symbol,
                              ctxprobes_function_return_handler_t handler)
{
    if (!t)
    {
        ERR("Target not initialized\n");
        return -1;
    }

    return 0;
}

int ctxprobes_variable(char *symbol,
                       ctxprobes_variable_handler_t handler)
{
    if (!t)
    {
        ERR("Target not initialized\n");
        return -1;
    }

    return 0;
}

