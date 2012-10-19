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
#include <unistd.h>

#include <log.h>
#include <dwdebug.h>
#include <target_api.h>
#include <target.h>
#include <target_xen_vm.h>

#include <probe_api.h>
#include <probe.h>

#include "ctxprobes.h"
#include "private.h"
#include "perf.h"

char *dom_name = NULL;
FILE *sysmap_handle = NULL;
struct target *t = NULL;

GHashTable *probes = NULL;
GHashTable *cprobes = NULL;
GHashTable *rprobes = NULL;
GHashTable *disfuncs = NULL;

ctxprobes_task_t *task_current = NULL;
ctxprobes_context_t context_current = CTXPROBES_CONTEXT_NORMAL;
ctxprobes_context_t context_prev_trap = CTXPROBES_CONTEXT_NORMAL;
ctxprobes_context_t context_prev_intr = CTXPROBES_CONTEXT_NORMAL;

ctxprobes_task_switch_handler_t user_task_switch_handler = NULL;
ctxprobes_context_change_handler_t user_context_change_handler = NULL;
ctxprobes_page_fault_handler_t user_page_fault_handler = NULL;

struct array_list *user_pidlist = NULL;

struct bsymbol *bsymbol_task_prev = NULL;
struct bsymbol *bsymbol_task_next = NULL;

/* This variable temporarily holds the address in SP between a function's
 * proloque invocation and return, based on an assumption that no other
 * functions get called in the meantime a function is being executed. */
REGVAL regsp;

/* This variable temporarily holds the irq number, based on an assumption
 * that no other interrupt handlers get called in the meantime a interrupt
 * handler is being executed. */
int irq_no;

/* This variable temporarily holds the address of the high-level user
   disfunc return handler. */
ctxprobes_disfunc_handler_t user_disfunc_return_handler;

static int array_list_contains(struct array_list *list, void *item)
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

static int probe_func_prologue(struct probe *probe,
                               void *data,
                               struct probe *trigger)
{
    char *symbol;
    ADDR retaddr = 0;
    REGVAL sp;

    ctxprobes_func_prologue_handler_t handler 
        = (ctxprobes_func_prologue_handler_t) data;

    symbol = bsymbol_get_name(probe->bsymbol);

    unload_task_info(task_current);
    if (load_task_info(&task_current, current_task_addr()))
    {
        verror("Cannot load current task info\n");
    }

    vdebugc(-1, LOG_C_FUNC, "%d (%s): Function %s prologue (context: %s)\n", 
            task_current->pid, task_current->comm, symbol, 
            context_string(context_current));
  
    errno = 0;
    sp = target_read_reg(t, TID_GLOBAL, t->spregno);
    if (errno)
        verror("Could not read SP!\n");
    vdebug(8, LOG_C_FUNC, "SP: 0x%08x\n", sp);

    /* FIXME: Save sp in a global variable. */
    regsp = sp;
    
    /* Grab the return address on the top of the stack */
    if (!target_read_addr(t, (ADDR)sp, sizeof(ADDR), 
                          (unsigned char *)&retaddr))
    {
        verror("Could not read top of stack!\n");
    }

    vdebug(3, LOG_C_FUNC, "Calling user probe handler 0x%08x\n", 
           (uint32_t)handler);
    handler(symbol, 
            retaddr, 
            task_current, 
            context_current);
    vdebug(3, LOG_C_FUNC, "Returned from user probe handler 0x%08x\n", 
           (uint32_t)handler);

    return 0;
}

static int probe_func_call(struct probe *probe,
                           void *data,
                           struct probe *trigger)
{
    int ret;
    char *symbol;
    ctxprobes_var_t *arg_list = NULL;
    int arg_count = 0;
    int i, j, len;
    char buf[256];
    int blen = 256;

    ctxprobes_func_call_handler_t handler 
        = (ctxprobes_func_call_handler_t) data;

    symbol = bsymbol_get_name(probe->bsymbol);

    unload_task_info(task_current);
    if (load_task_info(&task_current, current_task_addr()))
    {
        verror("Cannot load current task info\n");
    }

    vdebugc(-1, LOG_C_FUNC, "%d (%s): Function %s called (context: %s)\n", 
            task_current->pid, task_current->comm, symbol, 
            context_string(context_current));
 
    ret = load_func_args(&arg_list, &arg_count, probe, trigger);
    if (ret)
        vdebugc(-1, LOG_C_WARN, "Failed to load function args\n");
    else if (arg_list && arg_count > 0)
    {
        vdebugc(-1, LOG_C_FUNC, "- Function arguments (count = %d):\n", 
	       arg_count);

        for (i = 0; i < arg_count; i++)
        {
	    if (!arg_list[i].buf)
		continue;

            len = arg_list[i].size;
            for (j = 0; j < len; j++) {
		if (2 * j >= blen)
		    break;
                snprintf(buf+2*j, blen - 2*j, "%02hhx", arg_list[i].buf[j]);
	    }
            if (is_string(arg_list[i].buf, len))
                vdebugc(-1, LOG_C_FUNC, "  %s = %s (0x%s)\n", arg_list[i].name, 
                        arg_list[i].buf, buf); 
            else if (len <= 4)
                vdebugc(-1, LOG_C_FUNC, "  %s = %d (0x%s)\n", arg_list[i].name, 
                        *(int *)arg_list[i].buf, buf); 
            else
                vdebugc(-1, LOG_C_FUNC, "  %s = 0x%s\n", arg_list[i].name, buf); 
        }
    }

    vdebug(3, LOG_C_FUNC, "Calling user probe handler 0x%08x\n", 
           (uint32_t)handler);
    handler(symbol, 
            arg_list, 
            arg_count, 
            task_current, 
            context_current);
    vdebug(3, LOG_C_FUNC, "Returned from user probe handler 0x%08x\n", 
           (uint32_t)handler);

    unload_func_args(arg_list, arg_count);

    return 0;
}

static int probe_func_return(struct probe *probe,
                             void *data,
                             struct probe *trigger)
{
    int ret;
    char *symbol;
    ctxprobes_var_t *arg_list = NULL;
    ctxprobes_var_t *retval = NULL;
    int arg_count = 0;
    int i, j, len;
    char buf[256];
    int blen = 256;
    ADDR retaddr = 0;
    REGVAL sp;

    ctxprobes_func_return_handler_t handler 
        = (ctxprobes_func_return_handler_t) data;

    symbol = bsymbol_get_name(probe->bsymbol);

    unload_task_info(task_current);
    if (load_task_info(&task_current, current_task_addr()))
    {
        verror("Cannot load current task info\n");
    }

    vdebugc(-1, LOG_C_FUNC, "%d (%s): Function %s returned (context: %s)\n", 
            task_current->pid, task_current->comm, symbol,
            context_string(context_current));
 
    ret = load_func_args(&arg_list, &arg_count, probe, trigger);
    if (ret)
        vdebugc(-1, LOG_C_WARN, "Failed to load function args\n");
    else
    {
        vdebugc(-1, LOG_C_FUNC, "- Function arguments:\n");
        for (i = 0; i < arg_count; i++)
        {
	    if (!arg_list[i].buf)
		continue;

            len = arg_list[i].size;
            for (j = 0; j < len; j++) {
		if (2 * j >= blen)
		    break;
                snprintf(buf+2*j, blen - 2*j, "%02hhx", arg_list[i].buf[len-j-1]);
	    }
            if (is_string(arg_list[i].buf, len))
                vdebugc(-1, LOG_C_FUNC, "  %s = %s (0x%s)\n", arg_list[i].name, 
                        arg_list[i].buf, buf); 
            else if (len <= 4)
                vdebugc(-1, LOG_C_FUNC, "  %s = %d (0x%s)\n", arg_list[i].name, 
                        *(int *)arg_list[i].buf, buf); 
            else
                vdebugc(-1, LOG_C_FUNC, "  %s = 0x%s\n", arg_list[i].name, buf); 
        }
    }

    ret = load_func_retval(&retval, trigger);
    if (ret)
        vdebugc(-1, LOG_C_WARN, "Failed to load function retval\n");
    else
    {
        vdebugc(-1, LOG_C_FUNC, "- Function return value: %d (0x%08x)\n", 
                *(int *)retval->buf, *(int *)retval->buf);
    }

    //errno = 0;
    //sp = target_read_reg(t, t->spregno);
    //if (errno)
    //    verror("Could not read SP!\n");
    /* FIXME: Use the saved SP in global variable. */
    sp = regsp;
    vdebug(8, LOG_C_FUNC, "SP: 0x%08x\n", sp);
    
    if (sp)
    {
        /* Grab the return address on the top of the stack */
        if (!target_read_addr(t, (ADDR)sp, sizeof(ADDR), 
                              (unsigned char *)&retaddr))
        {
            verror("Could not read top of stack!\n");
        }
    }

    vdebugc(3, LOG_C_FUNC, "Calling user probe handler 0x%08x\n", 
            (uint32_t)handler);
    handler(symbol, 
            arg_list, 
            arg_count, 
            retval, 
            retaddr, 
            task_current, 
            context_current);
    vdebugc(3, LOG_C_FUNC, "Returned from user probe handler 0x%08x\n", 
            (uint32_t)handler);

    unload_func_retval(retval);
    unload_func_args(arg_list, arg_count);

    return 0;
}

static int probe_var(struct probe *probe,
                     void *data,
                     struct probe *trigger)
{
    ctxprobes_var_t value;
    int tmp = -1;

    ctxprobes_var_handler_t handler = (ctxprobes_var_handler_t) data;

    unload_task_info(task_current);
    if (load_task_info(&task_current, current_task_addr()))
    {
        verror("Cannot load current task info\n");
    }

    vdebugc(-1, LOG_C_VAR, "%d (%s): Variable %s (0x%08x) read or written "
            "(context: %s)\n", 
            task_current->pid, task_current->comm, 
            probe->name, probe_addr(probe), 
            context_string(context_current));
    
    if (!target_read_addr(t, 
                          probe_addr(probe), 
                          4, /* FIXME: size hard-coded */ 
                          (unsigned char *)&tmp))
    {
        verror("Could not read memory for %s (0x%08x)\n", 
               probe->name, probe_addr(probe));
        return -1;
    }

    value.name = probe->name;
    value.size = 4; /* FIXME: size hard-coded */
    value.buf = (char *)&tmp;

    vdebug(3, LOG_C_VAR, "Calling user probe handler 0x%08x\n", 
           (uint32_t)handler);
    handler(probe_addr(probe),
            probe->name, 
            &value, 
            task_current, 
            context_current);
    vdebug(3, LOG_C_VAR, "Returned from user probe handler 0x%08x\n",
           (uint32_t)handler);
    
    return 0;
}

static int probe_disfunc_return(struct probe *probe,
                                void *data,
                                struct probe *trigger)
{ 
    REGVAL ip;
    tid_t tid = target_gettid(probe->target);
    struct bsymbol *bsymbol;
    struct bsymbol *tbsymbol;

    ctxprobes_disfunc_handler_t handler = (ctxprobes_disfunc_handler_t) data;
    
    unload_task_info(task_current);
    if (load_task_info(&task_current, current_task_addr()))
    {
        verror("Cannot load current task info\n");
    }

    vdebugc(-1, LOG_C_DISASM, "%d (%s): Disassembled function %s returned "
            "(context: %s)\n", 
            task_current->pid, task_current->comm, 
            probe->name, context_string(context_current));
    
    ip = target_read_reg(t, tid, t->ipregno);
    if (errno)
    {
        verror("Could not read IP!\n");
        return 0;
    }

    bsymbol = target_lookup_sym_addr(t, ip);
    if (!bsymbol)
    {
        vdebugc(-1, LOG_C_WARN, "Warning: Unknown function returned: "
                "ip = 0x%08x\n", ip);
    }
    else {
	/* Don't instrument inline instances! */
	if (bsymbol_is_inline(bsymbol)) {
	    tbsymbol = bsymbol_create_noninline(bsymbol);
	    vdebug(2,LOG_C_WARN,"switching from inline %s to noninline %s\n",
		   bsymbol_get_name(bsymbol),bsymbol_get_name(tbsymbol));
	    bsymbol_release(bsymbol);
	    bsymbol = tbsymbol;
	    bsymbol_hold(bsymbol);
	}
    }

    vdebug(3, LOG_C_DISASM, "Calling user probe handler 0x%08x\n", 
           (uint32_t)handler);
    handler(bsymbol,
            ip,
            task_current, 
            context_current);
    vdebug(3, LOG_C_DISASM, "Returned from user probe handler 0x%08x\n", 
           (uint32_t)handler);

    bsymbol_release(bsymbol);

    return 0;
}

static int probe_disfunc_call(struct probe *probe,
                              void *data,
                              struct probe *trigger)
{
    REGVAL ip;
    struct bsymbol *bsymbol;
    struct bsymbol *tbsymbol;
    ADDR funcstart = 0;
    struct symbol *symbol;

    ctxprobes_disfunc_handler_t call_handler = (ctxprobes_disfunc_handler_t) data;

    /* FIXME: use a global variable temporarily. */
    ctxprobes_disfunc_handler_t return_handler = user_disfunc_return_handler;

    unload_task_info(task_current);
    if (load_task_info(&task_current, current_task_addr()))
    {
        verror("Cannot load current task info\n");
    }

    vdebugc(-1, LOG_C_DISASM, "%d (%s): Disassembled function %s called "
            "(context: %s)\n", 
            task_current->pid, task_current->comm, 
            probe->name, context_string(context_current));
    
    ip = target_read_reg(t, TID_GLOBAL, t->ipregno);
    if (errno)
    {
        verror("Could not read IP!\n");
        return 0;
    }

    bsymbol = target_lookup_sym_addr(t, ip);
    if (!bsymbol)
    {
        vdebugc(-1, LOG_C_WARN, "Warning: Unknown function called: "
                "ip = 0x%08x\n", ip);
    }
    else
    {
	/* Don't instrument inline instances! */
	if (bsymbol_is_inline(bsymbol)) {
	    tbsymbol = bsymbol_create_noninline(bsymbol);
	    vdebug(2,LOG_C_WARN,"switching from inline %s to noninline %s\n",
		   bsymbol_get_name(bsymbol),bsymbol_get_name(tbsymbol));
	    bsymbol_release(bsymbol);
	    bsymbol = tbsymbol;
	    bsymbol_hold(bsymbol);
	}

        if ((funcstart = instrument_func(bsymbol, 
                                         probe_disfunc_call, 
                                         probe_disfunc_return, 
                                         call_handler, /* data <- ctxprobes handler */
                                         return_handler, /* data <- ctxprobes handler */
                                         0 /* non-root */)) == 0) 
        {
            verror("Could not instrument function %s (0x%08x)!\n",
                   bsymbol->lsymbol->symbol->name, funcstart);
        }
    }

    vdebugc(3, LOG_C_DISASM, "Calling user probe handler 0x%08x\n", 
            (uint32_t)call_handler);
    call_handler(bsymbol,
                 ip,
                 task_current, 
                 context_current);
    vdebugc(3, LOG_C_DISASM, "Returned from user probe handler 0x%08x\n", 
            (uint32_t)call_handler);
        
    bsymbol_release(bsymbol);

    return 0;
}

/* TRAP_divide_error -- trap gate #0; call */
static int probe_divide_error_call(struct probe *probe, 
                                   void *data, 
                                   struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap divide error called\n", 
                task_current->pid, task_current->comm);
    }

    return 0;
}

/* TRAP_divide_error -- trap gate #0; return */
static int probe_divide_error_return(struct probe *probe, 
                                     void *data, 
                                     struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap divide error returned\n", 
                task_current->pid, task_current->comm);
    }

    return 0;
}

/* TRAP_debug -- interrupt gate #1; call */
static int probe_debug_call(struct probe *probe, 
                            void *data, 
                            struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap debug called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_debug -- interrupt gate #1; return */
static int probe_debug_return(struct probe *probe, 
                              void *data, 
                              struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap debug returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_nmi -- interrupt gate #2; call */
static int probe_nmi_call(struct probe *probe, 
                          void *data, 
                          struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap NMI called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_nmi -- interrupt gate #2; return */
static int probe_nmi_return(struct probe *probe, 
                            void *data, 
                            struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap NMI returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_int3 -- system interrupt gate #3; call */
static int probe_int3_call(struct probe *probe, 
                           void *data, 
                           struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap breakpoint called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_int3 -- system interrupt gate #3; return */
static int probe_int3_return(struct probe *probe, 
                             void *data, 
                             struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap breakpoint returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_overflow -- system gate #4; call */
static int probe_overflow_call(struct probe *probe, 
                               void *data, 
                               struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap overflow called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_overflow -- system gate #4; return */
static int probe_overflow_return(struct probe *probe, 
                                 void *data, 
                                 struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap overflow returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_bounds -- trap gate #5; call */
static int probe_bounds_call(struct probe *probe, 
                             void *data, 
                             struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap bounds check called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_bounds -- trap gate #5; return */
static int probe_bounds_return(struct probe *probe, 
                               void *data, 
                               struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap bounds check returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_invalid_op -- trap gate #6; call */
static int probe_invalid_op_call(struct probe *probe, 
                                 void *data, 
                                 struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap invalid opcode called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_invalid_op -- trap gate #6; return */
static int probe_invalid_op_return(struct probe *probe, 
                                   void *data, 
                                   struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap invalid opcode returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_no_device -- trap gate #7; call */
static int probe_device_not_available_call(struct probe *probe, 
                                           void *data, 
                                           struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap device not available called\n", 
                task_current->pid, task_current->comm);
    }

    return 0;
}

/* TRAP_no_device -- trap gate #7; return */
static int probe_device_not_available_return(struct probe *probe, 
                                             void *data, 
                                             struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap device not available returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_double_fault -- trap gate #8; call */
static int probe_double_fault_call(struct probe *probe, 
                                   void *data, 
                                   struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap double fault called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_double_fault -- trap gate #8; return */
static int probe_double_fault_return(struct probe *probe, 
                                     void *data, 
                                     struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap double fault returned\n", 
                task_current->pid, task_current->comm);
    }

    return 0;
}

/* TRAP_copro_seg -- trap gate #9; call */
static int probe_coprocessor_segment_overrun_call(struct probe *probe, 
                                                  void *data, 
                                                  struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap coprocessor segment overrun called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_copro_seg -- trap gate #9; return */
static int probe_coprocessor_segment_overrun_return(struct probe *probe, 
                                                    void *data, 
                                                    struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap coprocessor segment overrun returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_invalid_tss -- trap gate #10; call */
static int probe_invalid_TSS_call(struct probe *probe, 
                                  void *data, 
                                  struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap invalid TSS called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_invalid_tss -- trap gate #10; return */
static int probe_invalid_TSS_return(struct probe *probe, 
                                    void *data, 
                                    struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap invalid TSS returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_no_segment -- trap gate #11; call */
static int probe_segment_not_present_call(struct probe *probe, 
                                          void *data, 
                                          struct probe *trigger)
{
    if (!user_pidlist || array_list_contains(user_pidlist, (void *)task_current->pid))
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap segment not present called\n", 
                task_current->pid, task_current->comm);
    return 0;
}

/* TRAP_no_segment -- trap gate #11; return */
static int probe_segment_not_present_return(struct probe *probe, 
                                            void *data, 
                                            struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap segment not present returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_stack_error -- trap gate #12; call */
static int probe_stack_segment_call(struct probe *probe, 
                                    void *data, 
                                    struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap stack exception called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_stack_error -- trap gate #12; return */
static int probe_stack_segment_return(struct probe *probe, 
                                      void *data, 
                                      struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap stack exception returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_gp_fault -- trap gate #13; call */
static int probe_general_protection_call(struct probe *probe, 
                                         void *data, 
                                         struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap general protection called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_gp_fault -- trap gate #13; return */
static int probe_general_protection_return(struct probe *probe, 
                                           void *data, 
                                           struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap general protection returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_page_fault -- trap gate #14; call */
static int probe_page_fault_call(struct probe *probe, 
                                 void *data, 
                                 struct probe *trigger)
{
    ctxprobes_var_t *arg_list = NULL;
    int arg_count = 0;
    unsigned long address = 0;
    struct pt_regs regs;
    unsigned long error_code;
    char error_str[128] = {0,};
    int ret;

    /* FIXME: this is a hard-coded way of getting the pagefault address */
    int xc_handle = -1;
    struct xen_vm_state *xstate = (struct xen_vm_state *)(t->state);
    if (xstate)
    {
        xc_handle = xc_interface_open();
        if (xc_handle >= 0)
        {
            xc_dominfo_t dominfo;
            memset(&dominfo, 0, sizeof(dominfo));
            if (xc_domain_getinfo(xc_handle, xstate->id, 1, &dominfo) > 0)
            {
                vcpu_guest_context_t context;
                memset(&context, 0, sizeof(context));
                if (xc_vcpu_getcontext(xc_handle, xstate->id, 
                                       dominfo.max_vcpu_id, &context) >= 0)
                    address = context.ctrlreg[2];
                else
                    verror("Could not get vcpu context for %d\n", xstate->id);
            }
            else
                verror("Could not get domain info for %d\n", xstate->id);
        }
        else
            verror("Could not open xc interface: %s\n", strerror(errno));
    }
    else
        verror("Could not get xen vm state\n");
    if (xc_handle >= 0)
        xc_interface_close(xc_handle);

    ret = load_func_args(&arg_list, &arg_count, probe, trigger);
    if (ret)
        vdebugc(-1, LOG_C_WARN, "Failed to load function args\n");

    memcpy(&regs, arg_list[0].buf, arg_list[0].size);

    memcpy(&error_code, arg_list[1].buf, arg_list[1].size);
    int protection_fault = ((error_code & 1) != 0);
    int write_access = ((error_code & 2) != 0);
    int user_mode = ((error_code & 4) != 0);
    int reserved_bit = ((error_code & 8) != 0);
    int instr_fetch = ((error_code & 16) != 0);

    strcat(error_str, protection_fault ?
           "protection-fault, " : "no-page-found, ");
    strcat(error_str, write_access ?
           "write, " : "read, ");
    strcat(error_str, user_mode ?
           "user, " : "kernel, ");
    strcat(error_str, reserved_bit ?
           "reserved-bit, " : "");
    strcat(error_str, instr_fetch ?
           "instr-fetch, " : "");
    error_str[strlen(error_str)-2] = '\0';

    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap page fault called "
                "(eip = 0x%08lx, addr = 0x%08lx, error = %s)\n", 
                task_current->pid, task_current->comm, 
                regs.eip, address, error_str);
    }

    if (user_page_fault_handler)
    {
        user_page_fault_handler(regs.eip, 
                                address, 
                                protection_fault,
                                write_access,
                                user_mode,
                                reserved_bit,
                                instr_fetch,
                                task_current);
    }

    return 0;
}

/* TRAP_page_fault -- trap gate #14; return */
static int probe_page_fault_return(struct probe *probe, 
                                   void *data, 
                                   struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap page fault returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_spurious_int -- trap gate #15; call */
static int probe_spurious_interrupt_bug_call(struct probe *probe, 
                                             void *data, 
                                             struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap spurious interrupt bug called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_spurious_int -- trap gate #15; return */
static int probe_spurious_interrupt_bug_return(struct probe *probe, 
                                               void *data, 
                                               struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap spurious interrupt bug returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_copro_error -- trap gate #16; call */
static int probe_coprocessor_error_call(struct probe *probe, 
                                        void *data, 
                                        struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap floating point error called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_copro_error -- trap gate #16; return */
static int probe_coprocessor_error_return(struct probe *probe, 
                                          void *data, 
                                          struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap floating point error returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_alignment_check -- trap gate #17; call */
static int probe_alignment_check_call(struct probe *probe, 
                                      void *data, 
                                      struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap alignment check called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_alignment_check -- trap gate #17; return */
static int probe_alignment_check_return(struct probe *probe, 
                                        void *data, 
                                        struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap alignment check returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_machine_check -- trap gate #18; call */
static int probe_machine_check_call(struct probe *probe, 
                                    void *data, 
                                    struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap machine check called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_machine_check -- trap gate #18; return */
static int probe_machine_check_return(struct probe *probe, 
                                      void *data, 
                                      struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap machine check returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_simd_error -- trap gate #19; call */
static int probe_simd_coprocessor_error_call(struct probe *probe, 
                                             void *data, 
                                             struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap SIMD floating point error called\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* TRAP_simd_error -- trap gate #19; return */
static int probe_simd_coprocessor_error_return(struct probe *probe, 
                                             void *data, 
                                             struct probe *trigger)
{
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Trap SIMD floating point error returned\n", 
                task_current->pid, task_current->comm);
    }
    
    return 0;
}

/* All traps except system calls are routed to corresponding handlers; call */
static int probe_trap_call(struct probe *probe, 
                           void *data, 
                           struct probe *trigger)
{
    context_prev_trap = context_current;
    context_current = CTXPROBES_CONTEXT_TRAP;

    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Context change: %s -> %s\n", 
                task_current->pid, task_current->comm, 
                context_string(context_prev_trap), 
                context_string(context_current));
    }

    if (strcmp("do_divide_error", probe->name) == 0)
        return probe_divide_error_call(probe, data, trigger);
    else if (strcmp("do_debug", probe->name) == 0)
        return probe_debug_call(probe, data, trigger);
    else if (strcmp("do_nmi", probe->name) == 0)
        return probe_nmi_call(probe, data, trigger);
    else if (strcmp("do_int3", probe->name) == 0)
        return probe_int3_call(probe, data, trigger);
    else if (strcmp("do_overflow", probe->name) == 0)
        return probe_overflow_call(probe, data, trigger);
    else if (strcmp("do_bounds", probe->name) == 0)
        return probe_bounds_call(probe, data, trigger);
    else if (strcmp("do_invalid_op", probe->name) == 0)
        return probe_invalid_op_call(probe, data, trigger);
    else if (strcmp("device_not_available", probe->name) == 0)
        return probe_device_not_available_call(probe, data, trigger);
    else if (strcmp("do_coprocessor_segment_overrun", probe->name) == 0)
        return probe_coprocessor_segment_overrun_call(probe, data, trigger);
    else if (strcmp("double_fault", probe->name) == 0)
        return probe_double_fault_call(probe, data, trigger);
    else if (strcmp("do_invalid_TSS", probe->name) == 0)
        return probe_invalid_TSS_call(probe, data, trigger);
    else if (strcmp("do_segment_not_present", probe->name) == 0)
        return probe_segment_not_present_call(probe, data, trigger);
    else if (strcmp("do_stack_segment", probe->name) == 0)
        return probe_stack_segment_call(probe, data, trigger);
    else if (strcmp("do_general_protection", probe->name) == 0)
        return probe_general_protection_call(probe, data, trigger);
    else if (strcmp("do_page_fault", probe->name) == 0)
        return probe_page_fault_call(probe, data, trigger);
    else if (strcmp("spurious_interrupt_bug", probe->name) == 0)
        return probe_spurious_interrupt_bug_call(probe, data, trigger);
    else if (strcmp("do_coprocessor_error", probe->name) == 0)
        return probe_coprocessor_error_call(probe, data, trigger);
    else if (strcmp("do_alignment_check", probe->name) == 0)
        return probe_alignment_check_call(probe, data, trigger);
    else if (strcmp("intel_machine_check", probe->name) == 0)
        return probe_machine_check_call(probe, data, trigger);
    else if (strcmp("do_simd_coprocessor_error", probe->name) == 0)
        return probe_simd_coprocessor_error_call(probe, data, trigger);

    verror("Unknown trap call!\n");

    /* Call user context change handler. */
    if (user_context_change_handler)
        user_context_change_handler(context_prev_trap, 
                                    context_current,
                                    task_current);

    return -1;
}

/* All traps except system calls are routed to corresponding handlers; return */
static int probe_trap_return(struct probe *probe, 
                             void *data, 
                             struct probe *trigger)
{
    int ret = -1;

    if (strcmp("do_divide_error", probe->name) == 0)
        ret = probe_divide_error_return(probe, data, trigger);
    else if (strcmp("do_debug", probe->name) == 0)
        ret = probe_debug_return(probe, data, trigger);
    else if (strcmp("do_nmi", probe->name) == 0)
        ret = probe_nmi_return(probe, data, trigger);
    else if (strcmp("do_int3", probe->name) == 0)
        ret = probe_int3_return(probe, data, trigger);
    else if (strcmp("do_overflow", probe->name) == 0)
        ret = probe_overflow_return(probe, data, trigger);
    else if (strcmp("do_bounds", probe->name) == 0)
        ret = probe_bounds_return(probe, data, trigger);
    else if (strcmp("do_invalid_op", probe->name) == 0)
        ret = probe_invalid_op_return(probe, data, trigger);
    else if (strcmp("device_not_available", probe->name) == 0)
        ret = probe_device_not_available_return(probe, data, trigger);
    else if (strcmp("do_coprocessor_segment_overrun", probe->name) == 0)
        ret = probe_coprocessor_segment_overrun_return(probe, data, trigger);
    else if (strcmp("double_fault", probe->name) == 0)
        ret = probe_double_fault_return(probe, data, trigger);
    else if (strcmp("do_invalid_TSS", probe->name) == 0)
        ret = probe_invalid_TSS_return(probe, data, trigger);
    else if (strcmp("do_segment_not_present", probe->name) == 0)
        ret = probe_segment_not_present_return(probe, data, trigger);
    else if (strcmp("do_stack_segment", probe->name) == 0)
        ret = probe_stack_segment_return(probe, data, trigger);
    else if (strcmp("do_general_protection", probe->name) == 0)
        ret = probe_general_protection_return(probe, data, trigger);
    else if (strcmp("do_page_fault", probe->name) == 0)
        ret = probe_page_fault_return(probe, data, trigger);
    else if (strcmp("spurious_interrupt_bug", probe->name) == 0)
        ret = probe_spurious_interrupt_bug_return(probe, data, trigger);
    else if (strcmp("do_coprocessor_error", probe->name) == 0)
        ret = probe_coprocessor_error_return(probe, data, trigger);
    else if (strcmp("do_alignment_check", probe->name) == 0)
        ret = probe_alignment_check_return(probe, data, trigger);
    else if (strcmp("intel_machine_check", probe->name) == 0)
        ret = probe_machine_check_return(probe, data, trigger);
    else if (strcmp("do_simd_coprocessor_error", probe->name) == 0)
        ret = probe_simd_coprocessor_error_return(probe, data, trigger);
    else
        verror("Unknown trap return!\n");
    
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Context change: %s -> %s\n", 
                task_current->pid, task_current->comm, 
                context_string(context_current), 
                context_string(context_prev_trap));
    }

    /* Call user context change handler. */
    if (user_context_change_handler)
        user_context_change_handler(context_current, 
                                    context_prev_trap,
                                    task_current);

    context_current = context_prev_trap;

    return  ret;
}

/* TRAP_syscall -- system gate #256; call */
static int probe_syscall_call(struct probe *probe, 
                              void *data, 
                              struct probe *trigger)
{
    unsigned int eax = target_read_reg(t, TID_GLOBAL, 0);
    
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): System call %d (0x%02x) called (context: %s)\n", 
            task_current->pid, task_current->comm,
            eax, eax, context_string(context_current));
    }

    return 0;
}

#if 0
/* TRAP_syscall -- system gate #256; return */
static int probe_syscall_return(struct probe *probe,
                                void *data,
                                struct probe *trigger)
{
    unsigned int eax = target_read_reg(t, 0);
    
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): System call %d (0x%02x) returned (context: %s)\n", 
            task_current->pid, task_current->comm,
            eax, eax, context_string(context_current));
    }
    
    return 0;
}
#endif

/* Interrupt request; call */
static int probe_interrupt_call(struct probe *probe, 
                                void *data, 
                                struct probe *trigger)
{
    ctxprobes_var_t *arg_list = NULL;
    int arg_count = 0;
    struct pt_regs *regs;
    int ret, irq;

    context_prev_intr = context_current;
    context_current = CTXPROBES_CONTEXT_INTERRUPT;

    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Context change: %s -> %s\n", 
                task_current->pid, task_current->comm, 
                context_string(context_prev_intr), 
                context_string(context_current));
    }

    ret = load_func_args(&arg_list, &arg_count, probe, trigger);
    if (ret)
        vdebugc(-1, LOG_C_WARN, "Failed to load function args\n");

    regs = (struct pt_regs *)arg_list[0].buf;
    irq = ~regs->orig_eax & 0xff;
    irq_no = irq;
   
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Interrupt %d (0x%02x) called\n",
                task_current->pid, task_current->comm, 
                irq, irq);
    }

    /* Call user context change handler. */
    if (user_context_change_handler)
        user_context_change_handler(context_prev_intr, 
                                    context_current,
                                    task_current);

    return 0;
}

/* Interrupt request; return */
static int probe_interrupt_return(struct probe *probe, 
                                  void *data, 
                                  struct probe *trigger)
{
    //ctxprobes_var_t *arg_list = NULL;
    //int arg_count = 0;
    //struct pt_regs *regs;
    int irq = irq_no;
    //int ret;
    
    /* FIXME: this currently fails to load symbol. */
    //ret = load_func_args(&arg_list, &arg_count, probe, trigger);
    //if (ret)
    //    vdebugc(-1, LOG_C_WARN, "Failed to load function args\n");

    //regs = (struct pt_regs *)arg_list[0].buf;
    //irq = ~regs->orig_eax & 0xff;

    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Interrupt %d (0x%02x) returned\n",
                task_current->pid, task_current->comm, 
                irq, irq);
    }

    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(-1, LOG_C_CTX, "%d (%s): Context change: %s -> %s\n", 
                task_current->pid, task_current->comm, 
                context_string(context_current), 
                context_string(context_prev_intr));
    }

    /* Call user context change handler. */
    if (user_context_change_handler)
        user_context_change_handler(context_current, 
                                    context_prev_intr,
                                    task_current);

    context_current = context_prev_intr;

    return 0;
}

/* Task switch */
static int probe_task_switch(struct probe *probe, 
                             void *data, 
                             struct probe *trigger)
{
    struct value *lvalue_task_prev, *lvalue_task_next;
    ctxprobes_task_t *task_prev, *task_next;
    int ret;

    lvalue_task_prev = target_load_symbol(probe->target,probe->thread->tid,
					  bsymbol_task_prev, 
					  LOAD_FLAG_NO_CHECK_BOUNDS | 
					  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lvalue_task_prev)
    {
        verror("Cannot access value of schedule.prev\n");
        //return -1;
        return 0;
    }

    lvalue_task_next = target_load_symbol(probe->target,probe->thread->tid,
					  bsymbol_task_next,  
					  LOAD_FLAG_NO_CHECK_BOUNDS | 
					  LOAD_FLAG_NO_CHECK_VISIBILITY);
    if (!lvalue_task_next)
    {
        verror("Cannot access value of schedule.next\n");
        //return -1;
        return 0;
    }

    ret = load_task_info(&task_prev, *(unsigned long *)lvalue_task_prev->buf);
    if (ret)
    {
        verror("Cannot load task info of schedule.prev\n");
        //return -1;
        return 0;
    }

    ret = load_task_info(&task_next, *(unsigned long *)lvalue_task_next->buf);
    if (ret)
    {
        verror("Cannot load task info of schedule.next\n");
        //return -1;
        return 0;
    }

    /* FIXME: consider change to the same task as a task switch for now. */
    //if (task_prev->vaddr != task_next->vaddr)
    {
        if (!user_pidlist || 
            (array_list_contains(user_pidlist, (void *)task_prev->pid) && 
            array_list_contains(user_pidlist, (void *)task_next->pid)))
        {
            vdebugc(-1, LOG_C_CTX, "Task switch: %d (%s) -> %d (%s)\n", 
                    task_prev->pid, task_prev->comm,
                    task_next->pid, task_next->comm);
        }

        /* Call user task switch handler. */
        if (user_task_switch_handler)
            user_task_switch_handler(task_prev, task_next);
    }
    
    unload_task_info(task_prev);

    //if (task_prev->vaddr != task_next->vaddr)
    {
        unload_task_info(task_current);
        task_current = task_next;
    }
    //else
    //    unload_task_info(task_next);

    return 0;
}

/* Load symbols of local variables in schedule, prev and next. */
static int probe_task_switch_init(struct probe *probe)
{
    vdebugc(5, LOG_C_CTX, "Task switch init\n");
    
    bsymbol_task_prev = target_lookup_sym(t,//probe->target, 
                                          "schedule.prev",
                                          ".",
                                          NULL,
                                          SYMBOL_TYPE_NONE);
    if (!bsymbol_task_prev)
    {
        verror("Failed to create a bsymbol for schedule.prev\n");
        return -1;
    }

    bsymbol_task_next = target_lookup_sym(t,//probe->target, 
                                          "schedule.next",
                                          ".",
                                          NULL,
                                          SYMBOL_TYPE_NONE);
    if (!bsymbol_task_next)
    {
        verror("Failed to create a bsymbol for schedule.next\n");
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
      probe_trap_return,                { .init = NULL } },
    { "do_debug",                       probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    { "do_nmi",                         probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    { "do_int3",                        probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    { "do_overflow",                    probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    { "do_bounds",                      probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    { "do_invalid_op",                  probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    //{ "device_not_available",           probe_trap_call, 
    //  NULL,                             { .init = NULL } },
    //{ "double_fault",                   probe_trap_call, 
    //  NULL,                             { .init = NULL } },
    { "do_coprocessor_segment_overrun", probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    { "do_invalid_TSS",                 probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    { "do_segment_not_present",         probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    { "do_stack_segment",               probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    { "do_general_protection",          probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    { "do_page_fault",                  probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    //{ "spurious_interrupt_bug",         probe_trap_call, 
    //  NULL,                             { .init = NULL } },
    { "do_coprocessor_error",           probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    { "do_alignment_check",             probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    //{ "intel_machine_check",            probe_trap_call, 
    //  NULL,                             { .init = NULL } },
    { "do_simd_coprocessor_error",      probe_trap_call, 
      probe_trap_return,                { .init = NULL } },
    { "system_call",                    probe_syscall_call, 
      NULL/*probe_syscall_return*/,             { .init = NULL } },
    { "do_IRQ",                         probe_interrupt_call, 
      probe_interrupt_return,           { .init = NULL } },
    { "schedule.switch_tasks",          probe_task_switch, 
      NULL,                             { .init = probe_task_switch_init } },
    //{ "ret_from_exception",             probe_trap_return, 
    //  NULL,                             { .init = NULL } },
    //{ "ret_from_intr",                  probe_interrupt_return, 
    //  NULL,                             { .init = NULL } },
};

static void sigh(int signo)
{
    ctxprobes_cleanup();
    exit(0);
}

int ctxprobes_init(char *domain_name, 
                   char *sysmap_file, 
                   int debug_level,
		   int xa_debug_level)
{
    int ret;

    if (t)
    {
        verror("Target already initialized\n");
        return -1;
    }

    dom_name = domain_name;

    sysmap_handle = fopen(sysmap_file, "r");
    if (!sysmap_handle)
    {
        verror("Could not open file %s\n", sysmap_file);
        return -2;
    }

    dwdebug_init();
    vmi_set_log_level(debug_level);
#ifdef XA_DEBUG
    xa_set_debug_level(xa_debug_level);
#endif

    t = xen_vm_attach(dom_name, NULL);
    if (!t)
    {
        verror("Can't attach to domain %s!\n", dom_name);
        ctxprobes_cleanup();
        return -3;
    }

    if (target_open(t, NULL))
    {
        verror("Can't open target %s!\n", dom_name);
        ctxprobes_cleanup();
        return -4;
    }

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    ret = perf_init();
    if (ret)
    {
        verror("Failed to init perf/branch counter reader\n");
        ctxprobes_cleanup();
        return -4;
    }
#endif

    probes = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (!probes)
    {
        verror("Can't create probe table for target %s\n", dom_name);
        ctxprobes_cleanup();
        return -5;
    }

    cprobes = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (!cprobes)
    {
        verror("Can't create prologue probe table for target %s\n", dom_name);
        ctxprobes_cleanup();
        return -5;
    }

    rprobes = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (!rprobes)
    {
        verror("Can't create return probe table for target %s\n", dom_name);
        ctxprobes_cleanup();
        return -5;
    }

    disfuncs = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (!disfuncs)
    {
        verror("Can't create disassembled function probe table for target %s\n", 
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
        
        vdebugc(-1, LOG_C_WARN, "Warning: Ending trace.\n");
     
        unregister_probes(probes);
        unload_task_info(task_current);
        
        if (bsymbol_task_prev)
            bsymbol_release(bsymbol_task_prev);
        if (bsymbol_task_next)
            bsymbol_release(bsymbol_task_next);

        target_close(t);
        target_free(t);

        vdebugc(-1, LOG_C_WARN, "Warning: Ended trace.\n");
        fclose(sysmap_handle);

        if (probes) 
            g_hash_table_destroy(probes);
        if (cprobes)
            g_hash_table_destroy(cprobes);
        if (rprobes)
            g_hash_table_destroy(rprobes);
        if (disfuncs)
            g_hash_table_destroy(disfuncs);

        bsymbol_task_prev = NULL;
        bsymbol_task_next = NULL;
        task_current = NULL;
        probes = NULL;
        t = NULL;
        sysmap_handle = NULL;
        dom_name = NULL;
    }
}

int ctxprobes_track(ctxprobes_task_switch_handler_t task_switch_handler,
                    ctxprobes_context_change_handler_t context_change_handler,  
                    ctxprobes_page_fault_handler_t page_fault_handler,  
                    struct array_list *pidlist)
{
    int ret;
    int i, probe_count;

    if (!t)
    {
        verror("Target not initialized\n");
        return -1;
    }

    user_task_switch_handler = task_switch_handler;
    user_context_change_handler = context_change_handler;
    user_page_fault_handler = page_fault_handler;
    user_pidlist = pidlist;

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
                verror("Failed to register call probe on '%s'\n", 
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
                verror("Failed to register return probe on '%s'\n", 
                       probe_list[i].symbol);
                ctxprobes_cleanup();
                return -1;
            }
        }
    }

    return 0;
}

int ctxprobes_wait(void)
{
    target_status_t tstat;
    ADDR task_struct_addr;
    int ret;
    struct bsymbol *init_task;

    if (!t)
    {
        verror("Target not initialized\n");
        return -1;
    }

    /*
     * Run the target for a little while so that it creates the first 
     * task, and get the task info after that.  This is a "stupid" way
     * of fixing the problem caused by starting VMI right after the
     * creation of the suspended guest VM.
     */
    init_task = target_lookup_sym(t,"init_task",NULL,NULL,SYMBOL_TYPE_FLAG_VAR);
    if (!init_task) {
	vwarn("could not lookup init_task in debuginfo!\n");
	return -1;
    }

    if (target_resolve_symbol_base(t,TID_GLOBAL,init_task,&task_struct_addr,
				   NULL)) {
	vwarn("could not resolve addr of init_task!\n");
	return -1;
    }

    bsymbol_release(init_task);

    ret = load_task_info(&task_current, (unsigned)task_struct_addr);
    if (ret)
    {
        vdebugc(-1, LOG_C_WARN, "Warning: Failed to load initial task info!\n");
        return -1;
    }
    
    if (!user_pidlist || 
        array_list_contains(user_pidlist, (void *)task_current->pid))
    {
        vdebugc(0, LOG_C_CTX, "Initial task: %d (%s)\n", 
                task_current->pid, task_current->comm);
    }

    /* 
     * The target is paused after the attach; we have to resume it now
     * that we've registered probes.
     */
    target_resume(t);

    vdebugc(-1, LOG_C_WARN, "Warning: Starting main debugging loop!\n");

    while (1)
    {
        tstat = target_monitor(t);
        if (tstat == TSTATUS_PAUSED)
        {
            vdebugc(-1, LOG_C_WARN, "Warning: Domain %s interrupted "
                    "at 0x%" PRIxREGVAL "\n",
                    dom_name, target_read_reg(t, TID_GLOBAL, t->ipregno));
            if (target_resume(t))
            {
                verror("Can't resume target domain %s\n", dom_name);
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

int ctxprobes_reg_func_call(char *symbol,
                            ctxprobes_func_call_handler_t handler)
{
    int ret;

    if (!t)
    {
        verror("Target not initialized\n");
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
        verror("Failed to register context-aware call probe on '%s'\n", symbol);
        return -1;
    }

    return 0;
}

int ctxprobes_reg_func_prologue(char *symbol,
                                ctxprobes_func_prologue_handler_t handler)
{
    int ret;

    if (!t)
    {
        verror("Target not initialized\n");
        return -1;
    }

    ret = register_prologue_probe(symbol, 
                                  probe_func_prologue,
                                  NULL, /* ops */
                                  PROBEPOINT_EXEC,
                                  SYMBOL_TYPE_FLAG_FUNCTION,
                                  handler); /* data <- ctxprobes handler */
    if (ret)
    {
        verror("Failed to register context-aware prologue probe on '%s'\n", 
               symbol);
        return -1;
    }

    return 0;
}

int ctxprobes_reg_func_return(char *symbol,
                              ctxprobes_func_return_handler_t handler)
{
    int ret;

    if (!t)
    {
        verror("Target not initialized\n");
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
        verror("Failed to register context-aware return probe on '%s'\n", symbol);
        return -1;
    }

    return 0;
}

int ctxprobes_reg_var(unsigned long addr, //char *symbol,
                      char *name, 
                      ctxprobes_var_handler_t handler,
                      int readwrite)
{
    int ret;

    if (!t)
    {
        verror("Target not initialized\n");
        return -1;
    }

    //ret = register_var_probe(symbol,
    //                         probe_var,
    //                         NULL, /* ops */
    //                         (readwrite) ? 
    //                             PROBEPOINT_READWRITE : PROBEPOINT_WRITE,
    //                         SYMBOL_TYPE_FLAG_NONE,//SYMBOL_TYPE_FLAG_VAR,
    //                         handler); /* data <- ctxprobes handler */
    //if (ret)
    //{
    //    verror("Failed to register context-aware var probe on '%s'\n", symbol);
    //    return -1;
    //}

    ret = register_raw_probe(addr, name, 
                             probe_var,
                             (readwrite) ? 
                                 PROBEPOINT_READWRITE : PROBEPOINT_WRITE,
                             handler); /* data <- ctxprobes handler */
    if (ret)
    {
        verror("Failed to register context-aware raw probe on '%s'\n", name);
        return -1;
    }

    return 0;
}

void ctxprobes_unreg_func_call(char *symbol,
        ctxprobes_func_call_handler_t handler)
{
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;

    g_hash_table_iter_init(&iter, probes);
    while (g_hash_table_iter_next(&iter,
           (gpointer)&key,
           (gpointer)&probe))
    {
        if (strcmp(probe->name, symbol) == 0 && 
            probe->handler_data == (void *)handler)
        {
            probe_unregister(probe, 1);
            probe_free(probe, 1);
            g_hash_table_iter_remove(&iter);
            break;
        }
    }
}

void ctxprobes_unreg_func_prologue(char *symbol,
                                   ctxprobes_func_prologue_handler_t handler)
{
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;
    struct bsymbol *bsymbol = NULL;
    ADDR funcstart = 0;
    
    bsymbol = target_lookup_sym(t, symbol, ".", NULL,
                                SYMBOL_TYPE_FLAG_FUNCTION);
    if (bsymbol)
    {
        if (location_resolve_symbol_base(t, TID_GLOBAL, bsymbol, &funcstart, NULL) == 0)
            g_hash_table_remove(cprobes, (gpointer)funcstart);
    }

    g_hash_table_iter_init(&iter, probes);
    while (g_hash_table_iter_next(&iter,
           (gpointer)&key,
           (gpointer)&probe))
    {
        if (strcmp(probe->name, symbol) == 0 && 
            probe->handler_data == (void *)handler)
        {
            probe_unregister(probe, 1);
            probe_free(probe, 1);
            g_hash_table_iter_remove(&iter);
            break;
        }
    }
}

void ctxprobes_unreg_func_return(char *symbol,
                                 ctxprobes_func_return_handler_t handler)
{
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;
    struct bsymbol *bsymbol = NULL;
    ADDR funcstart = 0;
    
    bsymbol = target_lookup_sym(t, symbol, ".", NULL, 
                                SYMBOL_TYPE_FLAG_FUNCTION);
    if (bsymbol)
    {
	if (location_resolve_symbol_base(t, TID_GLOBAL, bsymbol, &funcstart, NULL) == 0)
            g_hash_table_remove(rprobes, (gpointer)funcstart);
    }

    g_hash_table_iter_init(&iter, probes);
    while (g_hash_table_iter_next(&iter,
           (gpointer)&key,
           (gpointer)&probe))
    {
        if (strcmp(probe->name, symbol) == 0 && 
            probe->handler_data == (void *)handler)
        {
            probe_unregister(probe, 1);
            probe_free(probe, 1);
            g_hash_table_iter_remove(&iter);
            break;
        }
    }
}

void ctxprobes_unreg_var(char *symbol,
                         ctxprobes_var_handler_t handler)
{
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;

    g_hash_table_iter_init(&iter, probes);
    while (g_hash_table_iter_next(&iter,
           (gpointer)&key,
           (gpointer)&probe))
    {
        if (strcmp(probe->name, symbol) == 0 && 
            probe->handler_data == (void *)handler)
        {
            probe_unregister(probe, 1);
            probe_free(probe, 1);
            g_hash_table_iter_remove(&iter);
            break;
        }
    }
}

int ctxprobes_instrument_func_name(char *symbol,
				   ctxprobes_disfunc_handler_t call_handler,
				   ctxprobes_disfunc_handler_t return_handler)
{
    struct bsymbol *bsymbol;
    ADDR funcstart;

    //struct dump_info udn = {
    //    .stream = stderr,
    //    .prefix = "",
    //    .detail = 1,
    //    .meta = 1,
    //};

    bsymbol = target_lookup_sym(t, symbol, ".", NULL,
				SYMBOL_TYPE_FLAG_FUNCTION);
    if (!bsymbol)
    {
	verror("Could not find symbol %s!\n", symbol);
	return 0;
    }

    //bsymbol_dump(bsymbol, &udn);

    if ((funcstart = instrument_func(bsymbol, 
                                     probe_disfunc_call, 
                                     probe_disfunc_return, 
                                     call_handler, /* data <- ctxprobes handler */
                                     return_handler, /* data <- ctxprobes handler */
                                     1 /* root */)) == 0) 
    {
        verror("Could not instrument function %s (0x%08x)!\n",
               bsymbol->lsymbol->symbol->name, funcstart);
        return -1;
    }

    user_disfunc_return_handler = return_handler;

    return 0;
}

int ctxprobes_instrument_func(struct bsymbol *bsymbol,
                              ctxprobes_disfunc_handler_t call_handler,
                              ctxprobes_disfunc_handler_t return_handler)
{
    ADDR funcstart;

    //struct dump_info udn = {
    //    .stream = stderr,
    //    .prefix = "",
    //    .detail = 1,
    //    .meta = 1,
    //};

    //bsymbol_dump(bsymbol, &udn);

    if ((funcstart = instrument_func(bsymbol, 
                                     probe_disfunc_call, 
                                     probe_disfunc_return, 
                                     call_handler, /* data <- ctxprobes handler */
                                     return_handler, /* data <- ctxprobes handler */
                                     1 /* root */)) == 0) 
    {
        verror("Could not instrument function %s (0x%08x)!\n",
               bsymbol->lsymbol->symbol->name, funcstart);
        return -1;
    }

    user_disfunc_return_handler = return_handler;

    return 0;
}

unsigned long ctxprobes_funcstart(struct bsymbol *bsymbol)
{
    ADDR funcstart;

    if (location_resolve_symbol_base(t, TID_GLOBAL, bsymbol, &funcstart, NULL)) 
    {
        verror("Could not resolve base addr for function %s!\n",
               bsymbol->lsymbol->symbol->name);
        return 0;
    }

    return (unsigned long)funcstart;
}

unsigned long ctxprobes_funcstart_name(char *symbol)
{
    struct bsymbol *bsymbol = NULL;
    ADDR funcstart;
    
    bsymbol = target_lookup_sym(t, symbol, ".", NULL, SYMBOL_TYPE_FLAG_FUNCTION);
    if (!bsymbol)
    {
        verror("Could not find symbol %s!\n", symbol);
        return 0;
    }

    if (location_resolve_symbol_base(t, TID_GLOBAL, bsymbol, &funcstart, NULL)) 
    {
        verror("Could not resolve base addr for function %s!\n",
               bsymbol->lsymbol->symbol->name);
        return 0;
    }

    return (unsigned long)funcstart;
}

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL

unsigned long long ctxprobes_get_rdtsc(void)
{
    if (!t)
    {
        verror("Target not initialized\n");
        return 0;
    }

    return (perf_get_rdtsc(t));
}

unsigned long long ctxprobes_get_brctr(void)
{
    if (!t)
    {
        verror("Target not initialized\n");
        return 0;
    }

    return (perf_get_brctr(t));
}

#endif /* CONFIG_DETERMINISTIC_TIMETRAVEL */

