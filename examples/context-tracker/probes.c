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
 *  examples/context-tracker/probes.c
 *
 *  Probe handlers used to track contexts.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#include <errno.h>
#include "target_xen_vm.h"

static struct bsymbol *bsymbol_task_prev;
static struct bsymbol *bsymbol_task_next;
static struct bsymbol *bsymbol_interrupt_regs;
static struct bsymbol *bsymbol_pagefault_regs;
static struct bsymbol *bsymbol_pagefault_error_code;
static struct bsymbol *bsymbol_exception_regs[64];
static struct bsymbol *bsymbol_exception_error_code[64];

/* GLOBALLY SHARED HANDLERS */

static void *probe_context_summarize(struct probe *probe)
{
	return context;
}

/* TASK SWITCH HANDLERS */

/* Called upon the execution of label schedule.switch_tasks. */
static int probe_taskswitch(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	struct value *value_prev, *value_next;
	GHashTableIter iter;
	probe_handler_t user_handler;
	void *user_handler_data;
	struct target *target = probe->target;
	struct target_thread *tthread = probe->thread;
	tid_t tid = tthread->tid;

	context = (ctxtracker_context_t *)data;

	if (!bsymbol_task_prev)
	{
		verror("bsymbol for previous task is NULL\n");
		return -1;
	}

	if (!bsymbol_task_next)
	{
		verror("bsymbol for next task is NULL\n");
		return -1;
	}

	value_prev = target_load_symbol(target,tid,bsymbol_task_prev,
					LOAD_FLAG_AUTO_DEREF);
	if (!value_prev)
	{
		verror("Could not load previous task symbol\n");
		return -1;
	}

	value_next = target_load_symbol(target,tid,bsymbol_task_next,
					LOAD_FLAG_AUTO_DEREF);
	if (!value_next)
	{
		verror("Could not load next task symbol\n");
		value_free(value_prev);
		return -1;
	}

	if (context->task.prev)
	    value_free(context->task.prev);
	context->task.prev = value_prev;

	if (context->task.cur)
		value_free(context->task.cur);
	context->task.cur = value_next;

	g_hash_table_iter_init(&iter, taskswitch_user_handlers);
	while (g_hash_table_iter_next(&iter, (gpointer)&user_handler, 
			(gpointer)&user_handler_data))
	{
		ret = user_handler(probe, user_handler_data, trigger);
		if (ret)
		{
			verror("User handler for task switches returned %d\n", ret);
			return ret;
		}
	}

	return 0;
}

/* Called after the probe on label schedule.switch_tasks gets initialized. */
static int probe_taskswitch_init(struct probe *probe)
{
	static const char *symbol_task_prev = "schedule.prev";
	static const char *symbol_task_next = "schedule.next";

	bsymbol_task_prev = target_lookup_sym(probe->target, 
			(char *)symbol_task_prev, ".", NULL /* srcfile */, 
			SYMBOL_TYPE_NONE);
	if (!bsymbol_task_prev)
	{
		verror("Could not find symbol '%s'\n", symbol_task_prev);
		return -1;
	}

	bsymbol_task_next = target_lookup_sym(probe->target, 
			(char *)symbol_task_next, ".", NULL /* srcfile */, 
			SYMBOL_TYPE_NONE);
	if (!bsymbol_task_next)
	{
		verror("Could not find symbol '%s'\n", symbol_task_next);
		return -1;
	}

	return 0;
}

/* Called before the probe on label schedule.switch_tasks gets deallocated. */
static int probe_taskswitch_fini(struct probe *probe)
{
	ctxtracker_context_t *context;

	context = (ctxtracker_context_t *)probe->handler_data;

	if (context->task.cur)
	{
		value_free(context->task.cur);
		context->task.cur = NULL;
	}

	if (context->task.prev)
	{
		value_free(context->task.prev);
		context->task.prev = NULL;
	}

	if (bsymbol_task_prev)
	{
		bsymbol_release(bsymbol_task_prev);
		bsymbol_task_prev = NULL;
	}

	if (bsymbol_task_next)
	{
		bsymbol_release(bsymbol_task_next);
		bsymbol_task_next = NULL;
	}

	return 0;
}

/* INTERRUPT HANDLERS */

/* Call to interrupt request handler do_IRQ */
static int probe_interrupt_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *member_regs_orig_eax = "orig_eax";

	int ret;
	ctxtracker_context_t *context;
	struct value *value_regs;
	REGVAL orig_eax;
	int irq_num;
	GHashTableIter iter;
	probe_handler_t user_handler;
	void *user_handler_data;
	struct target *target = probe->target;
	struct target_thread *tthread = probe->thread;
	tid_t tid = tthread->tid;

	context = (ctxtracker_context_t *)data;

	if (!bsymbol_interrupt_regs)
	{
		verror("bsymbol for interrupt regs is NULL\n");
		return -1;
	}

	value_regs = target_load_symbol(target,tid,bsymbol_interrupt_regs,
					LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load interrupt regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_orig_eax, 
			&orig_eax);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_orig_eax);
		value_free(value_regs);
		return ret;
	}

	irq_num = ~orig_eax & 0xff;

	context->flags |= TRACK_INTERRUPT;

	context->interrupt.irq_num = irq_num;
	context->interrupt.regs = value_regs;

	g_hash_table_iter_init(&iter, interrupt_entry_user_handlers);
	while (g_hash_table_iter_next(&iter, (gpointer)&user_handler, 
			(gpointer)&user_handler_data))
	{
		ret = user_handler(probe, user_handler_data, trigger);
		if (ret)
		{
			verror("User handler for interrupt entries returned %d\n", ret);
			return ret;
		}
	}

	return 0;
}

/* Return from interrupt request handler do_IRQ */
static int probe_interrupt_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	GHashTableIter iter;
	probe_handler_t user_handler;
	void *user_handler_data;

	context = (ctxtracker_context_t *)data;

	g_hash_table_iter_init(&iter, interrupt_exit_user_handlers);
	while (g_hash_table_iter_next(&iter, (gpointer)&user_handler, 
			(gpointer)&user_handler_data))
	{
		ret = user_handler(probe, user_handler_data, trigger);
		if (ret)
		{
			verror("User handler for interrupt exits returned %d\n", ret);
			return ret;
		}
	}

	context->interrupt.irq_num = 0;
	if (context->interrupt.regs)
		value_free(context->interrupt.regs);
	context->interrupt.regs = NULL;

	context->flags &= ~(TRACK_INTERRUPT);

	return 0;
}

/* Called after the probe on do_IRQ entry gets initialized. */
static int probe_interrupt_init(struct probe *probe)
{
	static const char *symbol_interrupt_regs = "do_IRQ.regs";

	bsymbol_interrupt_regs = target_lookup_sym(probe->target, 
			(char *)symbol_interrupt_regs, ".", NULL /* srcfile */, 
			SYMBOL_TYPE_NONE);
	if (!bsymbol_interrupt_regs)
	{
		verror("Could not find symbol '%s'\n", symbol_interrupt_regs);
		return -1;
	}

	return 0;
}

/* Called before the probe on do_IRQ entry gets deallocated. */
static int probe_interrupt_fini(struct probe *probe)
{
	ctxtracker_context_t *context;

	context = (ctxtracker_context_t *)probe->handler_data;

	if (bsymbol_interrupt_regs)
	{
		bsymbol_release(bsymbol_interrupt_regs);
		bsymbol_interrupt_regs = NULL;
	}

	context->interrupt.irq_num = 0;
	if (context->interrupt.regs)
		value_free(context->interrupt.regs);
	context->interrupt.regs = NULL;

	context->flags &= ~(TRACK_INTERRUPT);

	return 0;
}

/* PAGE FAULT HANDLERS */

/* TRAP_page_fault -- trap gate #14; entry */
static int probe_pagefault_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL cr2;
	ADDR addr;
	uint32_t error_code;
	bool protection_fault;
	bool write_access;
	bool user_mode;
	bool reserved_bit;
	bool instr_fetch;
	GHashTableIter iter;
	probe_handler_t user_handler;
	void *user_handler_data;
	struct target *target = probe->target;
	struct target_thread *tthread = probe->thread;
	tid_t tid = tthread->tid;

	context = (ctxtracker_context_t *)data;

	if (!bsymbol_pagefault_regs)
	{
		verror("bsymbol for pagefault regs is NULL\n");
		return -1;
	}

	if (!bsymbol_pagefault_error_code)
	{
		verror("bsymbol for pagefault error_code is NULL\n");
		return -1;
	}

	cr2 = target_read_reg(target,TID_GLOBAL,XV_TSREG_CR2);
	if (errno)
	{
		verror("Could not read cr2 register\n");
		return -1;
	}

	value_regs = target_load_symbol(target,tid,bsymbol_pagefault_regs,
					LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load pagefault regs symbol\n");
		return -1;
	}

	value_error_code = target_load_symbol(target,tid,
					      bsymbol_pagefault_error_code, 
					      LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load pagefault error_code symbol\n");
		value_free(value_regs);
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	addr = (ADDR)cr2;

	protection_fault = ((error_code & 1) != 0);
	write_access = ((error_code & 2) != 0);
	user_mode = ((error_code & 4) != 0);
	reserved_bit = ((error_code & 8) != 0);
	instr_fetch = ((error_code & 16) != 0);

	context->flags |= TRACK_PAGEFAULT;

	context->pagefault.addr = addr;
	context->pagefault.regs = value_regs;
	context->pagefault.protection_fault = protection_fault;
	context->pagefault.write_access = write_access;
	context->pagefault.user_mode = user_mode;
	context->pagefault.reserved_bit = reserved_bit;
	context->pagefault.instr_fetch = instr_fetch;

	g_hash_table_iter_init(&iter, pagefault_entry_user_handlers);
	while (g_hash_table_iter_next(&iter, (gpointer)&user_handler, 
			(gpointer)&user_handler_data))
	{
		ret = user_handler(probe, user_handler_data, trigger);
		if (ret)
		{
			verror("User handler for page fault entries returned %d\n", ret);
			return ret;
		}
	}

	return 0;
}

/* TRAP_page_fault -- trap gate #14; exit */
static int probe_pagefault_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	GHashTableIter iter;
	probe_handler_t user_handler;
	void *user_handler_data;

	context = (ctxtracker_context_t *)data;

	g_hash_table_iter_init(&iter, pagefault_exit_user_handlers);
	while (g_hash_table_iter_next(&iter, (gpointer)&user_handler, 
			(gpointer)&user_handler_data))
	{
		ret = user_handler(probe, user_handler_data, trigger);
		if (ret)
		{
			verror("User handler for page fault exits returned %d\n", ret);
			return ret;
		}
	}

	context->pagefault.addr = 0;
	if (context->pagefault.regs)
		value_free(context->pagefault.regs);
	context->pagefault.regs = NULL;
	context->pagefault.protection_fault = false;
	context->pagefault.write_access = false;
	context->pagefault.user_mode = false;
	context->pagefault.reserved_bit = false;
	context->pagefault.instr_fetch = false;

	context->flags &= ~(TRACK_PAGEFAULT);

	return 0;
}

/* Called after the probe on do_page_fault entry gets initialized. */
static int probe_pagefault_init(struct probe *probe)
{
	static const char *symbol_pagefault_regs = "do_page_fault.regs";
	static const char *symbol_pagefault_error_code = "do_page_fault.error_code";

	bsymbol_pagefault_regs = target_lookup_sym(probe->target, 
			(char *)symbol_pagefault_regs, ".", NULL /* srcfile */, 
			SYMBOL_TYPE_NONE);
	if (!bsymbol_pagefault_regs)
	{
		verror("Could not find symbol '%s'\n", symbol_pagefault_regs);
		return -1;
	}

	bsymbol_pagefault_error_code = target_lookup_sym(probe->target, 
			(char *)symbol_pagefault_error_code, ".", NULL /* srcfile */, 
			SYMBOL_TYPE_NONE);
	if (!bsymbol_pagefault_error_code)
	{
		verror("Could not find symbol '%s'\n", symbol_pagefault_error_code);
		return -1;
	}

	return 0;
}

/* Called before the probe on do_page_fault entry gets deallocated. */
static int probe_pagefault_fini(struct probe *probe)
{
	ctxtracker_context_t *context;

	context = (ctxtracker_context_t *)probe->handler_data;

	if (bsymbol_pagefault_regs)
	{
		bsymbol_release(bsymbol_pagefault_regs);
		bsymbol_pagefault_regs = NULL;
	}

	if (bsymbol_pagefault_error_code)
	{
		bsymbol_release(bsymbol_pagefault_error_code);
		bsymbol_pagefault_error_code = NULL;
	}

	context->pagefault.addr = 0;
	if (context->pagefault.regs)
		value_free(context->pagefault.regs);
	context->pagefault.regs = NULL;
	context->pagefault.protection_fault = false;
	context->pagefault.write_access = false;
	context->pagefault.user_mode = false;
	context->pagefault.reserved_bit = false;
	context->pagefault.instr_fetch = false;

	context->flags &= ~(TRACK_PAGEFAULT);

	return 0;
}

/* EXCEPTION HANDLERS */

struct exception_handler_data {
	int index;
	ctxtracker_context_t *context;
};

/* Common handler called by all probe handlers on exception function entries. */
static int probe_exception_entry(struct probe *probe, void *data,
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	uint32_t error_code;
	GHashTableIter iter;
	probe_handler_t user_handler;
	void *user_handler_data;
	struct target *target = probe->target;
	struct target_thread *tthread = probe->thread;
	tid_t tid = tthread->tid;

	handler_data = (struct exception_handler_data *)data;
	i = handler_data->index;
	context = handler_data->context;

	if (!bsymbol_exception_regs[i])
	{
		verror("bsymbol for exception regs is NULL\n");
		return -1;
	}

	if (!bsymbol_exception_error_code[i])
	{
		verror("bsymbol for exception error_code is NULL\n");
		return -1;
	}

	value_regs = target_load_symbol(target,tid,bsymbol_exception_regs[i],
					LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	value_error_code = target_load_symbol(target,tid,
					      bsymbol_exception_error_code[i], 
					      LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	context->flags |= TRACK_EXCEPTION;

	context->exception.regs = value_regs;
	context->exception.error_code = error_code;

	g_hash_table_iter_init(&iter, exception_entry_user_handlers);
	while (g_hash_table_iter_next(&iter, (gpointer)&user_handler, 
			(gpointer)&user_handler_data))
	{
		ret = user_handler(probe, user_handler_data, trigger);
		if (ret)
		{
			verror("User handler for exception entries returned %d\n", ret);
			return ret;
		}
	}

	return 0;
}

/* Common handler called by all probe handlers on exception function exits. */
static int probe_exception_exit(struct probe *probe, void *data,
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	GHashTableIter iter;
	probe_handler_t user_handler;
	void *user_handler_data;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	g_hash_table_iter_init(&iter, exception_exit_user_handlers);
	while (g_hash_table_iter_next(&iter, (gpointer)&user_handler, 
			(gpointer)&user_handler_data))
	{
		ret = user_handler(probe, user_handler_data, trigger);
		if (ret)
		{
			verror("User handler for exception exits returned %d\n", ret);
			return ret;
		}
	}

	memset(context->exception.name, 0, sizeof(char)*128);
	if (context->exception.regs)
		value_free(context->exception.regs);
	context->exception.regs = NULL;
	context->exception.error_code = 0;

	context->flags &= ~(TRACK_EXCEPTION);

	return 0;
}

/* TRAP_divide_error -- trap gate #0; entry */
static int probe_divide_error_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "divide error";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_divide_error -- trap gate #0; exit */
static int probe_divide_error_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_debug -- interrupt gate #1; entry */
static int probe_debug_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "debug";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_debug -- interrupt gate #1; exit */
static int probe_debug_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_nmi -- interrupt gate #2; entry */
static int probe_nmi_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "nmi";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_nmi -- interrupt gate #2; exit */
static int probe_nmi_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_int3 -- system interrupt gate #3; entry */
static int probe_int3_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "breakpoint";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_int3 -- system interrupt gate #3; exit */
static int probe_int3_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_overflow -- system gate #4; entry */
static int probe_overflow_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "overflow";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_overflow -- system gate #4; exit */
static int probe_overflow_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_bounds -- trap gate #5; entry */
static int probe_bounds_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "bounds";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_bounds -- trap gate #5; exit */
static int probe_bounds_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_invalid_op -- trap gate #6; entry */
static int probe_invalid_op_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "invalid opcode";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;
	
	return 0;
}

/* TRAP_invalid_op -- trap gate #6; exit */
static int probe_invalid_op_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_no_device -- trap gate #7; entry */
static int probe_device_not_available_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_device_not_available_entry;

	return 0;
}

/* TRAP_no_device -- trap gate #7; exit */
static int probe_device_not_available_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_device_not_available_exit;

	return 0;
}

/* TRAP_double_fault -- trap gate #8; entry */
static int probe_double_fault_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_double_fault_entry;

	return 0;
}

/* TRAP_double_fault -- trap gate #8; exit */
static int probe_double_fault_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_double_fault_exit;

	return 0;
}

/* TRAP_copro_seg -- trap gate #9; entry */
static int probe_coprocessor_segment_overrun_entry(struct probe *probe, 
		void *data, struct probe *trigger)
{
	static const char *exception_name = "coprocessor segment";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_copro_seg -- trap gate #9; exit */
static int probe_coprocessor_segment_overrun_exit(struct probe *probe, 
		void *data, struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_invalid_tss -- trap gate #10; entry */
static int probe_invalid_TSS_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "invalid tss";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_invalid_tss -- trap gate #10; exit */
static int probe_invalid_TSS_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_no_segment -- trap gate #11; entry */
static int probe_segment_not_present_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "no segment";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_no_segment -- trap gate #11; exit */
static int probe_segment_not_present_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_stack_error -- trap gate #12; entry */
static int probe_stack_segment_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "stack error";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_stack_error -- trap gate #12; exit */
static int probe_stack_segment_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_gp_fault -- trap gate #13; entry */
static int probe_general_protection_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "gp fault";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;
	
	return 0;
}

/* TRAP_gp_fault -- trap gate #13; exit */
static int probe_general_protection_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_spurious_int -- trap gate #15; entry */
static int probe_spurious_interrupt_bug_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_spurious_interrupt_bug_entry;

	return 0;
}

/* TRAP_spurious_int -- trap gate #15; exit */
static int probe_spurious_interrupt_bug_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_spurious_interrupt_bug_exit;

	return 0;
}

/* TRAP_copro_error -- trap gate #16; entry */
static int probe_coprocessor_error_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "coprocessor error";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;
	
	return 0;
}

/* TRAP_copro_error -- trap gate #16; exit */
static int probe_coprocessor_error_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_alignment_check -- trap gate #17; entry */
static int probe_alignment_check_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "alignment check";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_alignment_check -- trap gate #17; exit */
static int probe_alignment_check_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_machine_check -- trap gate #18; entry */
static int probe_machine_check_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_machine_check_entry;

	return 0;
}

/* TRAP_machine_check -- trap gate #18; exit */
static int probe_machine_check_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_machine_check_exit;

	return 0;
}

/* TRAP_simd_error -- trap gate #19; entry */
static int probe_simd_coprocessor_error_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *exception_name = "simd error";

	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	strcpy(context->exception.name, exception_name);

	ret = probe_exception_entry(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* TRAP_simd_error -- trap gate #19; exit */
static int probe_simd_coprocessor_error_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;

	handler_data = (struct exception_handler_data *)data;
	context = handler_data->context;

	ret = probe_exception_exit(probe, data, trigger);
	if (ret)
		return ret;

	return 0;
}

/* Called after a probe on an exception handler entry gets initialized. */
static int probe_exception_init(struct probe *probe)
{
	int i;
	char *symbol;
	struct exception_handler_data *handler_data;
	char symbol_exception_regs[128];
	char symbol_exception_error_code[128];

	symbol = probe->name;
	handler_data = (struct exception_handler_data *)probe->handler_data;
	i = handler_data->index;

	sprintf(symbol_exception_regs, "%s.regs", symbol);
	sprintf(symbol_exception_error_code, "%s.error_code", symbol);

	bsymbol_exception_regs[i] = target_lookup_sym(probe->target, 
			(char *)symbol_exception_regs, ".", NULL /* srcfile */, 
			SYMBOL_TYPE_NONE);
	if (!bsymbol_exception_regs[i])
	{
		verror("Could not find symbol '%s'\n", symbol_exception_regs);
		return -1;
	}

	bsymbol_exception_error_code[i] = target_lookup_sym(probe->target, 
			(char *)symbol_exception_error_code, ".", NULL /* srcfile */, 
			SYMBOL_TYPE_NONE);
	if (!bsymbol_exception_error_code[i])
	{
		verror("Could not find symbol '%s'\n", symbol_exception_error_code);
		return -1;
	}

	return 0;
}

/* Called before the probe on an exception handler entry gets deallocated. */
static int probe_exception_fini(struct probe *probe)
{
	int i;
	struct exception_handler_data *handler_data;

	handler_data = (struct exception_handler_data *)probe->handler_data;
	i = handler_data->index;

	if (bsymbol_exception_regs[i])
	{
		bsymbol_release(bsymbol_exception_regs[i]);
		bsymbol_exception_regs[i] = NULL;
	}

	if (bsymbol_exception_error_code[i])
	{
		bsymbol_release(bsymbol_exception_error_code[i]);
		bsymbol_exception_error_code[i] = NULL;
	}

	if (i == 0)
	{
		memset(context->exception.name, 0, sizeof(char)*128);
		if (context->exception.regs)
			value_free(context->exception.regs);
		context->exception.regs = NULL;
		context->exception.error_code = 0;

		context->flags &= ~(TRACK_EXCEPTION);
	}

	return 0;
}

/* SYSTEM CALL HANDLERS */

/* TRAP_sysentry -- system gate #256; entry */
static int probe_syscall_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	unsigned int eax;
	int sc_num;
	GHashTableIter iter;
	probe_handler_t user_handler;
	void *user_handler_data;
	tid_t tid = probe->thread->tid;

	context = (ctxtracker_context_t *)data;

	eax = target_read_reg(t,tid,0);
	sc_num = eax;

	context->flags |= TRACK_SYSCALL;

	context->syscall.sc_num = sc_num;

	g_hash_table_iter_init(&iter, syscall_entry_user_handlers);
	while (g_hash_table_iter_next(&iter, (gpointer)&user_handler, 
			(gpointer)&user_handler_data))
	{
		ret = user_handler(probe, user_handler_data, trigger);
		if (ret)
		{
			verror("User handler for system call entries returned %d\n", ret);
			return ret;
		}
	}

	return 0;
}

/* TRAP_sysentry -- system gate #256; exit */
static int probe_syscall_exit(struct probe *probe, void *data,
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	GHashTableIter iter;
	probe_handler_t user_handler;
	void *user_handler_data;
	struct target *target = probe->target;
	tid_t tid;
	struct target_thread *tthread;
	struct xen_vm_thread_state *xtstate;
	REGVAL espval;
	unsigned long cs;
	unsigned long eip;

	tthread = target->current_thread;
	tid = tthread->tid;
	xtstate = (struct xen_vm_thread_state *)tthread->state;

	/*
	 * If we're coming from interrupt mode, this is not an exit.
	 *
	 * If we're returning to a kernel thread (ring < 3), not a
	 * syscall.
	 */
	if (HARDIRQ_COUNT(xtstate->thread_info_preempt_count)
	    || SOFTIRQ_COUNT(xtstate->thread_info_preempt_count)) {
	    vdebug(5,LOG_T_THREAD,"in interrupt context, not syscall ret\n");
	    return 0;
	}
	else {
	    /* Load esp + 4 (CS register), and read CPL; if it's not
	     * 0x3, this is not a syscall return.
	     */
	    espval = target_read_creg(target,tid,CREG_SP);
	    if (!target_read_addr(target,espval + 4,sizeof(unsigned long),
				  (unsigned char *)&cs)) 
		vwarn("could not read which CPL returning to; not checking!\n");
	    else if (!target_read_addr(target,espval,sizeof(unsigned long),
				  (unsigned char *)&eip)) 
		vwarn("could not read which EIP returning to; not checking!\n");
	    else if ((cs & 0x3) < 0x3) {
		vdebug(5,LOG_T_THREAD,
		       "not ret to user (EIP 0x%lx,CS 0x%lx); not syscall ret\n",
		       eip);
		return 0;
	    }
	    else {
		vdebug(5,LOG_T_THREAD,
		       "ret to user (EIP 0x%lx, CS 0x%lx); is syscall ret!\n",
		       eip,cs);
	    }
	}

	context = (ctxtracker_context_t *)data;

	g_hash_table_iter_init(&iter, syscall_exit_user_handlers);
	while (g_hash_table_iter_next(&iter, (gpointer)&user_handler, 
			(gpointer)&user_handler_data))
	{
		ret = user_handler(probe, user_handler_data, trigger);
		if (ret)
		{
			verror("User handler for system call exits returned %d\n", ret);
			return ret;
		}
	}

	context->syscall.sc_num = 0;

	context->flags &= ~(TRACK_SYSCALL);

	return 0;
}

/* Called after the probe on system_call entry gets initialized. */
static int probe_syscall_init(struct probe *probe)
{
	return 0;
}

/* Called before the probe on system_call entry gets deallocated. */
static int probe_syscall_fini(struct probe *probe)
{
	ctxtracker_context_t *context;

	context = (ctxtracker_context_t *)probe->handler_data;

	context->syscall.sc_num = 0;

	context->flags &= ~(TRACK_SYSCALL);

	return 0;
}

