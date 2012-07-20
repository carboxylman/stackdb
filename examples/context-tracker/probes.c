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

static const char *member_task_pid = "pid";
static const char *member_task_name = "comm";
static const char *member_regs_orig_eax = "orig_eax";
static const char *member_regs_eip = "eip";
	
static struct bsymbol *bsymbol_task_prev;
static struct bsymbol *bsymbol_task_next;
static struct bsymbol *bsymbol_interrupt_regs;
static struct bsymbol *bsymbol_pagefault_regs;
static struct bsymbol *bsymbol_pagefault_error_code;
static struct bsymbol *bsymbol_exception_regs[64];
static struct bsymbol *bsymbol_exception_error_code[64];

/* TASK SWITCH HANDLERS */

/* Called upon the execution of label schedule.switch_tasks. */
static int probe_taskswitch(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	struct value *value_prev, *value_next;
	int prev_pid, next_pid;
	char prev_name[PATH_MAX], next_name[PATH_MAX];

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

	value_prev = bsymbol_load(bsymbol_task_prev, LOAD_FLAG_AUTO_DEREF);
	if (!value_prev)
	{
		verror("Could not load previous task symbol\n");
		return -1;
	}

	ret = get_member_i32(probe->target, value_prev, member_task_pid, &prev_pid);
	if (ret)
	{
		verror("Could not load member int32 '%s.%s'\n", 
				value_prev->lsymbol->symbol->name, member_task_pid);
		value_free(value_prev);
		return ret;
	}

	ret = get_member_string(probe->target, value_prev, member_task_name, 
			prev_name);
	if (ret)
	{
		verror("Could not load member string '%s.%s'\n", 
				value_prev->lsymbol->symbol->name, member_task_name);
		value_free(value_prev);
		return ret;
	}

	value_next = bsymbol_load(bsymbol_task_next, LOAD_FLAG_AUTO_DEREF);
	if (!value_next)
	{
		verror("Could not load next task symbol\n");
		value_free(value_prev);
		return -1;
	}

	ret = get_member_i32(probe->target, value_next, member_task_pid, &next_pid);
	if (ret)
	{
		verror("Could not load member int32 '%s.%s'\n", 
				value_next->lsymbol->symbol->name, member_task_pid);
		value_free(value_prev);
		value_free(value_next);
		return ret;
	}

	ret = get_member_string(probe->target, value_next, member_task_name, 
			next_name);
	if (ret)
	{
		verror("Could not load member string '%s.%s'\n", 
				value_next->lsymbol->symbol->name, member_task_name);
		value_free(value_prev);
		value_free(value_next);
		return ret;
	}

	vdebugc(-1, LOG_C_CTX, "TASK SWITCH: %d (%s) -> %d (%s)\n", 
			prev_pid, prev_name, next_pid, next_name);

	/* FIXME: uncomment the below code when Dave works out the problem. */
	//if (context->task.prev)
		//value_free(context->task.prev);
	context->task.prev = value_prev;

	if (context->task.cur)
		value_free(context->task.cur);
	context->task.cur = value_next;

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
	int ret;
	ctxtracker_context_t *context;
	struct value *value_regs;
	REGVAL orig_eax;
	int irq_num;
	int task_pid;
	char task_name[PATH_MAX];

	context = (ctxtracker_context_t *)data;

	if (!bsymbol_interrupt_regs)
	{
		verror("bsymbol for interrupt regs is NULL\n");
		return -1;
	}

	value_regs = bsymbol_load(bsymbol_interrupt_regs, LOAD_FLAG_AUTO_DEREF);
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

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid, 
				&task_pid);
		if (ret)
		{
			verror("Could not load member int32 '%s.%s'\n", 
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			value_free(value_regs);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur, 
				member_task_name, task_name);
		if (ret)
		{
			verror("Could not load member string '%s.%s'\n", 
					context->task.cur->lsymbol->symbol->name, member_task_name);
			value_free(value_regs);
			return ret;
		}
	
		vdebugc(-1, LOG_C_CTX, "%d (%s): Interrupt %d (0x%02x) requested\n", 
				task_pid, task_name, irq_num, irq_num);
	}
	else
	{
		vdebugc(-1, LOG_C_CTX, "UNKNOWN TASK: Interrupt %d (0x%02x) "
				"requested\n", irq_num, irq_num);
	}

	context->flags |= TRACK_INTERRUPT;

	context->interrupt.irq_num = irq_num;
	context->interrupt.regs = value_regs;

	return 0;
}

/* Return from interrupt request handler do_IRQ */
static int probe_interrupt_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	int irq_num;
	int task_pid;
	char task_name[PATH_MAX];
	
	context = (ctxtracker_context_t *)data;

	irq_num = context->interrupt.irq_num;

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid, 
				&task_pid);
		if (ret)
		{
			verror("Could not load member int32 '%s.%s'\n", 
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur, 
				member_task_name, task_name);
		if (ret)
		{
			verror("Could not load member string '%s.%s'\n", 
					context->task.cur->lsymbol->symbol->name, member_task_name);
			return ret;
		}
	
		vdebugc(-1, LOG_C_CTX, "%d (%s): Interrupt %d (0x%02x) handled\n", 
				task_pid, task_name, irq_num, irq_num);
	}
	else
	{
		vdebugc(-1, LOG_C_CTX, "UNKNOWN TASK: Interrupt %d (0x%02x) handled\n", 
				irq_num, irq_num);
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
	REGVAL eip;
	ADDR addr;
	uint32_t error_code;
	bool protection_fault;
	bool write_access;
	bool user_mode;
	bool reserved_bit;
	bool instr_fetch;
	char str_error_code[128];
	int task_pid;
	char task_name[PATH_MAX];

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

	ret = read_ctrlreg(probe->target, 2, &cr2);
	if (ret)
	{
		verror("Could not read cr2 register\n");
		return -1;
	}

	value_regs = bsymbol_load(bsymbol_pagefault_regs, LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load pagefault regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_error_code = bsymbol_load(bsymbol_pagefault_error_code, 
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

	strcpy(str_error_code, protection_fault ? 
			"protection-fault, " : "no-page-found, ");
	strcat(str_error_code, write_access ? 
			"write, " : "read, ");
	strcat(str_error_code, user_mode ?
			"user, " : "kernel, ");
	strcat(str_error_code, reserved_bit ?
			"reserved-bit, " : "");
	strcat(str_error_code, instr_fetch ?
			"instr-fetch, " : "");
	str_error_code[strlen(str_error_code)-2] = '\0';

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid, 
				&task_pid);
		if (ret)
		{
			verror("Could not load member int32 '%s.%s'\n", 
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur, 
				member_task_name, task_name);
		if (ret)
		{
			verror("Could not load member string '%s.%s'\n", 
					context->task.cur->lsymbol->symbol->name, member_task_name);
			return ret;
		}
	
		vdebugc(-1, LOG_C_CTX, "%d (%s): Page fault 0x%08x occurred "
				"(eip = 0x%08x, %s)\n", 
				task_pid, task_name, addr, eip, str_error_code);
	}
	else
	{
		vdebugc(-1, LOG_C_CTX, "UNKNOWN TASK: Page fault 0x%08x occurred "
				"(eip = 0x%08x, %s)\n", 
				addr, eip, str_error_code);
	}

	context->flags |= TRACK_PAGEFAULT;

	context->pagefault.addr = addr;
	context->pagefault.regs = value_regs;
	context->pagefault.protection_fault = protection_fault;
	context->pagefault.write_access = write_access;
	context->pagefault.user_mode = user_mode;
	context->pagefault.reserved_bit = reserved_bit;
	context->pagefault.instr_fetch = instr_fetch;

	return 0;
}

/* TRAP_page_fault -- trap gate #14; exit */
static int probe_pagefault_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	ADDR addr;
	int task_pid;
	char task_name[PATH_MAX];
	
	context = (ctxtracker_context_t *)data;

	addr = context->pagefault.addr;

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid, 
				&task_pid);
		if (ret)
		{
			verror("Could not load member int32 '%s.%s'\n", 
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur, 
				member_task_name, task_name);
		if (ret)
		{
			verror("Could not load member string '%s.%s'\n", 
					context->task.cur->lsymbol->symbol->name, member_task_name);
			return ret;
		}
	
		vdebugc(-1, LOG_C_CTX, "%d (%s): Page fault 0x%08x handled\n", 
				task_pid, task_name, addr);
	}
	else
	{
		vdebugc(-1, LOG_C_CTX, "UNKNOWN TASK: Page fault 0x%08x handled\n", 
				addr);
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

/* TRAP_divide_error -- trap gate #0; entry */
static int probe_divide_error_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "Divide error exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);

	return 0;
}

/* TRAP_divide_error -- trap gate #0; exit */
static int probe_divide_error_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "Divide error exception handled\n");
	
	return 0;
}

/* TRAP_debug -- interrupt gate #1; entry */
static int probe_debug_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "Debug exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_debug -- interrupt gate #1; exit */
static int probe_debug_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "Debug exception handled\n");
	
	return 0;
}

/* TRAP_nmi -- interrupt gate #2; entry */
static int probe_nmi_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "NMI exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_nmi -- interrupt gate #2; exit */
static int probe_nmi_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "NMI exception handled\n");
	
	return 0;
}

/* TRAP_int3 -- system interrupt gate #3; entry */
static int probe_int3_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "Breakpoint exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_int3 -- system interrupt gate #3; exit */
static int probe_int3_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "Breakpoint exception handled\n");
	
	return 0;
}

/* TRAP_overflow -- system gate #4; entry */
static int probe_overflow_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "Overflow exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_overflow -- system gate #4; exit */
static int probe_overflow_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "Overflow exception handled\n");
	
	return 0;
}

/* TRAP_bounds -- trap gate #5; entry */
static int probe_bounds_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "Bounds check exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_bounds -- trap gate #5; exit */
static int probe_bounds_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "Bounds check exception handled\n");
	
	return 0;
}

/* TRAP_invalid_op -- trap gate #6; entry */
static int probe_invalid_op_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "Invalid opcode exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_invalid_op -- trap gate #6; exit */
static int probe_invalid_op_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "Invalid opcode exception handled\n");
	
	return 0;
}

/* TRAP_no_device -- trap gate #7; entry */
static int probe_device_not_available_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_device_not_available_entry;
	
	vdebugc(-1, LOG_C_CTX, "Device not available exception occurred\n");
	
	return 0;
}

/* TRAP_no_device -- trap gate #7; exit */
static int probe_device_not_available_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_device_not_available_exit;
	
	vdebugc(-1, LOG_C_CTX, "Device not available exception handled\n");
	
	return 0;
}

/* TRAP_double_fault -- trap gate #8; entry */
static int probe_double_fault_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_double_fault_entry;
	
	vdebugc(-1, LOG_C_CTX, "Double fault exception occurred\n");
	
	return 0;
}

/* TRAP_double_fault -- trap gate #8; exit */
static int probe_double_fault_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_double_fault_exit;
	
	vdebugc(-1, LOG_C_CTX, "Double fault exception handled\n");
	
	return 0;
}

/* TRAP_copro_seg -- trap gate #9; entry */
static int probe_coprocessor_segment_overrun_entry(struct probe *probe, 
		void *data, struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "Coprocessor segment overrun exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_copro_seg -- trap gate #9; exit */
static int probe_coprocessor_segment_overrun_exit(struct probe *probe, 
		void *data, struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "Coprocessor segment overrun exception handled\n");
	
	return 0;
}

/* TRAP_invalid_tss -- trap gate #10; entry */
static int probe_invalid_TSS_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "Invalid TSS exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_invalid_tss -- trap gate #10; exit */
static int probe_invalid_TSS_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "Invalid TSS exception handled\n");
	
	return 0;
}

/* TRAP_no_segment -- trap gate #11; entry */
static int probe_segment_not_present_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "Segment not present exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_no_segment -- trap gate #11; exit */
static int probe_segment_not_present_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "Segment not present exception handled\n");
	
	return 0;
}

/* TRAP_stack_error -- trap gate #12; entry */
static int probe_stack_segment_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "Stack exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_stack_error -- trap gate #12; exit */
static int probe_stack_segment_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "Stack exception handled\n");
	
	return 0;
}

/* TRAP_gp_fault -- trap gate #13; entry */
static int probe_general_protection_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "General protection exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_gp_fault -- trap gate #13; exit */
static int probe_general_protection_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "General protection exception handled\n");
	
	return 0;
}

/* TRAP_spurious_int -- trap gate #15; entry */
static int probe_spurious_interrupt_bug_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_spurious_interrupt_bug_entry;
	
	vdebugc(-1, LOG_C_CTX, "Spurious interrupt exception occurred\n");
	
	return 0;
}

/* TRAP_spurious_int -- trap gate #15; exit */
static int probe_spurious_interrupt_bug_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_spurious_interrupt_bug_exit;
	
	vdebugc(-1, LOG_C_CTX, "Spurious interrupt exception handled\n");
	
	return 0;
}

/* TRAP_copro_error -- trap gate #16; entry */
static int probe_coprocessor_error_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "Floating point exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_copro_error -- trap gate #16; exit */
static int probe_coprocessor_error_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "Floating point exception handled\n");
	
	return 0;
}

/* TRAP_alignment_check -- trap gate #17; entry */
static int probe_alignment_check_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "Alignment check exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_alignment_check -- trap gate #17; exit */
static int probe_alignment_check_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "Alignment check exception handled\n");
	
	return 0;
}

/* TRAP_machine_check -- trap gate #18; entry */
static int probe_machine_check_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_machine_check_entry;
	
	vdebugc(-1, LOG_C_CTX, "Machine check exception occurred\n");
	
	return 0;
}

/* TRAP_machine_check -- trap gate #18; exit */
static int probe_machine_check_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	/* FIXME: remove the below line when machineries allow this probe function 
	   to be registered. */
	(void)probe_machine_check_exit;
	
	vdebugc(-1, LOG_C_CTX, "Machine check exception handled\n");
	
	return 0;
}

/* TRAP_simd_error -- trap gate #19; entry */
static int probe_simd_coprocessor_error_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	int i, ret;
	struct exception_handler_data *handler_data;
	ctxtracker_context_t *context;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL eip;
	uint32_t error_code;
	
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

	value_regs = bsymbol_load(bsymbol_exception_regs[i], LOAD_FLAG_AUTO_DEREF);
	if (!value_regs)
	{
		verror("Could not load exception regs symbol\n");
		return -1;
	}

	ret = get_member_regval(probe->target, value_regs, member_regs_eip, &eip);
	if (ret)
	{
		verror("Could not load member regval '%s.%s'\n", 
				value_regs->lsymbol->symbol->name, member_regs_eip);
		value_free(value_regs);
		return ret;
	}

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_exception_error_code[i], 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load exception error_code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	vdebugc(-1, LOG_C_CTX, "SIMD floating point exception occurred: "
			"eip = 0x%08x, error-code = 0x%08x\n",
			eip, error_code);
	
	return 0;
}

/* TRAP_simd_error -- trap gate #19; exit */
static int probe_simd_coprocessor_error_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	ctxtracker_context_t *context;
	
	context = (ctxtracker_context_t *)data;

	vdebugc(-1, LOG_C_CTX, "SIMD floating point exception handled\n");
	
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
	int task_pid;
	char task_name[PATH_MAX];

	context = (ctxtracker_context_t *)data;

	eax = target_read_reg(t, 0);
	sc_num = eax;

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid, 
				&task_pid);
		if (ret)
		{
			verror("Could not load member int32 '%s.%s'\n", 
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur, 
				member_task_name, task_name);
		if (ret)
		{
			verror("Could not load member string '%s.%s'\n", 
					context->task.cur->lsymbol->symbol->name, member_task_name);
			return ret;
		}
	
		vdebugc(-1, LOG_C_CTX, "%d (%s): System call %d (0x%02x) called\n", 
				task_pid, task_name, sc_num, sc_num);
	}
	else
	{
		vdebugc(-1, LOG_C_CTX, "UNKNOWN TASK: System call %d (0x%02x) called\n",
				sc_num, sc_num);
	}

	context->flags |= TRACK_SYSCALL;

	context->syscall.sc_num = sc_num;

	return 0;
}

/* TRAP_sysentry -- system gate #256; exit */
static int probe_syscall_exit(struct probe *probe, void *data,
		struct probe *trigger)
{
	int ret;
	ctxtracker_context_t *context;
	int sc_num;
	int task_pid;
	char task_name[PATH_MAX];

	context = (ctxtracker_context_t *)data;

	sc_num = context->syscall.sc_num;

	if (context->task.cur)
	{
		ret = get_member_i32(probe->target, context->task.cur, member_task_pid, 
				&task_pid);
		if (ret)
		{
			verror("Could not load member int32 '%s.%s'\n", 
					context->task.cur->lsymbol->symbol->name, member_task_pid);
			return ret;
		}

		ret = get_member_string(probe->target, context->task.cur, 
				member_task_name, task_name);
		if (ret)
		{
			verror("Could not load member string '%s.%s'\n", 
					context->task.cur->lsymbol->symbol->name, member_task_name);
			return ret;
		}
	
		vdebugc(-1, LOG_C_CTX, "%d (%s): System call %d (0x%02x) returned\n", 
				task_pid, task_name, sc_num, sc_num);
	}
	else
	{
		vdebugc(-1, LOG_C_CTX, "UNKNOWN TASK: System call %d (0x%02x) "
				"returned\n", sc_num, sc_num);
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

