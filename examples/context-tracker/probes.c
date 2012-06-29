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

static struct bsymbol *bsymbol_task_prev;
static struct bsymbol *bsymbol_task_next;

static struct bsymbol *bsymbol_interrupt_regs;
static int interrupt_no;

static struct bsymbol *bsymbol_pagefault_regs;
static struct bsymbol *bsymbol_pagefault_error_code;
static ADDR pagefault_addr;

/* TASK SWITCH HANDLERS */

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

/* Called upon the execution of label schedule.switch_tasks. */
static int probe_taskswitch(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *member_task_pid = "pid";
	static const char *member_task_name = "comm";

	int ret;
	struct value *value_prev, *value_next;
	int prev_pid, next_pid;
	char prev_name[PATH_MAX], next_name[PATH_MAX];

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

	/* NOTE: load and free symbols one by one due to target's bug. */

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

	value_free(value_prev);

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
		value_free(value_next);
		return ret;
	}

	ret = get_member_string(probe->target, value_next, member_task_name, 
			next_name);
	if (ret)
	{
		verror("Could not load member string '%s.%s'\n", 
				value_next->lsymbol->symbol->name, member_task_name);
		value_free(value_next);
		return ret;
	}

	value_free(value_next);

	vdebugc(-1, LOG_C_CTX, "Task switch: %d (%s) -> %d (%s)\n", 
			prev_pid, prev_name, next_pid, next_name);

	return 0;
}

/* INTERRUPT HANDLERS */

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
	if (bsymbol_interrupt_regs)
	{
		bsymbol_release(bsymbol_interrupt_regs);
		bsymbol_interrupt_regs = NULL;
	}

	return 0;
}

/* Call to interrupt request handler do_IRQ */
static int probe_interrupt_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *member_regs_orig_eax = "orig_eax";
	
	int ret;
	struct value *value_regs;
	REGVAL orig_eax;

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

	value_free(value_regs);

	interrupt_no = ~orig_eax & 0xff;

	vdebugc(-1, LOG_C_CTX, "Interrupt %d (0x%02x) requested\n", 
			interrupt_no, interrupt_no);

	return 0;
}

/* Return from interrupt request handler do_IRQ */
static int probe_interrupt_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	vdebugc(-1, LOG_C_CTX, "Interrupt %d (0x%02x) handled\n", 
			interrupt_no, interrupt_no);

	return 0;
}

/* PAGE FAULT HANDLERS */

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
	if (bsymbol_pagefault_error_code)
	{
		bsymbol_release(bsymbol_pagefault_error_code);
		bsymbol_pagefault_error_code = NULL;
	}

	return 0;
}

/* TRAP_page_fault -- trap gate #14; entry */
static int probe_pagefault_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	static const char *member_regs_eip = "eip";

	int ret;
	struct value *value_regs;
	struct value *value_error_code;
	REGVAL cr2;
	REGVAL eip;
	uint32_t error_code;
	bool protection_fault;
	bool write_access;
	bool user_mode;
	bool reserved_bit;
	bool instr_fetch;
	char str_error_code[128];

	if (!bsymbol_pagefault_regs)
	{
		verror("bsymbol for pagefault regs is NULL\n");
		return -1;
	}

	if (!bsymbol_pagefault_error_code)
	{
		verror("bsymbol for pagefault error code is NULL\n");
		return -1;
	}

	ret = read_ctrlreg(probe->target, 2, &cr2);
	if (ret)
	{
		verror("Could not read cr2 register\n");
		return -1;
	}

	/* NOTE: load and free symbols one by one due to target's bug. */
	
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

	value_free(value_regs);

	value_error_code = bsymbol_load(bsymbol_pagefault_error_code, 
			LOAD_FLAG_AUTO_DEREF);
	if (!value_error_code)
	{
		verror("Could not load pagefault error code symbol\n");
		return -1;
	}

	error_code = v_u32(value_error_code);

	value_free(value_error_code);

	pagefault_addr = (ADDR)cr2;

	protection_fault = ((error_code & 1) != 0);
	write_access = ((error_code & 2) != 0);
	user_mode = ((error_code & 4) != 0);
	reserved_bit = ((error_code & 8) != 0);
	instr_fetch = ((error_code & 16) != 0);

	/* FIXME: do not run this parsing when no need to print out context info. */
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

	vdebugc(-1, LOG_C_CTX, "Page fault occurred: address = 0x%08x"
			", eip = 0x%08x, error = (%s)\n", 
			pagefault_addr, eip, str_error_code);

	return 0;
}

/* TRAP_page_fault -- trap gate #14; exit */
static int probe_pagefault_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	vdebugc(-1, LOG_C_CTX, "Page fault handled: address = 0x%08x\n", 
			pagefault_addr);

	return 0;
}

/* EXCEPTION HANDLERS */

/* TRAP_divide_error -- trap gate #0; entry */
static int probe_divide_error_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_divide_error -- trap gate #0; exit */
static int probe_divide_error_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_debug -- interrupt gate #1; entry */
static int probe_debug_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_debug -- interrupt gate #1; exit */
static int probe_debug_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_nmi -- interrupt gate #2; entry */
static int probe_nmi_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_nmi -- interrupt gate #2; exit */
static int probe_nmi_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_int3 -- system interrupt gate #3; entry */
static int probe_int3_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_int3 -- system interrupt gate #3; exit */
static int probe_int3_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_overflow -- system gate #4; entry */
static int probe_overflow_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_overflow -- system gate #4; exit */
static int probe_overflow_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_bounds -- trap gate #5; entry */
static int probe_bounds_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_bounds -- trap gate #5; exit */
static int probe_bounds_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_invalid_op -- trap gate #6; entry */
static int probe_invalid_op_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_invalid_op -- trap gate #6; exit */
static int probe_invalid_op_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_no_device -- trap gate #7; entry */
static int probe_device_not_available_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_no_device -- trap gate #7; exit */
static int probe_device_not_available_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_double_fault -- trap gate #8; entry */
static int probe_double_fault_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_double_fault -- trap gate #8; exit */
static int probe_double_fault_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_copro_seg -- trap gate #9; entry */
static int probe_coprocessor_segment_overrun_entry(struct probe *probe, 
		void *data, struct probe *trigger)
{
	return 0;
}

/* TRAP_copro_seg -- trap gate #9; exit */
static int probe_coprocessor_segment_overrun_exit(struct probe *probe, 
		void *data, struct probe *trigger)
{
	return 0;
}

/* TRAP_invalid_tss -- trap gate #10; entry */
static int probe_invalid_TSS_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_invalid_tss -- trap gate #10; exit */
static int probe_invalid_TSS_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_no_segment -- trap gate #11; entry */
static int probe_segment_not_present_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_no_segment -- trap gate #11; exit */
static int probe_segment_not_present_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_stack_error -- trap gate #12; entry */
static int probe_stack_segment_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_stack_error -- trap gate #12; exit */
static int probe_stack_segment_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_gp_fault -- trap gate #13; entry */
static int probe_general_protection_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_gp_fault -- trap gate #13; exit */
static int probe_general_protection_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_spurious_int -- trap gate #15; entry */
static int probe_spurious_interrupt_bug_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_spurious_int -- trap gate #15; exit */
static int probe_spurious_interrupt_bug_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_copro_error -- trap gate #16; entry */
static int probe_coprocessor_error_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_copro_error -- trap gate #16; exit */
static int probe_coprocessor_error_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_alignment_check -- trap gate #17; entry */
static int probe_alignment_check_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_alignment_check -- trap gate #17; exit */
static int probe_alignment_check_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_machine_check -- trap gate #18; entry */
static int probe_machine_check_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_machine_check -- trap gate #18; exit */
static int probe_machine_check_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_simd_error -- trap gate #19; entry */
static int probe_simd_coprocessor_error_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* TRAP_simd_error -- trap gate #19; exit */
static int probe_simd_coprocessor_error_exit(struct probe *probe, void *data, 
		struct probe *trigger)
{
	return 0;
}

/* SYSTEM CALL HANDLERS */

/* TRAP_sysentry -- system gate #256; entry */
static int probe_syscall_entry(struct probe *probe, void *data, 
		struct probe *trigger)
{
	unsigned int eax = target_read_reg(t, 0); // system entry number
	return 0;
}

/* TRAP_sysentry -- system gate #256; exit */
static int probe_syscall_exit(struct probe *probe, void *data,
		struct probe *trigger)
{
	unsigned int eax = target_read_reg(t, 0); // system entry number
	return 0;
}