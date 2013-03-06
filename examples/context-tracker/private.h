/*
 * Copyright (c) 2012, 2013 The University of Utah
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
 *  examples/context-tracker/private.h
 *
 *  Private utility functions for context tracker.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#ifndef __CTXTRACKER_UTIL_H__
#define __CTXTRACKER_UTIL_H__

#include <target_api.h>
#include "ctxtracker.h"

struct probe *register_probe_label(struct target *target, const char *symbol, 
		const probe_handler_t handler, const struct probe_ops *ops, void *data);

struct probe *register_probe_function_entry(struct target *target,
		const char *symbol, const probe_handler_t handler, 
		const struct probe_ops *ops, void *data);

struct probe *register_probe_function_exit(struct target *target,
		const char *symbol, const probe_handler_t handler, 
		const struct probe_ops *ops, void *data);

int get_member_i32(struct target *target, struct value *value_struct, 
		const char *member, int32_t *i32);

int get_member_string(struct target *target, struct value *value_struct, 
		const char *member, char *string);

int get_member_regval(struct target *target, struct value *value_struct, 
		const char *member, REGVAL *regval);

/* EXCEPTION HANDLERS */

struct exception_handler_data {
	int index;
	ctxtracker_context_t *context;
};

void *probe_context_summarize(struct probe *probe);
result_t probe_taskswitch(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_taskswitch_init(struct probe *probe);
result_t probe_taskswitch_fini(struct probe *probe);
result_t probe_interrupt_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_interrupt_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_interrupt_init(struct probe *probe);
result_t probe_interrupt_fini(struct probe *probe);
result_t probe_pagefault_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_pagefault_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_pagefault_init(struct probe *probe);
result_t probe_pagefault_fini(struct probe *probe);
result_t probe_exception_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_exception_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_divide_error_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_divide_error_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_debug_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_debug_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_nmi_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_nmi_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_int3_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_int3_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_overflow_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_overflow_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_bounds_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_bounds_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_invalid_op_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_invalid_op_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_device_not_available_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_device_not_available_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_double_fault_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_double_fault_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_coprocessor_segment_overrun_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_coprocessor_segment_overrun_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_invalid_TSS_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_invalid_TSS_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_segment_not_present_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_segment_not_present_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_stack_segment_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_stack_segment_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_general_protection_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_general_protection_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_spurious_interrupt_bug_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_spurious_interrupt_bug_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_coprocessor_error_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_coprocessor_error_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_alignment_check_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_alignment_check_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_machine_check_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_machine_check_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_simd_coprocessor_error_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_simd_coprocessor_error_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_exception_init(struct probe *probe);
result_t probe_exception_fini(struct probe *probe);
result_t probe_syscall_entry(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_syscall_exit(struct probe *probe, void *data,
		struct probe *trigger);
result_t probe_syscall_init(struct probe *probe);
result_t probe_syscall_fini(struct probe *probe);

#endif /* __CTXTRACKER_UTIL_H__ */
