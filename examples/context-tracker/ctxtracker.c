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
 *  examples/context-tracker/ctxtracker.c
 *
 *  A very thin abstraction to track context changes of a Linux VM, 
 *  implemented on top of target.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#include <stdio.h>
#include <errno.h>

#include <log.h>
#include <target.h>
#include <target_api.h>
#include <target_xen_vm.h>
#include <probe_api.h>
#include <probe.h>

#include "ctxtracker.h"
#include "private.h"

struct target *t;

static GHashTable *probes;
static GHashTable *taskswitch_probes;
static GHashTable *interrupt_probes;
static GHashTable *pagefault_probes;
static GHashTable *exception_probes;
static GHashTable *syscall_probes;

ctxtracker_context_t *context;

GHashTable *taskswitch_user_handlers;
GHashTable *interrupt_entry_user_handlers;
GHashTable *interrupt_exit_user_handlers;
GHashTable *pagefault_entry_user_handlers;
GHashTable *pagefault_exit_user_handlers;
GHashTable *exception_entry_user_handlers;
GHashTable *exception_exit_user_handlers;
GHashTable *syscall_entry_user_handlers;
GHashTable *syscall_exit_user_handlers;

static int track_taskswitch(void)
{
	static const char *symbol = "schedule.switch_tasks";
	static const probe_handler_t handler = probe_taskswitch;
	static const struct probe_ops ops = { 
		.gettype = NULL,
		.init = probe_taskswitch_init,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = probe_context_summarize,
		.fini = probe_taskswitch_fini
	};

	struct probe *probe;

	if (taskswitch_probes)
	{
		verror("Task switches are already being tracked\n");
		return -1;
	}

	taskswitch_probes = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (!taskswitch_probes)
	{
		verror("Could not create probe table for task switches\n");
		return -ENOMEM;
	}

	probe = register_probe_label(t, symbol, handler, &ops, 
			context /* handler_data */);

	g_hash_table_insert(probes, (gpointer)probe /* key */, 
			(gpointer)probe /* value */);

	g_hash_table_insert(taskswitch_probes, (gpointer)probe /* key */, 
			(gpointer)probe /* value */);

	return 0;
}

static int track_interrupt(void)
{
	static const char *symbol = "do_IRQ";
	static const probe_handler_t entry_handler = probe_interrupt_entry;
	static const probe_handler_t exit_handler = probe_interrupt_exit;
	static const struct probe_ops entry_ops = { 
		.gettype = NULL,
		.init = probe_interrupt_init,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = probe_context_summarize,
		.fini = probe_interrupt_fini
	};
	static const struct probe_ops exit_ops = { 
		.gettype = NULL,
		.init = NULL,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = probe_context_summarize,
		.fini = NULL
	};

	struct probe *entry_probe;
	struct probe *exit_probe;

	if (interrupt_probes)
	{
		verror("Interrupts are already being tracked\n");
		return -1;
	}

	interrupt_probes = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (!interrupt_probes)
	{
		verror("Could not create probe table for interrupts\n");
		return -ENOMEM;
	}

	entry_probe = register_probe_function_entry(t, symbol, entry_handler, 
			&entry_ops, context /* handler_data */);
	if (!entry_probe)
		return -1;

	exit_probe = register_probe_function_exit(t, symbol, exit_handler, 
			&exit_ops, context /* handler_data */);
	if (!exit_probe)
	{
		probe_unregister(entry_probe, 1 /* force */);
		probe_free(entry_probe, 1 /* force */);
		return -1;
	}

	g_hash_table_insert(probes, (gpointer)entry_probe /* key */, 
			(gpointer)entry_probe /* value */);
	g_hash_table_insert(probes, (gpointer)exit_probe /* key */, 
			(gpointer)exit_probe /* value */);

	g_hash_table_insert(interrupt_probes, (gpointer)entry_probe /* key */, 
			(gpointer)entry_probe /* value */);
	g_hash_table_insert(interrupt_probes, (gpointer)exit_probe /* key */, 
			(gpointer)exit_probe /* value */);

	return 0;
}

static int track_pagefault(void)
{
	static const char *symbol = "do_page_fault";
	static const probe_handler_t entry_handler = probe_pagefault_entry;
	static const probe_handler_t exit_handler = probe_pagefault_exit;
	static const struct probe_ops entry_ops = { 
		.gettype = NULL,
		.init = probe_pagefault_init,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = probe_context_summarize,
		.fini = probe_pagefault_fini
	};
	static const struct probe_ops exit_ops = { 
		.gettype = NULL,
		.init = NULL,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = probe_context_summarize,
		.fini = NULL
	};

	struct probe *entry_probe;
	struct probe *exit_probe;

	if (pagefault_probes)
	{
		verror("Page faults are already being tracked\n");
		return -1;
	}

	pagefault_probes = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (!pagefault_probes)
	{
		verror("Could not create probe table for page faults\n");
		return -ENOMEM;
	}

	entry_probe = register_probe_function_entry(t, symbol, entry_handler, 
			&entry_ops, context /* handler_data */);
	if (!entry_probe)
		return -1;

	exit_probe = register_probe_function_exit(t, symbol, exit_handler, 
			&exit_ops, context /* handler_data */);
	if (!exit_probe)
	{
		probe_unregister(entry_probe, 1 /* force */);
		probe_free(entry_probe, 1 /* force */);
		return -1;
	}

	g_hash_table_insert(probes, (gpointer)entry_probe /* key */, 
			(gpointer)entry_probe /* value */);
	g_hash_table_insert(probes, (gpointer)exit_probe /* key */, 
			(gpointer)exit_probe /* value */);

	g_hash_table_insert(pagefault_probes, (gpointer)entry_probe /* key */, 
			(gpointer)entry_probe /* value */);
	g_hash_table_insert(pagefault_probes, (gpointer)exit_probe /* key */, 
			(gpointer)exit_probe /* value */);

	return 0;
}

static int track_exception(void)
{
	/* Commented symbols are functions not found in both sysmap.map and 
	   debuginfo. */
	static const char *symbols[] = {
		"do_divide_error",
		"do_debug",
		"do_nmi",
		"do_int3",
		"do_overflow",
		"do_bounds",
		"do_invalid_op",
	//	"device_not_available",
	//	"double_fault",
		"do_coprocessor_segment_overrun",
		"do_invalid_TSS",
		"do_segment_not_present",
		"do_stack_segment",
		"do_general_protection",
	//	"spurious_interrupt_bug",
		"do_coprocessor_error",
		"do_alignment_check",
	//	"intel_machine_check",
		"do_simd_coprocessor_error"
	};
	static const probe_handler_t entry_handlers[] = {
		probe_divide_error_entry,
		probe_debug_entry,
		probe_nmi_entry,
		probe_int3_entry,
		probe_overflow_entry,
		probe_bounds_entry,
		probe_invalid_op_entry,
	//	probe_device_not_available_entry,
	//	probe_double_fault_entry,
		probe_coprocessor_segment_overrun_entry,
		probe_invalid_TSS_entry,
		probe_segment_not_present_entry,
		probe_stack_segment_entry,
		probe_general_protection_entry,
	//	probe_spurious_interrupt_bug_entry,
		probe_coprocessor_error_entry,
		probe_alignment_check_entry,
	//	probe_machine_check_entry,
		probe_simd_coprocessor_error_entry
	};
	static const probe_handler_t exit_handlers[] = {
		probe_divide_error_exit,
		probe_debug_exit,
		probe_nmi_exit,
		probe_int3_exit,
		probe_overflow_exit,
		probe_bounds_exit,
		probe_invalid_op_exit,
	//	probe_device_not_available_exit,
	//	probe_double_fault_exit,
		probe_coprocessor_segment_overrun_exit,
		probe_invalid_TSS_exit,
		probe_segment_not_present_exit,
		probe_stack_segment_exit,
		probe_general_protection_exit,
	//	probe_spurious_interrupt_bug_exit,
		probe_coprocessor_error_exit,
		probe_alignment_check_exit,
	//	probe_machine_check_exit,
		probe_simd_coprocessor_error_exit
	};
	static const struct probe_ops entry_ops = { 
		.gettype = NULL,
		.init = probe_exception_init,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = probe_context_summarize,
		.fini = probe_exception_fini
	};
	static const struct probe_ops exit_ops = { 
		.gettype = NULL,
		.init = NULL,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = probe_context_summarize,
		.fini = NULL
	};
	static struct exception_handler_data handler_data[64];

	int i, count;
	struct probe *entry_probe;
	struct probe *exit_probe;

	if (exception_probes)
	{
		verror("Exceptions are already being tracked\n");
		return -1;
	}

	exception_probes = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (!exception_probes)
	{
		verror("Could not create probe table for exceptions\n");
		return -ENOMEM;
	}

	count = sizeof(symbols) / sizeof(symbols[0]);

	for (i = 0; i < count; i++)
	{
		handler_data[i].index = i;
		handler_data[i].context = context;

		entry_probe = register_probe_function_entry(t, symbols[i], 
				entry_handlers[i], &entry_ops, &handler_data[i]);
		if (!entry_probe)
			return -1;

		exit_probe = register_probe_function_exit(t, symbols[i], 
				exit_handlers[i], &exit_ops,  &handler_data[i]);
		if (!exit_probe)
		{
			probe_unregister(entry_probe, 1 /* force */);
			probe_free(entry_probe, 1 /* force */);
			return -1;
		}

		g_hash_table_insert(probes, (gpointer)entry_probe /* key */, 
				(gpointer)entry_probe /* value */);
		g_hash_table_insert(probes, (gpointer)exit_probe /* key */, 
				(gpointer)exit_probe /* value */);

		g_hash_table_insert(exception_probes, (gpointer)entry_probe /* key */, 
				(gpointer)entry_probe /* value */);
		g_hash_table_insert(exception_probes, (gpointer)exit_probe /* key */, 
				(gpointer)exit_probe /* value */);
	}

	return 0;
}

static int track_syscall(void)
{
	static const char *symbol = "system_call";
	static const probe_handler_t entry_handler = probe_syscall_entry;
	static const probe_handler_t exit_handler = probe_syscall_exit;
	static const struct probe_ops entry_ops = { 
		.gettype = NULL,
		.init = probe_syscall_init,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = probe_context_summarize,
		.fini = probe_syscall_fini
	};
	static const struct probe_ops exit_ops = { 
		.gettype = NULL,
		.init = NULL,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = probe_context_summarize,
		.fini = NULL
	};

	struct probe *entry_probe;
	struct probe *exit_probe;

	if (syscall_probes)
	{
		verror("System calls are already being tracked\n");
		return -1;
	}

	syscall_probes = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (!syscall_probes)
	{
		verror("Could not create probe table for system calls\n");
		return -ENOMEM;
	}

	entry_probe = register_probe_function_entry(t, symbol, entry_handler, 
			&entry_ops, context /* handler_data */);
	if (!entry_probe)
		return -1;
	
	exit_probe = register_probe_function_exit(t, symbol, exit_handler, 
			&exit_ops, context /* handler_data */);
	if (!exit_probe)
	{
		probe_unregister(entry_probe, 1 /* force */);
		probe_free(entry_probe, 1 /* force */);
		return -1;
	}

	g_hash_table_insert(probes, (gpointer)entry_probe /* key */, 
			(gpointer)entry_probe /* value */);
	g_hash_table_insert(probes, (gpointer)exit_probe /* key */, 
			(gpointer)exit_probe /* value */);

	g_hash_table_insert(syscall_probes, (gpointer)entry_probe /* key */, 
			(gpointer)entry_probe /* value */);
	g_hash_table_insert(syscall_probes, (gpointer)exit_probe /* key */, 
			(gpointer)exit_probe /* value */);

	return 0;
}

static void untrack(GHashTable **probe_table)
{
	GHashTableIter iter;
	gpointer key;
	struct probe *probe;

	if (probe_table && *probe_table)
	{
		g_hash_table_iter_init(&iter, *probe_table);
		while (g_hash_table_iter_next(&iter, (gpointer)&key, (gpointer)&probe))
		{
			probe_unregister(probe, 1 /* force */);
			probe_free(probe, 1 /* force */);

			g_hash_table_remove(probes, key);
		}

		g_hash_table_destroy(*probe_table);
		*probe_table = NULL;
	}
}

static void register_user_handler(probe_handler_t handler, void *handler_data,
		GHashTable *handler_list)
{
	g_hash_table_insert(handler_list, (gpointer)handler /* key */, 
			(gpointer)handler_data /* value */);
}

int ctxtracker_init(struct target *target)
{
	struct xen_vm_state *xstate;
	char *domain_name;

	if (!target)
	{
		verror("Target is NULL\n");
		return -EINVAL;
	}

	if (!target->state)
	{
		verror("Target state is NULL; target may not be initialized\n");
		return -EINVAL;
	}

	t = target;
	xstate = (struct xen_vm_state *)t->state;
	domain_name = xstate->name;

	probes = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (!probes)
	{
		verror("Could not create probe table for target %s\n", domain_name);
		ctxtracker_cleanup();
		return -ENOMEM;
	}

	taskswitch_user_handlers = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (!taskswitch_user_handlers)
	{
		verror("Could not create user handler list for task switches\n");
		ctxtracker_cleanup();
		return -ENOMEM;
	}

	interrupt_entry_user_handlers = g_hash_table_new(g_direct_hash, 
			g_direct_equal);
	if (!interrupt_entry_user_handlers)
	{
		verror("Could not create user handler list for interrupt entries\n");
		ctxtracker_cleanup();
		return -ENOMEM;
	}

	interrupt_exit_user_handlers = g_hash_table_new(g_direct_hash, 
			g_direct_equal);
	if (!interrupt_exit_user_handlers)
	{
		verror("Could not create user handler list for interrupt exits\n");
		ctxtracker_cleanup();
		return -ENOMEM;
	}

	pagefault_entry_user_handlers = g_hash_table_new(g_direct_hash, 
			g_direct_equal);
	if (!pagefault_entry_user_handlers)
	{
		verror("Could not create user handler list for page fault entries\n");
		ctxtracker_cleanup();
		return -ENOMEM;
	}

	pagefault_exit_user_handlers = g_hash_table_new(g_direct_hash, 
			g_direct_equal);
	if (!pagefault_exit_user_handlers)
	{
		verror("Could not create user handler list for page fault exits\n");
		ctxtracker_cleanup();
		return -ENOMEM;
	}

	exception_entry_user_handlers = g_hash_table_new(g_direct_hash, 
			g_direct_equal);
	if (!exception_entry_user_handlers)
	{
		verror("Could not create user handler list for exception entries\n");
		ctxtracker_cleanup();
		return -ENOMEM;
	}

	exception_exit_user_handlers = g_hash_table_new(g_direct_hash, 
			g_direct_equal);
	if (!exception_exit_user_handlers)
	{
		verror("Could not create user handler list for exception exits\n");
		ctxtracker_cleanup();
		return -ENOMEM;
	}

	syscall_entry_user_handlers = g_hash_table_new(g_direct_hash, 
			g_direct_equal);
	if (!syscall_entry_user_handlers)
	{
		verror("Could not create user handler list for system call entries\n");
		ctxtracker_cleanup();
		return -ENOMEM;
	}

	syscall_exit_user_handlers = g_hash_table_new(g_direct_hash, 
			g_direct_equal);
	if (!syscall_exit_user_handlers)
	{
		verror("Could not create user handler list for system call exits\n");
		ctxtracker_cleanup();
		return -ENOMEM;
	}

	context = (ctxtracker_context_t *)malloc(sizeof(ctxtracker_context_t));
	if (!context)
	{
		verror("Could not allocate memory for context info\n");
		ctxtracker_cleanup();
		return -ENOMEM;
	}
	memset(context, 0, sizeof(ctxtracker_context_t));

	return 0;
}

void ctxtracker_cleanup(void)
{
	struct probe *probe;
	GHashTableIter iter;
	gpointer key;

	if (probes)
	{
		g_hash_table_iter_init(&iter, probes);
		while (g_hash_table_iter_next(&iter, (gpointer)&key, (gpointer)&probe))
		{
			probe_unregister(probe, 1 /* force */);
			probe_free(probe, 1 /* force */);
		}

		g_hash_table_destroy(probes);
		probes = NULL;	
	}

	if (context)
	{
		free(context);
		context = NULL;
	}

	if (taskswitch_user_handlers)
	{
		g_hash_table_destroy(taskswitch_user_handlers);
		taskswitch_user_handlers = NULL;
	}

	if (interrupt_entry_user_handlers)
	{
		g_hash_table_destroy(interrupt_entry_user_handlers);
		interrupt_entry_user_handlers = NULL;
	}

	if (interrupt_exit_user_handlers)
	{
		g_hash_table_destroy(interrupt_exit_user_handlers);
		interrupt_exit_user_handlers = NULL;
	}

	if (pagefault_entry_user_handlers)
	{
		g_hash_table_destroy(pagefault_entry_user_handlers);
		pagefault_entry_user_handlers = NULL;
	}

	if (pagefault_exit_user_handlers)
	{
		g_hash_table_destroy(pagefault_exit_user_handlers);
		pagefault_exit_user_handlers = NULL;
	}

	if (exception_entry_user_handlers)
	{
		g_hash_table_destroy(exception_entry_user_handlers);
		exception_entry_user_handlers = NULL;
	}

	if (exception_exit_user_handlers)
	{
		g_hash_table_destroy(exception_exit_user_handlers);
		exception_exit_user_handlers = NULL;
	}

	if (syscall_entry_user_handlers)
	{
		g_hash_table_destroy(syscall_entry_user_handlers);
		syscall_entry_user_handlers = NULL;
	}

	if (syscall_exit_user_handlers)
	{
		g_hash_table_destroy(syscall_exit_user_handlers);
		syscall_exit_user_handlers = NULL;
	}

	if (interrupt_probes)
	{
		g_hash_table_destroy(interrupt_probes);
		interrupt_probes = NULL;
	}

	if (pagefault_probes)
	{
		g_hash_table_destroy(pagefault_probes);
		pagefault_probes = NULL;
	}

	if (exception_probes)
	{
		g_hash_table_destroy(exception_probes);
		exception_probes = NULL;
	}

	if (syscall_probes)
	{
		g_hash_table_destroy(syscall_probes);
		syscall_probes = NULL;
	}

	t = NULL;
}

int ctxtracker_track(ctxtracker_track_t flags, bool track)
{
	int ret;

	if (!t)
	{
		verror("Context tracker not initialized\n");
		return -1;
	}

	if (flags == TRACK_NONE)
		return 0;

	if (flags & TRACK_TASKSWITCH)
	{
		if (track)
		{
			ret = track_taskswitch();
			if (ret)
				return ret;
		}
		else
			untrack(&taskswitch_probes);

	}

	if (flags & TRACK_INTERRUPT)
	{
		if (track)
		{
			ret = track_interrupt();
			if (ret)
				return ret;
		}
		else
			untrack(&interrupt_probes);
	}

	if (flags & TRACK_PAGEFAULT)
	{
		if (track)
		{
			ret = track_pagefault();
			if (ret)
				return ret;
		}
		else
			untrack(&pagefault_probes);
	}

	if (flags & TRACK_EXCEPTION)
	{
		if (track)
		{
			ret = track_exception();
			if (ret)
				return ret;
		}
		else
			untrack(&exception_probes);
	}

	if (flags & TRACK_SYSCALL)
	{
		if (track)
		{
			ret = track_syscall();
			if (ret)
				return ret;
		}
		else
			untrack(&syscall_probes);
	}

	return 0;
}

int ctxtracker_register_handler(ctxtracker_track_t flags, 
		probe_handler_t handler, void *handler_data, bool entry)
{
	if (!t)
	{
		verror("Context tracker not initialized\n");
		return -1;
	}

	if (flags == TRACK_NONE)
		return 0;

	if (flags & TRACK_TASKSWITCH)
		register_user_handler(handler, handler_data, taskswitch_user_handlers);

	if (flags & TRACK_INTERRUPT)
	{
		if (entry)
			register_user_handler(handler, handler_data,
					interrupt_entry_user_handlers);
		else
			register_user_handler(handler, handler_data,
					interrupt_exit_user_handlers);
	}

	if (flags & TRACK_PAGEFAULT)
	{
		if (entry)
			register_user_handler(handler, handler_data, 
					pagefault_entry_user_handlers);
		else
			register_user_handler(handler, handler_data,
					pagefault_exit_user_handlers);
	}

	if (flags & TRACK_EXCEPTION)
	{
		if (entry)
			register_user_handler(handler, handler_data, 
					exception_entry_user_handlers);
		else
			register_user_handler(handler, handler_data,
					exception_exit_user_handlers);
	}

	if (flags & TRACK_SYSCALL)
	{
		if (entry)
			register_user_handler(handler, handler_data,
					syscall_entry_user_handlers);
		else
			register_user_handler(handler, handler_data,
					syscall_exit_user_handlers);
	}

	return 0;
}

void *ctxtracker_summarize(struct probe *probe)
{
	return probe_context_summarize(probe);
}
