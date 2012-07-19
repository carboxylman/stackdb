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
#include <limits.h>

#include <log.h>
#include <target.h>
#include <target_api.h>
#include <target_xen_vm.h>
#include <probe_api.h>
#include <probe.h>

#include "ctxtracker.h"
#include "util.h"

static struct target *t;

static GHashTable *probes;
static GHashTable *taskswitch_probes;
static GHashTable *interrupt_probes;
static GHashTable *pagefault_probes;
static GHashTable *exception_probes;
static GHashTable *syscall_probes;

static ctxtracker_context_t *context;

/* FIXME: remove this once you start using target's ELF symtab symbols. */
static FILE *sysmap_handle;

#include "probes.c"

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
		.summarize = NULL,
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

	probe = register_probe_label(t, symbol, handler, &ops, NULL);

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
	static const struct probe_ops ops = { 
		.gettype = NULL,
		.init = probe_interrupt_init,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = NULL,
		.fini = probe_interrupt_fini
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

	entry_probe = register_probe_function_entry(t, symbol, entry_handler, &ops, 
			NULL);
	if (!entry_probe)
		return -1;

	exit_probe = register_probe_function_exit(t, symbol, exit_handler, NULL, 
			NULL);
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
	static const struct probe_ops ops = { 
		.gettype = NULL,
		.init = probe_pagefault_init,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = NULL,
		.fini = probe_pagefault_fini
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

	entry_probe = register_probe_function_entry(t, symbol, entry_handler, &ops,
			NULL);
	if (!entry_probe)
		return -1;

	exit_probe = register_probe_function_exit(t, symbol, exit_handler, NULL, 
			NULL);
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
	static const struct probe_ops ops = { 
		.gettype = NULL,
		.init = probe_exception_init,
		.registered = NULL,
		.enabled = NULL,
		.disabled = NULL,
		.unregistered = NULL,
		.summarize = NULL,
		.fini = probe_exception_fini
	};

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
		entry_probe = register_probe_function_entry(t, symbols[i], 
				entry_handlers[i], &ops, (void *)i /* data */);
		if (!entry_probe)
			return -1;

		exit_probe = register_probe_function_exit(t, symbols[i], 
				exit_handlers[i], NULL, NULL);
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

	struct probe *entry_probe;

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

	/* FIXME: update this once you start using target's ELF symtab symbols. */
	entry_probe = register_probe_function_sysmap(t, symbol, entry_handler, NULL,
			NULL, sysmap_handle);
	if (!entry_probe)
		return -1;

	g_hash_table_insert(probes, (gpointer)entry_probe /* key */, 
			(gpointer)entry_probe /* value */);

	g_hash_table_insert(syscall_probes, (gpointer)entry_probe /* key */, 
			(gpointer)entry_probe /* value */);

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
			/* FIXME: uncomment this after fixing double faults detected by 
			   glib. */
			//probe_free(probe, 1 /* force */);

			g_hash_table_remove(probes, key);
		}

		g_hash_table_destroy(*probe_table);
		*probe_table = NULL;
	}
}

/* FIXME: remove the sysmap_name argument once you start using target's ELF 
   symtab symbols. */
int ctxtracker_init(struct target *target, const char *sysmap_name)
{
	int ret;
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

	/* FIXME: remove this once you start using target's ELF symtab symbols. */
	if (!sysmap_name)
	{
		verror("System.map file name is NULL\n");
		return -EINVAL;
	}

	t = target;
	xstate = (struct xen_vm_state *)t->state;
	domain_name = xstate->name;

	/* FIXME: remove this once you start using target's ELF symtab symbols. */
	sysmap_handle = fopen(sysmap_name, "r");
	if (!sysmap_handle)
	{
		ret = -errno;
		verror("Could not open file %s for target %s\n", sysmap_name, 
				domain_name);
		ctxtracker_cleanup();
		return ret;
	}

	probes = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (!probes)
	{
		verror("Could not create probe table for target %s\n", domain_name);
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

	return 0;
}

void ctxtracker_cleanup(void)
{
	struct probe *probe;
	GHashTableIter iter;
	gpointer key;

	if (context)
	{
		free(context);
		context = NULL;
	}

	if (probes)
	{
		g_hash_table_iter_init(&iter, probes);
		while (g_hash_table_iter_next(&iter, (gpointer)&key, (gpointer)&probe))
		{
			probe_unregister(probe, 1 /* force */);
			/* FIXME: uncomment this after fixing double faults detected by 
			   glib. */
			//probe_free(probe, 1 /* force */);
		}

		g_hash_table_destroy(probes);
		probes = NULL;	
	}

	if (taskswitch_probes)
	{
		g_hash_table_destroy(taskswitch_probes);
		taskswitch_probes = NULL;
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

	/* FIXME: remove this once you start using target's ELF symtab symbols. */
	if (sysmap_handle)
	{
		fclose(sysmap_handle);
		sysmap_handle = NULL;
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

