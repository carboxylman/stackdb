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
		.fini = probe_taskswitch_fini
	};

	struct bsymbol *bsymbol;
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

	bsymbol = target_lookup_sym(t, (char *)symbol, ".", NULL /* srcfile */, 
			SYMBOL_TYPE_FLAG_NONE);
	if (!bsymbol)
	{
		verror("Could not find symbol '%s' in debuginfo\n", symbol);
		return -1;
	}

	probe = probe_create(t, (struct probe_ops *)&ops, (char *)symbol, handler, 
			NULL /* post_handler */, NULL /* data */, 0 /* autofree */);
	if (!probe)
	{
		verror("Could not create probe on '%s'\n", bsymbol_get_name(bsymbol));
		bsymbol_release(bsymbol);
		return -1;
	}

	if (!probe_register_symbol(probe, bsymbol, PROBEPOINT_SW, PROBEPOINT_EXEC,
				PROBEPOINT_LAUTO))
	{
		verror("Could not register probe on '%s'\n", bsymbol_get_name(bsymbol));
		probe_free(probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return -1;
	}

	bsymbol_release(bsymbol);

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
		.fini = probe_interrupt_fini
	};

	int ret;
	struct bsymbol *bsymbol;
	struct probe *entry_probe;
	struct probe *exit_probe;
	ADDR base_addr = 0;

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

	bsymbol = target_lookup_sym(t, (char *)symbol, ".", NULL /* srcfile */, 
			SYMBOL_TYPE_FLAG_NONE);
	if (!bsymbol)
	{
		verror("Could not find symbol '%s' in debuginfo\n", symbol);
		return -1;
	}

	/* Register a probe on the function entry. */

	entry_probe = probe_create(t, (struct probe_ops *)&ops, (char *)symbol, 
			entry_handler, NULL /* post_handler */, NULL /* data */, 
			0 /* autofree */);
	if (!entry_probe)
	{
		verror("Could not create probe on '%s' entry\n", 
				bsymbol_get_name(bsymbol));
		bsymbol_release(bsymbol);
		return -1;
	}

	if (!probe_register_symbol(entry_probe, bsymbol, PROBEPOINT_SW, 
				PROBEPOINT_EXEC, PROBEPOINT_LAUTO))
	{
		verror("Could not register probe on '%s' entry\n", 
				bsymbol_get_name(bsymbol));
		probe_free(entry_probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return -1;
	}

	/* Register a probe on the function exit. */

	ret = location_resolve_symbol_base(t, bsymbol, &base_addr, 
			NULL /* range */);
	if (ret)
	{
		verror("Could not resolve base addr for function '%s'\n", 
				bsymbol_get_name(bsymbol));
		probe_unregister(entry_probe, 1 /* force */);
		probe_free(entry_probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return ret;
	}

	exit_probe = probe_create(t, NULL /* ops */, bsymbol_get_name(bsymbol), 
			exit_handler, NULL /* post_handler */, NULL /* data */, 
			0 /* autofree */);
	if (!exit_probe)
	{
		verror("Could not create probe on '%s' exit\n", 
				bsymbol_get_name(bsymbol));
		probe_unregister(entry_probe, 1 /* force */);
		probe_free(entry_probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return -1;
	}

	if (!probe_register_function_instrs(bsymbol, PROBEPOINT_SW, 1 /* noabort */,
				INST_RET, exit_probe, INST_NONE))
	{
		verror("Could not register probe on '%s' exit\n", 
				bsymbol_get_name(bsymbol));
		probe_unregister(entry_probe, 1 /* force */);
		probe_free(entry_probe, 1 /* force */);
		probe_free(exit_probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return -1;
	}

	if (probe_num_sources(exit_probe) == 0)
	{
		verror("No return sites in '%s'\n", bsymbol_get_name(bsymbol));
		probe_unregister(entry_probe, 1 /* force */);
		probe_unregister(exit_probe, 1 /* force */);
		probe_free(entry_probe, 1 /* force */);
		probe_free(exit_probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return -1;
	}

	bsymbol_release(bsymbol);

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
		.fini = probe_pagefault_fini
	};

	int ret;
	struct bsymbol *bsymbol;
	struct probe *entry_probe;
	struct probe *exit_probe;
	ADDR base_addr = 0;

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

	bsymbol = target_lookup_sym(t, (char *)symbol, ".", NULL /* srcfile */, 
			SYMBOL_TYPE_FLAG_NONE);
	if (!bsymbol)
	{
		verror("Could not find symbol '%s' in debuginfo\n", symbol);
		return -1;
	}

	/* Register a probe on the function entry. */

	entry_probe = probe_create(t, (struct probe_ops *)&ops, (char *)symbol, 
			entry_handler, NULL /* post_handler */, NULL /* data */, 
			0 /* autofree */);
	if (!entry_probe)
	{
		verror("Could not create probe on '%s' entry\n", 
				bsymbol_get_name(bsymbol));
		bsymbol_release(bsymbol);
		return -1;
	}

	if (!probe_register_symbol(entry_probe, bsymbol, PROBEPOINT_SW, 
				PROBEPOINT_EXEC, PROBEPOINT_LAUTO))
	{
		verror("Could not register probe on '%s' entry\n", 
				bsymbol_get_name(bsymbol));
		probe_free(entry_probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return -1;
	}

	/* Register a probe on the function exit. */

	ret = location_resolve_symbol_base(t, bsymbol, &base_addr, 
			NULL /* range */);
	if (ret)
	{
		verror("Could not resolve base addr for function '%s'\n", 
				bsymbol_get_name(bsymbol));
		probe_unregister(entry_probe, 1 /* force */);
		probe_free(entry_probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return ret;
	}

	exit_probe = probe_create(t, NULL /* ops */, bsymbol_get_name(bsymbol), 
			exit_handler, NULL /* post_handler */, NULL /* data */, 
			0 /* autofree */);
	if (!exit_probe)
	{
		verror("Could not create probe on '%s' exit\n", 
				bsymbol_get_name(bsymbol));
		probe_unregister(entry_probe, 1 /* force */);
		probe_free(entry_probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return -1;
	}

	if (!probe_register_function_instrs(bsymbol, PROBEPOINT_SW, 1 /* noabort */,
				INST_RET, exit_probe, INST_NONE))
	{
		verror("Could not register probe on '%s' exit\n", 
				bsymbol_get_name(bsymbol));
		probe_unregister(entry_probe, 1 /* force */);
		probe_free(entry_probe, 1 /* force */);
		probe_free(exit_probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return -1;
	}

	if (probe_num_sources(exit_probe) == 0)
	{
		verror("No return sites in '%s'\n", bsymbol_get_name(bsymbol));
		probe_unregister(entry_probe, 1 /* force */);
		probe_unregister(exit_probe, 1 /* force */);
		probe_free(entry_probe, 1 /* force */);
		probe_free(exit_probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return -1;
	}

	bsymbol_release(bsymbol);

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
	return 0;
}

static int track_syscall(void)
{
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

