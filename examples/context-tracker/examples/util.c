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
 *  examples/context-tracker/examples/util.c
 *
 *  Utility functions that all context tracker enabled applications 
 *  share.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include <target_api.h>
#include <target_xen_vm.h>
#include <probe_api.h>
#include <ctxtracker.h>

#include "util.h"
#include "debug.h"

struct target *init_probes(const char *domain_name, int debug_level)
{
	struct target *t;
	int ret;

	dwdebug_init();
	vmi_set_log_level(debug_level);
#ifdef XA_DEBUG
	xa_set_debug_level(debug_level);
#endif

	t = xen_vm_attach((char *)domain_name, NULL);
	if (!t)
	{
		ERR("Can't attach to domain %s\n", domain_name);
		return NULL;
	}

	ret = target_open(t);
	if (ret)
	{
		ERR("Can't open target %s\n", domain_name);
		return NULL;
	}

	return t;
}

void cleanup_probes(GHashTable *probes)
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
	}
}

int run_probes(struct target *t, GHashTable *probes)
{
	target_status_t tstat;
	struct xen_vm_state *xstate = (struct xen_vm_state *)t->state;
	const char *domain_name = xstate->name;

	/* 
	 * The target is paused after the attach; we have to resume it now
	 * that we've registered probes.
	 */
	target_resume(t);

	while (1)
	{
		tstat = target_monitor(t);
		if (tstat == TSTATUS_PAUSED)
		{
			WARN("Domain %s interrupted at 0x%" PRIxREGVAL "\n", 
					domain_name, target_read_reg(t, t->ipregno));

			if (target_resume(t))
			{
				ERR("Can't resume target domain %s\n", domain_name);
				target_close(t);
				return -16;
			}
		}
		else
		{
			cleanup_probes(probes);
			ctxtracker_cleanup();
			
			tstat = target_close(t);
			target_free(t);

			if (probes)
				g_hash_table_destroy(probes);
			
			if (tstat == TSTATUS_DONE)
				return 0;
			else if (tstat == TSTATUS_ERROR)
				return -9;
			else
				return -10;
		}
	}

	return 0;
}
