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
 *  examples/context-tracker/util.c
 *
 *  Utility functions for context tracker.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#include <stdio.h>

#include <log.h>
#include <target.h>
#include <target_api.h>
#include <target_xen_vm.h>

#include "util.h"

struct probe *register_probe_label(struct target *target, const char *symbol, 
		const probe_handler_t handler, const struct probe_ops *ops, void *data)
{
	struct bsymbol *bsymbol;
	struct probe *probe;

	if (!target || !symbol)
		return NULL;

	bsymbol = target_lookup_sym(target, (char *)symbol, ".", 
			NULL /* srcfile */, SYMBOL_TYPE_FLAG_LABEL);
	if (!bsymbol)
	{
		verror("Could not find label '%s' in debuginfo\n", symbol);
		return NULL;
	}

	probe = probe_create(target, (struct probe_ops *)ops, 
			bsymbol_get_name(bsymbol), handler, NULL /* post_handler */, 
			data, 0 /* autofree */);
	if (!probe)
	{
		verror("Could not create probe on label '%s'\n", 
				bsymbol_get_name(bsymbol));
		bsymbol_release(bsymbol);
		return NULL;
	}

	if (!probe_register_symbol(probe, bsymbol, PROBEPOINT_SW, PROBEPOINT_EXEC,
				PROBEPOINT_LAUTO))
	{
		verror("Could not register probe on label '%s'\n", 
				bsymbol_get_name(bsymbol));
		probe_free(probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return NULL;
	}

	bsymbol_release(bsymbol);

	return probe;
}

struct probe *register_probe_function_entry(struct target *target,
		const char *symbol, const probe_handler_t handler, 
		const struct probe_ops *ops, void *data)
{
	struct bsymbol *bsymbol;
	struct probe *probe;

	if (!target || !symbol)
		return NULL;

	bsymbol = target_lookup_sym(target, (char *)symbol, ".", 
			NULL /* srcfile */, SYMBOL_TYPE_FLAG_FUNCTION);
	if (!bsymbol)
	{
		verror("Could not find function '%s' in debuginfo\n", symbol);
		return NULL;
	}

	probe = probe_create(target, (struct probe_ops *)ops, 
			bsymbol_get_name(bsymbol), handler, NULL /* post_handler */, 
			data, 0 /* autofree */);
	if (!probe)
	{
		verror("Could not create probe on function '%s' entry\n", 
				bsymbol_get_name(bsymbol));
		bsymbol_release(bsymbol);
		return NULL;
	}

	if (!probe_register_symbol(probe, bsymbol, PROBEPOINT_SW, PROBEPOINT_EXEC,
				PROBEPOINT_LAUTO))
	{
		verror("Could not register probe on function '%s' entry\n", 
				bsymbol_get_name(bsymbol));
		probe_free(probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return NULL;
	}

	bsymbol_release(bsymbol);

	return probe;
}

struct probe *register_probe_function_exit(struct target *target, 
		const char *symbol, const probe_handler_t handler, 
		const struct probe_ops *ops, void *data)
{
	int ret;
	struct bsymbol *bsymbol;
	struct probe *probe;
	ADDR base_addr = 0;

	if (!target || !symbol)
		return NULL;

	bsymbol = target_lookup_sym(target, (char *)symbol, ".", 
			NULL /* srcfile */, SYMBOL_TYPE_FLAG_FUNCTION);
	if (!bsymbol)
	{
		verror("Could not find function '%s' in debuginfo\n", symbol);
		return NULL;
	}

	ret = location_resolve_symbol_base(target, bsymbol, &base_addr, 
			NULL /* range */);
	if (ret)
	{
		verror("Could not resolve base address for function '%s'\n", 
				bsymbol_get_name(bsymbol));
		bsymbol_release(bsymbol);
		return NULL;
	}

	probe = probe_create(target, (struct probe_ops *)ops, 
			bsymbol_get_name(bsymbol), handler, NULL /* post_handler */, 
			data, 0 /* autofree */);
	if (!probe)
	{
		verror("Could not create probe on function '%s' exit\n", 
				bsymbol_get_name(bsymbol));
		bsymbol_release(bsymbol);
		return NULL;
	}

	if (!probe_register_function_instrs(bsymbol, PROBEPOINT_SW, 1 /* noabort */,
				INST_RET, probe, INST_NONE))
	{
		verror("Could not register probe on function '%s' exit\n", 
				bsymbol_get_name(bsymbol));
		probe_free(probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return NULL;
	}

	if (probe_num_sources(probe) == 0)
	{
		verror("No return sites in function '%s'\n", bsymbol_get_name(bsymbol));
		probe_unregister(probe, 1 /* force */);
		probe_free(probe, 1 /* force */);
		bsymbol_release(bsymbol);
		return NULL;
	}

	bsymbol_release(bsymbol);

	return probe;
}

/* FIXME: remove this once you start using target's ELF symtab symbols. */
struct probe *register_probe_function_sysmap(struct target *target,
		const char *symbol, const probe_handler_t handler, 
		const struct probe_ops *ops, void *data, FILE *sysmap_handle)
{
	struct probe *probe;
	ADDR addr;

	if (!target || !symbol)
		return NULL;
	
	addr = read_sysmap_addr(symbol, sysmap_handle);
	if (!addr)
	{
		verror("Could not find function '%s' in system.map\n", symbol);
		return NULL;
	}

	probe = probe_create(target, (struct probe_ops *)ops, (char *)symbol, 
			handler, NULL /* post_handler */, data, 0 /* autofree */);
	if (!probe)
	{
		verror("Could not create probe on function '%s' entry\n", symbol);
		return NULL;
	}

	if (!probe_register_addr(probe, addr, PROBEPOINT_BREAK, PROBEPOINT_SW, 
			PROBEPOINT_EXEC, PROBEPOINT_LAUTO, NULL))
	{
		verror("Could not register probe on '%s' entry\n", symbol);
		probe_free(probe, 1 /* force */);
		return NULL;
	}

	return probe;
}

/* FIXME: remove this once you start using target's ELF symtab symbols. */
ADDR read_sysmap_addr(const char *symbol, FILE *sysmap_handle)
{
	int ret;
	ADDR addr;
	char sym[256];
	char symtype;

	if (!symbol || !sysmap_handle)
		return 0;

	fseek(sysmap_handle, 0, SEEK_SET);

	while ((ret = fscanf(sysmap_handle, "%x %c %s255", &addr, &symtype, sym)) 
			!= EOF)
	{
		if (ret < 0)
		{
			verror("Could not fscanf Systemp.map\n");
			return -5;
		}
		else if (ret != 3)
			continue;

		if (strcmp(symbol, sym) == 0)
			return addr;
	}

	return 0;
}

int read_ctrlreg(struct target *target, int regno, REGVAL *regval)
{
	int ret;
	struct xen_vm_state *xstate;
	int xc_handle;
	xc_dominfo_t dominfo;
	vcpu_guest_context_t context;

	if (!target || !target->state)
		return -1;

	xstate = (struct xen_vm_state *)target->state;

	xc_handle = xc_interface_open();
	if (xc_handle < 0)
	{
		verror("Could not open xc interface: %s\n", strerror(errno));
		return xc_handle;
	}

	ret = xc_domain_getinfo(xc_handle, xstate->id, 1, &dominfo);
	if (ret <= 0)
	{
		verror("Could not get domain info for target '%s'\n", xstate->name);
		return -2;
	}

	ret = xc_vcpu_getcontext(xc_handle, xstate->id, dominfo.max_vcpu_id, 
			&context);
	if (ret)
	{
		verror("Could not get vcpu context for target '%s'\n", xstate->name);
		return ret;
	}

	*regval = context.ctrlreg[regno];

	return 0;
}

int get_member_i32(struct target *target, struct value *value_struct, 
		const char *member, int32_t *i32)
{
	struct value *value;

	if (!target || !value_struct || !member || !i32)
		return -1;

	value = target_load_value_member(target, value_struct, member, 
			NULL /* delim */, LOAD_FLAG_NONE);
	if (!value)
		return -2;

	*i32 = v_i32(value);

	value_free(value);

	return 0;
}

int get_member_string(struct target *target, struct value *value_struct, 
		const char *member, char *string)
{
	struct value *value;

	if (!target || !value_struct || !member || !string)
		return -1;

	value = target_load_value_member(target, value_struct, member, 
			NULL /* delim */, LOAD_FLAG_NONE);
	if (!value)
		return -2;

	strncpy(string, value->buf, value->bufsiz);

	value_free(value);

	return 0;
}

int get_member_regval(struct target *target, struct value *value_struct, 
		const char *member, REGVAL *regval)
{
	struct value *value;

	if (!target || !value_struct || !member || !regval)
		return -1;

	value = target_load_value_member(target, value_struct, member, 
			NULL /* delim */, LOAD_FLAG_NONE);
	if (!value)
		return -2;

	*regval = *((REGVAL *)value->buf);

	value_free(value);

	return 0;
}
