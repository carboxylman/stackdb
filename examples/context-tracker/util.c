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
#include <target_api.h>
#include <target_xen_vm.h>

#include "util.h"

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
