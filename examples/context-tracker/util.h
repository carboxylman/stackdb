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
 *  examples/context-tracker/util.h
 *
 *  Utility functions for context tracker.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#ifndef __CTXTRACKER_UTIL_H__
#define __CTXTRACKER_UTIL_H__

#include <target_api.h>

int read_ctrlreg(struct target *target, int regno, REGVAL *regval);

int get_member_i32(struct target *target, struct value *value_struct, 
		const char *member, int32_t *i32);

int get_member_string(struct target *target, struct value *value_struct, 
		const char *member, char *string);

int get_member_regval(struct target *target, struct value *value_struct, 
		const char *member, REGVAL *regval);

#endif /* __CTXTRACKER_UTIL_H__ */
