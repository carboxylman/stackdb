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

#include "target_api.h"
#include "dwdebug.h"

#define THREAD_SIZE 8192
#define current_thread_ptr(esp) ((esp) & ~(THREAD_SIZE - 1))

struct value *linux_load_current_task(struct target *target) {
    struct value *value;
    ADDR itptr;
    REGVAL esp;
    struct bsymbol *it_type;
    struct symbol *itptr_type;

    it_type = target_lookup_sym(target,"struct task_struct",
				NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);
    if (!it_type) {
	verror("could not find type for struct task_struct!\n");
	return NULL;
    }

    itptr_type = \
	target_create_dynamic_type_pointer(target,
					   bsymbol_get_symbol(it_type));

    errno = 0;
    esp = target_read_reg(target,target->spregno);
    if (errno) {
	verror("could not read ESP!\n");
	return NULL;
    }

    itptr = current_thread_ptr(esp);

    value = target_load_type(target,itptr_type,itptr,
			     LOAD_FLAG_AUTO_DEREF);

    symbol_release(itptr_type);
    bsymbol_release(it_type);

    return value;
}

int linux_get_task_pid(struct target *target,struct value *task) {
    struct value *value;
    int pid;

    if (!task)
	return -1;

    value = target_load_value_member(target,task,"pid",NULL,
				     LOAD_FLAG_NONE);
    if (!value) {
	verror("could not load 'pid' of task!\n");
	return -2;
    }
    pid = v_i32(value);

    value_free(value);

    return pid;
}
