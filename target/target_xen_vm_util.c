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
#include "target_xen_vm.h"

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
	target_create_synthetic_type_pointer(target,
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

/*
 * Since linux linked lists are formed by chaining C structs together
 * using struct members as the list next/prev pointers, we provide a
 * generic function to traverse them.
 *
 * Basically, we calculate the offset of the list head member name in
 * the type, and then, starting with the struct at the @head - offset,
 * we load that value.  We then continue looping by loading the next
 * struct specified in the list head member's next field.
 */
int linux_list_for_each_struct(struct target *t,struct bsymbol *bsymbol,
			       char *list_head_member_name,
			       linux_list_iterator_t iterator,void *data) {
    struct symbol *symbol;
    struct symbol *type;
    struct symbol *list_head_member_symbol = NULL;
    OFFSET list_head_member_offset;
    ADDR head;
    ADDR next_head;
    ADDR current_struct_addr;
    struct value *value = NULL;
    int i = 0;
    int retval = -1;

    struct dump_info udn = {
	.stream = stderr,
	.prefix = "",
	.detail = 1,
	.meta = 1,
    };

    symbol = bsymbol_get_symbol(bsymbol);
    type = symbol_get_datatype(symbol);
    if (!type) {
	verror("no type for bsymbol %s!\n",bsymbol_get_name(bsymbol));
	goto out;
    }

    list_head_member_symbol = symbol_get_one_member(type,
						    list_head_member_name);
    if (!list_head_member_symbol) {
	verror("no such member %s in symbol %s!\n",list_head_member_name,
	       symbol_get_name(type));
	goto out;
    }

    if (symbol_get_location_offset(list_head_member_symbol,
				   &list_head_member_offset)) {
	verror("could not get offset for member %s in symbol %s!\n",
	       symbol_get_name(list_head_member_symbol),symbol_get_name(type));
	symbol_dump(symbol,&udn);
	goto out;
    }

    current_struct_addr = head = \
	target_addressof_bsymbol(t,bsymbol,LOAD_FLAG_NONE,NULL);
    if (errno) {
	verror("could not get the address of bsymbol %s!\n",
	       bsymbol_get_name(bsymbol));
	goto out;
    }
    /* The real head is plus the member offset. */
    head += list_head_member_offset;

    /* Now, start loading the struct values one by one, starting with
     * the symbol arg itself.
     */
    while (1) {
	value = target_load_type(t,type,current_struct_addr,LOAD_FLAG_NONE);
	if (!value) {
	    verror("could not load value in list position %d, aborting!\n",i);
	    goto out;
	}

	if (iterator(t,value,data))
	    break;

	next_head = *((ADDR *)(value->buf + list_head_member_offset));
	if (next_head == head)
	    break;

	current_struct_addr = next_head - list_head_member_offset;
	++i;
	value_free(value);
    }

    retval = 0;

 out:
    if (list_head_member_symbol)
	symbol_release(list_head_member_symbol);
    if (value)
	value_free(value);

    return retval;
}
