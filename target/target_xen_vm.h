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

#ifndef __TARGET_XEN_VM_H__
#define __TARGET_XEN_VM_H__


#include <xenctrl.h>
#include <xenaccess/xenaccess.h>

/*
 * target-specific state for xen vms.
 */
struct xen_vm_state {
    domid_t id;
    char *name;

    char *vmpath;
    char *kernel_filename;
    char *kernel_version;
    char *kernel_elf_filename;

    int context_dirty;
    int context_valid;
    vcpu_guest_context_t context;

    xc_dominfo_t dominfo;
    int dominfo_valid;

    /* XenAccess instance used to read/write domain's memory */
    xa_instance_t xa_instance;

    /* XXX: can we debug a 32-bit target on a 64-bit host?  If yes, how 
     * we use this might have to change.
     */
    unsigned long dr[8];

#if __WORDSIZE == 32
    uint32_t eflags;
#else
    uint64_t rflags;
#endif
};

/*
 * Attaches to @domain (which may be paused or running) (@domain may be
 * a name string or a domain id number).  @dfoptlist is a
 * NULL-terminated list of debugfile_load_opts structs (ideally parsed
 * from debugfile_load_opts_parse if you're coming from the command
 * line).
 */
struct target *xen_vm_attach(char *domain,
			     struct debugfile_load_opts **dfoptlist);

struct value *linux_load_current_task(struct target *target);
int linux_get_task_pid(struct target *target,struct value *task);

typedef int (*linux_list_iterator_t)(struct target *t,struct value *value,
				     void *data);
int linux_list_for_each_struct(struct target *t,struct bsymbol *bsymbol,
			       char *list_head_member_name,
			       linux_list_iterator_t iterator,void *data);

#endif /* __TARGET_XEN_VM_H__ */
