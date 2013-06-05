/*
 * Copyright (c) 2013 The University of Utah
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

#ifndef __TARGET_XEN_VM_PROCESS_H__
#define __TARGET_XEN_VM_PROCESS_H__

#include <glib.h>

#include "evloop.h"
#include "target_api.h"

/*
 * Notes:
 *
 * First, we always add all threads in the thread group associated with
 * the thread the user instantiates the overlay for.  If they don't
 * provide the main thread, we "pivot" it into place in our init() ops.
 */

extern struct target_ops xen_vm_process_ops;

struct xen_vm_process_spec *xen_vm_process_build_spec(void);
void xen_vm_process_free_spec(struct xen_vm_process_spec *spec);

/*
 * Nothing at the moment.
 */
struct xen_vm_process_spec { };
struct xen_vm_process_thread_state { };

/*
 * This just helps us scan for updates to a task's
 * task_struct->mm->mmap (vm_area_struct list).
 *
 * There is one of these for each target memrange.
 */
struct xen_vm_process_vma {
    struct value *vma;
    ADDR next_vma_addr;
    struct xen_vm_process_vma *next;
    struct memrange *range;
};

struct xen_vm_process_state {
    ADDR mm_addr;
    struct value *mm;
    /* Cache these to determine if range is heap/stack. */
    ADDR mm_start_brk;
    ADDR mm_brk;
    ADDR mm_start_stack;

    struct xen_vm_process_vma *vma_cache;
    int vma_len;
};

#endif /* __TARGET_XEN_VM_PROCESS_H__ */
