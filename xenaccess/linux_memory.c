/*
 * The libxa library provides access to resources in domU machines.
 * 
 * Copyright (C) 2005 - 2007  Bryan D. Payne (bryan@thepaynes.cc)
 * Copyright (C) 2011, 2012 The University of Utah
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * --------------------
 * This file contains routines for accessing memory on a linux domU.
 *
 * File: linux_memory.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 *
 * $Id$
 * $Date$
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <xenctrl.h>
#include "xa_private.h"

#define THREAD_SIZE 8192
#define current_thread_ptr(esp) ((esp) & ~(THREAD_SIZE - 1))

/* finds the task struct for a given pid */
unsigned char *linux_get_taskstruct (
        xa_instance_t *instance, int pid, uint32_t *offset)
{
    unsigned char *memory = NULL;
    uint32_t list_head = 0, next_process = 0;
    int task_pid = 0;
    int pid_offset = instance->os.linux_instance.pid_offset;
    int tasks_offset = instance->os.linux_instance.tasks_offset;
    int i = 0;

#ifdef ENABLE_XEN
    vcpu_guest_context_t ctx;
    //xc_dominfo_t di;
    unsigned long thread_info_ptr;
    unsigned long thread_info_addr;
    uint32_t loffset;

    //xc_domain_getinfo(instance->m.xen.xc_handle,instance->m.xen.domain_id,1,&di);
    if (xc_vcpu_getcontext(instance->m.xen.xc_handle,instance->m.xen.domain_id,
			   0, // XXX: di.max_vcpu_id,
			   &ctx) == 0) {
	/* check the current thread first; see if it's our pid */
	thread_info_ptr = current_thread_ptr(ctx.user_regs.esp);
	memory = xa_access_kernel_va(instance, thread_info_ptr,
				     &loffset, PROT_READ);
	if (memory != NULL) {
	    thread_info_addr = *((unsigned long *)(memory + loffset));
	    munmap(memory, instance->page_size);

	    memory = xa_access_kernel_va(instance, thread_info_addr + tasks_offset,
					 &loffset, PROT_READ);
	    if (memory != NULL) {
		if (*((int *)(memory + loffset + (pid_offset - tasks_offset))) == pid) {
		    xa_dbprint(0,"opt: pid %d == current thread (0x%x)\n",
			       *((int *)(memory + loffset + (pid_offset - tasks_offset))),
			       thread_info_addr);
		    *offset = loffset;
		    return memory;
		}
		
		xa_dbprint(0,"opt: pid %d != current thread (0x%x)\n",
			   *((int *)(memory + loffset + (pid_offset - tasks_offset))),
			   thread_info_ptr);
		munmap(memory, instance->page_size);
	    }
	    else 
		xa_dbprint(0,"opt: could not access current thread at (0x%x)\n",
			   thread_info_addr);
	}
	else 
	    xa_dbprint(0,"opt: could not access current thread ptr at (0x%x)\n",
		       thread_info_ptr);
    }
    else 
	xa_dbprint(0,"opt: could not getcontext!\n");
#endif

    /* first we need a pointer to this pid's task_struct */
    next_process = instance->init_task + tasks_offset;
    list_head = next_process;

    while (++i) {
	xa_dbprint(0,"getting task_struct at (0x%x)\n",next_process);
        memory = xa_access_kernel_va(instance, next_process,
				     offset, PROT_READ);
        if (NULL == memory){
            printf("ERROR: failed to get task_struct (%d)\n",i);
            goto error_exit;
        }
        memcpy(&next_process, memory + *offset, 4);

        memcpy(&task_pid,
               memory + *offset + (pid_offset - tasks_offset),
               4
        );
        
        /* if pid matches, then we found what we want */
        if (task_pid == pid) {
	    //printf("linux_get_taskstruct: found pid %d!\n",pid);
            return memory;
        }
	else {
	    xa_dbprint(0,"checked pid %d\n",task_pid);
	}

        /* if we are back at the list head, we are done */
        if (list_head == next_process) {
            printf("ERROR: failed to get task_struct: back at init_task\n");
            goto error_exit;
        }
        munmap(memory, instance->page_size);
    }

error_exit:
    if (memory) munmap(memory, instance->page_size);
    return NULL;
}

/*TODO make sure that this returns a mach address */
/* finds the address of the page global directory for a given pid */
uint64_t linux_pid_to_pgd (xa_instance_t *instance, int pid)
{
    unsigned char *memory = NULL;
    uint64_t pgd = 0;
    uint32_t ptr = 0, offset = 0;
    int mm_offset = instance->os.linux_instance.mm_offset;
    int tasks_offset = instance->os.linux_instance.tasks_offset;
    int pgd_offset = instance->os.linux_instance.pgd_offset;

    /* first we need a pointer to this pid's task_struct */
    memory = linux_get_taskstruct(instance, pid, &offset);
    if (NULL == memory){
        printf("ERROR: could not find task struct for pid = %d\n", pid);
        goto error_exit;
    }

    /* now follow the pointer to the memory descriptor and
       grab the pgd value */
    memcpy(&ptr, memory + offset + mm_offset - tasks_offset, 4);
    munmap(memory, instance->page_size);

    if (!ptr) {
	xa_dbprint(0,"NULL mm_struct ptr for pid %d, must be kthread\n",pid);
	return 0;
    }

    if (instance->pae)
	xa_read_long_long_virt(instance, ptr + pgd_offset, 0, &pgd);
    else {
	uint32_t tpgd = 0;
	xa_read_long_virt(instance, ptr + pgd_offset, 0, &tpgd);
	pgd = tpgd;
    }

    /* update the cache with this new pid->pgd mapping */
    xa_update_pid_cache(instance, pid, pgd);

error_exit:
    return pgd;
}

void *linux_access_kernel_symbol (
        xa_instance_t *instance, char *symbol, uint32_t *offset, int prot)
{
    uint32_t virt_address;
    uint64_t address;

    /* check the LRU cache */
    if (xa_check_cache_sym(instance, symbol, 0, &address)){
        return xa_access_ma64(instance, address, offset, PROT_READ);
    }

    /* get the virtual address of the symbol */
    if (linux_system_map_symbol_to_address(
            instance, symbol, &virt_address) == XA_FAILURE){
        return NULL;
    }

    xa_update_cache(instance, symbol, virt_address, 0, 0);
    return xa_access_kernel_va(instance, virt_address, offset, prot);
}

/* fills the taskaddr struct for a given linux process */
int xa_linux_get_taskaddr (
        xa_instance_t *instance, int pid, xa_linux_taskaddr_t *taskaddr)
{
    unsigned char *memory;
    uint32_t ptr = 0, offset = 0;
    int mm_offset = instance->os.linux_instance.mm_offset;
    int tasks_offset = instance->os.linux_instance.tasks_offset;
    int addr_offset = instance->os.linux_instance.addr_offset;

    /* find the right task struct */
    memory = linux_get_taskstruct(instance, pid, &offset);
    if (NULL == memory){
        printf("ERROR: could not find task struct for pid = %d\n", pid);
        goto error_exit;
    }

    /* copy the information out of the memory descriptor */
    memcpy(&ptr, memory + offset + mm_offset - tasks_offset, 4);
    munmap(memory, instance->page_size);
    memory = xa_access_kernel_va(instance, ptr, &offset, PROT_READ);
    if (NULL == memory){
        printf("ERROR: failed to follow mm pointer (0x%x)\n", ptr);
        goto error_exit;
    }
    memcpy(
        taskaddr,
        memory + offset + addr_offset,
        sizeof(xa_linux_taskaddr_t)
    );
    munmap(memory, instance->page_size);

    return XA_SUCCESS;

error_exit:
    if (memory) munmap(memory, instance->page_size);
    return XA_FAILURE;
}
