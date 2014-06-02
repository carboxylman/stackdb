/*
 * Copyright (c) 2011, 2012, 2013, 2014  The University of Utah
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

#define LINUX
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/kthread.h>
#include <linux/fdtable.h>
#include <linux/sched.h> 
#include <asm/thread_info.h>
#include <asm/signal.h>
#include <asm/siginfo.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include "repair_driver.h"
#include <linux/version.h>
#include <asm/uaccess.h>
#include <linux/linkage.h>
#include <asm/pgtable.h>
#include <asm/pgtable_types.h>
#include <asm/desc.h>
#include <asm/page.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/mmu_context.h>
#include <linux/rmap.h>
#include <asm/tlbflush.h>

#define FUNCTION_COUNT 1
#define SUBMODULE_ID  4

extern struct submod_table submodule;
extern int ack_ready;
struct submodule submod;

static int insert_ret_sled(struct task_struct *task, char *name) {

    struct vm_area_struct *vma = NULL, *next = NULL, *vma_new = NULL;
    struct mm_struct *mm = NULL; 
    char *object =  NULL;
    unsigned long vm_start_addr, start_addr;
    void *start_addr_new;
    unsigned long end_addr, prev_addr;
    char ret_opcode = '\xc3';
    char noop = '\x90';
    struct page *user_page;
    unsigned int length = 0, ret;
    unsigned int i, no_of_pages,page_size;
    char *char_ptr = NULL;


    mm = get_task_mm(task);
    if(!mm) {
	printk(KERN_INFO " Task has no mm struct \n");
	return 0;
    }

    down_read(&mm->mmap_sem);
    vma  = mm->mmap;
    while(vma) {
	next = vma->vm_next;
	if(vma->vm_file) {
	    object =  vma->vm_file->f_path.dentry->d_name.name;
	    if( !strcmp(object, name)) {	
		//printk(KERN_INFO "INFO: Found a linked vm_area for  object %s.\n",name);
		//printk(KERN_INFO " Check if the vm_area is executable \n");
		if(!(vma->vm_flags & VM_EXEC)) {
		    //printk(KERN_INFO "The area is not executable \n");
		    vma = next;
		    continue;
		}
		vm_start_addr = vma->vm_start;
		end_addr = vma->vm_end;
		length  = vma->vm_end - vma->vm_start;
		no_of_pages = length / PAGE_SIZE;
		printk(KERN_INFO "INFO: Start address %lx\n",vm_start_addr);
		printk(KERN_INFO "INFO: End address %lx\n",end_addr);
		printk(KERN_INFO "INFO: VM area length = %u\n",length);
		printk(KERN_INFO "INFO: Number of pages %d\n",no_of_pages);
	    	
		for(i = 0; i< no_of_pages; i++) {

		    start_addr = vm_start_addr + (i * PAGE_SIZE);
		    ret = get_user_pages(NULL, mm , (unsigned long) start_addr,
					       1 , 1 , 1, &user_page, &vma_new);
		    if(ret <= 0 ) {
			printk(KERN_INFO "INFO: Failed to load the processes pages\n");
			up_read(&mm->mmap_sem);
			mmput(mm);			
			return 1;
		    }

		    //printk(KERN_INFO "INFO: Start address %lx\n",start_addr);
		    start_addr_new = kmap(user_page);
		    //printk(KERN_INFO " New start address %lx\n",start_addr_new);

		    char_ptr = (char *) (start_addr_new) ;	
		    /*Now create a RET sled till the end address */
		    page_size = PAGE_SIZE;
		    while (page_size) {
			//printk(KERN_INFO "INFO: start address + offset  %lx\n",
			//                              start_addr_new + offset);
			if(*char_ptr != ret_opcode) {
			    memcpy( char_ptr, (void*)&noop, sizeof(char));
			}
			char_ptr++;
			page_size--;
		    }
		    	
		    set_page_dirty_lock(user_page);
		    kunmap(user_page); 
		    //printk(KERN_INFO "INFO: put_page() called \n");
		    put_page(user_page);
		}
	    }  
	}
	vma = next;
    }
    up_read(&mm->mmap_sem);
    mmput(mm);
    return 0;
}

static int insert_ret_sled_func(struct cmd_rec *cmd, struct ack_rec *ack) {
    int length = 0;
    char *char_ptr = NULL;
    char **object_name;
    int ret, i = 0;
    int  pid;
    struct task_struct *task = NULL;



    printk(KERN_INFO " Number of arguments passed is %d\n",cmd->argc);

    object_name = kmalloc((cmd->argc - 1)* sizeof(char*), GFP_KERNEL);
    char_ptr = (char *)cmd->argv;

    /* read the pid */
    pid = *(int *) char_ptr;
    printk(KERN_INFO "INFO: PID passed is %d\n",pid);
    char_ptr = char_ptr + sizeof(int);
	
    /*read the object names passed */
    for( i=0; i< (cmd->argc - 2); i++) {
	length = *(int *)char_ptr;
	printk(KERN_INFO "length %d\n",length);
	char_ptr = char_ptr + sizeof(int);
	object_name[i] = kmalloc((length * sizeof(char)), GFP_KERNEL);
	memcpy(object_name[i], (void *)char_ptr, length );
	printk(KERN_INFO "INFO: object_name[%d] = %s length = %d\n",
					    i,object_name[i], length);
	char_ptr = char_ptr + length ;
    }

    /*set the command and submodule id in the ack structure */
    ack->cmd_id = cmd->cmd_id;
    ack->submodule_id = cmd->submodule_id;
    ack->argc = 0;

    /* Iterate over all the tasks and check for a matching PID*/
    for_each_process(task) {
	if (task->pid == pid) {

	    /* We have found the task_struct for the process*/
	    printk(KERN_INFO "Found process %s with PID = %d\n",
		    task->comm, task->pid);
	    send_sig(SIGSTOP, task,0);
	    for(i = 0; i < cmd->argc - 1; i++) {
		ret = insert_ret_sled(task,object_name[i]);
		if(ret) {
		    printk(KERN_INFO "INFO: Failed to unload object %s \n",
							    object_name[i]);
		}
	    }
	    send_sig(SIGCONT, task,0);
	    break;	
	}
    }

    for( i = 0; i< (cmd->argc-2); i++) {
	kfree(object_name[i]);
    }
`
    kfree(object_name);

    /* Set flag to indicate the result is ready */
    ack_ready++;
    return 0;
}


static int driver_mod_register_submodule(void * __unused) {

    int ret = 0;
    /*Initialize struct members */
    submod.func_count = FUNCTION_COUNT;
    submod.submodule_id = SUBMODULE_ID;

    /* allocate memory for the array of function pointers */
    submod.func_table = (cmd_impl_t *) kmalloc(FUNCTION_COUNT * sizeof(cmd_impl_t), GFP_KERNEL );
    if(!submod.func_table) {
	printk(KERN_INFO "Failed to allocate memory for the function table\n");
	return -ENOMEM;
    }

    /* initilize the function table */
    submod.func_table[0] = insert_ret_sled_func;

    /* register the submodule table maintained in the repair driver */
    submodule.mod_table[submod.submodule_id] = &submod;

    return ret;
}

static int driver_mod_unregister_submodule(void * __unused) {

    /* reinitialize the function pointer to NULL */
    submod.func_table[0] = NULL;
    /* Remove the entry for this module from the main table  */
    submodule.mod_table[submod.submodule_id] = NULL;
    return 0;
}


static int __init sled_object_init(void) {
    int result;
    printk(KERN_INFO "Initialize the function table for start_process submdule.\n");
    result = driver_mod_register_submodule(NULL);
    if(result ) {
	printk(KERN_INFO " Module register function failed \n");
	return result;
    }
    return 0;
}

static void __exit sled_object_exit(void) {
    int result;

    printk(KERN_INFO "In the exit function \n");
    /* Unregister  from the module table */
    result =  driver_mod_unregister_submodule(NULL);
    if(result) {
	printk(KERN_INFO " Module unregister function failed \n");
    }
}

module_init(sled_object_init);
module_exit(sled_object_exit);
MODULE_LICENSE("GPL");
