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

#define FUNCTION_COUNT 1
#define SUBMODULE_ID  4

extern struct submod_table submodule;
extern int ack_ready;
struct submodule submod;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
extern int change_page_attr(struct page * page, int number, pgprot_t prot);
#else
extern pte_t *lookup_address(unsigned long address, unsigned int *level);
#endif

int set_page_rw(unsigned long addr) {

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
    struct page *pg;
    pgprot_t prot;
    pg = virt_to_page(addr);
    prot.pgprot = VM_READ | VM_WRITE;
    return change_page_attr(pg, 1, prot);
#else
    unsigned int level;
    printk(KERN_INFO " Now doing lookup \n");
    pte_t *pte = lookup_address(addr, &level);
    if(pte == NULL) {
	printk(KERN_INFO "lookup_address failed\n");
	return -EINVAL;

    }
    printk(KERN_INFO " lookup_address done\n");
    if(pte->pte &~ _PAGE_RW) {
	pte->pte |= _PAGE_RW;
    }
    return 0;
#endif
}

int set_page_ro(unsigned long addr) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
    struct page *pg;
    pgprot_t prot;
    pg = virt_to_page(addr);
    prot.pgprot = VM_READ;
    return change_page_attr(pg,1,prot);
#else  
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if(pte->pte & _PAGE_RW) {
	pte->pte &= ~_PAGE_RW;
	return -EINVAL;
    }
    return 0;
#endif
}


static int insert_ret_sled(struct task_struct *task, char *name) {

    struct vm_area_struct *vma = NULL, *next = NULL;
    struct mm_struct *mm = NULL; 
    char *object =  NULL;
    void *start_addr;
    void *start_addr_new;
    void *end_addr;
    char *char_ptr = NULL;
    char opcode = '\xC3';
    struct page *user_page[1];
    unsigned int length = 0, ret;


    mm = get_task_mm(task);
    if(!mm) {
	printk(KERN_INFO " Task has no mm struct \n");
	return 0;
    }
    vma  = mm->mmap;
    while(vma) {
	next = vma->vm_next;
	if(vma->vm_file) {
	    object =  vma->vm_file->f_path.dentry->d_name.name;
	    if( !strcmp(object, name)) {
			
		printk(KERN_INFO "INFO: Found a linked vm_area for  object %s.\n",name);
		start_addr = (void *)vma->vm_start;
		end_addr = (void *) vma->vm_end;
		length  = vma->vm_end - vma->vm_start;
		printk(KERN_INFO " Start address %lx\n",start_addr);
		printk(KERN_INFO " ENd address %lx\n",end_addr);
		printk(KERN_INFO "INFO: Page length = %u\n",length);
		//vma->vm_flags|=VM_DONTCOPY; 
	    	
		 down_read(&mm->mmap_sem);
		/* read the pag with virtual at that virual address into memory */
		ret = get_user_pages(NULL, mm , (unsigned long) start_addr, 1 , 1 , 1, user_page, NULL);
		if(ret <= 0 ) {
		    printk(KERN_INFO "INFO: Failed to load the processes pages\n");
		    up_read(&mm->mmap_sem);
		    return 1;
		}
		up_read(&mm->mmap_sem);	
		printk(KERN_INFO "kmap the page \n");
		/* disable page fault on that address */
		start_addr_new = kmap_atomic(user_page[0]);
    
		printk(KERN_INFO " New start address %lx\n",start_addr_new);

		//printk(KERN_INFO " Setting the write permissions at %lx \n",
		//			    start_addr_new);
		//set_page_rw(start_addr_new);
		//printk(KERN_INFO " Write permission set\n");
		char_ptr = (char*) start_addr_new;
	
		
		/*Now create a RET sled till the end address */
		length = 4096;
		while (length) {
		    //printk(KERN_INFO " %x\n", *char_ptr);
		    memcpy((void *)char_ptr, (void*)&opcode, sizeof(char));
		    char_ptr++;
		    length--;
		}
		//printk(KERN_INFO " Reset the orignal permissions on the page. \n");
		//set_page_ro(start_addr_new);
		
		set_page_dirty_lock(user_page[0]);
		kunmap_atomic(start_addr_new);
		//put_page(user_page[0]);
		page_cache_release(user_page[0]);
		printk(KERN_INFO "Checking the next page \n");
	    }
	}
	vma = next;
    }
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
	    for(i = 0; i < cmd->argc - 1; i++) {
		ret = insert_ret_sled(task,object_name[i]);
		if(ret) {
		    printk(KERN_INFO "INFO: Failed to unload object %s \n",object_name[i]);
		}
	    }
	    break;	
	}
    }

    for( i = 0; i< (cmd->argc-2); i++) {
	kfree(object_name[i]);
    }

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
