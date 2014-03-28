/*
 * Copyright (c) 2011, 2012, 2013, 2014 The University of Utah
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
#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/err.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/unistd.h>
#include <linux/kallsyms.h>

#include <asm/uaccess.h>
#include <linux/linkage.h>
#include <asm/pgtable.h>
#include <asm/desc.h>
#include <asm/page.h>
#include "repair_driver.h"

#define FUNCTION_COUNT 2
#define SUBMODULE_ID  7

extern struct submod_table submodule;
extern int ack_ready;
struct submodule submod;
char **blocked_objects = NULL;
int no_of_objects;


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


asmlinkage int (*original_open) (const char *, int, int);


asmlinkage long (*original_mmap)(unsigned long addr, unsigned long len,
			         unsigned long prot, unsigned long flags,
			         unsigned long fd, unsigned long pgoff);


asmlinkage long hooked_mmap(unsigned long addr, unsigned long len,
			    unsigned long prot, unsigned long flags, 
			    unsigned long fd, unsigned long off) {

    struct task_struct *task;
    char *file_name;
    int i;
    long ret;
    struct file *file = NULL;

    //printk(KERN_INFO " fd = %ul off = %ul\n", fd, off);
    file = fget(fd);
    if(!file ) goto out;
    printk(KERN_INFO "Got the file struct \n");
    file_name = file->f_path.dentry->d_name.name;
    printk(KERN_INFO "got the filename %s\n",file_name);
    for ( i= 0; i < no_of_objects ; i++) {
    	if(strstr(file_name, blocked_objects[i])) {
    	    printk(KERN_INFO "INFO: Trying to mmap the restricted object %s \n",blocked_objects[i]);
    	    ret -ENOENT;
    	    return ret;
    	}
    }
out:
    ret = original_mmap(addr,len,prot,flags,fd,off);
    return ret;

}


asmlinkage  int hooked_open(const char * name, int flags, int mode) {

    int i = 0;
    int ret = 0 ;
   // printk(KERN_INFO "INFO: In the hooked open syscall \n");
   printk(KERN_INFO "Name = %s",name);
    for ( i= 0; i < no_of_objects ; i++) {
	if(strstr(name, blocked_objects[i])) {
	   printk(KERN_INFO "INFO: Trying to load the restricted object %s \n",blocked_objects[i]);
	    ret -EPERM;
	    return ret;
	}
    }

    ret = original_open( name, flags, mode);
    return ret;

}


static int add_hook_func(struct cmd_rec *cmd, struct ack_rec *ack) {

    void **system_call_table = NULL;
    unsigned char *char_ptr = NULL;
    int i, length;


    /* Parse the arguments passed */
    printk(KERN_INFO "INFO: Number of arguments passed is %d.\n",cmd->argc);

    /* Get the base address for the system.map table */
    char_ptr = (unsigned char*)cmd->argv;
    system_call_table = (void *) (*(unsigned long *)char_ptr);
    char_ptr = char_ptr + (sizeof(unsigned long));

   /* Allocate memory to create a list of blocked object names */
    no_of_objects = cmd->argc ;
    blocked_objects = kmalloc(no_of_objects * sizeof(char*), GFP_KERNEL);

    /*read the object names passed */
    for( i=0; i< (no_of_objects); i++) {
	length = *(int *)char_ptr;
	printk(KERN_INFO "length %d\n",length);
	char_ptr = char_ptr + sizeof(int);
	blocked_objects[i] = kmalloc((length * sizeof(char)), GFP_KERNEL);
	memcpy(blocked_objects[i], (void *)char_ptr, length );
	printk(KERN_INFO "INFO: bloked_objects[%d] = %s length = %d\n",
					    i,blocked_objects[i], length);
	char_ptr = char_ptr + length ;
    }

    /*set the command and submodule id in the ack structure */
    ack->cmd_id = cmd->cmd_id;
    ack->submodule_id = cmd->submodule_id;

    printk(KERN_INFO " Setting the write permissions at %lx \n",
	    system_call_table);

    /* store the original address of the system_call */
    //original_open = system_call_table[__NR_open];

    original_mmap = system_call_table[__NR_mmap];
    printk(KERN_INFO " Current entry in sys call table %p \n",original_mmap);

    /* Set write permissions on the system call table */
    set_page_rw((unsigned long) system_call_table);
    printk(KERN_INFO " Write permission set\n");
    /* Now reset the sys call address in the table */

    system_call_table[__NR_open] = hooked_open;
    system_call_table[__NR_mmap] = hooked_mmap;

    printk(KERN_INFO "INFO: System call table entry changed to %lx.\n",
	    hooked_open);

    printk(KERN_INFO " Reset the orignal permissions on the system call table. \n");
    /* Revert the permissions back to readonly */
    set_page_ro(( unsigned long )system_call_table);

    /* Set flag to indicate the result is ready */
    ack_ready++;
    return 0;
}

static int remove_hook_func(struct cmd_rec *cmd, struct ack_rec *ack) {

    void **system_call_table = NULL;
    unsigned char *char_ptr = NULL;
    int i, length;


    /* Parse the arguments passed */
    printk(KERN_INFO "INFO: Number of arguments passed is %d.\n",cmd->argc);

    /* Get the base address for the system.map table */
    char_ptr = (unsigned char*)cmd->argv;
    system_call_table = *(unsigned long *)char_ptr;
    char_ptr = char_ptr + (sizeof(unsigned long));

    /* Set write permissions on the system call table */
    set_page_rw((unsigned long) system_call_table);
    printk(KERN_INFO " Write permission set\n");
    /* Now reset the sys call address in the table */

    system_call_table[__NR_open] = original_open;
    system_call_table[__NR_mmap] = original_mmap;
    printk(KERN_INFO "INFO: System call table entry changed to %lx.\n",
	    hooked_open);

    printk(KERN_INFO " Reset the orignal permissions on the system call table. \n");
    /* Revert the permissions back to readonly */
    set_page_ro(( unsigned long )system_call_table);

    /* Free the memory allocated */
    for( i = 0 ; i< no_of_objects ;i++) {
	kfree(blocked_objects[i]);
    }
    kfree(blocked_objects);
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
    submod.func_table[0] = add_hook_func;
    submod.func_table[1] = remove_hook_func; 

    /* register the submodule table maintained in the repair driver */
    submodule.mod_table[submod.submodule_id] = &submod;
    printk(KERN_INFO " Registered with the submodule table\n");

    return ret;
}

static int driver_mod_unregister_submodule(void * __unused) {

    /* reinitialize the function pointer to NULL */
    submod.func_table[0] = NULL;
    submod.func_table[1] = NULL;
    /* Remove the entry for this module from the main table  */
    submodule.mod_table[submod.submodule_id] = NULL;

    return 0;

}


static int __init trusted_load_init(void) {
    int result;
    printk(KERN_INFO "Initialize the function table for this submdule.\n");
    result = driver_mod_register_submodule(NULL);
    if(result ) {
	printk(KERN_INFO " Module register function failed \n");
	return result;
    }


    return 0;
}

static void __exit trusted_load_exit(void) {
    int result;

    printk(KERN_INFO "In the exit function \n");
    /* Unregister  from the module table */
    result =  driver_mod_unregister_submodule(NULL);
    if(result) {
	printk(KERN_INFO " Module unregister function failed \n");
    }

}

module_init(trusted_load_init);
module_exit(trusted_load_exit);
MODULE_LICENSE("GPL");
