/*
 * Copyright (c) 2011, 2012, 2013 The University of Utah
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
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/unistd.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>

#include <asm/uaccess.h>
#include <linux/linkage.h>
#include <asm/pgtable.h>
#include <asm/desc.h>
#include <asm/page.h>
#include "repair_driver.h"

#define FUNCTION_COUNT 1
#define SUBMODULE_ID  2

extern struct submod_table submodule;
extern int ack_ready;
struct submodule submod;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
int change_page_attr(struct page * page, int number, pgprot_t prot);
#endif

void set_page_rw(long unsigned int addr) {

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
    struct page *pg;
    pgprot_t prot;
    pg = virt_to_page(addr);
    prot.pgprot = VM_READ | VM_WRITE;
    return change_page_attr(pg, 1, prot);
#else
    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);
    if(pte->pte &~ _PAGE_RW) {
	pte->pte |= _PAGE_RW;
    }
#endif
}

void set_page_ro(long unsigned int addr) {
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
    }
#endif
}



static int map_reset_func(struct cmd_rec *cmd, struct ack_rec *ack) {

    void **system_call_table = NULL;
    int offset = 0;
    void * func_addr = NULL;
    void * curr_func_addr = NULL;


    /* Parse the arguments passed */
    if(cmd->argc < 1 || cmd->argc > 1) {
	printk(KERN_INFO "system_map_reset module requires exactly 1 argument to be passed i.e, PID");
	return -EINVAL;
    }

    /* Get the base address for the system.map table */
    system_call_table = (void*)cmd->argv[0];
    /* Get the offset in the table */
    offset = cmd->argv[2];
    /* Get the correct address */
    func_addr = (void *)cmd->argv[1];
    /*set the command and submodule id in the ack structure */
    ack->cmd_id = cmd->cmd_id;
    ack->submodule_id = cmd->submodule_id;

    printk(KERN_INFO " Address passes %x %x %d\n",
	    cmd->argv[0], cmd->argv[1],cmd->argv[2]);
    printk(KERN_INFO " Setting the write permissions at %x \n",
	    system_call_table);
    /* Set write permissions on the system call table */
    set_page_rw((long unsigned int) system_call_table);
    printk(KERN_INFO " Write permission set\n");
    /* Now reset the sys call address in the table */
    curr_func_addr = system_call_table[offset];
    printk(KERN_INFO " Current entry in the system call table : %x.\n",
	    curr_func_addr);
    system_call_table[offset] = func_addr;
    printk(KERN_INFO " System call table entry changed to %x.\n",
	    func_addr);

    printk(KERN_INFO " Reset the orignal permissions on the system call table. \n");

    /* Revert the permissions back to readonly */
    set_page_ro((long unsigned int )system_call_table);

    /* set the execution status in the ack record to success */
    ack->exec_status = 1;
    /* 
     * since the execution of the command does not return anything
     * set argc = 0;
     */
    ack->argc = 0;

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
    submod.func_table[0] = map_reset_func;

    /* register the submodule table maintained in the repair driver */
    submodule.mod_table[submod.submodule_id] = &submod;
    printk(KERN_INFO " Registered with the submodule table\n");

    return ret;
}

static int driver_mod_unregister_submodule(void * __unused) {

    /* reinitialize the function pointer to NULL */
    submod.func_table[0] = NULL;
    /* Remove the entry for this module from the main table  */
    submodule.mod_table[submod.submodule_id] = NULL;

    return 0;

}


static int __init system_map_reset_init(void) {
    int result;
    printk(KERN_INFO "Initialize the function table for this submdule.\n");
    result = driver_mod_register_submodule(NULL);
    if(result ) {
	printk(KERN_INFO " Module register function failed \n");
	return result;
    }


    return 0;
}

static void __exit system_map_reset_exit(void) {
    int result;

    printk(KERN_INFO "In the exit function \n");
    /* Unregister  from the module table */
    result =  driver_mod_unregister_submodule(NULL);
    if(result) {
	printk(KERN_INFO " Module unregister function failed \n");
    }

}

module_init(system_map_reset_init);
module_exit(system_map_reset_exit);
