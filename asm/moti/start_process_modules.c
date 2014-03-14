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
#include <linux/sched.h> 
#include <asm/thread_info.h>
#include <asm/signal.h>
#include <asm/siginfo.h>
#include <linux/slab.h>
#include "repair_driver.h"
#include <linux/version.h>

#define FUNCTION_COUNT 1
#define SUBMODULE_ID  6

extern struct submod_table submodule;
extern int ack_ready;
struct submodule submod;


static int start_process_func(struct cmd_rec *cmd, struct ack_rec *ack) {
    int length = 0;
    int *int_ptr = NULL;
    char *argv[10];
    char *envp[10];
    int ret, i = 0;


    printk(KERN_INFO " Number of arguments passed is %d\n",cmd->argc);
    int_ptr = (int *)cmd->argv;
    length = *int_ptr;
    
    /*read the argv passed */
    for( i=0; i< (cmd->argc + 1); i++) {
	length = *int_ptr;
	int_ptr++;
	
	if(length == 0) {
	    argv[i] = NULL;
	    break;
	}
	
	argv[i] = malloc(length * sizeof(char));
	memcpy(argv[i], (void *)int_ptr, length);
	printk(KERN_INFO "INFO: argv[%d] = %s\n",i,argv[i]);
	int_ptr = int_ptr + length;
    }

    /* read the envp passed */
    for(i = 0 ; i< 3; i++) {
	length = *int_ptr;
	int_ptr++;
	
	if(length == 0) {
	    *envp[i] = NULL;
	    break;
	}
	
	envp[i] = malloc(length * sizeof(char));
	memcpy(envp[i], (void *)int_ptr, length);
	printk(KERN_INFO "INFO: envp[%d] = %s\n",i,envp[i]);
	int_ptr = int_ptr + length;

    }

    /*set the command and submodule id in the ack structure */
    ack->cmd_id = cmd->cmd_id;
    ack->submodule_id = cmd->submodule_id;
    ack->argc = 0;

    /* Finally make teh function call */
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    if (ret == -ENOENT || ret == -EACCES) {
	printk(KERN_INFO " Prigram  was not found or isn't executable.\n");
    }

    /* Set flag to indicate the result is ready */
    ack_ready++;
    return ret;
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
    submod.func_table[0] = start_process_func;

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


static int __init start_process_init(void) {
    int result;
    printk(KERN_INFO "Initialize the function table for start_process submdule.\n");
    result = driver_mod_register_submodule(NULL);
    if(result ) {
	printk(KERN_INFO " Module register function failed \n");
	return result;
    }
    return 0;
}

static void __exit start_process_exit(void) {
    int result;

    printk(KERN_INFO "In the exit function \n");
    /* Unregister  from the module table */
    result =  driver_mod_unregister_submodule(NULL);
    if(result) {
	printk(KERN_INFO " Module unregister function failed \n");
    }
}

module_init(start_process_init);
module_exit(start_process_exit);
