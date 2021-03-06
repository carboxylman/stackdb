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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/sched.h> 
#include <asm/thread_info.h>
#include <asm/signal.h>
#include <asm/siginfo.h>
#include <linux/slab.h>
#include "repair_driver.h"
#include <linux/version.h>

#define FUNCTION_COUNT 1
#define SUBMODULE_ID  0

extern struct submod_table submodule;
extern int ack_ready;
struct submodule submod;


static int ps_kill_func(struct cmd_rec *cmd, struct ack_rec *ack) {
    struct task_struct *task;
    int found_flag = 0;
    int psaction_pid = 0;
    int *int_ptr = NULL;


    /* Parse the arguments passed */
    if(cmd->argc < 1 || cmd->argc > 1) {
	printk(KERN_INFO "pasction module requires exactly 1 argument to be passed i.e, PID");
	printk(KERN_INFO " Number of arguments passed is %d\n",cmd->argc);
	return -EINVAL;
    }

    /* Extract the PID passed */
    int_ptr = (int *)cmd->argv;
    psaction_pid = *int_ptr;
    printk(KERN_INFO "Process ID passed is %d.\n",psaction_pid);
    //bzero(ack, sizeof(struct ack_rec));
    /*set the command and submodule id in the ack structure */
    ack->cmd_id = cmd->cmd_id;
    ack->submodule_id = cmd->submodule_id;


    /* Iterate over all the tasks and check for a matching PID*/
    for_each_process(task) {
	if (task->pid == psaction_pid) {
	    /* We have found the task_struct for the process*/
	    printk(KERN_INFO "Found process %s with PID = %d\n",
		    task->comm, task->pid);
	    
	    force_sig(SIGKILL, task);
	    found_flag = 1;
	}
    }

    if (!found_flag) {
	printk(KERN_INFO "Process with PID = %d not found", psaction_pid);
	//ack->exec_status = 0;
	ack->argc = 0;

    }
    
    psaction_pid = 0;
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
    submod.func_table[0] = ps_kill_func;

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


static int __init psaction_init(void) {
    int result;
    printk(KERN_INFO "Initialize the function table for this submdule.\n");
    result = driver_mod_register_submodule(NULL);
    if(result ) {
	printk(KERN_INFO " Module register function failed \n");
	return result;
    }


    return 0;
}

static void __exit psaction_exit(void) {
    int result;

    printk(KERN_INFO "In the exit function \n");
    /* Unregister  from the module table */
    result =  driver_mod_unregister_submodule(NULL);
    if(result) {
	printk(KERN_INFO " Module unregister function failed \n");
    }

}

module_init(psaction_init);
module_exit(psaction_exit);
