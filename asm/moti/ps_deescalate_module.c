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
#include <repair_driver.h>

#define FUNCTION_COUNT 1
#define SUBMODULE_ID  1

extern struct submod_table submodule;
extern int ack_ready;
struct submodule submod;


static int ps_deescalate_func(struct cmd_rec *cmd, struct ack_rec *ack) {
    struct task_struct *task;
    int found_flag = 0;
    int ps_deescalate_pid = 0;
    int ps_deescalate_uid = 0;
    int ps_deescalate_euid = 0;


    /* Parse the arguments passed */
    if(cmd->argc < 1 || cmd->argc > 3) {
	printk(KERN_INFO "ps_deescalate module requires atleast 2 arguments to be passed i.e, PID and UID");
	return -EINVAL;
    }

    /* Extract the PID and the UID passed */
    ps_deescalate_pid = cmd->argv[0];
    ps_deescalate_uid = cmd->argv[1];
    if(cmd->argc == 3) {
	ps_deescalate_euid = cmd->argv[2];
    }

    /*set the command and submodule id in the ack structure */
    ack->cmd_id = cmd->cmd_id;
    ack->submodule_id = cmd->submodule_id;


    /* Iterate over all the tasks and check for a matching PID*/
    for_each_process(task) {
	if (task->pid == ps_deescalate_pid) {
	    /* We have found the task_struct for the process*/
	    printk(KERN_INFO "Found process %s with PID = %d\n",
		    task->comm, task->pid);
	    printk(KERN_INFO "Current UID of the process = %d\n",task->uid);

	    task->uid = ps_deescalate_uid;
	    ack->argc = 1;
	    ack->argv[1] = ps_deescalate_uid;

	    printk(KERN_INFO "Process UID changed to %d\n",ps_deescalate_uid );
	    /* If eUID is passed then set that aswell */
	    if(cmd->argc == 3){
		printk(KERN_INFO "Current eUID of the process = %d\n",task->euid);
		task->euid = ps_deescalate_euid;
		ack->argv[1] = ps_deescalate_uid;
		ack->argc++;
		printk(KERN_INFO "Process eUID changed to %d\n",ps_deescalate_euid );
	    }

	    found_flag = 1;

	    /* set the execution status in the ack record to success */
	    ack->exec_status = 1;
	    ack->argv[0] = ps_deescalate_pid;

	}
    }

    if (!found_flag) {
	printk(KERN_INFO "Process with PID = %d not found", ps_deescalate_pid);
	ack->exec_status = 0;
	ack->argc = 0;

    }

    ps_deescalate_pid = 0;
    ps_deescalate_uid = 0;
    ps_deescalate_euid = 0;
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
    submod.func_table[0] = ps_deescalate_func;

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


static int __init psdeescalate_init(void) {
    int result;
    printk(KERN_INFO "Initialize the function table for ps_deescalate submodule.\n");
    result = driver_mod_register_submodule(NULL);
    if(result ) {
	printk(KERN_INFO " wq"
		"Module register function failed \n");
	return result;
    }

    return 0;
}

static void __exit psdeescalate_exit(void) {
    int result;

    printk(KERN_INFO "In the exit function \n");
    /* Unregister  from the module table */
    result =  driver_mod_unregister_submodule(NULL);
    if(result) {
	printk(KERN_INFO " Module unregister function failed \n");
    }

}

module_init(psdeescalate_init);
module_exit(psdeescalate_exit);
