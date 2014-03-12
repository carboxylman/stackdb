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
#include <linux/version.h>
#include <linux/cred.h>
#include "repair_driver.h"

#define FUNCTION_COUNT 1
#define SUBMODULE_ID  1

extern struct submod_table submodule;
extern int ack_ready;
struct submodule submod;


static int ps_setuid_func(struct cmd_rec *cmd, struct ack_rec *ack) {
    struct task_struct *task;
    int found_flag = 0;
    int ps_deescalate_pid = 0;
    int ps_deescalate_uid = 0;
    int ps_deescalate_gid = 0;
    int *int_ptr = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
    struct cred * nonconst_cred;
    const struct cred *const_cred;
#endif


    /* Parse the arguments passed */
    if(cmd->argc != 3) {
	printk(KERN_INFO "set_real_id requires  3 arguments to be passed i.e, PID, UID and GID");
	return -EINVAL;
    }

    /* Extract the PID and the UID passed */
    int_ptr = (int *)cmd->argv;
    ps_deescalate_pid = *int_ptr;
    int_ptr++;
    ps_deescalate_uid = *int_ptr;;
    int_ptr++;
    ps_deescalate_gid = *int_ptr;


    /*set the command and submodule id in the ack structure */
    ack->cmd_id = cmd->cmd_id;
    ack->submodule_id = cmd->submodule_id;


    /* Iterate over all the tasks and check for a matching PID*/
    for_each_process(task) {
	if (task->pid == ps_deescalate_pid) {
	    /* We have found the task_struct for the process*/
	    printk(KERN_INFO "Found process %s with PID = %d\n",
		    task->comm, task->pid);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,21)
	    printk(KERN_INFO "Current real UID of the process = %d\n",task->uid);
	    printk(KERN_INFO "Current real GID of the process = %d\n",task->gid);

	    task->uid = ps_deescalate_uid;
	    task->gid = ps_deescalate_gid
	    ack->argc = 2;
	    ack->argv[1] = ps_deescalate_uid;
	    ack->argv[2] = ps_deescalate_gid;

	    printk(KERN_INFO "Process UID and GID changed to %d and %d\n",
		    ps_deescalate_uid, ps_deescalate_gid);

	    found_flag = 1;
#else
	    /* for objective and real subjective task credentials */
	    nonconst_cred = get_cred(task->real_cred);
	    printk(KERN_INFO "Current real UID of the process = %d\n", nonconst_cred->uid);
	    printk(KERN_INFO "Current real GID of the process = %d\n", nonconst_cred->gid);
	    printk(KERN_INFO "Current effective UID of the process = %d\n", nonconst_cred->euid);
	    printk(KERN_INFO "Current effective GID of the process = %d\n", nonconst_cred->egid);

	    nonconst_cred->uid = ps_deescalate_uid;
	    nonconst_cred->gid = ps_deescalate_gid;
	    nonconst_cred->euid = ps_deescalate_uid;
	    nonconst_cred->egid = ps_deescalate_gid;

	    printk(KERN_INFO "Changed real UID of the process = %d\n",nonconst_cred->uid);
	    printk(KERN_INFO "Changed real GID of the process = %d\n",nonconst_cred->gid);
	    printk(KERN_INFO "Changed effective UID of the process = %d\n",nonconst_cred->euid);
	    printk(KERN_INFO "Changed effective GID of the process = %d\n",nonconst_cred->egid);
	    
	    put_cred(task->real_cred);

	    /* for effective subjective task credentials */
	    nonconst_cred = get_cred(task->cred);
	    printk(KERN_INFO "Current real UID of the process = %d\n", nonconst_cred->uid);
	    printk(KERN_INFO "Current real GID of the process = %d\n", nonconst_cred->gid);
	    printk(KERN_INFO "Current effective UID of the process = %d\n", nonconst_cred->euid);
	    printk(KERN_INFO "Current effective GID of the process = %d\n", nonconst_cred->egid);

	    nonconst_cred->uid = ps_deescalate_uid;
	    nonconst_cred->gid = ps_deescalate_gid;
	    nonconst_cred->euid = ps_deescalate_uid;
	    nonconst_cred->egid = ps_deescalate_gid;
 
	    printk(KERN_INFO "Changed real UID of the process = %d\n",nonconst_cred->uid);
	    printk(KERN_INFO "Changed real GID of the process = %d\n",nonconst_cred->gid);
	    printk(KERN_INFO "Changed effective UID of the process = %d\n",nonconst_cred->euid);
	    printk(KERN_INFO "Changed effective GID of the process = %d\n",nonconst_cred->egid);
	    
	    put_cred(task->cred);


	    found_flag = 1;
#endif
	    /* set the execution status in the ack record to success */
	    //ack->exec_status = 1;
	    ack->argv[0] = ps_deescalate_pid;

	}
    }

    if (!found_flag) {
	printk(KERN_INFO "Process with PID = %d not found", ps_deescalate_pid);
	//ack->exec_status = 0;
	ack->argc = 0;

    }

    ps_deescalate_pid = 0;
    ps_deescalate_uid = 0;
    ps_deescalate_gid = 0;
    /* Set flag to indicate the result is ready */
    ack_ready++;
    return 0;
}


static int ps_seteid_func(struct cmd_rec *cmd, struct ack_rec *ack) {
    struct task_struct *task;
    int found_flag = 0;
    int ps_deescalate_pid = 0;
    int ps_deescalate_euid = 0;
    int ps_deescalate_egid = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
    struct cred * nonconst_cred;
#endif



    /* Parse the arguments passed */
    if(cmd->argc != 3) {
	printk(KERN_INFO "set_effective_id requires  3 arguments to be passed i.e, PID, eUID and eGID");
	return -EINVAL;
    }

    /* Extract the PID and the UID passed */
    ps_deescalate_pid = cmd->argv[0];
    ps_deescalate_euid = cmd->argv[1];
    ps_deescalate_egid = cmd->argv[2];


    /*set the command and submodule id in the ack structure */
    ack->cmd_id = cmd->cmd_id;
    ack->submodule_id = cmd->submodule_id;


    /* Iterate over all the tasks and check for a matching PID*/
    for_each_process(task) {
	if (task->pid == ps_deescalate_pid) {
	    /* We have found the task_struct for the process*/
	    printk(KERN_INFO "Found process %s with PID = %d\n",
		    task->comm, task->pid);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,21)
	    printk(KERN_INFO "Current eUID of the process = %d\n",task->euid);
	    printk(KERN_INFO "Current eGID of the process = %d\n",task->egid);


	    task->euid = ps_deescalate_euid;
	    task->egid = ps_deescalate_egid
	    ack->argc = 2;
	    ack->argv[1] = ps_deescalate_euid;
	    ack->argv[2] = ps_deescalate_egid;

	    printk(KERN_INFO "Process eUID and eGID changed to %d and %d\n",
		    ps_deescalate_euid, ps_deescalate_egid);

	    found_flag = 1;
#else
	    printk(KERN_INFO "Current real eUID of the process = %d\n",task->cred->euid);
	    printk(KERN_INFO "Current real GID of the process = %d\n",task->cred->egid);

	    /* typecase the constant structure to a non constant type */
	    nonconst_cred = (struct cred *) task->cred;
	    nonconst_cred->euid = ps_deescalate_euid;
	    nonconst_cred->egid = ps_deescalate_egid;
	    
	    task->cred = (const struct cred *) nonconst_cred;
 
	    printk(KERN_INFO "Changed real UID of the process = %d\n",task->cred->euid);
	    printk(KERN_INFO "Changed real GID of the process = %d\n",task->cred->egid);

	    found_flag = 1;
#endif
	    /* set the execution status in the ack record to success */
	    //ack->exec_status = 1;
	    ack->argv[0] = ps_deescalate_pid;

	}
    }

    if (!found_flag) {
	printk(KERN_INFO "Process with PID = %d not found", ps_deescalate_pid);
	//ack->exec_status = 0;
	ack->argc = 0;

    }

    ps_deescalate_pid = 0;
    ps_deescalate_euid = 0;
    ps_deescalate_egid = 0;
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
    submod.func_table[0] = ps_setuid_func;
    submod.func_table[1] = ps_seteid_func;

    /* register the submodule table maintained in the repair driver */
    submodule.mod_table[submod.submodule_id] = &submod;

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


static int __init psdeescalate_init(void) {
    int result;
    printk(KERN_INFO "Initialize the function table for ps_deescalate submodule.\n");
    result = driver_mod_register_submodule(NULL);
    if(result ) {
	printk(KERN_INFO "Module register function failed \n");
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
