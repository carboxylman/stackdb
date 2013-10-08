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
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/net.h>
#include <asm/thread_info.h>
#include <asm/signal.h>
#include <asm/siginfo.h>
#include <linux/slab.h>
#include "repair_driver.h"
#include <linux/version.h>

#define FUNCTION_COUNT 1
#define SUBMODULE_ID  3

extern struct submod_table submodule;
extern int ack_ready;
struct submodule submod;


static int killsocket_func(struct cmd_rec *cmd, struct ack_rec *ack) {
    struct task_struct *task;
    struct socket sock;
    struct files_struct *open_files;
    struct fdtable *files_table = NULL;
    int found_flag = 0;
    int target_pid = 0;
    int i = 0;
    int err;


    /* Parse the arguments passed */
    if(cmd->argc < 1 || cmd->argc > 1) {
	printk(KERN_INFO "killsocket module requires exactly 1 argument to be passed i.e, PID");
	return -EINVAL;
    }

    /* Extract the PID passed */
    target_pid = cmd->argv[0];
    /*set the command and submodule id in the ack structure */
    ack->cmd_id = cmd->cmd_id;
    ack->submodule_id = cmd->submodule_id;


    /* Iterate over all the tasks and check for a matching PID*/
    for_each_process(task) {
	if (task->pid == target_pid) {
	    /* We have found the task_struct for the process*/
	    printk(KERN_INFO "Found process %s with PID = %d\n",
		    task->comm, task->pid);
	    open_files = task->files;
	    files_table = files_fdtable(open_files);
            
	    /* Iterate through the entire array of
	     * open files and check if it id s socket
	     */
	    while(files_table->fd[i] != NULL) {
		if (S_ISSOCK(fd[i]->f_path.dentry->d_inode->i_mode)) {
		    printk(KERN_INFO " Found an open network socket.\n");
		    sock = (struct socket *) fd[i]->private_data;
		    err = security_socket_shutdown(sock, SHUT_RDWR);
		    if(!err) {
			err = sock->ops->shutdown(sock,SHUT_RDWR);
		    }
		    fput_light(sock->file, fput_needed);
		}
	    i++;
	    }
		      
	    found_flag = 1;
	    /* set the execution status in the ack record to success */
	    ack->exec_status = 1;
	    /* since the execution of the command does not return anything
	     * set acrg = 0;
	     */
	    ack->argc = 1;
	    ack->argv[0] = psaction_pid;
	}
    }

    if (!found_flag) {
	printk(KERN_INFO "Process with PID = %d not found", psaction_pid);
	ack->exec_status = 0;
	ack->argc = 0;

    }
    
    target_pid = 0;
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
    submod.func_table[0] = killsocket_func;

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


static int __init killsocket_init(void) {
    int result;
    printk(KERN_INFO "Initialize the function table for this submdule.\n");
    result = driver_mod_register_submodule(NULL);
    if(result ) {
	printk(KERN_INFO " Module register function failed \n");
	return result;
    }


    return 0;
}

static void __exit killsocket_exit(void) {
    int result;

    printk(KERN_INFO "In the exit function \n");
    /* Unregister  from the module table */
    result =  driver_mod_unregister_submodule(NULL);
    if(result) {
	printk(KERN_INFO " Module unregister function failed \n");
    }

}

module_init(killsocket_init);
module_exit(killsocket_exit);
