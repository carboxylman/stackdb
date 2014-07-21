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
#include <linux/fdtable.h>
#include <linux/kthread.h>
#include <linux/sched.h> 
#include <asm/thread_info.h>
#include <asm/signal.h>
#include <asm/siginfo.h>
#include <linux/slab.h>
#include "repair_driver.h"
#include <linux/version.h>
#include <linux/rcupdate.h>

#define FUNCTION_COUNT 1
#define SUBMODULE_ID  5

extern struct submod_table submodule;
extern int ack_ready;
struct submodule submod;


static int file_close( const void *v, struct file *file, unsigned int n) {

    char *file_name = NULL;
    char *name = (char *) v;

    /* get the file name from the file struct */
    file_name = (char *)file->f_path.dentry->d_name.name;
   
    if( !strcmp(file_name, name)) {
	printk(KERN_INFO "INFO: Found open file %s.\n",name);
	filp_close(file, NULL);
	printk(KERN_INFO " Closed the open file\n");
	return n;
    }
    return 0;
}


static int close_file_func(struct cmd_rec *cmd, struct ack_rec *ack) {

    struct task_struct *task;
    int length = 0;
    char *char_ptr = NULL;
    int pid;
    char * file_name;
    int ret = 0, res = 0;
    struct fdtable *fdt;



    printk(KERN_INFO " Number of arguments passed is %d\n",cmd->argc);
    char_ptr = (char *)cmd->argv;
    
    /* read the arguments passed */
    pid = *(int *)char_ptr;
    //printk(KERN_INFO "PID passed is %d\n",pid);
    char_ptr = char_ptr + sizeof(int);

    length = *(int *)char_ptr;
    //printk(KERN_INFO "length %d\n",length);
    char_ptr = char_ptr + sizeof(int);	
    file_name = kmalloc((length * sizeof(char)) , GFP_KERNEL);
    memcpy((void *)file_name, (void *)char_ptr, length);
    //printk(KERN_INFO "INFO: File name = %s\n",file_name);
    char_ptr = char_ptr + length;
    

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
	    res = iterate_fd(task->files, 0, file_close, (void *)file_name);
	    if(res) {

		fdt = files_fdtable(task->files);
		rcu_assign_pointer(fdt->fd[res], NULL);

	    }
	    break;
	}
	//printk(KERN_INFO "Process with pid = %d not found.\n",pid);
    }

    kfree(file_name);
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
    submod.func_table[0] = close_file_func;

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


static int __init close_file_init(void) {
    int result;
    printk(KERN_INFO "Initialize the function table for start_process submdule.\n");
    result = driver_mod_register_submodule(NULL);
    if(result ) {
	printk(KERN_INFO " Module register function failed \n");
	return result;
    }
    return 0;
}

static void __exit close_file_exit(void) {
    int result;

    printk(KERN_INFO "In the exit function \n");
    /* Unregister  from the module table */
    result =  driver_mod_unregister_submodule(NULL);
    if(result) {
	printk(KERN_INFO " Module unregister function failed \n");
    }
}

module_init(close_file_init);
module_exit(close_file_exit);
