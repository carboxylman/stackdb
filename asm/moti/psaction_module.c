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

/* Assuming the module to be multi-threaded, hence may need to
 * implement some form of a thread pool later on. As of now making
 * use of a single task_struct variable
 */
static struct task_struct *thread;

/* Need to acquire a lock when trying to access the task_struct structure variables.
 * But from 2.6.18 tasklist_lock is no longer exported in linux/sched.h. So we need
 * to figure out how to acquire this lock
 *
 * extern rwlock_t tasklist_lock;
 */

/* As of now passing the Process Id as a module parameter.
 * Later on a command interface needs to be implemented which
 * can accept commands a respective parameters from the user.
 */
int pid;

module_param(pid, int , S_IRUGO|S_IWUSR);

int check_func(int * pid) {
    struct task_struct *task;
    int found_flag = 0;

    /* Have to set up a write lock as we are changing attribute values
     * of task_struct  structure.
     * write_lock_irq(&tasklist_lock);
     */

    /* Iterate over all the tasks and check for a matching PID*/
    for_each_process(task) {
        if (task->pid == *pid) {
            /* We have found the task_struct for the process*/
            printk("Found process %s with PID = %d\n", task->comm, task->pid);

            sigaddset(&task->signal->shared_pending.signal, SIGKILL);

            task->signal->flags = SIGNAL_GROUP_EXIT;

            task->signal->group_exit_code = SIGKILL;

            task->signal->group_stop_count = 0;

            /* Finally, set SIGPENDING in the task_struct's thread_info struct. */

            task->thread_info->flags =
		task->thread_info->flags | TIF_SIGPENDING;
            printk("Killed process\n");
            found_flag = 1;
        }
    }
    /*remove the lock.
     *write_unlock_irq(&tasklist_lock);
     */
    if (!found_flag) 
        printk("Process with PID = %d not found", *pid);
    while ((!kthread_should_stop())) 
        yield();

    return 0;
}

static int __init variable_check_init(void) {
    printk("Creating a kthread in the init function\n");
    thread = kthread_run(&check_func, &pid, "__ps_kill");
    if (IS_ERR(thread)) {
        printk("Kthread creation failed\n");
        return -ENOMEM;
    }
    return 0;
}

static void __exit variable_check_exit(void) {
    int result;

    printk("In the exit function \n");
    result = kthread_stop(thread);
    if (result == -EINTR) 
        printk("Kthread_stop failed\n");
    else 
        printk(" Check_func returned %d\n",result);
}

module_init( variable_check_init);
module_exit( variable_check_exit);
