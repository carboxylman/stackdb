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

static int counter;
static int check_value;
static struct task_struct *thread;

module_param(check_value, int , S_IRUGO|S_IWUSR);

int check_func(int * check_value) {
    int i = 0;

    printk("kthread executing . . .\n");
    while ((!kthread_should_stop())) {
        if (counter == *check_value) {
            printk("The counter has changed to the required value \n");
        }
	else {
            printk("Calling yield \n");
            yield();
        }
    }
    return 0;

}

static int __init variable_check_init(void) {
    counter = 10;

    printk("Initializing the counter variable to 10 \n");
    printk("Creating a kthread in the init function\n");
    thread = kthread_run(&check_func, &check_value, "check_func_thread");
    if (IS_ERR(thread)) {
        printk("Kthread_run error\n");
        return -ENOMEM;
    }
    printk("Thread created and running successfully\n");
    return 0;
}
static void __exit variable_check_exit(void) {
    int result;

    printk("In the exit function, killing the kthread\n");
    result = kthread_stop(thread);
    if (result == -EINTR) {
        printk("Kthread_stop failed\n");
    }
    else {
        printk(" check_func returned %d\n",result);
    }
}

module_init( variable_check_init);
module_exit( variable_check_exit);
