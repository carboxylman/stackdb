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


int check_func(int * check_value)
{
	int i = 0;
	printk("kthread executing . . .\n");
	while((!kthread_should_stop()))
	{
		if(counter == *check_value)
		{
			printk("The counter has changed to the required value \n");
		}	
		else {
			printk("Calling yield \n");
			yield();
/*			if(result == -1)
			{
				printk("yield failed\n");
			}
*/
		}
	}
	return 0; 

}


static int __init variable_check_init(void)
{
	printk("Initializing the counter variable to 10 \n");
	counter = 10;
	printk("Creating a kthread in the init function\n");
	thread = kthread_run(&check_func, &check_value, "check_func_thread");
	if(IS_ERR(thread))
	{
		printk("Kthread_run error\n");
		return -ENOMEM;
	}
	printk("Thread created and running successfully\n");
	return 0;
}
static void __exit variable_check_exit(void)
{
	int result;
	printk("In the exit function, killing the kthread\n");
	 result = kthread_stop(thread);
	if(result == -EINTR)
	{
		printk("Kthread_stop failed\n");
	} else
	{
		printk(" check_func returned %d\n",result);
	}
}

module_init(variable_check_init);
module_exit(variable_check_exit);
