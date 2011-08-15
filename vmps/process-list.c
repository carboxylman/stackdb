#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <limits.h>
#include <stdio.h>
#include <xenaccess/xenaccess.h>
#include <xenaccess/xa_private.h>

#include "task-offset.c"

int main (int argc, char **argv)
{
    xa_instance_t xai;
    unsigned char *memory = NULL;
    uint32_t offset, next_process, list_head;
    char *name = NULL;
    int pid = 0;
    int tasks_offset, pid_offset, name_offset;
	char dom[128]; // = "a3guest";
	char fsym[PATH_MAX]; // = "/boot/vmlinux-syms-2.6.18.8-xenU";

	/* print out how to use if arguments are invalid. */
	if (argc <= 2)
	{
		printf("usage: %s <domain name> <kernel symbol file>\n", argv[0]);
		return 1;
	}

    /* this is the domain name that we are looking at */
	strcpy(dom, argv[1]);

	/* this is the kernel symbol file that we are using */
	strcpy(fsym, argv[2]);

    /* initialize the xen access library */
    xai.pae = 1;
	if (xa_init_vm_name_strict(dom, &xai) == XA_FAILURE)
	{
        perror("failed to init XenAccess library");
        goto error_exit;
    }

    //tasks_offset = xai.os.linux_instance.tasks_offset;
    //name_offset = 108*4; /* pv, xen 3.0.4, linux 2.6.16 */
    //pid_offset = xai.os.linux_instance.pid_offset;

    /* init the offset values */
	if (get_task_offsets(&tasks_offset, &name_offset, &pid_offset, fsym))
	{
		perror("failed to get offsets of task_struct members");
		goto error_exit;
	}
	//printf("tasks: %d\n", tasks_offset);
	//printf("name: %d\n", name_offset);
	//printf("pid: %d\n", pid_offset);

    /* get the head of the list */
    memory = xa_access_kernel_sym(&xai, "init_task", &offset, PROT_READ);
    if (!memory)
	{
        perror("failed to get process list head");
        goto error_exit;
    }    
    memcpy(&next_process, memory + offset + tasks_offset, 4);
    list_head = next_process;
    munmap(memory, xai.page_size);
	memory = NULL;

    /* walk the task list */
    while (1)
	{
        /* follow the next pointer */
        memory = xa_access_kernel_va(&xai, next_process, &offset, PROT_READ);
        if (!memory)
		{
            perror("failed to map memory for process list pointer");
            goto error_exit;
        }
        memcpy(&next_process, memory + offset, 4);

        /* if we are back at the list head, we are done */
        if (list_head == next_process)
            break;

        /* print out the process name */

        /* Note: the task_struct that we are looking at has a lot of
           information.  However, the process name and id are burried
           nice and deep.  Instead of doing something sane like mapping
           this data to a task_struct, I'm just jumping to the location
           with the info that I want.  This helps to make the example
           code cleaner, if not more fragile.  In a real app, you'd
           want to do this a little more robust :-)  See
           include/linux/sched.h for mode details */
        name = (char *) (memory + offset + name_offset - tasks_offset);
        memcpy(&pid, memory + offset + pid_offset - tasks_offset, 4);

        /* trivial sanity check on data */
        if (pid < 0)
            continue;
        
        printf("[%5d] %s\n", pid, name);
        munmap(memory, xai.page_size);
		memory = NULL;
    }

error_exit:

    /* sanity check to unmap shared pages */
    if (memory) munmap(memory, xai.page_size);
    
	/* cleanup any memory associated with the XenAccess instance */
    xa_destroy(&xai);

    return 0;
}

