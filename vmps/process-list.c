#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/mman.h>
#include <unistd.h>
#include <xenaccess/xenaccess.h>
#include <xenaccess/xa_private.h>
#include "task-offset.h"

int predict_ksyms(char *ksyms, const char *sysmap)
{
    int len, i;

    /* replace 'System.map' with 'vmlinux-syms' */
    len = strlen(sysmap);
    memset(ksyms, 0, PATH_MAX);
    for (i = 0; i < len; i++)
    {
        if (strncmp(sysmap + i, "System.map-", 11) == 0)
        {
			strncat(ksyms, sysmap, i);
            strcat(ksyms, "vmlinux-syms-");
            strcat(ksyms, sysmap + i + 11);
            break;
        }
    }

    if (ksyms[0] == '\0' || access(ksyms, R_OK) != 0)
    {
        fprintf(stderr, "couldn't find kernel symbol file after checking %s\n",
            ksyms);
        return -1;
    }

    return 0;
}

int main (int argc, char **argv)
{
    xa_instance_t xai;
    unsigned char *memory = NULL;
    uint32_t offset, next_process, list_head;
    char *name = NULL;
    int pid = 0;
    int tasks_offset, pid_offset, name_offset;
    char domain[128];
    char ksyms[PATH_MAX];
	domid_t domid = 0;
	int xc_handle = -1;

    /* print out how to use if arguments are invalid. */
    if (argc <= 1)
    {
        printf("usage: %s <domain name>\n", argv[0]);
        return 1;
    }

    if (getuid())
    {
        fprintf(stderr, "need a root access\n");
        return 1;
    }

    /* this is the domain name that we are looking at */
    strcpy(domain, argv[1]);

    /* initialize the xen access library */
    memset(&xai, 0, sizeof(xai));
    xai.os_type = XA_OS_LINUX;
    if (xa_init_vm_name_strict(domain, &xai) == XA_FAILURE)
    {
        perror("failed to init xa instance");
        goto error_exit;
    }
	domid = xai.m.xen.domain_id;
	xc_handle = xai.m.xen.xc_handle;
    //printf("domain: %s (domid: %d)\n", domain, domid);

    if (predict_ksyms(ksyms, xai.sysmap))
    {
        fprintf(stderr, "failed to predict kernel symbol path\n");
        goto error_exit;
    }
    //printf("ksyms: %s\n", ksyms);

    /* init the offset values */
    if (get_task_offsets(&tasks_offset, &name_offset, &pid_offset, ksyms))
    {
        perror("failed to get offsets of task_struct members");
        goto error_exit;
    }
    //printf("tasks offset: %d\n", tasks_offset);
    //printf("name offset: %d\n", name_offset);
    //printf("pid offset: %d\n", pid_offset);

	xc_domain_pause(xc_handle, domid);

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
    
	xc_domain_unpause(xc_handle, domid);
	
    /* cleanup any memory associated with the XenAccess instance */
    xa_destroy(&xai);

    return 0;
}

