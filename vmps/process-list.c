#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/mman.h>
#include <unistd.h>
#include <xenaccess/xenaccess.h>
#include <xenaccess/xa_private.h>
#include "process-list.h"
#include "offset.h"
#include "conf.h"
#include "list.h"
#include "report.h"

LIST_HEAD(process_list);
int process_count = 0;

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
    int i, opt_report = 0;
    struct process *p = NULL, *old_p = NULL;
    char *msg = NULL;

    /* print out how to use if arguments are invalid. */
    if (argc <= 1 || strcmp(argv[1], "--help") == 0)
    {
        printf("Usage: %s [OPTION] <DOMAIN NAME>\n", argv[0]);
        printf("  -r, --report     report process list to stats server\n");
        printf("  --help           display this help and exit\n");
        return 1;
    }

    if (getuid())
    {
        fprintf(stderr, "Must run as root\n");
        return 1;
    }
    
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--report") == 0)
        {
            opt_report = 1;
        }
        else if (argv[i][0] != '-')
        {
            /* this is the domain name that we are looking at */
            strcpy(domain, argv[i]);
        }
    }

	/* load the config file */
    if (conf_parse(CONF_FILE_NAME, conf_handler, NULL) < 0)
    {
        fprintf(stderr, "Failed to load '%s'\n", CONF_FILE_NAME);
        return 1;
    }

    /* initialize the xen access library */
    memset(&xai, 0, sizeof(xai));
    xai.os_type = XA_OS_LINUX;
    if (xa_init_vm_name_strict(domain, &xai) == XA_FAILURE)
    {
        fprintf(stderr, "Failed to init xa instance"
                " - Domain %s probably does not exist\n", domain);
        goto error_exit;
    }
    domid = xai.m.xen.domain_id;
    xc_handle = xai.m.xen.xc_handle;
    //printf("domain: %s (domid: %d)\n", domain, domid);
    //printf("report %s\n", (opt_report) ? "enabled" : "disabled");

    if (predict_ksyms(ksyms, xai.sysmap))
    {
        fprintf(stderr, "Failed to predict kernel symbol path\n");
        goto error_exit;
    }
    //printf("ksyms: %s\n", ksyms);

    /* init the offset values */
    if (get_task_offsets(&tasks_offset, &name_offset, &pid_offset, ksyms))
    {
        perror("Failed to get offsets of task_struct members");
        goto error_exit;
    }
    //printf("tasks offset: %d\n", tasks_offset);
    //printf("name offset: %d\n", name_offset);
    //printf("pid offset: %d\n", pid_offset);

    if (opt_report)
    {
        if (init_stats())
            goto error_exit;
    }

    xc_domain_pause(xc_handle, domid);

    /* get the head of the list */
    memory = xa_access_kernel_sym(&xai, "init_task", &offset, PROT_READ);
    if (!memory)
    {
        perror("Failed to get process list head");
        goto error_exit;
    }    
    memcpy(&next_process, memory + offset + tasks_offset, 4);
    list_head = next_process;
    munmap(memory, xai.page_size);
    memory = NULL;
    
    printf("%5s %s\n", "PID", "CMD");

    /* walk the task list */
    while (1)
    {
        /* follow the next pointer */
        memory = xa_access_kernel_va(&xai, next_process, &offset, PROT_READ);
        if (!memory)
        {
            perror("Failed to map memory for process list pointer");
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
        
        if (opt_report)
        {
            /* add process info to the linked list */
            p = (struct process *) malloc( sizeof(struct process) );
            if (!p)
            {
                perror("Failed to allocate memory for process info");
                goto error_exit;
            }
            p->pid = pid;
            strncpy(p->name, name, PROCESS_NAME_MAX);
            list_add_tail(&p->list, &process_list);
            process_count++;
        }

        /* print out the process info. */
        printf("%5d %s\n", pid, name);
        
        munmap(memory, xai.page_size);
        memory = NULL;
    }

    /* report all process info. to stats server */
    if (opt_report)
    {
        /* build a user message out of all process info. */
        msg = (char *) malloc ( process_count * (PROCESS_NAME_MAX+128) + 512 );
        if (!msg)
        {
            perror("Failed to allocate memory for user message");
            goto error_exit;
        }
        sprintf(msg, "%d%%20processes%%20found%%20in%%20%s:%%20", 
            process_count, domain);
        list_for_each_entry(p, &process_list, list)
        {
            sprintf(msg + strlen(msg), "%s(%d),%%20", p->name, p->pid);
        }
        msg[strlen(msg)-4] = '\0';

        /* report the message to stats server */
        if (report_event(msg))
        {
            fprintf(stderr, "Failed to report process list to stats server");
            goto error_exit;
        }
        printf("List reported to stats server\n"); 
    }

error_exit:

    if (opt_report)
    {
        /* delete the user mssage */
        if (msg) free(msg);

        /* delete all process info saved */
        list_for_each_entry(p, &process_list, list)
        {
            if (old_p) free(old_p);
            old_p = p;
        }
        if (old_p) free(old_p);
    }

    /* sanity check to unmap shared pages */
    if (memory) munmap(memory, xai.page_size);
    
    xc_domain_unpause(xc_handle, domid);
    
    /* cleanup any memory associated with the XenAccess instance */
    xa_destroy(&xai);

    return 0;
}

int conf_handler(void* user, 
                 const char* section, 
                 const char* name, 
                 const char* value)
{
#define MATCH(s, n) strcasecmp(section, s) == 0 && strcasecmp(name, n) == 0
    if (MATCH("report", "statsserver"))
        strncpy(opt_statsserver, value, 128);
    else if (MATCH("report", "querykey"))
        strncpy(opt_querykey, value, 256);

    return 0;
}

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

