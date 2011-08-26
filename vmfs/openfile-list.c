#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/mman.h>
#include <unistd.h>
#include <xenaccess/xenaccess.h>
#include <xenaccess/xa_private.h>
#include "offset.h"

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

int fill_parent_dir(char *buf, 
                    uint32_t d_parent, 
                    uint32_t d_parent_offset,
                    uint32_t d_name_offset,
                    uint32_t qlen_offset,
                    uint32_t qname_offset,
                    xa_instance_t *xai)
{
    unsigned char *dentry = NULL;
    char *dname = NULL;
    uint32_t offset = 0;
    uint32_t len, name;
    uint32_t d_old_parent;
    int ret = 0;

    if (d_parent == 0)
        return 0;

    dentry = xa_access_kernel_va(xai, d_parent, &offset, PROT_READ);
    if (!dentry)
    {
        perror("failed to map memory for parent dentry");
        return -1;
    }
    d_old_parent = d_parent;
    memcpy(&d_parent, dentry + offset + d_parent_offset, 4);
    memcpy(&len, dentry + offset + d_name_offset + qlen_offset, 4);
    memcpy(&name, dentry + offset + d_name_offset + qname_offset, 4);

    dname = xa_access_kernel_va(xai, name, &offset, PROT_READ);
    if (!dname)
    {
        munmap(dentry, xai->page_size);
        perror("failed to map memory for parent name");
        return -1;
    }

    if (d_old_parent != d_parent)
    {
        ret = fill_parent_dir(buf, d_parent, d_parent_offset, d_name_offset,
            qlen_offset, qname_offset, xai);
    }
    
    memcpy(buf + ret, dname + offset, len);
    ret += len;
    if (buf[ret-1] != '/' && buf[ret-1] != ':')
    {
        buf[ret] = '/';
        ret++;
    }

    munmap(dentry, xai->page_size);
    munmap(dname, xai->page_size);
    dentry = NULL;
    dname = NULL;

    return ret;
}

int main (int argc, char **argv)
{
    xa_instance_t xai;
    unsigned char *task_struct = NULL;
    unsigned char *files_struct = NULL;
    unsigned char *fdtable = NULL;
    uint32_t *fd_list = NULL;
    unsigned char *file = NULL;
    unsigned char *dentry = NULL;
    unsigned char *vfsmount = NULL;
    uint32_t offset, next_process, list_head;
    uint32_t files, fdt, max_fds, fd, f_dentry, f_vfsmnt;
    uint32_t d_parent, mnt_devname, qlen, qname;
    int doffset, pid = 0;
    char *name = NULL;
    char *dname = NULL;
    char *vname = NULL;
    char dname_buf[PATH_MAX];
    int tasks_offset, pid_offset, name_offset;
    int files_offset, fdt_offset, max_fds_offset, fd_offset;
    int f_dentry_offset, f_vfsmnt_offset, d_parent_offset, d_name_offset;
    int mnt_devname_offset, qlen_offset, qname_offset;
    char domain[128];
    char ksyms[PATH_MAX];
    domid_t domid = 0;
    int xc_handle = -1;
    int i;

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
    if (get_task_offsets(&tasks_offset, 
                         &name_offset, 
                         &pid_offset, 
                         &files_offset,
                         ksyms))
    {
        perror("failed to get offsets of task_struct members");
        goto error_exit;
    }
    //printf("tasks offset: %d\n", tasks_offset);
    //printf("name offset: %d\n", name_offset);
    //printf("pid offset: %d\n", pid_offset);
    //printf("files offset: %d\n", files_offset);

    if (get_files_offsets(&fdt_offset, ksyms))
    {
        perror("failed to get offsets of file_struct members");
        goto error_exit;
    }
    //printf("files->fdt offset: %d\n", fdt_offset);

    if (get_fdt_offsets(&max_fds_offset, &fd_offset, ksyms))
    {
        perror("failed to get offsets of fdtable members");
        goto error_exit;
    }
    //printf("files->fdt->max_fds offset: %d\n", max_fds_offset);
    //printf("files->fdt->fd offset: %d\n", fd_offset);

    if (get_fd_offsets(&f_dentry_offset, &f_vfsmnt_offset, ksyms))
    {
        perror("failed to get offsets of file members");
        goto error_exit;
    }
    //printf("files->fdt->fd->f_dentry offset: %d\n", f_dentry_offset);
    //printf("files->fdt->fd->f_vfsmnt offset: %d\n", f_vfsmnt_offset);

    if (get_dentry_offsets(&d_parent_offset, &d_name_offset, ksyms))
    {
        perror("failed to get offsets of dentry members");
        goto error_exit;
    }
    //printf("files->fdt->fd->f_dentry->d_parent offset: %d\n", d_parent_offset);
    //printf("files->fdt->fd->f_dentry->d_name offset: %d\n", d_name_offset);

    if (get_vfsmnt_offsets(&mnt_devname_offset, ksyms))
    {
        perror("failed to get offsets of vfsmount members");
        goto error_exit;
    }
    //printf("files->fdt->fd->f_vfsmnt->mnt_devname offset: %d\n", 
    //    mnt_devname_offset);

    if (get_qstr_offsets(&qlen_offset, &qname_offset, ksyms))
    if (get_qstr_offsets(&qlen_offset, &qname_offset, ksyms))
    {
        perror("failed to get offsets of qstr members");
        goto error_exit;
    }
    //printf("files->fdt->fd->f_dentry->d_name->len offset: %d\n", qlen_offset);
    //printf("files->fdt->fd->f_dentry->d_name->name offset: %d\n", qname_offset);

    xc_domain_pause(xc_handle, domid);

    /* get the head of the list */
    task_struct = xa_access_kernel_sym(&xai, "init_task", &offset, PROT_READ);
    if (!task_struct)
    {
        perror("failed to get process list head");
        goto error_exit;
    }    
    memcpy(&next_process, task_struct + offset + tasks_offset, 4);
    list_head = next_process;
    munmap(task_struct, xai.page_size);
    task_struct = NULL;

    printf("%5s %-16s %-4s %s\n", "PID", "CMD", "FD", "FILE");
    /* walk the task list */
    while (1)
    {
        /* follow the next pointer */
        task_struct = xa_access_kernel_va(&xai, next_process, &offset, 
            PROT_READ);
        if (!task_struct)
        {
            perror("failed to map memory for task_struct");
            goto error_exit;
        }
        memcpy(&next_process, task_struct + offset, 4);

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
        name = (char *) (task_struct + offset + name_offset - tasks_offset);
        memcpy(&pid, task_struct + offset + pid_offset - tasks_offset, 4);
        memcpy(&files, task_struct + offset + files_offset - tasks_offset, 4);

        /* trivial sanity check on data */
        if (pid < 0)
            continue;
        
        files_struct = xa_access_kernel_va(&xai, files, &offset, PROT_READ);
        if (!files_struct)
        {
            perror("failed to map memory for files_struct");
            goto error_exit;
        }
        memcpy(&fdt, files_struct + offset + fdt_offset, 4);

        fdtable = xa_access_kernel_va(&xai, fdt, &offset, PROT_READ);
        if (!fdtable)
        {
            perror("failed to map memory for fdtable");
            goto error_exit;
        }
        memcpy(&max_fds, fdtable + offset + max_fds_offset, 4);
        memcpy(&fd, fdtable + offset + fd_offset, 4);
        
        fd_list = xa_access_kernel_va(&xai, fd, &offset, PROT_READ);
        if (!fd_list)
        {
            perror("failed to map memory for fd_list");
            goto error_exit;
        }
        fd_list = (uint32_t *)(((char *)fd_list) + offset);

        for (i = 0; i < max_fds; i++)
        {
            if (fd_list[i])
            {
                file = xa_access_kernel_va(&xai, fd_list[i], &offset, 
                        PROT_READ);
                if (!file)
                {
                    perror("failed to map memory for file");
                    goto error_exit;
                }
                memcpy(&f_dentry, file + offset + f_dentry_offset, 4);
                memcpy(&f_vfsmnt, file + offset + f_vfsmnt_offset, 4);

                vfsmount = xa_access_kernel_va(&xai, f_vfsmnt, &offset,
                    PROT_READ);
                if (!vfsmount)
                {
                    perror("failed to mape memory for vfsmount");
                    goto error_exit;
                }
                memcpy(&mnt_devname, vfsmount + offset + mnt_devname_offset, 4);

                vname = xa_access_kernel_va(&xai, mnt_devname, &offset, 
                    PROT_READ);
                if (!vname)
                {
                    perror("failed to map memory for device name");
                    goto error_exit;
                }
                vname += offset;
                if (strcmp(vname, "devpts") == 0)
                    vname = "/dev/pts";
                else if (vname[0] != '/' || strcmp(vname, "/dev/root") == 0)
                    vname = "";

                dentry = xa_access_kernel_va(&xai, f_dentry, &offset, 
                    PROT_READ);
                if (!dentry)
                {
                    perror("failed to map memory for dentry");
                    goto error_exit;
                }
                memcpy(&d_parent, dentry + offset + d_parent_offset, 4);
                memcpy(&qlen, dentry + offset + d_name_offset + qlen_offset, 
                    4);
                memcpy(&qname, dentry + offset + d_name_offset + qname_offset,
                    4);

                dname = xa_access_kernel_va(&xai, qname, &offset, PROT_READ);
                if (!dname)
                {
                    perror("failed to map memory for dentry name");
                    goto error_exit;
                }
                memset(dname_buf, 0, PATH_MAX);
                doffset = 0;
                if (f_dentry != d_parent)
                {
                    doffset = fill_parent_dir(dname_buf, d_parent, 
                        d_parent_offset, d_name_offset, qlen_offset, 
                        qname_offset, &xai);
                    if (doffset < 0)
                        goto error_exit;
                }
                memcpy(dname_buf + doffset, dname + offset, qlen);

                /* print the data obtained */
                printf("%5d %-16s %-4d %s%s\n", pid, name, i, vname, dname_buf);

                munmap(file, xai.page_size);
                munmap(vfsmount, xai.page_size);
                munmap(dentry, xai.page_size);
                munmap(dname, xai.page_size);
                file = NULL;
                vfsmount = NULL;
                dentry = NULL;
                dname = NULL;
            }
        }

        munmap(task_struct, xai.page_size);
        munmap(files_struct, xai.page_size);
        munmap(fdtable, xai.page_size);
        munmap(fd_list, xai.page_size);
        task_struct = NULL;
        files_struct = NULL;
        fdtable = NULL;
        dentry = NULL;
    }

error_exit:
    /* sanity check to unmap shared pages */
    if (task_struct) munmap(task_struct, xai.page_size);
    if (files_struct) munmap(files_struct, xai.page_size);
    if (fdtable) munmap(fdtable, xai.page_size);
    if (fd_list) munmap(fd_list, xai.page_size);
    if (file) munmap(file, xai.page_size);
    if (vfsmount) munmap(vfsmount, xai.page_size);
    if (dentry) munmap(dentry, xai.page_size);
    if (dname) munmap(dname, xai.page_size);

    xc_domain_unpause(xc_handle, domid);
    
    /* cleanup any memory associated with the XenAccess instance */
    xa_destroy(&xai);

    return 0;
}

