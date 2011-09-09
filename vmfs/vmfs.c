#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>

#include <xenaccess/xenaccess.h>
#include <xenaccess/xa_private.h>

#include "vmfs.h"
#include "list.h"
#include "config.h"
#include "offset.h"
#include "web.h"
#include "log.h"

#define PNAME_MAX (128)
#define DNAME_MAX (128)

/* process info */
struct proc {
    struct list_head list;
    int pid;
    char name[PNAME_MAX+1];
    struct list_head files;
    int file_count;
};

/* open file info */
struct openfile {
    struct list_head list;
    struct list_head node;
    int fd;
    char dev[DNAME_MAX+1];
    char name[PATH_MAX+1];
};

LIST_HEAD(proc_list);
int proc_count;

LIST_HEAD(file_list);
int file_count;
int fd_count;

char domain[128];
domid_t domid;
xa_instance_t xa;
int xc_handle = -1;
char debuginfo[PATH_MAX+1];
int interval;
struct timeval now;
int the_pid;
char the_cmd[CMD_WIDTH+1];

int off_tasks, off_pid, off_name, off_files;
int off_fdt;
int off_max_fds, off_fd;
int off_f_dentry, off_f_vfsmnt;
int off_d_parent, off_d_name;
int off_mnt_devname;
int off_qstr_len, off_qstr_name;

int opt_daemon;
int opt_log, opt_web, opt_console = 1; /* console on by default */
int opt_pid, opt_cmd;

static void print_usage(const char *exec);
static void get_options(int argc, char *argv[]);
static void signal_interrupt(void);
static int load_config(const char *config);
static int init_xa(xa_instance_t *xa, const char *domain);
static int predict_debuginfo(char *debuginfo, const char *sysmap);
static int find_offsets(void);
static int walk_task_list(void);
static int walk_file_list(struct proc *p, uint32_t files);
static int walk_fd_list(struct proc *p, uint32_t *fd_list, uint32_t max_fds);
static int fill_parent_dir(char *path, uint32_t parent);
static int report_file_list(void);

int main (int argc, char *argv[])
{
    if (getuid() != 0)
    {
        fprintf(stderr, "Must run as root\n");
        return 1;
    }
    
    if (argc <= 1) 
        print_usage(argv[0]);

    get_options(argc, argv);

    if (load_config(CONFIG_FILE))
        return 1;

    if (opt_daemon)
    {
        signal_interrupt();
        printf("Run in daemon mode at %d sec interval\n", interval);
    }

    /* initialize reporting targets */
    if (opt_log)
        if (log_init()) goto error_exit;
    if (opt_web)
        if (web_init()) goto error_exit;

    if (init_xa(&xa, domain))
        return 1;

    /* do not predict debuginfo path if it is specified in config */
    if (predict_debuginfo(debuginfo, xa.sysmap))
        goto error_exit;

    /* obtain the offsets of task_struct members 
       NOTE: this takes the longest time due to inefficient DWARF reading */
    printf("Loading kernel debug-info (be patient, it may take a while)\n");
    if (find_offsets())
        goto error_exit;

    /* list all tasks repeatedly with a time interval */
    do {
        gettimeofday(&now, NULL);
        if (walk_task_list()) return 1;
        sleep(interval);
    } while (opt_daemon);

error_exit:
    xa_destroy(&xa);
    log_cleanup();

    return 0;
}

static 
void print_usage(const char *exec)
{
    printf("Usage: %s [OPTION] <DOMAIN NAME>\n", exec);
    printf("options:\n");
    printf("  -d, --daemon <sec>   run in daemon mode with time interval sec\n");
    printf("  -c, --console        report open file list(s) to console (default)\n");
    printf("  -w, --web            report open file list(s) to stats web server\n");
    printf("  -l, --log            report open file list(s) to log file\n");
    printf("  -p, --pid <pid>      exclude(^)|select pid\n");
    printf("  -n, --cmd <cmd>      exclude(^)|select cmd (compare width: %d)\n", 
        CMD_WIDTH);
    printf("  -h, --help           display this help and exit\n");
    exit(1);
}

static 
void get_options(int argc, char *argv[])
{
    int i, tmp_console = 0;

    for (i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-d") == 0 || 
             strcmp(argv[i], "--daemon") == 0) &&
            (i+1) < argc)
        {
            opt_daemon = 1;
            interval = atoi(argv[++i]);
            if (interval == 0)
                print_usage(argv[0]);
        }
        else if (strcmp(argv[i], "-c") == 0 || 
                 strcmp(argv[i], "--console") == 0)
        {
            tmp_console = 1;
        }
        else if (strcmp(argv[i], "-w") == 0 || 
                 strcmp(argv[i], "--web") == 0)
        {
            opt_web = 1;
        }
        else if (strcmp(argv[i], "-l") == 0 || 
                 strcmp(argv[i], "--log") == 0)
        {
            opt_log = 1;
        }
        else if ((strcmp(argv[i], "-p") == 0 || 
                  strcmp(argv[i], "--pid") == 0) &&
                 (i+1) < argc)
        {
            opt_pid = 1;
            the_pid = atoi(argv[++i]);
            if (the_pid == 0)
                print_usage(argv[0]);
        }
        else if ((strcmp(argv[i], "-n") == 0 || 
                  strcmp(argv[i], "--cmd") == 0) &&
                 (i+1) < argc)
        {
            opt_cmd = 1;
            strncpy(the_cmd, argv[++i], CMD_WIDTH);
        }
        else if (strcmp(argv[i], "-h") == 0 ||
                 strcmp(argv[i], "--help") == 0)
        {
            print_usage(argv[0]);
        }
        else if (argv[i][0] != '-')
        {
            /* this is the domain name that we are looking at */
            strcpy(domain, argv[i]);
        }
        else
        { 
            print_usage(argv[0]);
        }
    }

    /* do not report to console unless it's explicitly specified when 
       we are reporting to web server or log file */
    if ((opt_web || opt_log) && !tmp_console)
        opt_console = 0;
}

static inline 
int config_handler(void* user, 
                   const char* section, 
                   const char* name, 
                   const char* value)
{
#define MATCH(s, n) strcasecmp(section, s) == 0 && strcasecmp(name, n) == 0
    if (MATCH("offset", "sysmap"))
        strncpy(conf_sysmap, value, PATH_MAX);
    else if (MATCH("offset", "debuginfo"))
        strncpy(conf_debuginfo, value, PATH_MAX);
    else if (MATCH("web", "statsserver"))
        strncpy(conf_statsserver, value, STATS_MAX);
    else if (MATCH("web", "querykey"))
        strncpy(conf_querykey, value, QUERY_MAX);
    else if (MATCH("log", "logfile"))
        strncpy(conf_logfile, value, PATH_MAX);
    return 0;
}

static
int load_config(const char *config)
{
    if (config_parse(config, config_handler, NULL) < 0)
    {
        fprintf(stderr, "Failed to load '%s'\n", config);
        return -1;
    }
    return 0;
}

static
int init_xa(xa_instance_t *xa, const char *domain)
{
    memset(xa, 0, sizeof(*xa));
    xa->os_type = XA_OS_LINUX; /* currently support linux only */
    if (strlen(conf_sysmap) > 0)
        xa->sysmap = conf_sysmap; /* use the sysmap file specified in config */
    if (xa_init_vm_name_strict((char *)domain, xa) == XA_FAILURE)
    {
        fprintf(stderr, "Failed to init xa instance"
                " - Domain %s probably does not exist\n", domain);
        return -1;
    }
    xc_handle = xa->m.xen.xc_handle;
    domid = xa->m.xen.domain_id;
    return 0;
}

static
int predict_debuginfo(char *debuginfo, const char *sysmap)
{
    int i, len;

    /* do not predict debuginfo path if it is specified in config */
    if (strlen(conf_debuginfo) > 0)
    {
        strncpy(debuginfo, conf_debuginfo, PATH_MAX);
        return 0;
    }

    /* replace 'System.map' with 'vmlinux-syms' */
    debuginfo[0] = '\0';
    len = strlen(sysmap);
    for (i = 0; i < len; i++)
    {
        if (strncmp(sysmap + i, "System.map-", 11) == 0)
        {
            strncat(debuginfo, sysmap, i);
            strcat(debuginfo, "vmlinux-syms-");
            strcat(debuginfo, sysmap + i + 11);
            break;
        }
    }

    if (strlen(debuginfo) == 0 || access(debuginfo, R_OK) != 0)
    {
        fprintf(stderr, "Couldn't find kernel symbol file after checking %s\n",
            debuginfo);
        return -1;
    }

    return 0;
}

static
int find_offsets(void)
{
    if (offset_task_struct(&off_tasks, 
                           &off_name, 
                           &off_pid, 
                           &off_files, 
                           debuginfo))
    {
        perror("Failed to find offsets of task_struct members");
        return -1;
    }

    if (offset_files_struct(&off_fdt, debuginfo))
    {
        perror("Failed to find offsets of file_struct members");
        return -1;
    }

    if (offset_fdtable(&off_max_fds, &off_fd, debuginfo))
    {
        perror("Failed to find offsets of fdtable members");
        return -1;
    }

    if (offset_file(&off_f_dentry, &off_f_vfsmnt, debuginfo))
    {
        perror("Failed to find offsets of file members");
        return -1;
    }

    if (offset_dentry(&off_d_parent, &off_d_name, debuginfo))
    {
        perror("Failed to find offsets of dentry members");
        return -1;
    }

    if (offset_vfsmount(&off_mnt_devname, debuginfo))
    {
        perror("Failed to find offsets of vfsmount members");
        return -1;
    }

    if (offset_qstr(&off_qstr_len, &off_qstr_name, debuginfo))
    {
        perror("Failed to find offsets of qstr members");
        return -1;
    }

    return 0;
}

static 
int walk_task_list(void)
{
    unsigned char *task_struct = NULL;
    uint32_t offset, next_proc, list_head;
    struct proc *p = NULL, *old_p = NULL;
    struct openfile *f = NULL, *old_f = NULL;
    char *name = NULL;
    int pid = 0;
    uint32_t files;
    int ret = -1;

    /* get the head of the list */
    task_struct = xa_access_kernel_sym(&xa, "init_task", &offset, PROT_READ);
    if (!task_struct)
    {
        perror("Failed to get process list head");
        return -1;
    }    
    memcpy(&next_proc, task_struct + offset + off_tasks, 4);
    list_head = next_proc;
    munmap(task_struct, xa.page_size);
    task_struct = NULL;
    
    xc_domain_pause(xc_handle, domid);

    /* walk the task list */
    while (1)
    {
        /* follow the next pointer */
        task_struct = xa_access_kernel_va(&xa, next_proc, &offset, PROT_READ);
        if (!task_struct)
        {
            perror("Failed to map memory for task_struct");
            goto error_exit;
        }
        memcpy(&next_proc, task_struct + offset, 4);

        /* if we are back at the list head, we are done */
        if (list_head == next_proc)
            break;

        name = (char *) (task_struct + offset + off_name - off_tasks);
        memcpy(&pid, task_struct + offset + off_pid - off_tasks, 4);

        /* trivial sanity check on data */
        if (pid < 0)
            continue;
        
        if ((opt_pid && pid == the_pid) ||
            (opt_cmd && strncmp(name, the_cmd, CMD_WIDTH) == 0) ||
            (!opt_pid && !opt_cmd))
        {
            memcpy(&files, task_struct + offset + off_files - off_tasks, 4);
            
            /* add obtained process info to the linked list */
            p = (struct proc *) malloc( sizeof(struct proc) );
            if (!p)
            {
                perror("Failed to allocate memory for process info");
                goto error_exit;
            }
            p->pid = pid;
            strncpy(p->name, name, PNAME_MAX);
            INIT_LIST_HEAD(&p->files);
            p->file_count = 0;
            list_add_tail(&p->list, &proc_list);
            proc_count++;

            if (walk_file_list(p, files))
                goto error_exit;
        }

        munmap(task_struct, xa.page_size);
        task_struct = NULL;
    }

    xc_domain_unpause(xc_handle, domid);
    
    /* report the list we figured out */
    if (report_file_list())
        goto error_exit;

    ret = 0;

error_exit:
    list_for_each_entry(p, &proc_list, list)
    {
        if (old_p) free(old_p);
        old_p = p;
        old_f = NULL;
        list_for_each_entry(f, &p->files, node)
        {
            if (old_f) free(old_f);
            old_f = f;
        }
        if (old_f) free(old_f);
    }
    if (old_p) free(old_p);
    INIT_LIST_HEAD(&proc_list);
    INIT_LIST_HEAD(&file_list);
    proc_count = 0;
    file_count = 0;
    fd_count = 0;

    if (task_struct) munmap(task_struct, xa.page_size);
    
    return ret;
}

static 
int walk_file_list(struct proc *p, uint32_t files)
{
    unsigned char *files_struct = NULL;
    unsigned char *fdtable = NULL;
    uint32_t *fd_list = NULL;
    uint32_t offset, fdt, max_fds, fd; 
    int ret = -1;

    files_struct = xa_access_kernel_va(&xa, files, &offset, PROT_READ);
    if (!files_struct)
    {
        perror("Failed to map memory for files_struct");
        return -1;
    }
    memcpy(&fdt, files_struct + offset + off_fdt, 4);

    fdtable = xa_access_kernel_va(&xa, fdt, &offset, PROT_READ);
    if (!fdtable)
    {
        perror("Failed to map memory for fdtable");
        goto error_exit;
    }
    memcpy(&max_fds, fdtable + offset + off_max_fds, 4);
    memcpy(&fd, fdtable + offset + off_fd, 4);

    fd_list = xa_access_kernel_va(&xa, fd, &offset, PROT_READ);
    if (!fd_list)
    {
        perror("Failed to map memory for fd_list");
        goto error_exit;
    }
    fd_list = (uint32_t *)(((char *)fd_list) + offset);

    if (walk_fd_list(p, fd_list, max_fds))
        goto error_exit;
    
    ret = 0;

error_exit:
    if (files_struct) munmap(files_struct, xa.page_size);
    if (fdtable) munmap(fdtable, xa.page_size);
    if (fd_list) munmap(fd_list, xa.page_size);

    return ret;
}

static
int walk_fd_list(struct proc *p, uint32_t *fd_list, uint32_t max_fds)
{
    unsigned char *file = NULL;
    unsigned char *vfsmount = NULL;
    unsigned char *dentry = NULL;
    unsigned char *devname = NULL;
    unsigned char *filename = NULL;
    char *dev, *name;
    struct openfile *f = NULL;
    uint32_t offset, f_vfsmnt, f_dentry;
    uint32_t mnt_devname, d_parent, qstr_len, qstr_name;
    int fd, name_offset, ret = -1;

    for (fd = 0; fd < max_fds; fd++)
    {
        if (fd_list[fd])
        {
            file = xa_access_kernel_va(&xa, fd_list[fd], &offset, PROT_READ);
            if (!file)
            {
                perror("Failed to map memory for file");
                goto error_exit;
            }
            memcpy(&f_vfsmnt, file + offset + off_f_vfsmnt, 4);
            memcpy(&f_dentry, file + offset + off_f_dentry, 4);

            /* read struct vfsmount to obtain device name */
            vfsmount = xa_access_kernel_va(&xa, f_vfsmnt, &offset, PROT_READ);
            if (!vfsmount)
            {
                perror("Failed to mape memory for vfsmount");
                goto error_exit;
            }
            memcpy(&mnt_devname, vfsmount + offset + off_mnt_devname, 4);
            
            devname = xa_access_kernel_va(&xa, mnt_devname, &offset, PROT_READ);
            if (!devname)
            {
                perror("Failed to map memory for device name");
                goto error_exit;
            }
            dev = (char *)devname + offset;

            /* read struct dentry to obtain file name */
            dentry = xa_access_kernel_va(&xa, f_dentry, &offset, PROT_READ);
            if (!dentry)
            {
                perror("Failed to map memory for dentry");
                goto error_exit;
            }
            memcpy(&d_parent, dentry + offset + off_d_parent, 4);
            memcpy(&qstr_len, dentry + offset + off_d_name + off_qstr_len, 4);
            memcpy(&qstr_name, dentry + offset + off_d_name + off_qstr_name, 4);

            filename = xa_access_kernel_va(&xa, qstr_name, &offset, PROT_READ);
            if (!filename)
            {
                perror("Failed to map memory for file name");
                goto error_exit;
            }
            name = (char *)filename + offset;

            f = (struct openfile *) malloc( sizeof(struct openfile) );
            if (!f)
            {
                perror("Failed to allocate memory for open file info");
                goto error_exit;
            }
            f->fd = fd;
            strncpy(f->dev, dev, DNAME_MAX);
            
            /* walk through parent directories to make it a full file path */
            memset(f->name, 0, PATH_MAX+1);
            name_offset = 0;
            if (f_dentry != d_parent)
            {
                name_offset = fill_parent_dir(f->name, d_parent);
                if (name_offset < 0) goto error_exit;
            }
            memcpy(f->name + name_offset, name, qstr_len);
           
            /* add obtained file info to the linked list */
            list_add_tail(&f->node, &p->files);
            p->file_count++;
            fd_count++;

            munmap(file, xa.page_size);
            munmap(vfsmount, xa.page_size);
            munmap(devname, xa.page_size);
            munmap(dentry, xa.page_size);
            munmap(filename, xa.page_size);
            file = vfsmount = devname = dentry = filename = NULL;
        }
    }

    ret = 0;

error_exit:
    if (file) munmap(file, xa.page_size);
    if (vfsmount) munmap(vfsmount, xa.page_size);
    if (devname) munmap(devname, xa.page_size);
    if (dentry) munmap(dentry, xa.page_size);
    if (filename) munmap(filename, xa.page_size);

    return ret;
}

static inline
struct openfile *find_file(const char *dev, const char *name)
{
    struct openfile *f = NULL;
    list_for_each_entry(f, &file_list, list)
    {
        if (strcmp(f->dev, dev) == 0 && strcmp(f->name, name) == 0)
            return f;
    }
    return NULL;
}

static inline
char *str_replace(const char *s, const char *old, const char *new)
{
    char *ret;
    int i, count = 0;
    size_t newlen = strlen(new);
    size_t oldlen = strlen(old);

    for (i = 0; s[i] != '\0'; i++)
    {
        if (strstr(&s[i], old) == &s[i])
        {
            count++;
            i += oldlen - 1;
        }
    }

    ret = malloc(i + count * (newlen - oldlen));
    if (ret == NULL)
        return NULL;

    i = 0;
    while (*s)
    {
        if (strstr(s, old) == s)
        {
            strcpy(&ret[i], new);
            i += newlen;
            s += oldlen;
        }
        else
        {
            ret[i++] = *s++;
        }
    }
    ret[i] = '\0';

    return ret;
}

static
int report_file_list(void)
{
    char *msg = NULL, *webmsg = NULL;
    struct proc *p = NULL;
    struct openfile *f = NULL, *cf = NULL;
    int ret = -1;

    /* change device aliases to consistent names */
    list_for_each_entry(p, &proc_list, list)
    {
        list_for_each_entry(f, &p->files, node)
        {
            if (strcmp(f->dev, "none") == 0)
                strcpy(f->dev, "/dev");
            else if (strcmp(f->dev, "devpts") == 0)
                strcpy(f->dev, "/dev/pts");
            else if (f->dev[0] != '/' || strcmp(f->dev, "/dev/root") == 0)
                strcpy(f->dev, "");
        }
    }

    /* build global file list to exclude overlapped file info */
    list_for_each_entry(p, &proc_list, list)
    {
        list_for_each_entry(f, &p->files, node)
        {
            if (find_file(f->dev, f->name) == NULL)
            {
                list_add_tail(&f->list, &file_list);
                file_count++;
            }
        }
    }

    if (opt_console)
    {
        if (opt_daemon)
        {
            printf("\n"
                    "[%u.%06u]\n"
                    "%-10s  %s (ID: %d)\n"
                    "%-10s  %d\n"
                    "%-10s  %d\n"
                    "%-10s  %d\n",
                    (unsigned int)now.tv_sec, (unsigned int)now.tv_usec,
                    "Domain:", domain, domid,
                    "Files:", file_count, 
                    "FDs:", fd_count,
                    "Processes:", proc_count);
        }
        printf("%5s %-16s %-4s %s\n", "PID", "CMD", "FD", "FILE");
        list_for_each_entry(p, &proc_list, list)
        {
            list_for_each_entry(f, &p->files, node)
            {
                printf("%5d %-16s %-4d %s%s\n", 
                        p->pid, p->name, f->fd, f->dev, f->name);
            }
        }
    }

    if (opt_log || opt_web)
    {
        if (msg) free(msg);
        msg = (char *) malloc ( file_count * (PATH_MAX+128) + 
            proc_count * (PNAME_MAX+128) + 256 );
        if (!msg)
        {
            perror("Failed to allocate memory for web report");
            return 1;
        }

        sprintf(msg, "[%u.%06u] %d files found in \"%s\" - ", 
            (unsigned int)now.tv_sec, (unsigned int)now.tv_usec, 
            file_count, domain);
        list_for_each_entry(cf, &file_list, list)
        {
            sprintf(msg + strlen(msg), "%s%s<-{", cf->dev, cf->name);
            list_for_each_entry(p, &proc_list, list)
            {
                list_for_each_entry(f, &p->files, node)
                {
                    if (strcmp(cf->dev, f->dev) == 0 && 
                        strcmp(cf->name, f->name) == 0)
                    {
                        sprintf(msg + strlen(msg), "%d:%s(%d),", 
                            f->fd, p->name, p->pid);
                    }
                }
            }
            msg[strlen(msg)-1] = '\0';
            strcat(msg, "}, ");
        }
        msg[strlen(msg)-2] = '\0';

        if (opt_log)
          {
            /* write the message to log file */
            fprintf(logfile, "%s\n", msg);
            fflush(logfile);
        }
        if (opt_web)
        {
            /* replace all spaces with "%20" */
            webmsg = str_replace(msg, " ", "%20");
            if (!webmsg)
            {
                perror("Failed to allocate memory for web user message");
                goto error_exit;
            }

            /* report the message to stats server */
            if (web_report(webmsg))
            {
                fprintf(stderr, "Failed to report process list to stats web server");
                goto error_exit;
            }
        }
    }

    if (opt_log || opt_web)
    {
        printf("[%u.%06u] %d files reported to ", 
            (unsigned int)now.tv_sec, (unsigned int)now.tv_usec, 
            file_count);
        if (opt_log)
        {
            printf("log file");
            if (opt_web) printf(" and ");
        }
        if (opt_web)
            printf("web server");
        printf(".\n");
    }
    
    ret = 0;

error_exit:
    if (webmsg) free(webmsg);
    if (msg) free(msg);

    return ret;
}

static 
int fill_parent_dir(char *path, uint32_t parent)
{
    unsigned char *dentry = NULL;
    char *name = NULL;
    uint32_t offset, old_parent, qstr_len, qstr_name;
    int name_offset = 0;

    if (parent == 0)
        return 0;

    dentry = xa_access_kernel_va(&xa, parent, &offset, PROT_READ);
    if (!dentry)
    {
        perror("Failed to map memory for parent dentry");
        return -1;
    }
    old_parent = parent;
    memcpy(&parent, dentry + offset + off_d_parent, 4);
    memcpy(&qstr_len, dentry + offset + off_d_name + off_qstr_len, 4);
    memcpy(&qstr_name, dentry + offset + off_d_name + off_qstr_name, 4);

    name = xa_access_kernel_va(&xa, qstr_name, &offset, PROT_READ);
    if (!name)
    {
        munmap(dentry, xa.page_size);
        perror("Failed to map memory for parent name");
        return -1;
    }

    if (old_parent != parent)
        name_offset = fill_parent_dir(path, parent);

    memcpy(path + name_offset, name + offset, qstr_len);
    name_offset += qstr_len;
    if (path[name_offset-1] != '/' && path[name_offset-1] != ':')
        path[name_offset++] = '/';

    munmap(dentry, xa.page_size);
    munmap(name, xa.page_size);
    return name_offset;
}

static inline
void signal_handler(int sig)
{
    struct proc *p = NULL, *old_p = NULL;
    struct openfile *f = NULL, *old_f = NULL;
    
    xc_domain_unpause(xc_handle, domid);
    
    list_for_each_entry(p, &proc_list, list)
    {
        if (old_p) free(old_p);
        old_p = p;
        old_f = NULL;
        list_for_each_entry(f, &p->files, node)
        {
            if (old_f) free(old_f);
            old_f = f;
        }
        if (old_f) free(old_f);
    }
    if (old_p) free(old_p);
    
    xa_destroy(&xa);
    log_cleanup();
    
    signal(sig, SIG_DFL);
    raise(sig);
}

static
void signal_interrupt(void)
{
    if (signal(SIGINT, signal_handler) == SIG_IGN)
        signal(SIGINT, SIG_IGN);
    if (signal(SIGABRT, signal_handler) == SIG_IGN)
        signal(SIGABRT, SIG_IGN);
    if (signal(SIGHUP, signal_handler) == SIG_IGN)
        signal(SIGHUP, SIG_IGN);
    if (signal(SIGILL, signal_handler) == SIG_IGN)
        signal(SIGILL, SIG_IGN);
    if (signal(SIGFPE, signal_handler) == SIG_IGN)
        signal(SIGFPE, SIG_IGN);
    if (signal(SIGSEGV, signal_handler) == SIG_IGN)
        signal(SIGSEGV, SIG_IGN);
    if (signal(SIGTERM, signal_handler) == SIG_IGN)
        signal(SIGTERM, SIG_IGN);
}
