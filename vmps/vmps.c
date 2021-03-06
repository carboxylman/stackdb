/*
 * Copyright (c) 2011, 2012 The University of Utah
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

#include "vmps.h"
#include "list.h"
#include "inih/config.h"
#include "offset.h"
#include "web.h"
#include "log.h"

/* domain info */
struct domain {
    struct list_head list;
    char name[128];
    domid_t domid;
    xa_instance_t xa;
    int xc;
    struct list_head proc_list;
    int proc_count;
};

#define PNAME_MAX (128)

/* process info */
struct proc {
    struct list_head list;
    int pid;
    char name[PNAME_MAX+1];
};

LIST_HEAD(domain_list);

char sysmap[PATH_MAX+1];
char debuginfo[PATH_MAX+1];
int interval;

int off_tasks, off_pid, off_name;
int opt_daemon, opt_log, opt_web, opt_console = 1; /* console on by default */

static void print_usage(const char *exec);
static void get_options(int argc, char *argv[]);
static void signal_interrupt(void);
static int load_config(const char *config);
static int init_xa(xa_instance_t *xa, const char *domain);
static int predict_debuginfo(char *debuginfo, const char *sysmap);
static int find_offsets(void);
static int walk_task_list(struct domain *d);
static int report_task_list(struct domain *d, struct timeval *now);
static void clear_domain_list(void);
static void clear_proc_list(struct list_head *proc_list);

int main (int argc, char *argv[])
{
    struct domain *d;
    
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

    /* do not predict debuginfo path if it is specified in config */
    if (predict_debuginfo(debuginfo, sysmap))
        goto error_exit;

    /* obtain the offsets of task_struct members 
       NOTE: this takes the longest time due to inefficient DWARF reading */
    if (find_offsets())
        goto error_exit;

    /* list all tasks repeatedly with a time interval */
    do {
        list_for_each_entry(d, &domain_list, list)
        {
            if (walk_task_list(d)) return 1;
        }
        sleep(interval);
    } while (opt_daemon);

error_exit:
    log_cleanup();
    clear_domain_list();
    return 0;
}

static 
void print_usage(const char *exec)
{
    printf("Usage: %s [OPTION]... <DOMAIN NAME>...\n", exec);
    printf("options:\n");
    printf("  -d, --daemon <sec>   run in daemon mode with time interval sec\n");
    printf("  -c, --console        report process list(s) to console (default)\n");
    printf("  -w, --web            report process list(s) to stats web server\n");
    printf("  -l, --log            report process list(s) to log file\n");
    printf("  -h, --help           display this help and exit\n");
    exit(1);
}

static 
void get_options(int argc, char *argv[])
{
    struct domain *d;
    int i, tmp_console = 0;

    INIT_LIST_HEAD(&domain_list);
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
        else if (strcmp(argv[i], "-h") == 0 ||
                strcmp(argv[i], "--help") == 0)
        {
            clear_domain_list();
            print_usage(argv[0]);
        }
        else if (argv[i][0] != '-')
        {
            /* this is one of the domains that we are looking at */
            d = (struct domain *) malloc (sizeof (struct domain) );
            if (!d)
            {
                perror("Failed to allocate memory for domain info");
                clear_domain_list();
                exit(1);
            }
            strcpy(d->name, argv[i]);
            if (init_xa(&d->xa, d->name))
            {
                free(d);
                clear_domain_list();
                exit(1);
            }
            d->domid = d->xa.m.xen.domain_id;
            d->xc = d->xa.m.xen.xc_handle;
            if (strlen(sysmap) == 0) strcpy(sysmap, d->xa.sysmap);
            INIT_LIST_HEAD(&d->proc_list);
            d->proc_count = 0;
            list_add_tail(&d->list, &domain_list);
        }
        else
        { 
            clear_domain_list();
            print_usage(argv[0]);
        }
    }

    /* do not report to console unless it's explicitly specified when 
       we are reporting to web server or log file */
    if ((opt_web || opt_log) && !tmp_console)
        opt_console = 0;

    /* no domains found */
    if (list_empty(&domain_list))
    {
        clear_domain_list();
        print_usage(argv[0]);
    }
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
    if (ini_parse(config, config_handler, NULL) < 0)
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
    //xa->pae = 1;
    xa->os_type = XA_OS_LINUX; /* currently support linux only */
    if (strlen(conf_sysmap) > 0)
        xa->sysmap = conf_sysmap; /* use the sysmap file specified in config */
    if (xa_init_vm_name_strict((char *)domain, xa) == XA_FAILURE)
    {
        fprintf(stderr, "Failed to init xa instance"
                " - Domain %s probably does not exist\n", domain);
        return -1;
    }
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
    if (offset_task_struct(&off_tasks, &off_name, &off_pid, debuginfo))
    {
        perror("Failed to get offsets of task_struct members");
        return -1;
    }
    return 0;
}

static 
void clear_domain_list(void)
{
    struct domain *d, *old_d = NULL;
    list_for_each_entry(d, &domain_list, list)
    {
        if (old_d) free(old_d);
        old_d = d;
        clear_proc_list(&d->proc_list);
        xa_destroy(&d->xa);
    }
    if (old_d) free(old_d);
    INIT_LIST_HEAD(&domain_list);
}

static 
void clear_proc_list(struct list_head *proc_list)
{
    struct proc *p, *old_p = NULL;
    list_for_each_entry(p, proc_list, list)
    {
        if (old_p) free(old_p);
        old_p = p;
    }
    if (old_p) free(old_p);
    INIT_LIST_HEAD(proc_list);
}

static 
int walk_task_list(struct domain *d)
{
    unsigned char *task_struct = NULL;
    uint32_t offset, next_proc, list_head;
    struct proc *p;
    char *name = NULL;
    int pid = 0;
    int ret = -1;
    struct timeval now;

    gettimeofday(&now, NULL);

    /* FIXME: this shoud be done just one time and later all domains can share
       next_proc. */
    /* get the head of the list */
    task_struct = xa_access_kernel_sym(&d->xa, "init_task", &offset, PROT_READ);
    if (!task_struct)
    {
        perror("Failed to get process list head");
        return -1;
    }    
    memcpy(&next_proc, task_struct + offset + off_tasks, 4);
    list_head = next_proc;
    munmap(task_struct, d->xa.page_size);
    task_struct = NULL;
    
    xc_domain_pause(d->xc, d->domid);
    
    /* walk the task list */
    while (1)
    {
        /* follow the next pointer */
        task_struct = xa_access_kernel_va(&d->xa, next_proc, &offset, PROT_READ);
        if (!task_struct)
        {
            perror("Failed to map task_struct for process list pointer");
            goto error_exit;
        }
        memcpy(&next_proc, task_struct + offset, 4);

        /* if we are back at the list head, we are done */
        if (list_head == next_proc)
            break;

        /* Note: the task_struct that we are looking at has a lot of
           information.  However, the process name and id are burried
           nice and deep.  Instead of doing something sane like mapping
           this data to a task_struct, I'm just jumping to the location
           with the info that I want.  This helps to make the example
           code cleaner, if not more fragile.  In a real app, you'd
           want to do this a little more robust :-)  See
           include/linux/sched.h for mode details */
        name = (char *) (task_struct + offset + off_name - off_tasks);
        memcpy(&pid, task_struct + offset + off_pid - off_tasks, 4);

        /* trivial sanity check on data */
        if (pid < 0)
            continue;
        
        /* add obtained process info to the linked list */
        p = (struct proc *) malloc( sizeof(struct proc) );
        if (!p)
        {
            perror("Failed to allocate task_struct for process info");
            goto error_exit;
        }
        p->pid = pid;
        strncpy(p->name, name, PNAME_MAX);
        list_add_tail(&p->list, &d->proc_list);
        d->proc_count++;

        munmap(task_struct, d->xa.page_size);
        task_struct = NULL;
    }

    xc_domain_unpause(d->xc, d->domid);
    
    /* report the list we figured out */
    if (report_task_list(d, &now))
        goto error_exit;

    ret = 0;

error_exit:
    clear_proc_list(&d->proc_list);
    d->proc_count = 0; 
    if (task_struct) munmap(task_struct, d->xa.page_size);    
    return ret;
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

    ret = malloc(i + count * (newlen - oldlen) + 1);
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

static inline
int first_domain(struct domain *d)
{
    return (domain_list.next == &d->list);
}

static inline 
int single_domain(struct domain *d)
{
    return ((domain_list.next == &d->list) && (domain_list.prev == &d->list));
}

static
int report_task_list(struct domain *d, struct timeval *now)
{
    char *msg = NULL, *webmsg = NULL;
    struct proc *p = NULL;
    int ret = -1;

    if (opt_console)
    {
        if (opt_daemon || !single_domain(d))
        {
            if (!first_domain(d)) printf("\n");
            if (opt_daemon)
            {
                printf("[%u.%06u]\n",
                        (unsigned int)now->tv_sec, (unsigned int)now->tv_usec);
            }
            printf("%-10s  %s (ID: %d)\n"
                    "%-10s  %d\n",
                    "Domain:", d->name, d->domid, 
                    "Processes:", d->proc_count);
        }
        printf("%5s %s\n", "PID", "CMD");
        list_for_each_entry(p, &d->proc_list, list)
        {
            printf("%5d %s\n", p->pid, p->name);
        }
    }

    if (opt_log || opt_web)
    {
        /* build a user message out of all process info. */
        msg = (char *) malloc ( d->proc_count * (PNAME_MAX+64) + 256 );
        if (!msg)
        {
            perror("Failed to allocate memory for user message");
            return 1;
        }
        
        sprintf(msg, "[%u.%06u] %d processes found in \"%s\" - ", 
            (unsigned int)now->tv_sec, (unsigned int)now->tv_usec, 
            d->proc_count, d->name);
        list_for_each_entry(p, &d->proc_list, list)
        {
            sprintf(msg + strlen(msg), "%s(%d), ", p->name, p->pid);
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
        
        printf("[%u.%06u] %d processes in \"%s\" reported to ", 
            (unsigned int)now->tv_sec, (unsigned int)now->tv_usec, 
            d->proc_count, d->name);
        if (opt_log)
        {
            printf("log");
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

static inline
void signal_handler(int sig)
{
    struct domain *d;

    list_for_each_entry(d, &domain_list, list)
    {
        xc_domain_unpause(d->xc, d->domid);
    }

    clear_domain_list();
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
