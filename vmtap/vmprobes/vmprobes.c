#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>

#include <xenctrl.h>
#include <xenaccess/xenaccess.h>

#include "list.h"
#include "cqueue.h"
#include "vmprobes.h"
#include "private.h"

#ifdef VMPROBE_DEBUG
static inline
void dbgprint(char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}
#else
#define dbgprint(format, args...) ((void)0)
#endif

#define __save_org_insn(probepoint)     (arch_save_org_insn(probepoint))
#define __insert_breakpoint(probepoint) (arch_insert_breakpoint(probepoint))
#define __remove_breakpoint(probepoint) (arch_remove_breakpoint(probepoint))
#define __enter_singlestep(regs)        (arch_enter_singlestep(regs))
#define __leave_singlestep(regs)        (arch_leave_singlestep(regs))
#define __get_org_ip(regs)              (arch_get_org_ip(regs))
#define __reset_ip(regs)                (arch_reset_ip(regs))
#define __get_cur_sp(regs)              (arch_get_cur_sp(regs))
#define __hash_long(val,bits)           (arch_hash_long(val,bits))

static struct vmprobe *probe_list[VMPROBE_MAX];
static struct cqueue handle_queue;

LIST_HEAD(probepoint_list);
LIST_HEAD(domain_list);

static int xc_handle = -1;
static int xce_handle = -1;

static bool interrupt;
static evtchn_port_t dbg_port;

static inline bool
only_probe_left(struct vmprobe *probe)
{
    return ((probe->probepoint->probe_list.next == &probe->node) &&
            (probe->probepoint->probe_list.prev == &probe->node));
}

static inline bool
only_probepoint_left(struct vmprobe_probepoint *probepoint)
{
    return ((probepoint->domain->probepoint_list.next == &probepoint->node) &&
            (probepoint->domain->probepoint_list.prev == &probepoint->node));
}

static inline bool
domain_paused(domid_t domid)
{
    xc_dominfo_t dominfo;
    return ((xc_domain_getinfo(xc_handle, domid, 1, &dominfo) == 1) &&
            (dominfo.domid == domid) &&
            dominfo.paused);
}

static inline int
get_vcpu(domid_t domid)
{
    xc_dominfo_t dominfo;
    xc_domain_getinfo(xc_handle, domid, 1, &dominfo);
    return dominfo.max_vcpu_id;
}

static inline struct cpu_user_regs *
get_regs(domid_t domid, vcpu_guest_context_t *ctx)
{
    xc_vcpu_getcontext(xc_handle, domid, get_vcpu(domid), ctx);
    return &ctx->user_regs;
}

static inline void
set_regs(domid_t domid, vcpu_guest_context_t *ctx)
{
    xc_vcpu_setcontext(xc_handle, domid, get_vcpu(domid), ctx);    
}

#ifdef VMPROBE_SIGNAL
static void
signal_handler(int sig)
{
    vmprobe_handle_t handle;

    VMPROBE_PERF_STOP("vmprobes gets control back by interrupt");
    VMPROBE_PERF_NEXT();

    for (handle = 0; handle < VMPROBE_MAX; handle++)
        unregister_vmprobe(handle);
    dbgprint("probes forcefully unregistered\n");
    
    VMPROBE_PERF_PRINT();

    signal(sig, SIG_DFL);
    raise(sig);
}

static void
signal_interrupt(void)
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
#endif /* VMPROBE_SIGNAL */

static int
init_evtchn(evtchn_port_t *dbg_port)
{
    int evtchn;
    int port;
    
    evtchn = xc_evtchn_open();
    if (evtchn < 0)
    {
        perror("failed to open evtchn device");
        return evtchn;
    }
    
    port = xc_evtchn_bind_virq(evtchn, VIRQ_DEBUGGER);
    if (port < 0)
    {
        perror("failed to bind debug virq port");
        xc_evtchn_close(evtchn);
        return port;
    }
    
    *dbg_port = port;
    return evtchn;
}

static int
set_debugging(domid_t domid, bool enable)
{
    struct xen_domctl domctl;
    char errmsg[128];

    domctl.cmd = XEN_DOMCTL_setdebugging;
    domctl.domain = domid;
    domctl.u.setdebugging.enable = enable;
    
    if (xc_domctl(xc_handle, &domctl))
    {
        sprintf(errmsg, "failed to %s debugging in dom%d", 
            (enable) ? "set" : "unset", domid);
        perror(errmsg);
        return -1;
    }
    
    return 0;
}

static inline struct vmprobe *
find_probe(vmprobe_handle_t handle)
{
    if (handle < 0 || handle >= VMPROBE_MAX)
        return NULL;
    
    return probe_list[handle];
}

static struct vmprobe *
add_probe(vmprobe_handler_t pre_handler,
          vmprobe_handler_t post_handler,
          struct vmprobe_probepoint *probepoint)
{
    struct vmprobe *probe;
    vmprobe_handle_t handle = -1;
    
    if (cqueue_empty(&handle_queue))
    {
        fprintf(stderr, "total number of probes cannot exceed %d\n", 
            VMPROBE_MAX);
        return NULL;
    }

    probe = (struct vmprobe *) malloc( sizeof(*probe) );
    if (!probe)
    {
        perror("failed to allocate a new probe");
        return NULL;
    }
    
    /* obtain a handle from the queue */
    cqueue_get(&handle_queue, &handle);

    probe->handle = handle;
    probe->pre_handler = pre_handler;
    probe->post_handler = post_handler;
    probe->probepoint = probepoint;
    probe->disabled = true; // disabled at first
    
    probe_list[handle] = probe;
    list_add_tail(&probe->node, &probepoint->probe_list);
    
    dbgprint("probe %d added\n", probe->handle);
    return probe;
}

static void
remove_probe(struct vmprobe *probe)
{
    vmprobe_handle_t handle;

    list_del(&probe->node);
    
    /* return the handle to the queue */
    handle = probe->handle;
    cqueue_put(&handle_queue, handle);
    probe_list[handle] = NULL;
    
    dbgprint("probe %d removed\n", probe->handle);
    free(probe);
}

static struct vmprobe_probepoint *
find_probepoint(unsigned long vaddr, struct vmprobe_domain *domain)
{
    struct vmprobe_probepoint *probepoint;

    list_for_each_entry(probepoint, &probepoint_list, list)
    {
        if (probepoint->domain == domain && probepoint->vaddr == vaddr)
            return probepoint;
    }
    
    return NULL;
}

static struct vmprobe_probepoint *
add_probepoint(unsigned long vaddr, struct vmprobe_domain *domain)
{
    struct vmprobe_probepoint *probepoint;
    
    probepoint = find_probepoint(vaddr, domain);
    if (probepoint)
        return NULL;
    
    probepoint = (struct vmprobe_probepoint *) malloc( sizeof(*probepoint) );
    if (!probepoint)
    {
        perror("failed to allocate a new probepoint");
        return NULL;
    }
    
    probepoint->vaddr = vaddr;
    probepoint->domain = domain;
    probepoint->state = VMPROBE_DISABLED;
    memset(&probepoint->opcode, 0, sizeof(vmprobe_opcode_t));
    INIT_LIST_HEAD(&probepoint->probe_list);
    
    list_add(&probepoint->list, &probepoint_list);
    list_add(&probepoint->node, &domain->probepoint_list);

    dbgprint("probepoint [%lx:dom%d] added\n", probepoint->vaddr,
        probepoint->domain->id);
    return probepoint;
}

static void
remove_probepoint(struct vmprobe_probepoint *probepoint)
{
    list_del(&probepoint->node);
    list_del(&probepoint->list);

    dbgprint("probepoint [%lx:dom%d] removed\n", probepoint->vaddr,
        probepoint->domain->id);
    free(probepoint);
}

static struct vmprobe_domain *
find_domain(domid_t domid)
{
    struct vmprobe_domain *domain;

    list_for_each_entry(domain, &domain_list, list)
    {
        if (domain->id == domid)
            return domain;
    }
    
    return NULL;
}

static struct vmprobe_domain *
add_domain(domid_t domid)
{
    struct vmprobe_domain *domain;
    
    domain = find_domain(domid);
    if (domain)
        return NULL;

    domain = (struct vmprobe_domain *) malloc( sizeof(*domain) );
    if (!domain)
    {
        perror("failed to allocate a new domain");
        return NULL;
    }
    
    /* initialize a xenaccess instance */
    memset(&domain->xa_instance, 0, sizeof(xa_instance_t));
    domain->xa_instance.os_type = XA_OS_LINUX; // currently linux only
    if (xa_init_vm_id_lax(domid, &domain->xa_instance) == XA_FAILURE)
    {
        free(domain);
        fprintf(stderr, "failed to init xa instance for dom%d\n", domid);
        return NULL;
    }

    domain->id = domid;
    domain->org_ip = 0;
    domain->sstep_probepoint = NULL;
    INIT_LIST_HEAD(&domain->probepoint_list);
    
    list_add(&domain->list, &domain_list);

    dbgprint("dom%d added\n", domain->id);
    return domain;
}

static void
remove_domain(struct vmprobe_domain *domain)
{
    list_del(&domain->list);

    xa_destroy(&domain->xa_instance);

    dbgprint("dom%d removed\n", domain->id);
    free(domain);
}

static int
handle_bphit(struct vmprobe_domain *domain, struct cpu_user_regs *regs)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;

    /* save the original ip value in case something bad happens */
    domain->org_ip = __get_org_ip(regs);

    probepoint = find_probepoint(domain->org_ip, domain);
    if (!probepoint)
        return -1;
    
    VMPROBE_PERF_START();
    list_for_each_entry(probe, &probepoint->probe_list, node)
    {
        if (!probe->disabled && probe->pre_handler)
            probe->disabled = probe->pre_handler(probe->handle, regs);
    }
    VMPROBE_PERF_STOP("vmprobes executes pre-handlers");
   
    /* restore ip register */
    VMPROBE_PERF_START();
    __reset_ip(regs);
    dbgprint("original ip %x restored in dom%d\n", regs->eip, domain->id);
    VMPROBE_PERF_STOP("vmprobes resets ip register in domU");

    /* restore the original instruction */
    VMPROBE_PERF_START();
    probepoint->state = VMPROBE_REMOVING;
    __remove_breakpoint(probepoint);
    dbgprint("bp removed at [%lx:dom%d]\n", probepoint->vaddr, domain->id);
    probepoint->state = VMPROBE_DISABLED;
    VMPROBE_PERF_STOP("vmprobes removes breakpoint in domU");
    
    if (!interrupt)
    {
        /* turn singlestep mode on */
        VMPROBE_PERF_START();
        __enter_singlestep(regs);
        dbgprint("sstep set in dom%d\n", domain->id);
        domain->sstep_probepoint = probepoint;
        VMPROBE_PERF_STOP("vmprobes sets singlestep in domU");
    }

    /* nothing bad has happened, so set it zero */
    domain->org_ip = 0;
    
    return 0;
}

static void
handle_sstep(struct vmprobe_domain *domain, struct cpu_user_regs *regs)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;

    probepoint = domain->sstep_probepoint;  

    VMPROBE_PERF_START();
    list_for_each_entry(probe, &probepoint->probe_list, node)
    {
        if (!probe->disabled && probe->post_handler)
            probe->disabled = probe->post_handler(probe->handle, regs);
    }
    VMPROBE_PERF_STOP("vmprobes executes post-handlers");

    if (!interrupt)
    {
        /* turn singlestep mode off */
        VMPROBE_PERF_START();
        __leave_singlestep(regs);
        dbgprint("sstep unset in dom%d\n", domain->id);
        domain->sstep_probepoint = NULL;
        VMPROBE_PERF_STOP("vmprobes unsets singlestep in domU");
        
        VMPROBE_PERF_NEXT();

        /* inject a breakpoint for the next round */
        VMPROBE_PERF_START();
        probepoint->state = VMPROBE_INSERTING;
        __insert_breakpoint(probepoint);
        dbgprint("bp set at [%lx:dom%d]\n", probepoint->vaddr, domain->id);
        probepoint->state = VMPROBE_BP_SET;
        VMPROBE_PERF_STOP("vmprobes injects breakpoint back in domU");    
    }
}

static void
cleanup_vmprobes(void)
{
    cqueue_cleanup(&handle_queue);
    
    xc_evtchn_close(xce_handle);
    xce_handle = -1;
    
    xc_interface_close(xc_handle);
    xc_handle = -1;

    dbgprint("vmprobes uninitialized\n");
}

static int
init_vmprobes(void)
{
    vmprobe_handle_t handle;
    
    if (xc_handle != -1)
        return -1; // xc interface already open

#ifdef VMPROBE_SIGNAL
    signal_interrupt();
#endif
    
    VMPROBE_PERF_RESET();

    xc_handle = xc_interface_open();
    if (xc_handle < 0)
    {
        perror("failed to open xc interface");
        return xc_handle;
    }

    xce_handle = init_evtchn(&dbg_port);
    if (xce_handle < 0)
    {
        cleanup_vmprobes();
        return xce_handle;
    }

    if (!cqueue_init(&handle_queue, VMPROBE_MAX))
    {
        perror("failed to init probe handle queue");
        cleanup_vmprobes();
        return -ENOMEM;
    }
    
    /* fill all handles in the queue */
    for (handle = 0; handle < VMPROBE_MAX; handle++)
        cqueue_put(&handle_queue, handle);

    interrupt = false;
    dbgprint("vmprobes initialized\n");
    return 0;
}

static int
__register_vmprobe(struct vmprobe *probe)
{
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;
    int ret;

    probepoint = probe->probepoint;
    domain = probepoint->domain;
    
    /* turn debugging mode on */
    VMPROBE_PERF_START();
    ret = set_debugging(domain->id, true);
    if (ret < 0)
        return ret;
    dbgprint("debugging set in dom%d\n", domain->id);
    VMPROBE_PERF_STOP("vmprobes sets debugging in domU");

    if (probepoint->state == VMPROBE_DISABLED)
    {
        VMPROBE_PERF_START();
        probepoint->state = VMPROBE_INSERTING;

        /* backup the original instruction */
        ret = __save_org_insn(probepoint);
        if (ret < 0)
        {
            probepoint->state = VMPROBE_DISABLED;
            return ret;
        }

        /* inject a breakpoint at the probe-point */
        ret = __insert_breakpoint(probepoint);
        if (ret < 0)
        {
            probepoint->state = VMPROBE_DISABLED;
            return ret;
        }
        dbgprint("bp set at [%lx:dom%d] for the first time\n", 
            probepoint->vaddr, domain->id);
    
        probepoint->state = VMPROBE_BP_SET;
        VMPROBE_PERF_STOP("vmprobes injects breakpoint in domU");
    }
    
    probe->disabled = false;
    return 0;
}

static int
__unregister_vmprobe(struct vmprobe *probe)
{
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;
    struct cpu_user_regs *regs;
    vcpu_guest_context_t ctx;
    int ret;
    
    probepoint = probe->probepoint;
    domain = probepoint->domain;
    
    if (only_probe_left(probe))
    {
        if (probepoint->state == VMPROBE_BP_SET)
        {
            VMPROBE_PERF_START();
            probepoint->state = VMPROBE_REMOVING;
        
            /* restore the original instruction */
            ret = __remove_breakpoint(probepoint);
            if (ret < 0)
            {
                probepoint->state = VMPROBE_BP_SET;
                return ret;
            }
            dbgprint("bp removed at [%lx:dom%d] for the last time\n",
                probepoint->vaddr, domain->id);

            probepoint->state = VMPROBE_DISABLED;
            VMPROBE_PERF_STOP("vmprobes removes breakpoint in domU");
        }
        
        if (only_probepoint_left(probepoint))
        {
            VMPROBE_PERF_START();
            regs = get_regs(domain->id, &ctx);
            VMPROBE_PERF_STOP("vmprobes obtains registers from domU");

            /* singlestep still on? */
            if (domain->sstep_probepoint)
            {
                /* turn singlestep mode off */
                VMPROBE_PERF_START();
                __leave_singlestep(regs);
                domain->sstep_probepoint = NULL;
                dbgprint("sstep unset in dom%d for the last time\n", 
                    domain->id);
                VMPROBE_PERF_STOP("vmprobes unsets singlestep in domU");
            }
    
            /* ip register not restored yet? */
            if (domain->org_ip)
            {
                /* restore ip register */
                VMPROBE_PERF_START();
                regs->eip = domain->org_ip;
                dbgprint("original ip %x restored in dom%d for the last time\n",
                    regs->eip, domain->id);
                domain->org_ip = 0;
                VMPROBE_PERF_STOP("vmprobes resets ip register in domU");
            }
       
               VMPROBE_PERF_START();
            set_regs(domain->id, &ctx);
            VMPROBE_PERF_STOP("vmprobes sets registers in domU");

            VMPROBE_PERF_START();
            /* turn debugging mode off */
            set_debugging(domain->id, false);
            dbgprint("debugging unset in dom%d for the last time\n", 
                domain->id);
            VMPROBE_PERF_STOP("vmprobes unsets debugging in domU");
        }
    }

    return 0;
}

vmprobe_handle_t
register_vmprobe(domid_t domid,
                 unsigned long vaddr,
                 vmprobe_handler_t pre_handler,
                 vmprobe_handler_t post_handler)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;
    int ret;

    if (domid <= 0 || !vaddr)
        return -1;
    
    if (domain_paused(domid))
    {
        fprintf(stderr, "dom%d currently paused\n", domid);
        return -EPERM;
    }
    
    /* initialize vmprobes library at the first probe registration attempt */
    if (list_empty(&domain_list))
    {
        if ((ret = init_vmprobes()) < 0)
            return ret;
    }

    domain = find_domain(domid);
    if (!domain)
    {
        domain = add_domain(domid);
        if (!domain)
            return -1;
    }
    
    probepoint = find_probepoint(vaddr, domain);
    if (!probepoint)
    {
        probepoint = add_probepoint(vaddr, domain);
        if (!probepoint)
            return -1;
    }
    
    probe = add_probe(pre_handler, post_handler, probepoint);
    if (!probe)
        return -1;
        
    VMPROBE_PERF_START();
    xc_domain_pause(xc_handle, domain->id);
    dbgprint("dom%d paused\n", domain->id);
    VMPROBE_PERF_STOP("vmprobes pauses domU");
    ret = __register_vmprobe(probe);
    if (ret < 0)
    {
        xc_domain_unpause(xc_handle, domain->id);
        unregister_vmprobe(probe->handle);
        return ret;
    }
    VMPROBE_PERF_START();
    xc_domain_unpause(xc_handle, domain->id);
    dbgprint("dom%d unpaused\n", domain->id);
    VMPROBE_PERF_STOP("vmprobes unpauses domU");
    
    VMPROBE_PERF_START();
    return probe->handle;
}

int
unregister_vmprobe(vmprobe_handle_t handle)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;
    int ret;

    probe = find_probe(handle);
    if (!probe)
        return -1;
    probepoint = probe->probepoint; 
    domain = probepoint->domain;
    
    VMPROBE_PERF_START();
    xc_domain_pause(xc_handle, domain->id);
    dbgprint("dom%d paused\n", domain->id);
    VMPROBE_PERF_STOP("vmprobes pauses domU");
    ret = __unregister_vmprobe(probe);
    if (ret < 0)
    {
        xc_domain_unpause(xc_handle, domain->id);
        return ret;
    }
    VMPROBE_PERF_START();
    xc_domain_unpause(xc_handle, domain->id);
    dbgprint("dom%d unpaused\n", domain->id);
    VMPROBE_PERF_STOP("vmprobes unpauses domU");

    remove_probe(probe);
    if (list_empty(&probepoint->probe_list))
    {
        remove_probepoint(probepoint);
        if (list_empty(&domain->probepoint_list))
            remove_domain(domain);
    }

    /* cleanup vmprobes library when the last probe is unregistered */
    if (list_empty(&domain_list))
        cleanup_vmprobes();
    
    return 0;
}

void
run_vmprobes(void)
{
    struct vmprobe_domain *domain = NULL;
    int fd;
    evtchn_port_t port;
    struct timeval tv;
    fd_set inset;
    struct cpu_user_regs *regs;
    vcpu_guest_context_t ctx;

    if (list_empty(&domain_list))
        return;

    fd = xc_evtchn_fd(xce_handle);

    while (!interrupt)
    {
        tv.tv_sec = 1;
        FD_ZERO(&inset);
        FD_SET(fd, &inset);
        
        select(fd + 1, &inset, NULL, NULL, &tv);
        if (FD_ISSET(fd, &inset))
        {
            /* we've got something from eventchn. let's see what it is! */
            port = xc_evtchn_pending(xce_handle);
            if (port == dbg_port)
            {
                /* ok, it's the debugger event */
                list_for_each_entry(domain, &domain_list, list)
                {
                    /* FIXME: domain paused - does this really mean a bp-hit? */
                    if (domain_paused(domain->id))
                    {
                        dbgprint("dom%d paused by %s\n", domain->id,
                            (!domain->sstep_probepoint) ? 
                            "bp-hit" : "sstep-hit");
#ifdef VMPROBE_BENCHMARK
                        if (domain->sstep_probepoint)
                        {
                            VMPROBE_PERF_STOP("vmprobes gets control back "
                                "after sstep-hit");
                        }
                        else
                        {
                            VMPROBE_PERF_STOP("vmprobes gets control back "
                                "after bp-hit");
                        }
#endif /* VMPROBE_BENCHMARK */
                        VMPROBE_PERF_START();
                        regs = get_regs(domain->id, &ctx);
                        VMPROBE_PERF_STOP("vmprobes obtains registers from "
                            "domU");

                        if (!domain->sstep_probepoint)
                            handle_bphit(domain, regs);
                        else
                            handle_sstep(domain, regs);
                        
                        VMPROBE_PERF_START();
                        set_regs(domain->id, &ctx);
                        VMPROBE_PERF_STOP("vmprobes sets registers to domU");
                        
                        VMPROBE_PERF_START();
                        xc_domain_unpause(xc_handle, domain->id);
                        dbgprint("dom%d unpaused\n", domain->id);
                        VMPROBE_PERF_STOP("vmprobes unpauses domU");
        
                        VMPROBE_PERF_START(); /* stops at bp-hit or sstep-hit */
                    }
                }
            }
            
            xc_evtchn_unmask(xce_handle, port);
        }
    }
}

void
stop_vmprobes(void)
{
    int fd;

    interrupt = true;

    /* close the fd to make the select() in run_vmprobes() return */
    fd = xc_evtchn_fd(xce_handle);
    close(fd);
}

int
disable_vmprobe(vmprobe_handle_t handle)
{
    struct vmprobe *probe;

    probe = find_probe(handle);
    if (!probe)
        return -1;
    
    probe->disabled = true;
    return 0;
}

int
enable_vmprobe(vmprobe_handle_t handle)
{
    struct vmprobe *probe;

    probe = find_probe(handle);
    if (!probe)
        return -1;
    
    probe->disabled = false;
    return 0;
}

int
vmprobe_enabled(vmprobe_handle_t handle)
{
    struct vmprobe *probe;

    probe = find_probe(handle);
    if (!probe)
        return -1;
    
    return (!probe->disabled);
}

unsigned long
vmprobe_vaddr(vmprobe_handle_t handle)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;

    probe = find_probe(handle);
    if (!probe)
        return 0;
    
    probepoint = probe->probepoint;
    if (!probepoint)
        return 0;

    return (probepoint->vaddr);
}

domid_t
vmprobe_domid(vmprobe_handle_t handle)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;

    probe = find_probe(handle);
    if (!probe)
        return 0;
    
    probepoint = probe->probepoint;
    if (!probepoint)
        return 0;

    domain = probepoint->domain;
    if (!domain)
        return 0;

    return domain->id;
}

xa_instance_t *
vmprobe_xa_instance(vmprobe_handle_t handle)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;

    probe = find_probe(handle);
    if (!probe)
        return NULL;
    
    probepoint = probe->probepoint;
    if (!probepoint)
        return NULL;

    domain = probepoint->domain;
    if (!domain)
        return NULL;

    return &domain->xa_instance;
}

#include "vmprobes_arch.c"
