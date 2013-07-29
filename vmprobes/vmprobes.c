/*
 * Copyright (c) 2011-2013 The University of Utah
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

#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>

#include <xenctrl.h>
#ifdef ENABLE_XENACCESS
#include "xenaccess/xenaccess.h"
#include "xenaccess/xa_private.h"
#endif
#ifdef ENABLE_LIBVMI
#include <libvmi/libvmi.h>
#endif

#include "list.h"
#include "cqueue.h"
#include "vmprobes.h"
#include "private.h"

static int vmprobes_debug_level = -1;
char *global_state = "INUSER";

void vmprobes_set_debug_level(int level,int xa_level)
{
#ifdef ENABLE_XENACCESS
#ifdef XA_DEBUG
    xa_set_debug_level(xa_level);
#endif
#endif
    vmprobes_debug_level = level;
}

#ifdef VMPROBE_DEBUG
void _vmprobes_debug(int level,char *format,...) {
    va_list args;
    if (vmprobes_debug_level < level)
	return;
    va_start(args, format);
    vfprintf(stderr, format, args);
    fflush(stderr);
    va_end(args);
}
#endif

#define __insert_code(probepoint,opcode_list,opcode_list_len) \
    (arch_insert_code((probepoint),(opcode_list),(opcode_list_len),0,0))
#define __remove_code(probepoint) (arch_remove_code(probepoint))
#define __insert_breakpoint(probepoint) (arch_insert_breakpoint(probepoint))
#define __remove_breakpoint(probepoint) (arch_remove_breakpoint(probepoint))
#define __in_singlestep(regs)        	(arch_in_singlestep(regs))
#define __enter_singlestep(regs)        (arch_enter_singlestep(regs))
#define __leave_singlestep(regs)        (arch_leave_singlestep(regs))
#define __get_org_ip(regs)              (arch_get_org_ip(regs))
#define __reset_ip(regs)                (arch_reset_ip(regs))
#define __get_cur_sp(regs)              (arch_get_cur_sp(regs))
#define __hash_long(val,bits)           (arch_hash_long(val,bits))

static struct vmprobe *probe_list[VMPROBE_MAX];
static struct cqueue handle_queue;
static struct cqueue action_handle_queue;
static struct vmprobe_action *probe_action_list[VMPROBE_ACTION_MAX];

LIST_HEAD(probepoint_list);
LIST_HEAD(domain_list);

#ifdef XENCTRL_HAS_XC_INTERFACE
typedef xc_interface * XC_HANDLE;
static xc_interface *xc_handle = NULL;
static xc_interface *xce_handle = NULL;
#define XC_IF_INVALID (NULL)
#else
typedef int XC_HANDLE;
static int xc_handle = -1;
static int xce_handle = -1;
#define XC_IF_INVALID (-1)
#endif

static bool stop = 0;
static bool interrupt = 0;
static int interrupt_sig = -1;
static evtchn_port_t dbg_port = -1;

/* Returns true if this probe is the only one associated with the probepoint */
static inline bool
only_probe_left(struct vmprobe *probe)
{
    return ((probe->probepoint->probe_list.next == &probe->node) &&
            (probe->probepoint->probe_list.prev == &probe->node));
}

/* Returns true if this probepoint is the only one associated with the dom */
static inline bool
only_probepoint_left(struct vmprobe_probepoint *probepoint)
{
    return ((probepoint->domain->probepoint_list.next == &probepoint->node) &&
            (probepoint->domain->probepoint_list.prev == &probepoint->node));
}

/* like domain_exists, but goes straight to the hypervisor for info */
static inline bool
domain_alive(domid_t domid)
{
    xc_dominfo_t dominfo;
    bool rc;

    assert(xc_handle != XC_IF_INVALID);
    rc = ((xc_domain_getinfo(xc_handle, domid, 1, &dominfo) == 1) &&
	  (dominfo.domid == domid) &&
	  dominfo.dying == 0 && dominfo.crashed == 0);
    return rc;
}

static inline bool
domain_paused(domid_t domid)
{
    xc_dominfo_t dominfo;

    assert(xc_handle != XC_IF_INVALID);
    return ((xc_domain_getinfo(xc_handle, domid, 1, &dominfo) == 1) &&
            (dominfo.domid == domid) &&
            dominfo.paused);
}

static inline int
get_vcpu(domid_t domid)
{
    xc_dominfo_t dominfo;

    assert(xc_handle != XC_IF_INVALID);
    xc_domain_getinfo(xc_handle, domid, 1, &dominfo);
    return dominfo.max_vcpu_id;
}

static inline struct cpu_user_regs *
get_regs(domid_t domid, vcpu_guest_context_t *ctx)
{
    assert(xc_handle != XC_IF_INVALID);
    if (xc_vcpu_getcontext(xc_handle, domid, get_vcpu(domid), ctx))
        return NULL;
    return &ctx->user_regs;
}

static inline int
set_regs(domid_t domid, vcpu_guest_context_t *ctx)
{
    assert(xc_handle != XC_IF_INVALID);
    if (xc_vcpu_setcontext(xc_handle, domid, get_vcpu(domid), ctx))
        return -1;
    return 0;
}

static void unregister_vmprobe_batch_internal(void) {
    vmprobe_handle_t handlelist[VMPROBE_MAX];
    struct vmprobe_domain *domain;
    struct vmprobe_domain *tdomain;
    int handle;

    list_for_each_entry_safe(domain, tdomain, &domain_list, list) {
	// setup a list for this domain:
	for (handle = 0; handle < VMPROBE_MAX; handle++) {
	    handlelist[handle] = -1;
	    if (probe_list[handle] 
		&& domain->id == probe_list[handle]->probepoint->domain->id) {
		handlelist[handle] = handle;
	    }
	}

	// batch unregister:
	unregister_vmprobe_batch(domain->id,handlelist,VMPROBE_MAX);
    }
}

#ifdef VMPROBE_SIGNAL
static struct handlers {
    int caught;
    struct sigaction oaction;
} handlers[_NSIG];

static void
signal_handler(int sig)
{
    vmprobe_handle_t handle;
    char *ostate = global_state;

    global_state = "INSIG";

    VMPROBE_PERF_STOP("vmprobes gets control back by interrupt");
    VMPROBE_PERF_NEXT();

    stop = true;
    interrupt = true;
    interrupt_sig = sig;

    // don't recurse
    if (handlers[sig].caught) {
	sigaction(sig, &handlers[sig].oaction, NULL);
	handlers[sig].caught = 0;
    }

    debug(0,"got signal %d in state %s, reset handler to %p\n",
	  sig, ostate, handlers[sig].oaction.sa_handler);

    if (0 && sig == SIGSEGV) {
        for (handle = 0; handle < VMPROBE_MAX; handle++)
            unregister_vmprobe(handle);
    }
    else {
        unregister_vmprobe_batch_internal();
    }

    debug(0,"probes forcefully unregistered\n");

    VMPROBE_PERF_PRINT();

    raise(sig);

    global_state = ostate;
}

static inline void
_sethandler(struct sigaction *act, int sig)
{
    if (sigaction(sig, act, &handlers[sig].oaction) == 0) {
	if (handlers[sig].oaction.sa_handler == SIG_IGN)
	    sigaction(sig, &handlers[sig].oaction, NULL);
	else
	    handlers[sig].caught = 1;
    }
}

static void
signal_interrupt(int on)
{
    struct sigaction act;

    /* restore default settings */
    if (!on) {
	int i;

	for (i = 0; i < sizeof(handlers) / sizeof(handlers[0]); i++) {
	    if (handlers[i].caught) {
		sigaction(i, &handlers[i].oaction, NULL);
		handlers[i].caught = 0;
	    }
	}
	return;
    }

    memset(&act, 0, sizeof(act));
    act.sa_handler = signal_handler;

    _sethandler(&act, SIGPIPE);
    _sethandler(&act, SIGQUIT);
    _sethandler(&act, SIGINT);
    _sethandler(&act, SIGABRT);
    _sethandler(&act, SIGHUP);
    _sethandler(&act, SIGILL);
    _sethandler(&act, SIGFPE);
    _sethandler(&act, SIGSEGV);
    _sethandler(&act, SIGTERM);
}
#endif /* VMPROBE_SIGNAL */

static XC_HANDLE
init_evtchn(evtchn_port_t *dbg_port)
{
    XC_HANDLE evtchn;
    int port;
    
#ifdef XENCTRL_HAS_XC_INTERFACE
    evtchn = xc_evtchn_open(NULL, 0);
#else
    evtchn = xc_evtchn_open();
#endif
    if (evtchn == XC_IF_INVALID) {
        perror("failed to open evtchn device");
        return evtchn;
    }
    
    port = xc_evtchn_bind_virq(evtchn, VIRQ_DEBUGGER);
    if (port < 0) {
        perror("failed to bind debug virq port");
        xc_evtchn_close(evtchn);
        return XC_IF_INVALID;
    }
    
    *dbg_port = port;
    return evtchn;
}

#if 0
static XC_HANDLE
reinit_evtchn(evtchn_port_t *dbg_port)
{
    XC_HANDLE evtchn;
    int port;
    
#ifdef XENCTRL_HAS_XC_INTERFACE
    evtchn = xc_evtchn_open(NULL, 0);
#else
    evtchn = xc_evtchn_open();
#endif
    if (evtchn == XC_IF_INVALID) {
        perror("failed to open evtchn device");
        return evtchn;
    }
    port = xc_evtchn_bind_virq(evtchn, VIRQ_DEBUGGER);
    if (port < 0) {
        perror("warning: failed to bind debug virq port");
    }
    else {
	*dbg_port = port;
    }
    
    return evtchn;
}
#endif

static int
set_debugging(domid_t domid, bool enable)
{
    struct xen_domctl domctl;

    domctl.cmd = XEN_DOMCTL_setdebugging;
    domctl.domain = domid;
    domctl.u.setdebugging.enable = enable;
    
    if (xc_domctl(xc_handle, &domctl))
        return -1;
    
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
    
    if (cqueue_empty(&handle_queue)) {
        error("total number of probes cannot exceed %d\n",VMPROBE_MAX);
        return NULL;
    }

    probe = (struct vmprobe *) malloc( sizeof(*probe) );
    if (!probe) {
        error("failed to allocate a new probe\n");
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
    
    debug(0,"probe %d added\n", probe->handle);
    return probe;
}

static void
remove_probe(struct vmprobe *probe)
{
    vmprobe_handle_t handle;
    vmprobe_action_t *action;
    vmprobe_action_t *tmp_action;

    /* destroy any actions it might have */
    list_for_each_entry_safe(action,tmp_action,
                 &probe->probepoint->action_list,node) {
	if (probe == action->probe)
	    action_destroy(action->handle);
    }

    list_del(&probe->node);
    
    /* return the handle to the queue */
    handle = probe->handle;
    cqueue_put(&handle_queue, handle);
    probe_list[handle] = NULL;
    
    if (probe->probepoint && probe->probepoint->domain)
	debug(0,"probe %d [dom%d:%lx] removed\n", probe->handle,
	      probe->probepoint->domain->id, probe->probepoint->vaddr);
    else
	debug(0,"probe %d removed\n", probe->handle);

    free(probe);
}

static struct vmprobe_probepoint *
find_probepoint(unsigned long vaddr, struct vmprobe_domain *domain)
{
    struct vmprobe_probepoint *probepoint;

    list_for_each_entry(probepoint, &probepoint_list, list) {
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
    if (!probepoint) {
        error("failed to allocate a new probepoint");
        return NULL;
    }
    
    probepoint->vaddr = vaddr;
    probepoint->domain = domain;
    probepoint->state = VMPROBE_DISABLED;
    probepoint->breakpoint_saved_instr = NULL;
    probepoint->breakpoint_saved_instr_len = 0;
    probepoint->saved_instr = NULL;
    probepoint->saved_instr_len = 0;
    INIT_LIST_HEAD(&probepoint->probe_list);

    INIT_LIST_HEAD(&probepoint->action_list);
    
    list_add(&probepoint->list, &probepoint_list);
    list_add(&probepoint->node, &domain->probepoint_list);

    debug(0,"probepoint [dom%d:%lx] added\n",
      probepoint->domain->id, probepoint->vaddr);
    return probepoint;
}

static void
remove_probepoint(struct vmprobe_probepoint *probepoint)
{
    list_del(&probepoint->node);
    list_del(&probepoint->list);

    list_del(&probepoint->action_list);

    debug(0,"probepoint [dom%d:%lx] removed\n",
	  probepoint->domain->id, probepoint->vaddr);

    free(probepoint);
}

#ifdef ENABLE_LIBVMI
/*
 * There is no eqivilent to these xenaccess functions
 * in libvmi. Getting the name or id of a VM requires
 * a libvmi handle.
 */
#include <xs.h>

uint32_t xa_get_domain_id (char *name)
{
    char **domains = NULL;
    unsigned int size = 0;
    int i = 0;
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    uint32_t domain_id = 0;
    char *tmp = malloc(256);

    xsh = xs_domain_open();
    if (!xsh) {
	fprintf(stderr,"ERROR: failed to open xenstore!\n");
	goto out;
    }
    domains = xs_directory(xsh, xth, "/local/domain", &size);
    for (i = 0; i < size; ++i){
        /* read in name */
        char *idStr = domains[i];
        snprintf(tmp, 256, "/local/domain/%s/name", idStr);
        char *nameCandidate = xs_read(xsh, xth, tmp, NULL);

        // if name matches, then return number
        if (nameCandidate && strncmp(name, nameCandidate, 256) == 0){
            int idNum = atoi(idStr);
            domain_id = (uint32_t) idNum;
            break;
        }

        /* free memory as we go */
        if (nameCandidate) free(nameCandidate);
    }

 out:
    if (tmp) free(tmp);
    if (domains) free(domains);
    if (xsh) xs_daemon_close(xsh);
    return domain_id;
}

char *xa_get_vmpath (int id)
{
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *tmp = NULL;
    char *vmpath = NULL;

    tmp = malloc(100);
    if (NULL == tmp){
        goto error_exit;
    }

    /* get the vm path */
    memset(tmp, 0, 100);
    sprintf(tmp, "/local/domain/%d/vm", id);
    xsh = xs_domain_open();
    vmpath = xs_read(xsh, xth, tmp, NULL);

error_exit:
    /* cleanup memory here */
    if (tmp) free(tmp);
    if (xsh) xs_daemon_close(xsh);

    return vmpath;
}

/* XXX another handy xenaccess function */
char *xa_get_kernel_name (int id)
{
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *vmpath = NULL;
    char *kernel = NULL;
    char *tmp = NULL;

    vmpath = xa_get_vmpath(id);

    /* get the kernel name */
    tmp = malloc(100);
    if (NULL == tmp){
        goto error_exit;
    }
    memset(tmp, 0, 100);
    sprintf(tmp, "%s/image/kernel", vmpath);
    xsh = xs_domain_open();
    kernel = xs_read(xsh, xth, tmp, NULL);

error_exit:
    /* cleanup memory here */
    if (tmp) free(tmp);
    if (vmpath) free(vmpath);
    if (xsh) xs_daemon_close(xsh);

    return kernel;
}

/* XXX made this one up */
char *xa_get_domain_name (int id)
{
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *vmpath = NULL;
    char *name = NULL;
    char *tmp = NULL;

    vmpath = xa_get_vmpath(id);

    /* get the domain name */
    tmp = malloc(100);
    if (NULL == tmp){
        goto error_exit;
    }
    memset(tmp, 0, 100);
    sprintf(tmp, "%s/name", vmpath);
    xsh = xs_domain_open();
    name = xs_read(xsh, xth, tmp, NULL);

error_exit:
    /* cleanup memory here */
    if (tmp) free(tmp);
    if (vmpath) free(vmpath);
    if (xsh) xs_daemon_close(xsh);

    return name;
}
#endif

struct vmprobe_domain *
find_domain(domid_t domid)
{
    struct vmprobe_domain *domain;

    list_for_each_entry(domain, &domain_list, list) {
        if (domain->id == domid)
            return domain;
    }
    
    return NULL;
}

int domain_exists(domid_t domid)
{
    char *vmpath = xa_get_vmpath((int)domid);

    if (vmpath) {
	free(vmpath);
	return 1;
    }
    return 0;
}

int domain_init(domid_t domid,char *sysmapfile) {
    struct vmprobe_domain *vmd;
#ifdef ENABLE_XENACCESS
    FILE *sysmapfh;
    int rc;
    unsigned int addr;
    char sym[256];
    char symtype;

    vmd = find_domain(domid);
    if (!vmd)
	return -1;

    if (!sysmapfile)
	return -2;

    sysmapfh = fopen(sysmapfile,"r");
    if (!sysmapfh) {
	error("could not fopen %s: %s\n",optarg,strerror(errno));
	return -3;
    }

    while ((rc = fscanf(sysmapfh,"%x %c %s255",&addr,&symtype,sym)) != EOF) {
	if (rc < 0) {
	    error("while reading %s: fscanf: %s\n",sysmapfile,strerror(errno));
	    return -5;
	}
	else if (rc != 3)
	    continue;
        
	if (!strcmp("init_task",sym)) {
	    vmd = find_domain(domid);
	    if (vmd->xa_instance.init_task != addr) {
		error("Updating init_task address (to 0x%x) in xenaccess.\n",
		      addr);
		vmd->xa_instance.init_task = addr;
		break;
	    }
	}
        
	if (!strcmp("swapper_pg_dir",sym)) {
	    vmd = find_domain(domid);
	    if (vmd->xa_instance.kpgd != addr) {
		error("Updating kpgd address (to 0x%x)in xenaccess.\n",
		      addr);
		vmd->xa_instance.kpgd = addr;
		break;
	    }
	}
    }
#endif
#ifdef ENABLE_LIBVMI
    vmd = find_domain(domid);
    if (!vmd)
	return -1;
    /* Everything else is done internal to libvmi at init time */
#endif

    return 0;
}

domid_t domain_lookup(char *name) {
    return (domid_t)xa_get_domain_id(name);
}

static struct vmprobe_domain *
add_domain(domid_t domid)
{
    struct vmprobe_domain *domain;
    
    domain = find_domain(domid);
    if (domain)
        return NULL;

    domain = (struct vmprobe_domain *) malloc( sizeof(*domain) );
    if (!domain) {
        error("failed to allocate a new domain");
        return NULL;
    }
    
#ifdef ENABLE_XENACCESS
    /* initialize a xenaccess instance */
    memset(&domain->xa_instance, 0, sizeof(xa_instance_t));
    //domain->xa_instance.page_offset = 0xc0000000;
    domain->xa_instance.os.linux_instance.tasks_offset = 108;
    domain->xa_instance.os.linux_instance.pid_offset = 168;
    domain->xa_instance.os.linux_instance.mm_offset = 132;
    domain->xa_instance.os.linux_instance.pgd_offset = 36;
    domain->xa_instance.sysmap = linux_predict_sysmap_name(domid);
    domain->xa_instance.os_type = XA_OS_LINUX; // currently linux only

    if (xa_init_vm_id_strict(domid, &domain->xa_instance) == XA_FAILURE) {
        error("failed to init xa instance for dom%d\n", domid);
	if (domain->xa_instance.sysmap)
	    free(domain->xa_instance.sysmap);
        free(domain);
        return NULL;
    }
    //domain->xa_instance.init_task = 0xc03542c0;
    domain->xa_instance.kpgd = 0; //0xc03c7684;
#endif
#ifdef ENABLE_LIBVMI
    domain->name = xa_get_domain_name(domid);
    if (domain->name == NULL) {
	error("could not determine kernel for dom%d\n", domid);
	free(domain);
	return NULL;
    }
    if (vmi_init(&domain->vmi_instance,
		 VMI_XEN|VMI_INIT_PARTIAL, domain->name) == VMI_FAILURE) {
        error("failed to init vmi instance for dom%d\n", domid);
	free(domain->name);
	free(domain);
        return NULL;
    }
    domain->kernel_name = xa_get_kernel_name(domid);
    if (domain->kernel_name == NULL) {
	error("could not determine kernel for dom%d\n", domid);
	vmi_destroy(domain->vmi_instance);
	free(domain->name);
	free(domain);
	return NULL;
    }

    /*
     * XXX total hack. Hardwire offsets according to what kernel running
     * in the guest. Okay, the hack part is that we encode the values here
     * rather than using the libvmi config file method.
     * Offsets are:
     *   linux_tasks: offset of "tasks" in task_struct
     *   linux_mm:    offset of "mm" in task_struct
     *   linux_pid:   offset of "pid" in task_struct
     *   linux_pgd:   offset of "pgd" in mm_struct
     * Values below came from running gdb on the appropriate kernel; e.g.
     *   p &((struct task_struct *)0)->tasks
     */
    {
	struct {
	    char *kpath;
	    char *sysmap;
	    uint32_t tasks, mm, pid, pgd;
	    int bitness;
	} vmimap[] = {
	    /* Xen 4.1 + Ubuntu 12 + Linux 3.8.4 64-bit */
	    {
		"/boot/vmlinuz-3.8.4",
		"/boot/System.map-3.8.4",
		0x260, 0x298, 0x2d4, 0x50,
		64
	    },
	    /* Xen 4.1 + Ubuntu 12 + Linux 3.2.16 64-bit */
	    {
		"/boot/vmlinuz-3.2.16emulab1",
		"/boot/System.map-3.2.16emulab1",
		0x238, 0x270, 0x2ac, 0x50,
		64
	    },
	    /* Xen 3.1 + Fedora 8 + Linux 2.6.18.8 32-bit PAE */
	    {
		"/boot/vmlinuz-2.6.18.8-xenU",
		"/boot/System.map-2.6.18.8-xenU",
		0x6c, 0x84, 0xa8, 0x24,
		32
	    },
	    /* Xen 3.0 TT + Fedora 8 + Linux 2.6.18 32-bit PAE */
	    {
		"/boot/vmlinuz-2.6.18-xenU",
		"/boot/System.map-2.6.18-xenU",
		0x6c, 0x84, 0xa8, 0x24,
		32
	    },
	    {
		NULL, NULL, 0, 0, 0, 0, 0
	    }
	}, *vptr;
	char str[128];

	for (vptr = vmimap; vptr->kpath != NULL; vptr++)
	    if (strcmp(vptr->kpath, domain->kernel_name) == 0)
		break;

	if (vptr->kpath == NULL) {
	    error("unrecognized kernel %s for dom%d\n",
		  domain->kernel_name, domid);
	    vmi_destroy(domain->vmi_instance);
	    free(domain->kernel_name);
	    free(domain->name);
	    free(domain);
	    return NULL;
	}

	snprintf(str, sizeof str,
		 "{ostype=\"Linux\"; sysmap=\"%s\"; linux_tasks=0x%x; linux_mm=0x%x; linux_pid=0x%x; linux_pgd=0x%x;}",
		 vptr->sysmap, vptr->tasks, vptr->mm, vptr->pid, vptr->pgd);

	if (vmi_init_complete(&domain->vmi_instance, str) == VMI_FAILURE) {
	    error("failed to complete init of vmi instance for dom%d\n",
		  domid);
	    vmi_destroy(domain->vmi_instance);
	    free(domain->kernel_name);
	    free(domain->name);
	    free(domain);
	    return NULL;
	}

	debug(2, "dom%d vmi_init done with config:\n%s\n", domid, str);
    }
#endif

    domain->id = domid;
    domain->org_ip = 0;
    domain->sstep_probepoint = NULL;
    INIT_LIST_HEAD(&domain->probepoint_list);
    
    domain->regs = NULL;
    memset(&domain->ctx, 0, sizeof(domain->ctx));

    list_add(&domain->list, &domain_list);

    debug(0,"dom%d added\n", domain->id);

    return domain;
}

static void
remove_domain(struct vmprobe_domain *domain)
{
    list_del(&domain->list);

#ifdef ENABLE_XENACCESS
    xa_destroy(&domain->xa_instance);

    if (domain->xa_instance.sysmap)
	free(domain->xa_instance.sysmap);
#endif
#ifdef ENABLE_LIBVMI
    vmi_destroy(domain->vmi_instance);
    free(domain->name);
    free(domain->kernel_name);
#endif

    debug(0,"dom%d removed\n", domain->id);

    free(domain);
}

/*
 * Either handle_bphit or handle_sstep can call us.  If it's a bphit and
 * we haven't run any actions yet, it's the first time hitting this
 * probepoint breakpoint, and we should start running all the actions we
 * can.
 *
 * Some actions can be run in a loop without modifying code.  Do all
 * those we can immediately.  If we modify code, do the modify and
 * single-step *at least once* (so we can restore the probepoint
 * breakpoint), then restore the breakpoint, then stay in or leave
 * single-step mode according to what the action needs.
 *
 *
 */
static int handle_actions(struct vmprobe_probepoint *probepoint,
              struct cpu_user_regs *regs)
{
    struct vmprobe_action *action;
    struct vmprobe_opcode *retop[1];
    int have_action = 0;

    /* 
     * Reset all the has executed flags so we know which actions are
     * still needing to run for this probepoint.
     */
    if (probepoint->state == VMPROBE_BP_SET) {
	debug(1,"resetting action execution flags for new action pass\n");
	list_for_each_entry(action,&probepoint->action_list,node) {
	    action->executed_this_pass = 0;
	}
	
	probepoint->action = NULL;
	probepoint->action_obviates_orig = 0;
	probepoint->action_requires_sstep = 0;
    }

    /*
     * If we need to keep stepping through this action, OR if it is
     * done, but there are more actions to do... then do them right
     * away!
     */
    if (probepoint->state == VMPROBE_ACTION_RUNNING) {
	/* XXX: check later if other kinds are "done" */
	if (1 || probepoint->action->type == VMPROBE_ACTION_RETURN) {
	    /* restore old code (i.e., the breakpoint and anything else) */
	    debug(1,"action finished at [dom%d:%lx]; restoring code\n",
		  probepoint->domain->id, probepoint->vaddr);
	    __remove_code(probepoint);
	    probepoint->state = VMPROBE_ACTION_DONE;
	}
	else {
	    debug(1,"action single step continues at [dom%d:%lx]\n",
		  probepoint->domain->id, probepoint->vaddr);
	    return 1;
	}
    }

    if (list_empty(&probepoint->action_list)) {
	return 0;
    }

    VMPROBE_PERF_START();
    /*
     * If there is a "current" action, we want to continue with the action
     * after that. Otherwise we want to start with the first action on the
     * list.
     *
     * XXX the "otherwise" case is why the first param of the list_entry
     * is strange: we treat the header embedded in the probepoint struct
     * as though it were embedded in an action struct so that when the
     * list_blahblah_continue() operator takes the "next" element, it
     * actually gets the first action on the probepoint list. This is a
     * note to myself so that I don't try to "fix" this code again,
     * thereby breaking it!
     */
    if (probepoint->action) 
	action = probepoint->action;
    else 
	action = list_entry(&probepoint->action_list,typeof(*action),node);
    list_for_each_entry_continue(action,&probepoint->action_list,node) {
	if (action->probe->disabled || action->executed_this_pass)
	    continue;

	if (action->type == VMPROBE_ACTION_CUSTOMCODE) {
	    /*
	     * Need to:
	     *  - copy code in
	     *  - single step until we're to the IP of
	     *    breakpoint+codelen, then restore orig code and BP;
	     *  <OR>
	     *  - restore breakpoint and just let code exec (no
	     *    post handler or any other actions!)
	     */
	}
	else if (action->type == VMPROBE_ACTION_RETURN) {
	    if (probepoint->action_obviates_orig) {
		printf("WARNING: cannot run return action; something else"
		       " already changed control flow!\n");
		continue;
	    }

	    /*
	     * Break out of this loop, and don't do any more
	     * actions.  This action is the final one.
	     */
	    ++have_action;
	    action->executed_this_pass = 1;

	    regs->eax = action->detail.retval;
	    /* put a ret in for the breakpoint, then single step */
	    retop[0] = &RETURN;
	    __insert_code(probepoint,retop,1);
	    debug(1,"ret inserted at [dom%d:%lx]\n",
		  probepoint->domain->id, probepoint->vaddr);

	    probepoint->action_obviates_orig = 1;
	    probepoint->action_requires_sstep = 1;
	    probepoint->action = action;
	    probepoint->state = VMPROBE_ACTION_RUNNING;

	    break;
	}
    }
    VMPROBE_PERF_STOP("vmprobes executes actions");

    return have_action;
}

static int
handle_bphit(struct vmprobe_domain *domain)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;
    int have_action = 0;
    struct cpu_user_regs *regs;

    regs = domain->regs;
    assert(regs != NULL);

    probepoint = find_probepoint(__get_org_ip(regs), domain);
    if (!probepoint)
        return -1;

    debug(2,"bphit probepoint [dom%d:%lx]\n",domain->id,probepoint->vaddr);

    if (probepoint->state == VMPROBE_BP_SET) {
        /* save the original ip value in case something bad happens */
        domain->org_ip = __get_org_ip(regs);

        VMPROBE_PERF_START();
        
        /*
         * Run pre-handlers if we have encountered our breakpoint for the
         * first time on this pass (which means we should not have an
         * action set!)
         */
        list_for_each_entry(probe, &probepoint->probe_list, node) {
            if (!probe->disabled && probe->pre_handler)
                probe->disabled = probe->pre_handler(probe->handle, regs);
        }

        VMPROBE_PERF_STOP("vmprobes executes pre-handlers");

        VMPROBE_PERF_START();
        
        /* restore ip register */
        __reset_ip(regs);
        domain->org_ip = 0;
        
        VMPROBE_PERF_STOP("vmprobes resets ip register in domU");
        debug(2,"original ip %lx restored in dom%d\n", regs->eip, domain->id);
    }

    /*
     * If we are running an action, handle our actions now.
     */
    if (probepoint->state == VMPROBE_BP_SET
            || probepoint->state == VMPROBE_ACTION_RUNNING) {
        have_action = handle_actions(probepoint,regs);
    }

    if (!have_action && !probepoint->action_obviates_orig) {
        VMPROBE_PERF_START();

        probepoint->state = VMPROBE_REMOVING;
        
        /* restore the original instruction */
        __remove_breakpoint(probepoint);
        
        probepoint->state = VMPROBE_DISABLED;
        
        VMPROBE_PERF_STOP("vmprobes removes breakpoint in domU");
        debug(2,"bp removed at [dom%d:%lx]\n", domain->id, probepoint->vaddr);
    }

    /* XXX: in future, check to see if action requires single step mode! */
    if (!interrupt 
            && ((have_action && probepoint->action_requires_sstep)
                || (!have_action && !probepoint->action_obviates_orig))) {
        /* turn singlestep mode on */
        VMPROBE_PERF_START();
        __enter_singlestep(regs);
        debug(2,"single step set in dom%d\n", domain->id);
        domain->sstep_probepoint = probepoint;
        VMPROBE_PERF_STOP("vmprobes sets singlestep in domU");
    }

    return 0;
}

static void
handle_sstep(struct vmprobe_domain *domain)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_action *action;
    struct vmprobe_action *taction;
    struct cpu_user_regs *regs;

    regs = domain->regs;
    assert(regs != NULL);

    probepoint = domain->sstep_probepoint;

    if (handle_actions(probepoint,regs)) {
	debug(1,"found actions to handle\n");
	if (!probepoint->action_requires_sstep) {
	    VMPROBE_PERF_START();
	    __leave_singlestep(regs);
	    debug(2,"single step unset in dom%d during action handling\n",
		  domain->id);
	    domain->sstep_probepoint = NULL;
	    VMPROBE_PERF_STOP("vmprobes unsets singlestep in domU");
	}

	/* run the rest of the actions before the post handlers */
	return;
    }

    VMPROBE_PERF_START();
    
    /*
     * Run post-handlers
     */
    list_for_each_entry(probe, &probepoint->probe_list, node) {
	if (!probe->disabled && probe->post_handler)
	    probe->disabled = probe->post_handler(probe->handle, regs);
    }
    
    VMPROBE_PERF_STOP("vmprobes executes post-handlers");

    if (!interrupt) {
	VMPROBE_PERF_START();
        
	/* turn singlestep mode off */
	__leave_singlestep(regs);
	domain->sstep_probepoint = NULL;
        
	VMPROBE_PERF_STOP("vmprobes unsets singlestep in domU");
	debug(2,"single step unset in dom%d\n", domain->id);
        
	VMPROBE_PERF_NEXT(); // next round of performance check

	if (!probepoint->action_obviates_orig) {
	    VMPROBE_PERF_START();
        
	    probepoint->state = VMPROBE_INSERTING;
        
	    /* inject a breakpoint for the next round */
	    __insert_breakpoint(probepoint);
        
	    probepoint->state = VMPROBE_BP_SET;
        
	    VMPROBE_PERF_STOP("vmprobes injects breakpoint back in domU");
	    debug(2,"bp set at [dom%d:%lx]\n", domain->id, probepoint->vaddr);
	}
	else {
	    /* Rely on obviating code to restore the breakpoint :) */
	    probepoint->state = VMPROBE_BP_SET;
	}
    }

    /* cleanup oneshot actions! */
    list_for_each_entry_safe(action,taction,&probepoint->action_list,node) {
	if (action->whence == VMPROBE_ACTION_ONESHOT)
	    action_cancel(action->handle);
    }

    return;
}

static void
cleanup_vmprobes(void)
{
    int ret;

    cqueue_cleanup(&handle_queue);
    cqueue_cleanup(&action_handle_queue);
    
    ret = xc_evtchn_unbind(xce_handle,(evtchn_port_t)dbg_port);
    if (ret)
        perror("failed to unbind debug virq port");
    dbg_port = -1;

    ret = xc_evtchn_close(xce_handle);
    if (ret)
        perror("failed to close event channel");
    xce_handle = XC_IF_INVALID;
    
    ret = xc_interface_close(xc_handle);
    if (ret)
        perror("failed to close xc interface");
    xc_handle = XC_IF_INVALID;

#ifdef VMPROBE_SIGNAL
    signal_interrupt(0);
#endif

    debug(0,"vmprobes uninitialized\n");
}

static int
init_vmprobes(void)
{
    vmprobe_handle_t handle;
    vmprobe_action_handle_t action_handle;
    
    if (xc_handle != XC_IF_INVALID) {
	debug(1, "vmprobes already initialized\n");
        return -1;
    }

#ifdef VMPROBE_SIGNAL
    signal_interrupt(1);
#endif
    
    VMPROBE_PERF_RESET();

#ifdef XENCTRL_HAS_XC_INTERFACE
    xc_handle = xc_interface_open(NULL, NULL, 0);
#else
    xc_handle = xc_interface_open();
#endif
    if (xc_handle == XC_IF_INVALID) {
        perror("failed to open xc interface");
        return -1;
    }

    xce_handle = init_evtchn(&dbg_port);
    if (xce_handle == XC_IF_INVALID) {
        perror("failed to open event channel\n");
        cleanup_vmprobes();
        return -1;
    }

    if (!cqueue_init(&handle_queue, VMPROBE_MAX)) {
        perror("failed to init probe handle queue");
        cleanup_vmprobes();
        return -ENOMEM;
    }
    
    /* fill all handles in the queue */
    for (handle = 0; handle < VMPROBE_MAX; handle++)
        cqueue_put(&handle_queue, handle);

    if (!cqueue_init(&action_handle_queue, VMPROBE_ACTION_MAX)) {
        perror("failed to init probe action handle queue");
        cleanup_vmprobes();
        return -ENOMEM;
    }
    for (action_handle = 0; action_handle < VMPROBE_ACTION_MAX; action_handle++)
        cqueue_put(&action_handle_queue, action_handle);

    interrupt = false;
    debug(0,"vmprobes initialized\n");
    return 0;
}

static int
reinit_vmprobes(void)
{
    if (xc_handle != XC_IF_INVALID)
        return -1; // xc interface already open

    VMPROBE_PERF_RESET();

#ifdef XENCTRL_HAS_XC_INTERFACE
    xc_handle = xc_interface_open(NULL, NULL, 0);
#else
    xc_handle = xc_interface_open();
#endif
    if (xc_handle == XC_IF_INVALID) {
        perror("failed to open xc interface");
        return -1;
    }

    xce_handle = init_evtchn(&dbg_port);
    if (xce_handle == XC_IF_INVALID) {
        cleanup_vmprobes();
        return -1;
    }

    interrupt = false;
    debug(0,"vmprobes reinitialized\n");
    return 0;
}

static int
__register_vmprobe(struct vmprobe *probe)
{
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;
#ifdef ENABLE_XENACCESS
    char *pages;
    uint32_t offset;
#endif
    int ret;

    probepoint = probe->probepoint;
    domain = probepoint->domain;
    
    VMPROBE_PERF_START();
    
    /* turn debugging mode on */
    ret = set_debugging(domain->id, true);
    if (ret < 0)
        return ret;
    
    VMPROBE_PERF_STOP("vmprobes sets debugging in domU");
    debug(2,"debugging set in dom%d for probe %d registration\n",
      domain->id, probe->handle);

    /* check if the probepoint is restored; we do not want to backup a
       previously inserted breakpoint */
    if (probepoint->state != VMPROBE_DISABLED)
        return 0;  // return success, the probepoint is already being managed

    VMPROBE_PERF_START();

    probepoint->state = VMPROBE_INSERTING;

    /* FIXME: David's code for batched probe registration?
       -- make this a function; it will shorten the code */
    memset(probe->vbytes,0,64);
#ifdef ENABLE_XENACCESS
    pages = xa_access_kernel_va_range(&domain->xa_instance, 
            probepoint->vaddr, 
            64, 
            &offset, 
            PROT_READ);
    if (pages) {
	int np = 1;

        memcpy(probe->vbytes,pages+offset,64);

	if (offset + 64 > domain->xa_instance.page_size)
            np++;
	if (munmap(pages, np * domain->xa_instance.page_size))
	    warning("munmap of %p failed\n", pages);
    }
#endif
#ifdef ENABLE_LIBVMI
    ret = vmi_read_va(domain->vmi_instance, probepoint->vaddr, 0,
		      probe->vbytes, 64);
    if (ret != 64)
	warning("dom%d: incomplete read (%d of %d) at 0x%lx\n",
		domain->id, ret, 64, probepoint->vaddr);
#endif

    /* backup the original instruction */
    /* inject a breakpoint at the probe-point */
    ret = __insert_breakpoint(probepoint);
    if (ret < 0) {
        probepoint->state = VMPROBE_DISABLED;
        return ret;
    }
#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    /* XXX: I have no idea if this is a good place to add this code
     * XXX: someone should implement proper error handling for the case Xen says "no"
     * XXX: someone should implement probe "unregister" code somewhere... I have no idea where
     */
    debug(2,"registering probe [dom%d:%lx] with Xen\n", domain->id, probepoint->vaddr);
    ret = xc_ttd_vmi_add_probe(xc_handle, domain->id, probepoint->vaddr);
    if (ret) {
        perror("Failed to register probe with Xen\n");
        probepoint->state = VMPROBE_DISABLED;
        return ret;
    }
#endif

    probepoint->state = VMPROBE_BP_SET;

    VMPROBE_PERF_STOP("vmprobes injects breakpoint in domU");
    debug(2,"bp set at [dom%d:%lx] for the first time\n", 
            domain->id,probepoint->vaddr);

    probe->disabled = false;
    return 0;
}

static void
__dump_probe(struct vmprobe *probe, char *str)
{
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;
#ifdef ENABLE_XENACCESS
    char *pages;
    uint32_t offset;
#endif
    char buf[64];
    int i;

    probepoint = probe->probepoint;
    domain = probepoint->domain;

    memset(buf, 0, 64);
#ifdef ENABLE_XENACCESS
    /* FIXME: David's code for batched probe registration? 
       -- make this a function, it will shorten the code much */
    pages = xa_access_kernel_va_range(&domain->xa_instance, 
            probepoint->vaddr, 
            64, 
            &offset, 
            PROT_READ);
    if (pages) {
	memcpy(buf, pages+offset, 64);
	i = 1;
	if (offset + 64 > domain->xa_instance.page_size)
	    i++;
	if (munmap(pages, i * domain->xa_instance.page_size))
	    warning("munmap of %p failed\n", pages);
    }
#endif
#ifdef ENABLE_LIBVMI
    if (vmi_read_va(domain->vmi_instance, probepoint->vaddr, 0, buf, 64) != 64)
	warning("incomplete read at 0x%lx\n", probepoint->vaddr);
#endif

    if (str)
	printf("%s:\n", str);
    printf("P:");
    for (i = 0; i < 16; ++i) {
	printf(" %08x",*((unsigned int *)&(probe->vbytes[i*4])));
    }
    printf("\nM:");
    for (i = 0; i < 16; ++i) {
	printf(" %08x",*((unsigned int *)(buf + i*4)));
    }
    printf("\n");
    fflush(stdout);
}

/*
 * Undo the domain address space and register state tweaks associated
 * with a probe(point).
 */
static int
__unregister_vmprobe(struct vmprobe *probe)
{
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;
    struct cpu_user_regs *regs = NULL;
    int ret, setregs = 0;

    probepoint = probe->probepoint;
    domain = probepoint->domain;

    /* Must be paused */
    assert(domain_paused(domain->id));

    /*
     * If there are other probes associated with the same probepoint,
     * there is nothing to do.
     */
    if (!only_probe_left(probe))
        return 0;

    /*
     * Get the registers if we need them.
     * We do this early in case it fails. Saves having to recover
     * from a half-cleaned up domain.
     */
    if (probepoint->state == VMPROBE_BP_SET ||
	domain->sstep_probepoint == probepoint) {

	VMPROBE_PERF_START();

	if ((regs = domain->regs) == NULL) {
	    regs = get_regs(domain->id, &domain->ctx);
	    if (regs == NULL) {
		error("unregister: failed to get vcpu registers in dom%d\n",
		      domain->id);
		return -1;
	    }
	}
	else
	    debug(1, "using existing dom%d registers\n", domain->id);

	VMPROBE_PERF_STOP("vmprobes obtains registers from domU");
    }

    /*
     * See if there is a breakpoint set. Three cases:
     *   1. Domain is not at the breakpoint. Here we can just remove
     *      the breakpoint from the address space.
     *   2. Domain is at the breakpoint and we are processing it now.
     *      In this case, the domain org_ip value will be set.
     *      Besides removing the breakpoint, we need to restore the
     *      IP to org_ip.
     *   3. Domain has hit the breakpoint, but we have not processed it.
     *	    Here org_ip won't be set but the domain IP will be at
     *      probepoint location plus the size of the breakpoint.
     *      Again, in addition to removing the breakpoint, we must back
     *      up the IP to the breakpoint location.
     */
    if (probepoint->state == VMPROBE_BP_SET) {
	unsigned long newip;

	/* check for case #3 */
	newip = domain->org_ip;
	if (newip == 0) {
	    assert(regs != NULL);
	    if (probepoint->vaddr == __get_org_ip(regs)) {
		newip = probepoint->vaddr;
		debug(1,"set ip=0x%lx in dom%d after unprocessed breakpoint\n",
		      probepoint->vaddr, domain->id);
	    }
	}

	/* all cases, remove the breakpoint restoring original instruction */
	VMPROBE_PERF_START();

	probepoint->state = VMPROBE_REMOVING;

	if (vmprobes_debug_level > 1)
	    __dump_probe(probe, "Before remove_bp");

	ret = __remove_breakpoint(probepoint);
	if (ret < 0) {
	    probepoint->state = VMPROBE_BP_SET;
	    return ret;
	}

	if (vmprobes_debug_level > 1)
	    __dump_probe(probe, "After remove_bp");

	probepoint->state = VMPROBE_DISABLED;

	VMPROBE_PERF_STOP("vmprobes removes breakpoint in domU");
	debug(1,"bp removed at [dom%d:%lx]\n",
	      domain->id, probepoint->vaddr);

	/* cases #2 or #3, fix up the IP */
	if (newip) {
	    VMPROBE_PERF_START();

	    assert(regs != NULL);
	    regs->eip = newip;
	    domain->org_ip = 0;
	    setregs = 1;

	    VMPROBE_PERF_STOP("vmprobes resets ip register in domU");
	    debug(1,"original ip=0x%x restored in dom%d\n",
		  regs->eip, domain->id);
	}
    }

    /*
     * If we were involved in a single-step related to this probepoint,
     * clear the single-step flag.
     */
    if (domain->sstep_probepoint == probepoint) {
        VMPROBE_PERF_START();

        /* turn singlestep mode off */
	assert(regs != NULL);
        __leave_singlestep(regs);
        domain->sstep_probepoint = NULL;
	setregs = 1;

        VMPROBE_PERF_STOP("vmprobes unsets singlestep in domU");
        debug(1,"sstep unset in dom%d\n", domain->id);
    }
    else if (domain->sstep_probepoint) {
        debug(1,"sstep set for dom%d, but not ours (0x%lx)\n",
	      domain->id, domain->sstep_probepoint->vaddr);
    }

    VMPROBE_PERF_START();

    /*
     * Set the restored register values back to vcpu.
     *
     * XXX we are a tad bit screwed if this fails because we have
     * potentially removed a breakpoint and messed with the single-step
     * state. We need to address this.
     */
    if (setregs && (ret = set_regs(domain->id, &domain->ctx)) != 0) {
        error("unregister: failed to set vcpu registers in dom%d\n",
	      domain->id);    
        return -1;
    }

    VMPROBE_PERF_STOP("vmprobes sets registers in domU");

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    /* XXX: I have no idea if this is a good place to add this code
     * XXX: someone should implement proper error handling for the case Xen says "no"
     */
    debug(2,"unregistering probe [dom%d:%lx] with Xen\n", domain->id, probepoint->vaddr);
    ret = xc_ttd_vmi_remove_probe(xc_handle, domain->id, probepoint->vaddr);
    if (ret) {
        error("Failed to unregister probe with Xen, ret:%d\n", ret);
    }
#endif

    /*
     * If we are the final probepoint in the domain, turn off debugging.
     */
    if (only_probepoint_left(probepoint)) {
	VMPROBE_PERF_START();

	/* turn debugging mode off */
	ret = set_debugging(domain->id, false);
	if (ret) {
	    error("unregister: failed to unset debugging in dom%d\n",
		  domain->id);
	    return -1;
	}

	VMPROBE_PERF_STOP("vmprobes unsets debugging in domU");
	debug(1,"debugging unset in dom%d\n", domain->id);
    }

    return 0;
}

/* 
 * If fail_behavior is not 1 nor 2, stop in our tracks and return.
 * If 1, undo what we've done and return.
 * If 2, skip the failing probe and continue.
 */
int
register_vmprobe_batch(domid_t domid,
               unsigned long *vaddrlist,
               int listlen,
               vmprobe_handler_t pre_handler,
               vmprobe_handler_t post_handler,
               vmprobe_handle_t *handlelist,
               int onfail)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;
    int rc;
    int i;
    int retval = 0;

    if (!handlelist)
	return -1;
    if (!listlen) 
	return 0;
    if (domid <= 0)
        return -1;
    
    /* initialize vmprobes library at the first probe registration attempt */
    /* XXX must be done before domain_paused */
    if (list_empty(&domain_list)) {
        if ((rc = init_vmprobes()) < 0)
            return rc;
    }

    if (domain_paused(domid)) {
        error("dom%d already paused\n", domid);
        return -EPERM;
    }
    
    domain = find_domain(domid);
    if (!domain) {
        domain = add_domain(domid);
        if (!domain) {
	    if (list_empty(&domain_list))
		cleanup_vmprobes();
            return -1;
	}
    }

#if 0
    if (domain_paused(domain->id)) {
	fprintf(stderr, "batch register: dom%d already paused\n", domain->id);
    }
#endif

    VMPROBE_PERF_START();
    if ((rc = xc_domain_pause(xc_handle,domain->id)) != 0) {
	error("dom%d: batch register: cannot pause (%d)\n", domain->id, rc);
	if (list_empty(&domain->probepoint_list)) {
	    remove_domain(domain);
	    if (list_empty(&domain_list))
		cleanup_vmprobes();
	}
	return rc;
    }
    debug(1,"dom%d paused\n",domain->id);
    VMPROBE_PERF_STOP("vmprobes pauses domU");

#if 0
    {
	struct cpu_user_regs *_regs;
	vcpu_guest_context_t _ctx;

	_regs = get_regs(domain->id, &_ctx);
	if (_regs) {
	    fprintf(stderr, "batch register: dom%d paused at 0x%lx\n", domain->id, _regs->eip);
	}
    }
#endif

    for (i = 0; i < listlen; ++i) {
	/* allow sparse lists */
	if (vaddrlist[i] == 0)
	    continue;

	probepoint = find_probepoint(vaddrlist[i],domain);
	if (!probepoint) {
	    probepoint = add_probepoint(vaddrlist[i],domain);
	    if (!probepoint) {
		handlelist[i] = -1;
		if (onfail == 2) {
		    ++retval;
		    continue;
		}
		else if (onfail == 1) {
		    ++retval;
		    goto errunreg;
		}
		else {
		    retval = 1;
		    goto out;
		}
	    }
	}

	probe = add_probe(pre_handler,post_handler,probepoint);
	if (!probe) {
	    if (list_empty(&probepoint->probe_list)) {
		remove_probepoint(probepoint);
		probepoint = NULL;
	    }

	    handlelist[i] = -1;
	    if (onfail == 2) {
		++retval;
		continue;
	    }
	    else if (onfail == 1) {
		++retval;
		goto errunreg;
	    }
	    else {
		retval = 1;
		goto out;
	    }
	}
        
	if (__register_vmprobe(probe) < 0) {
	    remove_probe(probe);
	    probe = NULL;
	    if (list_empty(&probepoint->probe_list)) {
		remove_probepoint(probepoint);
		probepoint = NULL;
	    }

	    handlelist[i] = -1;
	    if (onfail == 2) {
		++retval;
		continue;
	    }
	    else if (onfail == 1) {
		++retval;
		goto errunreg;
	    }
	    else {
		retval = 1;
		goto out;
	    }
	}

	handlelist[i] = probe->handle;
    }
    goto out;

 errunreg:
    for (i = 0; i < listlen; ++i) {
	if (vaddrlist[i] == 0)
	    continue;

	if (handlelist[i] < 0)
	    continue;

	if ((probe = find_probe(handlelist[i]))) {
	    __unregister_vmprobe(probe);

	    remove_probe(probe);
	    probe = NULL;
	}

	assert(domain != NULL);
	if ((probepoint = find_probepoint(vaddrlist[i],domain))) {
	    if (list_empty(&probepoint->probe_list)) {
		remove_probepoint(probepoint);
		probepoint = NULL;
		if (list_empty(&domain->probepoint_list)) {
		    remove_domain(domain);
		    domain = NULL;
		}
	    }
	}
    }

 out:
    VMPROBE_PERF_START();
    xc_domain_unpause(xc_handle, domid);
    debug(1,"dom%d unpaused\n", domid);
    VMPROBE_PERF_STOP("vmprobes unpauses domU");

    /* cleanup vmprobes library when the last probe is unregistered */
    if (list_empty(&domain_list))
        cleanup_vmprobes();

    return retval;
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
    
    /* do not proceed further if the domain is currently paused */
    ret = domain_paused(domid);
    if (ret) {
        error("dom%d currently paused\n", domid);
        return -EPERM;
    }
    
    /* initialize vmprobes library at the first probe registration attempt */
    ret = list_empty(&domain_list);
    if (ret) {
        ret = init_vmprobes();
        if (ret < 0)
            return ret;
    }

    /* add the domain to the list if it is the first time to instrument it */
    domain = find_domain(domid);
    if (!domain) {
        domain = add_domain(domid);
        if (!domain) {
	    if (list_empty(&domain_list))
		;
            return -1;
	}
    }
    
    /* add the probepoint to the list if it is the first time to instrument 
       it */
    probepoint = find_probepoint(vaddr, domain);
    if (!probepoint) {
        probepoint = add_probepoint(vaddr, domain);
        if (!probepoint)
            return -1;
    }
    
    /* add the probe to the list */
    probe = add_probe(pre_handler, post_handler, probepoint);
    if (!probe)
        return -1;
      
    debug(1,"trying to pause dom%d\n", domain->id);
    VMPROBE_PERF_START();
    
#if 0
    if (domain_paused(domain->id)) {
	fprintf(stderr, "register: dom%d already paused\n", domain->id);
    }
#endif

    /* pause the domain */
    ret = xc_domain_pause(xc_handle, domain->id);
    if (ret < 0) {
        error("dom%d: probe register: cannot pause (%d)\n", domain->id, ret);
        goto out_error_domctl;
    }
    
#if 0
    {
	struct cpu_user_regs *_regs;
	vcpu_guest_context_t _ctx;

	_regs = get_regs(domain->id, &_ctx);
	if (_regs) {
	    fprintf(stderr, "register: dom%d paused at 0x%lx\n", domain->id, _regs->eip);
	}
    }
#endif

    VMPROBE_PERF_STOP("vmprobes sets domU to be paused");

    /* inject the probe at the probepoint */
    ret = __register_vmprobe(probe);
    if (ret < 0)
        goto out_error;
    
    debug(1,"trying to unpause dom%d\n", domain->id);
    VMPROBE_PERF_START();
    
    /* unpause the domain */
    ret = xc_domain_unpause(xc_handle, domain->id);
    if (ret < 0) {
        error("failed to unpause dom%d\n", domain->id);
        goto out_error_domctl;
    }
    
    VMPROBE_PERF_STOP("vmprobes sets domU to be unpaused"); 
    VMPROBE_PERF_START();

    /* return the probe handle, unique probe identifier assigned in 
       add_probe() */
    return probe->handle;

out_error:
    if (xc_domain_unpause(xc_handle, domid))
        warning("failed to unpause dom%d\n", domid);

out_error_domctl:
    if (unregister_vmprobe(probe->handle))
        warning("failed to unregister probe %d\n", probe->handle);

    return ret;
}

int
unregister_vmprobe_batch(domid_t domid,
	     vmprobe_handle_t *handlelist,
             int listlen)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;
    int retval = 0;
    int i;

    if (!listlen)
	return 0;

    if (!(domain = find_domain(domid))) 
	return -1;
    
#if 0
    if (domain_paused(domid)) {
	fprintf(stderr, "batch unregister: dom%d already paused\n", domid);
    }
#endif

    VMPROBE_PERF_START();
    if ((i = xc_domain_pause(xc_handle, domid)) != 0) {
        error("dom%d: batch unregister: cannot pause (%d)\n", domid, i);
	return -1;
    }
    debug(1,"dom%d paused\n", domid);
    VMPROBE_PERF_STOP("vmprobes pauses domU");

#if 0
    {
	struct cpu_user_regs *_regs;
	vcpu_guest_context_t _ctx;

	_regs = get_regs(domid, &_ctx);
	if (_regs) {
	    fprintf(stderr, "batch unregister: dom%d paused at 0x%lx\n", domid, _regs->eip);
	}
    }
#endif

    for (i = 0; i < listlen; ++i) {
	/* allow sparse lists */
	if (handlelist[i] < 0)
	    continue;

	if (!(probe = find_probe(handlelist[i]))) {
	    ++retval;
	    continue;
	}

	assert(domain != NULL);
	probepoint = probe->probepoint; 
	if (probepoint->domain != domain) {
	    ++retval;
	    continue;
	}

	if (__unregister_vmprobe(probe) < 0) {
	    ++retval;
	    continue;
	}

	remove_probe(probe);
	probe = NULL;
	if (list_empty(&probepoint->probe_list)) {
	    remove_probepoint(probepoint);
	    probepoint = NULL;
	    if (list_empty(&domain->probepoint_list)) {
		remove_domain(domain);
		domain = NULL;
	    }
	}
    }

    VMPROBE_PERF_START();
    xc_domain_unpause(xc_handle, domid);
    debug(1,"dom%d unpaused\n", domid);
    VMPROBE_PERF_STOP("vmprobes unpauses domU");

    /* make sure we didn't kill the sucker */
    if (!domain_alive(domid)) {
	if (domain) {
	    fprintf(stderr, "pooch screwed: dom%d died during surgery\n",
		    domid);
	    raise(SIGSEGV);
	    pause();
	}
    }

    /* cleanup vmprobes library when the last probe is unregistered */
    if (list_empty(&domain_list))
        cleanup_vmprobes();
    
    return retval;
}

int
unregister_vmprobe(vmprobe_handle_t handle)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;
    int ret;

    /* validate the probe handle */
    probe = find_probe(handle);
    if (!probe)
        return -1;

    probepoint = probe->probepoint; 
    domain = probepoint->domain;
    
    debug(1,"trying to pause dom%d\n", domain->id);
    VMPROBE_PERF_START();
    
#if 0
    if (domain_paused(domain->id)) {
	fprintf(stderr, "unregister: dom%d already paused\n", domain->id);
    }
#endif

    /* pause the domain */
    ret = xc_domain_pause(xc_handle, domain->id);
    if (ret < 0) {
        error("dom%d: probe unregister: cannot pause (%d)\n", domain->id, ret);
        return -1; // this is critical, do not proceed further
    }
    
#if 0
    {
	struct cpu_user_regs *_regs;
	vcpu_guest_context_t _ctx;

	_regs = get_regs(domain->id, &_ctx);
	if (_regs) {
	    fprintf(stderr, "unregister: dom%d paused at 0x%lx\n", domain->id, _regs->eip);
	}
    }
#endif

    VMPROBE_PERF_STOP("vmprobes sets domU to be paused");
    
    /* remove the probe from the probepoint */
    ret = __unregister_vmprobe(probe);
    if (ret < 0) {
        // FIXME: failed to remove the probe, should exit or proceed further?
        // let's do nothing for now.
        warning("failed to remove probe from dom%d\n", domain->id);
    }

    debug(1,"trying to unpause dom%d\n", domain->id);
    VMPROBE_PERF_START();
    
    /* unpause the domain */
    ret = xc_domain_unpause(xc_handle, domain->id);
    if (ret < 0) {
        // FIXME: failed to unpause the domain, should exit or proceed further?
        // let's just print a warning message for now.
        warning("failed to unpause dom%d\n", domain->id);
    }
    
    VMPROBE_PERF_STOP("vmprobes sets domU to be unpaused"); 

    /* remove the probe, related probepoint and domain from the lists */
    remove_probe(probe);
    if (list_empty(&probepoint->probe_list)) {
        remove_probepoint(probepoint);
        if (list_empty(&domain->probepoint_list))
            remove_domain(domain);
    }

    /* cleanup vmprobes library when the last probe is unregistered */
    if (list_empty(&domain_list))
        cleanup_vmprobes();
    
    return 0;
}

static inline struct vmprobe_action *
find_probe_action(vmprobe_action_handle_t action_handle)
{
    if (action_handle < 0 || action_handle >= VMPROBE_ACTION_MAX)
        return NULL;
    
    return probe_action_list[action_handle];
}

int action_sched(vmprobe_handle_t handle,
         vmprobe_action_handle_t action_handle,
         int whence)
{
    struct vmprobe *probe;
    struct vmprobe_action *action;
    struct vmprobe_action *lpc;

    action = find_probe_action(action_handle);
    if (!action) {
	error("action_sched: no such action %d\n",action_handle);
	return -1;
    }

    if (action->probe != NULL) {
	error("action_sched: action %d already associated with probe %d\n",
	      action->handle,handle);
	return -1;
    }

    probe = find_probe(handle);
    if (!probe) {
	error("action_sched: no such probe %d\n",handle);
	return -1;
    }

    /* only allow one return action per probepoint */
    list_for_each_entry(lpc,&probe->probepoint->action_list,node) {
	if (lpc->type == VMPROBE_ACTION_RETURN) {
	    error("action_sched: probepoint for probe %d already has return action %d\n",
		  lpc->probe->handle,lpc->handle);
	    return -1;
	}
    }

    if (whence != VMPROBE_ACTION_ONESHOT && whence != VMPROBE_ACTION_REPEATPRE
	&& whence != VMPROBE_ACTION_REPEATPOST) {
	error("action_sched: unknown whence %d for action %d\n",
	      whence,action_handle);
	return -1;
    }
    action->whence = whence;

    /*
     * Ok, we're safe; add to list!
     */
    list_add_tail(&action->node,&probe->probepoint->action_list);
    action->probe = probe;

    return 0;
}

vmprobe_action_handle_t action_return(unsigned long retval)
{
    vmprobe_action_t *action;

    action = (vmprobe_action_t *)malloc(sizeof(vmprobe_action_t));
    if (!action) {
	error("no memory to allocate probe action\n");
	return -ENOMEM;
    }
    memset((void *)action,0,sizeof(vmprobe_action_t));

    cqueue_get(&action_handle_queue,&action->handle);
    action->type = VMPROBE_ACTION_RETURN;
    action->whence = VMPROBE_ACTION_UNSCHED;
    INIT_LIST_HEAD(&action->node);

    probe_action_list[action->handle] = action;

    action->detail.retval = retval;

    return action->handle;
}

vmprobe_action_handle_t action_code(uint32_t flags,
                    vmprobe_opcode_t **code,
                    uint32_t len)
{
    return (vmprobe_action_handle_t)0;
}

vmprobe_action_handle_t action_regmod(uint8_t regnum,
                      unsigned long regval)
{
    return (vmprobe_action_handle_t)0;
}

vmprobe_action_handle_t action_memmod(char *data,
                      unsigned long len,
                      unsigned long destaddr)
{
    return (vmprobe_action_handle_t)0;
}

void action_cancel(vmprobe_action_handle_t action_handle)
{
    struct vmprobe_action *action;

    action = find_probe_action(action_handle);
    if (!action) {
	error("action_cancel: no such action %d\n",action_handle);
	return;
    }

    if (!action->probe)
	return;

    list_del(&action->node);
    action->probe = NULL;

    return;
}

void action_destroy(vmprobe_action_handle_t action_handle)
{
    struct vmprobe_action *action;
    int i;

    action = find_probe_action(action_handle);
    if (!action) {
	error("action_destroy: no such action %d\n",action_handle);
	return;
    }

    if (action->probe) {
	action_cancel(action_handle);
    }

    probe_action_list[action_handle] = NULL;
    cqueue_put(&action_handle_queue,action_handle);

    if (action->type == VMPROBE_ACTION_CUSTOMCODE
	&& action->detail.code.nr_opcodes) {
	for (i = 0; i < action->detail.code.nr_opcodes; ++i) {
	    free(action->detail.code.opcodes[i]);
	}
	free(action->detail.code.opcodes);
    }
    else if (action->type == VMPROBE_ACTION_MEMMOD
	     && action->detail.memmod.len) {
	free(action->detail.memmod.data);
    }

    free(action);

    return;
}

void
run_vmprobes(void)
{
    struct vmprobe_domain *domain = NULL;
    int ret, fd;
    evtchn_port_t port = -1;
    struct timeval tv;
    fd_set inset;

    /* no domain means no probe registered */
    if (list_empty(&domain_list)) {
        error("no probe has been registered\n");
        return;
    }

    /* get a select()able file descriptor of the event channel */
    fd = xc_evtchn_fd(xce_handle);
    if (fd == -1) {
        error("event channel not initialized\n");
        return;
    }

    global_state = "INRUN";

    /* loop until the stop flag is set */
    while (!stop) {
        tv.tv_sec = 0;
        tv.tv_usec = 50;
        FD_ZERO(&inset);
        FD_SET(fd, &inset);

	global_state = "IDLE";

        /* wait for a domain to trigger the VIRQ */
        ret = select(fd+1, &inset, NULL, NULL, &tv);
        if (ret == -1) // timeout
            continue;

	global_state = "INRUN";

        /* an interrupt while waiting at select()? */
        if (interrupt && interrupt_sig > -1) {
            debug(0,"caught signal and removing probes safely!\n");
            unregister_vmprobe_batch_internal();
            raise(interrupt_sig);
        }
        
	/* stop requested? */
	if (stop)
	    break;

	/* nothing to do */
        if (!FD_ISSET(fd, &inset))
	    continue;

        /* we've got something from eventchn. let's see what it is! */
        port = xc_evtchn_pending(xce_handle);
        if (port != dbg_port)
            goto retry; // not the event that we are looking for

        /* it's a debugger event, find the domain that reported the event */
	/* XXX we need to round-robin here for fairness */
        list_for_each_entry(domain, &domain_list, list) {
	    global_state = "INDOMS";

            /* FIXME: domain paused - does this really mean a bp/sstep-hit? */
            if (domain_paused(domain->id)) {
		global_state = "INDOM";

                if (domain->sstep_probepoint)
		    debug(1,"dom%d paused by sstep-hit, probepoint@0x%lx\n",
			  domain->id, domain->sstep_probepoint->vaddr);
		 else
		     debug(1,"dom%d paused by bp-hit\n", domain->id);

#ifdef VMPROBE_BENCHMARK
                /* domain->sstep_probepoint is set to non-zero if the
                   event is a singlestep hit */
                if (domain->sstep_probepoint) {
                    VMPROBE_PERF_STOP("vmprobes gets control back "
                            "after sstep-hit");
                }
                else {
                    VMPROBE_PERF_STOP("vmprobes gets control back after "
                        "bp-hit");
                }
#endif /* VMPROBE_BENCHMARK */

                VMPROBE_PERF_START();

                /* obtain vcpu register values */
		assert(domain->regs == NULL);
		domain->regs = get_regs(domain->id, &domain->ctx);
		if (domain->regs == NULL) {
		    /* FIXME: should we exit or retry? */
		    error("failed to get vcpu registers in dom%d\n",domain->id);
		    continue; // at least check other domains
                }

                VMPROBE_PERF_STOP("vmprobes obtains registers from domU");

		debug(1,"dom%d paused at 0x%lx\n", domain->id, domain->regs->eip);

                /* handle the triggered probe based on its event type */
                if (__in_singlestep(domain->regs) &&
		    !domain->sstep_probepoint) {
                    // domain not supposed to be in singlestep mode
                    warning("phantom single step for dom%d!\n", domain->id);
		    // we need to clear it or we will be right back here!
		    __leave_singlestep(domain->regs);
                }
                else if (!domain->sstep_probepoint) {
		    global_state = "INBP";
                    handle_bphit(domain); /* breakpoint hit */
		}
                else {
		    global_state = "INSS";
                    handle_sstep(domain); /* singlestep hit */
		}
		global_state = "INDOM";

                VMPROBE_PERF_START();

                /* set the restored register values back to vcpu;
                   register values are restored in the event handling
                   function; handle_bphit() or handle_sstep() */
                ret = set_regs(domain->id, &domain->ctx);
		domain->regs = NULL;
                if (ret) {
		    /* FIXME: should we exit or retry? */
                    error("failed to set vcpu registers in dom%d\n",
                        domain->id);
		    continue; // at least check other domains
                }

                VMPROBE_PERF_STOP("vmprobes sets registers to domU");

#ifdef ENABLE_XENACCESS
                xa_destroy_cache(&domain->xa_instance);
                xa_destroy_pid_cache(&domain->xa_instance);
#endif
#ifdef ENABLE_LIBVMI
		/* XXX is this right? */
		vmi_v2pcache_flush(domain->vmi_instance);
		vmi_symcache_flush(domain->vmi_instance);
		vmi_pidcache_flush(domain->vmi_instance);
#endif

                debug(1,"trying to unpause dom%d\n", domain->id);
                VMPROBE_PERF_START();

                /* unpause the domain */
                ret = xc_domain_unpause(xc_handle, domain->id);
                if (ret < 0) {
		    /* FIXME: should we exit or retry? */
		    error("failed to unpause dom%d\n", domain->id);
		    continue; // at least check other domains
                }

                VMPROBE_PERF_STOP("vmprobes unpauses domU");

                VMPROBE_PERF_START(); /* stops at bp-hit or sstep-hit */

	    } /* if (domain_paused(domain->id)) */

	    global_state = "INDOMS";

	} /* list_for_each_entry(domain, &domain_list, list) */

	global_state = "INRUN";

retry:
        /* unmask the event channel */
        ret = xc_evtchn_unmask(xce_handle, port);
        if (ret == -1) {
            error("failed to unmask event channel\n");
            break;
        }

    } /* while (!stop) */

    /* FIXME: should we do this always? */
    if (interrupt && interrupt_sig > -1) {
        debug(0,"caught signal and removing probes safely!\n");
        unregister_vmprobe_batch_internal();
        raise(interrupt_sig);
    }

    global_state = "INUSER";
}

void
interrupt_vmprobes(void)
{
    //int fd;
    int ret;

    interrupt = true;

    if (xce_handle == XC_IF_INVALID)
	return;

    /* there is no need to close the event channel to interrupt the loop in
       run_vmprobes(), just notify it */
    ret = xc_evtchn_notify(xce_handle, dbg_port);
    if (ret == -1)
        error("failed to notify event channel\n");

    /* close the fd to make the select() in run_vmprobes() return */
    //fd = xc_evtchn_fd(xce_handle);
    //close(fd);
}

void
stop_vmprobes(void)
{
    //int fd;
    
    /* NOTE: interrupt and stop are differernt; stop makes run_vmprobes() 
       finish its job whereas interrupt only makes the select() return once */

    stop = true;

    interrupt_vmprobes();

    /* NOTE: unbinding debug port and closing event channel happen in
       cleanup_vmprobes() */
}

int
restart_vmprobes(void)
{
    interrupt = false;
    stop = false;

#if 0
    // reopen event channel
    xce_handle = reinit_evtchn(&dbg_port);
    if (xce_handle == XC_IF_INVALID) {
        return -1;
    }
#endif
    reinit_vmprobes();

    return 0;
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

int
vmprobe_setcookie(vmprobe_handle_t handle, void *cookie)
{
    struct vmprobe *probe;

    probe = find_probe(handle);
    if (!probe)
        return -1;

    probe->cookie = cookie;
    return 0;
}

void *
vmprobe_getcookie(vmprobe_handle_t handle)
{
    struct vmprobe *probe;

    probe = find_probe(handle);
    if (!probe)
        return NULL;

    return probe->cookie;
}

#include "vmprobes_arch.c"

#ifdef ENABLE_XENACCESS
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

static unsigned char *
mmap_pages(xa_instance_t *xa_instance,
           unsigned long vaddr, 
           unsigned long size, 
           uint32_t *offset,
	   int *npages,
           int prot,
	   int pid)
{
    unsigned char *pages;
    unsigned long page_size, page_offset;
    char *dstr = "small";

    page_size = xa_instance->page_size;
    page_offset = vaddr & (page_size - 1);

    if (size > 0 && size <= (page_size - page_offset)) {
        /* let xenaccess use its memory cache for small size */
        pages = xa_access_user_va(xa_instance, vaddr, offset, 
                  pid, prot);
	if (!pages) {
	    if (!pid)
		return NULL;

	    pages = xa_access_user_va(xa_instance, vaddr, offset, 
				      0, prot);
	    if (!pages)
		return NULL;
	}
	*npages = 1;
    }
    else {
	dstr = "large";
        /* xenaccess can't map multiple pages properly, use our own function */
        pages = xa_access_user_va_range(xa_instance, vaddr, size,
                    offset, pid, prot);

	if (!pages) { // && pid) {
	    //return NULL;
	    if (!pid)
		return NULL;

	    /* try kernel */
	    pages = xa_access_user_va_range(xa_instance, vaddr, size, 
					    offset, 
					    0, prot);
	    if (!pages) 
		return NULL;
	}

	/*
	 * Compute how many pages were mapped.
	 * *offset is the offset within the initial page mapped.
	 * Number of pages is thus:
	 *   round((*offset+size), page_size)
	 */
	*npages = (*offset + size) / page_size;
	if ((*offset + size) % page_size)
	    (*npages)++;

    }

    debug(2,"%ld bytes at %lx mapped (%s)\n", size, vaddr,dstr);
    return pages; /* munmap it later */
}

unsigned char *
vmprobe_get_data(vmprobe_handle_t handle,struct cpu_user_regs *regs,
         char *name,unsigned long addr,int pid,
         unsigned long target_length,unsigned char *target_buf)
{
    struct vmprobe *probe;
    xa_instance_t *xa_instance;
    /* FIXME: size of char depends on the guest's architecture */
    unsigned char *pages;
    uint32_t offset = 0;
    unsigned long length = target_length, size = 0;
    unsigned long page_size;
    unsigned char *retval = NULL;
    unsigned long page_offset;
    int no_pages;
    
    probe = find_probe(handle);
    assert(probe);

    xa_instance = vmprobe_xa_instance(handle);
    assert(xa_instance);

    page_size = xa_instance->page_size;
    page_offset = addr & (page_size - 1);

    debug(2,"loading %s: %d bytes at (addr=%08x,pid=%d), offset = %d\n",
      name,target_length,addr,pid,page_offset);

    /* if we know what length we need, just grab it */
    if (length > 0) {
	pages = (unsigned char *)mmap_pages(xa_instance, 
					    addr,
					    target_length, 
					    &offset, 
					    &no_pages,
					    PROT_READ,
					    pid);
	if (!pages)
	    return NULL;

	assert(offset == page_offset);
	debug(2,"loading %s: %d bytes at (addr=%08x,pid=%d) mapped %d pages\n",
	      name,target_length,addr,pid,no_pages);
    }
    else {
	/* increase the mapping size by this much if the string is longer 
	   than we expect at first attempt. */
	size = (page_size - page_offset);

	while (1) {
	    if (1 || size > page_size) 
		debug(2,"increasing size to %d (name=%s,addr=%08x,pid=%d)\n",
		      size,name,addr,pid);
	    pages = (unsigned char *)mmap_pages(xa_instance,addr,
			size,&offset,&no_pages,PROT_READ,pid);
	    if (!pages)
		return NULL;

	    length = strnlen((const char *)(pages + offset), size);
	    if (length < size) {
		debug(2,"got string of length %d, mapped %d pages\n",
		      length, no_pages);
		break;
	    }
	    if (munmap(pages, no_pages * page_size))
		warning("munmap of %p failed\n", pages);
	    size += page_size;
	}
    }

    if (!target_buf)
	retval = (unsigned char *)malloc(length+1);
    else 
	retval = target_buf;
    if (retval) {
	memcpy(retval, pages + offset, length);
	if (target_length == 0) {
	    retval[length] = '\0';
	}
    }
    if (munmap(pages, no_pages * page_size))
	warning("munmap of %p failed\n", pages);
    
    return retval;
}
#endif

#ifdef ENABLE_LIBVMI
vmi_instance_t
vmprobe_vmi_instance(vmprobe_handle_t handle)
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

    return domain->vmi_instance;
}

unsigned char *
vmprobe_get_data(vmprobe_handle_t handle,struct cpu_user_regs *regs,
         char *name,unsigned long addr,int pid,
         unsigned long target_length,unsigned char *target_buf)
{
    struct vmprobe *probe;
    vmi_instance_t vmi;
    int alloced = 0;
    size_t cc;

    probe = find_probe(handle);
    assert(probe);

    vmi = vmprobe_vmi_instance(handle);
    assert(vmi);

    debug(2,"loading %s: %d bytes at (addr=%lx,pid=%d)\n",
	  name,target_length,addr,pid);

    /* if length == 0, we are copying in a string. */
    if (target_length == 0)
	return (unsigned char *)vmi_read_str_va(vmi, (addr_t)addr, pid);

    /* allocate buffer if necessary */
    if (!target_buf) {
	target_buf = malloc(target_length + 1);
	if (!target_buf)
	    return NULL;
	alloced = 1;
    }

    /* read the data */
    cc = vmi_read_va(vmi, (addr_t)addr, pid, target_buf, target_length);

    /* there is no provision for a partial read, assume an error */
    if ((unsigned long)cc != target_length) {
	warning("vmi_read_va of %s at 0x%lx returns partial data (%lu of %lu)\n",
		name, addr, (unsigned long)cc, target_length);
	if (alloced)
	    free(target_buf);
	return NULL;
    }

    return target_buf;
}
#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
