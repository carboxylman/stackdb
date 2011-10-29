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
#include "xenaccess/xenaccess.h"
#include "xenaccess/xa_private.h"

#include "list.h"
#include "cqueue.h"
#include "vmprobes.h"
#include "private.h"

static int vmprobes_debug_level = -1;

void vmprobes_set_debug_level(int level)
{
    xa_set_debug_level(level);
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
    debug(0,"probes forcefully unregistered\n");
    
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
        error("total number of probes cannot exceed %d\n",VMPROBE_MAX);
        return NULL;
    }

    probe = (struct vmprobe *) malloc( sizeof(*probe) );
    if (!probe)
    {
        error("failed to allocate a new probe");
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
    
    debug(0,"probe %d removed\n", probe->handle);
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
	  probepoint->domain->id,probepoint->vaddr);
    free(probepoint);
}

struct vmprobe_domain *
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
	fprintf(stderr,"ERROR: could not fopen %s: %s",
		optarg,strerror(errno));
	return -3;
    }

    while ((rc = fscanf(sysmapfh,"%x %c %s255",&addr,&symtype,sym)) != EOF) {
	if (rc < 0) {
	    fprintf(stderr,"ERROR: while reading %s: fscanf: %s\n",
		    sysmapfile,strerror(errno));
	    return -5;
	}
	else if (rc != 3)
	    continue;
	    
	if (!strcmp("init_task",sym)) {
	    vmd = find_domain(domid);
	    if (vmd->xa_instance.init_task != addr) {
		fprintf(stderr,"Updating init_task address (to 0x%x)in xenaccess.\n",
			addr);
		vmd->xa_instance.init_task = addr;
		break;
	    }
	}
    }

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
    if (!domain)
    {
        perror("failed to allocate a new domain");
        return NULL;
    }
    
    /* initialize a xenaccess instance */
    memset(&domain->xa_instance, 0, sizeof(xa_instance_t));
    domain->xa_instance.os.linux_instance.tasks_offset = 108;
    domain->xa_instance.os.linux_instance.pid_offset = 168;
    domain->xa_instance.os.linux_instance.mm_offset = 132;
    domain->xa_instance.os.linux_instance.pgd_offset = 36;
    domain->xa_instance.sysmap = linux_predict_sysmap_name(domid);
    domain->xa_instance.os_type = XA_OS_LINUX; // currently linux only

    if (xa_init_vm_id_strict(domid, &domain->xa_instance) == XA_FAILURE)
    {
        free(domain);
        error("failed to init xa instance for dom%d\n", domid);
        return NULL;
    }
    //domain->xa_instance.init_task = 0xc03542c0;
    domain->xa_instance.kpgd = 0; //0xc03c7684;

    domain->id = domid;
    domain->org_ip = 0;
    domain->sstep_probepoint = NULL;
    INIT_LIST_HEAD(&domain->probepoint_list);
    
    list_add(&domain->list, &domain_list);

    debug(0,"dom%d added\n", domain->id);

    //uint32_t offset;
    //linux_get_taskstruct(&domain->xa_instance,65000,&offset);
    //debug(0,"searched for task 65000 in dom%d\n", domain->id);

    return domain;
}

static void
remove_domain(struct vmprobe_domain *domain)
{
    list_del(&domain->list);

    xa_destroy(&domain->xa_instance);

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
	debug(0,"resetting action execution flags for new action pass\n");
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
	    debug(0,"action finished at [dom%d:%lx]; restoring code\n",
		  probepoint->domain->id, probepoint->vaddr);
	    __remove_code(probepoint);
	    probepoint->state = VMPROBE_ACTION_DONE;
	}
	else {
	    debug(0,"action single step continues at [dom%d:%lx]\n",
		  probepoint->domain->id, probepoint->vaddr);
	    return 1;
	}
    }

    if (list_empty(&probepoint->action_list)) {
	return 0;
    }

    VMPROBE_PERF_START();
    if (probepoint->action) 
	action = probepoint->action;
    else 
	action = list_entry(&probepoint->action_list.next,
			    typeof(*action),node);
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
	    debug(0,"ret inserted at [dom%d:%lx]\n",
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
handle_bphit(struct vmprobe_domain *domain, struct cpu_user_regs *regs)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;
    int have_action = 0;

    probepoint = find_probepoint(__get_org_ip(regs), domain);
    if (!probepoint)
        return -1;

    debug(0,"bphit probepoint [dom%d:%lx]\n",domain->id,probepoint->vaddr);

    if (probepoint->state == VMPROBE_BP_SET) {
	/* save the original ip value in case something bad happens */
	domain->org_ip = __get_org_ip(regs);

	/*
	 * Run pre-handlers if we have encountered our breakpoint for the
	 * first time on this pass (which means we should not have an
	 * action set!)
	 */
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
	debug(0,"original ip %x restored in dom%d\n", regs->eip, domain->id);
	VMPROBE_PERF_STOP("vmprobes resets ip register in domU");
    }

    /*
     * If we are running an action, handle our actions now.
     */
    if (probepoint->state == VMPROBE_BP_SET
	|| probepoint->state == VMPROBE_ACTION_RUNNING) {
	have_action = handle_actions(probepoint,regs);
    }

    if (!have_action && !probepoint->action_obviates_orig) {
	/* restore ip register */
	//VMPROBE_PERF_START();
	//__reset_ip(regs);
	//debug(0,"original ip %x restored in dom%d\n", regs->eip, domain->id);
	//VMPROBE_PERF_STOP("vmprobes resets ip register in domU");

	/* restore the original instruction */
	VMPROBE_PERF_START();
	probepoint->state = VMPROBE_REMOVING;
	__remove_breakpoint(probepoint);
	debug(0,"bp removed at [dom%d:%lx]\n", domain->id, probepoint->vaddr);
	probepoint->state = VMPROBE_DISABLED;
	VMPROBE_PERF_STOP("vmprobes removes breakpoint in domU");
    }
    
    /* XXX: in future, check to see if action requires single step mode! */
    if (!interrupt 
	&& ((have_action && probepoint->action_requires_sstep)
	    || (!have_action && !probepoint->action_obviates_orig))) {
        /* turn singlestep mode on */
        VMPROBE_PERF_START();
        __enter_singlestep(regs);
        debug(0,"single step set in dom%d\n", domain->id);
        domain->sstep_probepoint = probepoint;
        VMPROBE_PERF_STOP("vmprobes sets singlestep in domU");
    }

    if (probepoint->state == VMPROBE_BP_SET) {
	/* nothing bad has happened, so set it zero */
	domain->org_ip = 0;
    }
    
    return 0;
}

static void
handle_sstep(struct vmprobe_domain *domain, struct cpu_user_regs *regs)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_action *action;
    struct vmprobe_action *taction;

    probepoint = domain->sstep_probepoint;

    if (handle_actions(probepoint,regs)) {
	debug(0,"found actions to handle\n");
	if (!probepoint->action_requires_sstep) {
	    VMPROBE_PERF_START();
	    __leave_singlestep(regs);
	    debug(0,"single step unset in dom%d during action handling\n",
		  domain->id);
	    domain->sstep_probepoint = NULL;
	    VMPROBE_PERF_STOP("vmprobes unsets singlestep in domU");
	}

	/* run the rest of the actions before the post handlers */
	return;
    }

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
        debug(0,"single step unset in dom%d\n", domain->id);
        domain->sstep_probepoint = NULL;
        VMPROBE_PERF_STOP("vmprobes unsets singlestep in domU");
        
        VMPROBE_PERF_NEXT();

	if (!probepoint->action_obviates_orig) {
	    /* inject a breakpoint for the next round */
	    VMPROBE_PERF_START();
	    probepoint->state = VMPROBE_INSERTING;
	    __insert_breakpoint(probepoint);
	    debug(0,"bp set at [dom%d:%lx]\n", domain->id, probepoint->vaddr);
	    probepoint->state = VMPROBE_BP_SET;
	    VMPROBE_PERF_STOP("vmprobes injects breakpoint back in domU");
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
    cqueue_cleanup(&handle_queue);
    cqueue_cleanup(&action_handle_queue);
    
    xc_evtchn_close(xce_handle);
    xce_handle = -1;
    
    xc_interface_close(xc_handle);
    xc_handle = -1;

    debug(0,"vmprobes uninitialized\n");
}

static int
init_vmprobes(void)
{
    vmprobe_handle_t handle;
    vmprobe_action_handle_t action_handle;
    
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

    if (!cqueue_init(&action_handle_queue, VMPROBE_ACTION_MAX))
    {
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
    debug(0,"debugging set in dom%d for probe %d registration\n",
	  domain->id, probe->handle);
    VMPROBE_PERF_STOP("vmprobes sets debugging in domU");

    if (probepoint->state == VMPROBE_DISABLED)
    {
        VMPROBE_PERF_START();
        probepoint->state = VMPROBE_INSERTING;

        /* backup the original instruction */
        /* inject a breakpoint at the probe-point */
        ret = __insert_breakpoint(probepoint);
        if (ret < 0)
        {
            probepoint->state = VMPROBE_DISABLED;
            return ret;
        }
        debug(0,"bp set at [dom%d:%lx] for the first time\n", 
	      domain->id,probepoint->vaddr);
    
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
            debug(0,"bp removed at [dom%d:%lx] for the last time\n",
		  domain->id, probepoint->vaddr);

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
                debug(0,"sstep unset in dom%d for the last time\n", 
                    domain->id);
                VMPROBE_PERF_STOP("vmprobes unsets singlestep in domU");
            }
    
            /* ip register not restored yet? */
            if (domain->org_ip)
            {
                /* restore ip register */
                VMPROBE_PERF_START();
                regs->eip = domain->org_ip;
                debug(0,"original ip %x restored in dom%d for the last time\n",
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
            debug(0,"debugging unset in dom%d for the last time\n", 
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
    debug(0,"dom%d paused\n", domain->id);
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
    debug(0,"dom%d unpaused\n", domain->id);
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
    debug(0,"dom%d paused\n", domain->id);
    VMPROBE_PERF_STOP("vmprobes pauses domU");
    ret = __unregister_vmprobe(probe);
    if (ret < 0)
    {
        xc_domain_unpause(xc_handle, domain->id);
        return ret;
    }
    VMPROBE_PERF_START();
    xc_domain_unpause(xc_handle, domain->id);
    debug(0,"dom%d unpaused\n", domain->id);
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
	fprintf(stderr,
		"action_sched: no such action %d\n",action_handle);
	return -1;
    }

    if (action->probe != NULL) {
	fprintf(stderr,
		"action_sched: action %d already associated with probe %d\n",
		action->handle,handle);
	return -1;
    }

    probe = find_probe(handle);
    if (!probe) {
	fprintf(stderr,
		"action_sched: no such probe %d\n",handle);
	return -1;
    }

    /* only allow one return action per probepoint */
    list_for_each_entry(lpc,&probe->probepoint->action_list,node) {
	if (lpc->type == VMPROBE_ACTION_RETURN) {
	    fprintf(stderr,
		    "action_sched: probepoint for probe %d already has return action %d\n",
		    lpc->probe->handle,lpc->handle);
	    return -1;
	}
    }

    if (whence != VMPROBE_ACTION_ONESHOT && whence != VMPROBE_ACTION_REPEATPRE
	&& whence != VMPROBE_ACTION_REPEATPOST) {
	fprintf(stderr,
		"action_sched: unknown whence %d for action %d\n",
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
	perror("no memory to allocate probe action\n");
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
    return (vmprobe_action_handle_t)NULL;
}

vmprobe_action_handle_t action_regmod(uint8_t regnum,
				      unsigned long regval)
{
    return (vmprobe_action_handle_t)NULL;
}

vmprobe_action_handle_t action_memmod(char *data,
				      unsigned long len,
				      unsigned long destaddr)
{
    return (vmprobe_action_handle_t)NULL;
}

void action_cancel(vmprobe_action_handle_t action_handle)
{
    struct vmprobe_action *action;

    action = find_probe_action(action_handle);
    if (!action) {
	fprintf(stderr,
		"ERROR: action_cancel: no such action %d\n",action_handle);
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
	fprintf(stderr,
		"action_destroy: no such action %d\n",action_handle);
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
                        debug(0,"dom%d paused by %s\n", domain->id,
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

			if (regs->eflags & 0x00000100 &&
			    !domain->sstep_probepoint) {
			    fprintf(stderr,"WARNING: phantom single step for dom%d!\n",domain->id);
			}
                        else if (!domain->sstep_probepoint)
                            handle_bphit(domain, regs);
                        else
                            handle_sstep(domain, regs);
                        
                        VMPROBE_PERF_START();
                        set_regs(domain->id, &ctx);
                        VMPROBE_PERF_STOP("vmprobes sets registers to domU");

			xa_destroy_cache(&domain->xa_instance);
			xa_destroy_pid_cache(&domain->xa_instance);

			VMPROBE_PERF_START();
			xc_domain_unpause(xc_handle, domain->id);
                        debug(0,"dom%d unpaused\n", domain->id);
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

static unsigned char *
mmap_pages(xa_instance_t *xa_instance,
           unsigned long vaddr, 
           unsigned long size, 
           uint32_t *offset,
           int prot,
	   int pid)
{
    unsigned char *pages;
    unsigned long page_size, tmp_offset;
    char *dstr = "small";

    page_size = xa_instance->page_size;
    tmp_offset = vaddr - (vaddr & ~(page_size - 1));

    if (size > 0 && (size - tmp_offset) < page_size)
    {
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
    }
    else
    {
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
    }

    debug(0,"%ld bytes at %lx mapped (%s)\n", size, vaddr,dstr);
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
    unsigned long inc_size, page_size, no_pages;
    unsigned char *retval = NULL;
    
    probe = find_probe(handle);
    assert(probe);

    xa_instance = vmprobe_xa_instance(handle);
    assert(xa_instance);
    page_size = xa_instance->page_size;

    debug(0,"loading %s: %d bytes at (addr=%08x,pid=%d)\n",
	  name,target_length,addr,pid);

    /* if we know what length we need, just grab it */
    if (length > 0) {
	pages = (unsigned char *)mmap_pages(xa_instance, 
					    addr,
					    target_length, 
					    &offset, 
					    PROT_READ,
					    pid);
	if (!pages)
	    return NULL;

	no_pages = length / page_size;
	if ((length + offset) > page_size) {
	    ++no_pages;
	}
    }
    else {
	/* increase the mapping size by this much if the string is longer 
	   than we expect at first attempt. */
	inc_size = (page_size - 1);

	while (1) {
	    size += inc_size;
	    if (1 || size > page_size) 
		debug(0,"increasing size to %d (name=%s,addr=%08x,pid=%d)\n",
		      size,name,addr,pid);
	    pages = (unsigned char *)mmap_pages(xa_instance,addr,
						size,&offset,PROT_READ,pid);
	    if (!pages)
		return NULL;

	    no_pages = size / page_size + 1;
	    length = strnlen((const char *)(pages + offset), size - offset);
	    if (length < (size - offset)) {
		break;
	    }
	    munmap(pages, no_pages * page_size);
	}
    }

    if (!target_buf)
	retval = (unsigned char *)malloc(length+1);
    else 
	retval = target_buf;
    if (retval) {
	memcpy(retval, pages + offset, length);
	if (target_length <= 0) {
	    retval[length] = '\0';
	}
    }
    munmap(pages, no_pages * page_size);
    
    return retval;
}
