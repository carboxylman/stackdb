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

void vmprobes_set_debug_level(int level,int xa_level)
{
    xa_set_debug_level(xa_level);
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

static bool stop = 0;
static bool interrupt = 0;
static int interrupt_sig = -1;
static evtchn_port_t dbg_port = -1;

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
    if (xc_vcpu_getcontext(xc_handle, domid, get_vcpu(domid), ctx))
        return NULL;
    return &ctx->user_regs;
}

static inline int
set_regs(domid_t domid, vcpu_guest_context_t *ctx)
{
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
static sighandler_t osighandler[_NSIG];

static void
signal_handler(int sig)
{
    vmprobe_handle_t handle;

    VMPROBE_PERF_STOP("vmprobes gets control back by interrupt");
    VMPROBE_PERF_NEXT();

    stop = true;
    interrupt = true;
    interrupt_sig = sig;

    // don't recurse
    signal(sig, osighandler[sig]);

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
}

static void
signal_interrupt(void)
{
    int i;

    for (i = 0; i < sizeof(osighandler) / sizeof(osighandler[0]); i++)
	osighandler[i] = SIG_DFL;

    if ((osighandler[SIGPIPE] = signal(SIGPIPE, signal_handler)) == SIG_IGN)
	signal(SIGPIPE, SIG_IGN);
    if ((osighandler[SIGQUIT] = signal(SIGQUIT, signal_handler)) == SIG_IGN)
        signal(SIGQUIT, SIG_IGN);
    if ((osighandler[SIGINT] = signal(SIGINT, signal_handler)) == SIG_IGN)
        signal(SIGINT, SIG_IGN);
    if ((osighandler[SIGABRT] = signal(SIGABRT, signal_handler)) == SIG_IGN)
        signal(SIGABRT, SIG_IGN);
    if ((osighandler[SIGHUP] = signal(SIGHUP, signal_handler)) == SIG_IGN)
        signal(SIGHUP, SIG_IGN);
    if ((osighandler[SIGILL] = signal(SIGILL, signal_handler)) == SIG_IGN)
        signal(SIGILL, SIG_IGN);
    if ((osighandler[SIGFPE] = signal(SIGFPE, signal_handler)) == SIG_IGN)
        signal(SIGFPE, SIG_IGN);
    if ((osighandler[SIGSEGV] = signal(SIGSEGV, signal_handler)) == SIG_IGN)
        signal(SIGSEGV, SIG_IGN);
    if ((osighandler[SIGTERM] = signal(SIGTERM, signal_handler)) == SIG_IGN)
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

#if 0
static int
reinit_evtchn(evtchn_port_t *dbg_port)
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
    
    if (cqueue_empty(&handle_queue))
    {
        error("total number of probes cannot exceed %d\n",VMPROBE_MAX);
        return NULL;
    }

    probe = (struct vmprobe *) malloc( sizeof(*probe) );
    if (!probe)
    {
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
    //domain->xa_instance.page_offset = 0xc0000000;
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
    if (probepoint->action) 
	action = probepoint->action;
    else 
	action = list_entry(probepoint->action_list.next,
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
handle_bphit(struct vmprobe_domain *domain, struct cpu_user_regs *regs)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;
    int have_action = 0;

    probepoint = find_probepoint(__get_org_ip(regs), domain);
    if (!probepoint)
        return -1;

    debug(2,"bphit probepoint [dom%d:%lx]\n",domain->id,probepoint->vaddr);

    if (probepoint->state == VMPROBE_BP_SET)
    {
        /* save the original ip value in case something bad happens */
        domain->org_ip = __get_org_ip(regs);

        VMPROBE_PERF_START();
        
        /*
         * Run pre-handlers if we have encountered our breakpoint for the
         * first time on this pass (which means we should not have an
         * action set!)
         */
        list_for_each_entry(probe, &probepoint->probe_list, node)
        {
            if (!probe->disabled && probe->pre_handler)
                probe->disabled = probe->pre_handler(probe->handle, regs);
        }

        VMPROBE_PERF_STOP("vmprobes executes pre-handlers");

        VMPROBE_PERF_START();
        
        /* restore ip register */
        __reset_ip(regs);
        
        VMPROBE_PERF_STOP("vmprobes resets ip register in domU");
        debug(2,"original ip %x restored in dom%d\n", regs->eip, domain->id);

        /* nothing bad has happened, so set it zero */
        domain->org_ip = 0;
    }

    /*
     * If we are running an action, handle our actions now.
     */
    if (probepoint->state == VMPROBE_BP_SET
            || probepoint->state == VMPROBE_ACTION_RUNNING) {
        have_action = handle_actions(probepoint,regs);
    }

    if (!have_action && !probepoint->action_obviates_orig) 
    {
        /* restore ip register */
        //VMPROBE_PERF_START();
        //__reset_ip(regs);
        //debug(2,"original ip %x restored in dom%d\n", regs->eip, domain->id);
        //VMPROBE_PERF_STOP("vmprobes resets ip register in domU");
        
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
handle_sstep(struct vmprobe_domain *domain, struct cpu_user_regs *regs)
{
    struct vmprobe *probe;
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_action *action;
    struct vmprobe_action *taction;

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
    list_for_each_entry(probe, &probepoint->probe_list, node)
    {
	if (!probe->disabled && probe->post_handler)
	    probe->disabled = probe->post_handler(probe->handle, regs);
    }
    
    VMPROBE_PERF_STOP("vmprobes executes post-handlers");

    if (!interrupt)
    {
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
    xce_handle = -1;
    
    ret = xc_interface_close(xc_handle);
    if (ret)
        perror("failed to close xc interface");
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
        perror("failed to open event channel\n");
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
reinit_vmprobes(void)
{
    if (xc_handle != -1)
        return -1; // xc interface already open

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

    interrupt = false;
    debug(0,"vmprobes reinitialized\n");
    return 0;
}

static int
__register_vmprobe(struct vmprobe *probe)
{
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;
    char *pages;
    uint32_t offset;
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

    /* backup the original instruction */
    /* inject a breakpoint at the probe-point */
    ret = __insert_breakpoint(probepoint);
    if (ret < 0)
    {
        probepoint->state = VMPROBE_DISABLED;
        return ret;
    }

    probepoint->state = VMPROBE_BP_SET;

    VMPROBE_PERF_STOP("vmprobes injects breakpoint in domU");
    debug(2,"bp set at [dom%d:%lx] for the first time\n", 
            domain->id,probepoint->vaddr);

    probe->disabled = false;
    return 0;
}

static void
__dump_probe(struct vmprobe *probe)
{
    struct vmprobe_probepoint *probepoint;
    struct vmprobe_domain *domain;
    char *pages;
    uint32_t offset;

    probepoint = probe->probepoint;
    domain = probepoint->domain;

    /* FIXME: David's code for batched probe registration? 
       -- make this a function, it will shorten the code much */
    pages = xa_access_kernel_va_range(&domain->xa_instance, 
            probepoint->vaddr, 
            64, 
            &offset, 
            PROT_READ);
    if (pages) {
	int i;

        for (i = 0; i < 16; ++i) {
            printf(" %08x",*((unsigned int *)&(probe->vbytes[i*4])));
        }
        printf("\n");
        for (i = 0; i < 16; ++i) {
            printf(" %08x",*((unsigned int *)(pages + offset + i*4)));
        }
        printf("\n");

	i = 1;
	if (offset + 64 > domain->xa_instance.page_size)
	    i++;
	if (munmap(pages, i * domain->xa_instance.page_size))
	    warning("munmap of %p failed\n", pages);
    }
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

    /* NOTE: here, we try to restore the states of the (1) probepoint and 
       (2) domain before we remove the specified probe completely. 
       if there are other probes at the probepoint we should not touch it. 
       likewise, if other probes are running in the domain, we have nothing to 
       do with the domain. */

    /* last probe at the probepoint? */
    ret = only_probe_left(probe);
    if (!ret)
        return 0; // if not, nothing to restore

    /* breakpoint set at the probepoint? */
    if (probepoint->state != VMPROBE_BP_SET)
        goto restore_domain; // jump to the 2nd phase; restore domain state

    VMPROBE_PERF_START();

    probepoint->state = VMPROBE_REMOVING;

    if (vmprobes_debug_level >= 0)
	__dump_probe(probe);

    /* restore the original instruction */
    ret = __remove_breakpoint(probepoint);
    if (ret < 0)
    {
        probepoint->state = VMPROBE_BP_SET;
        return ret;
    }

    if (vmprobes_debug_level >= 0)
	__dump_probe(probe);

    probepoint->state = VMPROBE_DISABLED;

    VMPROBE_PERF_STOP("vmprobes removes breakpoint in domU");
    debug(2,"bp removed at [dom%d:%lx] for the last time\n",
            domain->id, probepoint->vaddr);

restore_domain:
    /* last probepoint in the domain? */
    ret = only_probepoint_left(probepoint);
    if (!ret)
        return 0; // if not, nothing to restore in the domain

    VMPROBE_PERF_START();

    /* obtain vcpu register values */
    regs = get_regs(domain->id, &ctx);
    if (!regs)
    {
        error("failed to get vcpu registers in dom%d\n", domain->id);
        return -1;
    }

    VMPROBE_PERF_STOP("vmprobes obtains registers from domU");

    /* singlestep still on? */
    if (domain->sstep_probepoint)
    {
        VMPROBE_PERF_START();

        /* turn singlestep mode off */
        __leave_singlestep(regs);
        domain->sstep_probepoint = NULL;

        VMPROBE_PERF_STOP("vmprobes unsets singlestep in domU");
        debug(2,"sstep unset in dom%d for the last time\n", 
                domain->id);
    }
    else
        debug(2,"sstep NOT unset for last time\n");

    /* ip register not restored yet? */
    if (domain->org_ip)
    {
        VMPROBE_PERF_START();

        /* restore ip register */
        regs->eip = domain->org_ip;
        domain->org_ip = 0;

        VMPROBE_PERF_STOP("vmprobes resets ip register in domU");
        debug(2,"original ip %x restored in dom%d for the last time\n",
                regs->eip, domain->id);
    }
    else
        debug(2,"orig IP NOT restored for last time (0x%08x)\n",regs->eip);

    VMPROBE_PERF_START();

    /* set the restored register values back to vcpu */
    ret = set_regs(domain->id, &ctx);
    if (ret)
    {
        error("failed to set vcpu registers in dom%d\n", domain->id);    
        return -1;
    }

    VMPROBE_PERF_STOP("vmprobes sets registers in domU");

    VMPROBE_PERF_START();

    /* turn debugging mode off */
    ret = set_debugging(domain->id, false);
    if (ret)
    {
        error("failed to unset debugging in dom%d\n", domain->id);
        return -1;
    }

    VMPROBE_PERF_STOP("vmprobes unsets debugging in domU");
    debug(2,"debugging unset in dom%d for the last time\n", 
            domain->id);

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
    
    if (domain_paused(domid)) {
        error("dom%d already paused\n", domid);
        return -EPERM;
    }
    
    /* initialize vmprobes library at the first probe registration attempt */
    if (list_empty(&domain_list)) {
        if ((rc = init_vmprobes()) < 0)
            return rc;
    }

    domain = find_domain(domid);
    if (!domain) {
        domain = add_domain(domid);
        if (!domain)
            return -1;
    }

    VMPROBE_PERF_START();
    xc_domain_pause(xc_handle,domain->id);
    debug(1,"dom%d paused\n",domain->id);
    VMPROBE_PERF_STOP("vmprobes pauses domU");

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
	    if (list_empty(&probepoint->probe_list))
		remove_probepoint(probepoint);

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
	    if (list_empty(&probepoint->probe_list))
		remove_probepoint(probepoint);

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
	}

	if ((probepoint = find_probepoint(vaddrlist[i],domain))) {
	    if (list_empty(&probepoint->probe_list)) {
		remove_probepoint(probepoint);

		if (list_empty(&domain->probepoint_list))
		    remove_domain(domain);
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
    if (ret)
    {
        error("dom%d currently paused\n", domid);
        return -EPERM;
    }
    
    /* initialize vmprobes library at the first probe registration attempt */
    ret = list_empty(&domain_list);
    if (ret)
    {
        ret = init_vmprobes();
        if (ret < 0)
            return ret;
    }

    /* add the domain to the list if it is the first time to instrument it */
    domain = find_domain(domid);
    if (!domain)
    {
        domain = add_domain(domid);
        if (!domain)
            return -1;
    }
    
    /* add the probepoint to the list if it is the first time to instrument 
       it */
    probepoint = find_probepoint(vaddr, domain);
    if (!probepoint)
    {
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
    
    /* pause the domain */
    ret = xc_domain_pause(xc_handle, domain->id);
    if (ret < 0)
    {
        error("failed to pause dom%d\n", domain->id);
        goto out_error_domctl;
    }
    
    VMPROBE_PERF_STOP("vmprobes sets domU to be paused");

    /* inject the probe at the probepoint */
    ret = __register_vmprobe(probe);
    if (ret < 0)
        goto out_error;
    
    debug(1,"trying to unpause dom%d\n", domain->id);
    VMPROBE_PERF_START();
    
    /* unpause the domain */
    ret = xc_domain_unpause(xc_handle, domain->id);
    if (ret < 0)
    {
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
    
    VMPROBE_PERF_START();
    xc_domain_pause(xc_handle, domain->id);
    debug(1,"dom%d paused\n", domain->id);
    VMPROBE_PERF_STOP("vmprobes pauses domU");

    for (i = 0; i < listlen; ++i) {
	/* allow sparse lists */
	if (handlelist[i] < 0)
	    continue;

	if (!(probe = find_probe(handlelist[i]))) {
	    ++retval;
	    continue;
	}

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
	if (list_empty(&probepoint->probe_list)) {
	    remove_probepoint(probepoint);
	    if (list_empty(&domain->probepoint_list))
		remove_domain(domain);
	}
    }

    VMPROBE_PERF_START();
    xc_domain_unpause(xc_handle, domain->id);
    debug(1,"dom%d unpaused\n", domain->id);
    VMPROBE_PERF_STOP("vmprobes unpauses domU");

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
    
    /* pause the domain */
    ret = xc_domain_pause(xc_handle, domain->id);
    if (ret < 0)
    {
        error("failed to pause dom%d\n", domain->id);
        return -1; // this is critical, do not proceed further
    }
    
    VMPROBE_PERF_STOP("vmprobes sets domU to be paused");
    
    /* remove the probe from the probepoint */
    ret = __unregister_vmprobe(probe);
    if (ret < 0)
    {
        // FIXME: failed to remove the probe, should exit or proceed further?
        // let's do nothing for now.
    }

    debug(1,"trying to unpause dom%d\n", domain->id);
    VMPROBE_PERF_START();
    
    /* unpause the domain */
    ret = xc_domain_unpause(xc_handle, domain->id);
    if (ret < 0)
    {
        // FIXME: failed to unpause the domain, should exit or proceed further?
        // let's just print a warning message for now.
        warning("failed to unpause dom%d\n", domain->id);
    }
    
    VMPROBE_PERF_STOP("vmprobes sets domU to be unpaused"); 

    /* remove the probe, related probepoint and domain from the lists */
    remove_probe(probe);
    if (list_empty(&probepoint->probe_list))
    {
        remove_probepoint(probepoint);
        if (list_empty(&domain->probepoint_list))
            remove_domain(domain);
    }

    /* cleanup vmprobes library when the last probe is unregistered */
    ret = list_empty(&domain_list);
    if (ret)
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
    struct cpu_user_regs *regs;
    vcpu_guest_context_t ctx;

    /* no domain means no probe registered */
    if (list_empty(&domain_list))
    {
        error("no probe has been registered\n");
        return;
    }

    /* get a select()able file descriptor of the event channel */
    fd = xc_evtchn_fd(xce_handle);
    if (fd == -1)
    {
        error("event channel not initialized\n");
        return;
    }

    /* loop until the stop flag is set */
    while (!stop)
    {
        tv.tv_sec = 0;
        tv.tv_usec = 50;
        FD_ZERO(&inset);
        FD_SET(fd, &inset);

        /* wait for a domain to trigger the VIRQ */
        ret = select(fd+1, &inset, NULL, NULL, &tv);
        if (ret == -1) // timeout
            continue;

        /* an interrupt while waiting at select()? */
        if (interrupt && interrupt_sig > -1)
        {
            debug(0,"caught signal and removing probes safely!\n");
            unregister_vmprobe_batch_internal();
            raise(interrupt_sig);
        
            /* stop requested? */
            if (stop)
                continue;
        }

        if (!FD_ISSET(fd, &inset))
            goto retry; // nothing in eventchn

        /* we've got something from eventchn. let's see what it is! */
        port = xc_evtchn_pending(xce_handle);
        if (port != dbg_port)
            goto retry; // not the event that we are looking for

        /* it's a debugger event, find the domain that reported the event */
        list_for_each_entry(domain, &domain_list, list)
        {
            /* FIXME: domain paused - does this really mean a bp/sstep-hit? */
            if (domain_paused(domain->id))
            {
                debug(1,"dom%d paused by %s\n", domain->id,
                        (!domain->sstep_probepoint) ? 
                        "bp-hit" : "sstep-hit");

#ifdef VMPROBE_BENCHMARK
                /* domain->sstep_probepoint is set to non-zero if the
                   event is a singlestep hit */
                if (domain->sstep_probepoint)
                {
                    VMPROBE_PERF_STOP("vmprobes gets control back "
                            "after sstep-hit");
                }
                else
                {
                    VMPROBE_PERF_STOP("vmprobes gets control back after "
                        "bp-hit");
                }
#endif /* VMPROBE_BENCHMARK */

                VMPROBE_PERF_START();

                /* obtain vcpu register values */
                regs = get_regs(domain->id, &ctx);
                if (!regs)
                {
                    error("failed to get vcpu registers in dom%d\n",domain->id);
                    goto retry; // FIXME: should we exit or retry?
                }

                VMPROBE_PERF_STOP("vmprobes obtains registers from domU");

                /* handle the triggered probe based on its event type */
                if (regs->eflags & 0x00000100 && 
                    !domain->sstep_probepoint)
                {
                    // domain not supposed to be in singlestep mode
                    warning("phantom single step for dom%d!\n", domain->id);
                }
                else if (!domain->sstep_probepoint)
                    handle_bphit(domain, regs); /* breakpoint hit */
                else
                    handle_sstep(domain, regs); /* singlestep hit */

                VMPROBE_PERF_START();

                /* set the restored register values back to vcpu;
                   register values are restored in the event handling
                   function; handle_bphit() or handle_sstep() */
                ret = set_regs(domain->id, &ctx);
                if (ret)
                {
                    error("failed to set vcpu registers in dom%d\n",
                        domain->id);
                    goto retry; // FIXME: should we exit or retry?
                }

                VMPROBE_PERF_STOP("vmprobes sets registers to domU");

                xa_destroy_cache(&domain->xa_instance);
                xa_destroy_pid_cache(&domain->xa_instance);

                debug(1,"trying to unpause dom%d\n", domain->id);
                VMPROBE_PERF_START();

                /* unpause the domain */
                ret = xc_domain_unpause(xc_handle, domain->id);
                if (ret < 0)
                {
                    error("failed to unpause dom%d\n", domain->id);
                    goto retry; // FIXME: should we exit or retry?
                }

                VMPROBE_PERF_STOP("vmprobes unpauses domU");

                VMPROBE_PERF_START(); /* stops at bp-hit or sstep-hit */

            } /* if (domain_paused(domain->id)) */

        } /* list_for_each_entry(domain, &domain_list, list) */

retry:
        /* unmask the event channel */
        ret = xc_evtchn_unmask(xce_handle, port);
        if (ret == -1)
        {
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
}

void
interrupt_vmprobes(void)
{
    //int fd;
    int ret;

    interrupt = true;

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

    /* NOTE: unbounding debug port and closing event channel happen in
       cleanup_vmprobes() */

    //xc_evtchn_unbind(xce_handle,(evtchn_port_t)dbg_port);
    //dbg_port = -1;
    
    //xc_evtchn_close(xce_handle);
    //xce_handle = -1;
    
    //xc_interface_close(xc_handle);
    //xc_handle = -1;

    /* close the fd to make the select() in run_vmprobes() return */
    //fd = xc_evtchn_fd(xce_handle);
    //close(fd);

    //xc_evtchn_close(xce_handle);
    //xce_handle = -1;
}

int
restart_vmprobes(void)
{
    interrupt = false;

#if 0
    // reopen event channel
    xce_handle = reinit_evtchn(&dbg_port);
    if (xce_handle < 0)
    {
        return xce_handle;
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
	   int *npages,
           int prot,
	   int pid)
{
    unsigned char *pages;
    unsigned long page_size, page_offset;
    char *dstr = "small";

    page_size = xa_instance->page_size;
    page_offset = vaddr & (page_size - 1);

    if (size > 0 && size <= (page_size - page_offset))
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
	*npages = 1;
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

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
