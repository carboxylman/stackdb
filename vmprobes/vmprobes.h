#ifndef _XEN_VMPROBES_H
#define _XEN_VMPROBES_H

#include <xenctrl.h>
#include <xenaccess/xenaccess.h>

#ifdef VMPROBE_DEBUG
void _vmprobes_debug(int level,char *format,...);

#define debug(level,format,...) _vmprobes_debug(level,"DEBUG: %s:%d: "format, __FUNCTION__, __LINE__, ## __VA_ARGS__)
#else
#define debug(devel,format,...) ((void)0)
#endif

#define error(format,...) fprintf(stderr, "ERROR: %s:%d: "format, __FUNCTION__, __LINE__, ## __VA_ARGS__)
#define warning(format,...) fprintf(stderr, "WARNING: %s:%d: "format, __FUNCTION__, __LINE__, ## __VA_ARGS__)

#ifndef VMPROBE_MAX
#define VMPROBE_MAX (1024)
#endif

typedef int vmprobe_handle_t;
typedef int (*vmprobe_handler_t)(vmprobe_handle_t, struct cpu_user_regs *);

typedef int vmprobe_action_handle_t;
#ifndef VMPROBE_ACTION_MAX
#define VMPROBE_ACTION_MAX (1024 * 8)
#endif

typedef enum {
    VMPROBE_ACTION_RETURN     = 0,
    VMPROBE_ACTION_REGMOD     = 1,
    VMPROBE_ACTION_MEMMOD     = 2,
    VMPROBE_ACTION_CUSTOMCODE = 3,
} vmprobe_action_type_t;

typedef enum {
    VMPROBE_ACTION_UNSCHED    = 0,
    VMPROBE_ACTION_ONESHOT    = 1,
    VMPROBE_ACTION_REPEATPRE  = 2,
    VMPROBE_ACTION_REPEATPOST = 3,
} vmprobe_action_whence_t;

typedef enum {
    VMPROBE_ACTION_FLAG_NOINT   = 1,
    VMPROBE_ACTION_FLAG_SAVECTX = 2,
    VMPROBE_ACTION_FLAG_DOBREAKREPLACEATEND = 4,
} vmprobe_action_flag_t;

void vmprobes_set_debug_level(int level);

/* The opcode struct is arch-specific. */
struct vmprobe_opcode;
typedef struct vmprobe_opcode vmprobe_opcode_t;

/* 
 * Registers a probe at a given virtual address in a domain, with pre- and
 * post-handlers.
 * If the probe has been successfully registered, the function will return a
 * new handle to the probe. Alternatively, the function can return a value of
 * -1 indicating that it failed to register the probe.
 */
vmprobe_handle_t
register_vmprobe(domid_t domid,
                 unsigned long vaddr,
                 vmprobe_handler_t pre_handler,
                 vmprobe_handler_t post_handler);

int domain_exists(domid_t domid);

domid_t domain_lookup(char *name);

int domain_init(domid_t domid,char *sysmapfile);

/* 
 * Schedules an action to occur, given a probe handler.  Actions can
 * only occur when a domain is paused after a probe breakpoint has been
 * hit.  Actions can be scheduled prior to beginning probing, or they
 * can be scheduled at probe handler runtime.
 *
 * Some actions may preclude others in the future.  For instance, a
 * return action depends greatly on the body of the called function NOT
 * being executed at all, so that %eax may be set and a 'ret'
 * instruction executed (so it's immediately after the 'call'
 * instruction; there is no state to clean up, etc.  Allowing a custom
 * code action prior to a return action might change the validity of
 * this assumption.
 *
 * But for now, the only restriction is
 *   - one return action per handle, and it will be performed after
 *     execution of the pre handler.
 *
 * Actions do not have priorities; they are executed in the order scheduled.
 */
int action_sched(vmprobe_handle_t handle,
		 vmprobe_action_handle_t action,
		 int whence);

/*
 * Cancel an action.
 */
void action_cancel(vmprobe_action_handle_t handle);

/*
 * High-level actions that require little ASM knowledge.
 */
vmprobe_action_handle_t action_return(unsigned long retval);

/*
 * Low-level actions that require little ASM knowledge, and may or may
 * not be permitted.
 */
vmprobe_action_handle_t action_code(uint32_t flags,
				    vmprobe_opcode_t **code,
				    uint32_t len);
vmprobe_action_handle_t action_regmod(uint8_t regnum,
				      unsigned long regval);
vmprobe_action_handle_t action_memmod(char *data,
				      unsigned long len,
				      unsigned long destaddr);

/*
 * Destroy an action (and cancel it first if necessary!).
 */
void action_destroy(vmprobe_action_handle_t handle);

/*
 * Unregisters a probe.
 * Upon successful completion, a value of 0 is returned. Otherwise, a value
 * of -1 is returned and the global integer variable errno is set to indicate 
 * the error.
 */
int
unregister_vmprobe(vmprobe_handle_t handle);

/*
 * Starts running the registered probes and wait until one of the probes stops.
 * To stop all probes, call stop_vmprobes() function below.
 */
void
run_vmprobes(void);

void
interrupt_vmprobes(void);

/*
 * Stops all running probes.
 */
void
stop_vmprobes(void);

int
restart_vmprobes(void);

/*
 * Disables a running probe. When disabled, both pre- and post-handlers are 
 * ignored until the probe is enabled back.
 * Returns a value of 0 upon successful completion, or a value of -1 if the
 * given handle is invalid.
 * NOTE: To enable a probe, call enable_vmprobe() function below.
 */
int
disable_vmprobe(vmprobe_handle_t handle);

/*
 * Enables an inactive probe.
 * Returns a value of 0 upon successful completion, or a value of -1 if the
 * given handle is invalid.
 */
int
enable_vmprobe(vmprobe_handle_t handle);

/*
 * Indicates whether a probe is enabled or not.
 * Returns a non-zero value if the probe is active, a value of 0 if the 
 * probe is inactive, or a value of -1 if the given handle is invalid.
 */
int
vmprobe_enabled(vmprobe_handle_t handle);

/*
 * Returns the virtual address the a probe is targeting.
 * If the given handle is invalid, the function returns a value of 0.
 */
unsigned long
vmprobe_vaddr(vmprobe_handle_t handle);

/*
 * Returns the id of the domain that a probe is instrumenting.
 * If the given handle is invalid, the function returns a value of 0.
 */
domid_t
vmprobe_domid(vmprobe_handle_t handle);

/*
 * Returns the pointer to a xenaccess instance that a probe belongs to.
 * If the given handle is invalid, the function returns NULL.
 * NOTE: This function is added to increase the performance of any future
 * abstraction on top of vmprobes.
 */
xa_instance_t *
vmprobe_xa_instance(vmprobe_handle_t handle);

unsigned char *
vmprobe_get_data(vmprobe_handle_t handle,struct cpu_user_regs *regs,
		 char *name,unsigned long addr,int pid,
		 unsigned long target_length,unsigned char *target_buf);

#endif /* _XEN_VMPROBES_H */
