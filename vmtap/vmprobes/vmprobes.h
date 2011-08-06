#ifndef _XEN_VMPROBES_H
#define _XEN_VMPROBES_H

#include <xenctrl.h>
#include <xenaccess/xenaccess.h>

#ifndef VMPROBE_MAX
#define VMPROBE_MAX (1024)
#endif

typedef int vmprobe_handle_t;
typedef int (*vmprobe_handler_t)(vmprobe_handle_t, struct cpu_user_regs *);

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

/*
 * Stops all running probes.
 */
void
stop_vmprobes(void);

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

#endif /* _XEN_VMPROBES_H */
