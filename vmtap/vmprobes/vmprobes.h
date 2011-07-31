#ifndef _XEN_VMPROBES_H
#define _XEN_VMPROBES_H

#include <xenctrl.h>

struct pt_regs;

typedef int vmprobe_handle_t;
typedef int (*vmprobe_handler_t)(vmprobe_handle_t, struct pt_regs *);

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
 * To enable a probe, call enable_vmprobe() function below.
 */
int
disable_vmprobe(vmprobe_handle_t handle);

/*
 * Enables a disabled probe.
 */
int
enable_vmprobe(vmprobe_handle_t handle);

#endif /* _XEN_VMPROBES_H */
