#ifndef _XEN_VMTAP_H
#define _XEN_VMTAP_H

#include <stdbool.h>
#include <vmprobes/vmprobes.h>

#ifndef VMTAP_PROBE_MAX
#define VMTAP_PROBE_MAX (VMPROBE_MAX)
#endif

typedef void (*vmtap_handler_t)(int, void *);

/*
 * Injects a probe at a given probe-point.
 * NOTE: read the file README for the details of probe-point specifications.
 */
bool
probe(const char *probepoint, vmtap_handler_t handler);

/*
 * Starts all probes injected.
 * NOTE: this function does not return until stop() is called or Ctrl+C is 
 * pressed.
 */
void
run(void);

/*
 * Stops all probes injected.
 */
void
stop(void);

/*
 * Disables a probe.
 */
bool
disable(int probe);

/*
 * Enables an inactive probe.
 */
bool
enable(int probe);

/*
 * Returns the id of the instrumented guest domain.
 */
int
domid(int probe);

/*
 * Returns the name of the instrumented guest domain.
 */
const char *
domain(int probe);

/*
 * Returns the virtual address of the probe-point.
 */
unsigned long
address(int probe);

/*
 * Returns the name of the instrumented symbol.
 */
const char *
symbol(int probe);

/*
 * Returns the offset from symbol to target address.
 */
unsigned long
offset(int probe);

/*
 * Returns an argument of the instrumented system call.
 * To indicate which argument to obtain, pass a number starting from 0 as the
 * second argument of this function.
 */
unsigned long
arg(int probe, int num);

/*
 * Returns an string-type argument of the instrumented system call.
 * To indicate which argument to obtain, pass a number starting from 0 as the
 * second argument of this function.
 * FIXME: this function will be deprecated when vmtap is integrated with a
 * "debuginfo explorer".
 */
const char *
argstr(int probe, int num);

#endif /* _XEN_VMTAP_H */
