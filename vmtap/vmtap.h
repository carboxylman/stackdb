#ifndef _XEN_VMTAP_H
#define _XEN_VMTAP_H

#include <stdbool.h>
#include <xenctrl.h>
#include <vmprobes/vmprobes.h>

#ifndef VMTAP_PROBE_MAX
#define VMTAP_PROBE_MAX (VMPROBE_MAX)
#endif

typedef void (*vmtap_callback_t)(int, void *);

#ifdef SWIG
/*
 * Injects a probe at a given probe-point. A user handler (a Python function)
 * is called whenever the probe is triggered.
 * NOTE: Read the README file for details about probe-point specifications.
 */
bool
probe(const char *probepoint, PyObject *pyhandler);
#endif /* SWIG */

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
domid_t
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
 * To indicate which argument to obtain, pass a number starting from 0 for the
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
arg_string(int probe, int num);

/*
 * Reads a char value at a given address in the domain of a probe.
 */
char
read_char(int probe, unsigned long address);

/*
 * Reads an integer value at a given address in the domain of a probe.
 */
int
read_int(int probe, unsigned long address);

/*
 * Reads a long value at a given address in the domain of a probe.
 */
long
read_long(int probe, unsigned long address);

/*
 * Reads a float value at a given address in the domain of a probe.
 */
float
read_float(int probe, unsigned long address);

/*
 * Reads a double value at a given address in the domain of a probe.
 */
double
read_double(int probe, unsigned long address);

/*
 * Reads a string value at a given address in the domain of a probe.
 */
const char *
read_string(int probe, unsigned long address);

#endif /* _XEN_VMTAP_H */
