#ifndef _XEN_VMTAP_PRIVATE_H
#define _XEN_VMTAP_PRIVATE_H

#include <xenctrl.h>
#include <vmprobes/vmprobes.h>
#include <xenaccess/xenaccess.h>
#include "vmtap.h"

/*
 * vmtap_probe -- represents a single vmtap probe.
 */
struct vmtap_probe
{
    /* Domain name */
    char *domain;    

    /* Symbol name */
    char *symbol;

    /* Offset from symbol to target address */
    unsigned long offset;

    /* User handler in python */
    void *pyhandler;

    /* VMprobe handle (also used as an identifier to indicate this probe) */
    vmprobe_handle_t vp_handle;

	/* XenAccess instance borrowed from domains in VMprobes */
	xa_instance_t *xa_instance;
    
    /* Register values */
    struct cpu_user_regs *regs;
};

/* Internal function that does probe injection 
   NOTE: Python user is supposed to call probe() instead of this function. */
bool
__probe(const char *probepoint, vmtap_callback_t callback, void *pyhandler);

#endif /* _XEN_VMTAP_PRIVATE_H */
