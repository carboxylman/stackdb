#ifndef _XEN_VMTAP_PRIVATE_H
#define _XEN_VMTAP_PRIVATE_H

#include <xenctrl.h>
#include <vmprobes/vmprobes.h>
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

	/* User handler */
	vmtap_handler_t handler;

	/* VMprobe handle (also used as an identifier to indicate this probe) */
	vmprobe_handle_t vp_handle;
	
	/* Register values */
	struct cpu_user_regs *regs;
};

#endif /* _XEN_VMTAP_PRIVATE_H */
