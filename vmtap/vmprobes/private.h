#ifndef _XEN_VMPROBES_PRIVATE_H
#define _XEN_VMPROBES_PRIVATE_H

#include <stdbool.h>

#include <xenctrl.h>
#include <xenaccess/xenaccess.h>

#include "list.h"
#include "vmprobes.h"
#include "vmprobes_arch.h"

struct vmprobe_probepoint;

/* 
 * vmprobe -- represents a single probe.
 */
struct vmprobe {
    /* A unique value that indicates this probe */
    vmprobe_handle_t handle;
    
    /* Link to the probe list in the parent domain */
    struct list_head node;

    /* User handler to run before probe-point is executed */
    vmprobe_handler_t pre_handler;

    /* User handler to run after probe-point is executed */
    vmprobe_handler_t post_handler;

    /* The target probe-point */
    struct vmprobe_probepoint *probepoint;

    /* True when the vmprobe is disabled */
    bool disabled;
};

/*
 * vmprobe_probepoint_state -- various states of a probe-point
 */
enum vmprobe_probepoint_state {
    VMPROBE_INSERTING,  // domain quiescing prior to breakpoint insertion
    VMPROBE_BP_SET,     // breakpoint in place
    VMPROBE_REMOVING,   // domain quiescing prior to breakpoint removal
    VMPROBE_DISABLED,   // breakpoint removal completed
};

struct vmprobe_domain;

/*
 * vmprobe_point -- represents a probe-point, at which several vmprobes can be
 * registered.
 * A probe-point can contain multiple probes.
 */
struct vmprobe_probepoint {
    /* Link to the global probepoint list */
    struct list_head list;

    /* Link to the probepoint list in the parent domain */
    struct list_head node;

    /* Location of the probe-point (virtual address) */
    unsigned long vaddr;

    /* The parent vmprobe_domain */
    struct vmprobe_domain *domain;

    /* Current state of this probe-point */
    enum vmprobe_probepoint_state state;
    
    /* Saved opcode (which has been replaced with breakpoint) */
    vmprobe_opcode_t opcode;
    
    /* list of probes at this probe-point */
    struct list_head probe_list;
};

/*
 * vmprobe_domain -- represents an instrumented domain.
 * A domain can include multiple probe-points.
 */
struct vmprobe_domain {
    /* Link to the domain list */
    struct list_head list;
    
    /* Domain ID */
    domid_t id;

    /* List of probe-points in this domain */
    struct list_head probepoint_list;

    /* The original ip value before a breakpoint hit */
    unsigned long org_ip;

    /* The probepoint currently being single-stepped*/
    struct vmprobe_probepoint *sstep_probepoint;

    /* XenAccess instance used to read/write domain's memory */
    xa_instance_t xa_instance;
};

#endif /* _XEN_VMPROBES_PRIVATE_H */
