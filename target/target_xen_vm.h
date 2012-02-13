#ifndef __TARGET_XEN_VM_H__
#define __TARGET_XEN_VM_H__


#include <xenctrl.h>
#include <xenaccess/xenaccess.h>

/*
 * target-specific state for xen vms.
 */
struct xen_vm_state {
    domid_t id;
    char *name;

    char *vmpath;
    char *kernel_filename;
    char *kernel_version;
    char *kernel_elf_filename;

    int context_dirty;
    int context_valid;
    vcpu_guest_context_t context;

    xc_dominfo_t dominfo;
    int dominfo_valid;

    /* XenAccess instance used to read/write domain's memory */
    xa_instance_t xa_instance;

    /* XXX: can we debug a 32-bit target on a 64-bit host?  If yes, how 
     * we use this might have to change.
     */
    unsigned long dr[8];
};

struct target *xen_vm_attach(char *domain);

#endif /* __TARGET_XEN_VM_H__ */
