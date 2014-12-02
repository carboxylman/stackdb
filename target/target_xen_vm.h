/*
 * Copyright (c) 2012-2014 The University of Utah
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __TARGET_XEN_VM_H__
#define __TARGET_XEN_VM_H__

#include "config.h"

#include <xenctrl.h>
#include <xen/xen.h>
#ifdef __x86_64__
#include <xen/hvm/save.h>
#endif

#include "target_arch_x86.h"
#include "evloop.h"

extern struct target_ops xen_vm_ops;

typedef enum {
    XV_FEATURE_BTS = 1,
} xen_vm_feature_t;

/*
 * target-specific state for xen vms.
 */

/*
 * Platform-specific registers for Xen VMs.
 */
#define XV_TSREG_START_INDEX 126
#define XV_TSREG_COUNT 14
#define XV_TSREG_END_INDEX (XV_TSREG_START_INDEX - XV_TSREG_COUNT + 1)
typedef enum {
    XV_TSREG_DR0 = XV_TSREG_START_INDEX,
    XV_TSREG_DR1 = XV_TSREG_START_INDEX - 1,
    XV_TSREG_DR2 = XV_TSREG_START_INDEX - 2,
    XV_TSREG_DR3 = XV_TSREG_START_INDEX - 3,
    XV_TSREG_DR6 = XV_TSREG_START_INDEX - 4,
    XV_TSREG_DR7 = XV_TSREG_START_INDEX - 5,

    XV_TSREG_CR0 = XV_TSREG_START_INDEX - 6,
    XV_TSREG_CR1 = XV_TSREG_START_INDEX - 7,
    XV_TSREG_CR2 = XV_TSREG_START_INDEX - 8,
    XV_TSREG_CR3 = XV_TSREG_START_INDEX - 9,
    XV_TSREG_CR4 = XV_TSREG_START_INDEX - 10,
    XV_TSREG_CR5 = XV_TSREG_START_INDEX - 11,
    XV_TSREG_CR6 = XV_TSREG_START_INDEX - 12,
    XV_TSREG_CR7 = XV_TSREG_START_INDEX - 13,
} xen_vm_tsreg_t;

struct xen_vm_spec {
    char *domain;
    char *kernel_filename;
    char *config_file;
    char *replay_dir;
    int dominfo_timeout;

    /* Max memcache limit, in bytes.  Backends must honor this! */
    unsigned long int memcache_mmap_size;

    unsigned int no_hw_debug_reg_clear:1,
	         no_hvm_setcontext:1,
	         clear_mem_caches_each_exception:1,
	         use_libvmi:1,
	         use_xenaccess:1,
	         no_use_multiplexer:1,
	         hypervisor_ignores_userspace_exceptions:1;
};

struct xen_vm_thread_state {
    /*
     * This is invalidated after each exception and resolved again.
     */
    ADDR pgd_phys;

    /*
     * Either this came directly from the CPU for the currently-running
     * thread; or we populated it based on the last saved CPU state for
     * the thread.
     *
     * Now, this gets tricky: if CONFIG_PREEMPT is supported, the
     * context will be the kernel thread's context -- not the user
     * context -- if the thread is in the kernel when it was preempted!
     *
     * Otherwise, it will be the state of the user thread (because
     * ifndef CONFIG_PREEMPT, kernel threads only stop on the
     * user-kernel boundary).
     */
    vcpu_guest_context_t context;

    //vcpu_guest_context_t alt_context;

    /* XXX: can we debug a 32-bit target on a 64-bit host?  If yes, how 
     * we use this might have to change.
     */
    unsigned long dr[8];
};

struct xen_vm_state {
    domid_t id;
    char *name;

    unsigned int hvm:1,
	         hvm_monitor_trap_flag_set:1;

    char *vmpath;
    char *ostype;
    char *kernel_filename;

    /* If we have an OS personality, try to load this from it. */
    ADDR kernel_start_addr;

    ADDR hypercall_page;

    shared_info_t *live_shinfo;
    xc_dominfo_t dominfo;
    vcpu_info_t vcpuinfo; /* Also part of loading dominfo. */
    int dominfo_valid;

    /* The most recent set of paging flags. */
    arch_x86_v2p_flags_t v2p_flags;

    /* Which memops are we using? */
    struct xen_vm_mem_ops *memops;
    void *memops_priv;

#ifdef __x86_64__
    uint8_t *hvm_context_buf;
    uint32_t hvm_context_bufsiz;
    HVM_SAVE_TYPE(CPU) *hvm_cpu;
#endif

    int evloop_fd;

    int xen_vm_vmp_client_fd;
    char *xen_vm_vmp_client_path;
};

struct target *xen_vm_instantiate(struct target_spec *spec,
				  struct evloop *evloop);
struct xen_vm_spec *xen_vm_build_spec(void);
void xen_vm_free_spec(struct xen_vm_spec *xspec);
int xen_vm_spec_to_argv(struct target_spec *spec,int *argc,char ***argv);

unsigned char *xen_vm_read_pid(struct target *target,int pid,ADDR addr,
			       unsigned long target_length,unsigned char *buf);
unsigned long xen_vm_write_pid(struct target *target,int pid,ADDR addr,
			       unsigned long length,unsigned char *buf);

/*
 * We support several different memory backends for Xen VMs.
 */
struct xen_vm_mem_ops {
    int (*init)(struct target *target);
    int (*attach)(struct target *target);
    int (*handle_exception_any)(struct target *target);
    int (*handle_exception_ours)(struct target *target);
    int (*handle_pause)(struct target *target);
    int (*addr_v2p)(struct target *target,tid_t tid,ADDR pgd,
		    ADDR vaddr,ADDR *paddr);
    unsigned char *(*read_phys)(struct target *target,ADDR paddr,
				unsigned long length,unsigned char *buf);
    unsigned long (*write_phys)(struct target *target,ADDR paddr,
				unsigned long length,unsigned char *buf);
    unsigned char *(*read_tid)(struct target *target,tid_t tid,ADDR pgd,ADDR addr,
			       unsigned long target_length,unsigned char *buf);
    unsigned long (*write_tid)(struct target *target,tid_t tid,ADDR pgd,ADDR addr,
			       unsigned long length,unsigned char *buf);
    int (*fini)(struct target *target);
};

#endif /* __TARGET_XEN_VM_H__ */
