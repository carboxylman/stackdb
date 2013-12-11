/*
 * Copyright (c) 2012-2013 The University of Utah
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


#include <xenctrl.h>
#include <xen/xen.h>
#ifdef __x86_64__
#include <xen/hvm/save.h>
#endif
#ifdef ENABLE_XENACCESS
#include <xenaccess/xenaccess.h>
#endif
#ifdef ENABLE_LIBVMI
#include <libvmi/libvmi.h>
#endif

#include "evloop.h"

extern struct target_ops xen_vm_ops;

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif
#define THREAD_SIZE 8192
/* x86_64 constant used in current_thread_ptr */
#define KERNEL_STACK_OFFSET (5*8)

typedef enum {
    XV_FEATURE_BTS = 1,
} xen_vm_feature_t;

/*
 * target-specific state for xen vms.
 */

#define THREAD_INFO_GET_CPL(tid) (((tid) & (0x3 << 62)) >> 62)
#define THREAD_INFO_GET_TID(tid) ((tid) & 0xffffffff)
#define THREAD_INFO_SET_CPL(tid,cpl) (tid) |= (((cpl) & 0x3) << 62)
#define THREAD_INFO_SET_TID(tid,pid) (tid) |= (0xffffffff & (pid))

#define TIF_32_SYSCALL_TRACE       0       /* syscall trace active */
#define TIF_32_NOTIFY_RESUME       1       /* resumption notification requested */
#define TIF_32_SIGPENDING          2       /* signal pending */
#define TIF_32_NEED_RESCHED        3       /* rescheduling necessary */
#define TIF_32_SINGLESTEP          4       /* restore singlestep on return to user mode */
#define TIF_32_IRET                5       /* return with iret */
#define TIF_32_SYSCALL_EMU         6       /* syscall emulation active */
#define TIF_32_SYSCALL_AUDIT       7       /* syscall auditing active */
#define TIF_32_SECCOMP             8       /* secure computing */
#define TIF_32_RESTORE_SIGMASK     9       /* restore signal mask in do_signal() */
#define TIF_32_MEMDIE              16
#define TIF_32_DEBUG               17      /* uses debug registers */
#define TIF_32_IO_BITMAP           18      /* uses I/O bitmap */

#define _TIF_32_SYSCALL_TRACE      (1<<TIF_32_SYSCALL_TRACE)
#define _TIF_32_NOTIFY_RESUME      (1<<TIF_32_NOTIFY_RESUME)
#define _TIF_32_SIGPENDING         (1<<TIF_32_SIGPENDING)
#define _TIF_32_NEED_RESCHED       (1<<TIF_32_NEED_RESCHED)
#define _TIF_32_SINGLESTEP         (1<<TIF_32_SINGLESTEP)
#define _TIF_32_IRET               (1<<TIF_32_IRET)
#define _TIF_32_SYSCALL_EMU        (1<<TIF_32_SYSCALL_EMU)
#define _TIF_32_SYSCALL_AUDIT      (1<<TIF_32_SYSCALL_AUDIT)
#define _TIF_32_SECCOMP            (1<<TIF_32_SECCOMP)
#define _TIF_32_RESTORE_SIGMASK    (1<<TIF_32_RESTORE_SIGMASK)
#define _TIF_32_DEBUG              (1<<TIF_32_DEBUG)
#define _TIF_32_IO_BITMAP          (1<<TIF_32_IO_BITMAP)


#define TIF_64_SYSCALL_TRACE       0       /* syscall trace active */
#define TIF_64_NOTIFY_RESUME       1       /* resumption notification requested */
#define TIF_64_SIGPENDING          2       /* signal pending */
#define TIF_64_NEED_RESCHED        3       /* rescheduling necessary */
#define TIF_64_SINGLESTEP          4       /* reenable singlestep on user return*/
#define TIF_64_IRET                5       /* force IRET */
#define TIF_64_SYSCALL_AUDIT       7       /* syscall auditing active */
#define TIF_64_SECCOMP             8       /* secure computing */
/* 16 free */
#define TIF_64_IA32                17      /* 32bit process */ 
#define TIF_64_FORK                18      /* ret_from_fork */
#define TIF_64_ABI_PENDING         19
#define TIF_64_MEMDIE              20

#define _TIF_64_SYSCALL_TRACE      (1<<TIF_64_SYSCALL_TRACE)
#define _TIF_64_NOTIFY_RESUME      (1<<TIF_64_NOTIFY_RESUME)
#define _TIF_64_SIGPENDING         (1<<TIF_64_SIGPENDING)
#define _TIF_64_SINGLESTEP         (1<<TIF_64_SINGLESTEP)
#define _TIF_64_NEED_RESCHED       (1<<TIF_64_NEED_RESCHED)
#define _TIF_64_IRET               (1<<TIF_64_IRET)
#define _TIF_64_SYSCALL_AUDIT      (1<<TIF_64_SYSCALL_AUDIT)
#define _TIF_64_SECCOMP            (1<<TIF_64_SECCOMP)
#define _TIF_64_IA32               (1<<TIF_64_IA32)
#define _TIF_64_FORK               (1<<TIF_64_FORK)
#define _TIF_64_ABI_PENDING        (1<<TIF_64_ABI_PENDING)

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

    unsigned int no_hw_debug_reg_clear:1,
	         no_hvm_setcontext:1;
};

struct xen_vm_thread_state {
    unsigned int exiting:1;

    ADDR task_struct_addr;

    /* 
     * This state all comes from the Linux PCB.  It is always blown away
     * on target_resume or target_singlestep .
     */
    /* The task struct is always valid unless we are in interrupt
     * context.
     */
    /* @task_struct is a "live" value!  it may be value_refresh()'d! */
    struct value *task_struct;
    num_t tgid;                      /* Read-only; not flushed */
    unum_t task_flags;
    /* The thread_info is always at the bottom of the kernel stack. */
    struct value *thread_info;
    unum_t thread_info_flags;
    num_t thread_info_preempt_count; /* Read-only; not flushed */
    /* The thread struct comes out of the task struct. */
    struct value *thread_struct;
    ADDR ptregs_stack_addr;
    ADDR mm_addr;
    /*
     * NB: pgd (cr3) is a little funny.  If the target is PAE, it might
     * be > 2**32.  So, this value has to always be a u64.
     *
     * Also note: this value is always a kernel virtual address; so use
     * __xen_vm_cr3 to read this value as a physical address.
     */
    uint64_t pgd;

    /*
     * These are information about the task's kernel stack.  esp0 is the
     * ring 0 stack pointer; stack_base is the bottom of the stack.
     */
    ADDR stack_base;
    ADDR esp0;

    /*
     * These are all for kernel threads, specifically.  The only time a
     * kernel thread will have saved context info is when it has been 
     * preempted or interrupted.  Otherwise, the kernel thread has been
     * context-switched out of, and this does not save its current
     * register set; context switching only saves esp/eip, fs/gs in the
     * task's thread struct; eflags and ebp were pushed on the stack
     * before context switch.
     */
    ADDR esp;
    ADDR eip;
    uint16_t fs;
    uint16_t gs;
    uint32_t eflags;
    ADDR ebp;

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

    /* XXX: can we debug a 32-bit target on a 64-bit host?  If yes, how 
     * we use this might have to change.
     */
    unsigned long dr[8];
};

struct xen_vm_state {
    domid_t id;
    char *name;

    /*
     * We create a default target_location_ctxt for loading things to
     * avoid a ton of mallocs, etc.  Most of what we need to load is not
     * thread-specific, and there is only a single giant kernel
     * memregion... so this is helpful.
     */
    struct target_location_ctxt *default_tlctxt;

    /*
     * Some kernel task_structs have thread_info; others have void *stack.
     * Some kernel pt_regs structs have ds/es/fs/gs, or various combinations.
     * Some kernel thread_structs have debugreg[8];
     * debugreg0--debugreg7; or a mix of ptrace_bps[4] and debugreg6 and
     * ptrace_dr7 ... argh.
     */
    unsigned int task_struct_has_thread_info:1,
	         task_struct_has_stack:1,
	         pt_regs_has_ds_es:1,
	         pt_regs_has_fs_gs:1,
	         thread_struct_has_ds_es:1,
	         thread_struct_has_fs:1,
	         thread_struct_has_debugreg:1,
	         thread_struct_has_debugreg0:1,
	         thread_struct_has_perf_debugreg:1,
	         hvm:1,
	         hvm_monitor_trap_flag_set:1;
    /*
     * Some kernel thread_structs have esp/esp0 (older); others have
     * sp/sp0 (newer).  These values are either esp0/sp0/eip, or esp/sp/ip.
     */
    const char *thread_sp0_member_name;
    const char *thread_sp_member_name;
    const char *thread_ip_member_name;

    /*
     * Newer kernels store uid/gid info in task->[real_]cred->(uid|gid);
     * older ones just in task->(uid|gid).
     */
    const char *task_uid_member_name;
    const char *task_gid_member_name;

    char *vmpath;
    char *ostype;
    char *kernel_filename;
    char *kernel_version;
    char *kernel_sysmap_filename;
    char *kernel_elf_filename;
    char *kernel_module_dir;
    ADDR kernel_start_addr;

    /*
     * On x86_64, current_thread_ptr is determined by looking at this
     * per_cpu offset.  On x86_64, percpu data is reached via %gs :(.
     */
    OFFSET kernel_stack_percpu_offset;

    struct bsymbol *init_task;
    struct symbol *task_struct_type;
    struct symbol *thread_struct_type;
    struct symbol *mm_struct_type;
    struct symbol *task_struct_type_ptr;
    struct symbol *pt_regs_type;
    int pt_regs_ip_offset;
    ADDR init_task_addr;
    struct symbol *thread_info_type;
    struct bsymbol *module_type;
    struct bsymbol *modules;

    struct probe *active_memory_probe;
    struct bsymbol *module_free_symbol;
    struct bsymbol *module_free_mod_symbol;
    int MODULE_STATE_LIVE;
    int MODULE_STATE_COMING;
    int MODULE_STATE_GOING;
    GHashTable *moddep;
    time_t last_moddep_mtime;

    struct probe *active_thread_entry_probe;
    struct bsymbol *thread_entry_f_symbol;
    struct bsymbol *thread_entry_v_symbol;

    struct probe *active_thread_exit_probe;
    struct bsymbol *thread_exit_f_symbol;
    struct bsymbol *thread_exit_v_symbol;

    unsigned int last_thread_count;
    uint8_t thread_auto_gc_counter;

    shared_info_t *live_shinfo;
    xc_dominfo_t dominfo;
    vcpu_info_t vcpuinfo; /* Also part of loading dominfo. */
    int dominfo_valid;

    GHashTable *task_struct_addr_to_thread;

#ifdef __x86_64__
    uint8_t *hvm_context_buf;
    uint32_t hvm_context_bufsiz;
    HVM_SAVE_TYPE(CPU) *hvm_cpu;
#endif

    int evloop_fd;

#ifdef ENABLE_XENACCESS
    /* XenAccess instance used to read/write domain's memory */
    xa_instance_t xa_instance;
#endif
#ifdef ENABLE_LIBVMI
    /* VMI instance used to read/write domain's memory */
    vmi_instance_t vmi_instance;
    int vmi_page_size;
#endif
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

struct symbol *linux_get_task_struct_type(struct target *target);
struct symbol *linux_get_task_struct_type_ptr(struct target *target);
struct symbol *linux_get_thread_info_type(struct target *target);
struct value *linux_load_current_task(struct target *target,
				      REGVAL kernel_esp);
struct value *linux_load_current_task_as_type(struct target *target,
					      struct symbol *datatype,
					      REGVAL kernel_esp);
int linux_get_task_pid(struct target *target,struct value *task);
int linux_get_task_tid(struct target *target,struct value *task);
struct value *linux_get_task(struct target *target,tid_t tid);

struct value *linux_load_current_thread_as_type(struct target *target,
						struct symbol *datatype,
						REGVAL kernel_esp);

char *linux_file_get_path(struct target *target,struct value *task,
			  struct value *file,char *buf,int buflen);

#define PREEMPT_MASK   0x000000ff
#define SOFTIRQ_MASK   0x0000ff00
#define HARDIRQ_MASK   0x0fff0000
#define PREEMPT_ACTIVE 0x10000000
#define PREEMPT_BITSHIFT 0
#define SOFTIRQ_BITSHIFT 8
#define HARDIRQ_BITSHIFT 16

/*
 * These macros are different than the kernel's!
 */
#define PREEMPT_COUNT(p) (((p) & PREEMPT_MASK) >> PREEMPT_BITSHIFT)
#define SOFTIRQ_COUNT(p) (((p) & SOFTIRQ_MASK) >> SOFTIRQ_BITSHIFT)
#define HARDIRQ_COUNT(p) (((p) & HARDIRQ_MASK) >> HARDIRQ_BITSHIFT)

num_t linux_get_preempt_count(struct target *target);

/*
 * If the iterator returns 1, we break out of the loop.
 * If the iterator returns -1, we break out of the loop, AND do NOT free
 * @value (so the caller can save it).
 */
typedef int (*linux_list_iterator_t)(struct target *t,struct value *value,
				     void *data);
int linux_list_for_each_struct(struct target *t,struct bsymbol *bsymbol,
			       char *list_head_member_name,int nofree,
			       linux_list_iterator_t iterator,void *data);

int linux_list_for_each_entry(struct target *t,struct bsymbol *btype,
			      struct bsymbol *list_head,
			      char *list_head_member_name,int nofree,
			      linux_list_iterator_t iterator,void *data);

#endif /* __TARGET_XEN_VM_H__ */
