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
#ifdef ENABLE_XENACCESS
#include <xenaccess/xenaccess.h>
#endif
#ifdef ENABLE_LIBVMI
#include <libvmi/libvmi.h>
#endif

#define THREAD_SIZE 8192

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
    char *config_file;
    char *replay_dir;
    int xenaccess_debug_level;
    char *console_logfile;
};

struct xen_vm_thread_state {
    ADDR task_struct_addr;

    /* 
     * This state all comes from the Linux PCB.  It is always blown away
     * on target_resume or target_singlestep .
     */
    /* The task struct is always valid unless we are in interrupt
     * context.
     */
    struct value *task_struct;
    num_t tgid;                      /* Read-only; not flushed */
    num_t task_flags;
    /* The thread_info is always at the bottom of the kernel stack. */
    struct value *thread_info;
    unum_t thread_info_flags;
    num_t thread_info_preempt_count; /* Read-only; not flushed */
    /* The thread struct comes out of the task struct. */
    struct value *thread_struct;
    ADDR ptregs_stack_addr;

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
    
    vcpu_guest_context_t context;

    /* XXX: can we debug a 32-bit target on a 64-bit host?  If yes, how 
     * we use this might have to change.
     */
    unsigned long dr[8];
};

struct xen_vm_state {
    domid_t id;
    char *name;

    char *vmpath;
    char *kernel_filename;
    char *kernel_version;
    char *kernel_elf_filename;
    char *kernel_module_dir;
    ADDR kernel_start_addr;

    struct bsymbol *init_task;
    struct symbol *task_struct_type;
    struct symbol *task_struct_type_ptr;
    ADDR init_task_addr;
    struct symbol *thread_info_type;
    struct bsymbol *module_type;
    struct bsymbol *modules;

    unsigned int last_thread_count;
    uint8_t thread_auto_gc_counter;

    xc_dominfo_t dominfo;
    vcpu_info_t vcpuinfo; /* Also part of loading dominfo. */
    int dominfo_valid;

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

struct target *xen_vm_instantiate(struct target_spec *spec);
struct xen_vm_spec *xen_vm_build_spec(void);
void xen_vm_free_spec(struct xen_vm_spec *xspec);

struct symbol *linux_get_task_struct_type(struct target *target);
struct symbol *linux_get_task_struct_type_ptr(struct target *target);
struct symbol *linux_get_thread_info_type(struct target *target);
struct value *linux_load_current_task(struct target *target);
struct value *linux_load_current_task_as_type(struct target *target,
					      struct symbol *datatype);
int linux_get_task_pid(struct target *target,struct value *task);
int linux_get_task_tid(struct target *target,struct value *task);
struct value *linux_get_task(struct target *target,tid_t tid);

struct value *linux_load_current_thread_as_type(struct target *target,
						struct symbol *datatype);

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
