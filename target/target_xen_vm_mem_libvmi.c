/*
 * Copyright (c) 2012, 2013, 2014 The University of Utah
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

#include "config.h"

#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "common.h"
#include "arch.h"
#include "arch_x86.h"
#include "arch_x86_64.h"
#include "target_api.h"
#include "target.h"
#include "target_arch_x86.h"
#include "target_os.h"

#include <xenctrl.h>
#include <xs.h>
#include "libvmi.h"
#include "target_xen_vm.h"


struct xen_vm_mem_libvmi_state {
    /* VMI instance used to read/write domain's memory */
    vmi_instance_t vmi_instance;
    int vmi_page_size;
};

/*
 * Prototypes.
 */

int xen_vm_mem_libvmi_init(struct target *target) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_libvmi_state *mstate;

    xstate = (struct xen_vm_state *)target->state;

    mstate = (struct xen_vm_mem_libvmi_state *)calloc(1,sizeof(*mstate));

    if (vmi_init(&mstate->vmi_instance,
		 VMI_XEN|VMI_INIT_PARTIAL, xstate->name) == VMI_FAILURE) {
        verror("failed to init vmi instance for dom %d\n", xstate->id);
	free(mstate);
        return -1;
    }

    xstate->memops_priv = mstate;

    return 0;
}

int xen_vm_mem_libvmi_attach(struct target *target) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_libvmi_state *mstate;
    unsigned int size;
    char *tmp;
    char *val;
    char *symbol_file;
    OFFSET tasks_offset,pid_offset,mm_offset,pgd_offset;

    xstate = (struct xen_vm_state *)target->state;
    mstate = (struct xen_vm_mem_libvmi_state *)xstate->memops_priv;

    /*
     * Make sure xenaccess/libvmi is setup to read from userspace
     * memory.
     *
     * This is hacky, but we do it by reading properties that the
     * personality has (hopefully) set.
     */
    val = (char *)g_hash_table_lookup(target->config,"OS_KERNEL_TASKS_OFFSET");
    if (val)
	tasks_offset = (ADDR)strtol(val,NULL,0);
    val = (char *)g_hash_table_lookup(target->config,"OS_KERNEL_PID_OFFSET");
    if (val)
	pid_offset = (ADDR)strtol(val,NULL,0);
    val = (char *)g_hash_table_lookup(target->config,"OS_KERNEL_MM_OFFSET");
    if (val)
	mm_offset = (ADDR)strtol(val,NULL,0);
    val = (char *)g_hash_table_lookup(target->config,"OS_KERNEL_MM_PGD_OFFSET");
    if (val)
	pgd_offset = (ADDR)strtol(val,NULL,0);

    symbol_file = (char *)g_hash_table_lookup(target->config,
					      "OS_KERNEL_SYSMAP_FILE");
    if (!symbol_file)
	symbol_file = "";

    /*
     * Offsets are:
     *   linux_tasks: offset of "tasks" in task_struct
     *   linux_mm:    offset of "mm" in task_struct
     *   linux_pid:   offset of "pid" in task_struct
     *   linux_pgd:   offset of "pgd" in mm_struct
     */
#define LIBVMI_CONFIG_TEMPLATE "{ostype=\"Linux\";" \
	" sysmap=\"%s\"; linux_tasks=0x%"PRIxOFFSET"; linux_mm=0x%"PRIxOFFSET";" \
	" linux_pid=0x%"PRIxOFFSET"; linux_pgd=0x%"PRIxOFFSET";" \
	" }"
#define LIBVMI_CONFIG_TEMPLATE_HVM "{ ostype=\"Linux\"; sysmap=\"%s\"; }"

    if (0 && xstate->hvm) {
	size = strlen(LIBVMI_CONFIG_TEMPLATE_HVM) + strlen(symbol_file) + 1;
	tmp = malloc(size);
	snprintf(tmp,size,LIBVMI_CONFIG_TEMPLATE_HVM,symbol_file);
    }
    else {
	size = strlen(LIBVMI_CONFIG_TEMPLATE) + strlen(symbol_file) + 4 * 16 + 1;
	tmp = malloc(size);
	snprintf(tmp,size,LIBVMI_CONFIG_TEMPLATE,
		 symbol_file,tasks_offset,mm_offset,pid_offset,pgd_offset);
    }

    if (vmi_init_complete(&mstate->vmi_instance, tmp) == VMI_FAILURE) {
	verror("failed to complete init of vmi instance for dom %d (config was '%s')\n",
	       xstate->id,tmp);
	vmi_destroy(mstate->vmi_instance);
	free(tmp);
	tmp = NULL;
	return -1;
    }

    /* XXX this is in the vmi_instance, but they don't expose it! */
    mstate->vmi_page_size = XC_PAGE_SIZE;

    return 0;
}

int xen_vm_mem_libvmi_handle_exception_any(struct target *target) {
    return 0;
}

int xen_vm_mem_libvmi_handle_exception_ours(struct target *target) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_libvmi_state *mstate;
    struct xen_vm_spec *xspec;

    xstate = (struct xen_vm_state *)target->state;
    xspec = (struct xen_vm_spec *)target->spec->backend_spec;
    mstate = (struct xen_vm_mem_libvmi_state *)xstate->memops_priv;

    /* XXX is this right? */
    if (xspec->clear_mem_caches_each_exception) {
	vmi_v2pcache_flush(mstate->vmi_instance);
	vmi_symcache_flush(mstate->vmi_instance);
	vmi_pidcache_flush(mstate->vmi_instance);
    }

    return 0;    
}

int xen_vm_mem_libvmi_handle_pause(struct target *target) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_libvmi_state *mstate;
    struct xen_vm_spec *xspec;

    xstate = (struct xen_vm_state *)target->state;
    xspec = (struct xen_vm_spec *)target->spec->backend_spec;
    mstate = (struct xen_vm_mem_libvmi_state *)xstate->memops_priv;

    /* XXX is this right? */
    if (xspec->clear_mem_caches_each_exception) {
	vmi_v2pcache_flush(mstate->vmi_instance);
	vmi_symcache_flush(mstate->vmi_instance);
	vmi_pidcache_flush(mstate->vmi_instance);
    }

    return 0;    
}

int xen_vm_mem_libvmi_addr_v2p(struct target *target,tid_t tid,ADDR pgd,
			       ADDR vaddr,ADDR *paddr) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_libvmi_state *mstate;
    uint64_t tvaddr = 0;
    uint64_t tpaddr = 0;
    uint64_t opaddr = 0;

    xstate = (struct xen_vm_state *)target->state;
    mstate = (struct xen_vm_mem_libvmi_state *)xstate->memops_priv;

    /*
     * Strip the offset bits to improve libvmi cache perf.
     */
    tvaddr = vaddr & ~(__PAGE_SIZE - 1);

    tpaddr = vmi_pagetable_lookup(mstate->vmi_instance,pgd,tvaddr);
    if (tpaddr == 0) {
	verror("could not lookup vaddr 0x%"PRIxADDR" in tid %"PRIiTID
	       " pgd 0x%"PRIxADDR"!\n",
	       vaddr,tid,pgd);
	return -1;
    }

    *paddr = tpaddr | (vaddr & (__PAGE_SIZE - 1));
    target_arch_x86_v2p(target,pgd,vaddr,ARCH_X86_V2P_LMA,&opaddr);

    vdebug(12,LA_TARGET,LF_XV,
	   "tid %"PRIiTID" vaddr 0x%"PRIxADDR" -> paddr 0x%"PRIxADDR" (paddr 0x%"PRIxADDR")\n",
	   tid,vaddr,*paddr,opaddr);

    return 0;
}

unsigned char *xen_vm_mem_libvmi_read_phys(struct target *target,ADDR paddr,
					   unsigned long length,
					   unsigned char *buf) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_libvmi_state *mstate;
    unsigned char *retval = NULL;

    xstate = (struct xen_vm_state *)target->state;
    mstate = (struct xen_vm_mem_libvmi_state *)xstate->memops_priv;

    if (!buf)
	retval = (unsigned char *)malloc(length+1);
    else 
	retval = buf;

    if (vmi_read_pa(mstate->vmi_instance,paddr,retval,length) != length) {
	verror("could not read %lu bytes at paddr 0x%"PRIxADDR": %s!\n",
	       length,paddr,strerror(errno));
	goto errout;
    }

    return retval;

 errout:
    if (!buf && retval)
	free(retval);
    if (!errno)
	errno = EFAULT;
    return NULL;
}

unsigned long xen_vm_mem_libvmi_write_phys(struct target *target,ADDR paddr,
					   unsigned long length,
					   unsigned char *buf) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_libvmi_state *mstate;

    xstate = (struct xen_vm_state *)target->state;
    mstate = (struct xen_vm_mem_libvmi_state *)xstate->memops_priv;

    if (vmi_write_pa(mstate->vmi_instance,paddr,buf,length) != length) {
	verror("could not write %lu bytes at paddr 0x%"PRIxADDR": %s!\n",
	       length,paddr,strerror(errno));
	goto errout;
    }

    return length;

 errout:
    if (!errno)
	errno = EFAULT;
    return 0;
}

/*
 * Reads a block of memory from the target.  If @buf is non-NULL, we
 * assume it is at least @length bytes long; the result is placed into
 * @buf and @buf is returned.  If @buf is NULL, we allocate a buffer
 * large enough to hold the result (@length if @length >0; if @length is
 * 0 we attempt to read a string at that address; we stop when we hit a
 * NULL byte).
 *
 * On error, returns NULL, and sets errno.
 */
unsigned char *xen_vm_mem_libvmi_read_tid(struct target *target,
					  tid_t tid,ADDR pgd,ADDR addr,
					  unsigned long target_length,
					  unsigned char *buf)
{
    struct xen_vm_state *xstate;
    struct xen_vm_mem_libvmi_state *mstate;
    vmi_instance_t vmi;
    int alloced = 0;
    size_t cc;
    ADDR paddr;

    xstate = (struct xen_vm_state *)target->state;
    mstate = (struct xen_vm_mem_libvmi_state *)xstate->memops_priv;
    vmi = mstate->vmi_instance;

    fflush(stderr);
    fflush(stdout);

    /*
     * Change the TID to 0 if TID was global.  The Xen backend always
     * defaults non-tid-specific reads/writes to the kernel, via
     * TID_GLOBAL.
     */
    if (tid == TID_GLOBAL)
	tid = 0;

    xen_vm_mem_libvmi_addr_v2p(target,tid,pgd,addr,&paddr);

    vdebug(16,LA_TARGET,LF_XV,
	   "read dom %d: addr=0x%"PRIxADDR" len=%d tid=%d\n",
	   xstate->id,addr,target_length,tid);

    /* if length == 0, we are copying in a string. */
    if (target_length == 0)
	return (unsigned char *)vmi_read_str_va(vmi, (addr_t)addr, tid);

    /* allocate buffer if necessary */
    if (!buf) {
	buf = malloc(target_length + 1);
	alloced = 1;
    }

    /* read the data */
    if (buf) {
	cc = vmi_read_va(vmi, (addr_t)addr, tid, buf, target_length);

	/* there is no provision for a partial read, assume an error */
	if ((unsigned long)cc != target_length) {
	    if (cc)
		verror("vmi_read_va returns partial data (%lu of %lu)\n",
		       (unsigned long)cc, target_length);
	    else 
		verror("vmi_read_va returns no data (%lu of %lu)\n",
		       (unsigned long)cc, target_length);
	    if (alloced)
		free(buf);
	    return NULL;
	}
	else {
	    vdebug(16,LA_TARGET,LF_XV,
		   "read dom %d: addr=0x%"PRIxADDR" len=%d tid=%d SUCCESS\n",
		   xstate->id,addr,target_length,tid);
	}
    }
    else
	verror("could not malloc buf\n");

    return buf;
}

/*
 * Writes @length bytes from @buf to @addr.  Returns the number of bytes
 * written (and sets errno nonzero if there is an error).  Successful if
 * @return == @length.
 */
unsigned long xen_vm_mem_libvmi_write_tid(struct target *target,
					  tid_t tid,ADDR pgd,ADDR addr,
					  unsigned long length,
					  unsigned char *buf) {
    struct xen_vm_state *xstate;
    struct xen_vm_mem_libvmi_state *mstate;

    xstate = (struct xen_vm_state *)target->state;
    mstate = (struct xen_vm_mem_libvmi_state *)xstate->memops_priv;

    /*
     * Change the TID to 0 if TID was global.  The Xen backend always
     * defaults non-tid-specific reads/writes to the kernel, via
     * TID_GLOBAL.
     */
    if (tid == TID_GLOBAL)
	tid = 0;

    vdebug(16,LA_TARGET,LF_XV,
	   "write dom %d: addr=0x%"PRIxADDR" len=%d tid=%d\n",
	   xstate->id,addr,length,tid);

    return (unsigned long)vmi_write_va(mstate->vmi_instance, (addr_t)addr,
				       tid, buf, (size_t)length);
}

int xen_vm_mem_libvmi_fini(struct target *target) {
    struct xen_vm_state *xstate;

    xstate = (struct xen_vm_state *)target->state;

    if (xstate->memops_priv) {
	free(xstate->memops_priv);
	xstate->memops_priv = NULL;
    }

    return 0;
}

struct xen_vm_mem_ops xen_vm_mem_ops_libvmi = {
    .init = xen_vm_mem_libvmi_init,
    .attach = xen_vm_mem_libvmi_attach,
    .handle_exception_any = xen_vm_mem_libvmi_handle_exception_any,
    .handle_exception_ours = xen_vm_mem_libvmi_handle_exception_ours,
    .handle_pause = xen_vm_mem_libvmi_handle_pause,
    .addr_v2p = xen_vm_mem_libvmi_addr_v2p,
    .read_phys = xen_vm_mem_libvmi_read_phys,
    .write_phys = xen_vm_mem_libvmi_write_phys,
    .read_tid = xen_vm_mem_libvmi_read_tid,
    .write_tid = xen_vm_mem_libvmi_write_tid,
    .fini = xen_vm_mem_libvmi_fini,
};
