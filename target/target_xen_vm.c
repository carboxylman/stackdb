#include <assert.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <endian.h>

#include <gelf.h>
#include <elf.h>
#include <libelf.h>

#include "config.h"

#include "dwdebug.h"
#include "target_api.h"
#include "target.h"

#include <xenctrl.h>
#include <xen/xen.h>
#include <xs.h>
#include <xenaccess/xenaccess.h>
#include <xenaccess/xa_private.h>

#include "target_xen_vm.h"

/*
 * Prototypes.
 */
struct target *xen_vm_attach(char *domain,
			     struct debugfile_load_opts **dfoptlist);

static int xen_vm_init(struct target *target);
static int xen_vm_attach_internal(struct target *target);
static int xen_vm_detach(struct target *target);
static int xen_vm_fini(struct target *target);
static int xen_vm_loadspaces(struct target *target);
static int xen_vm_loadregions(struct target *target,struct addrspace *space);
static int xen_vm_loaddebugfiles(struct target *target,struct addrspace *space,
				 struct memregion *region);
static target_status_t xen_vm_status(struct target *target);
static int xen_vm_pause(struct target *target);
static int xen_vm_resume(struct target *target);
static target_status_t xen_vm_monitor(struct target *target);
static target_status_t xen_vm_poll(struct target *target,
				   target_poll_outcome_t *outcome,int *pstatus);
static unsigned char *xen_vm_read(struct target *target,ADDR addr,
				  unsigned long length,unsigned char *buf,
				  void *targetspecdata);
static unsigned long xen_vm_write(struct target *target,ADDR addr,
				  unsigned long length,unsigned char *buf,
				  void *targetspecdata);
static char *xen_vm_reg_name(struct target *target,REG reg);
static REGVAL xen_vm_read_reg(struct target *target,REG reg);
static int xen_vm_write_reg(struct target *target,REG reg,REGVAL value);
static int xen_vm_flush_context(struct target *target);
static REG xen_vm_get_unused_debug_reg(struct target *target);
static int xen_vm_set_hw_breakpoint(struct target *target,REG num,ADDR addr);
static int xen_vm_set_hw_watchpoint(struct target *target,REG num,ADDR addr,
				    probepoint_whence_t whence,
				    probepoint_watchsize_t watchsize);
static int xen_vm_unset_hw_breakpoint(struct target *target,REG num);
static int xen_vm_unset_hw_watchpoint(struct target *target,REG num);
int xen_vm_disable_hw_breakpoints(struct target *target);
int xen_vm_enable_hw_breakpoints(struct target *target);
int xen_vm_notify_sw_breakpoint(struct target *target,ADDR addr,
				int notification);
int xen_vm_singlestep(struct target *target);
int xen_vm_singlestep_end(struct target *target);

/*
 * Globals.
 */
static int xc_refcnt = 0;

static int xc_handle = -1;
static int xce_handle = -1;
#if !defined(XC_EVTCHN_PORT_T)
#error "XC_EVTCHN_PORT_T undefined!"
#endif
static XC_EVTCHN_PORT_T dbg_port = -1;

#define EF_TF (0x00000100)
#define EF_IF (0x00000200)

/*
 * Set up the target interface for this library.
 */
struct target_ops xen_vm_ops = {
    .init = xen_vm_init,
    .fini = xen_vm_fini,
    .attach = xen_vm_attach_internal,
    .detach = xen_vm_detach,
    .loadspaces = xen_vm_loadspaces,
    .loadregions = xen_vm_loadregions,
    .loaddebugfiles = xen_vm_loaddebugfiles,
    .status = xen_vm_status,
    .pause = xen_vm_pause,
    .resume = xen_vm_resume,
    .monitor = xen_vm_monitor,
    .poll = xen_vm_poll,
    .read = xen_vm_read,
    .write = xen_vm_write,
    .regname = xen_vm_reg_name,
    .readreg = xen_vm_read_reg,
    .writereg = xen_vm_write_reg,
    .flush_context = xen_vm_flush_context,
    .get_unused_debug_reg = xen_vm_get_unused_debug_reg,
    .set_hw_breakpoint = xen_vm_set_hw_breakpoint,
    .set_hw_watchpoint = xen_vm_set_hw_watchpoint,
    .unset_hw_breakpoint = xen_vm_unset_hw_breakpoint,
    .unset_hw_watchpoint = xen_vm_unset_hw_watchpoint,
    .disable_hw_breakpoints = xen_vm_disable_hw_breakpoints,
    .enable_hw_breakpoints = xen_vm_enable_hw_breakpoints,
    .notify_sw_breakpoint = xen_vm_notify_sw_breakpoint,
    .singlestep = xen_vm_singlestep,
    .singlestep_end = xen_vm_singlestep_end,
};

/**
 ** These are the only user-visible functions.
 **/

/*
 * Attaches to domid.  We basically check the xenstore to figure out
 * what kernel the domain is running, and try to find vmlinux based on
 * that.  We also read how much mem the domain has; if it is
 * PAE-enabled; 
 */
struct target *xen_vm_attach(char *domain,
			     struct debugfile_load_opts **dfoptlist) {
    struct target *target;
    struct xen_vm_state *xstate = NULL;
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char *buf = NULL;
    char *tmp = NULL;
    char **domains = NULL;
    unsigned int size;
    unsigned int i;
    int have_id = 0;
    unsigned int slen;
    int fd;
    Elf *elf = NULL;
    char *eident = NULL;

    if (geteuid() != 0) {
	verror("must be root!\n");
	errno = EPERM;
	return NULL;
    }

    vdebug(5,LOG_T_XV,"attaching to domain %s\n",domain);

    if (!(target = target_create("xen_vm",NULL,&xen_vm_ops,dfoptlist)))
	return NULL;

    if (!(xstate = (struct xen_vm_state *)malloc(sizeof(*xstate)))) {
	free(target);
	return NULL;
    }
    memset(xstate,0,sizeof(*xstate));

    target->state = xstate;

    if (!(buf = malloc(PATH_MAX*2)))
	return NULL;

    if (!(xsh = xs_domain_open())) {
	verror("could not open xenstore!\n");
	return NULL;
    }

    /* First figure out whether we need to resolve the ID, or the name. */
    errno = 0;
    xstate->id = (domid_t)strtol(domain,&tmp,10);
    if (errno == ERANGE) {
	verror("bad domain id: %s\n",strerror(errno));
	goto errout;
    }
    else if (errno == EINVAL || tmp == domain) 
	have_id = 0;
    else {
	vdebug(4,LOG_T_XV,"found id %d (from %s)\n",xstate->id,domain);
	have_id = 1;
    }
    tmp = NULL;

    /* We have to try to find the ID first. */
    if (!have_id) {
	domains = xs_directory(xsh,xth,"/local/domain",&size);
	for (i = 0; i < size; ++i) {
	    /* read in name */
	    snprintf(buf,PATH_MAX * 2,"/local/domain/%s/name",domains[i]);
	    tmp = xs_read(xsh,xth,buf,NULL);

	    if (tmp && strcmp(domain,tmp) == 0) {
		vdebug(9,LOG_T_XV,"dom %s (from %s) matches\n",tmp,domain);
		errno = 0;
		xstate->id = (domid_t)strtol(domains[i],NULL,10);
		if (errno) {
		    verror("matching domain name for %s; but bad domain id %s: %s\n",
			   tmp,domains[i],strerror(errno));
		    goto errout;
		}
		xstate->name = tmp;
		have_id = 1;
		vdebug(4,LOG_T_XV,"dom %d (from %s) matches id\n",
		       xstate->id,domain);
		break;
	    }
	    free(tmp);
        }

	free(domains);
	domains = NULL;

	if (!have_id) {
	    verror("could not find domain id for %s!\n",domain);
	    errno = EINVAL;
	    goto errout;
	}
    }

    /* Once we have an ID, try that to find the name if we need. */
    if (!xstate->name) {
	sprintf(buf,"/local/domain/%d/name",xstate->id);
	xstate->name = xs_read(xsh,xth,buf,NULL);
	if (!xstate->name) 
	    vwarn("could not read name for dom %d; may cause problems!\n",
		  xstate->id);
    }

    /* Now try to find vmpath. */
    sprintf(buf,"/local/domain/%d/vm",xstate->id);
    xstate->vmpath = xs_read(xsh,xth,buf,NULL);
    if (!xstate->vmpath) 
	vwarn("could not read vmpath for dom %d; may cause problems!\n",
	      xstate->id);

    if (xstate->vmpath) {
	sprintf(buf,"%s/image/kernel",xstate->vmpath);
	xstate->kernel_filename = xs_read(xsh,xth,buf,NULL);
	if (!xstate->kernel_filename) 
	    vwarn("could not read kernel for dom %d; may cause problems!\n",
		  xstate->id);
    }

    /* Now load up our xa_instance as much as we can now; we'll try to
       do more when we load the debuginfo file for the kernel. */
    xstate->xa_instance.os_type = XA_OS_LINUX;
    if (xa_init_vm_id_strict_noos(xstate->id,&xstate->xa_instance) == XA_FAILURE) {
	if (xstate->xa_instance.sysmap)
	    free(xstate->xa_instance.sysmap);
        verror("failed to init xa instance for dom %d\n",xstate->id);
        return NULL;
    }

    target->live = 1;
    target->writeable = 1;
    target->mmapable = 0; /* XXX: change this once we get mmap API
			     worked out. */

    if (xstate->kernel_filename) {
	/* First, parse out its version.  We look for the first number
	 * followed by a dot.
	 */
	slen = strlen(xstate->kernel_filename);
	for (i = 0; i < slen; ++i) {
	    if (isdigit(xstate->kernel_filename[i])
		&& (i + 1) < slen
		&& xstate->kernel_filename[i + 1] == '.') {
		xstate->kernel_version = &xstate->kernel_filename[i];
		break;
	    }
	}

	if (!xstate->kernel_version) {
	    verror("could not parse kernel version info for %s!\n",
		   xstate->kernel_filename);
	    goto errout;
	}

	/* Figure out where the real ELF file is. */
	if ((tmp = strstr(xstate->kernel_filename,"vmlinuz"))) {
	    xstate->kernel_elf_filename = malloc(PATH_MAX * 2);
	    snprintf(xstate->kernel_elf_filename,PATH_MAX * 2,
		     "/boot/%s%s","vmlinux-syms",
		     xstate->kernel_filename + (tmp - xstate->kernel_filename) + 7);
	}
    }

    if (!xstate->kernel_elf_filename) {
	verror("could not discover kernel ELF filename from %s; aborting!\n",
	       xstate->kernel_filename);
	goto errout;
    }

    if (xstate->kernel_elf_filename) {
	/* Then grab stuff from the ELF binary itself. */
	if ((fd = open(xstate->kernel_elf_filename,0,O_RDONLY)) < 0) {
	    verror("open %s: %s\n",xstate->kernel_elf_filename,strerror(errno));
	    goto errout;
	}

	elf_version(EV_CURRENT);
	if (!(elf = elf_begin(fd,ELF_C_READ,NULL))) {
	    verror("elf_begin %s: %s\n",xstate->kernel_elf_filename,
		   elf_errmsg(elf_errno()));
	    goto errout;
	}

	/* read the ident stuff to get wordsize and endianness info */
	if (!(eident = elf_getident(elf,NULL))) {
	    verror("elf_getident %s: %s\n",xstate->kernel_elf_filename,
		   elf_errmsg(elf_errno()));
	    goto errout;
	}

	if ((uint8_t)eident[EI_CLASS] == ELFCLASS32) {
	    target->wordsize = 4;
	    vdebug(3,LOG_T_XV,"32-bit %s\n",xstate->kernel_elf_filename);
	}
	else if ((uint8_t)eident[EI_CLASS] == ELFCLASS64) {
	    target->wordsize = 8;
	    vdebug(3,LOG_T_XV,"64-bit %s\n",xstate->kernel_elf_filename);
	}
	else {
	    verror("unknown elf class %d; not 32/64 bit!\n",
		   (uint8_t)eident[EI_CLASS]);
	    goto errout;
	}
	target->ptrsize = target->wordsize;

	if ((uint8_t)eident[EI_DATA] == ELFDATA2LSB) {
	    target->endian = DATA_LITTLE_ENDIAN;
	    vdebug(3,LOG_T_XV,"little endian %s\n",xstate->kernel_elf_filename);
	}
	else if ((uint8_t)eident[EI_DATA] == ELFDATA2MSB) {
	    target->endian = DATA_BIG_ENDIAN;
	    vdebug(3,LOG_T_XV,"big endian %s\n",xstate->kernel_elf_filename);
	}
	else {
	    verror("unknown elf data %d; not big/little endian!\n",
		   (uint8_t)eident[EI_DATA]);
	    goto errout;
	}

	elf_end(elf);
	elf = NULL;
    }
    else {
	vwarn("could not find kernel ELF (vmlinux) file for %s; assuming"
	       " host/target same binary info!\n",xstate->kernel_filename);
#if __WORDSIZE == 64
	target->wordsize = 8;
	target->ptrsize = 8;
#else
	target->wordsize = 4;
	target->ptrsize = 4;
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN
	target->endian = DATA_LITTLE_ENDIAN;
#else
	target->endian = DATA_BIG_ENDIAN;
#endif
    }

    /* Which register is the fbreg is dependent on host cpu type, not
     * target cpu type.
     */
#if __WORDSIZE == 64
    target->fbregno = 6;
    target->spregno = 7;
    target->ipregno = 16;
#else
    target->fbregno = 5;
    target->spregno = 4;
    target->ipregno = 8;
#endif

    target->breakpoint_instrs = malloc(1);
    *(char *)(target->breakpoint_instrs) = 0xcc;
    target->breakpoint_instrs_len = 1;
    target->breakpoint_instr_count = 1;

    target->ret_instrs = malloc(1);
    /* RET */
    *(char *)(target->ret_instrs) = 0xc3;
    target->ret_instrs_len = 1;
    target->ret_instr_count = 1;

    target->full_ret_instrs = malloc(2);
    /* LEAVE */
    *(char *)(target->full_ret_instrs) = 0xc9;
    /* RET */
    *(((char *)(target->full_ret_instrs))+1) = 0xc3;
    target->full_ret_instrs_len = 2;
    target->full_ret_instr_count = 2;

    vdebug(5,LOG_T_XV,"opened dom %d\n",xstate->id);

    return target;

 errout:
    if (elf)
	elf_end(elf);
    if (domains) {
	for (i = 0; i < size; ++i) {
	    free(domains[i]);
	}
	free(domains);
    }
    if (xstate->vmpath)
	free(xstate->vmpath);
    if (xstate->name)
	free(xstate->name);
    if (xsh)
	xs_daemon_close(xsh);
    if (xstate)
	free(xstate);

    return NULL;
}

/**
 ** Utility functions.
 **/

static int xen_vm_load_dominfo(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);

    if (!xstate->dominfo_valid) {
        vdebug(4,LOG_T_XV,
	       "load dominfo; current dominfo is invalid\n");
	if (xc_domain_getinfo(xc_handle,xstate->id,1,
			      &xstate->dominfo) <= 0) {
	    verror("could not get domaininfo for %d\n",xstate->id);
	    errno = EINVAL;
	    return -1;
	}
	xstate->dominfo_valid = 1;
    } else {
        vdebug(4,LOG_T_XV,
	       "did not need to load dominfo; current dominfo is valid\n");
    }

    return 0;
}

static int xen_vm_load_context(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    int rc;

    if (!xstate->context_valid) {
	if (!xstate->dominfo_valid) {
	    rc = xen_vm_load_dominfo(target);
	    if (rc)
		return rc;
	}

	if (xc_vcpu_getcontext(xc_handle,xstate->id,
			       xstate->dominfo.max_vcpu_id,
			       &xstate->context) < 0) {
	    verror("could not get vcpu context for %d\n",xstate->id);
	    errno = EINVAL;
	    return -1;
	}
	xstate->context_valid = 1;

	vdebug(4,LOG_T_XV,
	       "debug registers (vcpu context): 0x%"PRIxADDR",0x%"PRIxADDR
	       ",0x%"PRIxADDR",0x%"PRIxADDR",0,0,0x%"PRIxADDR",0x%"PRIxADDR"\n",
	       xstate->context.debugreg[0],xstate->context.debugreg[1],
	       xstate->context.debugreg[2],xstate->context.debugreg[3],
	       xstate->context.debugreg[6],xstate->context.debugreg[7]);
    }
    else {
	vdebug(4,LOG_T_XV,
	       "did not need to load context; current context is valid\n");
    }

    return 0;
}

/**
 ** Target API implementation.
 **/

static int xen_vm_init(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    vdebug(5,LOG_T_XV,"dom %d\n",xstate->id);

    xstate->context_dirty = 0;
    xstate->context_valid = 0;
    xstate->dominfo_valid = 0;

    return 0;
}

static int xen_vm_attach_internal(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct xen_domctl domctl;

    domctl.cmd = XEN_DOMCTL_setdebugging;
    domctl.domain = xstate->id;
    domctl.u.setdebugging.enable = true;

    vdebug(5,LOG_T_XV,"dom %d\n",xstate->id);

    if (xc_handle == -1) {
	xc_handle = xc_interface_open();
	if (xc_handle < 0) {
	    verror("failed to open xc interface: %s\n",strerror(errno));
	    return -1;
	}

	xce_handle = xc_evtchn_open();
	if (xce_handle < 0) {
	    xc_interface_close(xc_handle);
	    verror("failed to open event channel: %s\n",strerror(errno));
	    return -1;
	}

	dbg_port = xc_evtchn_bind_virq(xce_handle,VIRQ_DEBUGGER);
	/* Try to cast dbg_port to something signed.  Old xc versions
	 * have a bug in that evtchn_port_t is declared as uint32_t, but
	 * the function prototypes that return them can theoretically
	 * return -1.  So, try to test for that...
	 */
	if ((int32_t)dbg_port < 0) {
	    verror("failed to bind debug virq port: %s",strerror(errno));
	    xc_evtchn_close(xce_handle);
	    xc_interface_close(xc_handle);
	}
    }

    if (xc_domctl(xc_handle,&domctl)) {
	verror("could not enable debugging of dom %d!\n",xstate->id);
        return -1;
    }

    /* NOT thread-safe! */
    ++xc_refcnt;

    if (target_pause(target)) {
	verror("could not pause target before attaching; letting user handle!\n");
    }

    /* Null out current state so we reload and see that it's paused! */
    xstate->dominfo_valid = 0;

    target->attached = 1;

    return 0;
}

static int xen_vm_detach(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    struct xen_domctl domctl;

    domctl.cmd = XEN_DOMCTL_setdebugging;
    domctl.domain = xstate->id;
    domctl.u.setdebugging.enable = false;

    vdebug(5,LOG_T_XV,"dom %d\n",xstate->id);

    if (!target->attached)
	return 0;

    if (xen_vm_status(target) == TSTATUS_PAUSED) {
	/* Flush back registers if they're dirty! */
	xen_vm_flush_context(target);
    }

    if (xc_domctl(xc_handle,&domctl)) {
	verror("could not disable debugging of dom %d!\n",xstate->id);
        return -1;
    }

    if (xen_vm_status(target) == TSTATUS_PAUSED) {
	xen_vm_resume(target);
    }

    --xc_refcnt;

    if (!xc_refcnt) {
	/* Close all the xc stuff; we're the last one. */
	if (xc_evtchn_unbind(xce_handle,(evtchn_port_t)dbg_port)) {
	    verror("failed to unbind debug virq port\n");
	}
	dbg_port = -1;

	if (xc_evtchn_close(xce_handle)) {
	    verror("failed to close event channel\n");
	}
	xce_handle = -1;
    
	if (xc_interface_close(xc_handle)) {
	    verror("failed to close xc interface\n");
	}
	xc_handle = -1;

	vdebug(4,LOG_T_XV,"xc detach dom %d succeeded.\n",xstate->id);
	target->attached = 0;
    }

    vdebug(3,LOG_T_XV,"detach dom %d succeeded.\n",xstate->id);
    target->attached = 0;

    return 0;
}

static int xen_vm_fini(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);

    vdebug(5,LOG_T_XV,"dom %d\n",xstate->id);

    if (target->attached) 
	xen_vm_detach(target);

    if (xstate->vmpath)
	free(xstate->vmpath);
    if (xstate->name)
	free(xstate->name);
    if (xstate)
	free(xstate);

    return 0;
}

/*
 * For now, just one big address space.
 */
static int xen_vm_loadspaces(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    struct addrspace *space = addrspace_create(target,"NULL",0,xstate->id);

    RHOLD(space);

    space->target = target;

    list_add_tail(&space->space,&target->spaces);

    return 0;
}

/*
 * For now, just find our kernel binary path from xen store, as well as
 * the max amount of mem, and create a single region (with a single
 * range that is R/W/X) covering either all 32 or 64 bits.
 *
 * The immediate reason to do this is that figuring out which memory is
 * currently mapped to kernel or user address space is going to be slow
 * because it involves lots of list traverses.  Plus, even if we had an
 * efficient data structure for searching address ranges, we would have
 * to reload the ranges/regions *every* time the domain runs.  We do not
 * want to do this!
 *
 * So, XXX: come back to it later.
 */
static int xen_vm_loadregions(struct target *target,struct addrspace *space) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    struct memregion *region;
    struct memrange *range;

    region = memregion_create(space,REGION_TYPE_MAIN,
			      xstate->kernel_elf_filename);
    range = memrange_create(region,0,ADDRMAX,0,
			    PROT_READ | PROT_WRITE | PROT_EXEC);

    return 0;
}

static int DEBUGPATHLEN = 2;
static char *DEBUGPATH[] = { 
    "/usr/lib/debug",
    "/usr/local/lib/debug"
};

/*
 * For now, just try to find the debuginfo for our kernel, unless the
 * user told us about it in xstate.
 *
 * We need to look for gnu_debuglink first, and then look in
 * /usr*lib/debug for a match.  Actually, we prefer the buildid because
 * for fedora kernel modules, we don't necessarily know the path to the
 * module in /lib/modules/VERSION/.../module.ko in the fs, so we can't
 * duplicate ... in the /usr/lib/debug search... so build id is the way
 * to go.
 *
 * But for just the kernel itself, this is easier.  If we have buildid
 * or debuglink, we use /usr*lib/debug.  Else, we look in /boot for a
 * file that replaces the vmlinuz part with vmlinux.
 */
static int xen_vm_loaddebugfiles(struct target *target,
				 struct addrspace *space,
				 struct memregion *region) {
    Elf *elf = NULL;
    Elf_Scn *scn;
    GElf_Shdr shdr_mem;
    GElf_Shdr *shdr;
    char *name;
    size_t shstrndx;
    int has_debuginfo = 0;
    char *buildid = NULL;
    char *debuglinkfile = NULL;
    uint32_t debuglinkfilecrc = 0;
    Elf_Data *edata;
    char *eident = NULL;
    int is64 = 0;
    Elf32_Nhdr *nthdr32;
    Elf64_Nhdr *nthdr64;
    char *ndata,*nend;
    int fd = -1;;
    int i;
    int len;
    int retval = 0;
    char pbuf[PATH_MAX];
    char *finalfile = NULL;
    char *regionfiledir = NULL;
    char *tmp;
    struct stat stbuf;
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    vdebug(5,LOG_T_XV,"dom %d\n",xstate->id);

    /*
     * Open up the actual ELF binary and look for three sections to inform
     * our search.  First, if there is a nonzero .debug_info section,
     * load that.  Second, if there is a .note.gnu.build-id section,
     * read the build id and decompose it into a two-byte dir/file.debug
     * string that we look for in our search path (i.e., we look for
     * $PATH/.build-id/b1/b2..bX.debug).  Otherwise, if there is a
     * .gnu_debuglink section, we read that section and try to find a
     * matching debug file. 
     */
    if (!region->name || strlen(region->name) == 0)
	return -1;

    if ((fd = open(region->name,0,O_RDONLY)) < 0) {
	verror("open %s: %s\n",region->name,strerror(errno));
	return -1;
    }

    elf_version(EV_CURRENT);
    if (!(elf = elf_begin(fd,ELF_C_READ,NULL))) {
	verror("elf_begin %s: %s\n",region->name,elf_errmsg(elf_errno()));
	goto errout;
    }

    /* read the ident stuff to get ELF byte size */
    if (!(eident = elf_getident(elf,NULL))) {
	verror("elf_getident %s: %s\n",region->name,elf_errmsg(elf_errno()));
	goto errout;
    }

    if ((uint8_t)eident[EI_CLASS] == ELFCLASS32) {
	is64 = 0;
	vdebug(3,LOG_T_XV,"32-bit %s\n",region->name);
    }
    else if ((uint8_t)eident[EI_CLASS] == ELFCLASS64) {
	is64 = 1;
    }
    else {
	verror("unknown elf class %d; not 32/64 bit!\n",
	       (uint8_t)eident[EI_CLASS]);
	goto errout;
    }

#if _INT_ELFUTILS_VERSION >= 152
    if (elf_getshdrstrndx(elf,&shstrndx) < 0) {
#else 
    if (elf_getshstrndx(elf,&shstrndx) < 0) {
#endif
	verror("cannot get section header string table index\n");
	goto errout;
    }

    scn = NULL;
    while ((scn = elf_nextscn(elf,scn)) != NULL) {
	shdr = gelf_getshdr(scn,&shdr_mem);

	if (shdr && shdr->sh_size > 0) {
	    name = elf_strptr(elf,shstrndx,shdr->sh_name);

	    if (strcmp(name,".debug_info") == 0) {
		vdebug(2,LOG_T_XV,
		       "found %s section (%d) in region filename %s\n",
		       name,shdr->sh_size,region->name);
		has_debuginfo = 1;
		continue;
	    }
	    else if (!buildid && shdr->sh_type == SHT_NOTE) {
		vdebug(2,LOG_T_XV,
		       "found %s note section (%d) in region filename %s\n",
		       name,shdr->sh_size,region->name);
		edata = elf_rawdata(scn,NULL);
		if (!edata) {
		    vwarn("cannot get data for valid section '%s': %s",
			  name,elf_errmsg(-1));
		    continue;
		}

		ndata = edata->d_buf;
		nend = ndata + edata->d_size;
		while (ndata < nend) {
		    if (is64) {
			nthdr64 = (Elf64_Nhdr *)ndata;
			/* skip past the header and the name string and its
			 * padding */
			ndata += sizeof(Elf64_Nhdr);
			vdebug(5,LOG_T_XV,"found note name '%s'\n",ndata);
			ndata += nthdr64->n_namesz;
			if (nthdr64->n_namesz % 4)
			    ndata += (4 - nthdr64->n_namesz % 4);
			vdebug(5,LOG_T_XV,"found note desc '%s'\n",ndata);
			/* dig out the build ID */
			if (nthdr64->n_type == NT_GNU_BUILD_ID) {
			    buildid = strdup(ndata);
			    break;
			}
			/* skip past the descriptor and padding */
			ndata += nthdr64->n_descsz;
			if (nthdr64->n_namesz % 4)
			    ndata += (4 - nthdr64->n_namesz % 4);
		    }
		    else {
			nthdr32 = (Elf32_Nhdr *)ndata;
			/* skip past the header and the name string and its
			 * padding */
			ndata += sizeof(Elf32_Nhdr);
			ndata += nthdr32->n_namesz;
			if (nthdr32->n_namesz % 4)
			    ndata += (4 - nthdr32->n_namesz % 4);
			/* dig out the build ID */
			if (nthdr32->n_type == NT_GNU_BUILD_ID) {
			    buildid = strdup(ndata);
			    break;
			}
			/* skip past the descriptor and padding */
			ndata += nthdr32->n_descsz;
			if (nthdr32->n_namesz % 4)
			    ndata += (4 - nthdr32->n_namesz % 4);
		    }
		}
	    }
	    else if (strcmp(name,".gnu_debuglink") == 0) {
		edata = elf_rawdata(scn,NULL);
		if (!edata) {
		    vwarn("cannot get data for valid section '%s': %s",
			  name,elf_errmsg(-1));
		    continue;
		}
		debuglinkfile = strdup(edata->d_buf);
		debuglinkfilecrc = *(uint32_t *)(edata->d_buf + edata->d_size - 4);
	    }
	}
    }

    elf_end(elf);
    elf = NULL;
    close(fd);
    fd = -1;

    vdebug(5,LOG_T_XV,"ELF info for region file %s:\n",region->name);
    vdebug(5,LOG_T_XV,"    has_debuginfo=%d,buildid='",has_debuginfo);
    if (buildid) {
	len = (int)strlen(buildid);
	for (i = 0; i < len; ++i)
	    vdebugc(5,LOG_T_XV,"%hhx",buildid[i]);
    }
    vdebugc(5,LOG_T_XV,"'\n");
    vdebug(5,LOG_T_XV,"    debuglinkfile=%s,debuglinkfilecrc=0x%x\n",
	   debuglinkfile,debuglinkfilecrc);

    if (has_debuginfo) {
	finalfile = region->name;
    }
    else if (buildid) {
	for (i = 0; i < DEBUGPATHLEN; ++i) {
	    snprintf(pbuf,PATH_MAX,"%s/.build-id/%02hhx/%s.debug",
		     DEBUGPATH[i],*buildid,(char *)(buildid+1));
	    if (stat(pbuf,&stbuf) == 0) {
		finalfile = pbuf;
		break;
	    }
	}
    }
    else if (debuglinkfile) {
	/* Find the containing dir path so we can use it in our search
	 * of the standard debug file dir infrastructure.
	 */
	regionfiledir = strdup(region->name);
	tmp = rindex(regionfiledir,'/');
	if (tmp)
	    *tmp = '\0';
	for (i = 0; i < DEBUGPATHLEN; ++i) {
	    snprintf(pbuf,PATH_MAX,"%s/%s/%s",
		     DEBUGPATH[i],regionfiledir,debuglinkfile);
	    if (stat(pbuf,&stbuf) == 0) {
		finalfile = pbuf;
		break;
	    }
	}
    }
    else {
	verror("could not find any debuginfo sources from ELF file %s!\n",
	       region->name);
	goto errout;
    }

    if (finalfile) {
	if (region->type == REGION_TYPE_MAIN 
	    || region->type == REGION_TYPE_LIB) {
	    if (!target_associate_debugfile(target,region,finalfile,
					    region->type == REGION_TYPE_MAIN ? \
					    DEBUGFILE_TYPE_MAIN : \
					    DEBUGFILE_TYPE_SHAREDLIB)
		&& errno != 0)
		goto errout;
	}
    }

    /* Success!  Skip past errout. */
    retval = 0;
    goto out;

 errout:
    retval = -1;

 out:
    if (elf)
	elf_end(elf);
    if (fd > -1)
	close(fd);
    if (regionfiledir) 
	free(regionfiledir);
    if (buildid)
	free(buildid);
    if (debuglinkfile)
	free(debuglinkfile);

    return retval;
}

static target_status_t xen_vm_status(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    target_status_t retval = TSTATUS_UNKNOWN;

    vdebug(5,LOG_T_XV,"dom %d\n",xstate->id);

    if (!xstate->dominfo_valid) {
	if (xen_vm_load_dominfo(target)) {
	    verror("could not load dominfo for dom %d\n",xstate->id);
	    return retval;
	}
    }

    if (xstate->dominfo.paused)
	retval = TSTATUS_PAUSED;
    else if (xstate->dominfo.running || xstate->dominfo.blocked) 
	/* XXX: is this right?  i.e., is "blocked" from the hypervisor
	   perspective? */
	retval = TSTATUS_RUNNING;
    else if (xstate->dominfo.dying || xstate->dominfo.crashed)
	retval = TSTATUS_DEAD;
    else if (xstate->dominfo.shutdown)
	retval = TSTATUS_STOPPED;
    else
	retval = TSTATUS_ERROR;

    vdebug(3,LOG_T_XV,"dom %d status %d\n",xstate->id,retval);

    return retval;
}

static int xen_vm_pause(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    vdebug(5,LOG_T_XV,"dom %d\n",xstate->id);

    if (!xstate->dominfo_valid) {
	if (xen_vm_load_dominfo(target)) 
	    vwarn("could not load dominfo for dom %d, trying to pause anyway!\n",xstate->id);
    }

    if (xstate->dominfo.paused)
	return 0;

    if (xc_domain_pause(xc_handle,xstate->id)) {
	verror("could not pause dom %d!\n",xstate->id);
	return -1;
    }

    xstate->dominfo_valid = 0;
    if (xen_vm_load_dominfo(target)) 
	vwarn("could not reload dominfo for dom %d after pause!\n",xstate->id);

    return 0;
}

static int xen_vm_resume(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    vdebug(5,LOG_T_XV,"dom %d\n",xstate->id);

    if (!xstate->dominfo_valid) {
	if (xen_vm_load_dominfo(target)) 
	    vwarn("could not load dominfo for dom %d, trying to pause anyway!\n",xstate->id);
    }

    if (!xstate->dominfo.paused)
	return -1;

    /* Flush back registers if they're dirty! */
    xen_vm_flush_context(target);

    /* flush_context will not have done this necessarily! */
    xstate->context_valid = 0;

    return xc_domain_unpause(xc_handle,xstate->id);
}


static target_status_t xen_vm_monitor(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    int ret, fd;
    XC_EVTCHN_PORT_T port = -1;
    struct timeval tv;
    fd_set inset;
    REGVAL ipval;
    int dreg = -1;
    struct probepoint *dpp;

    /* get a select()able file descriptor of the event channel */
    fd = xc_evtchn_fd(xce_handle);
    if (fd == -1) {
        verror("event channel not initialized\n");
        return TSTATUS_ERROR;
    }

    while (1) {
        tv.tv_sec = 0;
        tv.tv_usec = 50;
        FD_ZERO(&inset);
        FD_SET(fd,&inset);

        /* wait for a domain to trigger the VIRQ */
        ret = select(fd+1,&inset,NULL,NULL,&tv);
        if (ret == -1) // timeout
            continue;

        if (!FD_ISSET(fd, &inset)) 
            goto again; // nothing in eventchn
	else {
	    /* From previous */
	    xa_destroy_cache(&xstate->xa_instance);
	    xa_destroy_pid_cache(&xstate->xa_instance);
	}

        /* we've got something from eventchn. let's see what it is! */
        port = xc_evtchn_pending(xce_handle);

	/* unmask the event channel BEFORE doing anything else,
	 * like unpausing the target!
	 */
	ret = xc_evtchn_unmask(xce_handle, port);
	if (ret == -1) {
	    verror("failed to unmask event channel\n");
	    break;
	}

        if (port != dbg_port)
            continue; // not the event that we are looking for

	xstate->context_valid = 0;
	xen_vm_load_context(target);

	if (target_status(target) == TSTATUS_PAUSED) {
	    errno = 0;
	    ipval = xen_vm_read_reg(target,target->ipregno);
	    if (errno) {
		verror("could not read EIP while finding probepoint: %s\n",
		       strerror(errno));
		return TSTATUS_ERROR;
	    }

	    /* handle the triggered probe based on its event type */
	    if (target->sstep_probepoint) {
		if (xstate->context.user_regs.eflags & 0x00000100) {
		    target->ss_handler(target,target->sstep_probepoint);
		    goto again;
		}
		else {
		    vwarn("expected single step to happen, but the flag"
			  " is clear; EIP is 0x%"PRIxADDR"; EFLAGS is 0x%"PRIx32"\n",
			  ipval,xstate->context.user_regs.eflags);
		    goto bpcheck;
		}
	    }
	    else {
	    bpcheck:
		dreg = -1;

		/* Check the hw debug status reg first */

		/* Only check the 4 low-order bits */
		if (xstate->context.debugreg[6] & 15) {
		    if (xstate->context.debugreg[6] & 0x1)
			dreg = 0;
		    else if (xstate->context.debugreg[6] & 0x2)
			dreg = 1;
		    else if (xstate->context.debugreg[6] & 0x4)
			dreg = 2;
		    else if (xstate->context.debugreg[6] & 0x8)
			dreg = 3;
		}

		if (dreg > -1) {
		    /* If we are relying on the status reg to tell us,
		     * then also read the actual hw debug reg to get the
		     * address we broke on.
		     */
		    errno = 0;
		    ipval = xstate->context.debugreg[dreg];

		    vdebug(4,LOG_T_XV,
			   "found hw break (status) in dreg %d on 0x%"PRIxADDR"\n",
			   dreg,ipval);
		}
		else {
		    vdebug(4,LOG_T_XV,
			   "dreg status was 0x%"PRIxREGVAL"; trying eip method\n",
			   (ADDR)xstate->context.debugreg[6]);

		    if (xstate->dr[0] == ipval)
			dreg = 0;
		    else if (xstate->dr[1] == ipval)
			dreg = 1;
		    else if (xstate->dr[2] == ipval)
			dreg = 2;
		    else if (xstate->dr[3] == ipval)
			dreg = 3;

		    if (dreg > -1) 
			vdebug(4,LOG_T_XV,
			       "found hw break (eip) in dreg %d on 0x%"PRIxADDR"\n",
			       dreg,ipval);
		    else
			vdebug(6,LOG_T_XV,
			       "did NOT find hw break (eip) on 0x%"PRIxADDR"\n",
			       ipval);
		}

		if (dreg > -1) {
		    /* Found HW breakpoint! */
		    /* Clear the status bits right now. */
		    xstate->context.debugreg[6] = 0;
		    xstate->context_dirty = 1;
		    vdebug(5,LOG_T_XV,"cleared status debug reg 6\n");

		    dpp = (struct probepoint *)g_hash_table_lookup(target->probepoints,
								   (gpointer)ipval);

		    if (dreg > -1 && !dpp) {
			verror("could not find probepoint for hw dbg reg %d!\n",
			       dreg);
			return TSTATUS_ERROR;
		    }

		    /* BEFORE we run the bp handler: 
		     *
		     * If the domain happens to be in singlestep mode, and
		     * we are hitting a breakpoint anyway... we have to
		     * handle the breakpoint, singlestep ourselves, AND
		     * THEN leave the processor in single step mode.
		     */
		    if (0 && xstate->context.user_regs.eflags & 0x00000100)
			target->sstep_leave_enabled = 1;

		    /* Run the breakpoint handler. */
		    target->bp_handler(target,dpp);
		    goto again;
		}
		else if ((dpp = (struct probepoint *) \
			  g_hash_table_lookup(target->probepoints,
					      (gpointer)(ipval - target->breakpoint_instrs_len)))) {
		    /* BEFORE we run the bp handler: 
		     *
		     * If the domain happens to be in singlestep mode, and
		     * we are hitting a breakpoint anyway... we have to
		     * handle the breakpoint, singlestep ourselves, AND
		     * THEN leave the processor in single step mode.
		     */
		    if (0 && xstate->context.user_regs.eflags & 0x00000100)
			target->sstep_leave_enabled = 1;

		    /* Run the breakpoint handler. */
		    target->bp_handler(target,dpp);
		    goto again;
		}
		else if (xstate->context.user_regs.eflags & 0x00000100) {
		    vwarn("phantom single step for dom %d (no breakpoint"
			  " set either!); letting user handle fault at"
			  " 0x%"PRIxADDR"!\n",xstate->id,ipval);
		    return TSTATUS_PAUSED;
		}
		else {
		    vwarn("could not find hardware bp and not sstep'ing;"
			  " letting user handle fault at 0x%"PRIxADDR"!\n",
			  ipval);
		    return TSTATUS_PAUSED;
		}
	    }
	}

    again:
	continue;
    }

    return TSTATUS_ERROR;
}

static target_status_t xen_vm_poll(struct target *target,
				   target_poll_outcome_t *outcome,int *pstatus) {
    return TSTATUS_ERROR;
}

static unsigned char *mmap_pages(xa_instance_t *xa_instance,ADDR addr, 
				 unsigned long size,uint32_t *offset,
				 int *npages,int prot,int pid) {
    unsigned char *pages;
    unsigned long page_size, page_offset;
    char *dstr = "small";

    page_size = xa_instance->page_size;
    page_offset = addr & (page_size - 1);

    if (size > 0 && size <= (page_size - page_offset)) {
        /* let xenaccess use its memory cache for small size */
        pages = xa_access_user_va(xa_instance,addr,offset,pid,prot);
	if (!pages) {
	    if (!pid)
		return NULL;

	    pages = xa_access_user_va(xa_instance,addr,offset,0,prot);
	    if (!pages)
		return NULL;
	}
	*npages = 1;
    }
    else {
	dstr = "large";
        /* xenaccess can't map multiple pages properly, use our own function */
        pages = xa_access_user_va_range(xa_instance,addr,size,offset,pid,prot);

	if (!pages) { // && pid) {
	    //return NULL;
	    if (!pid)
		return NULL;

	    /* try kernel */
	    pages = xa_access_user_va_range(xa_instance,addr,size,offset,0,prot);
	    if (!pages) 
		return NULL;
	}

	/*
	 * Compute how many pages were mapped.
	 * *offset is the offset within the initial page mapped.
	 * Number of pages is thus:
	 *   round((*offset+size), page_size)
	 */
	*npages = (*offset + size) / page_size;
	if ((*offset + size) % page_size)
	    (*npages)++;
    }

    vdebug(4,LOG_T_XV,"%ld bytes at %lx mapped (%s)\n",size,addr,dstr);

    return pages; /* munmap it later */
}

static unsigned char *xen_vm_read(struct target *target,
					  ADDR addr,
					  unsigned long target_length,
					  unsigned char *buf,
					  void *targetspecdata) {
    unsigned char *pages;
    unsigned int offset = 0;
    unsigned long length = target_length, size = 0;
    unsigned long page_size;
    unsigned char *retval = NULL;
    unsigned int page_offset;
    int no_pages;
    struct xen_vm_state *xstate;
    int pid = 0;

    xstate = (struct xen_vm_state *)(target->state);

    if (targetspecdata)
	pid = *(int *)targetspecdata;

    // XXX: need to check, if pid > 0, if we can actually read it --
    // i.e., do we have the necessary task_struct offsets for xenaccess,
    // and is it in mem...

    page_size = xstate->xa_instance.page_size;
    page_offset = addr & (page_size - 1);

    vdebug(5,LOG_T_XV,
	   "read dom %d: addr=0x%"PRIxADDR" offset=%d len=%d pid=%d\n",
	   xstate->id,addr,page_offset,target_length,pid);

    /* if we know what length we need, just grab it */
    if (length > 0) {
	pages = (unsigned char *)mmap_pages(&xstate->xa_instance,addr,
					    length,&offset,&no_pages,
					    PROT_READ,pid);
	if (!pages)
	    return NULL;

	assert(offset == page_offset);
	vdebug(3,LOG_T_XV,
	       "read dom %d: addr=0x%"PRIxADDR" offset=%d pid=%d len=%d mapped pages=%d\n",
	       xstate->id,addr,page_offset,pid,length,no_pages);
    }
    else {
	/* increase the mapping size by this much if the string is longer 
	   than we expect at first attempt. */
	size = (page_size - page_offset);

	while (1) {
	    if (1 || size > page_size) 
		vdebug(6,LOG_T_XV,
		       "increasing size to %d (dom=%d,addr=%"PRIxADDR",pid=%d)\n",
		       size,xstate->id,addr,pid);
	    pages = (unsigned char *)mmap_pages(&xstate->xa_instance,addr,size,
						&offset,&no_pages,
						PROT_READ,pid);
	    if (!pages)
		return NULL;

	    length = strnlen((const char *)(pages + offset), size);
	    if (length < size) {
		vdebug(3,LOG_T_XV,"got string of length %d, mapped %d pages\n",
		       length,no_pages);
		break;
	    }
	    if (munmap(pages,no_pages * page_size))
		vwarn("munmap of %p failed\n",pages);
	    size += page_size;
	}
    }

    if (!buf)
	retval = (unsigned char *)malloc(length+1);
    else 
	retval = buf;
    if (retval) {
	memcpy(retval,pages + offset,length);
	if (target_length == 0) {
	    retval[length] = '\0';
	}
    }

    if (munmap(pages,no_pages * page_size))
	vwarn("munmap of %p failed\n",pages);
    
    return retval;
}

unsigned long xen_vm_write(struct target *target,ADDR addr,unsigned long length,
			   unsigned char *buf,void *targetspecdata) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);
    struct memrange *range = NULL;
    unsigned char *pages;
    unsigned int offset = 0;
    unsigned long page_size;
    unsigned int page_offset;
    int no_pages;
    int pid = 0;

    xstate = (struct xen_vm_state *)(target->state);

    if (targetspecdata)
	pid = *(int *)targetspecdata;

    page_size = xstate->xa_instance.page_size;
    page_offset = addr & (page_size - 1);

    vdebug(5,LOG_T_XV,
	   "write dom %d: addr=0x%"PRIxADDR" offset=%d len=%d pid=%d\n",
	   xstate->id,addr,page_offset,length,pid);

    target_find_memory_real(target,addr,NULL,NULL,&range);

    /*
     * This is mostly a stub for later, when we might actually check
     * bounds of writes.
     */
    if (!range || !(range->prot_flags & PROT_WRITE)) {
	errno = EFAULT;
	return 0;
    }

    /* Map the pages we have to write to. */
    pages = (unsigned char *)mmap_pages(&xstate->xa_instance,addr,
					length,&offset,&no_pages,
					PROT_WRITE,pid);
    if (!pages) {
	errno = EFAULT;
	return 0;
    }

    assert(offset == page_offset);
    vdebug(3,LOG_T_XV,
	   "write dom %d: addr=0x%"PRIxADDR" offset=%d pid=%d len=%d mapped pages=%d\n",
	   xstate->id,addr,page_offset,pid,length,no_pages);

    memcpy(pages + offset,buf,length);

    if (munmap(pages,no_pages * page_size))
	vwarn("munmap of %p failed\n",pages);

    return length;
}

/*
 * The register mapping between x86_64 registers is defined by AMD in
 * http://www.x86-64.org/documentation/abi-0.99.pdf :
 */

/* Register mapping.
 *
 * First, be aware that our host bit size (64/32) *does* influence which
 * registers we can access -- i.e., 64-bit host tracing a
 * 32-bit process still gets the 64-bit registers -- but even then, we
 * want the 32-bit mapping for DWARF reg num to i386 reg.
 *
 * XXX XXX XXX
 * If structs in xen/xen.h (and arch-specific includes containing
 * cpu_user_regs) change, ever, these mappings will be wrong.
 */
#if __WORDSIZE == 64
#define X86_64_DWREG_COUNT 67
static int dreg_to_offset[X86_64_DWREG_COUNT] = { 
    offsetof(struct vcpu_guest_context,user_regs.rax),
    offsetof(struct vcpu_guest_context,user_regs.rdx),
    offsetof(struct vcpu_guest_context,user_regs.rcx),
    offsetof(struct vcpu_guest_context,user_regs.rbx),
    offsetof(struct vcpu_guest_context,user_regs.rsi),
    offsetof(struct vcpu_guest_context,user_regs.rdi),
    offsetof(struct vcpu_guest_context,user_regs.rbp),
    offsetof(struct vcpu_guest_context,user_regs.rsp),
    offsetof(struct vcpu_guest_context,user_regs.r8),
    offsetof(struct vcpu_guest_context,user_regs.r9),
    offsetof(struct vcpu_guest_context,user_regs.r10),
    offsetof(struct vcpu_guest_context,user_regs.r11),
    offsetof(struct vcpu_guest_context,user_regs.r12),
    offsetof(struct vcpu_guest_context,user_regs.r13),
    offsetof(struct vcpu_guest_context,user_regs.r14),
    offsetof(struct vcpu_guest_context,user_regs.r15),
    offsetof(struct vcpu_guest_context,user_regs.rip),
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    -1, -1, -1, -1, -1, -1, -1, -1, 
    offsetof(struct vcpu_guest_context,user_regs.rflags),
    offsetof(struct vcpu_guest_context,user_regs.es),
    offsetof(struct vcpu_guest_context,user_regs.cs),
    offsetof(struct vcpu_guest_context,user_regs.ss),
    offsetof(struct vcpu_guest_context,user_regs.ds),
    offsetof(struct vcpu_guest_context,user_regs.fs),
    offsetof(struct vcpu_guest_context,user_regs.gs),
    -1, -1, 
    -1, -1, /* XXX: what about fs_base, gs_base; that's what these are. */
    -1, -1, 
    -1, -1, -1, -1, -1,
};
static char *dreg_to_name[X86_64_DWREG_COUNT] = { 
    "rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip",
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    "rflags", "es", "cs", "ss", "ds", "fs", "gs",
    NULL, NULL,
    NULL, NULL, /* "fs_base", "gs_base", */
    NULL, NULL,
    NULL, NULL, NULL, NULL, NULL,
};
#endif

#define X86_32_DWREG_COUNT 10
static int dreg_to_offset32[X86_32_DWREG_COUNT] = { 
    offsetof(struct vcpu_guest_context,user_regs.eax),
    offsetof(struct vcpu_guest_context,user_regs.ecx),
    offsetof(struct vcpu_guest_context,user_regs.edx),
    offsetof(struct vcpu_guest_context,user_regs.ebx),
    offsetof(struct vcpu_guest_context,user_regs.esp),
    offsetof(struct vcpu_guest_context,user_regs.ebp),
    offsetof(struct vcpu_guest_context,user_regs.esi),
    offsetof(struct vcpu_guest_context,user_regs.edi),
    offsetof(struct vcpu_guest_context,user_regs.eip),
    offsetof(struct vcpu_guest_context,user_regs.eflags),
};
static char *dreg_to_name32[X86_32_DWREG_COUNT] = { 
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "eip", "eflags",
};

/*
 * Register functions.
 */
char *xen_vm_reg_name(struct target *target,REG reg) {
#if __WORDSIZE == 64
    if (reg >= X86_64_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 64-bit target mapping!\n",reg);
	return NULL;
    }
    return dreg_to_name64[reg];
#else
    if (reg >= X86_32_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 32-bit target mapping!\n",reg);
	return NULL;
    }
    return dreg_to_name32[reg];
#endif
}

REGVAL xen_vm_read_reg(struct target *target,REG reg) {
    int offset;
    struct xen_vm_state *xstate;
    REGVAL retval;

    xstate = (struct xen_vm_state *)(target->state);

    /* vdebug(5,LOG_T_XV,"reading reg %s\n",xen_vm_reg_name(target,reg)); */

#if __WORDSIZE == 64
    if (reg >= X86_64_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 64-bit target mapping!\n",reg);
	errno = EINVAL;
	return 0;
    }
    offset = dreg_to_offset64[reg];
#else
    if (reg >= X86_32_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 32-bit target mapping!\n",reg);
	errno = EINVAL;
	return 0;
    }
    offset = dreg_to_offset32[reg];
#endif

    /* Don't bother checking if process is stopped! */
    if (!xstate->context_valid) {
	if (xen_vm_load_context(target)) 
	    return 0;
    }

#if __WORDSIZE == 64
    if (likely(reg < 50))
	retval = (REGVAL)*(uint64_t *)(((char *)&(xstate->context)) + offset);
    else
	retval = (REGVAL)*(uint16_t *)(((char *)&(xstate->context)) + offset);
#else 
    retval = (REGVAL)*(uint32_t *)(((char *)&(xstate->context)) + offset);
#endif
    vdebug(5,LOG_T_XV,"read reg %s 0x%"PRIxREGVAL"\n",
	   xen_vm_reg_name(target,reg),retval);

    return retval;
}

int xen_vm_write_reg(struct target *target,REG reg,REGVAL value) {
    int offset;
    struct xen_vm_state *xstate;

    xstate = (struct xen_vm_state *)(target->state);

    vdebug(5,LOG_T_XV,"writing reg %s 0x%"PRIxREGVAL"\n",
	   xen_vm_reg_name(target,reg),value);

#if __WORDSIZE == 64
    if (reg >= X86_64_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 64-bit target mapping!\n",reg);
	errno = EINVAL;
	return -1;
    }
    offset = dreg_to_offset64[reg];
#else
    if (reg >= X86_32_DWREG_COUNT) {
	verror("DWARF regnum %d does not have a 32-bit target mapping!\n",reg);
	errno = EINVAL;
	return -1;
    }
    offset = dreg_to_offset32[reg];
#endif

    /* Don't bother checking if process is stopped! */
    if (!xstate->context_valid) {
	if (xen_vm_load_context(target)) 
	    return 0;
    }

#if __WORDSIZE == 64
    if (likely(reg < 50))
	*(uint64_t *)(((char *)&(xstate->context)) + offset) = (uint64_t)value;
    else
	*(uint16_t *)(((char *)&(xstate->context)) + offset) = (uint16_t)value;
#else 
    *(uint32_t *)(((char *)&(xstate->context)) + offset) = (uint32_t)value;
#endif

    /* Flush the context in target_resume! */
    xstate->context_dirty = 1;

    return 0;
}

static int xen_vm_flush_context(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);

    if (xstate->context_valid && xstate->context_dirty) {
	vdebug(9,LOG_T_XV,"dom %d\n",xstate->id);

	vdebug(4,LOG_T_XV,"EIP is 0x%"PRIxREGVAL" before context flush\n",
	       xen_vm_read_reg(target,target->ipregno));

	if (xc_vcpu_setcontext(xc_handle,xstate->id,
			       xstate->dominfo.max_vcpu_id,
			       &xstate->context) < 0) {
	    verror("could not set vcpu context for dom %d\n",xstate->id);
	    errno = EINVAL;
	    return -1;
	}
	/* Invalidate our cache. */
	xstate->context_dirty = 0;
	xstate->context_valid = 0;

	vdebug(4,LOG_T_XV,
	       "debug registers (vcpu context): 0x%"PRIxADDR",0x%"PRIxADDR
	       ",0x%"PRIxADDR",0x%"PRIxADDR",0,0,0x%"PRIxADDR",0x%"PRIxADDR"\n",
	       xstate->context.debugreg[0],xstate->context.debugreg[1],
	       xstate->context.debugreg[2],xstate->context.debugreg[3],
	       xstate->context.debugreg[6],xstate->context.debugreg[7]);

	vdebug(4,LOG_T_XV,
	       "debug registers (our copy): 0x%"PRIxADDR",0x%"PRIxADDR
	       ",0x%"PRIxADDR",0x%"PRIxADDR",0,0,0x%"PRIxADDR",0x%"PRIxADDR"\n",
	       xstate->dr[0],xstate->dr[1],xstate->dr[2],xstate->dr[3],
	       xstate->dr[6],xstate->dr[7]);
    }

    /* Invalidate dominfo here too so we reload it. */
    xstate->dominfo_valid = 0;

    return 0;
}

/*
 * Hardware breakpoint support.
 */
static REG xen_vm_get_unused_debug_reg(struct target *target) {
    struct xen_vm_state *xstate;
    REG retval = -1;

    xstate = (struct xen_vm_state *)(target->state);

    if (!xstate->dr[0]) { retval = 0; }
    else if (!xstate->dr[1]) { retval = 1; }
    else if (!xstate->dr[2]) { retval = 2; }
    else if (!xstate->dr[3]) { retval = 3; }

    vdebug(5,LOG_T_XV,"returning unused debug reg %d\n",retval);

    return retval;
}

struct x86_dr_format {
    int dr0_l:1;
    int dr0_g:1;
    int dr1_l:1;
    int dr1_g:1;
    int dr2_l:1;
    int dr2_g:1;
    int dr3_l:1;
    int dr3_g:1;
    int exact_l:1;
    int exact_g:1;
    int reserved:6;
    probepoint_whence_t dr0_break:2;
    probepoint_watchsize_t dr0_len:2;
    probepoint_whence_t dr1_break:2;
    probepoint_watchsize_t dr1_len:2;
    probepoint_whence_t dr2_break:2;
    probepoint_watchsize_t dr2_len:2;
    probepoint_whence_t dr3_break:2;
    probepoint_watchsize_t dr3_len:2;
};

static int xen_vm_set_hw_breakpoint(struct target *target,
					    REG reg,ADDR addr) {
    struct xen_vm_state *xstate;
#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    int ret;
#endif

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    xstate = (struct xen_vm_state *)(target->state);

    if (!xstate->context_valid) {
	if (xen_vm_load_context(target)) 
	    return -1;
    }

    if (xstate->context.debugreg[reg] != 0) {
	vwarn("debug reg %"PRIiREG" already has an address, overwriting (0x%lx)!\n",
	      reg,xstate->context.debugreg[reg]);
	//errno = EBUSY;
	//return -1;
    }

    /* Set the address, then the control bits. */
    xstate->dr[reg] = (unsigned long)addr;

    /* Clear the status bits */
    xstate->dr[6] = 0; //&= ~(1 << reg);

    /* Set the local control bit, and unset the global bit. */
    xstate->dr[7] |= (1 << (reg * 2));
    xstate->dr[7] &= ~(1 << (reg * 2 + 1));
    /* Set the break to be on execution (00b). */
    xstate->dr[7] &= ~(3 << (16 + (reg * 4)));

    /* Now save these values for later write in flush_context! */
    xstate->context.debugreg[reg] = xstate->dr[reg];
    xstate->context.debugreg[6] = xstate->dr[6];
    xstate->context.debugreg[7] = xstate->dr[7];

    xstate->context_dirty = 1;

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    ret = xc_ttd_vmi_add_probe(xc_handle,xstate->id,addr);

    if (ret) {
        verror("failed to register probe [dom%d:%"PRIxADDR" (%d)\n",
	       xstate->id,addr,ret);
        return ret;
    }
    vdebug(4,LOG_T_XV | LOG_P_PROBE,"registered probe [dom%d:%"PRIxADDR"]\n",
	   xstate->id,addr);
#endif

    return 0;
}

static int xen_vm_set_hw_watchpoint(struct target *target,
					    REG reg,ADDR addr,
					    probepoint_whence_t whence,
					    probepoint_watchsize_t watchsize) {
    struct xen_vm_state *xstate;
#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    int ret;
#endif

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    xstate = (struct xen_vm_state *)(target->state);

    if (!xstate->context_valid) {
	if (xen_vm_load_context(target)) 
	    return -1;
    }

    if (xstate->context.debugreg[reg] != 0) {
	vwarn("debug reg %"PRIiREG" already has an address, overwriting (0x%lx)!\n",
	      reg,xstate->context.debugreg[reg]);
	//errno = EBUSY;
	//return -1;
    }

    /* Set the address, then the control bits. */
    xstate->dr[reg] = addr;

    /* Clear the status bits */
    xstate->dr[6] = 0; //&= ~(1 << reg);

    /* Set the local control bit, and unset the global bit. */
    xstate->dr[7] |= (1 << (reg * 2));
    xstate->dr[7] &= ~(1 << (reg * 2 + 1));
    /* Set the break to be on whatever whence was) (clear the bits first!). */
    xstate->dr[7] &= ~(3 << (16 + (reg * 4)));
    xstate->dr[7] |= (whence << (16 + (reg * 4)));
    /* Set the watchsize to be whatever watchsize was). */
    xstate->dr[7] &= ~(3 << (18 + (reg * 4)));
    xstate->dr[7] |= (watchsize << (18 + (reg * 4)));

    vdebug(4,LOG_T_XV,
	   "dreg6 = 0x%"PRIxADDR"; dreg7 = 0x%"PRIxADDR", w = %d, ws = 0x%x\n",
	   xstate->dr[6],xstate->dr[7],whence,watchsize);

    /* Now save these values for later write in flush_context! */
    xstate->context.debugreg[reg] = xstate->dr[reg];
    xstate->context.debugreg[6] = xstate->dr[6];
    xstate->context.debugreg[7] = xstate->dr[7];

    xstate->context_dirty = 1;

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    ret = xc_ttd_vmi_add_probe(xc_handle,xstate->id,addr);

    if (ret) {
        verror("failed to register probe [dom%d:%"PRIxADDR" (%d)\n",
	       xstate->id,addr,ret);
        return ret;
    }
    vdebug(4,LOG_T_XV | LOG_P_PROBE,"registered probe [dom%d:%"PRIxADDR"]\n",
	   xstate->id,addr);
#endif

    return 0;
}

static int xen_vm_unset_hw_breakpoint(struct target *target,REG reg) {
    struct xen_vm_state *xstate;
#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    int ret;
    ADDR addr;
#endif

    if (reg < 0 || reg > 3) {
	errno = EINVAL;
	return -1;
    }

    xstate = (struct xen_vm_state *)(target->state);

    if (!xstate->context_valid) {
	if (xen_vm_load_context(target)) 
	    return -1;
    }

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    addr = xstate->dr[reg];
#endif

    /* Set the address, then the control bits. */
    xstate->dr[reg] = 0;

    /* Clear the status bits */
    xstate->dr[6] = 0; //&= ~(1 << reg);

    /* Unset the local control bit, and unset the global bit. */
    xstate->dr[7] &= ~(3 << (reg * 2));

    /* Now save these values for later write in flush_context! */
    xstate->context.debugreg[reg] = xstate->dr[reg];
    xstate->context.debugreg[6] = xstate->dr[6];
    xstate->context.debugreg[7] = xstate->dr[7];

    xstate->context_dirty = 1;

#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    ret = xc_ttd_vmi_remove_probe(xc_handle,xstate->id,addr);

    if (ret) {
        verror("failed to unregister probe [dom%d:%"PRIxADDR" (%d)\n",
	       xstate->id,addr,ret);
        return ret;
    }
    vdebug(4,LOG_T_XV | LOG_P_PROBE,"unregistered probe [dom%d:%"PRIxADDR"]\n",
	   xstate->id,addr);
#endif

    return 0;
}

static int xen_vm_unset_hw_watchpoint(struct target *target,REG reg) {
    /* It's the exact same thing, yay! */
    return xen_vm_unset_hw_breakpoint(target,reg);
}

int xen_vm_disable_hw_breakpoints(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);

    if (!xstate->context_valid) {
	if (xen_vm_load_context(target)) 
	    return -1;
    }

    xstate->context.debugreg[7] = 0;

    xstate->context_dirty = 1;

    return 0;
}

int xen_vm_enable_hw_breakpoints(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)(target->state);

    if (!xstate->context_valid) {
	if (xen_vm_load_context(target)) 
	    return -1;
    }

    xstate->context.debugreg[7] = xstate->dr[7];

    xstate->context_dirty = 1;

    return 0;
}

int xen_vm_notify_sw_breakpoint(struct target *target,ADDR addr,
				int notification) {
#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    struct xen_vm_state *xstate;
    int ret = -1;
    char *msg = "unregister";

    xstate = (struct xen_vm_state *)(target->state);

    if (!xstate->context_valid) {
	if (xen_vm_load_context(target)) 
	    return -1;
    }

    if (notification) {
	msg = "register";
	ret = xc_ttd_vmi_add_probe(xc_handle,xstate->id,addr);
    }
    else {
	ret = xc_ttd_vmi_remove_probe(xc_handle,xstate->id,addr);
    }

    if (ret) {
        verror("failed to %s probe [dom%d:%"PRIxADDR" (%d)\n",
	       msg,xstate->id,addr,ret);
        return ret;
    }
    vdebug(4,LOG_T_XV | LOG_P_PROBE,"%sed probe [dom%d:%"PRIxADDR"]\n",
	   msg,xstate->id,addr);
#endif
    return 0;
}

int xen_vm_singlestep(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    if (!xstate->context_valid) {
	if (xen_vm_load_context(target)) 
	    return -1;
    }

#if __WORDSIZE == 32
    xstate->eflags = xstate->context.user_regs.eflags;
#else
    xstate->eflags = xstate->context.user_regs.rflags;
#endif
    xstate->context.user_regs.eflags |= EF_TF;
    xstate->context.user_regs.eflags &= ~EF_IF;
    xstate->context_dirty = 1;

    if (target_flush_context(target) < 0) {
	verror("could not flush context; single step start will probably fail!\n");
	return -1;
    }

    /* flush_context will not have done this necessarily! */
    xstate->context_valid = 0;

    /*
     * Because the semantics of target_singlestep() dictate that the
     * target will be running after target_singlestep(), we manually
     * resume it.
     */
    return target_resume(target);
}

int xen_vm_singlestep_end(struct target *target) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;

    if (target->sstep_leave_enabled) {
	target->sstep_leave_enabled = 0;
	return 0;
    }

    if (!xstate->context_valid) {
	if (xen_vm_load_context(target)) 
	    return -1;
    }

    //xstate->context.user_regs.eflags &= ~EF_TF;
    //xstate->context.user_regs.eflags &= ~EF_IF;
#if __WORDSIZE ==32
    xstate->context.user_regs.eflags = xstate->eflags;
#else
    xstate->context.user_regs.rflags = xstate->eflags;
#endif

    xstate->context_dirty = 1;

    if (target_flush_context(target) < 0) {
	verror("could not flush context; single step end will probably fail!\n");
	return -1;
    }

    /* flush_context will not have done this necessarily! */
    xstate->context_valid = 0;

    return 0;
}
