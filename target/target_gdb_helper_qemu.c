/*
 * Copyright (c) 2014 The University of Utah
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
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/mman.h>
#ifdef ENABLE_LIBVIRT
#include <libvirt/libvirt.h>
#include <libvirt/libvirt-qemu.h>
#endif

#include "common.h"
#include "arch.h"
#include "arch_x86.h"
#include "arch_x86_64.h"
#include "regcache.h"
#include "target_api.h"
#include "target.h"

#include "target_gdb.h"
#include "target_gdb_rsp.h"

/*
 * Ok, if we use the QEMU QMP, we can extract even more info... like
 * more machine registers -- and if the user starts QEMU with the
 * -mem-path option and configures our LD_PRELOADable libqemuhacks.so
 * appropriately, we can read/write phys memory directly by mmap!  This
 * is a huge performance benefit.
 */

/*
 * Local prototypes.
 */
int gdb_helper_qemu_addr_v2p(struct target *target,tid_t tid,ADDR pgd,
			     ADDR vaddr,ADDR *paddr);
unsigned char *gdb_helper_qemu_read_tid(struct target *target,
					tid_t tid,ADDR pgd,ADDR addr,
					unsigned long length,
					unsigned char *buf);

struct gdb_helper_qemu_state {
    int qemu_qmp_fd;
    int ram_mmap_fd;
    void *ram_mmap;
    unsigned long ram_mmap_size;
#ifdef ENABLE_LIBVIRT
    virConnectPtr qemu_libvirt_conn;
    virDomainPtr qemu_libvirt_dom;
#endif
};

int gdb_helper_qemu_init(struct target *target) {
    struct gdb_spec *gspec = (struct gdb_spec *)target->spec->backend_spec;
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    struct gdb_helper_qemu_state *qstate;
    struct stat sbuf;

    qstate = calloc(1,sizeof(*qstate));

    target->memcache = memcache_create(0,0,NULL);

    if (gspec->qemu_mem_path) {
	/* We use memcache for v2p -- create one. */
	if (target->memcache) {
	    verror("memcache already in use!\n");
	    errno = EINVAL;
	    return -1;
	}

	if (stat(gspec->qemu_mem_path,&sbuf) < 0) {
	    verror("could not stat QEMU mem-path file %s: %s (%d)!\n",
		   gspec->qemu_mem_path,strerror(errno),errno);
	    free(qstate);
	    return -1;
	}
	qstate->ram_mmap_size = sbuf.st_size;
	qstate->ram_mmap_fd = open(gspec->qemu_mem_path,O_RDWR);
	if (qstate->ram_mmap_fd < 0) {
	    verror("could not open QEMU mem-path file %s: %s (%d)!\n",
		   gspec->qemu_mem_path,strerror(errno),errno);
	    free(qstate);
	    return -1;
	}
	qstate->ram_mmap = mmap(NULL,qstate->ram_mmap_size,PROT_READ | PROT_WRITE,
				MAP_SHARED,qstate->ram_mmap_fd,0);
	if (qstate->ram_mmap == (void *) -1) {
	    verror("could not mmap QEMU mem-path file %s: %s (%d)!\n",
		   gspec->qemu_mem_path,strerror(errno),errno);
	    free(qstate);
	    return -1;
	}
    }

    qstate->qemu_qmp_fd = -1;
    gstate->hops_priv = qstate;

#ifdef ENABLE_LIBVIRT
    qstate->qemu_libvirt_conn = 0;
    qstate->qemu_libvirt_dom = 0;
#endif

    return 0;
}

int __recv_til_block(int fd,char *buf,unsigned int len,int blockfirst) {
    char sbuf[4096];
    char *bufp;
    unsigned int rlen;
    unsigned int count;
    int rc;
    int i;

    if (buf) {
	bufp = buf;
	rlen = len;
    }
    else {
	bufp = sbuf;
	rlen = sizeof(sbuf);
    }

    /*
     * Recv everything we can until we would block; throw it away.
     */
    count = 0;
    i = 0;
    while (1) {
	rc = recv(fd,bufp + count,rlen - count,
		  (i == 0 && blockfirst) ? 0 : MSG_DONTWAIT);
	++i;
	if (rc < 0) {
	    if (errno == EAGAIN || errno == EWOULDBLOCK) {
		break;
	    }
	    else {
		verror("recv: %s (%d)\n",strerror(errno),errno);
		return -1;
	    }
	}
	else if (rc == 0) {
	    verror("qmp server disconnected unexpectedly!\n");
	    return -1;
	}
	else {
	    count += (unsigned int)rc;
	    if (!buf) {
		vdebug(9,LA_TARGET,LF_GDB,"(discarding) recv QMP '%s'\n",bufp);
		count = 0;
	    }
	    else {
		vdebug(9,LA_TARGET,LF_GDB,"(saving) recv QMP '%s'\n",bufp);
	    }

	    if (count == rlen)
		break;
	}
    }

    return count;
}

int gdb_helper_qemu_attach(struct target *target) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    struct gdb_spec *gspec = (struct gdb_spec *)target->spec->backend_spec;
    struct gdb_helper_qemu_state *qstate = \
	(struct gdb_helper_qemu_state *)gstate->hops_priv;
    struct hostent *he;
    void *dst;
    int addrtype;
    int dlen;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    char *cmd = "{ \"execute\": \"qmp_capabilities\" }";

    /*
     * If spec->qemu_qmp_port, connect.  Set nonblocking.
     */
    if (gspec->qemu_qmp_hostname || gspec->qemu_qmp_port > 0) {
	if (!gspec->qemu_qmp_hostname)
	    gspec->qemu_qmp_hostname = strdup("localhost");
	if (gspec->qemu_qmp_port < 0)
	    gspec->qemu_qmp_port = 1235;

	he = gethostbyname(gspec->qemu_qmp_hostname);
	if (!he) {
	    verror("gethostbyname(%s): %s (%d)!",gspec->qemu_qmp_hostname,
		   hstrerror(h_errno),h_errno);
	    goto in_err;
	}

	addrtype = he->h_addrtype;
	if (addrtype == AF_INET) {
	    memcpy(&sin.sin_addr,he->h_addr,he->h_length);
	    //sin.sin_addr.s_addr = INADDR_ANY;
	    dlen = sizeof(sin);
	    dst = &sin;
	    sin.sin_port = htons(gspec->qemu_qmp_port);
	    sin.sin_family = addrtype;
	}
	else if (addrtype == AF_INET6) {
	    memcpy(&sin6.sin6_addr,he->h_addr,he->h_length);
	    dlen = sizeof(sin6);
	    dst = &sin6;
	    sin6.sin6_port = htons(gspec->qemu_qmp_port);
	    sin6.sin6_family = addrtype;
	}
	else {
	    verror("unknown addrtype %d for hostname %s!\n",
		   addrtype,gspec->qemu_qmp_hostname);
	    goto in_err;
	}

	/*
	if (inet_pton(addrtype,he->h_addr,dst) != 1) {
	    verror("could not convert addr %s to network!\n",he->h_addr);
	    goto in_err;
	}
	*/

	qstate->qemu_qmp_fd = socket(addrtype,SOCK_STREAM,0);
	if (qstate->qemu_qmp_fd < 0) {
	    verror("socket(): %s\n",strerror(errno));
	    goto in_err;
	}

	if (connect(qstate->qemu_qmp_fd,(struct sockaddr *)dst,dlen) < 0) {
	    verror("connect(%s): %s\n",he->h_name,strerror(errno));
	    goto in_err;
	}

	vdebug(5,LA_TARGET,LF_GDB,
	       "connected to tcp socket %s:%d (fd %d)\n",
	       he->h_name,gspec->qemu_qmp_port,qstate->qemu_qmp_fd);

	/*
	 * Make it nonblocking.
	 */
	/*
	flags = fcntl(qstate->qemu_qmp_fd,F_GETFL,0);
	flags |= O_NONBLOCK;
	fcntl(qstate->qemu_qmp_fd,F_SETFL,flags);
	*/

	/*
	 * Enter capabilities execution mode.
	 */
	__recv_til_block(qstate->qemu_qmp_fd,NULL,0,0);
	write(qstate->qemu_qmp_fd,cmd,strlen(cmd));
	__recv_til_block(qstate->qemu_qmp_fd,NULL,0,1);
    }
#ifdef ENABLE_LIBVIRT
    else if (gspec->qemu_libvirt_domain) {
	qstate->qemu_libvirt_conn = virConnectOpen(NULL);
	if (!qstate->qemu_libvirt_conn)
	    return -1;
	qstate->qemu_libvirt_dom =
	    virDomainLookupByName(qstate->qemu_libvirt_conn,
				  gspec->qemu_libvirt_domain);
	if (!qstate->qemu_libvirt_dom) {
	    verror("could not find libvirt domain '%s'!\n",
		   gspec->qemu_libvirt_domain);
	    if (!errno)
		errno = ECONNREFUSED;
	    virConnectClose(qstate->qemu_libvirt_conn);
	    qstate->qemu_libvirt_conn = NULL;
	    return -1;
	}
    }
#endif

    return 0;

 in_err:
    if (qstate->qemu_qmp_fd > -1) {
	close(qstate->qemu_qmp_fd);
	qstate->qemu_qmp_fd = -1;
    }
    return -1;
}

int gdb_helper_qemu_handle_exception_any(struct target *target) {
    return 0;
}

int gdb_helper_qemu_handle_exception_ours(struct target *target) {
    struct gdb_spec *xspec;

    xspec = (struct gdb_spec *)target->spec->backend_spec;

    /* XXX: invalidate caches? */
    if (xspec->clear_mem_caches_each_exception) {
	memcache_invalidate_all(target->memcache);
    }
    else
	memcache_inc_ticks(target->memcache,1);

    return 0;
}

int gdb_helper_qemu_handle_pause(struct target *target) {
    struct gdb_spec *xspec;

    xspec = (struct gdb_spec *)target->spec->backend_spec;

    /* XXX: invalidate caches? */
    if (xspec->clear_mem_caches_each_exception) {
	memcache_invalidate_all(target->memcache);
    }
    else
	memcache_inc_ticks(target->memcache,1);

    return 0;
}

int gdb_helper_qemu_load_machine(struct target *target,
				 struct regcache *regcache) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    struct gdb_helper_qemu_state *qstate = \
	(struct gdb_helper_qemu_state *)gstate->hops_priv;
    unsigned int i;
    char *cmd = "{ \"execute\": \"human-monitor-command\","
	        "  \"arguments\": { \"command-line\": \"info registers\" } }\n";
    char *buf;
    unsigned int bufsiz;
    char *idx;
    REGVAL regval;

    if (qstate->qemu_qmp_fd > 0) {
	bufsiz = 4096;
	buf = malloc(bufsiz);
	__recv_til_block(qstate->qemu_qmp_fd,NULL,0,0);

	/*
	 * Send the command -- the whole thing.
	 */
	write(qstate->qemu_qmp_fd,cmd,strlen(cmd));

	/*
	 * Block until we receive enough crap that has a GS *= *deadbeef.xs
	 */
	__recv_til_block(qstate->qemu_qmp_fd,buf,bufsiz,1);
    }
#ifdef ENABLE_LIBVIRT
    else if (qstate->qemu_libvirt_conn) {
	buf = NULL;
	virDomainQemuMonitorCommand(qstate->qemu_libvirt_dom,cmd,&buf,0);
	if (!buf) {
	    if (!errno)
		errno = ECOMM;
	    return -1;
	}
	bufsiz = strlen(buf);
    }
#endif
    else {
	errno = EINVAL;
	return -1;
    }

    for (i = 0; i < bufsiz; ++i) {
	if (buf[i] == '\r' || buf[i] == '\n')
	    buf[i] = ' ';
    }

    if (target->arch->type == ARCH_X86_64) {
	idx = strstr(buf,"GS =0000 ");
	if (idx) {
	    regval = (REGVAL)strtoull(idx + strlen("GS =0000"),NULL,16);

	    vdebug(9,LA_TARGET,LF_GDB,"gs_base = 0x%"PRIxREGVAL"\n",regval);

	    regcache_init_reg(regcache,REG_X86_64_GS_BASE,regval);
	}
	else
	    vwarnopt(9,LA_TARGET,LF_GDB,"no GS for gs_base!\n");
    }

    idx = strstr(buf,"CR0=");
    if (idx) {
	regval = (REGVAL)strtoull(idx + strlen("CR0="),NULL,16);

	vdebug(9,LA_TARGET,LF_GDB,"cr0 = 0x%"PRIxREGVAL"\n",regval);

	if (target->arch->type == ARCH_X86_64)
	    regcache_init_reg(regcache,REG_X86_64_CR0,regval);
	else
	    regcache_init_reg(regcache,REG_X86_CR0,regval);
    }
    else
	vwarnopt(9,LA_TARGET,LF_GDB,"no cr0!\n");

    idx = strstr(buf,"CR3=");
    if (idx) {
	regval = (REGVAL)strtoull(idx + strlen("CR3="),NULL,16);

	vdebug(9,LA_TARGET,LF_GDB,"cr3 = 0x%"PRIxREGVAL"\n",regval);

	if (target->arch->type == ARCH_X86_64)
	    regcache_init_reg(regcache,REG_X86_64_CR3,regval);
	else
	    regcache_init_reg(regcache,REG_X86_CR3,regval);
    }
    else
	vwarnopt(9,LA_TARGET,LF_GDB,"no cr3!\n");

    idx = strstr(buf,"CR4=");
    if (idx) {
	regval = (REGVAL)strtoull(idx + strlen("CR4="),NULL,16);

	vdebug(9,LA_TARGET,LF_GDB,"cr4 = 0x%"PRIxREGVAL"\n",regval);

	if (target->arch->type == ARCH_X86_64)
	    regcache_init_reg(regcache,REG_X86_64_CR4,regval);
	else
	    regcache_init_reg(regcache,REG_X86_CR4,regval);
    }
    else
	vwarnopt(9,LA_TARGET,LF_GDB,"no cr4!\n");

    idx = strstr(buf,"DR6=");
    if (idx) {
	regval = (REGVAL)strtoull(idx + strlen("DR6="),NULL,16);

	vdebug(9,LA_TARGET,LF_GDB,"dr6 = 0x%"PRIxREGVAL"\n",regval);

	if (target->arch->type == ARCH_X86_64)
	    regcache_init_reg(regcache,REG_X86_64_DR6,regval);
	else
	    regcache_init_reg(regcache,REG_X86_DR6,regval);
    }
    else
	vwarnopt(9,LA_TARGET,LF_GDB,"no dr6!\n");

    idx = strstr(buf,"EFER=");
    if (idx) {
	regval = (REGVAL)strtoull(idx + strlen("EFER="),NULL,16);

	vdebug(9,LA_TARGET,LF_GDB,"efer = 0x%"PRIxREGVAL"\n",regval);

	if (target->arch->type == ARCH_X86_64)
	    regcache_init_reg(regcache,REG_X86_64_MSR_EFER,regval);
	else
	    regcache_init_reg(regcache,REG_X86_MSR_EFER,regval);
    }
    else
	vwarnopt(9,LA_TARGET,LF_GDB,"no efer!\n");

    if (qstate->qemu_qmp_fd > 0)
	__recv_til_block(qstate->qemu_qmp_fd,NULL,0,0);

    free(buf);

    return 0;
}

unsigned char *gdb_helper_qemu_read_tid_mem_path(struct target *target,
						 tid_t tid,ADDR pgd,ADDR addr,
						 unsigned long length,
						 unsigned char *buf) {
    struct gdb_state *xstate;
    struct gdb_helper_qemu_state *mstate;
    char *ram_mmap_start,*ram_mmap_end;
    ADDR lvaddr;
    OFFSET voffset = 0;
    char *mmap = NULL;
    unsigned long mlen;
    ADDR paddr;
    unsigned long i,j;
    int rc;
    unsigned long plength = 0;
    char *lbuf;
    unsigned long alen = 0;

    xstate = (struct gdb_state *)target->state;
    mstate = (struct gdb_helper_qemu_state *)xstate->hops_priv;

    if (!mstate->ram_mmap) {
	vwarnopt(5,LA_TARGET,LF_GDB,"QEMU -mem-path option not enabled!\n");
	errno = ENOTSUP;
	return NULL;
    }

    if (buf)
	lbuf = (char *)buf;
    else if (length)
	lbuf = malloc(length + 1);
    else {
	lbuf = NULL;
    }

    ram_mmap_start = (char *)mstate->ram_mmap;
    ram_mmap_end = (char *)mstate->ram_mmap + mstate->ram_mmap_size;

    /*
     * Ok, translate vaddrs to paddrs page by page and read.
     */

    lvaddr = addr & ~(__PAGE_SIZE - 1);
    voffset = addr & (__PAGE_SIZE - 1);

    for (i = 0; length == 0 || plength < length; ++i) {
	rc = gdb_helper_qemu_addr_v2p(target,tid,pgd,lvaddr + i * __PAGE_SIZE,
				      &paddr);
	if (rc) {
	    verror("could not translate v 0x%"PRIxADDR"; start v 0x%"PRIxADDR"!\n",
		   lvaddr,addr);
	    if (lbuf != (char *)buf)
		free(lbuf);
	    return NULL;
	}

	mlen = __PAGE_SIZE;
	if (i == 0) {
	    mlen -= voffset;
	}

	if (length > 0 && (plength + mlen) > length)
	    mlen = (length - plength);

	mmap = ram_mmap_start + paddr;
	if (i == 0)
	    mmap += voffset;

	if (mmap < ram_mmap_start || mmap >= ram_mmap_end) {
	    verror("Bad physical address 0x%"PRIxADDR"!\n",paddr);
	    errno = EFAULT;
	    if (lbuf != (char *)buf)
		free(lbuf);
	    return NULL;
	}
	else {
	    /* If looking for string, make more room in lbuf! */
	    if (!buf && !length) {
	    	alen += mlen;
		lbuf = realloc(lbuf,alen);
	    }

	    /* Copy the whole chunk to the end of the page. */
	    memcpy(lbuf + plength,mmap,mlen);

	    /* If looking for string, look for '\0'. */
	    if (!buf && !length) {
		for (j = plength; j < (plength + mlen); ++j) {
		    if (lbuf[j] == '\0')
			break;
		}
		if (j < (plength + mlen)) {
		    lbuf = realloc(lbuf,plength + j + 1);
		    lbuf[j] = '\0';
		    break;
		}
	    }

	    /* Update our total bytes read. */
	    plength += mlen;
	}
    }

    return (unsigned char *)lbuf;
}

unsigned long gdb_helper_qemu_write_tid_mem_path(struct target *target,
						 tid_t tid,ADDR pgd,ADDR addr,
						 unsigned long length,
						 unsigned char *buf) {
    struct gdb_state *xstate;
    struct gdb_helper_qemu_state *mstate;
    char *ram_mmap_start,*ram_mmap_end;
    ADDR lvaddr;
    OFFSET voffset = 0;
    char *mmap = NULL;
    unsigned long mlen;
    ADDR paddr;
    unsigned long i;
    int rc;
    unsigned long plength = 0;

    xstate = (struct gdb_state *)target->state;
    mstate = (struct gdb_helper_qemu_state *)xstate->hops_priv;

    if (!mstate->ram_mmap) {
	vwarnopt(5,LA_TARGET,LF_GDB,"QEMU -mem-path option not enabled!\n");
	errno = ENOTSUP;
	return 0;
    }

    ram_mmap_start = (char *)mstate->ram_mmap;
    ram_mmap_end = (char *)mstate->ram_mmap + mstate->ram_mmap_size;

    /*
     * Ok, translate vaddrs to paddrs page by page and write.
     */

    lvaddr = addr & ~(__PAGE_SIZE - 1);
    voffset = addr & (__PAGE_SIZE - 1);

    for (i = 0; plength < length; ++i) {
	rc = gdb_helper_qemu_addr_v2p(target,tid,pgd,lvaddr + i * __PAGE_SIZE,
				      &paddr);
	if (rc) {
	    verror("could not translate v 0x%"PRIxADDR"; start v 0x%"PRIxADDR"!\n",
		   lvaddr,addr);
	    return 0;
	}

	mlen = __PAGE_SIZE;
	if (i == 0) {
	    mlen -= voffset;
	}

	if ((plength + mlen) > length)
	    mlen = (length - plength);

	mmap = ram_mmap_start + paddr;
	if (i == 0)
	    mmap += voffset;

	if (mmap < ram_mmap_start || mmap >= ram_mmap_end) {
	    verror("Bad physical address 0x%"PRIxADDR"!\n",paddr);
	    errno = EFAULT;
	    return 0;
	}
	else {
	    /* Copy the whole chunk to the end of the page or @length. */
	    memcpy(mmap,buf + plength,mlen);
	    /* Update our total bytes written. */
	    plength += mlen;
	}
    }

    return plength;
}

unsigned char *gdb_helper_qemu_read_v_str(struct target *target,
					  tid_t tid,ADDR pgd,ADDR addr) {
    int j;
    unsigned char *lbuf = NULL;
    int lbuf_alen;
    int lbuf_len;

    /*
     * Best strategy is to read page by page (starting with the remnant
     * of the page containing @addr), or byte by byte -- depending on
     * the GDB stub.  A page should always be safe, so do that for now.
     *
     * Ok, turns out a page is *not* safe, and for instance, will cause
     * the QEMU GDB stub to crash.  So stick with target wordsize, ugh!!!
     */

    //lbuf_alen = __PAGE_SIZE - (addr & (__PAGE_SIZE - 1));
    lbuf_alen = target->arch->wordsize;
    lbuf = realloc(lbuf,lbuf_alen);
    lbuf_len = 0;

    do {
	if (!gdb_helper_qemu_read_tid(target,tid,pgd,addr + lbuf_len,
				      lbuf_alen - lbuf_len,lbuf + lbuf_len)) {
	    verror("failed to read string at 0x%"PRIxADDR" (target %s)!\n",
		   addr,target->name);
	    free(lbuf);
	    return NULL;
	}

	/*
	 * Scan the mmap as necessary for '\0', malloc as necessary, and
	 * break or keep going.
	 */
	for (j = lbuf_len; j < lbuf_alen; ++j) {
	    if (lbuf[j] == '\0')
		break;
	}

	if (j < lbuf_alen) {
	    /* Found it!  realloc and return. */
	    lbuf = realloc(lbuf,j + 1);
	    return lbuf;
	}
	else {
	    lbuf_len = lbuf_alen;
	    //lbuf_alen += __PAGE_SIZE;
	    lbuf_alen += target->arch->wordsize;
	    lbuf = realloc(lbuf,lbuf_alen);
	}
    } while (1);

    return (unsigned char *)lbuf;
}

/*
 * XXX NB: When we talk to the QEMU GDB, we can't seem to read/write
 * "big chunks" without crashing the GDB stub, and thus QEMU --- so just
 * read 1KB at a time.
 */
#define GDB_MAX_IO 1024

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
unsigned char *gdb_helper_qemu_read_tid(struct target *target,
					tid_t tid,ADDR pgd,ADDR addr,
					unsigned long length,
					unsigned char *buf) {
    struct target_thread *tthread;
    int rc;
    int didalloc = 0;
    unsigned long bread,left;
    struct gdb_state *xstate;
    struct gdb_helper_qemu_state *mstate;

    xstate = (struct gdb_state *)target->state;
    mstate = (struct gdb_helper_qemu_state *)xstate->hops_priv;

    if (mstate->ram_mmap) {
	vdebug(5,LA_TARGET,LF_GDB,"trying QEMU -mem-path!\n");

	return gdb_helper_qemu_read_tid_mem_path(target,tid,pgd,addr,length,buf);
    }

    /*
     * Check @tid is current thread or global thread or that all threads
     * share a single address space!
     *
     * How to check if all threads share a single address space?  Maybe
     * just by checking the target type for now; if OS, assume threads
     * need not share an address space; if process or higher-level,
     * assume they do?
     */
    if (target->personality <= TARGET_PERSONALITY_OS && tid != TID_GLOBAL) {
	tthread = target_load_current_thread(target,0);
	if (!tthread) {
	    vwarn("could not load current thread; assuming tid %d is current!\n",
		  tid);
	}
	else {
	    if (tthread->tid != tid) {
		verror("tid %d is not current nor global; cannot read!\n",tid);
		return NULL;
	    }
	}
    }

    if (length == 0)
	return gdb_helper_qemu_read_v_str(target,tid,pgd,addr);

    if (!buf) {
	didalloc = 1;
	buf = malloc(length);
    }

    bread = 0;
    while (bread < length) {
	left = length - bread;
	rc = gdb_rsp_read_mem(target,addr + bread,
			      (left) > GDB_MAX_IO ? GDB_MAX_IO : left,
			      buf + bread);
	if (rc == 0) {
	    if (left > GDB_MAX_IO)
		bread += GDB_MAX_IO;
	    else
		bread += left;

	    if (bread >= length)
		return buf;
	    else
		continue;
	}
	else {
	    verror("v 0x%"PRIxADDR" len %lu: %s (%d); continuing\n",
		   addr,length,strerror(errno),rc);
	    if (didalloc)
		free(buf);
	    return NULL;
	}
    }
}

/*
 * Writes @length bytes from @buf to @addr.  Returns the number of bytes
 * written (and sets errno nonzero if there is an error).  Successful if
 * @return == @length.
 */
unsigned long gdb_helper_qemu_write_tid(struct target *target,
					tid_t tid,ADDR pgd,ADDR addr,
					unsigned long length,
					unsigned char *buf) {
    struct target_thread *tthread;
    int rc;
    unsigned long bwrote,left;
    struct gdb_state *xstate;
    struct gdb_helper_qemu_state *mstate;

    xstate = (struct gdb_state *)target->state;
    mstate = (struct gdb_helper_qemu_state *)xstate->hops_priv;

    if (mstate->ram_mmap) {
	vdebug(5,LA_TARGET,LF_GDB,"trying QEMU -mem-path!\n");

	return gdb_helper_qemu_write_tid_mem_path(target,tid,pgd,addr,length,buf);
    }

    /*
     * Check @tid is current thread or global thread or that all threads
     * share a single address space!
     *
     * How to check if all threads share a single address space?  Maybe
     * just by checking the target type for now; if OS, assume threads
     * need not share an address space; if process or higher-level,
     * assume they do?
     */
    if (target->personality <= TARGET_PERSONALITY_OS && tid != TID_GLOBAL) {
	tthread = target_load_current_thread(target,0);
	if (!tthread) {
	    vwarn("could not load current thread; assuming tid %d is current!\n",
		  tid);
	}
	else {
	    if (tthread->tid != tid) {
		verror("tid %d is not current nor global; cannot read!\n",tid);
		errno = EINVAL;
		return 0;
	    }
	}
    }

    bwrote = 0;
    while (bwrote < length) {
	left = length - bwrote;
	rc = gdb_rsp_write_mem(target,addr + bwrote,
			       (left) > GDB_MAX_IO ? GDB_MAX_IO : left,
			       buf + bwrote);
	if (rc == 0) {
	    if (left > GDB_MAX_IO)
		bwrote += GDB_MAX_IO;
	    else
		bwrote += left;

	    if (bwrote >= length)
		return length;
	    else
		continue;
	}
	else {
	    verror("v 0x%"PRIxADDR" len %lu: %s (%d)\n",
		   addr,length,strerror(errno),rc);
	    return 0;
	}
    }

    /* NB: only way we get here is if length == 0 */
    return 0;
}

int gdb_helper_qemu_addr_v2p(struct target *target,tid_t tid,ADDR pgd,
			     ADDR vaddr,ADDR *paddr) {
    struct gdb_state *xstate;
    struct gdb_helper_qemu_state *mstate;
    ADDR tvaddr,tpaddr;
    int rc;

    xstate = (struct gdb_state *)target->state;
    mstate = (struct gdb_helper_qemu_state *)xstate->hops_priv;

    if (!mstate->ram_mmap) {
	vwarnopt(5,LA_TARGET,LF_GDB,"QEMU -mem-path option not enabled!\n");
	errno = ENOTSUP;
	return -1;
    }

    /*
     * Strip the offset bits to improve builtin/xenaccess cache perf.
     */
    tvaddr = vaddr & ~(__PAGE_SIZE - 1);

    rc = memcache_get_v2p(target->memcache,pgd,tvaddr,paddr,NULL);
    if (rc == 0)
	return 0;
    else if (rc < 0) {
	vwarn("error while looking up vaddr 0x%"PRIxADDR" (for vaddr"
	      " 0x%"PRIxADDR") in memcache: %s (%d); trying full lookup!\n",
	      tvaddr,vaddr,strerror(errno),rc);
    }

    rc = target_arch_x86_v2p(target,pgd,vaddr,ARCH_X86_V2P_LMA,&tpaddr);
    if (rc) {
	verror("could not lookup vaddr 0x%"PRIxADDR" in tid %"PRIiTID
	       " pgd 0x%"PRIxADDR"!\n",
	       vaddr,tid,pgd);
	return -1;
    }

    *paddr = tpaddr | (vaddr & (__PAGE_SIZE - 1));

    vdebug(12,LA_TARGET,LF_XV,
	   "tid %"PRIiTID" vaddr 0x%"PRIxADDR" -> paddr 0x%"PRIxADDR"\n",
	   tid,vaddr,*paddr);

    memcache_set_v2p(target->memcache,pgd,vaddr,*paddr);

    return 0;
}

unsigned char *gdb_helper_qemu_read_phys_str(struct target *target,
					     ADDR addr) {
    struct gdb_state *xstate;
    struct gdb_helper_qemu_state *mstate;
    char *end;
    char *ram_mmap_start,*ram_mmap_end;
    unsigned long mlen;
    char *retval;

    xstate = (struct gdb_state *)target->state;
    mstate = (struct gdb_helper_qemu_state *)xstate->hops_priv;

    if (!mstate->ram_mmap) {
	vwarnopt(5,LA_TARGET,LF_GDB,"QEMU -mem-path option not enabled!\n");
	errno = ENOTSUP;
	return NULL;
    }

    /*
     * Read phys pages until we see a '\0'.
     */
    ram_mmap_start = (char *)mstate->ram_mmap + addr;
    ram_mmap_end = (char *)mstate->ram_mmap + mstate->ram_mmap_size;
    end = ram_mmap_start;

    while (end >= (char *)mstate->ram_mmap && end < ram_mmap_end) {
	if (*end == '\0')
	    break;
	++end;
    }

    mlen = end - ram_mmap_start;
    retval = malloc(mlen + 1);
    if (mlen > 0)
	memcpy(retval,ram_mmap_start,mlen);
    retval[mlen] = '\0';

    return (unsigned char *)retval;
}

unsigned char *gdb_helper_qemu_read_phys(struct target *target,ADDR paddr,
					    unsigned long length,
					    unsigned char *buf) {
    struct gdb_state *xstate;
    struct gdb_helper_qemu_state *mstate;
    char *ram_mmap_start,*ram_mmap_end;

    xstate = (struct gdb_state *)target->state;
    mstate = (struct gdb_helper_qemu_state *)xstate->hops_priv;

    if (!mstate->ram_mmap) {
	vwarnopt(5,LA_TARGET,LF_GDB,"QEMU -mem-path option not enabled!\n");
	errno = ENOTSUP;
	return NULL;
    }

    ram_mmap_start = (char *)mstate->ram_mmap + paddr;
    ram_mmap_end = (char *)mstate->ram_mmap + mstate->ram_mmap_size;

    if (ram_mmap_start >= (char *)mstate->ram_mmap
	&& (ram_mmap_start + length) < ram_mmap_end) {
	/* allocate buffer if necessary */
	if (!buf) {
	    buf = malloc(length + 1);
	    buf[length] = '\0';
	}
	memcpy(buf,ram_mmap_start,length);
    }
    else {
	verror("bad read paddr/length 0x%"PRIxADDR" %lu\n",paddr,length);
	errno = EFAULT;
	return NULL;
    }

    return (unsigned char *)buf;
}

unsigned long gdb_helper_qemu_write_phys(struct target *target,ADDR paddr,
					    unsigned long length,
					    unsigned char *buf) {
    struct gdb_state *xstate;
    struct gdb_helper_qemu_state *mstate;
    char *ram_mmap_start,*ram_mmap_end;

    xstate = (struct gdb_state *)target->state;
    mstate = (struct gdb_helper_qemu_state *)xstate->hops_priv;

    if (!mstate->ram_mmap) {
	vwarnopt(5,LA_TARGET,LF_GDB,"QEMU -mem-path option not enabled!\n");
	errno = ENOTSUP;
	return 0;
    }

    ram_mmap_start = (char *)mstate->ram_mmap + paddr;
    ram_mmap_end = (char *)mstate->ram_mmap + mstate->ram_mmap_size;

    if (ram_mmap_start >= (char *)mstate->ram_mmap
	&& (ram_mmap_start + length) < ram_mmap_end) {
	memcpy(ram_mmap_start,buf,length);
	return length;
    }
    else {
	verror("bad write paddr/length 0x%"PRIxADDR" %lu\n",paddr,length);
	errno = EFAULT;
	return 0;
    }
}

int gdb_helper_qemu_fini(struct target *target) {
    struct gdb_state *gstate = (struct gdb_state *)target->state;
    struct gdb_helper_qemu_state *qstate = calloc(1,sizeof(*qstate));

    if (qstate->qemu_qmp_fd > -1) {
	close(qstate->qemu_qmp_fd);
	qstate->qemu_qmp_fd = -1;
    }
#ifdef ENABLE_LIBVIRT
    else if (qstate->qemu_libvirt_conn) {
	qstate->qemu_libvirt_dom = 0;
	virConnectClose(qstate->qemu_libvirt_conn);
	qstate->qemu_libvirt_conn = 0;
    }
#endif

    if (qstate->ram_mmap) {
	munmap(qstate->ram_mmap,qstate->ram_mmap_size);
	qstate->ram_mmap = NULL;
	qstate->ram_mmap_size = 0;
	close(qstate->ram_mmap_fd);
    }

    free(qstate);
    gstate->hops_priv = NULL;

    return 0;
}

struct gdb_helper_ops gdb_helper_ops_qemu = {
    .init = gdb_helper_qemu_init,
    .attach = gdb_helper_qemu_attach,

    .handle_exception_any = gdb_helper_qemu_handle_exception_any,
    .handle_exception_ours = gdb_helper_qemu_handle_exception_ours,
    .handle_pause = gdb_helper_qemu_handle_pause,

    .load_machine = gdb_helper_qemu_load_machine,
    /*
     * No physical address space access; see comments at top!
     */
    .addr_v2p = gdb_helper_qemu_addr_v2p,
    .read_phys = gdb_helper_qemu_read_phys,
    .write_phys = gdb_helper_qemu_write_phys,

    .read_tid = gdb_helper_qemu_read_tid,
    .write_tid = gdb_helper_qemu_write_tid,

    .fini = gdb_helper_qemu_fini,
};
