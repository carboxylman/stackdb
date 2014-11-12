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

#ifndef __TARGET_GDB_H__
#define __TARGET_GDB_H__

#include "config.h"

#include "common.h"
#include "target.h"
#include "target_arch_x86.h"
#include "evloop.h"

#include "target_gdb_rsp.h"

#include <argp.h>
#include <glib.h>

extern struct target_ops gdb_ops;
extern struct argp gdb_argp;
extern char *gdb_argp_header;

struct gdb_spec {
    unsigned int do_stdio:1,
	         do_udp:1,
	         do_unix:1,
	         clear_mem_caches_each_exception:1,
	         is_qemu:1,
	         is_kvm:1;

    /* Max memcache limit, in bytes.  Backends must honor this! */
    unsigned long int memcache_mmap_size;

    char *devfile;
    char *sockfile;
    char *hostname;
    int port;

    char *qemu_qmp_hostname;
    int qemu_qmp_port;
    /*
     * NB: might have to extend this if we have VMs with > 4GB RAM; QEMU
     * splits the allocation into below 4GB and above 4GB; don't know if
     * they get mmap'd to the same file with the mem-path option.
     */
    char *qemu_mem_path;

    char *main_filename;

    char *qemu_libvirt_domain;
};

struct gdb_thread_state {
    //vcpu_guest_context_t context;

    //vcpu_guest_context_t alt_context;

    /* XXX: can we debug a 32-bit target on a 64-bit host?  If yes, how 
     * we use this might have to change.
     */
    unsigned long dr[8];
};

struct gdb_state {
    int fd;
    int wfd;
    char *sockfile;

    unsigned int need_interrupt:1,
	         writing:1,
	         need_ack:1,
	         rsp_status_valid:1,
	         vcont:1,
	         vcont_c:1,
	         vcont_C:1,
	         vcont_s:1,
	         vcont_S:1,
	         vcont_t:1,
	         vcont_r:1,
	         machine_valid:1,
	         stepping:1;

    unsigned int max_stub_packet_size;

    GHashTable *stubfeatures;

    char *ibuf;
    unsigned int ibuf_alen;
    unsigned int ibuf_len;

    char *obuf;
    unsigned int obuf_len;
    /*
     * Whatever sent the last message might want to handle a response;
     * this is that handler; its private data; and its final return code.
     */
    gdb_rsp_handler_t handler;
    void *handler_data;
    gdb_rsp_handler_ret_t handler_ret;

    struct gdb_rsp_stop_status last_stop_status;

    struct regcache *machine;

    char *ostype;

    /* If we have an OS personality, try to load this from it. */
    ADDR kernel_start_addr;

    int valid;

    /* The most recent set of paging flags. */
    arch_x86_v2p_flags_t v2p_flags;

    /* Which hops are we using? */
    struct gdb_helper_ops *hops;
    void *hops_priv;

    /*
#ifdef __x86_64__
    uint8_t *hvm_context_buf;
    uint32_t hvm_context_bufsiz;
    HVM_SAVE_TYPE(CPU) *hvm_cpu;
#endif
    */

    int evloop_fd;
};

struct target *gdb_instantiate(struct target_spec *spec,
				  struct evloop *evloop);
struct gdb_spec *gdb_build_spec(void);
void gdb_free_spec(struct gdb_spec *xspec);
int gdb_spec_to_argv(struct target_spec *spec,int *argc,char ***argv);

/*
 * We support several different memory backends for Xen VMs.
 */
struct gdb_helper_ops {
    int (*init)(struct target *target);
    int (*attach)(struct target *target);
    int (*handle_exception_any)(struct target *target);
    int (*handle_exception_ours)(struct target *target);
    int (*handle_pause)(struct target *target);
    int (*load_machine)(struct target *target,struct regcache *regcache);
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

#endif /* __TARGET_GDB_H__ */
