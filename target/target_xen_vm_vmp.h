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

#ifndef __TARGET_XEN_VM_VMP_H__
#define __TARGET_XEN_VM_VMP_H__

#include "config.h"

#define TARGET_XV_VMP_BIN_PATH INSTALL_DIR "/bin/target_xen_vm_vmp"
#define TARGET_XV_VMP_SOCKET_FILENAME "vmi.target_xv_vmp.sock"
#define TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT "vmi.target_xv_vmp_client.%hd.sock"
/* Just for printing the %hd */
#define TARGET_XV_VMP_SOCKET_CLIENT_FILE_FORMAT_EXTRA 6

/*
 * Right now this structure is meaningless, because we cannot and will
 * not put the reponsibility of demultiplexing which domains are
 * experiencing debug exceptions into the hands of the demultiplexer.
 * There is too much Xen hypervisor variability in proper handling of
 * debug flags and CPU state that we would like to use to demultiplex;
 * and we cannot rely on it.  So we just "forward" the signal to all
 * clients (as if they had sent a client_request with vmid=0) without
 * trying to establish which domains are really experiencing a debug
 * exception.
 */

struct target_xen_vm_vmp_client_request {
    unsigned long int vmid;
};

struct target_xen_vm_vmp_client_response {
    unsigned long int vmid;
};

#ifdef XENCTRL_HAS_XC_INTERFACE
int xen_vm_xc_attach(xc_interface **xc_handle,xc_interface **xce_handle);
int xen_vm_xc_detach(xc_interface **xc_handle,xc_interface **xce_handle);
int xen_vm_virq_attach(xc_interface *xce_handle,XC_EVTCHN_PORT_T *dbg_port);
int xen_vm_virq_detach(xc_interface *xce_handle,XC_EVTCHN_PORT_T *dbg_port);
#else
int xen_vm_xc_attach(int *xc_handle,int *xce_handle);
int xen_vm_xc_detach(int *xc_handle,int *xce_handle);
int xen_vm_virq_attach(int xce_handle,XC_EVTCHN_PORT_T *dbg_port);
int xen_vm_virq_detach(int xce_handle,XC_EVTCHN_PORT_T *dbg_port);
#endif

#endif /* __TARGET_XEN_VM_VMP_H__ */
