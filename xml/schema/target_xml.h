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

#ifndef __TARGET_XML_H__
#define __TARGET_XML_H__

#include "config.h"
#include "target_xml_moduleStub.h"
#include "debuginfo_xml_moduleStub.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"
#include "target_linux_userproc.h"
#ifdef ENABLE_XENSUPPORT
#include "target_xen_vm.h"
#endif
#include "target_gdb.h"
#include "target_os_process.h"
#include "target_php.h"
#include <glib.h>

target_type_t 
x_TargetTypeT_to_t_target_type_t(struct soap *soap,
				 enum vmi1__TargetTypeT type,
				 GHashTable *reftab,
				 target_type_t *out);
enum vmi1__TargetTypeT 
t_target_type_t_to_x_TargetTypeT(struct soap *soap,
				 target_type_t type,
				 GHashTable *reftab,
				 enum vmi1__TargetTypeT *out);

target_mode_t 
x_TargetModeT_to_t_target_mode_t(struct soap *soap,
				 enum vmi1__TargetModeT mode,
				 GHashTable *reftab,
				 target_mode_t *out);
enum vmi1__TargetModeT 
t_target_mode_t_to_x_TargetModeT(struct soap *soap,
				 target_mode_t mode,
				 GHashTable *reftab,
				 enum vmi1__TargetModeT *out);

thread_bpmode_t 
x_ThreadBPModeT_to_t_thread_bpmode_t(struct soap *soap,
				     enum vmi1__ThreadBPModeT mode,
				     GHashTable *reftab,
				     thread_bpmode_t *out);
enum vmi1__ThreadBPModeT 
t_thread_bpmode_t_to_x_ThreadBPModeT(struct soap *soap,
				     thread_bpmode_t mode,
				     GHashTable *reftab,
				     enum vmi1__ThreadBPModeT *out);

struct target_spec *
x_TargetSpecT_to_t_target_spec(struct soap *soap,
			       struct vmi1__TargetSpecT *spec,
			       GHashTable *reftab,
			       struct target_spec *out);
struct vmi1__TargetSpecT *
t_target_spec_to_x_TargetSpecT(struct soap *soap,
			       struct target_spec *spec,
			       GHashTable *reftab,
			       struct vmi1__TargetSpecT *out);

#ifdef ENABLE_XENSUPPORT
struct xen_vm_spec *
x_TargetXenSpecT_to_t_xen_vm_spec(struct soap *soap,
				  struct vmi1__TargetXenSpecT *xspec,
				  GHashTable *reftab,
				  struct xen_vm_spec *out);
struct vmi1__TargetXenSpecT *
t_xen_vm_spec_to_x_TargetXenSpecT(struct soap *soap,
				  struct xen_vm_spec *spec,
				  GHashTable *reftab,
				  struct vmi1__TargetXenSpecT *out);
#endif

struct gdb_spec *
x_TargetGdbSpecT_to_t_gdb_spec(struct soap *soap,
			       struct vmi1__TargetGdbSpecT *xspec,
			       GHashTable *reftab,
			       struct gdb_spec *out);
struct vmi1__TargetGdbSpecT *
t_gdb_spec_to_x_TargetGdbSpecT(struct soap *soap,
			       struct gdb_spec *spec,
			       GHashTable *reftab,
			       struct vmi1__TargetGdbSpecT *out);

struct linux_userproc_spec *
x_TargetPtraceSpecT_to_t_linux_userproc_spec(struct soap *soap,
					     struct vmi1__TargetPtraceSpecT *xspec,
					     GHashTable *reftab,
					     struct linux_userproc_spec *out);
struct vmi1__TargetPtraceSpecT *
t_linux_userproc_spec_to_x_TargetPtraceSpecT(struct soap *soap,
					     struct linux_userproc_spec *spec,
					     GHashTable *reftab,
					     struct vmi1__TargetPtraceSpecT *out);
struct vmi1__TargetT *
t_target_id_to_x_TargetT(struct soap *soap,
			 int target_id,struct target_spec *spec,
			 GHashTable *reftab,
			 struct vmi1__TargetT *out);

struct vmi1__TargetT *
t_target_to_x_TargetT(struct soap *soap,
		      struct target *target,
		      GHashTable *reftab,
		      struct vmi1__TargetT *out);

thread_status_t 
x_ThreadStatusT_to_t_thread_status_t(struct soap *soap,
				     enum vmi1__ThreadStatusT status,
				     GHashTable *reftab,
				     thread_status_t *out);
enum vmi1__ThreadStatusT 
t_thread_status_t_to_x_ThreadStatusT(struct soap *soap,
				     thread_status_t status,
				     GHashTable *reftab,
				     enum vmi1__ThreadStatusT *out);

target_status_t 
x_TargetStatusT_to_t_target_status_t(struct soap *soap,
				     enum vmi1__TargetStatusT status,
				     GHashTable *reftab,
				     target_status_t *out);
enum vmi1__TargetStatusT 
t_target_status_t_to_x_TargetStatusT(struct soap *soap,
				     target_status_t status,
				     GHashTable *reftab,
				     enum vmi1__TargetStatusT *out);

struct vmi1__ThreadT *
t_target_thread_to_x_ThreadT(struct soap *soap,
			     struct target_thread *thread,
			     GHashTable *reftab,
			     struct vmi1__ThreadT *out);

struct vmi1__TargetT *
t_target_to_x_TargetT(struct soap *soap,
		      struct target *target,
		      GHashTable *reftab,
		      struct vmi1__TargetT *out);

struct vmi1__AddrSpaceT *
t_addrspace_to_x_AddrSpaceT(struct soap *soap,
			    struct addrspace *space,
			    GHashTable *reftab,
			    struct vmi1__AddrSpaceT *out);

enum vmi1__MemRegionTypeT 
t_region_type_t_to_x_MemRegionTypeT(struct soap *soap,
				    region_type_t rtype,
				    GHashTable *reftab,
				    enum vmi1__MemRegionTypeT *out);

struct vmi1__MemRegionT *
t_memregion_to_x_MemRegionT(struct soap *soap,
			    struct memregion *memregion,
			    GHashTable *reftab,
			    struct vmi1__MemRegionT *out);

struct vmi1__MemRangeT *
t_memrange_to_x_MemRangeT(struct soap *soap,
			  struct memrange *range,
			  GHashTable *reftab,
			  struct vmi1__MemRangeT *out);

struct vmi1__ProbeT *
t_probe_to_x_ProbeT(struct soap *soap,
		    struct probe *probe,
		    GHashTable *reftab,
		    struct vmi1__ProbeT *out);

struct vmi1__ProbeEventT *
t_probe_to_x_ProbeEventT(struct soap *soap,
			 struct probe *probe,tid_t tid,int type,struct probe *trigger,struct probe *base,
			 GHashTable *reftab,
			 struct vmi1__ProbeEventT *out);

probepoint_type_t
x_ProbepointTypeT_to_t_probepoint_type_t(struct soap *soap,
					 enum vmi1__ProbepointTypeT in);
enum vmi1__ProbepointTypeT 
t_probepoint_type_t_to_x_ProbepointTypeT(struct soap *soap,
					 probepoint_type_t in);

probepoint_style_t
x_ProbepointStyleT_to_t_probepoint_style_t(struct soap *soap,
					   enum vmi1__ProbepointStyleT in);
enum vmi1__ProbepointStyleT 
t_probepoint_style_t_to_x_ProbepointStyleT(struct soap *soap,
					   probepoint_style_t in);

probepoint_whence_t
x_ProbepointWhenceT_to_t_probepoint_whence_t(struct soap *soap,
					     enum vmi1__ProbepointWhenceT in);
enum vmi1__ProbepointWhenceT 
t_probepoint_whence_t_to_x_ProbepointWhenceT(struct soap *soap,
					     probepoint_whence_t in);

probepoint_watchsize_t
x_ProbepointSizeT_to_t_probepoint_watchsize_t(struct soap *soap,
					      enum vmi1__ProbepointSizeT in);
enum vmi1__ProbepointSizeT 
t_probepoint_watchsize_t_to_x_ProbepointSizeT(struct soap *soap,
					      probepoint_watchsize_t in);


action_type_t
x_ActionTypeT_to_t_action_type_t(struct soap *soap,
				 enum vmi1__ActionTypeT in);
enum vmi1__ActionTypeT 
t_action_type_t_to_x_ActionTypeT(struct soap *soap,
				 action_type_t in);

action_whence_t
x_ActionWhenceT_to_t_action_whence_t(struct soap *soap,
				     enum vmi1__ActionWhenceT in);
enum vmi1__ActionWhenceT 
t_action_whence_t_to_x_ActionWhenceT(struct soap *soap,
				     action_whence_t in);

handler_msg_t
x_HandlerMsgT_to_t_handler_msg_t(struct soap *soap,
				 enum vmi1__HandlerMsgT in);
enum vmi1__HandlerMsgT 
t_handler_msg_t_to_x_HandlerMsgT(struct soap *soap,
				 handler_msg_t in);

struct vmi1__ActionT *
t_action_to_x_ActionT(struct soap *soap,
		      struct action *action,
		      GHashTable *reftab,
		      struct vmi1__ActionT *out);

struct vmi1__ActionEventT *
t_action_to_x_ActionEventT(struct soap *soap,
			   struct action *action,struct target_thread *tthread,
			   handler_msg_t msg,int msg_detail,
			   GHashTable *reftab,
			   struct vmi1__ActionEventT *out);

#endif /* __TARGET_XML_H__ */
