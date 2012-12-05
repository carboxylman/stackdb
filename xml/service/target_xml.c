/*
 * Copyright (c) 2012 The University of Utah
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

#include "target_xml.h"
#include "debuginfo_xml.h"

enum target_type_t 
x_TargetTypeT_to_t_target_type_t(struct soap *soap,
				 enum vmi1__TargetTypeT type,
				 GHashTable *reftab,
				 enum target_type_t *out);
enum vmi1__TargetTypeT *
t_target_type_t_to_x_TargetTypeT(struct soap *soap,
				 enum target_type_t type,
				 GHashTable *reftab,
				 enum vmi1__TargetTypeT *out);

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

#ifdef ENABLE_XENACCESS
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

struct target *
x_TargetT_to_t_target(struct soap *soap,
		      struct vmi1__TargetT *target,
		      GHashTable *reftab,
		      struct target *out);
struct vmi1__TargetT *
t_target_to_x_TargetT(struct soap *soap,
		      struct target *target,
		      GHashTable *reftab,
		      struct vmi1__TargetT *out);
