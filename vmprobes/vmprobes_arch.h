/*
 * Copyright (c) 2011, 2012 The University of Utah
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

#if defined (VMPROBE_i386)
#include "vmprobes_i386.h"
#elif defined (VMPROBE_x86_64) || defined (VMPROBE_x86) || defined (VMPROBE_x64)
#include "vmprobes_x86_64.h"
#elif defined (VMPROBE_ppc) || defined (VMPROBE_powerpc)
#include "vmprobe_ppc.h"
#elif defined (VMPROBE_s390) || defined (VMPROBE_s390x)
#include "vmprobes_s390.h"
#else
#error "Hardware architecture not defined or supported"
#endif
