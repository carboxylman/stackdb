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

#ifndef __TARGET_ARCH_X86_H__
#define __TARGET_ARCH_X86_H__

#include "config.h"
#include "arch.h"
#include "arch_x86.h"
#include "arch_x86_64.h"
#include "target_api.h"

typedef enum {
    ARCH_X86_V2P_NOTPAGING  = 1 << 0, /* Paging disabled */
    ARCH_X86_V2P_PAE        = 1 << 1, /* PAE */
    /*
     * target_arch_x86_v2p trusts the PS bit in the PTEs and just
     * does PSE for it.  Moreover, it does PSE-36 by default, because
     * PSE-36 just uses reserved bits (16-13) in the normal PTE, and
     * those bits *must* be zero in a normal PSE entry.  Moreover, it
     * just does PSE-40 because I assume PSE-40 uses the other 4 bits
     * (20-17) in the PTE that were otherwise reserved (those bits also
     * are reserved and must be zero for PSE or PSE-36).  Bit 21 stays
     * reserved and stays 0.  Probably no CPU really supports PSE-40
     * (well, it seems like AMD64 CPUs running in legacy mode *do*
     * support this!).
     *
     * Anyway, to sum up, target_arch_x86_v2p trusts the PTEs *unless*
     * NOPSE, NOPSE36, NOPSE40 are set.  If you pass a 0-value cpuid_edx
     * regval to target_arch_x86_get_flags(), it will set the NOPSE*
     * flags!  Usually this is not going to be what you want on any sane
     * modern CPU.  Better to pass a REGVALMAX value as cpuid_edx to
     * obtain "auto-PSE" support!
     */
    ARCH_X86_V2P_NOPSE      = 1 << 2, /* No PSE */
    ARCH_X86_V2P_NOPSE36    = 1 << 3, /* No PSE-36 */
    ARCH_X86_V2P_NOPSE40    = 1 << 4, /* No PSE-40 */
    ARCH_X86_V2P_LMA        = 1 << 5, /* 4-level PTs */
    ARCH_X86_V2P_PV         = 1 << 6, /* Translating for a PV Xen VM */
} arch_x86_v2p_flags_t;

int target_arch_x86_v2p_get_flags(struct target *target,REGVAL cr0,REGVAL cr4,
				  REGVAL msr_efer,REGVAL cpuid_edx,
				  arch_x86_v2p_flags_t *flags);
int target_arch_x86_v2p(struct target *target,ADDR pgd,ADDR virt,
			arch_x86_v2p_flags_t flags,ADDR *phys);
int target_arch_x86_v2p_flags_snprintf(struct target *target,
				   arch_x86_v2p_flags_t flags,
				   char *buf,unsigned int bufsiz);

#endif /* __TARGET_ARCH_X86_H__ */
