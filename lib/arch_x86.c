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
#include "string.h"
#include "common.h"
#include "arch.h"
#include "arch_x86.h"

static char *x86_reg_names[ARCH_X86_REG_COUNT] = { 
    "eax","ecx","edx","ebx","esp","ebp","esi","edi","eip","eflags",
    NULL,
    "st0","st1","st2","st3","st4","st5","st6","st7",
    NULL,NULL,
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    "mm0","mm1","mm2","mm3","mm4","mm5","mm6","mm7",
    "x87cw","x87sw","mxcsr",
    "es","cs","ss","ds","fs","gs",
    "cr0","cr1","cr2","cr3","cr4",
    "dr0","dr1","dr2","dr3",NULL,NULL,"dr6","dr7",
};

static REG x86_common_to_arch[COMMON_REG_COUNT] = { 
    [CREG_IP] = REG_X86_EIP,
    [CREG_SP] = REG_X86_ESP,
    [CREG_BP] = REG_X86_EBP,
    [CREG_FLAGS] = REG_X86_EFLAGS,
    [CREG_RET] = REG_X86_EAX,
};

static uint8_t x86_reg_sizes[ARCH_X86_REG_COUNT] = {
    4,4,4,4,4,4,4,4,4,4,
    0,
    10,10,10,10,10,10,10,10,
    0,0,
    16,16,16,16,16,16,16,16,
    16,16,16,16,16,16,16,16,
    4,4,4,
    4,4,4,4,4,4,
    4,4,4,4,4,
    4,4,4,4,0,0,4,4,
};

static int x86_so_d0[] = { -1, };
static int x86_so_d1[] = {
    REG_X86_EIP,REG_X86_EBP,REG_X86_ESP,REG_X86_EFLAGS,
    REG_X86_EAX,REG_X86_EBX,REG_X86_ECX,REG_X86_EDX,REG_X86_EDI,REG_X86_ESI,
    REG_X86_CS,REG_X86_SS,REG_X86_DS,REG_X86_ES,REG_X86_FS,REG_X86_GS,-1,
};
static int x86_so_d2[] = {
    REG_X86_CR0,REG_X86_CR1,REG_X86_CR2,REG_X86_CR3,REG_X86_CR4,
    REG_X86_DR0,REG_X86_DR1,REG_X86_DR2,REG_X86_DR3,REG_X86_DR6,REG_X86_DR7,-1,
};
static int *x86_snprintf_ordering[ARCH_SNPRINTF_DETAIL_LEVELS] = {
    x86_so_d0,x86_so_d1,x86_so_d2,
};
static uint8_t x86_bpi[] = { 0xcc, };
static uint8_t x86_ri[] = { 0xc3, };
static uint8_t x86_fri[] = { 0xc9,0xc3, };

struct arch arch_x86 = {
    .type = ARCH_X86,

    .endian = ENDIAN_LITTLE,
    .wordsize = 4,
    .ptrsize = 4,

    .regcount = ARCH_X86_REG_COUNT,

    .reg_sizes = x86_reg_sizes,
    .common_to_arch = x86_common_to_arch,
    .reg_names = x86_reg_names,

    .snprintf_ordering = { x86_so_d0,x86_so_d1,x86_so_d2, },//x86_snprintf_ordering,
    .max_snprintf_ordering = 2,

    .breakpoint_instrs = x86_bpi,
    .breakpoint_instrs_len = 1,
    .breakpoint_instr_count = 1,

    .ret_instrs = x86_ri,
    .ret_instrs_len = 1,
    .ret_instr_count = 1,

    /* LEAVE, RET */
    .full_ret_instrs = x86_fri,
    .full_ret_instrs_len = 2,
    .full_ret_instr_count = 2,
};
