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
#include "arch_x86_64.h"

static char *x86_64_reg_names[ARCH_X86_64_REG_COUNT] = { 
    "rax","rdx","rcx","rbx","rsi","rdi","rbp","rsp",
    "r8","r9","r10","r11","r12","r13","r14","r15",
    "rip",
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15",
    "st0","st1","st2","st3","st4","st5","st6","st7",
    "mm0","mm1","mm2","mm3","mm4","mm5","mm6","mm7",
    "rflags","es","cs","ss","ds","fs","gs",
    NULL,NULL,
    "fs_base","gs_base","gs_base_kernel","gs_base_user",
    "tr","ldt","mxcsr","x87cw","x87sw","gdt",
    NULL,NULL,
    "cr0","cr1","cr2","cr3","cr4",NULL,NULL,NULL,"cr8",
    NULL,
    "dr0","dr1","dr2","dr3",NULL,NULL,"dr6","dr7",
};

static REG x86_64_common_to_arch[COMMON_REG_COUNT] = {
    [CREG_IP] = REG_X86_64_RIP,
    [CREG_SP] = REG_X86_64_RSP,
    [CREG_BP] = REG_X86_64_RBP,
    [CREG_FLAGS] = REG_X86_64_RFLAGS,
    [CREG_RET] = REG_X86_64_RAX,
};

static uint8_t x86_64_reg_sizes[ARCH_X86_64_REG_COUNT] = {
    8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,
    8,
    64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,
    10,10,10,10,10,10,10,10,
    16,16,16,16,16,16,16,16,
    8,8,8,8,8,8,8,
    0,0,
    8,8,8,8,
    8,8,8,8,8,8,
    0,0,
    8,8,8,8,8,0,0,0,8,
    0,
    8,8,8,8,0,0,8,8,
};

static int x86_64_so_d0[] = { -1, };
static int x86_64_so_d1[] = {
    REG_X86_64_RIP,REG_X86_64_RBP,REG_X86_64_RSP,REG_X86_64_RFLAGS,
    REG_X86_64_RAX,REG_X86_64_RBX,REG_X86_64_RCX,REG_X86_64_RDX,
    REG_X86_64_RDI,REG_X86_64_RSI,
    REG_X86_64_R8,REG_X86_64_R9,REG_X86_64_R10,REG_X86_64_R11,REG_X86_64_R12,
    REG_X86_64_R13,REG_X86_64_R14,REG_X86_64_R15,
    REG_X86_64_CS,REG_X86_64_SS,REG_X86_64_DS,REG_X86_64_ES,
    REG_X86_64_FS,REG_X86_64_GS,
    REG_X86_64_FS_BASE,REG_X86_64_GS_BASE,REG_X86_64_GS_BASE_KERNEL,
    REG_X86_64_GS_BASE_USER,-1,
};
static int x86_64_so_d2[] = {
    REG_X86_64_CR0,REG_X86_64_CR1,REG_X86_64_CR2,REG_X86_64_CR3,
    REG_X86_64_DR0,REG_X86_64_DR1,REG_X86_64_DR2,REG_X86_64_DR3,
    REG_X86_64_DR6,REG_X86_64_DR7,-1,
};
static uint8_t x86_64_bpi[] = { 0xcc, };
static uint8_t x86_64_ri[] = { 0xc3, };
static uint8_t x86_64_fri[] = { 0xc9,0xc3, };

struct arch arch_x86_64 = {
    .type = ARCH_X86_64,

    .endian = ENDIAN_LITTLE,
    .wordsize = 8,
    .ptrsize = 8,

    .regcount = ARCH_X86_64_REG_COUNT,

    .reg_sizes = x86_64_reg_sizes,
    .common_to_arch = x86_64_common_to_arch,
    .reg_names = x86_64_reg_names,

    .snprintf_ordering = { x86_64_so_d0,x86_64_so_d1,x86_64_so_d2, }, //x86_64_snprintf_ordering,
    .max_snprintf_ordering = 2,

    .breakpoint_instrs = x86_64_bpi,
    .breakpoint_instrs_len = 1,
    .breakpoint_instr_count = 1,

    .ret_instrs = x86_64_ri,
    .ret_instrs_len = 1,
    .ret_instr_count = 1,

    /* LEAVE, RET */
    .full_ret_instrs = x86_64_fri,
    .full_ret_instrs_len = 2,
    .full_ret_instr_count = 2,
};
