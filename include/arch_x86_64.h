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

#ifndef __ARCH_X86_64_H__
#define __ARCH_X86_64_H__

extern struct arch arch_x86_64;

/*
 * NB: we specifically don't support
 */

/*
 * The register mapping between x86_64 registers is defined by AMD in
 * http://www.x86-64.org/documentation/abi-0.99.pdf :
 */

#define ARCH_X86_64_REG_COUNT 89

/* 64-bit GP regs. */
#define REG_X86_64_RAX  0
#define REG_X86_64_RDX  1
#define REG_X86_64_RCX  2
#define REG_X86_64_RBX  3
#define REG_X86_64_RSI  4
#define REG_X86_64_RDI  5
#define REG_X86_64_RBP  6
#define REG_X86_64_RSP  7
#define REG_X86_64_R8   8
#define REG_X86_64_R9   9
#define REG_X86_64_R10 10
#define REG_X86_64_R11 11
#define REG_X86_64_R12 12
#define REG_X86_64_R13 13
#define REG_X86_64_R14 14
#define REG_X86_64_R15 15

/* Special DWARF reg for getting the RA; we overload it for RIP */
#define REG_X86_64_RIP 16

/*
 * The SIMD instructions.  They were 128-bit SSE regs (xmm); 256-bit AVX
 * regs (ymm); and finally now 512-bit AVX-512 regs (zmm).
 *
 * XXX: I don't have DWARF numbers for zmm16-31.  Technically I don't
 * think DWARF does either :).  Whatever, we're not supporting vector
 * nor FP regs.
 */
#define REG_X86_64_XMM0 17
#define REG_X86_64_XMM1 18
#define REG_X86_64_XMM2 19
#define REG_X86_64_XMM3 20
#define REG_X86_64_XMM4 21
#define REG_X86_64_XMM5 22
#define REG_X86_64_XMM6 23
#define REG_X86_64_XMM7 24
#define REG_X86_64_XMM8 25
#define REG_X86_64_XMM9 26
#define REG_X86_64_XMM10 27
#define REG_X86_64_XMM11 28
#define REG_X86_64_XMM12 29
#define REG_X86_64_XMM13 30
#define REG_X86_64_XMM14 31
#define REG_X86_64_XMM15 32

/* 80-bit FP regs. */
#define REG_X86_64_ST0 33
#define REG_X86_64_ST1 34
#define REG_X86_64_ST2 35
#define REG_X86_64_ST3 36
#define REG_X86_64_ST4 37
#define REG_X86_64_ST5 38
#define REG_X86_64_ST6 39
#define REG_X86_64_ST7 40

#define REG_X86_64_MM0 41
#define REG_X86_64_MM1 42
#define REG_X86_64_MM2 43
#define REG_X86_64_MM3 44
#define REG_X86_64_MM4 45
#define REG_X86_64_MM5 46
#define REG_X86_64_MM6 47
#define REG_X86_64_MM7 48

/* These are technically 32-bit, but who cares. */
#define REG_X86_64_RFLAGS 49
#define REG_X86_64_ES  50
#define REG_X86_64_CS  51
#define REG_X86_64_SS  52
#define REG_X86_64_DS  53
#define REG_X86_64_FS  54
#define REG_X86_64_GS  55

#define REG_X86_64_FS_BASE 58
#define REG_X86_64_GS_BASE 59
/*
 * Maybe special for Xen?  At least 60 is not a DWARF reg... but might
 * be useful for VMs.
 */
#define REG_X86_64_GS_BASE_KERNEL 60
#define REG_X86_64_GS_BASE_USER 61

#define REG_X86_64_TR 62
#define REG_X86_64_LDT 63
#define REG_X86_64_MXCSR 64 /* 128-bit */
#define REG_X86_64_X87CW 65
#define REG_X86_64_X87SW 66

/* This is not a DWARF register, but we want it to be somewhere! */
#define REG_X86_64_GDT 67

/*
 * DWARF cannot address the rest of these.
 */

/*
 * These registers are not "official" registers DWARF debuggers should
 * ask for, but we want to map them somewhere!
 */

#define REG_X86_64_CR0 70
#define REG_X86_64_CR1 71
#define REG_X86_64_CR2 72
#define REG_X86_64_CR3 73
#define REG_X86_64_CR4 74

#define REG_X86_64_CR8 78

/* XXX: some chips have an XCR0 register; ignore it for now. */

#define REG_X86_64_DR0 80
#define REG_X86_64_DR1 81
#define REG_X86_64_DR2 82
#define REG_X86_64_DR3 83

#define REG_X86_64_DR6 86
#define REG_X86_64_DR7 87

#define REG_X86_64_MSR_EFER 88

#endif /* __ARCH_X86_64_H__ */
