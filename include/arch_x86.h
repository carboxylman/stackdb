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

#ifndef __ARCH_X86_H__
#define __ARCH_X86_H__

#include "arch.h"

extern struct arch arch_x86;

/*
 * This is the SVR4 DWARF map from gdb/gdb/i386-tdep.c .
 */

#define ARCH_X86_REG_COUNT 59

/* 32-bit GP regs. */
#define REG_X86_EAX  0
#define REG_X86_ECX  1
#define REG_X86_EDX  2
#define REG_X86_EBX  3
#define REG_X86_ESP  4
#define REG_X86_EBP  5
#define REG_X86_ESI  6
#define REG_X86_EDI  7
#define REG_X86_EIP  8
#define REG_X86_EFLAGS 9

/* FP regs. */
#define REG_X86_ST0 11
#define REG_X86_ST1 12
#define REG_X86_ST2 13
#define REG_X86_ST3 14
#define REG_X86_ST4 15
#define REG_X86_ST5 16
#define REG_X86_ST6 17
#define REG_X86_ST7 18

#define REG_X86_XMM0 21
#define REG_X86_XMM1 22
#define REG_X86_XMM2 23
#define REG_X86_XMM3 24
#define REG_X86_XMM4 25
#define REG_X86_XMM5 26
#define REG_X86_XMM6 27
#define REG_X86_XMM7 28

#define REG_X86_MM0 29
#define REG_X86_MM1 30
#define REG_X86_MM2 31
#define REG_X86_MM3 32
#define REG_X86_MM4 33
#define REG_X86_MM5 34
#define REG_X86_MM6 35
#define REG_X86_MM7 36

#define REG_X86_X87CW 37
#define REG_X86_FCTRL REG_X86_X87CW
#define REG_X86_X87SW 38
#define REG_X86_FSTAT REG_X86_X87SW
#define REG_X86_MXCSR 39

/* These are technically 32-bit, but who cares. */
#define REG_X86_ES  40
#define REG_X86_CS  41
#define REG_X86_SS  42
#define REG_X86_DS  43
#define REG_X86_FS  44
#define REG_X86_GS  45

/*
 * DWARF cannot address the rest of these.
 */

/*
 * These registers are not "official" registers DWARF debuggers should
 * ask for, but we want to map them somewhere!
 */

#define REG_X86_CR0 46
#define REG_X86_CR1 47
#define REG_X86_CR2 48
#define REG_X86_CR3 49
#define REG_X86_CR4 50

#define REG_X86_DR0 51
#define REG_X86_DR1 52
#define REG_X86_DR2 53
#define REG_X86_DR3 54
#define REG_X86_DR4 55

#define REG_X86_DR6 57
#define REG_X86_DR7 58

#endif /* __ARCH_X86_H__ */
