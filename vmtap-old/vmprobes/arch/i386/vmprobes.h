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

/* 
 * File:   arch/i386/vmprobes.h
 * Author: Chung Hwan Kim
 * E-mail: chunghwn@cs.utah.edu
 */

#ifndef _ARCH_I386_VMPROBES_H
#define _ARCH_I386_VMPROBES_H

/* opcode size = 1 byte */
typedef uint8_t vmprobe_opcode_t;

/* breakpoint instruction */
#define BREAKPOINT_INSTRUCTION (0xcc)

/* trace enable bit (enables singlestep when it's set in eflags) */
#define PSL_T (0x00000100)

/* registers */
struct pt_regs {
    long ebx; /* 0 */
    long ecx; /* 4 */
    long edx; /* 8 */
    long esi; /* 12 */
    long edi; /* 16 */
    long ebp; /* 20 */
    long eax; /* 24 */
    int  xds; /* 28 */
    int  xes; /* 32 */
    int  xfs; /* 36 */
    int  xgs; /* 40 */
    long orig_eax; /* 44 */
    long eip;    /* 48 */
    int  xcs;    /* 52 */
    long eflags; /* 56 */
    long esp;    /* 60 */
    int  xss;    /* 64 */   
};

/* vcpu_guest_context_t.user_regs -> pt_regs */
#define SET_PT_REGS(pt, xc)                     \
{                                               \
    pt.ebx = xc.ebx;                            \
    pt.ecx = xc.ecx;                            \
    pt.edx = xc.edx;                            \
    pt.esi = xc.esi;                            \
    pt.edi = xc.edi;                            \
    pt.ebp = xc.ebp;                            \
    pt.eax = xc.eax;                            \
    pt.eip = xc.eip;                            \
    pt.xcs = xc.cs;                             \
    pt.eflags = xc.eflags;                      \
    pt.esp = xc.esp;                            \
    pt.xss = xc.ss;                             \
    pt.xes = xc.es;                             \
    pt.xds = xc.ds;                             \
    pt.xfs = xc.fs;                             \
    pt.xgs = xc.gs;                             \
}

/* pt_regs * -> vcpu_guest_context_t.user_regs */
#define SET_XC_REGS(pt, xc)                     \
{                                               \
    xc.ebx = pt->ebx;                           \
    xc.ecx = pt->ecx;                           \
    xc.edx = pt->edx;                           \
    xc.esi = pt->esi;                           \
    xc.edi = pt->edi;                           \
    xc.ebp = pt->ebp;                           \
    xc.eax = pt->eax;                           \
    xc.eip = pt->eip;                           \
    xc.cs = pt->xcs;                            \
    xc.eflags = pt->eflags;                     \
    xc.esp = pt->esp;                           \
    xc.ss = pt->xss;                            \
    xc.es = pt->xes;                            \
    xc.ds = pt->xds;                            \
    xc.fs = pt->xfs;                            \
    xc.gs = pt->xgs;                            \
}

#endif // _ARCH_I386_VMPROBES_H
