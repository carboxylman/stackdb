/*
 * Copyright (c) 2012, 2013 The University of Utah
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

#ifndef __CFI_H__
#define __CFI_H__

#include <glib.h>
#include "common.h"
#include "target_api.h"
#include "probe_api.h"

/*
 * Our CFI implementation handles multithreaded targets, and provides a
 * few configuration options.
 *
 * Right now, it only supports dynamic CFI, seeded from a root set of target
 * functions.  When we start dynamic CFI, we disasm the root set
 * functions, and place probes on any of their control flow transfer
 * instructions (well, right now, just CALL/RET).  If the CFI_AUTOFOLLOW
 * flag is set, when control is transferred to a currently untracked
 * part of the code, we attempt to probe that code as well (growing our
 * tracked function set).
 *
 * See more below about static CFI for how it *would* work, and why it
 * is basically inferior to dynamic CFI -- and thus why we will never
 * implement it :).
 */

typedef enum {
    /*
     * In dynamic mode, we place probes on control transfer instructions
     * (initially only CALL and RET) within each tracked function.  When
     * a CALL probe is hit, a posthandler probe records the return addr
     * on our shadow stack; when a RET probe is hit, a prehandler probe
     * pop/checks the return addr with our shadow stack.
     *
     * Dynamic mode is well-suited to the case when when you have
     * control flow instructions that are runtime-dependent (i.e., are
     * not just absolute calls or jumps); most programs have these.  It
     * also frees you from having to insert 
     */
    CFI_DYNAMIC = 1,
    /*
     * NB: right now, static mode is unsupported, since its utility is
     * highly debatable.  The biggest reason not to do is because it
     * basically requires more probes per function.  Consider: if we
     * have to maintain our shadow stack via the entry/exit probes, BUT
     * also have to implement AUTOFOLLOW by placing probes on any
     * indirect control flow transfer functions inside the function --
     * we may as well do a dynamic analysis and record return addresses
     * *at* the control flow transfer sites themselves; this is much cheaper.
     *
     * In static mode, we place probes on each tracked function's first
     * instruction, and on any return instructions, and push the retaddr
     * onto our shadow stack when we hit the first instr, and pop/check
     * we leave the function.  Then if AUTOFOLLOW support is requested,
     * we also have to probe inside the function to catch control flow
     * transfers.
     */
    CFI_STATIC  = 2,
} cfi_mode_t;

typedef enum {
    CFI_NONE       = 0,
    /*
     * AUTOFOLLOW means that for each tracked function, its internal
     * control flow instructions are probed as well, and when they are
     * hit, we add more probes to their target functions (or code
     * blocks; might not be a function).  If we can't figure out what
     * the code block is, we would have to single step to maintain
     * control; we don't do that yet (and that behavior will be
     * controlled by CFI_SINGLESTEP_UNKNOWN below).
     *
     * This happens automatically; this flag disables it.
     */
    CFI_NOAUTOFOLLOW = 1 << 0,
    /*
     * If control flow becomes unknown, single step until we reach a
     * region that is no longer unknown, and track all control flow
     * until we return to a known location.
     */
    CFI_SINGLESTEP_UNKNOWN = 1 << 1,
    /*
     * If a violation is detected, try to fix up the return address on
     * the stack before returning!  This might not end up working 
     * semantically within the target, but it's easy to expose :).
     */
    CFI_FIXUP = 1 << 2,
} cfi_flags_t;

struct cfi_status;
struct cfi_thread_status;
struct cfi_data;

/*
 * Create a CFI "probe", starting from a set of root functions.
 *
 * NB: if flags & CFI_AUTOFOLLOW, you had better only have a single CFI
 * "probe" on this target/tid pair.  If you try to add another, they
 * will interfere with each other by trying to disasm each others' code
 * blocks as they add new tracked functions, and if one probe has
 * already probed a block that another probe then tries to disassemble,
 * the disassembly will fail if software probes are in place!!
 */
struct probe *probe_cfi(struct target *target,tid_t tid,
			cfi_mode_t mode,cfi_flags_t flags,
			struct array_list *root_functions,
			struct array_list *root_addrs,
			probe_handler_t pre_handler,probe_handler_t post_handler,
			void *handler_data);

char *cfi_thread_backtrace(struct cfi_data *cfi,struct cfi_thread_status *cts,
			   char *sep);

struct cfi_status {
    uint8_t isviolation:1;

    ADDR oldretaddr;
    ADDR newretaddr;

    uint16_t violations;
    int nonrootsethits;
};

struct cfi_thread_status {
    struct array_list *shadow_stack;
    struct array_list *shadow_stack_symbols;
    struct cfi_status status;
};

struct cfi_data {
    cfi_mode_t mode;
    cfi_flags_t flags;

    struct target *target;

    /*
     * A specific tid to track.
     */
    int tid;

    /*
     * A hashtable of disassembled functions.  We need to cache them to
     * make sure we don't try to disasm them after we have started
     * probing them!
     */
    GHashTable *disfuncs;

    /*
     * A hashtable of disassembled functions THAT DO NOT have any
     * control flow exiting from them, as far as we can tell.  We need
     * to cache them to make sure we don't try to disasm them after we
     * have started probing them!
     *
     * AND, we cannot add calls/jumps to them into our stack!  We must
     * push NULL instead.
     */
    GHashTable *disfuncs_noflow;

    /*
     * The internal probes we use.
     */
    GHashTable *probes;

    /*
     * Since we support multithreaded targets, we have to keep a shadow
     * stack for each thread.
     */
    GHashTable *thread_status;

    /*
     * This table tracks which return probes are probes on RET
     * instructions that have immediates.  We want to handle these
     * differently than normal RETs, because these pop the retaddr
     * first, then release stack bytes.  This pattern, I believe, is
     * only useful when returning to a different procedure and reusing
     * the current procedure's stack frame.  So, we have to detect this
     * as a valid RET, even though it's munging the stack.
     */
    GHashTable *ret_immediate_addrs;

    /* The high-level probe. */
    struct probe *cfi_probe;

    /* Overall status of the high-level probe. */
    struct cfi_status status;
};

#endif /* __CFI_H__ */
