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

/*
 *  examples/context-tracker/ctxtracker.h
 *
 *  A very thin abstraction to track context changes of a Linux VM, 
 *  implemented on top of target.
 *
 *  Authors: Chung Hwan Kim, chunghwn@cs.utah.edu
 * 
 */

#ifndef ENABLE_XENACCESS
#error "XenAccess must be enabled"
#endif

#ifndef __CTXTRACKER_H__
#define __CTXTRACKER_H__

#include <stdbool.h>
#include <target_api.h>

typedef enum {
	TRACK_BIT_NONE       = 0,
	TRACK_BIT_TASKSWITCH = 1,
	TRACK_BIT_INTERRUPT  = 2,
	TRACK_BIT_PAGEFAULT  = 3,
	TRACK_BIT_EXCEPTION  = 4,
	TRACK_BIT_SYSCALL    = 5,
} ctxtracker_track_bit_t;

typedef enum {
	TRACK_NONE           = 0,
	TRACK_TASKSWITCH     = 1 << TRACK_BIT_TASKSWITCH,
	TRACK_INTERRUPT      = 1 << TRACK_BIT_INTERRUPT,
	TRACK_PAGEFAULT      = 1 << TRACK_BIT_PAGEFAULT,
	TRACK_EXCEPTION      = 1 << TRACK_BIT_EXCEPTION,
	TRACK_SYSCALL        = 1 << TRACK_BIT_SYSCALL,
} ctxtracker_track_t;

#define TRACK_ALL (TRACK_TASKSWITCH | TRACK_INTERRUPT | TRACK_PAGEFAULT \
		| TRACK_EXCEPTION | TRACK_SYSCALL)

/* Context information */
typedef struct {

	/* Task information */
	struct {
		struct value *cur;	// current task info
		struct value *prev;	// previous task info
	} task;
	
	/* Trap type that is being handled, set to a combination of the following:
	   TRACK_NONE:       no trap is being handled.
	   TRACK_INTERRUPT:  an interrupt is being handled.
	   TRACK_PAGEFAULT:  a page fault is being handled.
	   TRACK_EXCEPTION:  an exception is being handled.
	   TRACK_SYSCALL:    a system call is being executed. */
	ctxtracker_track_t flags;

	/* Interrupt details */
	struct {
		int irq_num;	// interrupt request number
		struct value *regs;	// register values from interrupt handler
	} interrupt;

	/* Page fault details */
	struct {
		ADDR addr;	// address at which page fault occurred
		struct value *regs;		// register values from page fault handler
		bool protection_fault;	// (T) protection fault, (F) no page found
		bool write_access;		// (T) write access, (F) read access
		bool user_mode;			// (T) user mode, (F) kernel mode 
		bool reserved_bit;		// (T) reserved bit
		bool instr_fetch;		// (T) instruction fetch
	} pagefault;

	/* Exception details */
	struct {
		char name[128];	// string value that indicates the name of exception
		struct value *regs;		// register values from exception handler
		uint32_t error_code;	// exception info
	} exception;

	/* System call details */
	struct {
		int sc_num;	// system call index
	} syscall;

} ctxtracker_context_t;

/*
 * Initialize context-aware-probes for a specified target. 'sysmap_name' is the
 * name of the System.map file for the target, which we use to instrument 
 * functions that debug-info does not tell us about.
 *
 * NOTE: Do the following to initialize dwdebug and target before you call this 
 * function and pass the opened 't'.
 * 1) dwdebug_init()
 * 2) vmi_set_log_level(level)
 * 3) xa_set_debug_level(level)
 * 4) struct target *t = xen_vm_attach(domain_name, NULL)
 * 5) target_open(t)
 */
/* FIXME: remove the sysmap_name argument once you start using target's ELF 
   symtab symbols. */
int ctxtracker_init(struct target *t);

/*
 * Clean up context tracker.
 *
 * NOTE: Do the following before you call this function.
 * 1) target_pause(t)
 *
 * NOTE: Do the following to close and free the target *after* you call this 
 * function.
 * 1) target_close(t)
 * 2) target_free(t)
 */
void ctxtracker_cleanup(void);

/*
 * Start or stop tracking contexts. 'flags' is a or'ed combination of TRACK_*,
 * which tells context tracker what types of contexts to track. Pass TRACK_ALL
 * to track all types of contexts. Context tracker starts tracking contexts of
 * the specified types if 'track' is true, otherwise it stops tracking them.
 */
int ctxtracker_track(ctxtracker_track_t flags, bool track);

/*
 * Register a handler on one or multiple types of context. 'flags' is a or'ed
 * combination of TRACK_* which tells context tracker what types of contexts
 * the 'handler' is called upon. If 'entry' is true, the 'handler' is registered
 * on the entries of the specified types of context. Otherwise, the 'handler'
 * is registered on the exits. For example, if the bit of TRACK_INTERRUPT is
 * set in 'flags' and 'entry' is false, then the 'handler' is called whenever
 * the target finishes handling the interrupt request.
 * NOTE: The value passed to 'entry' is ignored for a TRACK_TASKSWITCH bit set
 * in 'flags', since a task switch has not entry or exit point.
 */
int ctxtracker_register_handler(ctxtracker_track_t flags, 
		probe_handler_t handler, void *handler_data, bool entry);

#endif /* __CTXTRACKER_H__ */
