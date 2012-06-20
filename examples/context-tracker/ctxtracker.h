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
int ctxtracker_init(struct target *t, const char *sysmap_name);

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

#endif /* __CTXTRACKER_H__ */
