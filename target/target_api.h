/*
 * Copyright (c) 2011, 2012, 2013 The University of Utah
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

#ifndef __TARGET_API_H__
#define __TARGET_API_H__

#include "common.h"
#include "list.h"
#include "evloop.h"
#include "dwdebug.h"
#include "probe_api.h"
#include "probe.h"
#include <glib.h>

/*
 * Must be called by the library user, if said user wants 
 * multi-target management.
 */
void target_init(void);
void target_fini(void);

/**
 ** This file describes the publicly-accessible target API.  The target
 ** library is really a library of debug routines that supports multiple
 ** backends.  It is built atop the dwdebug library, which is a library
 ** for parsing DWARF debug information.  It provides two backends: a
 ** Linux ptrace userspace backend, and a Xen virtual machine (assumes a
 ** Linux guest) backend.  Both backends are x86-only at the moment.
 ** The linux ptrace backend supports 32/64-bit targets, but not 32-bit
 ** emulated atop 64-bit host.  The Xen VM/Linux guest backend supports
 ** 32-bit Xen/guest; it has partial, nonfunctional support for
 ** 64-bit-ness.  Right now, the backend code does not separate the
 ** logic for dealing with a target in an architecture-independent way
 ** -- the arch stuff is jammed in with the target code.  This should
 ** not be this way; eventually, hopefully, it will change into a target
 ** backend that supports different arch/machine ops.  Also, there are
 ** probably some x86-isms that have leaked into the "generic" target
 ** and probe code :(.
 **
 ** The target library supports two modes of dealing with threads inside
 ** a target.  Some targets provide control over executing threads 
 ** (i.e., can the library pause random threads at will, or not); the
 ** Linux ptrace target of course supports this; the Xen VM target does
 ** not (it could *mostly* support "pausing" all non-current threads in
 ** a single CPU guest, BUT even this requires that the debug lib handle
 ** NMIs, asynch interrupts, and some synchronous exceptions --
 ** overloading the kernel's IDT -- but right now we don't do this).
 **
 ** Targets that do not provide control over thread scheduling must
 ** still provide thread identification.  This is important for shared
 ** (i.e., memory-based) breakpoints, which any thread could hit at any
 ** time -- not just the thread the user is interested in.  Our handling
 ** of such breakpoints must be context-aware, so that we maintain
 ** handling information on a per-thread basis.
 **
 ** So the library supports two kinds of targets: ones that provide
 ** thread control (ptrace), and ones that provide thread awareness (Xen).
 **
 ** The intent is that the target library provides a library above the
 ** dwdebug library, so you should never (or rarely) have to call into
 ** dwdebug to deal with symbol information.  The reason for this
 ** attempted restriction is as follows.  First, an in-memory
 ** representation of DWARF debug data that facilitates fast lookups is
 ** big.  So, we want to share it between targets (or between all target
 ** library users) as much as possible (possible when targets use the
 ** same debuginfo, or a subset thereof).  Second, memory locations are,
 ** naturally, virtual addresses in debuginfo.  For the
 ** statically-linked core of an executable, there is no difference
 ** between virtual/physical; the core is mmap'd at the static
 ** addresses.  But shared objects/libs may be mmap'd anywhere in the
 ** address space, so we have to translate.  Rather than smacking the
 ** details of physical translation into the debuginfo data structures,
 ** for each target instance, we build this translation into the target
 ** library.  This is perhaps annoying, but facilitates better sharing.
 **
 ** The target library is described via the API functions listed below.
 ** To build a new target backend, you must implement the target_ops
 ** operations; see the documentation for `struct target_ops` below.
 **
 ** For information on how to probe a target, see probe_api.h .
 **/

/*
 * The thread identifier type (tid_t) is declared in include/common.h .
 */

/*
 * Each target must support operations on the "global" thread.  The
 * intent is that library users can use TID_GLOBAL to probe and access
 * per-thread state, without having to deal with each thread
 * individually.  How this is actually implemented *is* target
 * backend-specific.
 *
 * In the Xen target, TID_GLOBAL will allow you to access the hardware
 * state for the current executing thread (or interrupt context, if not
 * in process context).  This means that if you ask for a hardware
 * probepoint, you'll set a debug register in the current thread.  In
 * the Linux kernel guest, this means that as long as no other thread in
 * the guest is using debug registers, that setting will be truly global
 * -- any running thread could be stopped with a debug exception at that
 * probepoint.  If you mix TID_GLOBAL and per-tid hardware probepoints,
 * however, your global probepoints will likely be stomped.  So, don't
 * do that.  (Actually, right now, the Xen target does not support
 * per-thread hardware breakpoints anyway -- but the behavior will be as
 * described in the previous sentence once it does.)
 *
 * In the Linux ptrace target, TID_GLOBAL gets you access only to the
 * primary thread of a process.  We probaby should, in the future, make
 * global truly global, in that if you ask for a hardware probepoint
 * with TID_GLOBAL, that all threads add a per-thread hardware
 * probepoint.  But not yet.
 */
#define TID_GLOBAL INT32_MAX

struct target;
struct target_thread;
struct target_ops;
struct target_spec;
struct target_memmod;
struct addrspace;
struct memregion;
struct memrange;

/*
 * These are flags; we need to create masks of them sometimes.
 */
typedef enum {
    TARGET_TYPE_NONE   = 0,
    TARGET_TYPE_PTRACE = 1 << 0,
    TARGET_TYPE_XEN    = 1 << 1,
    TARGET_TYPE_XEN_PROCESS = 1 << 2,
} target_type_t;
#define TARGET_TYPE_BITS 3

typedef enum {
    TARGET_MODE_NONE = 0,
    TARGET_MODE_LIVE = 1,
    TARGET_MODE_RECORD = 2,
    TARGET_MODE_REPLAY = 3,
} target_mode_t;

/*
 * NB: make sure these align with THREAD_STATUS_* and ASTATUS_* !
 */
typedef enum {
    TSTATUS_UNKNOWN        = 0,
    /*
     * The normal state of affairs; it can be returned regardless of if
     * target_is_open() or not.
     */
    TSTATUS_RUNNING        = 1,
    /*
     * A target can only be paused if target_is_open() is true.
     */
    TSTATUS_PAUSED         = 2,
    /*
     * A severe error has occured; user should cleanup.  There are
     * exactly zero guarantees about the target's status at this point.
     * The only guarantee is that the target libraries should not crash,
     * no matter what the user tries to do to cleanup -- removing
     * probes, freeing probes, closing the target, freeing the target.
     */
    TSTATUS_ERROR          = 3,
    /*
     * The target has either exited, or we have detached from it.
     */
    TSTATUS_DONE           = 4,
    /*
     * This is a temporary state to be returned when the target library
     * knows the target will exit, but is still live enough to examine
     * its runtime state, remove probes, etc.  Not all backends may
     * provide this state.
     *
     * It implies TSTATUS_PAUSED.
     *
     * If it is uncaught, that is ok; the user can just catch
     * TSTATUS_DONE.
     */
    TSTATUS_EXITING        = 5,

    /*
     * These states can only be returned when target_is_open() is
     * false.  DEAD corresponds to a zombie target; STOPPED corresponds
     * to a target that is SIGSTOP'd, or the backend equivalent to
     * that.
     */
    TSTATUS_DEAD           = 16,
    TSTATUS_STOPPED,
} target_status_t;

#define TSTATUS_MAX TSTATUS_STOPPED

extern char *TSTATUS_STRINGS[];
#define TSTATUS(n) (((n) <= TSTATUS_MAX) ? TSTATUS_STRINGS[(n)] : NULL)

typedef enum {
    /*
     * The first few status bits are deliberately the same as the target
     * status bits.
     */
    THREAD_STATUS_UNKNOWN  = 0,
    THREAD_STATUS_RUNNING  = 1,
    THREAD_STATUS_PAUSED   = 2,
    THREAD_STATUS_ERROR    = 3,
    THREAD_STATUS_DONE     = 4,
    THREAD_STATUS_EXITING  = 5,

    THREAD_STATUS_DEAD     = 16,
    THREAD_STATUS_STOPPED,

    /*
     * These are thread-specific.
     */
    THREAD_STATUS_SLEEPING,
    THREAD_STATUS_ZOMBIE,
    THREAD_STATUS_BLOCKEDIO,
    THREAD_STATUS_PAGING,
    THREAD_STATUS_RETURNING_USER,
    THREAD_STATUS_RETURNING_KERNEL,
} thread_status_t;

#define THREAD_STATUS_MAX THREAD_STATUS_RETURNING_KERNEL

#define THREAD_STATUS_BITS  5

#define THREAD_SPECIFIC_STATUS(status) \
    ((thread_status_t)(status) >= THREAD_STATUS_SLEEPING)

extern char *THREAD_STATUS_STRINGS[];
#define THREAD_STATUS(n) (((n) <= THREAD_STATUS_RETURNING_KERNEL)	\
			  ? THREAD_STATUS_STRINGS[(n)] : NULL)

/*
 * When we handle a breakpoint, we *have* to single step some
 * instruction(s) to get us past the breakpoint (unless it's a hardware
 * BP and there are no actions nor post handlers).  If there are no
 * complex actions that replace the original instruction's effect
 * (obviate), it's the original instruction; otherwise it might have
 * been (part of) a non-boosted complex action running at the
 * probepoint.  BUT, since hardware probepoints are per-thread, we only
 * have to worry about shared software probepoints.  These are embedded
 * in memory shared amidst multiple threads, so before changing memory
 * (i.e., to single step the original instruction, or a complex action),
 * we technically must stop all other threads that share the memory.
 * However, this is expensive, may be undesireable, or may be impossible
 * (i.e., if the target does not support thread control, but only
 * supports thread observation/detection).
 *
 * So we support different modes for handling shared probepoints.  In
 * THREAD_BPMODE_STRICT, we *require* that the target pause all other
 * threads before handling a probepoint at all.  The handling thread
 * blocks all other threads until handling is done.
 *
 * In THREAD_BPMODE_SEMI_STRICT, we allow a probepoint to change memory
 * and single step one instruction, and immediately change memory back.
 * This means we assume/trust that there won't be a thread collision at
 * the probepoint where thread A hits the probepoint, changes mem, and
 * invokes a single step -- but is interrupted before it executes that,
 * and thread B hits the probepoint (but it won't actually hit it; it
 * would hit wahtever we put in place of the breakpoint -- either the
 * orig instruction, or a complex action (the former would be a missed
 * breakpoint hit; the latter could completely screw up thread B)).
 * There are other cases.  But we assume in this mode that the memory
 * change/single step of a single instruction is "atomic".  This is the
 * only way the Xen VM target can work right now (we could disable
 * interrupts, kind of, but we can't disable NMIs... so we would have to
 * override at least the NMI handler... and we have to deal with things
 * like page faults sanely -- it's perfectly legit for a breakpointed
 * instruction to page fault).
 *
 * Finally, in THREAD_BPMODE_LOOSE, we allow anything to happen at the
 * probepoint without requiring that threads be paused; the handling
 * process is free to allow as many memory changes and single steps as
 * it likes.  This mode is dangerous!!!
 *
 * We permit multiple instructions to be inserted here, but this is
 * dangerous.  For a multithreaded target, we're already at risk as
 * soon as we hit the breakpoint and change it into another real
 * instruction, because another thread could hit the changed real
 * instruction if the first thread is interrupted before it can
 * single step.  So technically, in BPMODE_STRICT, we have to pause
 * all other threads before changing the breakpoint at all.  But,
 * some targets can't really do this (or can't do it well, or it's
 * hard -- for instnace, for a Xen VM with a Linux guest, we can
 * disable interrupts while we handle, but even that doesn't disable
 * NMIs, so we would have to override the guest's NMI handler... and
 * what exactly we would do in the override code is questionable
 * anyway!).  So we invent another mode, BPMODE_SEMI_STRICT that
 * says if we have only a single real instruction to single step, we
 * "trust" that it won't be interrupted; in this mode, if there are
 * multiple instructions to step, we try to pause all other threads
 * before handling the breakpoint.  Finally, in BPMODE_LOOSE, we
 * allow endless single steps at the breakpoint without attempting
 * to pause threads.
 */
typedef enum {
    THREAD_BPMODE_STRICT = 0,
    THREAD_BPMODE_SEMI_STRICT = 1,
    THREAD_BPMODE_LOOSE = 2,
} thread_bpmode_t;

typedef enum {
    POLL_NOTHING          = 0,
    POLL_ERROR            = 1,
    POLL_SUCCESS          = 2,
    POLL_UNKNOWN          = 3,
    __POLL_MAX,
} target_poll_outcome_t;

extern char *POLL_STRINGS[];
#define POLL(n) (((n) < sizeof(POLL_STRINGS)/sizeof(char *)) \
		 ? POLL_STRINGS[(n)] : NULL)

typedef enum {
    LOAD_FLAG_NONE = 0,
    LOAD_FLAG_SHOULD_MMAP = 1,
    LOAD_FLAG_MUST_MMAP = 2,
    LOAD_FLAG_NO_CHECK_BOUNDS = 4,
    LOAD_FLAG_NO_CHECK_VISIBILITY = 8,
    LOAD_FLAG_AUTO_DEREF = 16,
    LOAD_FLAG_AUTO_DEREF_RECURSE = 32,
    LOAD_FLAG_AUTO_STRING = 64,
    LOAD_FLAG_NO_AUTO_RESOLVE = 128,
    LOAD_FLAG_VALUE_FORCE_COPY = 256,
} load_flags_t;

typedef enum {
    ACTIVE_PROBE_FLAG_NONE          = 0,
    ACTIVE_PROBE_FLAG_THREAD_ENTRY  = 1 << 0,
    ACTIVE_PROBE_FLAG_THREAD_EXIT   = 1 << 1,
    ACTIVE_PROBE_FLAG_MEMORY        = 1 << 2,
    ACTIVE_PROBE_FLAG_OTHER         = 1 << 3,
} active_probe_flags_t;
#define ACTIVE_PROBE_BITS 4

/**
 ** These functions form the target API.
 **/

/*
 * Returns a target specification by parsing command line arguments.
 * Assumes that the caller is also a driver program that requires its
 * own arguments.  Caller must fully specify @program_parser (we fill it
 * with child argp parsers).  Caller must specify at least one target
 * type in @target_types.
 */
struct target_spec *target_argp_driver_parse(struct argp *driver_parser,
					     void *driver_state,
					     int argc,char **argv,
					     target_type_t target_types,
					     int filter_quoted);

struct target_spec *target_argp_target_spec(struct argp_state *state);

void *target_argp_driver_state(struct argp_state *state);

void target_driver_argp_init_children(struct argp_state *state);

int target_spec_to_argv(struct target_spec *spec,char *arg0,
			int *argc,char ***argv);

/*
 * Generic function that creates a target, given @spec.
 */
struct target *target_instantiate(struct target_spec *spec,
				  struct evloop *evloop);

struct target_spec *target_build_spec(target_type_t type,target_mode_t mode);
void target_free_spec(struct target_spec *spec);

target_type_t target_type(struct target *target);

/*
 * Get the name of a target.  The name will be initially filled in after
 * target_ops->init is called (by target_open).
 */
char *target_name(struct target *target);

/*
 * Simple accessor to get the target's ID.
 */
int target_id(struct target *target);

/*
 * Opens a target.  If returns 0, the target is paused and ready for API
 * calls.  If it returns nonzero, it failed.
 *
 * (Internally, it calls the following target_ops: init(), loadspaces(),
 * loadregions(space), loaddebugfiles(space,region), postloadinit(),
 * attach().)
 */
int target_open(struct target *target);

/*
 * Returns a pointer to a string representation of the given target.  If
 * @buf is non-NULL, the representation is written to buf (for @bufsiz
 * characters, not including a trailing NULL character).
 */
char *target_tostring(struct target *target,char *buf,int bufsiz);

/*
 * Populates an evloop with any select()able file descriptors that this
 * target needs monitored, and with their evloop callback functions.
 * This way, the user can use a single evloop to handle multiple
 * different kinds of blocking waiting, as well as multiple targets,
 * instead of directly poll()ing or monitor()ing a single target.
 *
 * If a file descriptor closes or exhibits error conditions, the
 * target's evloop callback function *must* remove the descriptor from
 * the @evloop -- there is no mechanism for the evloop to clean up
 * garbage.
 */
int target_attach_evloop(struct target *target,struct evloop *evloop);

/*
 * Removes the selectable file descriptors for @target from @target->evloop.
 */
int target_detach_evloop(struct target *target);

/*
 * Returns 1 if @evloop is already attached to @target; 0 if not.
 */
int target_is_evloop_attached(struct target *target,struct evloop *evloop);

/*
 * Enables/disables active probing techniques based on bits set in
 * @flags.
 *
 * NB: sometimes it may not be possible to enable certain bits (backend
 * may not support it); or disable certain bits (backend may require
 * them, or an overlay target requires them).  No good way to help the
 * user navigate this for now; it's basically best-effort; and if you
 * use an overlay target, the overlay target's requirements for active
 * probing *will* override yours.
 */
int target_set_active_probing(struct target *target,active_probe_flags_t flags);

/*
 *
 * If @evloop is specified, the target *must* add a select()able fd,
 * handler, and state to @evloop.  @evloop must be specified if the user
 * is going to use evloop_* instead of target_monitor or target_poll to
 * wait on one or more targets from a single
 */

/*
 * Monitors (blocking) a target for debug/exception events, tries to handle any
 * probes attached to the target, and only returns if it can't handle
 * some condition that arises, or if an error occurs while handling an
 * expected debug exception (probably a bug).
 */
target_status_t target_monitor(struct target *target);

/*
 * Polls a target for debug/exception events, and *will* try to handle
 * any probes if it gets an event.  It saves the outcome in @outcome if
 * you provide a non-NULL value.  @pstatus is mostly a legacy of the
 * linux userspace target; in any case, its value is target-specific,
 * and the target backend may populate it however it wishes.  Finally,
 * like target_monitor, target_poll will return control to the user for
 * any exceptions it encounters that it can't handle.
 *
 * You must always call target_resume() following a poll, if you choose
 * to continue.
 *
 * NOTE: @tv may be modified during the poll, as described in the
 * select(2) manual page.  This gives you a hint of how long the poll
 * had to wait.
 *
 * ALSO NOTE: the behavior of @tv is different that described in
 * select(2).  If you pass NULL, we auto-fill a struct timeval with 0s,
 * meaning that select and thus target_poll() will return immediately if
 * nothing is pending; select blocks if you pass NULL.  We don't need
 * that behavior, since target_monitor() sort of provides it.
 */
target_status_t target_poll(struct target *target,struct timeval *tv,
			    target_poll_outcome_t *outcome,int *pstatus);

/*
 * Resumes a target from a user-visible pause.  This will resume all of
 * the resumable threads, and guarantees that the user can call
 * target_poll or target_monitor again.  If the user does not call
 * target_resume before invoking those functions, the target may not be
 * running.
 */
int target_resume(struct target *target);

/*
 * Pauses a target.  This completely pauses a target, and all its
 * threads.
 */
int target_pause(struct target *target);

/*
 * Returns 1 if the target is open; 0 otherwise.  Most target
 * operations only make sense if the target is open (i.e., reading
 * mem, reading CPU state, pausing/resuming/monitoring/probing, etc).
 */
int target_is_open(struct target *target);

/*
 * Returns the target's status.
 */
target_status_t target_status(struct target *target);

/*
 * Closes a target and releases all its resources.
 *
 * (Internally, this calls the following target_ops: detach(), kill() (if
 * target->kill_on_close is set).)
 */
int target_close(struct target *target);

/*
 * Destroys a target.
 */
int target_kill(struct target *target,int sig);

/*
 * Frees a target.
 */
void target_free(struct target *target);

/*
 * Overlay support.
 */
struct array_list *target_list_available_overlay_tids(struct target *target,
						      target_type_t type);
struct array_list *target_list_overlays(struct target *target);
tid_t target_lookup_overlay_thread_by_id(struct target *target,int id);
tid_t target_lookup_overlay_thread_by_name(struct target *target,char *name);
struct target *target_instantiate_overlay(struct target *target,tid_t tid,
					  struct target_spec *spec);
target_status_t target_notify_overlay(struct target *overlay,tid_t tid,ADDR ipval,
				      int *again);

/*
 * Returns the probe attached to this target with ID @probe_id, if any.
 */
struct probe *target_lookup_probe(struct target *target,int probe_id);

/*
 * Returns the action attached to this target with ID @probe_id, if any.
 */
struct action *target_lookup_action(struct target *target,int action_id);

/*
 * Reads a block of memory from the target.  If @buf is non-NULL, we
 * assume it is at least @length bytes long; the result is placed into
 * @buf and @buf is returned.  If @buf is NULL, we allocate a buffer
 * large enough to hold the result (@length if @length >0; if @length is
 * 0 we attempt to read a string at that address; we stop when we hit a
 * NULL byte).
 *
 * On error, returns NULL, and sets errno.
 */
unsigned char *target_read_addr(struct target *target,ADDR addr,
				unsigned long length,unsigned char *buf);

/*
 * Writes @length bytes from @buf to @addr.  Returns the number of bytes
 * written (and sets errno nonzero if there is an error).  Successful if
 * @return == @length.
 */
unsigned long target_write_addr(struct target *target,ADDR addr,
				unsigned long length,unsigned char *buf);

int target_addr_v2p(struct target *target,tid_t tid,ADDR vaddr,ADDR *paddr);
unsigned char *target_read_physaddr(struct target *target,ADDR paddr,
				    unsigned long length,unsigned char *buf);
unsigned long target_write_physaddr(struct target *target,ADDR paddr,
				    unsigned long length,unsigned char *buf);

/*
 * Returns a string representation for the DWARF register number on this
 * particular target type.  Will (likely) differ between targets/archs.
 */
char *target_reg_name(struct target *target,REG reg);

/*
 * Returns the target-specific DWARF register number for the
 * target-specific register name @name.
 */
REG target_dw_reg_no_targetname(struct target *target,char *name);

/*
 * Returns the target-specific DWARF register number for the common
 * register @reg.
 */
REG target_dw_reg_no(struct target *target,common_reg_t reg);

/*
 * Reads the DWARF register @reg from thread @tid in @target.  Returns 0
 * and sets errno nonzero on error.
 */
REGVAL target_read_reg(struct target *target,tid_t tid,REG reg);

/*
 * Writes @value to the DWARF register @reg.  Returns 0 on success;
 * nonzero on failure.
 */
int target_write_reg(struct target *target,tid_t tid,REG reg,REGVAL value);

/*
 * Reads the common register @reg in thread @tid in target @target.
 * Returns 0 and sets errno on failure.
 */
REGVAL target_read_creg(struct target *target,tid_t tid,common_reg_t reg);

/*
 * Writes @value to the common register @reg.  Returns 0 on success;
 * nonzero on failure.
 */
int target_write_creg(struct target *target,tid_t tid,common_reg_t reg,
		      REGVAL value);

/*
 * @return a copy of current values of @target/@tid's registers.
 *
 * Keys are strings corresponding to the target's register names; values
 * are REGVAL *'s.
 */
GHashTable *target_copy_registers(struct target *target,tid_t tid);

/*
 * Returns the currently executing thread's TID.  Only valid when the
 * target's current thread is paused; returns 0 and sets errno EBUSY if
 * that is not true.
 */
tid_t target_gettid(struct target *target);

/*
 * @return: an array_list of TIDs that are in our cache.  In this case,
 * use (tid_t)array_list_item(list,i) to get the value.
 */
struct array_list *target_list_tids(struct target *target);

/*
 * @return: an array_list of target_thread structs that are in our
 * cache.
 */
struct array_list *target_list_threads(struct target *target);

/*
 * @return: a GHashTable of TIDs->threads that are in our cache.  The
 * hashtable keys are tid_t types, not ptr_t types!
 *
 * You might wonder why you need to call this; after all,
 * target->threads is a perfectly good hashtable.  But, if you ever need
 * to loop over the keys in the hash and maybe delete a thread, you need
 * to be really careful.  This eliminates the need for such caution by
 * basically duplicating the hashtable.
 */
GHashTable *target_hash_threads(struct target *target);

/*
 * @return: an array_list of TIDs that are part of the target, whether
 * they are loaded or not.
 */
struct array_list *target_list_available_tids(struct target *target);

/*
 * @return: a GHashTable of TIDs that are part of the target, whether
 * they are loaded or not.  Just a map of tid_t to tid_t .
 */
GHashTable *target_hash_available_tids(struct target *target);

/*
 * Load the currently executing thread (may also load the "global"
 * thread, depending on the target backend).
 */
struct target_thread *target_load_current_thread(struct target *target,
						 int force);

/*
 * Load a specific thread's context from the target.  If the thread does
 * not exist in the target, we return NULL.  If it exists in our cache
 * and is valid, we do not re-read its state unless @force is nonzero.
 */
struct target_thread *target_load_thread(struct target *target,tid_t tid,
					 int force);
/*
 * (Re)load all our cached threads' contexts.  Only invalid threads are
 * loaded unless @force is set nonzero.  This function does not attempt
 * to discover other threads in the target that are unknown; it only
 * tries to reload those it has been told about.
 */
int target_load_all_threads(struct target *target,int force);

/*
 * Loads all threads that are part of the target.  May evict cached
 * threads that no longer exist or whose tids have been reused for other
 * threads.  Only reloads invalid threads if @force is nonzero.
 */
int target_load_available_threads(struct target *target,int force);

/*
 * Pauses a thread (if the target supports thread control).  If @nowait
 * is set, it will not wait for the pause signal to hit the thread.
 *
 * XXX: at this point, @nowait is not supported!
 */
int target_pause_thread(struct target *target,tid_t tid,int nowait);

/*
 * Flush the currently executing thread's context.  Context is only
 * written if it is dirty.
 */
int target_flush_current_thread(struct target *target);

/*
 * Flush a specific thread's context back to the target.  Context is
 * only written if it is dirty.
 */
int target_flush_thread(struct target *target,tid_t tid);
/*
 * Flush all our cached threads' contexts back to target.
 */
int target_flush_all_threads(struct target *target);

/*
 * Garbage collects cached threads.  If !target->ops->gc_threads, it
 * grabs the list of available thread ids, and compares those to the
 * current cache, evicting any stale members of the cache and destroying
 * those threads.
 *
 * @return the number of threads evicted/destroyed, or < 0 on error.
 */
int target_gc_threads(struct target *target);

char *target_thread_tostring(struct target *target,tid_t tid,int detail,
			     char *buf,int bufsiz);
void target_dump_thread(struct target *target,tid_t tid,FILE *stream,int detail);
void target_dump_all_threads(struct target *target,FILE *stream,int detail);

struct target_memmod *target_insert_sw_breakpoint(struct target *target,tid_t tid,
						  ADDR addr);
int target_remove_sw_breakpoint(struct target *target,tid_t tid,
				struct target_memmod *mmod);
int target_enable_sw_breakpoint(struct target *target,tid_t tid,
				struct target_memmod *mmod);
int target_disable_sw_breakpoint(struct target *target,tid_t tid,
				 struct target_memmod *mmod);
int target_change_sw_breakpoint(struct target *target,tid_t tid,
				struct target_memmod *mmod,
				unsigned char *code,unsigned long code_len);

REG target_get_unused_debug_reg(struct target *target,tid_t tid);
int target_set_hw_breakpoint(struct target *target,tid_t tid,REG reg,ADDR addr);
int target_set_hw_watchpoint(struct target *target,tid_t tid,REG reg,ADDR addr,
			     probepoint_whence_t whence,int watchsize);
int target_unset_hw_breakpoint(struct target *target,tid_t tid,REG reg);
int target_unset_hw_watchpoint(struct target *target,tid_t tid,REG reg);

int target_disable_hw_breakpoints(struct target *target,tid_t tid);
int target_enable_hw_breakpoints(struct target *target,tid_t tid);

int target_disable_hw_breakpoint(struct target *target,tid_t tid,REG dreg);
int target_enable_hw_breakpoint(struct target *target,tid_t tid,REG dreg);

int target_notify_sw_breakpoint(struct target *target,ADDR addr,
				int notification);
int target_singlestep(struct target *target,tid_t tid,int isbp);
int target_singlestep_end(struct target *target,tid_t tid);

uint64_t target_get_tsc(struct target *target);
uint64_t target_get_time(struct target *target);
uint64_t target_get_counter(struct target *target);

/*
 * Feature functions.  Enable/disable a specific feature on a target.
 * Feature flags are target-specific.
 */
int target_enable_feature(struct target *target,int feature,void *arg);
int target_disable_feature(struct target *target,int feature);

/*
 * @return: nonzero if the target thread is valid (loaded).
 */
int target_thread_is_valid(struct target *target,tid_t tid);

/*
 * @return: nonzero if the target thread is dirty (context has been modified).
 */
int target_thread_is_dirty(struct target *target,tid_t tid);

/*
 * @return: the thread's status if it exists in our cache, or
 * THREAD_STATUS_UNKNOWN if the thread does not exist or if the status
 * is actually unknown.
 */
thread_status_t target_thread_status(struct target *target,tid_t tid);


/**
 ** Functions to deal with "widest range" lookup, text code loading and
 ** caching, and safe disassembly.  We want to be sure we always start
 ** disassembly at a safe place in the text bytes we load -- not
 ** wherever the library use requests (which might be in some weird
 ** place).  Plus, we want to cache well-defined chunks of code to avoid
 ** fragmentation in the cache.
 **/
int target_lookup_safe_disasm_range(struct target *target,ADDR addr,
				    ADDR *start,ADDR *end,void **data);
int target_lookup_next_safe_disasm_range(struct target *target,ADDR addr,
					 ADDR *start,ADDR *end,void **data);
unsigned char *target_load_code(struct target *target,
				ADDR start,unsigned int len,
				int nocache,int force_copy,int *caller_free);

/**
 ** Lookup functions.
 **/
/*
 * Find the symbol table corresponding to the supplied PC.
 */
struct symtab *target_lookup_pc(struct target *target,uint64_t pc);

/*
 * Looks up a symbol, or hierarchy of nested symbols.  Users shouldn't
 * need to know the details of the bsymbol struct; it largely functions
 * as a placeholder that saves the result of a nested lookup so that it
 * is available for a later load.  The single symbol, or deepest-nested
 * symbol, is in .symbol.  The chain of nested symbols (possibly
 * including anonymous symbols), which includes the deepest-nested
 * symbol itself, is in .chain.
 *
 * The bsymbol struct should be passed to _load functions, where it may
 * be further annotated with load information.
 *
 * Each symbol chain member is either a SYMBOL_TYPE_VAR or a
 * SYMBOL_TYPE_FUNCTION -- unless the first member in your @name string
 * resolves to a SYMBOL_TYPE_TYPE.  In this case, the first member will
 * be a SYMBOL_TYPE_TYPE!
 *
 * This function takes a ref to its return value on the user's behalf;
 * call bsymbol_release() to release (and maybe free) it.
 */

struct bsymbol *target_lookup_sym(struct target *target,
				  const char *name,const char *delim,
				  char *srcfile,symbol_type_flag_t ftype);
struct bsymbol *target_lookup_sym_member(struct target *target,
					 struct bsymbol *bsymbol,
					 const char *name,const char *delim);

struct bsymbol *target_lookup_sym_addr(struct target *target,ADDR addr);

struct bsymbol *target_lookup_sym_line(struct target *target,
				       char *filename,int line,
				       SMOFFSET *offset,ADDR *addr);

/**
 ** Address/memory range functions.
 **/
int target_contains_real(struct target *target,ADDR addr);
int target_find_memory_real(struct target *target,ADDR addr,
			    struct addrspace **space_saveptr,
			    struct memregion **region_saveptr,
			    struct memrange **range_saveptr);

int target_resolve_symbol_base(struct target *target,tid_t tid,
			       struct bsymbol *bsymbol,ADDR *addr_saveptr,
			       struct memrange **range_saveptr);
/**
 ** Load functions.  Everything that gets loaded is loaded as a value
 ** struct.
 **
 ** Each load function can handle a bsymbol that contains a nested
 ** symbol chain.  Members may nest in either 1) functions, or 2)
 ** struct/unions.  Obviously, once you are in a struct/union, the only
 ** members of those can be variables.  Thus, all functions must come
 ** first in the chain.  So, here are some examples of nested symbols
 ** that can be followed by these functions:
 **   function.subfunc.param1, function.local, function.localstructinst.x,
 **   structinst.x.y.z, structinst->x.y.z, structinst->x->y->z
 ** Now, since we support automatic pointer
 ** dereferencing, you don't have to worry about actually using -> or .;
 ** you just use . .  If the final symbol is itself a pointer to
 ** something, if the AUTO_DEREF or AUTO_STRING load flags are set, the
 ** pointer will be dereferenced as much as possible before loading.
 ** Otherwise, it won't be.  The AUTO_DEREF flags do not affect the
 ** behavior of intermediate pointer symbols in the chain; those are
 ** always autoloaded if possible.  If you don't like this intermediate
 ** pointer autoloading behavior, don't use it!
 **/
ADDR target_addressof_symbol(struct target *target,tid_t tid,
			      struct bsymbol *bsymbol,load_flags_t flags,
			      struct memrange **range_saveptr);
OFFSET target_offsetof_symbol(struct target *target,struct bsymbol *bsymbol,
			      char *member,const char *delim);
struct value *target_load_symbol(struct target *target,tid_t tid,
				 struct bsymbol *bsymbol,load_flags_t flags);
/*
 * You can ask for *any* nesting of variables, given some bound symbol.
 * If @bsymbol is a function, you can ask for its args or locals.  If
 * the locals or args are structs, you can directly ask for members --
 * but make sure that if you want pointers followed, you set the
 * LOAD_FLAG_AUTO_DEREF flag; otherwise a nested load across a pointer
 * (i.e., if the current member we're working on is a pointer, and you
 * have specified another nested member within that thing, we won't be
 * able to follow the pointer, and hence will fail to find the next
 * member) will fail.  If @bsymbol is a struct/union var, you can of
 * course ask for any of its (nested) members.
 *
 * Your top-level @bsymbol must be either a function or a struct/union
 * var; nothing else makes sense as far as loading memory.
 */
struct value *target_load_symbol_member(struct target *target,tid_t tid,
					struct bsymbol *bsymbol,
					const char *member,const char *delim,
					load_flags_t flags);
struct value *target_load_value_member(struct target *target,
				       struct value *old_value,
				       const char *member,const char *delim,
				       load_flags_t flags);
/*
 * This function creates a value by loading the number of bytes
 * specified by @type from a real @addr.
 */
struct value *target_load_type(struct target *target,struct symbol *type,
			       ADDR addr,load_flags_t flags);
/*
 * Load a raw value (i.e., no symbol or type info) using an object
 * file-based location (i.e., a fixed object-relative address) and a
 * specific region.
 *
 * Note: you cannot mmap raw values; they must be copied from target memory.
 */
struct value *target_load_addr_obj(struct target *target,struct memregion *region,
				   ADDR obj_addr,load_flags_t flags,int len);
/*
 * Load a raw value (i.e., no symbol or type info) using a real address.
 *
 * Note: you cannot mmap raw values; they must be copied from target memory.
 */
struct value *target_load_addr_real(struct target *target,ADDR addr,
				    load_flags_t flags,int len);

/*
 * Starting at @addr, which is of type @datatype, load as many pointers
 * as specified by our @flags (if @flags does not have
 * LOAD_FLAG_AUTO_DEREF or LOAD_FLAG_AUTO_STRING set, or @datatype is
 * not a pointer type symbol, this function will immediately return, and
 * will return @addr without setting @datatype_saveptr and
 * @range_saveptr).
 *
 * This function will keep loading pointers as long as @datatype and its
 * pointed-to type (recursively) are pointers.  Once @datatype is no
 * longer a pointer, we stop, return the last pointer value, save the
 * non-pointer type in @datatype_saveptr, and save the memrange
 * containing the last pointer in @range_saveptr.
 * 
 * You can set @datatype_saveptr and/or @range_saveptr to NULL safely.
 *
 * If an error occurs (i.e., attempt to deref a NULL pointer), we return
 * 0 and set errno appropriately.
 */
ADDR target_autoload_pointers(struct target *target,struct symbol *datatype,
			      ADDR addr,load_flags_t flags,
			      struct symbol **datatype_saveptr,
			      struct memrange **range_saveptr);
/* 
 * Load @count void pointers.  Save off the range containing the final
 * pointer (not the final pointed-to value!) in @range_saveptr if
 * supplied.  If an intermediate pointer is NULL, we set errno to EFAULT
 * and return 0.
 */
ADDR target_load_pointers(struct target *target,ADDR addr,int count,
			  struct memrange **range_saveptr);

/*
 * bsymbol_load is deprecated -- use target_load_*() instead!
 */
#if 0
/*
 * Load a symbol's value, but just return a raw pointer.  If flags
 * contains LOAD_FLAGS_MMAP, we try to mmap the target's memory instead
 * of reading and copying the data; if that fails, we return NULL.  If
 * buf is not NULL, it should be sized to
 * symbol->datatype->s.ti.byte_size (best available as symbol_get
 */
struct value *bsymbol_load(struct bsymbol *bsymbol,load_flags_t flags);
#endif

/**
 ** Symbol functions.
 **/
/*
 * If you have the type of symbol you're interested in, but you need to
 * load a pointer to a chunk of memory of that type, you can create a
 * synthetic type symbol that points to your "base" type.
 *
 * Synthetic symbols are the only kind of symbols that hold refs to other
 * symbols (in this case, the return value holds a ref to @type).  This
 * function also holds a ref to the symbol it returns, since it is
 * anticipated that only users will call this function.
 */
struct symbol *target_create_synthetic_type_pointer(struct target *target,
						  struct symbol *type);

typedef result_t (*target_debug_bp_handler_t)(struct target *target,
					      struct target_thread *tthread,
					      struct probepoint *probepoint,
					      int was_stepping);
typedef result_t (*target_debug_handler_t)(struct target *target,
					   struct target_thread *tthread,
					   struct probepoint *probepoint);

/**
 ** Bound symbol interface functions -- user should not need any more
 ** knowledge of bsymbols other than these few functions.
 **/
char *bsymbol_get_name(struct bsymbol *bsymbol);
struct symbol *bsymbol_get_symbol(struct bsymbol *bsymbol);
struct lsymbol *bsymbol_get_lsymbol(struct bsymbol *bsymbol);
int bsymbol_is_inline(struct bsymbol *bsymbol);
/*
 * Creates a bsymbol that basically is the deepest non-inline instance
 * part of @bsymbol.
 *
 * This function does not take a reference to the returned bsymbol;
 * (call bsymbol_hold() to get that ref if you need it; otherwise free
 * it as soon as you are done with it and don't pass it to anyone).
 */
struct bsymbol *bsymbol_create_noninline(struct bsymbol *bsymbol);
void bsymbol_dump(struct bsymbol *bsymbol,struct dump_info *ud);
/*
 * Takes a reference to the bsymbol.  Users should not call this; target
 * lookup functions will do this for you.
 */
void bsymbol_hold(struct bsymbol *bsymbol);
/*
 * Releases a reference to the bsymbol and tries to free it.
 */
REFCNT bsymbol_release(struct bsymbol *bsymbol);

/**
 ** Value functions.
 **/
/*
 * Creates a fully independent value with a copy of whatever was in
 * @in's value buffer; also holds refs to in->type and in->lsymbol if
 * they exist -- so you must free it with value_free like normal.
 *
 * Note that if you clone a value that is sharing a parent value's
 * buffer space, the clone does not maintain this relationship; clones
 * always have their own private buffer.
 */
struct value *value_clone(struct value *in);
/*
 * Returns the resolved address of the value; if the value is a register
 * value, it returns 0 and sets errno to EINVAL.
 */
ADDR value_addr(struct value *value);
void value_free(struct value *value);
void value_dump(struct value *value,struct dump_info *ud);

/*
 * Refreshes @value if necessary.  If @value is a child of another
 * value, we will try to force a refresh of its parent (and upwards
 * recursively).  Be careful of @recursive -- this might make values
 * change unexpectedly for you!  You must only use value_refresh if you
 * are fine with "live" values.
 */
int value_refresh(struct value *value,int recursive);

typedef enum {
    VALUE_DIFF_SAME = 0,
    VALUE_DIFF_DIFF = 1,
    VALUE_DIFF_MAYBE = 2,
    VALUE_DIFF_UNKNOWN = 3,
} value_diff_t;

typedef uintptr_t value_hash_t;

/*
 * Reloads the content of @value and recomputes its new hash, setting
 * @vdiff accordingly if supplied.  If @vdiff is VALUE_DIFF_DIFF, and if
 * @old_* are supplied, they are set to the old values, if any.
 * @old_buf and @old_bufsiz can only be set if the value was not mmap'd
 * (if it was, the value has already changed in the buffer and we don't
 * know what it was; so if this is important, then make sure to load the
 * value with LOAD_FLAG_NO_MMAP).  @old_vhash will always be set if
 * VALUE_DIFF_DIFF.
 *
 * If there was an error loading the value, -1 is returned.  This is the
 * only case an error can (realistically) occur.
 */
int value_refresh_diff(struct value *value,int recurse,value_diff_t *vdiff,
		       char **old_buf,int *old_bufsiz,value_hash_t *old_vhash);

/**
 ** Value macros.
 **/
/*
 * Load a value.  If @invalue is specified, load @varstr as a member.
 * If @invalue is not specified, lookup @varstr on @target as a symbol,
 * and load it!  Load with @loadflags.  If @outvarptr is specified, copy
 * the raw value's bytes into it -- if sizeof(*@outvarptr) < value->buflen 
 * (poor man's C type "equivalence" check).  If @outvalueptr is not
 * NULL, save the loaded struct value into *@outvalueptr and don't free
 * it (otherwise it is freed).

 * (NB: initially we had supported this (If *@outvalueptr == @invalue,
 * value_free(*@outvalueptr) first!), but not now -- it is not good.)
 *
 * This encapsulates the common ways we use VMI to load values, and
 * saves the user a lot of code.
 */
#define VLS(target,varstr,loadflags,outvarptr,outvalueptr,errlabel)	\
    do {								\
	struct value *_outvalue;					\
	void *__outvar = (outvarptr);					\
	struct bsymbol *_varsym;					\
	_varsym = target_lookup_sym((target),(varstr),NULL,NULL,	\
				    SYMBOL_TYPE_NONE);			\
	if (!_varsym) {							\
	    goto errlabel;						\
	}								\
	_outvalue = target_load_symbol((target),TID_GLOBAL,_varsym,	\
				       (loadflags));			\
	bsymbol_release(_varsym);					\
	if (!_outvalue)							\
	    goto errlabel;						\
        if (__outvar) {							\
	    if ((int)sizeof(*(outvarptr)) < _outvalue->bufsiz) {	\
		verror("outvar size %u smaller than outvalue len %d\n", \
		       (unsigned)sizeof(*(outvarptr)),_outvalue->bufsiz); \
		value_free(_outvalue);					\
		goto errlabel;						\
	    }								\
	    memcpy(outvarptr,_outvalue->buf,sizeof(*(outvarptr)));	\
	}								\
	if (outvalueptr) 						\
	    *(struct value **)(outvalueptr) = _outvalue;		\
	else 								\
	    value_free(_outvalue);					\
    } while (0);
#define VL(target,invalue,varstr,loadflags,outvalueptr,errlabel)	\
    do {								\
	struct value *_outvalue;					\
									\
	if ((invalue) != NULL) {					\
	    _outvalue = target_load_value_member((target),(invalue),(varstr), \
						 NULL,(loadflags));	\
	}								\
	else { 								\
	    struct bsymbol *_varsym;					\
	    _varsym = target_lookup_sym((target),(varstr),NULL,NULL,	\
					SYMBOL_TYPE_NONE);		\
	    if (!_varsym) {						\
		goto errlabel;						\
	    }								\
	    _outvalue = target_load_symbol((target),TID_GLOBAL,_varsym, \
					   (loadflags));		\
	    bsymbol_release(_varsym);					\
	}								\
	if (!_outvalue)							\
	    goto errlabel;						\
	if (outvalueptr) {						\
	    if (0 && *(struct value **)(outvalueptr) == invalue) {	\
		value_free(*(struct value **)(outvalueptr));		\
	    }								\
	    *(struct value **)(outvalueptr) = _outvalue;		\
	}								\
	else {								\
	    value_free(_outvalue);					\
	}								\
    } while (0);
#define VLV(target,invalue,varstr,loadflags,outvarptr,outvalueptr,errlabel) \
    do {								\
	struct value *_outvalue;					\
	void *__outvar = (outvarptr);					\
									\
	if ((invalue) != NULL) {					\
	    _outvalue = target_load_value_member((target),(invalue),(varstr), \
						 NULL,(loadflags));	\
	}								\
	else { 								\
	    struct bsymbol *_varsym;					\
	    _varsym = target_lookup_sym((target),(varstr),NULL,NULL,	\
					SYMBOL_TYPE_NONE);		\
	    if (!_varsym) {						\
		goto errlabel;						\
	    }								\
	    _outvalue = target_load_symbol((target),TID_GLOBAL,_varsym, \
					   (loadflags));		\
	    bsymbol_release(_varsym);					\
	}								\
	if (!_outvalue)							\
	    goto errlabel;						\
        if (__outvar) {							\
	    if ((int)sizeof(*(outvarptr)) < _outvalue->bufsiz) {	\
		verror("outvar size %u smaller than outvalue len %d\n", \
		       (unsigned)sizeof(*(outvarptr)),_outvalue->bufsiz); \
		value_free(_outvalue);					\
		goto errlabel;						\
	    }								\
	    memcpy(outvarptr,_outvalue->buf,sizeof(*(outvarptr)));	\
	}								\
	if (outvalueptr) {						\
	    if (0 && *(struct value **)(outvalueptr) == invalue) {	\
		value_free(*(struct value **)(outvalueptr));		\
	    }								\
	    *(struct value **)(outvalueptr) = _outvalue;		\
	}								\
	else {								\
	    value_free(_outvalue);					\
	}								\
    } while (0);
#define VLA(target,addr,loadflags,outbufptr,outbuflen,outvalueptr,errlabel) \
    do {								\
	struct value *_outvalue;					\
									\
	_outvalue = target_load_addr_real((target),(addr),(loadflags),	\
					  outbuflen);			\
	if (!_outvalue)							\
	    goto errlabel;						\
	if (!*outbufptr) {						\
	    *outbufptr = malloc(outbuflen);				\
	}								\
	memcpy(*outbufptr,_outvalue->buf,outbuflen);			\
	if (outvalueptr) {						\
	    *(struct value **)(outvalueptr) = _outvalue;		\
	}								\
	else {								\
	    value_free(_outvalue);					\
	}								\
    } while (0);

/**
 ** Quick value converters
 **/
signed char      v_c(struct value *v);
unsigned char    v_uc(struct value *v);
wchar_t          v_wc(struct value *v);
uint8_t          v_u8(struct value *v);
uint16_t         v_u16(struct value *v);
uint32_t         v_u32(struct value *v);
uint64_t         v_u64(struct value *v);
int8_t           v_i8(struct value *v);
int16_t          v_i16(struct value *v);
int32_t          v_i32(struct value *v);
int64_t          v_i64(struct value *v);
num_t            v_num(struct value *v);
unum_t           v_unum(struct value *v);
float            v_f(struct value *v);
double           v_d(struct value *v);
long double      v_dd(struct value *v);
ADDR             v_addr(struct value *v);
char *           v_string(struct value *v);

/**
 ** Value update functions.
 **/
int value_update(struct value *value,const char *buf,int bufsiz);
int value_update_zero(struct value *value,const char *buf,int bufsiz);
int value_update_c(struct value *value,signed char v);
int value_update_uc(struct value *value,unsigned char v);
int value_update_wc(struct value *value,wchar_t v);
int value_update_u8(struct value *value,uint8_t v);
int value_update_u16(struct value *value,uint16_t v);
int value_update_u32(struct value *value,uint32_t v);
int value_update_u64(struct value *value,uint64_t v);
int value_update_i8(struct value *value,int8_t v);
int value_update_i16(struct value *value,int16_t v);
int value_update_i32(struct value *value,int32_t v);
int value_update_i64(struct value *value,int64_t v);
int value_update_f(struct value *value,float v);
int value_update_d(struct value *value,double v);
int value_update_dd(struct value *value,long double v);
int value_update_addr(struct value *value,ADDR v);
int value_update_num(struct value *value,num_t v);
int value_update_unum(struct value *value,unum_t v);

/**
 ** The single value store function.
 **/
int target_store_value(struct target *target,struct value *value);

#define value_to_u64(v) (*((uint64_t *)(v)->buf))
#define value_to_u32(v) (*((uint32_t *)(v)->buf))
#define value_to_u16(v) (*((uint16_t *)(v)->buf))
#define value_to_u8(v) (*((uint8_t *)(v)->buf))

#define value_to_i64(v) (*((int64_t *)(v)->buf))
#define value_to_i32(v) (*((int32_t *)(v)->buf))
#define value_to_i16(v) (*((int16_t *)(v)->buf))
#define value_to_i8(v) (*((int8_t *)(v)->buf))

#if __WORDSIZE == 64
#define value_to_unsigned_long value_to_u64
#define value_to_long value_to_i64
#else
#define value_to_unsigned_long value_to_u32
#define value_to_long value_to_i32
#endif

#define value_to_int value_to_i32
#define value_to_unsigned_int value_to_u32

#define value_to_char(v) ((char)value_to_i8((v)))
#define value_to_unsigned_char(v) ((unsigned char)value_to_i8((v)))
#define value_to_string(v) ((v)->buf)
#if __WORDSIZE == 64
#define value_to_num(v) value_to_i64((v))
#else
#define value_to_num(v) value_to_i32((v))
#endif

/**
 ** Quick raw value converters
 **/
signed char      rv_c(void *buf);
unsigned char    rv_uc(void *buf);
wchar_t          rv_wc(void *buf);
uint8_t          rv_u8(void *buf);
uint16_t         rv_u16(void *buf);
uint32_t         rv_u32(void *buf);
uint64_t         rv_u64(void *buf);
int8_t           rv_i8(void *buf);
int16_t          rv_i16(void *buf);
int32_t          rv_i32(void *buf);
int64_t          rv_i64(void *buf);
float            rv_f(void *buf);
double           rv_d(void *buf);
long double      rv_dd(void *buf);
ADDR             rv_addr(void *buf);

/**
 ** The primary target data structures.
 **/

/* 
 * For now, targets can support multiple threads.  However, these
 * threads should share their address spaces; if they do not, use a
 * separate target to track them.
 *
 * Targets can support either single-thread mode or multi-thread mode
 * (or may only support one or the other).  To support single-thread
 * mode, each target should supply a "default thread" that either really
 * is the single thread of the target, or somehow abstracts around the
 * fact that there are multiple threads running.
 *
 * In single thread mode, only the default thread is used; hardware
 * state of the machine is always in this thread's context.  So, if the
 * user/library calls target_load_current_thread, the default thread is
 * always populated with current hardware state and returned.
 * target_load_thread(tid) will always fail in single-thread mode.
 * Summary: single-thread mode exists so that the user doesn't have to
 * worry about which thread context they are executing in, if they don't
 * care.
 *
 * In thread-aware mode, the user is unaware that there are multiple
 * threads, but the VMI library knows there are; it detects these
 * threads as separate execution contexts so that it can maintain
 * probepoint state amongst multiple threads.  However, they are not
 * exposed to the user (i.e., the user sees only the def
 *
 * In multi-thread mode, target_load_current_thread should load the
 * current thread's hardware context into a thread that is truly
 * associated with the thread's real TID (unlike loading the current
 * thread in single-thread mode).  Hence, in multi-thread mode, the
 * default thread is never used.
 *
 * When setting probes, if your target is single threaded, probes are
 * always "global" -- that is, if they manifest as hardware debug
 * register probes, the debug registers are set globally; if they
 * manifest as software probes, the software probes will cause
 * interrupts no matter what thread hits them, and the probes will
 * always be notified no matter which thread is executing.
 *
 * When setting probes on a multi threaded target, you have two options:
 * set the probes per-thread, or to be TID_GLOBAL.  The idea is that if
 * a probe is per-thread, the probe will only be notified if the thread
 * named hits the probe.  If you have set TID_GLOBAL for your probe, the
 * probe will be notified for any thread that triggers the probe.  Why
 * is the distinction important?  If you set software probes, they will
 * cause interrupts in any thread in the target (since they are embedded
 * in the shared text pages).  BUT, if you set the probes per-thread,
 * the probes will only be notified in the thread they were associated
 * with.
 *
 * When setting a hardware probe per-thread or with TID_GLOBAL, the
 * behavior is target-dependent, because it depends on the model for
 * using/sharing the hardware debug registers.  On x86 architectures,
 * there is no hardware support for sharing the debug registers, so
 * things are tricky.
 *
 * For our two existing targets, these are the rules:
 *
 * xen_vm -- you should either set all your hardware probes with
 * TID_GLOBAL, or per-thread.  Do not mix them.  Why?  Because once you
 * set a per-thread probe, the Linux kernel running in the guest VM will
 * modify the contents of the debug registers when a process is context
 * switched.  This will wipe out any registers set with TID_GLOBAL, and
 * your TID_GLOBAL probes may not work anymore.  We recommend that you
 * only probe with TID_GLOBAL for this target.
 *
 * linux_userspace_process -- TID_GLOBAL is meaningless on this target.
 * You can only set per-thread hardware debug registers.
 *
 */

typedef enum {
    THREAD_RESUMEAT_NONE = 0,
    THREAD_RESUMEAT_BPH = 1,
    THREAD_RESUMEAT_SSR,
    THREAD_RESUMEAT_NA,
    THREAD_RESUMEAT_PH,
} thread_resumeat_t;

struct target_thread {
    struct target *target;
    tid_t tid;
    int8_t valid:1,
  	   dirty:1,
	   resumeat:3,
	   attached:1;
    thread_status_t status:THREAD_STATUS_BITS;
    target_type_t supported_overlay_types:TARGET_TYPE_BITS;

    /*
     * Target backends may or may not set this field when they load
     * threads.  If it is set, it will be freed when the thread is
     * freed.
     */
    char *name;

    void *state;

    /*
     * A hashtable of addresses to probe points.
     */
    GHashTable *hard_probepoints;

    /*
     * Info about the probepoint we are handling.  A single thread can
     * only be directly handling one probepoint at once.  The only case
     * where we could stack up two breakpoints is when we single step
     * after hitting a  breakpoint, and we trigger a watchpoint.  This
     * is a special case, and for x86 targets, the x86 guarantees that
     * the watchpoint exception will happen first, then the single step
     * exception.  But in any case, we know what is happening, so we can
     * handle it.
     *
     * The other case where it could happen is if an interrupt fires
     * before the single step following a breakpoint can run, or if an
     * exception occurs during the single step, which triggers control
     * flow to divert to another path involving another probepoint.  In
     * the interrupt case, the thread could be preempted by another
     * thread.  This is bad, because when we handled the breakpoint, we
     * replaced the breakpoint instruction with either an action
     * instruction or the original instruction and were about to single
     * step it.  The only way we could handle this is to snoop on
     * higher-prio interrupts; see if the interrupt preempted our
     * handling of a breakpoint, and put the breakpoint instruction back
     * in (or reenable the hw breakpoint in question) before the
     * interrupt is handled.  Then, when the other thread resumes, we're
     * going to single step the breakpoint instruction, and we need to
     * recognize this and basically try the single step again.
     *
     * For the case where an exception fires during the single
     * step... actually I think the x86 will not fire the single step
     * trap until the exception has been handled, because the single
     * step trap cannot happen until the instruction pointer can be
     * moved past the instruction... ?
     *
     * The other case where this can happen is when one of the actions
     * is one or more custom code actions, and we have to execute more
     * instructions that just the one single step following a
     * breakpoint.  In this case, our thread might get interrupted while
     * handling actions, and we must therefore remember which action for
     * which probepoint we are handling later when the thread resumes.
     *
     * So, anyway, for these reasons at least, we have to keep
     * per-probepoint, per-action state for each thread.  We push a new
     * context each time we hit a breakpoint.  When a debug event
     * happens for a thread, we continue operating with the context atop
     * the stack.  This doesn't solve the problems of interrupts and
     * exceptions during or before the single step of the breakpoint,
     * but it solves the problem of running multiple actions within the
     * thread.  If we didn't have the stack, we would no longer know
     * which probepoint we were handling...
     */
    struct thread_probepoint_context *tpc;
    struct array_list *tpc_stack;

    /*
     * If this target supports an underlying physical address space, and
     * that address space can be shared amongst the target's threads, we
     * might place breakpoints in shared pages.  So -- if we hit a
     * breakpoint at such a page in a thread that is not registered on
     * the breakpoint, we have to emulate the breakpoint's behavior.  See
     * target_memmod_emulate_bp_handler() and target_memmod_ss_handler().
     */
    struct target_memmod *emulating_debug_mmod;

    /*
     * Any single step actions that are executing in this thread.  We
     * might have more than one at a single probepoint, or we might have
     * accumulated one or more from previous probepoints that are still
     * being handled.  They each have per-thread state, since an action
     * for a probe attached to TID_GLOBAL could be fired in any thread.
     * If it wasn't for that case, action state would be per-thread
     * only, but able to be kept entirely within the action struct.
     */
    struct list_head ss_actions;
};

struct target_spec {
    target_type_t target_type;

    int target_id;
    target_mode_t target_mode;
    thread_bpmode_t bpmode;
    probepoint_style_t style;
    uint8_t start_paused:1,
	    kill_on_close:1;
    active_probe_flags_t active_probe_flags:ACTIVE_PROBE_BITS;

    char *debugfile_root_prefix;
    /* struct array_list of struct debugfile_load_opts * */
    struct array_list *debugfile_load_opts_list;

    /*
     * If kill_on_close, call kill() during close() with this signal.
     */
    int kill_on_close_sig;

    /*
     * I/O behavior is a bit complicated.  We want a couple things -- to
     * support the target library by itself (i.e., user code calling
     * directly into the library); and to support the XML SOAP server
     * calling into the library on behalf of the user.  In both cases,
     * we might want I/O logged to a file; we might want I/O callbacks
     * to the user (we might want it buffered too, but forget that for
     * now).
     *
     * So, if the caller wants stdio interaction, the backend must open
     * the I/O devices and expose them to the caller as an FD -- the
     * caller specifies this by providing evloop_handler_ts for the
     * stdio descriptor types it cares about.  If the user does not
     * specify one of these, but instead specifies a filename, the
     * backend must auto-write/-read the output/input to/from the named
     * file.
     *
     * (If handlers are provided, the caller *must* call
     * target_attach_evloop() sometime -- otherwise if the target does
     * i/o on those descriptors, they will probably fill up and block it!)
     *
     *
     * Only the backend knows how to deal with I/O, for each backend.
     * So, we have to rely on the backend to give us file descriptors
     * for the target I/Os we care about.  We assume stdin, stdout, and
     * an optional stderr.  The problem is, some backends might provide
     * stdio access only if we launch a new target (Ptrace); others
     * might provide access anytime (Xen); but we can't know until the
     * backend parses the spec and figures out what to do.
     *
     * (Even if the backend opens one of these files, it must not remove
     * it!  That is the user or caller's job.)
     *
     * This kind of sucks... but we'll just warn the client if it tries
     * to do something the backend doesn't support.  Later we can do
     * something better, like warning a priori.
     *
     */
    evloop_handler_t in_evh;
    evloop_handler_t out_evh;
    evloop_handler_t err_evh;

    char *infile;
    char *outfile;
    char *errfile;

    void *backend_spec;
};

struct target_argp_parser_state {
    int num_children;
    void *driver_state;
    struct target_spec *spec;
    int quoted_argc;
    int quoted_start;
    char **quoted_argv;
};

typedef enum {
    TARGET_STATE_CHANGE_EXITED = 1,
    TARGET_STATE_CHANGE_EXITING,
    TARGET_STATE_CHANGE_ERROR,
    TARGET_STATE_CHANGE_THREAD_CREATED,
    TARGET_STATE_CHANGE_THREAD_EXITED,
    TARGET_STATE_CHANGE_THREAD_EXITING,
    TARGET_STATE_CHANGE_REGION_NEW,
    TARGET_STATE_CHANGE_REGION_MOD,
    TARGET_STATE_CHANGE_REGION_DEL,
    TARGET_STATE_CHANGE_RANGE_NEW,
    TARGET_STATE_CHANGE_RANGE_MOD,
    TARGET_STATE_CHANGE_RANGE_DEL,
} target_state_change_type_t;

struct target_state_change {
    tid_t tid;
    target_state_change_type_t chtype;
    unsigned long code;
    unsigned long data;
    ADDR start;
    ADDR end;
    char *msg;
};

/*
 * A target is the top-level entity a user creates or associates with to
 * start a debugging session.  Targets bind state and type metadata to
 * an execution context and at least one address space.
 */
struct target {
    uint32_t live:1,
    	     writeable:1,
	     nodisablehwbponss:1,
	     threadctl:1,
	     endian:1,
	     mmapable:1,
	     wordsize:4,
	     ptrsize:4,
	     opened:1,
	     kill_on_close:1;
    active_probe_flags_t active_probe_flags:ACTIVE_PROBE_BITS;

    /*
     * How we track status is a little funny.  Basically, we want the
     * target's event handlers (monitor, poll, an evloop handler) to set
     * status before leaving the handling code (to return into the rest
     * of the library, or to the user code).  This avoids lots of
     * (potentially, depending on backend) expensive calls to
     * @ops->status.
     *
     * The backend must only set target and thread status via
     * target(_thread)_set_status or similar, so that we can track and
     * debug the changes.  The backend must set status corresponding to
     * whatever state it leaves the target in.  That means, for
     * instance, for the ptrace target, if it resumes tracing on behalf
     * of the user, it sets status to RUNNING.  The backend should only
     * set status to _ERROR if the error is a fatal, final error, and
     * the target API cannot continue.  monitor/poll can return _ERROR,
     * *but* only if they are temporary errors that the backend feels
     * safe continuing with.  In reality, the backend author must
     * minimize these; the user cannot deal with them very well, other
     * than cleaning up as best they can.
     *
     * When the target is not opened, we always call into the backend to
     * set the status field each time target_status is called.
     */
    target_status_t status;

    /*
     * Targets can add target_state_change structs to this array; it is
     * also their responsibility to free them.  Basically, the idea is
     * that internal handlers could set one or more; then if they cause
     * monitor/poll/evloop_handler to return to the user, the user can
     * see what changed; then the internal handler should empty the list
     * at its next run.
     */
    struct array_list *state_changes;

    REG fbregno;
    REG spregno;
    REG ipregno;

    /*
     * Each target has a unique integer ID; this is the key into the
     * target hashtable, for instance.
     */
    int id;

    /*
     * Each target has a unique name; this is generated by
     * target_ops->tostring during target_init.
     */
    char *name;

    void *state;
    struct target_ops *ops;
    struct target_spec *spec;

    int kill_on_close_sig;

    /*
     * If the spec specified stdio interactions via handlers, these are
     * the file descriptors.
     */
    int infd;
    int outfd;
    int errfd;

    /*
     * A simple key/value store for generic target configuration
     * options.  Anything keys/values placed in it will be free()d when
     * the hashtable is freed, so be careful!
     */
    GHashTable *config;

    /*
     * If the target is attached to an evloop, this is that evloop.
     */
    struct evloop *evloop;

    /* Targets can have multiple address spaces, but not sure how we're
     * going to use this yet.
     */
    struct list_head spaces;

    /*
     * Each target has a primary binfile associated with it; think
     * "main" for userspace, the kernel for kernels.
     */
    struct binfile *binfile;

    /*
     * If this is an overlay, this is the underlying "base" target info.
     */
    struct target *base;
    struct target_thread *base_thread;
    int base_id;
    tid_t base_tid;

    /*
     * Any live overlay targets are placed here.  There can only be a
     * single overlay per thread, at the moment.
     */
    GHashTable *overlays;

    GHashTable *threads;
    /*
     * For single-threaded targets, this will always be the global
     * thread.  For multi-threaded targets, it will be the
     * currently-executing thread (and if there is no thread context,
     * i.e., the machine is in interrupt context, it will be the global
     * thread).
     */
    struct target_thread *current_thread;
    /* 
     * This is the thread that should be used for any TID_GLOBAL
     * operations.  Its state should always be loaded
     */
    struct target_thread *global_thread;

    /*
     * If we have to pause all threads in the target while we handle a
     * breakpoint for one thread, we always make sure to waitpid() for
     * this blocking thread first, and handle it first, before handling
     * any others.
     */
    struct target_thread *blocking_thread;

    /*
     * This is for target backends to use if they wish.
     *
     * The idea is, each time we single step a thread, we make a note of
     * it here; each time we run the monitor loop looking for debug
     * exceptions, after we find one, clear this variable after checking
     * any state related to it, so that we know how to handle the debug
     * exception -- but then CLEAR it before handling the exception via
     * the probe library.  The Xen target does this; the linux ptrace
     * target does not.
     *
     * This is not completely trustworthy on targets that do not provide
     * good thread control.  It is here for the case in which we single
     * step an instruction that might switch contexts.  If we have just
     * done that, and this var is set, a target's monitor loop should
     * notice and try to "handle" the singlestep in the previous thread,
     * even though the thread is no longer running.
     */
    struct target_thread *sstep_thread;
    /*
     * Also, if the overlay target uses the underlay's single step
     * mechanism, provide a place to mark that it did, so that the
     * overlay can handle the resulting single steps if it needs to.
     */
    struct target *sstep_thread_overlay;

    GHashTable *soft_probepoints;

    /*
     * A table of memory modifications, and their states.  We use this
     * to support software probepoints.
     */
    GHashTable *mmods;

    /*
     * A table of physical memory modifications, and their states.  We
     * use this to support software probepoints.
     *
     * Phys mmods are global to a target because it supports MMU-based
     * multiple address spaces -- i.e., addrs are fundamentally virt
     * addrs in a target.  This allows a target to be aware of physical
     * addrs below virt addrs.  So, it can support the case where a
     * memmod might have been made in the VMM of a userspace process,
     * but that this memmod might also manifest in the VMM of another
     * userspace process at a different virt addr; but at the same phys
     * addr.
     */
    GHashTable *phys_mmods;

    /*
     * A hashtable of probe IDs to probes that were created on this
     * target.
     *
     * Probes may be attached to specific threads, but we track them
     * globally here, mostly for the XML RPC server.
     */
    GHashTable *probes;

    /*
     * A hashtable of (scheduled) action IDs to actions.
     *
     * Although (scheduled) actions are attached to probepoints, we
     * track them by ID on a per-target basis.  Right now, this is only
     * used for XML RPCs; internally, the IDs are unused.
     *
     * Also note that we do not explicitly "free" actions; users 
     */
    GHashTable *actions;

    /*
     * Counters for the IDs for probes/actions.
     */
    int probe_id_counter;
    int action_id_counter;

    /*
     * If we mmap any of the target's memory, this hashtable will have
     * the map entry.
     */
    GHashTable *mmaps;

    /* Cache of loaded code, by address range. */
    clrange_t code_ranges;

    /* One or more opcodes that create a software breakpoint */
    void *breakpoint_instrs;
    unsigned int breakpoint_instrs_len;
    /* How many opcodes are in the above sequence, so we can single-step
     * past them all.
     */
    unsigned int breakpoint_instr_count;

    void *ret_instrs;
    unsigned int ret_instrs_len;
    unsigned int ret_instr_count;

    void *full_ret_instrs;
    unsigned int full_ret_instrs_len;
    unsigned int full_ret_instr_count;

    /* Single step and breakpoint handlers.  Since we control
     * single-step mode, we report *any* single step stop events to the
     * handler, and do nothing with them ourselves.
     *
     * For breakpoints, if we don't have a probepoint matching the
     * breaking EIP, target_monitor will return to the library user, and
     * they'll have to handle the exception themselves (i.e., this would
     * happen if their code had a software breakpoint in it).
     */
    target_debug_handler_t ss_handler;
    target_debug_bp_handler_t bp_handler;
};

struct target_ops {
    char *(*tostring)(struct target *target,char *buf,int bufsiz);

    /* init any target state, like a private per-target state struct */
    int (*init)(struct target *target);
    /* init any target state, like a private per-target state struct */
    int (*fini)(struct target *target);
    /* actually connect to the target to enable read/write */
    int (*attach)(struct target *target);
    /* detach from target, but don't unload */
    int (*detach)(struct target *target);
    /* destroy the target */
    int (*kill)(struct target *target,int sig);

    /* Divide the target into address spaces with different IDs, that
     * might contain multiple subregions.
     */
    int (*loadspaces)(struct target *target);
    /* divide the address space into regions, each containing one
     * or more ranges, with different protection flags, that might come
     * from different source binary files.
     */
    int (*loadregions)(struct target *target,
		       struct addrspace *space);
    /* for each loaded region, load one or more debugfiles and associate
     * them with the region.
     */
    int (*loaddebugfiles)(struct target *target,
			  struct addrspace *space,
			  struct memregion *region);
    /* Once regions and debugfiles are loaded, we call this -- it's a
     * second-pass init, basically.
     */
    int (*postloadinit)(struct target *target);
    /* Once @attach has been called and has succeeded, we call this --
     * primarily it's a chance for the target to register probes on
     * itself.
     *
     * We initially call it with @target->spec->active_probe_flags; but
     * users may later call target_set_active_probing() to fine-tune
     * settings.
     */
    int (*set_active_probing)(struct target *target,active_probe_flags_t flags);
    /* Once @attach has been called and has succeeded, the target is
     * opened.  This is the final function we call in target_open.
     */
    int (*postopened)(struct target *target);

    /*
     * "Underlay" targets (that support overlays) must define these
     * functions.
     */
    struct target *(*instantiate_overlay)(struct target *target,
					  struct target_thread *tthread,
					  struct target_spec *spec);
    struct target_thread *(*lookup_overlay_thread_by_id)(struct target *target,
							 int id);
    struct target_thread *(*lookup_overlay_thread_by_name)(struct target *target,
							   char *name);
    /*
     * Overlay targets must support this if their exceptions come from
     * the underlying target.
     */
    target_status_t (*overlay_event)(struct target *overlay,tid_t tid,
				     ADDR ipval,int *again);

    /* get target status. */
    target_status_t (*status)(struct target *target);
    /* pause a target */
    int (*pause)(struct target *target,int nowait);
    /* resume from a paused state */
    int (*resume)(struct target *target);
    /* wait for something to happen to the target */
    target_status_t (*monitor)(struct target *target);
    target_status_t (*poll)(struct target *target,struct timeval *tv,
			    target_poll_outcome_t *outcome,int *pstatus);

    int (*attach_evloop)(struct target *target,struct evloop *evloop);
    int (*detach_evloop)(struct target *target);

    /* read some memory, potentially into a supplied buffer. */
    unsigned char *(*read) (struct target *target,ADDR addr,
			    unsigned long length,unsigned char *buf);
    /* write some memory */
    unsigned long (*write)(struct target *target,ADDR addr,
			   unsigned long length,unsigned char *buf);

    /*
     * Some targets might support threads that have their own virtual
     * address spaces, but an underlying system (like the kernel) might
     * share phys memory amongst separate thread virtual address
     * spaces.
     *
     * (The Xen target uses this to provide shared-page breakpoint
     * support to Xen Process overlay targets.)
     */

    int (*addr_v2p)(struct target *target,tid_t tid,ADDR vaddr,ADDR *paddr);

    /* read some phys memory, potentially into a supplied buffer. */
    unsigned char *(*read_phys)(struct target *target,ADDR paddr,
				unsigned long length,unsigned char *buf);
    /* write some phys memory */
    unsigned long (*write_phys)(struct target *target,ADDR paddr,
				unsigned long length,unsigned char *buf);

    /* Get target-specific register name. */
    char *(*regname)(struct target *target,REG reg);
    /* Get target-specific DWARF reg number for the target-specific name. */
    REG (*dwregno_targetname)(struct target *target,char *name);
    /* Get target-specific DWARF reg number for the "common" register. */
    REG (*dwregno)(struct target *target,common_reg_t reg);

    /**
     ** Many of the following operations can be parameterized by a thread id.
     **/

    /* Context stuff so that we can handle multithreaded targets, and
     * infinite single stepping in their presence.
     */
    tid_t (*gettid)(struct target *target);
    void (*free_thread_state)(struct target *target,void *state);
    struct array_list *(*list_available_tids)(struct target *target);
    struct target_thread *(*load_thread)(struct target *target,tid_t tid,
					 int force);
    struct target_thread *(*load_current_thread)(struct target *target,
						 int force);
    int (*load_all_threads)(struct target *target,int force);
    int (*load_available_threads)(struct target *target,int force);
    int (*pause_thread)(struct target *target,tid_t tid,int nowait);
    /* flush target(:tid) machine state */
    int (*flush_thread)(struct target *target,tid_t tid);
    int (*flush_current_thread)(struct target *target);
    int (*flush_all_threads)(struct target *target);
    int (*gc_threads)(struct target *target);
    char *(*thread_tostring)(struct target *target,tid_t tid,int detail,
			     char *buf,int bufsiz);

    /* get/set contents of a register */
    REGVAL (*readreg)(struct target *target,tid_t tid,REG reg);
    int (*writereg)(struct target *target,tid_t tid,REG reg,REGVAL value);
    GHashTable *(*copy_registers)(struct target *target,tid_t tid);

    /* breakpoint/watchpoint stuff */
    struct target_memmod *(*insert_sw_breakpoint)(struct target *target,tid_t tid,
						  ADDR addr);
    int (*remove_sw_breakpoint)(struct target *target,tid_t tid,
				struct target_memmod *mmod);
    int (*enable_sw_breakpoint)(struct target *target,tid_t tid,
				struct target_memmod *mmod);
    int (*disable_sw_breakpoint)(struct target *target,tid_t tid,
				 struct target_memmod *mmod);
    int (*change_sw_breakpoint)(struct target *target,tid_t tid,
				struct target_memmod *mmod,
				unsigned char *code,unsigned long code_len);
    REG (*get_unused_debug_reg)(struct target *target,tid_t tid);
    int (*set_hw_breakpoint)(struct target *target,tid_t tid,REG reg,ADDR addr);
    int (*set_hw_watchpoint)(struct target *target,tid_t tid,REG reg,ADDR addr,
			     probepoint_whence_t whence,
			     probepoint_watchsize_t watchsize);
    int (*unset_hw_breakpoint)(struct target *target,tid_t tid,REG reg);
    int (*unset_hw_watchpoint)(struct target *target,tid_t tid,REG reg);
    int (*disable_hw_breakpoints)(struct target *target,tid_t tid);
    int (*enable_hw_breakpoints)(struct target *target,tid_t tid);
    int (*disable_hw_breakpoint)(struct target *target,tid_t tid,REG dreg);
    int (*enable_hw_breakpoint)(struct target *target,tid_t tid,REG dreg);
    int (*notify_sw_breakpoint)(struct target *target,ADDR addr,
				int notification);
    int (*singlestep)(struct target *target,tid_t tid,int isbp,
		      struct target *overlay);
    int (*singlestep_end)(struct target *target,tid_t tid,
			  struct target *overlay);

    /* Instruction-specific stuff for stepping. */
    /*
     * Returns > 0 if the instruction might switch contexts; 0
     * if not; -1 on error.
     */
    int (*instr_can_switch_context)(struct target *target,ADDR addr);

    /*
     * Stuff for counters.  Each target should provide its TSC
     * timestamp, an internal notion of time since boot in nanoseconds,
     * and if they support indexed execution, a "cycle counter" or
     * something.
     */
    uint64_t (*get_tsc)(struct target *target);
    uint64_t (*get_time)(struct target *target);
    uint64_t (*get_counter)(struct target *target);

    int (*enable_feature)(struct target *target,int feature,void *arg);
    int (*disable_feature)(struct target *target,int feature);
};

struct value {
    /*
     * We keep a reference to the target thread that resolved this
     * value.  Why?  Because although memory is thread-independent, the
     * location of variables is thread-dependent; it may depend on CPU
     * register state (i.e., a DWARF location expression that involves
     * reading the contents of registers).
     *
     * When a thread doesn't matter, @thread will be
     * target->global_thread (i.e., for loading values by type).
     */
    struct target_thread *thread;

    /*
     * The type of value -- it may NOT be the primary type of the
     * bsymbol!  i.e., it may be the pointed-to type, or we may have
     * stripped off the const/vol qualifiers.
     *
     * We could also save the load flags so we always know what type of
     * memory this object is pointing to, but we'll skip that for now.
     */
    struct symbol *type;

    /*
     * A backreference to the symbol this value is associated with.
     */
    struct lsymbol *lsymbol;

    /* The memrange this value exists in. */
    struct memrange *range;

    /* The region stamp at load time. */
    uint32_t region_stamp;

    int bufsiz;
    char *buf;

    uint8_t ismmap:1,
	    isreg:1,
	    isstring:1;

    /* If this value is mmap'd instead of alloc'd, store that too. */
    struct mmap_entry *mmap;

    /*
     * The location of the value.
     */
    union {
	ADDR addr;
	REG reg;
    } res;

    /*
     * The value of the PC when we last loaded this symbol.
     */
    ADDR res_ip;

    struct value *parent_value;
};


#endif
