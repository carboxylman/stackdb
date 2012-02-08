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
 * Foundation, 51 Franklin St, Suite 500, Boston, MA 02110-1335, USA.
 */

#ifndef __TARGET_API_H__
#define __TARGET_API_H__

#include "common.h"
#include "list.h"
#include "dwdebug.h"
#include "probe_api.h"
#include <glib.h>

struct target;
struct target_ops;
struct addrspace;
struct memregion;
struct memrange;

typedef enum {
    TSTATUS_UNKNOWN        = 0,
    TSTATUS_RUNNING        = 1,
    TSTATUS_PAUSED         = 2,
    TSTATUS_DEAD           = 3,
    TSTATUS_STOPPED        = 4,
    TSTATUS_ERROR          = 5,
    TSTATUS_DONE           = 6,
} target_status_t;

typedef enum {
    POLL_NOTHING          = 0,
    POLL_ERROR            = 1,
    POLL_SUCCESS          = 2,
    POLL_UNKNOWN          = 3,
    __POLL_MAX,
} target_poll_outcome_t;

extern char *TSTATUS_STRINGS[];
#define TSTATUS(n) (((n) < sizeof(TSTATUS_STRINGS)/sizeof(char *)) \
		    ? TSTATUS_STRINGS[(n)] : NULL)

extern char *POLL_STRINGS[];
#define POLL(n) (((n) < sizeof(POLL_STRINGS)/sizeof(char *)) \
		 ? POLL_STRINGS[(n)] : NULL)

/**
 ** These functions form the target API.
 **/
int target_open(struct target *target);
/*
 * Monitors a target for debug/exception events, tries to handle any
 * probes attached to the target, and only returns if it can't handle
 * some condition that arises.
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
 */
target_status_t target_poll(struct target *target,
			    target_poll_outcome_t *outcome,int *pstatus);
int target_resume(struct target *target);
int target_pause(struct target *target);
target_status_t target_status(struct target *target);
int target_close(struct target *target);
unsigned char *target_read_addr(struct target *target,
				ADDR addr,
				unsigned long length,
				unsigned char *buf);
unsigned long target_write_addr(struct target *target,ADDR addr,
				unsigned long length,unsigned char *buf);
char *target_reg_name(struct target *target,REG reg);
REGVAL target_read_reg(struct target *target,REG reg);
int target_write_reg(struct target *target,REG reg,REGVAL value);
int target_flush_context(struct target *target);
void target_free(struct target *target);
struct target *target_create(char *type,void *state,struct target_ops *ops);
struct mmap_entry *target_lookup_mmap_entry(struct target *target,
					    ADDR base_addr);
void target_attach_mmap_entry(struct target *target,
			      struct mmap_entry *mme);
void target_release_mmap_entry(struct target *target,
			       struct mmap_entry *mme);
REG target_get_unused_debug_reg(struct target *target);
int target_set_hw_breakpoint(struct target *target,REG reg,ADDR addr);
int target_set_hw_watchpoint(struct target *target,REG reg,ADDR addr,
			     probepoint_whence_t whence,int watchsize);
int target_unset_hw_breakpoint(struct target *target,REG reg);
int target_unset_hw_watchpoint(struct target *target,REG reg);

int target_disable_hw_breakpoints(struct target *target);
int target_enable_hw_breakpoints(struct target *target);

int target_singlestep(struct target *target);
int target_singlestep_end(struct target *target);

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
 */

struct bsymbol *target_lookup_sym(struct target *target,
				  char *name,const char *delim,
				  char *srcfile,symbol_type_flag_t ftype);

/**
 ** Quick raw value converters
 **/
signed char      rvalue_c(void *buf);
unsigned char    rvalue_uc(void *buf);
wchar_t          rvalue_wc(void *buf);
uint8_t          rvalue_u8(void *buf);
uint16_t         rvalue_u16(void *buf);
uint32_t         rvalue_u32(void *buf);
uint64_t         rvalue_u64(void *buf);
int8_t           rvalue_i8(void *buf);
int16_t          rvalue_i16(void *buf);
int32_t          rvalue_i32(void *buf);
int64_t          rvalue_i64(void *buf);

typedef int (*target_debug_handler_t)(struct target *target,
				      struct probepoint *probepoint);

/**
 ** The primary target data structures.
 **/
/*
 * A target is the top-level entity a user creates or associates with to
 * start a debugging session.  Targets bind state and type metadata to
 * an execution context and at least one address space.
 */
struct target {
    char *type;
    uint8_t live:1,
    	    writeable:1,
	    attached:1,
	    endian:1,
	    mmapable:1,
	    wordsize:4,
	    ptrsize:4;
    REG fbregno;
    REG ipregno;

    void *state;
    struct target_ops *ops;

    /* Targets can have multiple address spaces, but not sure how we're
     * going to use this yet.
     */
    struct list_head spaces;

    /*
     * If we mmap any of the target's memory, this hashtable will have
     * the map entry.
     */
    GHashTable *mmaps;

    /*
     * A hashtable of addresses to probe points.
     */
    GHashTable *probepoints;

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

    struct probepoint *sstep_probepoint;

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
    target_debug_handler_t bp_handler;
};

struct target_ops {
    /* init any target state, like a private per-target state struct */
    int (*init)(struct target *target);
    /* init any target state, like a private per-target state struct */
    int (*fini)(struct target *target);
    /* actually connect to the target to enable read/write */
    int (*attach)(struct target *target);
    /* detach from target, but don't unload */
    int (*detach)(struct target *target);

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

    /* get target status. */
    target_status_t (*status)(struct target *target);
    /* pause a target */
    int (*pause)(struct target *target);
    /* resume from a paused state */
    int (*resume)(struct target *target);
    /* wait for something to happen to the target */
    target_status_t (*monitor)(struct target *target);
    target_status_t (*poll)(struct target *target,
			    target_poll_outcome_t *outcome,int *pstatus);

    /* get/set contents of a register */
    char *(*regname)(struct target *target,REG reg);
    REGVAL (*readreg)(struct target *target,REG reg);
    int (*writereg)(struct target *target,REG reg,REGVAL value);
    int (*flush_context)(struct target *target);

    /* read some memory, potentially into a supplied buffer. */
    unsigned char *(*read) (struct target *target,ADDR addr,
			    unsigned long length,unsigned char *buf);
    /* write some memory */
    unsigned long (*write)(struct target *target,ADDR addr,
			   unsigned long length,unsigned char *buf);

    /* breakpoint/watchpoint stuff */
    REG (*get_unused_debug_reg)(struct target *target);
    int (*set_hw_breakpoint)(struct target *target,REG reg,ADDR addr);
    int (*set_hw_watchpoint)(struct target *target,REG reg,ADDR addr,
			     probepoint_whence_t whence,
			     probepoint_watchsize_t watchsize);
    int (*unset_hw_breakpoint)(struct target *target,REG reg);
    int (*unset_hw_watchpoint)(struct target *target,REG reg);
    int (*disable_hw_breakpoints)(struct target *target);
    int (*enable_hw_breakpoints)(struct target *target);
    int (*singlestep)(struct target *target);
    int (*singlestep_end)(struct target *target);
};

#endif
