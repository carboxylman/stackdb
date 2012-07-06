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

/**
 ** These functions form the target API.
 **/
/*
 * Opens a target.
 */
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
				unsigned char *buf,
				void *targetspecdata);
unsigned long target_write_addr(struct target *target,ADDR addr,
				unsigned long length,unsigned char *buf,
				void *targetspecdata);
char *target_reg_name(struct target *target,REG reg);
REGVAL target_read_reg(struct target *target,REG reg);
int target_write_reg(struct target *target,REG reg,REGVAL value);
int target_flush_context(struct target *target);
void target_free(struct target *target);
struct target *target_create(char *type,void *state,struct target_ops *ops,
			     struct debugfile_load_opts **dfoptlist);
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

int target_notify_sw_breakpoint(struct target *target,ADDR addr,
				int notification);

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
 *
 * This function takes a ref to its return value on the user's behalf;
 * call bsymbol_release() to release (and maybe free) it.
 */

struct bsymbol *target_lookup_sym(struct target *target,
				  char *name,const char *delim,
				  char *srcfile,symbol_type_flag_t ftype);
struct bsymbol *target_lookup_sym_member(struct target *target,
					 struct bsymbol *bsymbol,
					 char *name,const char *delim);

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
ADDR target_addressof_bsymbol(struct target *target,struct bsymbol *bsymbol,
			      load_flags_t flags,
			      struct memrange **range_saveptr);

struct value *target_load_symbol(struct target *target,struct bsymbol *bsymbol,
				 load_flags_t flags);
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
struct value *target_load_symbol_member(struct target *target,
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
 * bsymbol_load is deprecated -- use target_load_*() instead!
 */
/*
 * Load a symbol's value, but just return a raw pointer.  If flags
 * contains LOAD_FLAGS_MMAP, we try to mmap the target's memory instead
 * of reading and copying the data; if that fails, we return NULL.  If
 * buf is not NULL, it should be sized to
 * symbol->datatype->s.ti.byte_size (best available as symbol_get
 */
struct value *bsymbol_load(struct bsymbol *bsymbol,load_flags_t flags);

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

typedef int (*target_debug_handler_t)(struct target *target,
				      struct probepoint *probepoint);

/**
 ** Bound symbol interface functions -- user should not need any more
 ** knowledge of bsymbols other than these few functions.
 **/
char *bsymbol_get_name(struct bsymbol *bsymbol);
struct symbol *bsymbol_get_symbol(struct bsymbol *bsymbol);
struct lsymbol *bsymbol_get_lsymbol(struct bsymbol *bsymbol);
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
void value_free(struct value *value);
void value_dump(struct value *value,struct dump_info *ud);

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
int64_t          v_num(struct value *v);
uint64_t         v_unum(struct value *v);
float            v_f(struct value *v);
double           v_d(struct value *v);
long double      v_dd(struct value *v);
ADDR             v_addr(struct value *v);

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
int value_update_num(struct value *value,int64_t v);
int value_update_unum(struct value *value,uint64_t v);

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
    REG spregno;
    REG ipregno;

    void *state;
    struct target_ops *ops;

    struct debugfile_load_opts **debugfile_opts_list;

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

    /*
     * A hashtable of pointers to probes.
     */
    GHashTable *probes;

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

    struct probepoint *sstep_probepoint;
    int sstep_leave_enabled;
    struct array_list *sstep_stack;

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
			    unsigned long length,unsigned char *buf,
			    void *targetspecdata);
    /* write some memory */
    unsigned long (*write)(struct target *target,ADDR addr,
			   unsigned long length,unsigned char *buf,
			   void *targetspecdata);

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
    int (*notify_sw_breakpoint)(struct target *target,ADDR addr,
				int notification);
    int (*singlestep)(struct target *target);
    int (*singlestep_end)(struct target *target);
};

struct value {
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

    /* If this value is mmap'd instead of alloc'd, store that too. */
    struct mmap_entry *mmap;
    char *buf;
    int bufsiz;
    uint8_t ismmap:1,
	    isstring:1;

    /* The resolved address of the value. */
    ADDR addr;
    /* The value of the PC when we last resolved this symbol's address. */
    ADDR addr_resolved_ip;

    struct value *parent_value;
};


#endif
