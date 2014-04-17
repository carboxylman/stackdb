/*
 * Copyright (c) 2013, 2014 The University of Utah
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

#include <sys/types.h>
#include <unistd.h>

#include "binfile.h"
#include "dwdebug.h"
#include "dwdebug_priv.h"
#include "target.h"
#include "target_api.h"
#include "probe_api.h"

#include "target_php.h"

/*
 * INITIALIZATION:
 *
 * To implement php, we do things a lot like the xdebug extension.  We
 * basically breakpoint at strategic places in the php compiler (i.e.,
 * to harvest globals and classes) and executor (i.e. to "implement"
 * function breakpoints).  The two main structures we need are the
 * compiler_globals and executor_globals structs.
 *
 * If php is not compiled with multithread support (! #define ZTS), we
 * can just read them directly.
 * 
 * BUT, if php is compiled with thread support, we have to access the
 * compiler_globals and executor_globals through thread-local storage.
 * We only support one kind of TSRM: Linux/pthreads.  Of course,
 * pthreads are 1-to-1 mapped to real kernel threads on any current
 * version of glibc.  This allows us to load the compiler_globals and
 * executor_globals addresses one time per thread, and cache it.  It
 * won't change.
 *
 * It would be nice if we could just load the compiler_globals and
 * executor_globals TLS structs whenever we attach to an executing php
 * process, but that isn't quite possible on Linux/pthreads.  Why?  Zend
 * uses pthread_(set|get)specific to implement TLS.  But the problem is
 * -- zend uses pthread_getspecific() to get key-specific TLS entries.
 * We don't want to depend on that; plus, it's probably different on
 * x86_64 (%fs-based TLS?) and i386.  Thus, unless we emulate those
 * calls specifically for the target, we can't quite get at the TLS
 * structs directly; we have to snoop on their values as local vars in
 * functions.  Emulating those calls is a bad idea, so we have to snoop.
 *
 *   (Here are the relevant src bits from php5.5-ish that led me to all
 *   these conclusions:
 *     
 *     #ifndef TSRM_DEBUG
 *     #define TSRM_ERROR(args)
 *     #define TSRM_SAFE_RETURN_RSRC(array, offset, range)		\
 *         if (offset==0) {						\
 *		return &array;						\
 *	   } else {							\
 *		return array[TSRM_UNSHUFFLE_RSRC_ID(offset)];		\
 *	   }
 *     #endif
 *
 *     #if defined(PTHREADS)
 *     static pthread_key_t tls_key;
 *     # define tsrm_tls_set(what)
 *     pthread_setspecific(tls_key, (void*)(what))
 *     # define tsrm_tls_get()
 *     pthread_getspecific(tls_key)
 *     #endif
 *
 *     void *ts_resource_ex(ts_rsrc_id id, THREAD_T *th_id) {
 *         THREAD_T thread_id;
 *	   int hash_value;
 *	   tsrm_tls_entry *thread_resources;
 *
 *	   thread_resources = tsrm_tls_get();
 *
 *	   if (thread_resources) {
 *		TSRM_ERROR((TSRM_ERROR_LEVEL_INFO, "Fetching resource id %d for current thread %d", id, (long) thread_resources->thread_id));
 *		// Read a specific resource from the thread's resources.
 *		// This is called outside of a mutex, so have to be aware about external
 *		// changes to the structure as we read it.
 *		TSRM_SAFE_RETURN_RSRC(thread_resources->storage, id, thread_resources->count);
 *	    }
 *	    thread_id = tsrm_thread_id();
 *
 *
 *
 *     #define TSRMLS_FETCH()
 *	void ***tsrm_ls = (void ***) ts_resource_ex(0, NULL)
 *     #define TSRM_UNSHUFFLE_RSRC_ID(rsrc_id)
 *	((rsrc_id)-1)
 *     #define TSRMG(id, type, element)
 *	(((type) (*((void ***) tsrm_ls))[TSRM_UNSHUFFLE_RSRC_ID(id)])->element)
 *
 *     #ifdef ZTS
 *     # define CG(v) TSRMG(compiler_globals_id, zend_compiler_globals *, v)
 *     #else
 *     # define CG(v) (compiler_globals.v)
 *     extern ZEND_API struct _zend_compiler_globals compiler_globals;
 *     #endif
 *
 *     #ifdef ZTS
 *     # define EG(v) TSRMG(executor_globals_id, zend_executor_globals *, v)
 *     #else
 *     # define EG(v) (executor_globals.v)
 *     extern ZEND_API zend_executor_globals executor_globals;
 *     #endif
 *   ).
 *
 * So how can we best snoop on the execution?  If we can catch the php
 * process directly at startup once it's been loaded, but before it
 * runs, we can place breakpoints on compiler_globals_ctor and
 * executor_globals_ctor, which will be called by Zend's TSRM lib when
 * new threads are created -- to initialize those copies of TLS for the
 * new thread.  Only one problem: Zend startup is a bit funny because it
 * creates "global" read-only version of the global structs, and they
 * are cloned to create read-write per-thread versions, I think.  So, we
 * need to breakpoint zend_post_startup(), then we can breakpoint the
 * ctors to obtain their per-thread struct addresses and remove the
 * zend_post_startup breakpoint.  Each time on of those ctors is called,
 * we have a new thread entering.  So, that's how we get access to these
 * critical structs if ZTS is enabled -- we hook onto a function that
 * has the TLS global pointer as an arg to it.
 *
 * But what if we're already executing?  We can either place probes on
 * key execution functions (but we won't catch them all; we can't probe
 * on all the opcode handlers).  We *can* look through the current stack
 * unwind of the the thread and find a function in the execution stack
 * that has the TLS global pointer as an arg.  Then we're good.
 *
 * Obviously, we are making the optimizing assumption that we only have
 * check tsrm_ls once per thread to get the "symbol" we're interested
 * in.
 *
 * SO -- what we're going to do instead is, on attach, unwind the stack
 * and look for functions with tsrm_ls (if php was compiled with ZTS).
 * If we find none, we place probes on the primary execution functions
 * (zend_execute, execute_ex, and execute_internal), and try to snoop
 * tsrm_ls at those points.  Then as soon as one or the other of those
 * is hit, load the current thread's compiler_globals and/or
 * executor_globals stuff from CG(tsrm_ls), and remove the corresponding
 * initial probes to find tsrm_ls.
 *
 *
 * BREAKPOINTS:
 * 
 * I had hoped that it would be sufficient to breakpoint on execute_ex
 * and execute_internal, but it is not; we cannot implement lineno
 * breakpoints without being able to trap on all statement executions.
 * zend_extension provides a way to hook the statement execution, but we
 * cannot just "add" a zend_extension with such a hook in from the
 * outside; requires dynamic memory allocation.  So, then we're left
 * with probing the individual opcode handlers (ugh -- there are a
 * *ton*).  Plus it is slow!  But it is the only way to do line-based
 * breakpoints from outside, and the only way to single step -- a step
 * is an opcode execution in PHP.
 *
 * Ok, we have a lot of opcode handlers we might need to breakpoint if
 * we wanted to catch all statements.  So we're going to give up on this
 * and only allow breakpoints on function/method calls.  Let's
 * breakpoint each FCALL opcode handler and hope for the best?  Do we
 * have to handle JMP handlers too?
 *
 * 
 * SYMBOLS:
 *
 * We want to *wait* until we hit an execution of a script before we
 * read the currently compiled global functions, vars, and types.  We do
 * *not* want to try to read them as they are parsed/compiled.  On the
 * other hand, this may lead us into problems later on where we have
 * dynamic compilation as a result of execution of a compiled scope.
 * XXX: what do we do at runtime as far as eval() and dynamic
 * types/functions go?  Vars we can handle by just doing a scope lookup
 * as necessary.  But wouldn't we have to catch the parsing functions
 * for types/functions?
 * 
 * But once we have an execution about to start, we scan the
 * compiler_globals struct and grab all the global vars, functions, and
 * types, and build symbols for them.  Then we need to check the
 * executor_globals struct for
 *
 *
 * UNWINDING:
 *
 * How do we walk the stack?  EG(argument_stack) ??
 * EG(current_execute_data) ??  xdebug builds a stack of function
 * invocations; can I get away without this?
 *
 *
 */

/*
 * Load it via tsrm_ls:
 *   *((zend_executor_globals *) (*((void ***) tsrm_ls))[6 - 1])
 *
 * Except we already did the first tsrm_ls deref when we loaded it.
 */
static struct value *php_TSRMG(struct target *target,ADDR tsrm_ls,int rsrc_id,
			       struct symbol *type) {
    ADDR ptr = tsrm_ls;

    if (!tsrm_ls) {
	errno = EINVAL;
	return NULL;
    }

    /* Deref the first pointer to the array. */
    /*
    ptr = 0;
    if (!target_read_addr(target->base,tsrm_ls,target->base->ptrsize,
			  (unsigned char *)&ptr)) {
	verror("could not read tsrm_ls 0x%"PRIxADDR"!\n",tsrm_ls);
	return NULL;
    }
    */

    /* Apply the unshuffled (rsrc_id - 1) rsrc_id index into the array. */
    ptr += (target->base->ptrsize * (rsrc_id - 1));

    /* Read it to get the pointer at that array index. */
    if (!target_read_addr(target->base,ptr,target->base->ptrsize,
			  (unsigned char *)&ptr)) {
	verror("could not read tsrm_ls idx %d (%d) 0x%"PRIxADDR
	       " (0x%"PRIxADDR")!\n",
	       rsrc_id - 1,rsrc_id,ptr,tsrm_ls);
	return NULL;
    }

    vdebug(5,LA_TARGET,LF_PHP,"TSRMG(0x%"PRIxADDR",%d,%s) about to load type\n",
	   ptr,rsrc_id,symbol_get_name(type));

    return target_load_type(target->base,type,ptr,LOAD_FLAG_AUTO_DEREF);
}

/*
 * Loads a member from the executor_globals struct.
 */
static struct value *php_EG(struct target *target,tid_t tid,char *name) {
    struct php_state *pstate = (struct php_state *)target->state;
    struct target_thread *tthread;
    struct php_thread_state *ptstate;
    struct value *retval = NULL;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return NULL;
    }
    ptstate = (struct php_thread_state *)tthread->state;

    /*
     * The only reason it would be unloaded would be if this was a
     * ZTS-enabled php; so handle that.
     */
    if (!ptstate->EG) {
	if (pstate->zts) {
	    if (!ptstate->ztsinfo.tsrm_ls) {
		verror("EG struct not yet loaded and no ZTS tsrm_ls yet!\n");
		return NULL;
	    }
	    else {
		ptstate->EG = php_TSRMG(target,ptstate->ztsinfo.tsrm_ls,
					pstate->ztsinfo.EG_id,
					pstate->_zend_executor_globals_type);
		if (!ptstate->EG) {
		    verror("could not load executor_globals struct"
			   " for thread %"PRIiTID"!\n",tid);
		    return NULL;
		}
	    }
	}
	else {
	    verror("EG not loaded for non-ZTS php -- BUG?!\n");
	    errno = EINVAL;
	    return NULL;
	}
    }
    else {
	vdebug(5,LA_TARGET,LF_PHP,"refreshing EG at 0x%"PRIxADDR"\n",
	       value_addr(ptstate->EG));
	/* Refresh the value. */
	value_refresh(ptstate->EG,0);
    }

    vdebug(5,LA_TARGET,LF_PHP,"about to load EG(%s) member\n",name);

    VLVAL(target->base,ptstate->base_tlctxt,ptstate->EG,name,
	  LOAD_FLAG_AUTO_DEREF | LOAD_FLAG_AUTO_STRING,&retval,errout);

    return retval;

 errout:
    verror("failed to load EG(%s) in thread %"PRIiTID"!\n",name,tid);
    return NULL;
}

#define PHP_UTIL_ZEND_HASH_APPLY_FREE       0
#define PHP_UTIL_ZEND_HASH_APPLY_SAVE  1 << 0
#define PHP_UTIL_ZEND_HASH_APPLY_STOP  1 << 1
typedef int (*php_util_zend_hash_apply_func_t)(struct target *target,
					       struct target_location_ctxt *tlctxt,
					       struct value *k,struct value *v,
					       void *priv);

static int php_util_zend_hash_apply(struct target *target,
				    struct target_location_ctxt *tlctxt,
				    struct value *zht,struct symbol *vtype,
				    php_util_zend_hash_apply_func_t f,
				    int f_wants_key,void *fpriv) {
    ADDR pData,pListNext;
    struct value *next_k,*next_v;
    struct value *bucket_v = NULL;
    struct value *next_bucket_v = NULL;
    int rc;

    /* Check if it's completely empty. */
    VLV(target,tlctxt,zht,"pListHead",LOAD_FLAG_NONE,&pListNext,NULL,errout);
    if (pListNext == 0) {
	vdebug(9,LA_TARGET,LF_PHP,"zend_hash 0x%"PRIxADDR" empty\n",
	       value_addr(zht));
	return 0;
    }
    pListNext = 0;

    VLVAL(target,tlctxt,zht,"pListHead",LOAD_FLAG_AUTO_DEREF,&bucket_v,errout);
    while (bucket_v) {
	VLVAR(target,tlctxt,bucket_v,"pData",LOAD_FLAG_NONE,&pData,
	      errout);
	VLVAR(target,tlctxt,bucket_v,"pListNext",LOAD_FLAG_NONE,&pListNext,
	      errout);

	if (!pData) {
	    verror("NULL data in zend_hash; skipping!\n");
	    goto next;
	}
	next_v = target_load_type(target,vtype,pData,LOAD_FLAG_AUTO_DEREF);
	if (!next_v) {
	    verror("could not load value of type '%s' at 0x%"PRIxADDR";"
		   " skipping!\n",
		   symbol_get_name(vtype),pData);
	    goto next;
	}
	if (f_wants_key) {
	    VLVAL(target,tlctxt,bucket_v,"arKey",LOAD_FLAG_AUTO_STRING,
		  &next_k,errout_key);

	    if (!next_k) {
	    errout_key:
		value_free(next_v);
		goto errout;
	    }
	}
	else
	    next_k = NULL;

	rc = f(target,tlctxt,next_k,next_v,fpriv);
	if (rc < 0) {
	    value_free(next_k);
	    value_free(next_v);
	    value_free(bucket_v);
	    return -1;
	}
	if (!(rc & PHP_UTIL_ZEND_HASH_APPLY_SAVE)) {
	    if (next_k)
		value_free(next_k);
	    value_free(next_v);
	}
	if (rc & PHP_UTIL_ZEND_HASH_APPLY_STOP) {
	    value_free(bucket_v);
	    return 0;
	}

	if (!pListNext) {
	    value_free(bucket_v);
	    return 0;
	}

    next:
	VLVAL(target,tlctxt,bucket_v,"pListNext",LOAD_FLAG_AUTO_DEREF,
	      &next_bucket_v,errout);
	value_free(bucket_v);
	bucket_v = next_bucket_v;
    }

 errout:
    verror("error loading member from zend_hash Bucket!\n");
    if (bucket_v)
	value_free(bucket_v);
    return -1;
}

/*
 * (Re-)Populate a PHP debugfile.
 *
 * NB: debugfiles are per-region, not per-thread!  This is technically
 * incorrect -- each PHP thread could have a different compiler/executor
 * state.  But we don't worry about that for now.
 *
 * Once we have addresses for the compiler_globals and executor_globals
 * structs, and have reached the first call to zend_execute, we can scan
 * the CG and EG values and dynamically generate symbols.
 *
 * 
 */

struct php_debugfile_info {
    struct target *target;
    struct debugfile *debugfile;
    struct symbol *current_symbol;
};

static struct symbol *php_debugfile_add_root(struct target *target,
					     struct debugfile *debugfile,
					     char *filename) {
    struct php_state *pstate = (struct php_state *)target->state;
    struct symbol *root;

    root = debugfile_lookup_root_name(debugfile,filename);
    if (root)
	return root;

    if (0 && strcmp(filename,"Reflection") == 0)
	asm("int $0x3");

    root = symbol_create(SYMBOL_TYPE_ROOT,SYMBOL_SOURCE_PHP,filename,1,
			 pstate->debugfile_symbol_counter++,
			 LOADTYPE_FULL,NULL);
    debugfile_insert_root(debugfile,root);

    return root;
}

/*
 * These came from ~5.5 php-src.
 */
#define PHP_ZEND_INTERNAL_FUNCTION		1U
#define PHP_ZEND_USER_FUNCTION			2U
#define PHP_ZEND_OVERLOADED_FUNCTION		3U
#define	PHP_ZEND_EVAL_CODE			4U
#define PHP_ZEND_OVERLOADED_FUNCTION_TEMPORARY	5U

static int php_debugfile_add_function(struct target *base,
				      struct target_location_ctxt *tlctxt,
				      struct value *zend_hash_key_v,
				      struct value *zend_function_v,
				      void *priv) {
    struct php_state *pstate;
    struct debugfile *debugfile;
    struct lsymbol *ls;
    struct symbol *symbol;
    struct value *v = NULL;
    unsigned int ftype = 0;
    struct symbol *root = NULL;
    struct target *target;
    struct php_debugfile_info *pdi;
    unsigned int num_args;
    ADDR arg_info_addr;
    struct symbol *arg_symbol;
    struct value *v2;
    unsigned int i;
    struct location *loc;
    int *argslot;
    unsigned int srcline = 0;

    pdi = (struct php_debugfile_info *)priv;
    target = pdi->target;
    debugfile = pdi->debugfile;
    pstate = (struct php_state *)target->state;

    /*
     * If this function is already in the debugfile via its address,
     * skip it!
     */
    ls = debugfile_lookup_addr(debugfile,value_addr(zend_function_v));
    if (ls) {
	lsymbol_release(ls);
	return PHP_UTIL_ZEND_HASH_APPLY_FREE;
    }

    VLV(tlctxt->thread->target,tlctxt,zend_function_v,"type",LOAD_FLAG_NONE,
	&ftype,NULL,errout);

    vdebug(5,LA_TARGET,LF_PHP,"zend_function 0x%"PRIxADDR" is type %d\n",
	   value_addr(zend_function_v),ftype);

    /*
     * If we are not adding this function to another symbol, then get or
     * create the root symbol.
     */
    if (!pdi->current_symbol) {
	if (ftype == PHP_ZEND_USER_FUNCTION) {
	    VLVAL(tlctxt->thread->target,tlctxt,zend_function_v,
		  "op_array.filename",LOAD_FLAG_AUTO_STRING,&v,errout);
	    VLVAR(tlctxt->thread->target,tlctxt,zend_function_v,
		  "op_array.line_start",LOAD_FLAG_NONE,&srcline,errout);

	    root = php_debugfile_add_root(base,debugfile,v_string(v));
	    if (v)
		value_free(v);
	}
	else if (ftype == PHP_ZEND_INTERNAL_FUNCTION) {
	    v = target_load_value_member(tlctxt->thread->target,tlctxt,
					 zend_function_v,
					 "internal_function.module.name",NULL,
					 LOAD_FLAG_AUTO_STRING);

	    root = php_debugfile_add_root(base,debugfile,
					  v ? v_string(v) : "__BUILTIN__");
	    if (v)
		value_free(v);
	}
	else 
	    goto out;
    }

    /* Now that we have the root symbol, create the function symbol. */
    v = target_load_value_member(tlctxt->thread->target,tlctxt,zend_function_v,
				 "common.function_name",NULL,
				 LOAD_FLAG_AUTO_STRING);
    if (!v) {
	verror("could not read function name for zend_function 0x%"PRIxADDR";"
	       " skipping!\n",value_addr(zend_function_v));
	goto errout;
    }

    if (pdi->current_symbol)
	symbol = symbol_create(SYMBOL_TYPE_FUNC,SYMBOL_SOURCE_PHP,v_string(v),1,
			       pstate->debugfile_symbol_counter++,LOADTYPE_FULL,
			       symbol_read_owned_scope(pdi->current_symbol));
    else
	symbol = symbol_create(SYMBOL_TYPE_FUNC,SYMBOL_SOURCE_PHP,v_string(v),1,
			       pstate->debugfile_symbol_counter++,LOADTYPE_FULL,
			       symbol_read_owned_scope(root));
    value_free(v);
    symbol_insert_symbol((pdi->current_symbol) ? pdi->current_symbol : root,
			 symbol);
    symbol_set_addr(symbol,value_addr(zend_function_v));
    symbol_set_srcline(symbol,(int)srcline);
    g_hash_table_insert(pstate->debugfile->addresses,
			(gpointer)(uintptr_t)symbol_get_addr(symbol),symbol);
    if (!pdi->current_symbol)
	debugfile_add_global(debugfile,symbol);

    /*
     * Ok, load the arguments.
     */
    VLVAR(tlctxt->thread->target,tlctxt,zend_function_v,"common.num_args",
	  LOAD_FLAG_NONE,&num_args,errout);
    VLVAR(tlctxt->thread->target,tlctxt,zend_function_v,"common.arg_info",
	  LOAD_FLAG_NONE,&arg_info_addr,errout);

    for (i = 0; i < num_args; ++i) {
	v = target_load_type(tlctxt->thread->target,pstate->zend_arg_info_type,
			     arg_info_addr,LOAD_FLAG_AUTO_DEREF);
	if (!v) {
	    vwarn("could not load arg %d for function %s",
		  i,symbol_get_name(symbol));
	    if (pdi->current_symbol)
		vwarnc(" in class %s\n",symbol_get_name(pdi->current_symbol));
	    else
		vwarnc("\n");
	    break;
	}

	VLVAL(tlctxt->thread->target,tlctxt,v,"name",LOAD_FLAG_AUTO_STRING,
	      &v2,errout);

	arg_symbol = symbol_create(SYMBOL_TYPE_VAR,SYMBOL_SOURCE_PHP,
				   v_string(v2),1,
				   pstate->debugfile_symbol_counter++,
				   LOADTYPE_FULL,symbol_read_owned_scope(symbol));
	symbol_set_parameter(arg_symbol);
	symbol_insert_symbol(symbol,arg_symbol);

	loc = location_create();
	argslot = malloc(sizeof(*argslot));
	*argslot = i;
	location_set_runtime(loc,(char *)argslot,sizeof(*argslot),0);
	symbol_set_location(arg_symbol,loc);

	value_free(v2);

	arg_info_addr += symbol_get_bytesize(pstate->zend_arg_info_type);
    }

 out:
    return PHP_UTIL_ZEND_HASH_APPLY_FREE;

 errout:
    verror("error parsing zend_function value at 0x%"PRIxADDR"!\n",
	   value_addr(zend_function_v));
    return PHP_UTIL_ZEND_HASH_APPLY_FREE;
}

static struct symbol *php_target_get_base_type_symbol(struct target *target,
						      php_base_symbol_t stype) {
    if (!PHP_ZEND_TYPE_IS_BASE(stype))
	return NULL;

    return ((struct php_state *)(target->state))->base_symbols[stype];
}

static int php_debugfile_add_constant(struct target *base,
				      struct target_location_ctxt *tlctxt,
				      struct value *zend_hash_key_v,
				      struct value *zend_zval_v,
				      void *priv) {
    struct php_state *pstate;
    struct symbol *symbol;
    unsigned char zvtype = 0;
    struct target *target;
    struct php_debugfile_info *pdi;
    char *buf;
    struct symbol *symbol_base_type;
    int symbol_base_type_size;

    pdi = (struct php_debugfile_info *)priv;
    target = pdi->target;
    pstate = (struct php_state *)target->state;

    if (!pdi->current_symbol) {
	errno = EINVAL;
	return -1;
    }
    if (!zend_hash_key_v || !v_string(zend_hash_key_v)) {
	errno = EINVAL;
	return -1;
    }

    VLVAR(tlctxt->thread->target,tlctxt,zend_zval_v,"type",LOAD_FLAG_NONE,
	  &zvtype,errout);

    if (PHP_ZEND_TYPE_IS_BASE(zvtype)) {
	vdebug(5,LA_TARGET,LF_PHP,
	       "class '%s' constant '%s' zval 0x%"PRIxADDR" is type %d\n",
	       symbol_get_name(pdi->current_symbol),v_string(zend_hash_key_v),
	       value_addr(zend_zval_v),(int)zvtype);
    }
    else {
	verror("class '%s' constant '%s' is non-base type %d; ignoring!\n",
	       symbol_get_name(pdi->current_symbol),v_string(zend_hash_key_v),
	       (int)zvtype);
	goto errout;
    }

    /* Create the constant symbol. */
    symbol = symbol_create(SYMBOL_TYPE_VAR,SYMBOL_SOURCE_PHP,
			   v_string(zend_hash_key_v),1,
			   pstate->debugfile_symbol_counter++,LOADTYPE_FULL,
			   symbol_read_owned_scope(pdi->current_symbol));
    symbol_base_type = php_target_get_base_type_symbol(target,zvtype);
    symbol->datatype = symbol_base_type;
    symbol_base_type_size = symbol_get_bytesize(symbol_base_type);
    if (zvtype == PHP_ZEND_NULL) {
	symbol_set_constval(symbol,NULL,0,0);
	goto out;
    }
    else if (zvtype == PHP_ZEND_LONG || zvtype == PHP_ZEND_BOOL) {
	buf = malloc(symbol_base_type_size);
	VLVAR(tlctxt->thread->target,tlctxt,zend_zval_v,"value.lval",
	      LOAD_FLAG_NONE,buf,errout);
	symbol_set_constval(symbol,buf,symbol_base_type_size,1);
    }
    else if (zvtype == PHP_ZEND_DOUBLE) {
	buf = malloc(symbol_base_type_size);
	VLVAR(tlctxt->thread->target,tlctxt,zend_zval_v,"value.dval",
	      LOAD_FLAG_NONE,buf,errout);
	symbol_set_constval(symbol,buf,symbol_base_type_size,1);
    }
    else if (zvtype == PHP_ZEND_STRING) {
	int slen;
	VLVAR(tlctxt->thread->target,tlctxt,zend_zval_v,"value.str.len",
	      LOAD_FLAG_NONE,&slen,errout);
	if (slen > 4096) {
	    verror("constant string length %d too big; skipping!\n",slen);
	    goto errout;
	}
	else if (slen < 1) {
	    verror("constant string length %d too small; skipping!\n",slen);
	    goto errout;
	}
	ADDR saddr;
	VLVAR(tlctxt->thread->target,tlctxt,zend_zval_v,"value.str.val",
	      LOAD_FLAG_NONE,&saddr,errout);
	buf = malloc(slen + 1);
	target_read_addr(tlctxt->thread->target,saddr,
			 (unsigned long)slen,(unsigned char *)buf);
	buf[slen] = '\0';
	symbol_set_constval(symbol,buf,slen,1);
    }
    symbol_insert_symbol(pdi->current_symbol,symbol);
    symbol_set_addr(symbol,value_addr(zend_zval_v));
    g_hash_table_insert(pstate->debugfile->addresses,
			(gpointer)(uintptr_t)symbol_get_addr(symbol),symbol);

 out:
    return PHP_UTIL_ZEND_HASH_APPLY_FREE;

 errout:
    verror("error parsing zval value at 0x%"PRIxADDR"!\n",
	   value_addr(zend_zval_v));
    return PHP_UTIL_ZEND_HASH_APPLY_FREE;
}

/*
 * These came from ~5.5 php-src.
 */
#define PHP_ZEND_INTERNAL_CLASS         1
#define PHP_ZEND_USER_CLASS             2

static int php_debugfile_add_class(struct target *base,
				   struct target_location_ctxt *tlctxt,
				   struct value *zend_hash_key_v,
				   struct value *zend_class_entry_v,
				   void *priv) {
    struct php_state *pstate;
    struct debugfile *debugfile;
    struct lsymbol *ls;
    struct symbol *symbol;
    struct symbol *old_current_symbol;
    struct value *v = NULL;
    char ctype = 0;
    struct symbol *root = NULL;
    struct php_debugfile_info *pdi;
    struct target *target;

    pdi = (struct php_debugfile_info *)priv;
    target = pdi->target;
    debugfile = pdi->debugfile;
    pstate = (struct php_state *)target->state;

    /*
     * If this class is already in the debugfile via its "address",
     * skip it!  Yes, this is a bad abuse of the symbol address field,
     * but we do it anyway!
     */
    ls = debugfile_lookup_addr(debugfile,value_addr(zend_class_entry_v));
    if (ls) {
	lsymbol_release(ls);
	return PHP_UTIL_ZEND_HASH_APPLY_FREE;
    }

    VLVAR(tlctxt->thread->target,tlctxt,zend_class_entry_v,"type",
	  LOAD_FLAG_NONE,&ctype,errout);

    vdebug(5,LA_TARGET,LF_PHP,"zend_class_entry 0x%"PRIxADDR" is type %d\n",
	   value_addr(zend_class_entry_v),(int)ctype);

    /* Get or create the root symbol if we don't have a current symbol. */
    if (!pdi->current_symbol) {
	if (ctype == PHP_ZEND_USER_CLASS) {
	    VLVAL(tlctxt->thread->target,tlctxt,zend_class_entry_v,
		  "info.user.filename",LOAD_FLAG_AUTO_STRING,&v,errout);

	    root = php_debugfile_add_root(base,debugfile,v_string(v));
	    value_free(v);
	}
	else if (ctype == PHP_ZEND_INTERNAL_CLASS) {
	    v = target_load_value_member(tlctxt->thread->target,tlctxt,
					 zend_class_entry_v,
					 "info.internal.module.name",NULL,
					 LOAD_FLAG_AUTO_STRING);

	    root = php_debugfile_add_root(base,debugfile,
					  v ? v_string(v) : "__BUILTIN__");
	    if (v)
		value_free(v);
	}
	else 
	    goto out;
    }

    /* Now that we have the root symbol, create the class symbol. */
    v = target_load_value_member(tlctxt->thread->target,tlctxt,
				 zend_class_entry_v,"name",NULL,
				 LOAD_FLAG_AUTO_STRING);
    if (!v) {
	verror("could not read class name for zend_class_entry 0x%"PRIxADDR";"
	       " skipping!\n",value_addr(zend_class_entry_v));
	goto errout;
    }

    if (pdi->current_symbol)
	symbol = symbol_create(SYMBOL_TYPE_TYPE,SYMBOL_SOURCE_PHP,v_string(v),1,
			       pstate->debugfile_symbol_counter++,LOADTYPE_FULL,
			       symbol_read_owned_scope(pdi->current_symbol));
    else
	symbol = symbol_create(SYMBOL_TYPE_TYPE,SYMBOL_SOURCE_PHP,v_string(v),1,
			       pstate->debugfile_symbol_counter++,LOADTYPE_FULL,
			       symbol_read_owned_scope(root));
    value_free(v);
    symbol_insert_symbol((pdi->current_symbol) ? pdi->current_symbol : root,
			 symbol);
    symbol->datatype_code = DATATYPE_CLASS;
    symbol_set_addr(symbol,value_addr(zend_class_entry_v));
    g_hash_table_insert(pstate->debugfile->addresses,
			(gpointer)(uintptr_t)symbol_get_addr(symbol),symbol);
    if (!pdi->current_symbol)
	debugfile_add_type(debugfile,symbol);

    /*
     * Read member functions, properties, constants.
     *
     * NB: someday support traits!
     */
    v = target_load_value_member(tlctxt->thread->target,tlctxt,
				 zend_class_entry_v,"function_table",NULL,
				 LOAD_FLAG_AUTO_DEREF);
    if (!v) {
	verror("could not load function_table for class '%s'; skipping it!\n",
	       symbol_get_name(symbol));
    }
    else {
	old_current_symbol = pdi->current_symbol;
	pdi->current_symbol = symbol;
	php_util_zend_hash_apply(tlctxt->thread->target,tlctxt,v,
				 pstate->zend_function_type,
				 php_debugfile_add_function,0,pdi);
	pdi->current_symbol = old_current_symbol;
	value_free(v);
    }

    /* Constants. */
    v = target_load_value_member(tlctxt->thread->target,tlctxt,
				 zend_class_entry_v,"constants_table",NULL,
				 LOAD_FLAG_AUTO_DEREF);
    if (!v) {
	verror("could not load constants_table for class '%s'; skipping it!\n",
	       symbol_get_name(symbol));
    }
    else {
	old_current_symbol = pdi->current_symbol;
	pdi->current_symbol = symbol;
	php_util_zend_hash_apply(tlctxt->thread->target,tlctxt,v,
				 pstate->zend_zval_ptr_type,
				 php_debugfile_add_constant,1,pdi);
	pdi->current_symbol = old_current_symbol;
	value_free(v);
    }

 out:
    return PHP_UTIL_ZEND_HASH_APPLY_FREE;

 errout:
    verror("error parsing zend_class_entry value at 0x%"PRIxADDR"!\n",
	   value_addr(zend_class_entry_v));
    return PHP_UTIL_ZEND_HASH_APPLY_FREE;
}

static int php_populate_debugfile(struct target *target,
				  struct debugfile *debugfile) {
    struct php_state *pstate;
    struct target *base;
    struct php_thread_state *gptstate;
    struct target_location_ctxt *base_tlctxt;
    struct value *v;
    struct php_debugfile_info pdi;

    pdi.target = target;
    pdi.debugfile = debugfile;
    pdi.current_symbol = NULL;

    pstate = (struct php_state *)target->state;
    base = target->base;
    gptstate = (struct php_thread_state *)target->global_thread->state;
    base_tlctxt = gptstate->base_tlctxt;

    v = php_EG(target,base_tlctxt->thread->tid,"function_table");
    if (!v) {
	verror("could not load EG(function_table)!\n");
	return -1;
    }

    php_util_zend_hash_apply(base,base_tlctxt,v,pstate->zend_function_type,
			     php_debugfile_add_function,0,&pdi);
    value_free(v);

    v = php_EG(target,base_tlctxt->thread->tid,"class_table");
    if (!v) {
	verror("could not load EG(class_table)!\n");
	return -1;
    }

    php_util_zend_hash_apply(base,base_tlctxt,v,
			     pstate->zend_class_entry_ptr_type,
			     php_debugfile_add_class,0,&pdi);
    value_free(v);

    struct dump_info ud = {
	.stream = stderr,
	.prefix = "    ",
	.meta = 1,
	.detail = 1,
    };

    debugfile_dump(debugfile,&ud,1,1,1,1,1);

    return 0;
}

/*
 * Convert a zhash to a ghashtable.  The string keys we strdup and set a
 * key destructor; the values are target(void *) unsigned long ints (so
 * there is no dtor for them).  So the caller just has to
 * g_hash_table_destroy() when finished.
 *
 * NB: the caller has to cast the values and load them by type to do
 * much useful stuff.
 */
GHashTable *php_zhash_to_ghash(struct target *target,struct value *zhash);

#define php_zhash_foreach_loadtype(target,zhash_val,lpc,value,value_type) 

/*
 * Loads the value as type @type, if it exists.
 */
struct value *php_zhash_find(struct target *target,struct value *zhash,char *key,
			     struct symbol *type);



struct php_spec *php_build_spec(void) {
    struct php_spec *pspec;

    pspec = calloc(1,sizeof(*pspec));

    return pspec;
}

void php_free_spec(struct php_spec *spec) {
    free(spec);
}

/*
 * Prototypes.
 */
static int php_snprintf(struct target *target,char *buf,int bufsiz);
static int php_init(struct target *target);
static int php_postloadinit(struct target *target);
static int php_attach(struct target *target);
static int php_detach(struct target *target);
static int php_fini(struct target *target);
static int php_loadspaces(struct target *target);
static int php_loadregions(struct target *target,struct addrspace *space);
static int php_loaddebugfiles(struct target *target,
			      struct addrspace *space,struct memregion *region);

static target_status_t php_status(struct target *target);
static int php_pause(struct target *target,int nowait);
static int php_resume(struct target *target);
static unsigned char *php_read(struct target *target,ADDR addr,
			       unsigned long length,unsigned char *buf);
static unsigned long php_write(struct target *target,ADDR addr,
			       unsigned long length,unsigned char *buf);
static struct value *php_read_symbol(struct target *target,
				     struct target_location_ctxt *tlctxt,
				     struct bsymbol *bsymbol,
				     load_flags_t flags);
static char *php_reg_name(struct target *target,REG reg);
static REG php_dwregno_targetname(struct target *target,char *name);
static REG php_dw_reg_no(struct target *target,common_reg_t reg);

static tid_t php_gettid(struct target *target);
static void php_free_thread_state(struct target *target,void *state);
static struct array_list *php_list_available_tids(struct target *target);
static struct target_thread *php_load_thread(struct target *target,
					     tid_t tid,int force);
static struct target_thread *php_load_current_thread(struct target *target,
						     int force);
static int php_load_all_threads(struct target *target,int force);
static int php_load_available_threads(struct target *target,int force);
static int php_flush_thread(struct target *target,tid_t tid);
static int php_flush_current_thread(struct target *target);
static int php_flush_all_threads(struct target *target);
static int php_invalidate_all_threads(struct target *target);
static int php_thread_snprintf(struct target_thread *tthread,
			       char *buf,int bufsiz,
			       int detail,char *sep,char *kvsep);
static REGVAL php_read_reg(struct target *target,tid_t tid,REG reg);
static int php_write_reg(struct target *target,tid_t tid,REG reg,REGVAL value);
static GHashTable *php_copy_registers(struct target *target,tid_t tid);

static struct target_location_ctxt *php_unwind(struct target *target,tid_t tid);
static int php_unwind_read_reg(struct target_location_ctxt *tlctxt,
			       REG reg,REGVAL *o_regval);
static struct target_location_ctxt_frame *
php_unwind_prev(struct target_location_ctxt *tlctxt);

static int php_probe_register_symbol(struct target *target,tid_t tid,
				     struct probe *probe,struct bsymbol *bsymbol,
				     probepoint_style_t style,
				     probepoint_whence_t whence,
				     probepoint_watchsize_t watchsize);

int php_singlestep(struct target *target,tid_t tid,int isbp,
		   struct target *overlay);
int php_singlestep_end(struct target *target,tid_t tid,
		       struct target *overlay);


struct target_ops php_ops = {
    .snprintf = php_snprintf,

    .init = php_init,
    .fini = php_fini,
    .attach = php_attach,
    .detach = php_detach,
    .kill = NULL,
    .loadspaces = php_loadspaces,
    .loadregions = php_loadregions,
    .loaddebugfiles = php_loaddebugfiles,
    .postloadinit = php_postloadinit,

    /* Don't support overlays at all. */
    .instantiate_overlay = NULL,

    .status = php_status,
    .pause = php_pause,
    .resume = php_resume,
    .monitor = NULL,
    .poll = NULL,
    .read = php_read,
    .write = php_write,

    .read_symbol = php_read_symbol,

    .regname = php_reg_name,
    .dwregno_targetname = php_dwregno_targetname,
    .dwregno = php_dw_reg_no,

    .gettid = php_gettid,
    .free_thread_state = php_free_thread_state,

    /* There are never any untracked threads in this target. */
    .list_available_tids = target_list_tids,
    /* There are never any untracked threads in this target. */
    .load_available_threads = php_load_all_threads,
    .load_thread = php_load_thread,
    .load_current_thread = php_load_current_thread,
    .load_all_threads = php_load_all_threads,
    .pause_thread = NULL,
    .flush_thread = php_flush_thread,
    .flush_current_thread = php_flush_current_thread,
    .flush_all_threads = php_flush_all_threads,
    .invalidate_all_threads = php_invalidate_all_threads,
    .thread_snprintf = php_thread_snprintf,

    .attach_evloop = NULL,
    .detach_evloop = NULL,

    .readreg = php_read_reg,
    .writereg = php_write_reg,
    .copy_registers = php_copy_registers,

    .unwind = php_unwind,
    .unwind_read_reg = php_unwind_read_reg,
    .unwind_prev = php_unwind_prev,

    .probe_register_symbol = php_probe_register_symbol,

    .singlestep = php_singlestep,
    .singlestep_end = php_singlestep_end,
};

static int php_snprintf(struct target *target,char *buf,int bufsiz) {
    return snprintf(buf,bufsiz,"php(%d)",target->base_tid);
}

static int php_init(struct target *target) {
    struct php_state *pstate;
    struct target_thread *base_thread = target->base_thread;
    struct php_thread_state *ptstate;
    struct target *base = target->base;
    tid_t base_tid = target->base_tid;

    /*
     * Setup target mode stuff.
     */
    target->threadctl = 0;
    target->live = base->live;
    target->writeable = base->writeable;
    target->mmapable = 0;
    /* NB: only native arch supported!  i.e., no 32-bit emu on 64-bit host. */
    target->endian = base->endian;
    target->wordsize = base->wordsize;
    target->ptrsize = base->ptrsize;

    /* Which register is the fbreg is dependent on host cpu type, not
     * target cpu type.
     */
#if __WORDSIZE == 64
    target->fbregno = 6;
    target->spregno = 7;
    target->ipregno = 16;
#else
    target->fbregno = 5;
    target->spregno = 4;
    target->ipregno = 8;
#endif

    /*
     * Make sure the base thread is loaded.
     */
    if (!(base_thread = target_load_thread(base,base_tid,0))) {
	verror("could not load base tid %d!\n",base_tid);
	return -1;
    }
    else if (base_thread != target->base_thread) {
	/*
	 * Catch stale threads; if there is a huge delay between
	 * target_instantiate and target_open, this could potentially
	 * happen -- but PID wraparound in the kernel would have to
	 * happen mighty fast!  Unlikely.
	 */
	vwarn("target->base_thread does not match with just-loaded thread"
	      " for %d; pid wraparound caused stale thread??\n",base_tid);
	target->base_thread = base_thread;
    }

    /*
     * Just adjust for the user, don't error :)
     */
    if (target->spec->bpmode == THREAD_BPMODE_STRICT) {
	vwarn("auto-enabling SEMI_STRICT bpmode on PHP target.\n");
	target->spec->bpmode = THREAD_BPMODE_SEMI_STRICT;
    }

    /*
     * Initialize our state.
     */
    target->state = pstate = calloc(1,sizeof(struct php_state));

    target->location_ops = &php_location_ops;

    /*
     * XXX: for now, just create a thread for the primary thread.
     */
    ptstate = calloc(1,sizeof(*ptstate));
    ptstate->base_tlctxt = 
	target_location_ctxt_create(base,target->base_tid,NULL);
    target->current_thread = target_create_thread(target,base_tid,ptstate);
    target_reuse_thread_as_global(target,target->current_thread);
    target_thread_set_status(target->current_thread,THREAD_STATUS_RUNNING);

    /*
     * Don't do anything else here; do it in attach().
     */
    return 0;
}

static int php_fini(struct target *target) {
    return 0;
}

/*
 * As described in the notes, first check if ZTS (thread safety) was
 * compiled in.  If not, everything is very easy.  If so, try to find
 * the thread-local storage pointer by unwinding the stack and finding
 * zend_execute_scripts.  If the stack doesn't include this
 *
 * XXX: eventually, we'll have to check the zend_execute and
 * zend_execute_internal pointers and break on those functions instead
 * of execute and execute_internal (and in later versions,
 * zend_execute_ex and execute_ex) to make sure we catch phps running
 * with dtrace or xdebug.
 */
static int php_attach(struct target *target) {
    struct php_state *pstate = (struct php_state *)target->state;
    struct php_thread_state *ptstate;
    struct target *base = target->base;
    struct bsymbol *bsymbol;
    struct symbol *arg;
    struct value *v;
    struct target_location_ctxt *tlctxt = NULL;
    struct target_location_ctxt_frame *tlctxtf = NULL;
    struct addrspace *space;
    struct memregion *region = NULL;
    ADDR derefed_tsrm_ls = 0;

    ptstate = (struct php_thread_state *)target->global_thread->state;

    if (target_pause(base)) {
	verror("could not pause base target %s!\n",base->name);
	return -1;
    }

    target_set_status(target,TSTATUS_PAUSED);

    /* Create a default lookup/load context. */
    /* Cheat: grab the first region :). */
    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    break;
	}
	break;
    }

    pstate->default_tlctxt = 
	target_location_ctxt_create(target,target->base_tid,region);

    /*
     * Figure out if this php has ZTS (thread safety) or not.
     */
    bsymbol = target_lookup_sym(base,"compiler_globals",NULL,NULL,
				SYMBOL_TYPE_FLAG_NONE);
    if (!bsymbol) {
	vdebug(3,LA_TARGET,LF_PHP,
	       "could not find compiler_globals; checking for ZTS\n");

	bsymbol = target_lookup_sym(base,"compiler_globals_id",NULL,NULL,
				    SYMBOL_TYPE_FLAG_NONE);
	if (!bsymbol) {
	    verror("could not find compiler_globals nor compiler_globals_id;"
		   " cannot attach to this PHP!\n");
	    errno = ENOTSUP;
	    return -1;
	}
	ptstate->base_tlctxt->region = bsymbol->region;
	bsymbol_release(bsymbol);

	tlctxt = target_location_ctxt_create_from_bsymbol(base,target->base_tid,
							  bsymbol);

	/* We have a threaded php. */
	pstate->zts = 1;

	/* Grab the TLS resource ids we need. */
	VLS(base,ptstate->base_tlctxt,"compiler_globals_id",LOAD_FLAG_NONE,
	    &pstate->ztsinfo.CG_id,NULL,errout);
	VLS(base,ptstate->base_tlctxt,"executor_globals_id",LOAD_FLAG_NONE,
	    &pstate->ztsinfo.EG_id,NULL,errout);
    }
    else {
	tlctxt = target_location_ctxt_create_from_bsymbol(base,target->base_tid,
							  bsymbol);
	ptstate->base_tlctxt->region = bsymbol->region;

	pstate->zts = 0;

	/* We will reload these later. */
	VLS(base,ptstate->base_tlctxt,"compiler_globals",LOAD_FLAG_NONE,
	    NULL,&ptstate->CG,errout);
	VLS(base,ptstate->base_tlctxt,"executor_globals",LOAD_FLAG_NONE,
	    NULL,&ptstate->EG,errout);

	bsymbol_release(bsymbol);
    }

    /*
     * Grab some types.
     */
    bsymbol = target_lookup_sym(base,"struct _zend_compiler_globals",NULL,NULL,
				SYMBOL_TYPE_FLAG_TYPE);
    if (!bsymbol) {
	verror("could not lookup struct _zend_compiler_globals; fatal!\n");
	return -1;
    }
    pstate->_zend_compiler_globals_type = bsymbol_get_symbol(bsymbol);
    RHOLD(pstate->_zend_compiler_globals_type,pstate);
    bsymbol_release(bsymbol);

    bsymbol = target_lookup_sym(base,"struct _zend_executor_globals",NULL,NULL,
				SYMBOL_TYPE_FLAG_TYPE);
    if (!bsymbol) {
	verror("could not lookup struct _zend_executor_globals; fatal!\n");
	return -1;
    }
    pstate->_zend_executor_globals_type = bsymbol_get_symbol(bsymbol);
    RHOLD(pstate->_zend_executor_globals_type,pstate);
    bsymbol_release(bsymbol);

    bsymbol = target_lookup_sym(base,"union _zend_function",NULL,NULL,
				SYMBOL_TYPE_FLAG_TYPE);
    if (!bsymbol) {
	verror("could not lookup union _zend_function; fatal!\n");
	return -1;
    }
    pstate->zend_function_type = bsymbol_get_symbol(bsymbol);
    RHOLD(pstate->zend_function_type,pstate);
    bsymbol_release(bsymbol);

    bsymbol = target_lookup_sym(base,"struct _zend_class_entry",NULL,NULL,
				SYMBOL_TYPE_FLAG_TYPE);
    if (!bsymbol) {
	verror("could not lookup struct _zend_class_entry; fatal!\n");
	return -1;
    }
    /* NB: the things in the class table are pointers to class_entry structs. */
    pstate->zend_class_entry_ptr_type = 
	target_create_synthetic_type_pointer(base,bsymbol_get_symbol(bsymbol));
    RHOLD(pstate->zend_class_entry_ptr_type,pstate);
    bsymbol_release(bsymbol);

    bsymbol = target_lookup_sym(base,"struct _zval_struct",NULL,NULL,
				SYMBOL_TYPE_FLAG_TYPE);
    if (!bsymbol) {
	verror("could not lookup struct _zval_struct; fatal!\n");
	return -1;
    }
    /* NB: we need both the struct AND pointers to zval structs. */
    pstate->zend_zval_type = bsymbol_get_symbol(bsymbol);
    RHOLD(pstate->zend_zval_type,pstate);
    pstate->zend_zval_ptr_type = 
	target_create_synthetic_type_pointer(base,bsymbol_get_symbol(bsymbol));
    RHOLD(pstate->zend_zval_ptr_type,pstate);
    bsymbol_release(bsymbol);

    bsymbol = target_lookup_sym(base,"struct _zend_arg_info",NULL,NULL,
				SYMBOL_TYPE_FLAG_TYPE);
    if (!bsymbol) {
	verror("could not lookup struct _zend_arg_info; fatal!\n");
	return -1;
    }
    pstate->zend_arg_info_type = bsymbol_get_symbol(bsymbol);
    RHOLD(pstate->zend_arg_info_type,pstate);
    bsymbol_release(bsymbol);




    bsymbol = target_lookup_sym(base,"zend_do_fcall_common_helper_SPEC",
				NULL,NULL,SYMBOL_TYPE_FLAG_FUNC);
    if (!bsymbol) {
	verror("could not lookup zend_do_fcall_common_helper_SPEC;"
	       " cannot probe; fatal\n");
	return -1;
    }
    pstate->fprobe_func = bsymbol;
    RHOLD(pstate->fprobe_func,pstate);
    bsymbol_release(bsymbol);

    bsymbol = target_lookup_sym_member(base,pstate->fprobe_func,
				       "execute_data",NULL);
    if (!bsymbol) {
	verror("could not lookup zend_do_fcall_common_helper_SPEC.execute_data arg"
	       "; cannot probe; fatal!\n");
	return -1;
    }
    pstate->fprobe_func_execute_data_arg = bsymbol;
    RHOLD(pstate->fprobe_func_execute_data_arg,pstate);
    bsymbol_release(bsymbol);

    bsymbol = target_lookup_sym(base,"zend_leave_helper_SPEC",
				NULL,NULL,SYMBOL_TYPE_FLAG_FUNC);
    if (!bsymbol) {
	verror("could not lookup zend_leave_helper_SPEC;"
	       " cannot probe; fatal\n");
	return -1;
    }
    pstate->fprobe_func_return = bsymbol;
    RHOLD(pstate->fprobe_func_return,pstate);
    bsymbol_release(bsymbol);

    /*
     * See if we attached to a running PHP (if zend_execute_scripts is
     * part of our unwind stack).  If so, and if ZTS was compiled in,
     * grab our TLS base pointer.  Otherwise, insert a probe on
     * zend_execute_scripts to know when execution is going to begin.
     */
    if (target_location_ctxt_unwind(tlctxt)) {
	verror("failed to unwind stack to see if php is executing scripts;"
	       " will probe for execution!\n");
    }
    else {
	tlctxtf = target_location_ctxt_current_frame(tlctxt);
	while (tlctxtf) {
	    if (!bsymbol_get_name(tlctxtf->bsymbol) 
		|| strcmp("zend_execute_scripts",
			  bsymbol_get_name(tlctxtf->bsymbol))) {
		tlctxtf = target_location_ctxt_prev(tlctxt);
		continue;
	    }

	    ptstate->is_executing = 1;

	    /* If we have ZTS compiled in, grab the TLS base pointer. */
	    if (pstate->zts) {
		arg = symbol_get_member(bsymbol_get_symbol(tlctxtf->bsymbol),
					"tsrm_ls",NULL);
		if (!arg) {
		    verror("could not find 'tsrm_ls' arg to '%s'; cannot"
			   " infer TLS base pointer for PHP thread %d!\n",
			   bsymbol_get_name(tlctxtf->bsymbol),target->base_tid);
		    goto errout;
		}
		v = target_load_symbol_member(base,tlctxt,tlctxtf->bsymbol,
					      "tsrm_ls",NULL,LOAD_FLAG_NONE);
		if (!v) {
		    verror("could not load 'tsrm_ls' arg to '%s'; cannot"
			   " infer TLS base pointer for PHP thread %d!\n",
			   bsymbol_get_name(tlctxtf->bsymbol),target->base_tid);
		    goto errout;
		}

		ptstate->ztsinfo.tsrm_ls = v_addr(v);
		value_free(v);

		/* Deref the first pointer to the array. */
		if (!target_read_addr(target->base,ptstate->ztsinfo.tsrm_ls,
				      target->base->ptrsize,
				      (unsigned char *)&derefed_tsrm_ls)) {
		    verror("could not read tsrm_ls 0x%"PRIxADDR"!\n",
			   ptstate->ztsinfo.tsrm_ls);
		    goto errout;
		}

		vdebug(5,LA_TARGET,LF_PHP,
		       "tsrm_ls=0x%"PRIxADDR", *tsrm_ls=0x%"PRIxADDR"\n",
		       ptstate->ztsinfo.tsrm_ls,derefed_tsrm_ls);

		ptstate->ztsinfo.tsrm_ls = derefed_tsrm_ls;
	    }

	    break;
	}
    }

    if (tlctxt) 
	target_location_ctxt_free(tlctxt);

    if (ptstate->is_executing && pstate->zts && !ptstate->ztsinfo.tsrm_ls) {
	vwarn("PHP thread %d is executing scripts, but could not find"
	      " tsrm_ls; will look later!\n",target->base_tid);
    }
    else if (ptstate->is_executing)
	php_populate_debugfile(target,pstate->debugfile);

    return 0;

 errout:
    if (tlctxt)
	target_location_ctxt_free(tlctxt);
    return -1;
}

static int php_detach(struct target *target) {
    /*
     * Just detach all our threads.
     */
    return 0;
}

static int php_loadspaces(struct target *target) {
    struct addrspace *space = addrspace_create(target,"php",target->base_tid);

    space->target = target;
    RHOLD(space,target);

    list_add_tail(&space->space,&target->spaces);

    return 0;
}

/*
 * PHP just has a single region and range.  Hm, or should they also have
 * ranges for each extension???  Shoot, probably yes.  Plus we have to
 * technically suck in the heap/stack from the underlying process.  Hm,
 * maybe we should just sort of clone the underlying one.
 * 
 * No, the right choice is to just have a single region/range that is
 * updated to cover the sum of the underlying regions/ranges.  Then
 * region/range protection is free due to the underlying target.
 *
 * It's either that or create a single debugfile that is linked to each
 * region.  Either way, I think the right thing here is to rely on
 * the base target's active probing to generate events for us, and
 * either grow our mirrored regions/ranges, or expand/reduce the big
 * main one.
 */
static int php_loadregions(struct target *target,struct addrspace *space) {
    struct memregion *region;
    struct memrange *range;

    region = memregion_create(space,REGION_TYPE_MAIN,"PHP");
    if (!region)
	return -1;
    /* XXX: use underlying target bounds! */
    range = memrange_create(region,0,ADDRMAX,0,
			    PROT_READ | PROT_WRITE | PROT_EXEC);
    if (!range)
	return -1;

    return 0;
}

/*
 * PHP regions have a single debugfile that is dynamically built.
 */
static int php_loaddebugfiles(struct target *target,
			      struct addrspace *space,
			      struct memregion *region) {
    struct php_state *pstate = (struct php_state *)target->state;
    struct php_thread_state *gptstate;
    struct symbol *builtin_root;
    struct symbol *base;
    char buf[64];

    vdebug(5,LA_TARGET,LF_XVP,"tid %d\n",target->base_tid);

    pstate->debugfile_symbol_counter = 0;

    php_snprintf(target,buf,sizeof(buf));
    pstate->debugfile = debugfile_create_basic(DEBUGFILE_TYPE_PHP,
					       DEBUGFILE_TYPE_FLAG_NONE,
					       buf,DEBUGFILE_LOAD_FLAG_NONE);
    if (!pstate->debugfile)
	return -1;

    if (target_associate_debugfile(target,region,pstate->debugfile)) {
	debugfile_free(pstate->debugfile,1);
	return -1;
    }

    pstate->base_symbols = calloc(PHP_BASE_SYMBOL_COUNT,sizeof(struct symbol *));

    /*
     * Add in the base types into the special __BUILTIN__ file.
     */
    builtin_root = php_debugfile_add_root(target,pstate->debugfile,"__BUILTIN__");
    pstate->builtin_root = builtin_root;

    base = symbol_create(SYMBOL_TYPE_TYPE,SYMBOL_SOURCE_PHP,"null",1,
			 pstate->debugfile_symbol_counter++,
			 LOADTYPE_FULL,symbol_read_owned_scope(builtin_root));
    base->datatype_code = DATATYPE_VOID;
    symbol_insert_symbol(builtin_root,base);
    pstate->base_symbols[PHP_BASE_NULL] = base;

    /*
     * NB: all values are encoded in PHP's _zval_value union as either
     * long, double, str { char *val;int len; }, HashTable *,
     * zend_object_value obj.  Thus, it is best to make the basic
     * numeric types be of size target->wordsize.
     */

    base = symbol_create(SYMBOL_TYPE_TYPE,SYMBOL_SOURCE_PHP,"bool",1,
			 pstate->debugfile_symbol_counter++,
			 LOADTYPE_FULL,symbol_read_owned_scope(builtin_root));
    base->datatype_code = DATATYPE_BASE;
    symbol_set_encoding(base,ENCODING_BOOLEAN);
    symbol_set_bytesize(base,target->wordsize);
    symbol_insert_symbol(builtin_root,base);
    pstate->base_symbols[PHP_BASE_BOOL] = base;

    base = symbol_create(SYMBOL_TYPE_TYPE,SYMBOL_SOURCE_PHP,"long",1,
			 pstate->debugfile_symbol_counter++,
			 LOADTYPE_FULL,symbol_read_owned_scope(builtin_root));
    base->datatype_code = DATATYPE_BASE;
    symbol_set_encoding(base,ENCODING_SIGNED);
    symbol_set_bytesize(base,target->wordsize);
    symbol_insert_symbol(builtin_root,base);
    pstate->base_symbols[PHP_BASE_LONG] = base;

    base = symbol_create(SYMBOL_TYPE_TYPE,SYMBOL_SOURCE_PHP,"double",1,
			 pstate->debugfile_symbol_counter++,
			 LOADTYPE_FULL,symbol_read_owned_scope(builtin_root));
    base->datatype_code = DATATYPE_BASE;
    symbol_set_encoding(base,ENCODING_FLOAT);
    symbol_set_bytesize(base,target->wordsize);
    symbol_insert_symbol(builtin_root,base);
    pstate->base_symbols[PHP_BASE_DOUBLE] = base;

    base = symbol_create(SYMBOL_TYPE_TYPE,SYMBOL_SOURCE_PHP,"string",1,
			 pstate->debugfile_symbol_counter++,
			 LOADTYPE_FULL,symbol_read_owned_scope(builtin_root));
    base->datatype_code = DATATYPE_BASE;
    symbol_set_encoding(base,ENCODING_STRING);
    symbol_insert_symbol(builtin_root,base);
    pstate->base_symbols[PHP_BASE_STRING] = base;

    base = symbol_create(SYMBOL_TYPE_TYPE,SYMBOL_SOURCE_PHP,"array",1,
			 pstate->debugfile_symbol_counter++,
			 LOADTYPE_FULL,symbol_read_owned_scope(builtin_root));
    base->datatype_code = DATATYPE_BASE;
    symbol_set_encoding(base,ENCODING_HASH);
    symbol_insert_symbol(builtin_root,base);
    pstate->base_symbols[PHP_BASE_HASH] = base;

    /*
     * If we're already executing, try to populate the debugfile!
     */
    gptstate = (struct php_thread_state *)target->global_thread->state;
    if (gptstate->is_executing) 
	php_populate_debugfile(target,pstate->debugfile);

    return 0;
}

static int php_postloadinit(struct target *target) {

    return 0;
}

static int php_set_active_probing(struct target *target,
				  active_probe_flags_t flags) {
    verror("active probing not supported\n");
    errno = ENOTSUP;
    return -1;
}

static target_status_t php_status(struct target *target) {
    return target_status(target->base);
}

static int php_pause(struct target *target,int nowait) {
    int rc;

    rc = target_pause(target->base);
    if (rc) 
	return rc;
    target_set_status(target,target->base->status);

    return 0;
}

static int php_resume(struct target *target) {
    int rc;

    rc = target_resume(target->base);
    if (rc) 
	return rc;
    target_set_status(target,target->base->status);

    return 0;
}

static unsigned char *php_read(struct target *target,ADDR addr,
			       unsigned long length,unsigned char *buf) {
    return target->base->ops->read(target->base,addr,length,buf);
}

static unsigned long php_write(struct target *target,ADDR addr,
			       unsigned long length,unsigned char *buf) {
    return target->base->ops->write(target->base,addr,length,buf);
}

static struct value *php_zval_to_value(struct target *target,
				       struct target_location_ctxt *tlctxt,
				       struct value *zval_v,
				       struct bsymbol *bsymbol) {
    struct php_state *pstate;
    struct php_thread_state *ptstate;
    unsigned char zvtype = 0;
    struct value *v = NULL;
    struct lsymbol *lsymbol;
    //struct symbol *symbol;
    //struct symbol *datatype;

    pstate = (struct php_state *)target->state;
    ptstate = (struct php_thread_state *)tlctxt->thread->state;

    if (bsymbol) {
	lsymbol = bsymbol_get_lsymbol(bsymbol);
	//symbol = bsymbol_get_symbol(bsymbol);
	//datatype = symbol_get_datatype(symbol);
    }
    else {
	lsymbol = NULL;
	//symbol = NULL;
	//datatype = NULL;
    }

    VLVAR(target->base,ptstate->base_tlctxt,zval_v,"type",
	  LOAD_FLAG_NONE,&zvtype,errout);

    /*
     * Remember, use the zval's datatype, not the symbol's (if any),
     * because the zval has dynamic type.
     */
    if (zvtype == PHP_ZEND_NULL) {
	v = value_create_noalloc(tlctxt->thread,NULL,lsymbol,
				 pstate->base_symbols[zvtype]);
    }
    else if (zvtype == PHP_ZEND_LONG || zvtype == PHP_ZEND_BOOL) {
	v = value_create(tlctxt->thread,NULL,lsymbol,
			 pstate->base_symbols[zvtype]);
	VLVAR(target->base,ptstate->base_tlctxt,zval_v,"value.lval",
	      LOAD_FLAG_NONE,(unsigned long *)v->buf,errout);
    }
    else if (zvtype == PHP_ZEND_DOUBLE) {
	v = value_create(tlctxt->thread,NULL,lsymbol,
			 pstate->base_symbols[zvtype]);
	VLVAR(target->base,ptstate->base_tlctxt,zval_v,"value.dval",
	      LOAD_FLAG_NONE,(double *)v->buf,errout);
    }
    else if (zvtype == PHP_ZEND_STRING) {
	int slen;
	VLVAR(target->base,ptstate->base_tlctxt,zval_v,"value.str.len",
	      LOAD_FLAG_NONE,&slen,errout);
	if (slen > 4096) {
	    verror("constant string length %d too big; skipping!\n",slen);
	    goto errout;
	}
	else if (slen < 1) {
	    verror("constant string length %d too small; skipping!\n",slen);
	    goto errout;
	}
	ADDR saddr;
	VLVAR(target->base,ptstate->base_tlctxt,zval_v,"value.str.val",
	      LOAD_FLAG_NONE,&saddr,errout);

	v = value_create_noalloc(tlctxt->thread,NULL,lsymbol,
				 pstate->base_symbols[zvtype]);
	v->buf = malloc(slen + 1);
	v->bufsiz = slen;
	target_read_addr(tlctxt->thread->target,saddr,
			 (unsigned long)slen,(unsigned char *)v->buf);
	v->buf[slen] = '\0';
	v->isstring = 1;
    }
    else {
	vwarn("unsupported zval type %d!\n",zvtype);
	errno = ENOTSUP;
	goto errout;
    }

    return v;

 errout:
    if (v)
	value_free(v);
    return NULL;
}

static struct value *php_read_symbol(struct target *target,
				     struct target_location_ctxt *tlctxt,
				     struct bsymbol *bsymbol,
				     load_flags_t flags) {
    struct php_state *pstate;
    struct value *zval_v;
    struct value *value;
    struct symbol *symbol;
    char *argslotdata;
    int argslot = 0;
    int len;
    struct value *EG_argument_stack_v = NULL;
    ADDR stack_top_addr;
    struct php_thread_state *ptstate;
    long unsigned int arg_count;
    struct symbol *parent;
    ADDR final;
    struct target *base;
    struct target_location_ctxt *base_tlctxt;
    struct target_location_ctxt_frame *tlctxtf = NULL;
    struct php_target_location_ctxt_frame_state *pfstate = NULL;
    struct value *EX_v;

    pstate = (struct php_state *)target->state;
    ptstate = (struct php_thread_state *)tlctxt->thread->state;
    base = target->base;
    base_tlctxt = ptstate->base_tlctxt;

    if (tlctxt->frames) {
	tlctxtf = (struct target_location_ctxt_frame *)			\
	    array_list_item(tlctxt->frames,tlctxt->lctxt->current_frame);
	pfstate = (struct php_target_location_ctxt_frame_state *)tlctxtf->priv;
    }

    symbol = bsymbol_get_symbol(bsymbol);
    if (!SYMBOL_IS_VAR(symbol) || !symbol_is_parameter(symbol)) {
	errno = EINVAL;
	goto errout;
    }

    /*
     * XXX: handle loading in an unwind context!
     */

    if (symbol_is_parameter(symbol)) {
	parent = symbol_find_parent(symbol);
	if (!SYMBOL_IS_FUNC(parent)) {
	    errno = EINVAL;
	    goto errout;
	}

	/*
	 * If we're not in a function, we can't load an argument.
	 *
	 * XXX: we should also really check to make sure that the called
	 * function matches the parent :) -- but for now just trust the
	 * user to do the right thing.
	 */
	if (tlctxtf && tlctxtf->frame > 0) {
	    if (!pfstate->execute_data_v) {
		errno = EINVAL;
		goto errout;
	    }
	    else
		EX_v = pfstate->execute_data_v;
	}
	else if (!ptstate->current_execute_data_v) {
	    errno = EINVAL;
	    goto errout;
	}
	else
	    EX_v = ptstate->current_execute_data_v;

	/*
	 * Grab the number of passed args and see if we can load our
	 * argslot from them.
	 */
	VLVAR(base,base_tlctxt,EX_v,"opline.extended_value",
	      LOAD_FLAG_NONE,&arg_count,errout);

	LOCATION_GET_DATA(SYMBOLX_VAR_LOC(symbol),argslotdata,len);
	/*
	 * NB: this is safe because we malloc an int when we store
	 * argslotdata.
	 */
	memcpy(&argslot,argslotdata,len);
	if (argslot < 0) {
	    verror("BUG: bad argslot %d for function %s!\n",
		   argslot,symbol_get_name(parent));
	    errno = EINVAL;
	    goto errout;
	}
	else if (argslot >= (int)arg_count) {
	    if (!SYMBOLX_VAR(symbol) || !SYMBOLX_VAR(symbol)->constval) {
		vwarnopt(9,LA_TARGET,LF_PHP,
			 "argslot %d exceeds arg_count %lu for function %s"
			 " and no default value; exception will be thrown!\n",
			 argslot,arg_count,symbol_get_name(parent));
		errno = EINVAL;
		goto errout;
	    }
	    else {
		/*
		 * Load constval as the default value.
		 */
		value = value_create_type(tlctxt->thread,NULL,
					  symbol_get_datatype(symbol));
		memcpy(value->buf,SYMBOLX_VAR(symbol)->constval,value->bufsiz);
	
		vdebug(8,LA_TARGET,LF_PHP,
		       "symbol %s: loaded default param value len %d\n",
		       symbol_get_name(symbol),value->bufsiz);
	    }
	}
	else {
	    vdebug(8,LA_TARGET,LF_PHP,
		   "trying to load arg %s in slot %d for function %s\n",
		   symbol_get_name(symbol),argslot,symbol_get_name(parent));
	}

	if (tlctxtf && tlctxtf->frame > 0) {
	    VLVAR(base,base_tlctxt,EX_v,"function_state.arguments",
		  LOAD_FLAG_NONE,&stack_top_addr,errout);
	}
	else {
	    EG_argument_stack_v = 
		php_EG(target,tlctxt->thread->tid,"argument_stack");
	    if (!EG_argument_stack_v) {
		verror("could not load argstack!\n");
		goto errout;
	    }

	    VLVAR(base,base_tlctxt,EG_argument_stack_v,"top",LOAD_FLAG_NONE,
		  &stack_top_addr,errout);
	}

	/*
	 * So, we have the argument_stack pointer; we have the number of
	 * arguments on the stack.  Now, for this symbol, get its arg
	 * index, read the pointer at the index, and load the zval at
	 * its address, and return!
	 */
	final = 0; // - 8
	if (tlctxtf && tlctxtf->frame == 0)
	    stack_top_addr -= 8;
	target_read_addr(base,stack_top_addr - (arg_count - argslot) * target->ptrsize,
			 base->ptrsize,(unsigned char *)&final);

	zval_v = target_load_type(base,pstate->zend_zval_type,final,
				  LOAD_FLAG_NONE);
	if (!zval_v) {
	    if (!errno)
		errno = EFAULT;
	    goto errout;
	}

	value = php_zval_to_value(target,tlctxt,zval_v,bsymbol);
	value_free(zval_v);
    }
    else if (SYMBOLX_VAR(symbol) && SYMBOLX_VAR(symbol)->constval) {
	/*
	 * Load constval.
	 */
	value = value_create_type(tlctxt->thread,NULL,
				  symbol_get_datatype(symbol));
	memcpy(value->buf,SYMBOLX_VAR(symbol)->constval,value->bufsiz);
	
	vdebug(8,LA_TARGET,LF_PHP,
	       "symbol %s: loaded default const value len %d\n",
	       symbol_get_name(symbol),value->bufsiz);
    }
    else {
	verror("cannot load var symbol %s; unsupported!\n",
	       symbol_get_name(symbol));
	errno = ENOTSUP;
	goto errout;
    }

    return value;

 errout:
    if (EG_argument_stack_v)
	value_free(EG_argument_stack_v);
    return NULL;
}

static char *php_reg_name(struct target *target,REG reg) {
    return target->base->ops->regname(target->base,reg);
}

static REG php_dwregno_targetname(struct target *target,char *name) {
    return target->base->ops->dwregno_targetname(target->base,name);
}

static REG php_dw_reg_no(struct target *target,common_reg_t reg) {
    return target->base->ops->dwregno(target->base,reg);
}

static tid_t php_gettid(struct target *target) {
    struct target_thread *tthread;

    // XXX: fix!
    return target->base_tid;

    if (target->current_thread && target->current_thread->valid)
	return target->current_thread->tid;

    tthread = php_load_current_thread(target,0);
    if (!tthread) {
	verror("could not load current thread to get TID!\n");
	return 0;
    }

    return tthread->tid;
}

static void php_free_thread_state(struct target *target,void *state) {
    if (state)
	free(state);
}

/*
 * XXX:
 *
 * Need to load/unload any new/stale threads in this function;
 * everything calls it, basically.  We need to keep a state bit in the
 * php_state struct saying if we scanned the list this pass
 * yet or not (and we can replace this with active probing, of course).
 */
static int __is_our_tid(struct target *target,tid_t tid) {
    if (g_hash_table_lookup(target->threads,(gpointer)(uintptr_t)tid))
	return 1;
    return 0;
}

/* XXX: obviously, need to reload the tgid list. */
static struct array_list *php_list_available_tids(struct target *target) {
    struct array_list *retval;

    retval = array_list_create(1);
    array_list_append(retval,(void *)(uintptr_t)target->base_tid);

    return retval;
}

static struct target_thread *php_load_thread(struct target *target,
					     tid_t tid,int force) {
    if (!target_load_thread(target->base,tid,force))
	return NULL;

    return target_lookup_thread(target,tid);
}

static struct target_thread *
php_load_current_thread(struct target *target,int force) {
    struct target_thread *uthread;

    uthread = target_load_current_thread(target->base,force);
    if (!uthread) {
	verror("could not load base target current thread: %s\n",
	       strerror(errno));
	target->current_thread = NULL;
	return NULL;
    }

    /* XXX: should we return the primary thread, or NULL? */
    if (!__is_our_tid(target,uthread->tid)) {
	vwarnopt(9,LA_TARGET,LF_XVP,
		 "base target current tid %d is not in tgid %d!\n",
		 uthread->tid,target->base_tid);
	errno = ESRCH;
	target->current_thread = NULL;
	return NULL;
    }

    target->current_thread = target_lookup_thread(target,uthread->tid);

    return target->current_thread;
}

/* XXX: need to actually do them all! */
static int php_load_all_threads(struct target *target,int force) {
    if (php_load_thread(target,target->base_tid,force))
	return 0;
    return 1;
}

static int php_load_available_threads(struct target *target,
						 int force) {
    if (php_load_thread(target,target->base_tid,force))
	return 0;
    return -1;
}

static int php_flush_thread(struct target *target,tid_t tid) {
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread->dirty)
	return 0;

    if (!__is_our_tid(target,tid)) {
	verror("tid %d is not in tgid %d!\n",tid,target->base_tid);
	errno = ESRCH;
	return -1;
    }

    /*
    rc = target->base->ops->flush_thread(target->base,tid);
    if (rc) {
	verror("could not flush base target tid %d: %s\n",tid,strerror(errno));
	return rc;
    }
    */

    tthread->dirty = 0;

    return 0;
}

static int php_flush_current_thread(struct target *target) {
    //if (target->current_thread)
    //    return php_flush_thread(target,target->current_thread->tid);
    return 0;
}

static int php_flush_all_threads(struct target *target) {
    return 0; //php_flush_thread(target,target->base_tid);
}

static int php_invalidate_all_threads(struct target *target) {
    GHashTableIter iter;
    struct target_thread *tthread;
    struct php_thread_state *ptstate;

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) {
	ptstate = (struct php_thread_state *)tthread->state;

	tthread->valid = 0;

	if (ptstate->current_execute_data_v) {
	    value_free(ptstate->current_execute_data_v);
	    ptstate->current_execute_data_v = NULL;
	}

	tthread->valid = 0;
    }

    return 0;
}

static int php_thread_snprintf(struct target_thread *tthread,
			       char *buf,int bufsiz,
			       int detail,char *sep,char *kvsep) {
    struct target *target;

    target = tthread->target;

    if (!__is_our_tid(target,tthread->tid)) {
	verror("tid %d is not in tgid %d!\n",
	       tthread->tid,tthread->target->base_tid);
	errno = ESRCH;
	return -1;
    }

    return target->base->ops->thread_snprintf(target->base_thread,
					      buf,bufsiz,detail,sep,kvsep);
}

/*
 * Meaningless to user, but may as well leave these.
 */
static REGVAL php_read_reg(struct target *target,tid_t tid,REG reg) {
    return target->base->ops->readreg(target->base,tid,reg);
}

static int php_write_reg(struct target *target,tid_t tid,REG reg,
				    REGVAL value) {
    return target->base->ops->writereg(target->base,tid,reg,value);
}

static GHashTable *php_copy_registers(struct target *target,tid_t tid) {
    return target->base->ops->copy_registers(target->base,tid);
}

static struct target_location_ctxt *php_unwind(struct target *target,tid_t tid) {
    struct target_location_ctxt *tlctxt;
    struct target_location_ctxt_frame *tlctxtf;
    struct target_thread *tthread;
    struct bsymbol *bsymbol;
    struct php_state *pstate;
    struct php_thread_state *ptstate;
    struct php_target_location_ctxt_frame_state *pfstate;
    struct value *zend_function_v;
    struct target *base;
    ADDR zend_function_addr;

    pstate = (struct php_state *)target->state;
    base = target->base;
    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return NULL;
    }
    ptstate = (struct php_thread_state *)tthread->state;

    /*
     * Load EG(current_execute_data) if not already loaded for this
     * thread.  Find the symbol.  Fix php_read_symbol to read from an
     * unwind context.
     */
    if (!ptstate->current_execute_data_v) {
	ptstate->current_execute_data_v = 
	    php_EG(target,tid,"current_execute_data");
	if (!ptstate->current_execute_data_v) {
	    verror("could not load execute_data arg; cannot determine which"
		   " function is going to execute; skipping!\n");
	    return RESULT_SUCCESS;
	}
    }

    zend_function_v = target_load_value_member(base,ptstate->base_tlctxt,
					       ptstate->current_execute_data_v,
					       "function_state.function",NULL,
					       LOAD_FLAG_AUTO_DEREF);
    if (!zend_function_v) {
	verror("could not load execute_data->function_state.function; cannot"
	       " determine which function is executing; skipping!\n");
	return RESULT_SUCCESS;
    }

    zend_function_addr = value_addr(zend_function_v);
    value_free(zend_function_v);
    zend_function_v = NULL;

    bsymbol = target_lookup_sym_addr(target,zend_function_addr);
    if (!bsymbol) {
	verror("did not find PHP function symbol for zend_function"
	       " 0x%"PRIxADDR"; skipping!\n",
	       zend_function_addr);
	return RESULT_SUCCESS;
    }

    vdebug(5,LA_TARGET,LF_PHP | LF_TUNW,
	   "unwind starting at '%s'\n",bsymbol_get_name(bsymbol));

    /* Ok, we have enough info to start unwinding. */

    tlctxt = target_location_ctxt_create_from_bsymbol(target,tid,bsymbol);
    tlctxt->frames = array_list_create(8);

    /*
     * Create the 0-th frame (current) (with a per-frame lops_priv).
     *
     * For each frame we create, its private target_location_ctxt->lctxt
     * is just a *ref* to unw->tlctxt->lctxt; this will get fixed
     * eventually; for now, see target_unwind_free() for our care in
     * handling this.
     */
    tlctxtf = calloc(1,sizeof(*tlctxtf));
    tlctxtf->tlctxt = tlctxt;
    tlctxtf->frame = 0;
    tlctxtf->bsymbol = bsymbol;
    tlctxtf->registers = NULL;

    pfstate = calloc(1,sizeof(*pfstate));
    pfstate->execute_data_v = value_clone(ptstate->current_execute_data_v);

    tlctxtf->priv = pfstate;

    array_list_append(tlctxt->frames,tlctxtf);

    return tlctxt;
}

static int php_unwind_read_reg(struct target_location_ctxt *tlctxt,
			       REG reg,REGVAL *o_regval) {
    errno = ENOTSUP;
    return 0;
}

static struct target_location_ctxt_frame *
php_unwind_prev(struct target_location_ctxt *tlctxt) {
    struct target_location_ctxt_frame *tlctxtf;
    struct php_target_location_ctxt_frame_state *pfstate;
    struct target_location_ctxt_frame *new;
    ADDR prev_execute_data_addr;
    struct value *prev_execute_data_v = NULL;
    struct value *zend_function_v = NULL;
    ADDR zend_function_addr;
    struct bsymbol *bsymbol = NULL;
    struct target *target;
    struct target *base;
    struct php_thread_state *ptstate;

    target = tlctxt->thread->target;
    base = target->base;
    ptstate = (struct php_thread_state *)tlctxt->thread->state;

    /* Just return it if it already exists. */
    new = (struct target_location_ctxt_frame *) \
	array_list_item(tlctxt->frames,tlctxt->lctxt->current_frame + 1);
    if (new)
	return new;

    tlctxtf = (struct target_location_ctxt_frame *) \
	array_list_item(tlctxt->frames,tlctxt->lctxt->current_frame);
    pfstate = (struct php_target_location_ctxt_frame_state *)tlctxtf->priv;

    /*
     * Try to load the pointer value of tlctxtf->priv->execute_data_v's
     * prev_execute_data member; if it is non-zero, build a new frame!
     * Otherwise we're done.
     */
    VLVAR(base,ptstate->base_tlctxt,pfstate->execute_data_v,"prev_execute_data",
	  LOAD_FLAG_NONE,&prev_execute_data_addr,errout);

    if (!prev_execute_data_addr) {
	vdebug(5,LA_TARGET,LF_PHP,
	       "stopping unwind at current frame %d; no prior frames",
	       tlctxtf->frame);
	return NULL;
    }

    /*
     * Now grab the prev_execute_data value!
     */
    VLVAL(base,ptstate->base_tlctxt,pfstate->execute_data_v,"prev_execute_data",
	  LOAD_FLAG_AUTO_DEREF,&prev_execute_data_v,errout);


    /*
     * Now grab the symbol for this execute_data!
     */
    zend_function_v = target_load_value_member(base,ptstate->base_tlctxt,
					       prev_execute_data_v,
					       "function_state.function",NULL,
					       LOAD_FLAG_AUTO_DEREF);
    if (!zend_function_v) {
	verror("could not load prev_execute_data->function_state.function; cannot"
	       " determine which function is executing; stopping unwind!\n");
	goto errout;
    }

    zend_function_addr = value_addr(zend_function_v);
    value_free(zend_function_v);
    zend_function_v = NULL;

    bsymbol = target_lookup_sym_addr(target,zend_function_addr);
    if (!bsymbol) {
	verror("did not find PHP function symbol for zend_function"
	       " 0x%"PRIxADDR"; stopping unwind!\n",
	       zend_function_addr);
	goto errout;
    }

    /*
     * Create the i-th frame (current) (with a per-frame lops_priv).
     *
     * For each frame we create, its private target_location_ctxt->lctxt
     * is just a *ref* to tlctxt->tlctxt->lctxt; this will get fixed
     * eventually; for now, see target_unwind_free() for our care in
     * handling this.
     */
    new = calloc(1,sizeof(*new));
    new->tlctxt = tlctxt;
    new->frame = array_list_len(tlctxt->frames);
    new->bsymbol = bsymbol;
    new->registers = NULL;

    pfstate = calloc(1,sizeof(*pfstate));
    pfstate->execute_data_v = prev_execute_data_v;

    new->priv = pfstate;

    array_list_append(tlctxt->frames,new);

    tlctxt->region = bsymbol->region;
    ++tlctxt->lctxt->current_frame;

    vdebug(5,LA_TARGET,LF_PHP | LF_TUNW,
	   "unwind created new previous frame %d for function '%s'\n",
	   tlctxt->lctxt->current_frame,bsymbol_get_name(bsymbol));

    return new;

 errout:
    if (bsymbol)
	bsymbol_release(bsymbol);
    if (zend_function_v)
	value_free(zend_function_v);
    if (prev_execute_data_v)
	value_free(prev_execute_data_v);
    //if (new)
    //    target_location_ctxt_frame_free(new);

    return NULL;
}

static int php_probe_fini(struct probe *probe) {
    struct php_thread_state *ptstate;

    ptstate = (struct php_thread_state *)probe->thread->state;

    if (!ptstate)
	return 0;

    if (ptstate->fprobe == probe) 
	ptstate->fprobe = NULL;
    else if (ptstate->fprobe_return == probe) 
	ptstate->fprobe_return = NULL;
    else if (ptstate->vprobe == probe) 
	ptstate->fprobe = NULL;

    return 0;
}

static struct probe_ops php_probe_ops = {
    .fini = php_probe_fini,
};

static result_t __php_function_probe_handler(int type,
					     struct probe *probe,
					     tid_t tid,void *handler_data,
					     struct probe *trigger,
					     struct probe *basep) {
    struct probe *ptmp;
    GList *list;
    int retval = 0;
    int rc;
    ADDR zend_function_addr;
    struct bsymbol *bsymbol;
    struct target *target;
    struct php_state *pstate;
    struct target_thread *tthread;
    struct target *base;
    struct php_thread_state *ptstate;
    struct value *zend_function_v;
    struct php_thread_stack_frame *stack_frame;

    target = (struct target *)handler_data;
    pstate = (struct php_state *)target->state;
    base = probe->target;
    tthread = target_lookup_thread(target,probe->thread->tid);
    ptstate = (struct php_thread_state *)tthread->state;

    /*
     * Check which function is executing (meaning check the addr of the
     * zval representing it); if that zval's addr matches one of the
     * probes subscribed to us, fire that probe's handlers!
     *
     * This basically emulates probe_do_sink_(pre|post)_handlers.
     */
    if (!ptstate->current_execute_data_v) {
	ptstate->current_execute_data_v = 
	    target_load_symbol(base,ptstate->base_tlctxt,
			       pstate->fprobe_func_execute_data_arg,
			       LOAD_FLAG_AUTO_DEREF);
	if (!ptstate->current_execute_data_v) {
	    verror("could not load execute_data arg; cannot determine which"
		   " function is going to execute; skipping!\n");
	    return RESULT_SUCCESS;
	}
    }

    zend_function_v = target_load_value_member(base,ptstate->base_tlctxt,
					       ptstate->current_execute_data_v,
					       "function_state.function",NULL,
					       LOAD_FLAG_AUTO_DEREF);
    if (!zend_function_v) {
	verror("could not load execute_data->function_state.function; cannot"
	       " determine which function is executing; skipping!\n");
	return RESULT_SUCCESS;
    }

    zend_function_addr = value_addr(zend_function_v);
    value_free(zend_function_v);
    zend_function_v = NULL;

    bsymbol = target_lookup_sym_addr(target,zend_function_addr);
    if (!bsymbol) {
	verror("did not find PHP function symbol for zend_function"
	       " 0x%"PRIxADDR"; skipping!\n",
	       zend_function_addr);
	return RESULT_SUCCESS;
    }

    vdebug(5,LA_TARGET,LF_PHP,
	   "bphandler checking '%s'\n",bsymbol_get_name(bsymbol));

    if (probe->sinks) {
	vdebug(5,LA_PROBE,LF_PROBE,"");
	LOGDUMPPROBE_NL(5,LA_PROBE,LF_PROBE,probe);

	list = probe->sinks;
	while (list) {
	    ptmp = (struct probe *)list->data;

	    /* Check if this probe matches. */
	    if (!ptmp->bsymbol || !bsymbol
		|| bsymbol_get_symbol(ptmp->bsymbol)
		       != bsymbol_get_symbol(bsymbol))
		goto next;

	    /*
	     * Do this stuff regardless of if there's a prehandler or
	     * not!  Why?  Because if we do it for the prehandler, we
	     * have to do it for the posthandler too.  Since we can't
	     * tell if we did it or didn't do it for the prehandler once
	     * we get to the posthandler, we ALWAYS have to do it!
	     */
	    PROBE_SAFE_OP_ARGS(ptmp,values_notify_phase,tid,PHASE_PRE_START);

	    /*
	     * Signal each of the sinks, IF their threads match (thus a
	     * sink can act as a filter on a thread id.
	     */
	    if (ptmp->pre_handler
		&& (ptmp->thread->tid == TID_GLOBAL 
		    || ptmp->thread->tid == tid)
		&& probe_filter_check(ptmp,tid,probe,0) == 0) {

		rc = ptmp->pre_handler(ptmp,tid,ptmp->handler_data,probe,basep);
		if (rc == RESULT_ERROR) {
		    probe_disable(ptmp);
		    retval |= rc;
		}
	    }

	    PROBE_SAFE_OP_ARGS(ptmp,values_notify_phase,tid,PHASE_PRE_END);

	next:
	    list = g_list_next(list);
	}
    }

    /* Save it on the stack. */
    stack_frame = calloc(1,sizeof(*stack_frame));
    stack_frame->bsymbol = bsymbol;
    stack_frame->current_execute_data_v = 
	value_clone(ptstate->current_execute_data_v);
    ptstate->stack_frames = g_slist_prepend(ptstate->stack_frames,stack_frame);

    //if (bsymbol)
    //    bsymbol_release(bsymbol);

    return retval;
}

static result_t php_function_return_probe_pre_handler(struct probe *probe,
						      tid_t tid,void *handler_data,
						      struct probe *trigger,
						      struct probe *basep) {
    struct target *target;
    //struct php_state *pstate;
    struct target_thread *tthread;
    //struct target *base;
    struct php_thread_state *ptstate;
    struct php_thread_stack_frame *stack_frame;
    struct probe *ptmp;
    GList *list;
    int retval = 0;
    int rc;
    struct bsymbol *bsymbol;

    target = (struct target *)handler_data;
    //pstate = (struct php_state *)target->state;
    //base = probe->target;
    tthread = target_lookup_thread(target,probe->thread->tid);
    ptstate = (struct php_thread_state *)tthread->state;

    if (!ptstate->stack_frames) {
	vwarnopt(12,LA_TARGET,LF_PHP,"stack underflow!\n");
	return RESULT_SUCCESS;
    }

    stack_frame = (struct php_thread_stack_frame *) \
	g_slist_nth_data(ptstate->stack_frames,0);
    bsymbol = stack_frame->bsymbol;

    vdebug(5,LA_TARGET,LF_PHP,
	   "bphandler checking '%s'\n",bsymbol_get_name(bsymbol));

    if (probe->sinks) {
	vdebug(5,LA_PROBE,LF_PROBE,"");
	LOGDUMPPROBE_NL(5,LA_PROBE,LF_PROBE,probe);

	list = probe->sinks;
	while (list) {
	    ptmp = (struct probe *)list->data;

	    /* Check if this probe matches. */
	    if (!ptmp->bsymbol || !bsymbol
		|| bsymbol_get_symbol(ptmp->bsymbol)
		       != bsymbol_get_symbol(bsymbol))
		goto next;

	    PROBE_SAFE_OP_ARGS(ptmp,values_notify_phase,tid,PHASE_POST_START);

	    /*
	     * Signal each of the sinks, IF their threads match (thus a
	     * sink can act as a filter on a thread id.
	     */
	    if (ptmp->post_handler
		&& (ptmp->thread->tid == TID_GLOBAL 
		    || ptmp->thread->tid == tid)
		&& probe_filter_check(ptmp,tid,probe,0) == 0) {

		rc = ptmp->post_handler(ptmp,tid,ptmp->handler_data,probe,basep);
		if (rc == RESULT_ERROR) {
		    probe_disable(ptmp);
		    retval |= rc;
		}
	    }

	    PROBE_SAFE_OP_ARGS(ptmp,values_notify_phase,tid,PHASE_POST_END);

	next:
	    list = g_list_next(list);
	}
    }

    /*
     * Pop it off the stack.
     *
     * XXX: maybe make sure we're really returning from the top-most
     * function on our shadow stack??
     *
     * XXX: what about exceptions?
     */
    ptstate->stack_frames = g_slist_remove(ptstate->stack_frames,stack_frame);

    bsymbol_release(stack_frame->bsymbol);
    value_free(stack_frame->current_execute_data_v);
    free(stack_frame);

    return RESULT_SUCCESS;
}

static result_t php_function_probe_pre_handler (struct probe *probe,
						tid_t tid,void *handler_data,
						struct probe *trigger,
						struct probe *base) {
    volatile result_t ret = __php_function_probe_handler(1,probe,tid,handler_data,trigger,base);
    return ret + 0;
}

static result_t php_function_probe_post_handler(struct probe *probe,
						tid_t tid,void *handler_data,
						struct probe *trigger,
						struct probe *base) {
    volatile result_t ret = __php_function_probe_handler(2,probe,tid,handler_data,trigger,base);
    return ret + 0;
}

static int php_insert_function_probes(struct target *target,tid_t tid) {
    struct php_state *pstate;
    struct php_thread_state *ptstate;
    struct target_thread *tthread;
    char buf[128];

    pstate = (struct php_state *)target->state;
    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return -1;
    }
    ptstate = (struct php_thread_state *)tthread->state;

    if (ptstate->fprobe)
	return 0;

    if (!pstate->fprobe_func) {
	verror("no fcall helper symbol; cannot probe!\n");
	return -1;
    }

    /*
     * Insert probes on the underlying target, on the function call
     * opcode handler functions.  Then subscribe a metaprobe to them,
     * save it off in ptstate->fprobe, and be done.
     *
     * Hm, upon further code analysis, we can more easily probe the
     * single 'zend_do_fcall_common_helper_SPEC' helper function, called
     * by all those opcodes.  That way, more of the function state is
     * already setup for us -- it's "closer" to the call site.
     */
    snprintf(buf,sizeof(buf),"php__%s__%d",
	     bsymbol_get_name(pstate->fprobe_func),tid);
    ptstate->fprobe = probe_create(target->base,tid,&php_probe_ops,buf,
				   php_function_probe_pre_handler,
				   php_function_return_probe_pre_handler, //php_function_probe_post_handler,
				   target,1,1);
    if (!ptstate->fprobe)
	return -1;
    if (!probe_register_symbol(ptstate->fprobe,pstate->fprobe_func,
			       PROBEPOINT_SW,0,0)) {
	probe_free(ptstate->fprobe,0);
	ptstate->fprobe = NULL;
	return -1;
    }

    /*
    snprintf(buf,sizeof(buf),"php__%s__%d",
	     bsymbol_get_name(pstate->fprobe_func),tid);
    ptstate->fprobe_return = probe_create(target->base,tid,&php_probe_ops,buf,
					  php_function_return_probe_pre_handler,
					  NULL,target,1,1);
    if (!ptstate->fprobe_return)
	return -1;
    if (!probe_register_symbol(ptstate->fprobe_return,
			       pstate->fprobe_func_return,PROBEPOINT_SW,0,0)) {
	probe_free(ptstate->fprobe_return,0);
	ptstate->fprobe_return = NULL;
	return -1;
    }
    */

    return 0;
}

static int php_probe_register_symbol(struct target *target,tid_t tid,
				     struct probe *probe,struct bsymbol *bsymbol,
				     probepoint_style_t style,
				     probepoint_whence_t whence,
				     probepoint_watchsize_t watchsize) {
    struct target_thread *tthread;
    struct php_thread_state *ptstate;
    struct symbol *symbol;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return -1;
    }
    ptstate = (struct php_thread_state *)tthread->state;

    /*
     * Just insert the primary probe(s) if they don't already exist for
     * this thread (probe the function call opcode handlers for
     * functions; probe the assignment and inc/dec opcode
     * handlers/helpers for watchpoints -- and NB we only support
     * write watchpoints).
     */
    symbol = bsymbol_get_symbol(bsymbol);
    if (SYMBOL_IS_FUNC(symbol)) {
	php_insert_function_probes(target,tid);
    }
    else if (SYMBOL_IS_VAR(symbol)) {
	verror("watchpoints not yet supported!\n");
	errno = ENOTSUP;
	return -1;
    }
    else {
	verror("cannot probe symbol type '%s'!\n",SYMBOL_TYPE(symbol->type));
	errno = ENOTSUP;
	return -1;
    }

    if (!probe_register_source(probe,ptstate->fprobe))
	return -1;

    probe->bsymbol = bsymbol;
    RHOLD(bsymbol,probe);

    return 0;
}

/*
 * Single step in php is different; we need to single step the opcode
 * execution.  What this means is catching the return from that
 * function, once we hit a breakpoint.  So it doesn't involve the base
 * target, *as long as* we can catch the opcode executor assuredly --
 * i.e., no long jmps etc.
 */
int php_singlestep(struct target *target,tid_t tid,int isbp,
			      struct target *overlay) {
    // XXX
}

int php_singlestep_end(struct target *target,tid_t tid,
				  struct target *overlay) {
    // XXX
}

/**
 ** The interface to the dwdebug library's lsymbol_resolve* and
 ** symbol_resolve* functions.
 **/

int __php_location_ops_setcurrentframe(struct location_ctxt *lctxt,int frame) {
    struct target_location_ctxt *tlctxt = 
	(struct target_location_ctxt *)lctxt->priv;
    struct target_location_ctxt_frame *tlctxtf = 
	target_location_ctxt_get_frame(tlctxt,frame);

    if (!tlctxtf) {
	errno = EBADSLT;
	return -1;
    }

    tlctxt->region = tlctxtf->bsymbol->region;
    lctxt->current_frame = frame;
    return 0;
}

struct symbol *__php_location_ops_getsymbol(struct location_ctxt *lctxt) {
    struct target_location_ctxt *tlctxt = 
	(struct target_location_ctxt *)lctxt->priv;
    struct target_location_ctxt_frame *tlctxtf = 
	target_location_ctxt_current_frame(tlctxt);

    return bsymbol_get_symbol(tlctxtf->bsymbol);
}

int __php_location_ops_getaddrsize(struct location_ctxt *lctxt) {
    struct target_location_ctxt *tlctxt;

    tlctxt = (struct target_location_ctxt *)lctxt->priv;
    return tlctxt->thread->target->wordsize;
}

int __php_location_ops_getregno(struct location_ctxt *lctxt,
				common_reg_t creg,REG *o_reg) {
    errno = ENOTSUP;
    return -1;
}

int __php_location_ops_readreg(struct location_ctxt *lctxt,
			       REG regno,REGVAL *regval) {
    errno = ENOTSUP;
    return -1;
}

int __php_location_ops_writereg(struct location_ctxt *lctxt,
				REG regno,REGVAL regval) {
    errno = ENOTSUP;
    return -1;
}

int __php_location_ops_cachereg(struct location_ctxt *lctxt,
				REG regno,REGVAL regval) {
    errno = ENOTSUP;
    return -1;
}

int __php_location_ops_readipreg(struct location_ctxt *lctxt,REGVAL *regval) {
    errno = ENOTSUP;
    return -1;
}

int __php_location_ops_readword(struct location_ctxt *lctxt,
				   ADDR real_addr,ADDR *pval) {
    struct target_location_ctxt *tlctxt;
    unsigned char *rc;

    tlctxt = (struct target_location_ctxt *)lctxt->priv;

    rc = target_read_addr(tlctxt->thread->target,real_addr,
			  tlctxt->thread->target->ptrsize,(unsigned char *)pval);
    if (rc != (unsigned char *)pval) {
	verror("could not read 0x%"PRIxADDR": %s!\n",
	       real_addr,strerror(errno));
	return -1;
    }

    return 0;
}

int __php_location_ops_writeword(struct location_ctxt *lctxt,
				    ADDR real_addr,ADDR pval) {
    struct target_location_ctxt *tlctxt;
    unsigned long rc;

    tlctxt = (struct target_location_ctxt *)lctxt->priv;

    rc = target_write_addr(tlctxt->thread->target,real_addr,
			   tlctxt->thread->target->ptrsize,
			   (unsigned char *)&pval);
    if (rc != tlctxt->thread->target->ptrsize) {
	verror("could not write 0x%"PRIxADDR" to 0x%"PRIxADDR": %s!\n",
	       pval,real_addr,strerror(errno));
	return -1;
    }

    return 0;
}

int __php_location_ops_relocate(struct location_ctxt *lctxt,
				   ADDR obj_addr,ADDR *real_addr) {
    *real_addr = obj_addr;
    return 0;
}

int __php_location_ops_unrelocate(struct location_ctxt *lctxt,
				     ADDR real_addr,ADDR *obj_addr) {
    *obj_addr = real_addr;
    return 0;
}

struct location_ops php_location_ops = {
    .setcurrentframe = __php_location_ops_setcurrentframe,
    .getsymbol = __php_location_ops_getsymbol,
    .readreg = __php_location_ops_readreg,
    .writereg = __php_location_ops_writereg,
    .cachereg = __php_location_ops_cachereg,
    .readipreg = __php_location_ops_readipreg,

    .readword = __php_location_ops_readword,
    .writeword = __php_location_ops_writeword,
    .relocate = __php_location_ops_relocate,
    .unrelocate = __php_location_ops_unrelocate,

    .getregno = __php_location_ops_getregno,
    .getaddrsize = __php_location_ops_getaddrsize,
};
