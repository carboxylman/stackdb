/*
 * Copyright (c) 2012-2013 The University of Utah
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

#ifndef __TARGET_PHP_H__
#define __TARGET_PHP_H__

extern struct target_ops php_ops;
extern struct location_ops php_location_ops;

struct php_spec {
    unsigned int nostatic:1;
};

struct php_target_location_ctxt_frame_state {
    struct value *execute_data_v;
    // XXX: what do we need to load variables in the function? etc.
};

struct php_thread_stack_frame {
    struct bsymbol *bsymbol;
    struct value *current_execute_data_v;
};

struct php_thread_state {
    unsigned int is_executing:1;

    struct value *current_execute_data_v;
    GSList *stack_frames;

    /*
     * A default context for loading values from the underlying target
     * in this thread; the region is the PHP binary's MAIN region; we
     * get it by looking up the first symbol in php_attach.
     *
     * Of course, if you try to lookup or load a symbol in an extension,
     * then you have to use a different tlctxt because the region (and
     * debugfile!) will be wrong.
     */
    struct target_location_ctxt *base_tlctxt;

    struct {
	ADDR tsrm_ls;
    } ztsinfo;

    struct value *CG;
    struct value *EG;

    struct probe *fprobe;
    struct probe *fprobe_return;
    struct probe *vprobe;
};

/*
 * We keep a special array of builtin symbols so 
 */
/* PHP ZEND data types */
#define PHP_ZEND_NULL		0
#define PHP_ZEND_LONG		1
#define PHP_ZEND_DOUBLE		2
#define PHP_ZEND_BOOL		3
#define PHP_ZEND_ARRAY		4
#define PHP_ZEND_OBJECT		5
#define PHP_ZEND_STRING		6
#define PHP_ZEND_RESOURCE	7
#define PHP_ZEND_CONSTANT	8
#define PHP_ZEND_CONSTANT_ARRAY	9
#define PHP_ZEND_CALLABLE	10

typedef enum php_base_symbol {
    PHP_BASE_NULL     = PHP_ZEND_NULL,
    PHP_BASE_LONG     = PHP_ZEND_LONG,
    PHP_BASE_DOUBLE   = PHP_ZEND_DOUBLE,
    PHP_BASE_BOOL     = PHP_ZEND_BOOL,
    PHP_BASE_HASH     = PHP_ZEND_ARRAY,
    PHP_BASE_STRING   = PHP_ZEND_STRING,
} php_base_symbol_t;
#define PHP_BASE_SYMBOL_COUNT   PHP_BASE_STRING + 1

#define PHP_ZEND_TYPE_IS_BASE(type)				\
    ((type) == PHP_BASE_NULL || (type) == PHP_BASE_LONG		\
     || (type) == PHP_BASE_DOUBLE || (type) == PHP_BASE_BOOL	\
     || (type) == PHP_BASE_STRING)

struct php_state {
    unsigned int zts:1;

    struct target_location_ctxt *default_tlctxt;

    /*
     * We're only going to have a single debugfile, even if we have
     * multiple threads.  Cache it here.
     */
    struct debugfile *debugfile;

    struct {
	/*
	 * These are the thread-local storage resource IDs for the
	 * compiler_globals and executor_globals structs.
	 */
	int CG_id;
	int EG_id;
    } ztsinfo;

    int debugfile_symbol_counter;
    struct symbol *builtin_root;
    struct symbol **base_symbols;

    struct symbol *zend_function_type;
    struct symbol *zend_class_entry_ptr_type;
    struct symbol *zend_zval_type;
    struct symbol *zend_zval_ptr_type;
    struct symbol *zend_arg_info_type;

    struct bsymbol *fprobe_func;
    struct bsymbol *fprobe_func_execute_data_arg;
    struct bsymbol *fprobe_func_return;

    struct symbol *_zend_compiler_globals_type;
    struct symbol *_zend_executor_globals_type;

    //GHashTable *
};

struct target *php_instantiate(struct target_spec *spec,
				  struct evloop *evloop);
struct php_spec *php_build_spec(void);
void php_free_spec(struct php_spec *xspec);
int php_spec_to_argv(struct target_spec *spec,int *argc,char ***argv);

#endif /* __TARGET_PHP_H__ */
