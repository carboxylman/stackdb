/*
 * Copyright (c) 2013 The University of Utah
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

#include "log.h"
#include "target_api.h"
#include "target.h"
#include "target_os.h"
#include "probe_api.h"
#include "glib_wrapper.h"

struct probe_value {
    probe_handler_phase_t phase;

    uint8_t finished:1,
	    pre_fully_loaded:1,
	    post_fully_loaded:1;

    /* name to struct value */
    GHashTable *nv;
    /* name to raw value */
    GHashTable *nr;
};

void probe_value_clear(struct probe_value *pv) {
    GHashTableIter iter;
    gpointer kp,vp;

    g_hash_table_iter_init(&iter,pv->nv);
    while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	free(kp);
	value_free((struct value *)vp);
	g_hash_table_iter_remove(&iter);
    }

    g_hash_table_iter_init(&iter,pv->nr);
    while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	free(kp);
	value_free((struct value *)vp);
	g_hash_table_iter_remove(&iter);
    }

    pv->pre_fully_loaded = 0;
    pv->post_fully_loaded = 0;
    pv->finished = 0;
}

void probe_value_free(struct probe_value *pv) {
    probe_value_clear(pv);
    if (pv->nv) {
	g_hash_table_destroy(pv->nv);
	pv->nv = NULL;
    }
    if (pv->nr) {
	g_hash_table_destroy(pv->nr);
	pv->nr = NULL;
    }
    free(pv);
}

struct probe_value *probe_value_create(probe_handler_phase_t phase) {
    struct probe_value *pv;

    pv = calloc(1,sizeof(*pv));
    pv->phase = phase;
    pv->nv = g_hash_table_new(g_str_hash,g_str_equal);
    pv->nr = g_hash_table_new(g_str_hash,g_str_equal);

    return pv;
}

/*
 * If it's a new pre, mark.
 * If it's a finished pre, mark.
 * If it's a new post, mark.
 * If it's a finished post, mark and mark finished.
 */
void probe_value_notify_phase_function_ee(struct probe *probe,tid_t tid,
					  probe_handler_phase_t phase) {
    GSList *stack;
    struct probe_value *pv = NULL;

    if (!probe->values)
	probe->values = g_hash_table_new(g_direct_hash,g_direct_equal);
    stack = (GSList *)g_hash_table_lookup(probe->values,(gpointer)(uintptr_t)tid);
    if (stack)
	pv = (struct probe_value *)stack->data;

    if (phase == PHASE_POST_END) {
	if (pv) {
	    pv->finished = 1;
	    pv->phase = phase;
	}
    }
    else {
	if (!pv) {
	    pv = probe_value_create(phase);
	    stack = g_slist_prepend(stack,pv);
	    g_hash_table_insert(probe->values,(gpointer)(uintptr_t)tid,stack);
	}
	else 
	    pv->phase = phase;
    }
}

void probe_value_notify_phase_watchedvar(struct probe *probe,tid_t tid,
					 probe_handler_phase_t phase) {
    struct probe_value *pv = NULL;

    if (!probe->values)
	probe->values = g_hash_table_new(g_direct_hash,g_direct_equal);
    pv = (struct probe_value *) \
	g_hash_table_lookup(probe->values,(gpointer)(uintptr_t)tid);

    if (phase == PHASE_PRE_END) {
	if (pv) {
	    pv->finished = 1;
	    pv->phase = phase;
	}
    }
    else {
	if (!pv) {
	    pv = probe_value_create(phase);
	    g_hash_table_insert(probe->values,(gpointer)(uintptr_t)tid,pv);
	}
	else 
	    pv->phase = phase;
    }
}

void probe_values_free_stacked(struct probe *probe) {
    GHashTableIter iter;
    gpointer vp;
    GSList *stack, *gsltmp;
    struct probe_value *pv;

    if (!probe->values)
	return;

    g_hash_table_iter_init(&iter,probe->values);
    while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	stack = (GSList *)vp;
	if (!stack)
	    continue;
	v_g_slist_foreach(stack,gsltmp,pv) {
	    probe_value_free(pv);
	}
	g_slist_free(stack);
    }
    g_hash_table_destroy(probe->values);
    probe->values = NULL;
}

void probe_values_free_basic(struct probe *probe) {
    GHashTableIter iter;
    gpointer vp;

    if (!probe->values)
	return;

    g_hash_table_iter_init(&iter,probe->values);
    while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	probe_value_free((struct probe_value *)vp);
    }
    g_hash_table_destroy(probe->values);
    probe->values = NULL;
}

int probe_value_record_stacked(struct probe *probe,tid_t tid,
			       char *name,struct value *value,int israw) {
    GSList *stack;
    struct probe_value *pv;
    struct value *value_prev = NULL;
    GHashTable *v;
    char *existing_name = NULL;

    if (!probe->values)
	probe->values = g_hash_table_new(g_direct_hash,g_direct_equal);
    stack = (GSList *)g_hash_table_lookup(probe->values,(gpointer)(uintptr_t)tid);

    if (stack)
	pv = (struct probe_value *)stack->data;
    else {
	pv = probe_value_create(PHASE_PRE_START);
	stack = g_slist_prepend(stack,pv);
	g_hash_table_insert(probe->values,(gpointer)(uintptr_t)tid,stack);
    }

    if (pv->finished) {
	/* clear it and pop it! */
	probe_value_free(pv);
	stack = g_slist_delete_link(stack,stack);
	/* push a new one; just guess on phase */
	pv = probe_value_create(PHASE_PRE_START);
	stack = g_slist_prepend(stack,pv);
	g_hash_table_insert(probe->values,(gpointer)(uintptr_t)tid,stack);
    }

    if (israw) 
	v = pv->nr;
    else
	v = pv->nv;

    if (g_hash_table_lookup_extended(v,name,(gpointer *)&existing_name,
				     (gpointer *)&value_prev) == TRUE) {
	g_hash_table_remove(v,name);
	free(existing_name);
	value_free(value_prev);
    }

    g_hash_table_insert(v,strdup(name),value);

    return 0;
}

int probe_value_record_basic(struct probe *probe,tid_t tid,
			     char *name,struct value *value,int israw) {
    struct probe_value *pv;
    struct value *value_prev;
    GHashTable *v;

    if (!probe->values)
	probe->values = g_hash_table_new(g_direct_hash,g_direct_equal);

    pv = (struct probe_value *) \
	g_hash_table_lookup(probe->values,(gpointer)(uintptr_t)tid);
    if (!pv) {
	pv = calloc(1,sizeof(*pv));
	pv->nv = g_hash_table_new(g_str_hash,g_str_equal);
	pv->nr = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(probe->values,(gpointer)(uintptr_t)tid,pv);
    }

    if (pv->finished)
	probe_value_clear(pv);

    if (israw) 
	v = pv->nr;
    else
	v = pv->nv;

    value_prev = (struct value *)g_hash_table_lookup(v,name);
    if (value_prev) 
	value_free(value_prev);

    g_hash_table_insert(v,strdup(name),value);

    return 0;
}

GHashTable *__probe_value_get_table_function_ee(struct probe *probe,tid_t tid,
						int israw,int allowlast) {
    struct array_list *args;
    struct symbol *symbol;
    GSList *stack;
    struct probe_value *pv = NULL;
    int i;
    struct symbol *argsym;
    struct value *v;
    char *name;
    load_flags_t flags;
    struct bsymbol *datatype;

    if (!israw)
	flags = LOAD_FLAG_AUTO_DEREF | LOAD_FLAG_AUTO_STRING;
    else
	flags = LOAD_FLAG_NONE;

    if (probe->values) {
	stack = (GSList *)						\
	    g_hash_table_lookup(probe->values,(gpointer)(uintptr_t)tid);
	if (stack) {
	    pv = (struct probe_value *)stack->data;
	    if (pv 
		&& (allowlast || !pv->finished)
		&& ((pv->phase == PHASE_PRE_START && pv->pre_fully_loaded)
		    || (pv->phase == PHASE_POST_START && pv->post_fully_loaded))) {
		if (israw)
		    return pv->nr;
		else
		    return pv->nv;
	    }
	}
    }

    if (pv && pv->finished) {
	/* clear it and pop it! */
	probe_value_free(pv);
	stack = g_slist_delete_link(stack,stack);
	/* push a new one; just guess on phase */
	pv = probe_value_create(PHASE_PRE_START);
	stack = g_slist_prepend(stack,pv);
	g_hash_table_insert(probe->values,(gpointer)(uintptr_t)tid,stack);
    }

    if (pv->phase == PHASE_PRE_START) {
	symbol = bsymbol_get_symbol(probe->bsymbol);
	if (!symbol)
	    return NULL;
	args = symbol_get_members(symbol,SYMBOL_VAR_TYPE_FLAG_ARG);
	if (!args)
	    return NULL;

	/*
	 * Load each argument if it hasn't already been loaded.
	 */
	array_list_foreach(args,i,argsym) {
	    name = symbol_get_name(argsym);
	    if (pv && (allowlast || !pv->finished)) {
		if (israw && g_hash_table_lookup(pv->nr,name))
		    continue;
		else if (!israw && g_hash_table_lookup(pv->nv,name))
		    continue;
	    }

	    v = target_load_symbol_member(probe->target,tid,probe->bsymbol,name,
					  NULL,flags);
	    if (v)
		probe_value_record_stacked(probe,tid,name,v,israw);
	}

	array_list_free(args);

	pv->pre_fully_loaded = 1;
    }
    else if (pv->phase == PHASE_POST_START) {
	/* x86 hack: load AX. */
	datatype = target_lookup_sym(probe->target,"long unsigned int",NULL,NULL,
				     SYMBOL_TYPE_FLAG_TYPE);
	if (datatype) {
	    v = target_load_type_reg(probe->target,bsymbol_get_symbol(datatype),
				     tid,
				     target_dw_reg_no(probe->target,CREG_AX),
				     LOAD_FLAG_NONE);
	    name = PROBE_VALUE_NAME_RETURN;
	    if (v)
		probe_value_record_stacked(probe,tid,name,v,israw);
	}
	bsymbol_release(datatype);
	pv->post_fully_loaded = 1;
    }

    if (israw)
	return pv->nr;
    else
	return pv->nv;
}

GHashTable *probe_value_get_table_function_ee(struct probe *probe,tid_t tid) {
    return __probe_value_get_table_function_ee(probe,tid,0,0);
}

GHashTable *probe_value_get_raw_table_function_ee(struct probe *probe,tid_t tid) {
    return __probe_value_get_table_function_ee(probe,tid,1,0);
}

GHashTable *probe_value_get_last_table_function_ee(struct probe *probe,tid_t tid) {
    return __probe_value_get_table_function_ee(probe,tid,0,1);
}

GHashTable *probe_value_get_last_raw_table_function_ee(struct probe *probe,
						       tid_t tid) {
    return __probe_value_get_table_function_ee(probe,tid,1,1);
}

static struct value *__probe_value_get_function_ee(struct probe *probe,tid_t tid,
						   char *name,int israw,
						   int allowlast) {
    GSList *stack;
    struct value *retval = NULL;
    struct symbol *symbol;
    struct bsymbol *bsymbol;
    struct probe_value *pv = NULL;
    struct value *v;
    load_flags_t flags;
    struct bsymbol *datatype;
    GHashTable *vt;

    /*
     * Try to find it in the current hash.
     */
    if (probe->values) {
	stack = (GSList *)						\
	    g_hash_table_lookup(probe->values,(gpointer)(uintptr_t)tid);
	if (stack) {
	    pv = (struct probe_value *)stack->data;
	    if (pv && (allowlast || !pv->finished)) {
		if (israw)
		    vt = pv->nr;
		else
		    vt = pv->nv;
		retval = (struct value *)g_hash_table_lookup(vt,name);
		if (retval)
		    return retval;
	    }
	}
    }

    if (!israw)
	flags = LOAD_FLAG_AUTO_DEREF | LOAD_FLAG_AUTO_STRING;
    else
	flags = LOAD_FLAG_NONE;

    /*
     * Otherwise look up and load!  If name is the bsymbol's name, or is
     * NULL, load the symbol; else load a member if possible.
     */
    bsymbol = probe->bsymbol;
    if (!bsymbol)
	return NULL;
    symbol = bsymbol_get_symbol(bsymbol);

    if (!name 
	|| (name && strcmp(name,symbol_get_name(symbol)) == 0)
	|| (name && strcmp(name,PROBE_VALUE_NAME_RETURN) == 0)) {
	datatype = target_lookup_sym(probe->target,"long unsigned int",NULL,NULL,
				     SYMBOL_TYPE_FLAG_TYPE);
	if (datatype) {
	    v = target_load_type_reg(probe->target,bsymbol_get_symbol(datatype),
				     tid,
				     target_dw_reg_no(probe->target,CREG_AX),
				     LOAD_FLAG_NONE);
	    name = PROBE_VALUE_NAME_RETURN;
	}
	else
	    v = NULL;
    }
    else {
	v = target_load_symbol_member(probe->target,tid,bsymbol,name,NULL,flags);
    }

    if (!v) 
	return NULL;

    /*
     * Record the value.
     */
    probe_value_record_stacked(probe,tid,name,v,israw);

    return v;
}

struct value *probe_value_get_function_ee(struct probe *probe,tid_t tid,
				      char *name) {
    return __probe_value_get_function_ee(probe,tid,name,0,0);
}

struct value *probe_value_get_raw_function_ee(struct probe *probe,tid_t tid,
					  char *name) {
    return __probe_value_get_function_ee(probe,tid,name,1,0);
}

struct value *probe_value_get_last_function_ee(struct probe *probe,tid_t tid,
					   char *name) {
    return __probe_value_get_function_ee(probe,tid,name,0,1);
}

struct value *probe_value_get_last_raw_function_ee(struct probe *probe,tid_t tid,
					       char *name) {
    return __probe_value_get_function_ee(probe,tid,name,1,1);
}

static struct value *__probe_value_get_basic(struct probe *probe,tid_t tid,
					     char *name,int israw,
					     int allowlast) {
    struct value *retval = NULL;
    struct symbol *symbol;
    struct bsymbol *bsymbol;
    struct probe_value *pv = NULL;
    struct value *v;
    load_flags_t flags;
    GHashTable *vt;

    bsymbol = probe->bsymbol;
    if (!name)
	name = bsymbol_get_name(bsymbol);

    /*
     * Try to find it in the current hash.
     */
    if (probe->values) {
	pv = (struct probe_value *) \
	    g_hash_table_lookup(probe->values,(gpointer)(uintptr_t)tid);
	if (pv && (allowlast || !pv->finished)) {
	    if (israw)
		vt = pv->nr;
	    else
		vt = pv->nv;
	    retval = (struct value *)g_hash_table_lookup(vt,name);
	    if (retval)
		return retval;
	}
    }

    if (!israw)
	flags = LOAD_FLAG_AUTO_DEREF | LOAD_FLAG_AUTO_STRING;
    else
	flags = LOAD_FLAG_NONE;

    /*
     * Otherwise look up and load!  If name is the bsymbol's name, or is
     * NULL, load the symbol; else load a member if possible.
     */
    if (!bsymbol)
	return NULL;
    symbol = bsymbol_get_symbol(bsymbol);

    if (!name || (name && strcmp(name,symbol_get_name(symbol)) == 0)) {
	v = target_load_symbol(probe->target,tid,bsymbol,flags);
	name = symbol_get_name(symbol);
    }
    else 
	v = target_load_symbol_member(probe->target,tid,bsymbol,name,NULL,flags);

    if (!v) 
	return NULL;

    /*
     * Record the value.
     */
    probe_value_record_basic(probe,tid,name,v,israw);

    return v;
}

struct value *probe_value_get_basic(struct probe *probe,tid_t tid,
				    char *name) {
    return __probe_value_get_basic(probe,tid,name,0,0);
}

struct value *probe_value_get_raw_basic(struct probe *probe,tid_t tid,
					char *name) {
    return __probe_value_get_basic(probe,tid,name,1,0);
}

struct value *probe_value_get_last_basic(struct probe *probe,tid_t tid,
					 char *name) {
    return __probe_value_get_basic(probe,tid,name,0,1);
}

struct value *probe_value_get_last_raw_basic(struct probe *probe,tid_t tid,
					     char *name) {
    return __probe_value_get_basic(probe,tid,name,1,1);
}

GHashTable *probe_value_get_table_basic(struct probe *probe,tid_t tid) {
    struct probe_value *pv;

    __probe_value_get_basic(probe,tid,NULL,0,0);
    pv = (struct probe_value *)g_hash_table_lookup(probe->values,
						   (gpointer)(uintptr_t)tid);
    if (!pv)
	return NULL;
    return pv->nv;
}

GHashTable *probe_value_get_raw_table_basic(struct probe *probe,tid_t tid) {
    struct probe_value *pv;

    __probe_value_get_basic(probe,tid,NULL,1,0);
    pv = (struct probe_value *)g_hash_table_lookup(probe->values,
						   (gpointer)(uintptr_t)tid);
    if (!pv)
	return NULL;
    return pv->nr;
}

GHashTable *probe_value_get_last_table_basic(struct probe *probe,tid_t tid) {
    struct probe_value *pv;

    __probe_value_get_basic(probe,tid,NULL,0,1);
    pv = (struct probe_value *)g_hash_table_lookup(probe->values,
						   (gpointer)(uintptr_t)tid);
    if (!pv)
	return NULL;
    return pv->nv;
}

GHashTable *probe_value_get_last_raw_table_basic(struct probe *probe,tid_t tid) {
    struct probe_value *pv;

    __probe_value_get_basic(probe,tid,NULL,1,1);
    pv = (struct probe_value *)g_hash_table_lookup(probe->values,
						   (gpointer)(uintptr_t)tid);
    if (!pv)
	return NULL;
    return pv->nr;
}

/**
 ** The API wrappers.
 **/
GHashTable *probe_value_get_table(struct probe *probe,tid_t tid) {
    return PROBE_SAFE_OP_ARGS(probe,get_value_table,tid);
}
GHashTable *probe_value_get_raw_table(struct probe *probe,tid_t tid) {
    return PROBE_SAFE_OP_ARGS(probe,get_raw_value_table,tid);
}
GHashTable *probe_value_get_last_table(struct probe *probe,tid_t tid) {
    return PROBE_SAFE_OP_ARGS(probe,get_last_value_table,tid);
}
GHashTable *probe_value_get_last_raw_table(struct probe *probe,tid_t tid) {
    return PROBE_SAFE_OP_ARGS(probe,get_last_raw_value_table,tid);
}
struct value *probe_value_get_raw(struct probe *probe,tid_t tid,char *name) {
    return PROBE_SAFE_OP_ARGS(probe,get_raw_value,tid,name);
}
struct value *probe_value_get(struct probe *probe,tid_t tid,char *name) {
    return PROBE_SAFE_OP_ARGS(probe,get_value,tid,name);
}
struct value *probe_value_get_last_raw(struct probe *probe,tid_t tid,char *name) {
    return PROBE_SAFE_OP_ARGS(probe,get_last_raw_value,tid,name);
}
struct value *probe_value_get_last(struct probe *probe,tid_t tid,char *name) {
    return PROBE_SAFE_OP_ARGS(probe,get_last_value,tid,name);
}

/**
 ** A couple simple default value probe implementations.  Watchpoints
 ** and function entry/exit.
 **/
struct probe *probe_value_var(struct target *target,tid_t tid,
			      struct bsymbol *bsymbol,
			      probe_handler_t pre_handler,
			      probe_handler_t post_handler,
			      void *handler_data);
#ifdef ENABLE_DISTORM
static struct probe *probe_value_function_ee(struct target *target,tid_t tid,
					     struct bsymbol *bsymbol,
					     probe_handler_t pre_handler,
					     probe_handler_t post_handler,
					     void *handler_data);
#endif

struct probe *probe_value_symbol(struct target *target,tid_t tid,
				 struct bsymbol *bsymbol,
				 probe_handler_t pre_handler,
				 probe_handler_t post_handler,
				 void *handler_data) {
    struct symbol *symbol;

    symbol = bsymbol_get_symbol(bsymbol);

    if (SYMBOL_IS_VAR(symbol)) 
	return probe_value_var(target,tid,bsymbol,
			       pre_handler,post_handler,handler_data);
#ifdef ENABLE_DISTORM
    else if (SYMBOL_IS_FUNCTION(symbol))
	return probe_value_function_ee(target,tid,bsymbol,
				       pre_handler,post_handler,handler_data);
#endif
    else {
	verror("can only value probe functions or vars!\n");
	return NULL;
    }
}

static const char *probe_value_var_gettype(struct probe *probe) {
    return "probe_value_var";
}

struct probe_ops var_ops = {
    .gettype = probe_value_var_gettype,
    .get_value_table = probe_value_get_table_basic,
    .get_raw_value_table = probe_value_get_raw_table_basic,
    .get_last_value_table = probe_value_get_last_table_basic,
    .get_last_raw_value_table = probe_value_get_last_raw_table_basic,
    .get_value = probe_value_get_basic,
    .get_raw_value = probe_value_get_raw_basic,
    .get_last_value = probe_value_get_last_basic,
    .get_last_raw_value = probe_value_get_last_raw_basic,
    .values_notify_phase = probe_value_notify_phase_watchedvar,
    .values_free = probe_values_free_basic,
};

struct probe *probe_value_var(struct target *target,tid_t tid,
			      struct bsymbol *bsymbol,
			      probe_handler_t pre_handler,
			      probe_handler_t post_handler,
			      void *handler_data) {
    struct probe *probe;

    probe = probe_create(target,tid,&var_ops,bsymbol_get_name(bsymbol),
			 pre_handler,post_handler,handler_data,0,1);
    if (!probe)
	return NULL;

    if (!probe_register_symbol(probe,bsymbol,PROBEPOINT_FASTEST,PROBEPOINT_WRITE,
			       PROBEPOINT_LAUTO)) {
	verror("could not register probe on %s!\n",bsymbol_get_name(bsymbol));
	probe_free(probe,1);
	return NULL;
    }

    return probe;
}

#ifdef ENABLE_DISTORM
static const char *probe_value_function_ee_gettype(struct probe *probe) {
    return "probe_value_function_entry_exit";
}

struct probe_ops function_ee_ops = {
    .gettype = probe_value_function_ee_gettype,
    .get_value_table = probe_value_get_table_function_ee,
    .get_raw_value_table = probe_value_get_raw_table_function_ee,
    .get_last_value_table = probe_value_get_last_table_function_ee,
    .get_last_raw_value_table = probe_value_get_last_raw_table_function_ee,
    .get_value = probe_value_get_function_ee,
    .get_raw_value = probe_value_get_raw_function_ee,
    .get_last_value = probe_value_get_last_function_ee,
    .get_last_raw_value = probe_value_get_last_raw_function_ee,
    .values_notify_phase = probe_value_notify_phase_function_ee,
    .values_free = probe_values_free_stacked,
};

static struct probe *probe_value_function_ee(struct target *target,tid_t tid,
					     struct bsymbol *bsymbol,
					     probe_handler_t pre_handler,
					     probe_handler_t post_handler,
					     void *handler_data) {
    struct probe *probe;

    if (!SYMBOL_IS_FUNCTION(bsymbol->lsymbol->symbol)) {
	verror("must supply a function symbol!\n");
	return NULL;
    }

    /*
     * NB: Value probes *must* have both pre and post handlers so that
     * they catch phase transitions.  So if one is not set, use the
     * default!
     */
    probe = probe_create(target,tid,&function_ee_ops,bsymbol_get_name(bsymbol),
			 pre_handler ? pre_handler : probe_do_sink_pre_handlers,
			 post_handler ? post_handler : probe_do_sink_post_handlers,
			 handler_data,0,1);

    if (!probe_register_function_ee(probe,PROBEPOINT_SW,bsymbol,0,1,1)) {
	verror("could not register entry/exit probes on function %s!\n",
	       bsymbol_get_name(bsymbol));
	probe_free(probe,1);
	return NULL;
    }

    return probe;
}
#endif
