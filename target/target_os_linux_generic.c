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

#include "target.h"
#include "target_os.h"

/*
 * We don't keep any local storage, so there is nothing to init or free!
 * All of our storage is based on target_gkv_*().
 */

int os_linux_init(struct target *target) {
    return 0;
}

int os_linux_close(struct target *target) {
    return 0;
}

int os_linux_fini(struct target *target) {
    return 0;
}

target_os_type_t os_linux_type(struct target *target) {
    return TARGET_OS_TYPE_LINUX;
}

/*
 * Lookup version by reading either 'system_utsname.release' OR
 * 'init_uts_ns.release' (if namespace support).  We don't care if we
 * read current's namespace uts struct or just init's uts namespace,
 * because we want the base OS's release.  I don't even know if the
 * kernel allows a process's UTS namespace to override the release info :).
 */
uint64_t os_linux_version(struct target *target) {
    uint64_t retval = 0;
    char *vstring;
    struct bsymbol *bs;
    struct value *v;
    char *endptr;
    char *next;
    unsigned long int vnum;
    uint64_t *sretval;

    /* Check cache. */
    if ((vstring = (char *)target_gkv_lookup(target,"os_linux_version_string"))
	&& (sretval = (uint64_t *)target_gkv_lookup(target,"os_linux_version")))
	return *sretval;

    /* Otherwise load it. */
    if (!(bs = target_lookup_sym(target,"system_utsname.release",NULL,NULL,
				 SYMBOL_TYPE_FLAG_VAR))
	&& !(bs = target_lookup_sym(target,"init_uts_ns.name.release",NULL,NULL,
				    SYMBOL_TYPE_FLAG_VAR))) {
	verror("could not find system_utsname.release"
	       " nor init_uts_ns.name.release!\n");
	return 0;
    }
    else if (!(v = target_load_symbol(target,TID_GLOBAL,bs,LOAD_FLAG_NONE))) {
	verror("could not load %s!\n",symbol_get_name(bsymbol_get_symbol(bs)));
	return 0;
    }

    bsymbol_release(bs);

    /* NULL out the last byte of the .release char array just to be safe */
    v->buf[v->bufsiz - 1] = '\0';

    /* Release is always, always <major>.<minor>.<patchlevel> */
    next = v->buf;
    endptr = NULL;
    vnum = strtoul(next,&endptr,10);
    if (endptr == next) {
	verror("could not determine major release number from '%s'!\n",v->buf);
	retval = 0;
	goto out;
    }
    retval |= vnum << 16;

    next = endptr + 1;
    endptr = NULL;
    vnum = strtoul(next,&endptr,10);
    if (endptr == next) {
	verror("could not determine minor release number from '%s'!\n",v->buf);
	retval = 0;
	goto out;
    }
    retval |= vnum << 8;

    next = endptr + 1;
    endptr = NULL;
    vnum = strtoul(next,&endptr,10);
    if (endptr == next) {
	verror("could not determine patchlevel release number from '%s'!\n",
	       v->buf);
	retval = 0;
	goto out;
    }
    retval |= vnum;

    vdebug(5,LA_TARGET,LF_OS,
	   "version number %"PRIu64" (0x%"PRIx64") from '%s'",
	   retval,v->buf);

    /* Cache it. */
    target_gkv_insert(target,"os_linux_version_string",strdup(v->buf),
		      target_gkv_dtor_free);
    sretval = malloc(sizeof(*sretval));
    *(uint64_t *)sretval = retval;
    target_gkv_insert(target,"os_linux_version",sretval,
		      target_gkv_dtor_free);

 out:
    bsymbol_release(bs);
    value_free(v);

    return retval;
}

int os_linux_version_cmp(struct target *target,uint64_t vers) {
    uint64_t ourvers;

    ourvers = target_os_version(target);

    if (ourvers == vers)
	return 0;
    else if (ourvers < vers)
	return -1;
    else
	return 1;
}

char *os_linux_version_string(struct target *target) {
    target_os_version(target);
    return (char *)target_gkv_lookup(target,"os_linux_version");
}

static void __os_linux_syscalls_by_num_dtor(struct target *target,
					    char *key,void *value) {
    GHashTableIter iter;
    gpointer vp;
    struct target_os_syscall *sc;
    GHashTable *syscalls_by_num;

    syscalls_by_num = (GHashTable *)value;

    if (syscalls_by_num) {
	g_hash_table_iter_init(&iter,syscalls_by_num);
	while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	    sc = (struct target_os_syscall *)vp;

	    if (sc->bsymbol)
		bsymbol_release(sc->bsymbol);
	    free(sc);
	}

	g_hash_table_destroy(syscalls_by_num);
    }
}

static void __os_linux_syscalls_by_X_dtor(struct target *target,
					  char *key,void *value) {
    GHashTable *syscalls_by_X;

    syscalls_by_X = (GHashTable *)value;

    if (syscalls_by_X) 
	g_hash_table_destroy(syscalls_by_X);
}

int os_linux_syscall_table_load(struct target *target) {
    struct bsymbol *bs = NULL;
    struct value *v = NULL;
    char *current;
    struct target_os_syscall *sc;
    GHashTable *syscalls_by_num;
    GHashTable *syscalls_by_addr;
    GHashTable *syscalls_by_name;

    if (target_gkv_lookup(target,"os_linux_syscalls_by_num")) 
	return 0;

    /*
     * Lookup and load the value of sys_call_table.  For x86[_64], the
     * values are the addresses of the system call functions.  We look
     * up those addrs in debuginfo and fill in the tables.
     */
    bs = target_lookup_sym(target,"sys_call_table",NULL,NULL,
			   SYMBOL_TYPE_FLAG_VAR);
    if (!bs) {
	verror("could not lookup symbol sys_call_table!\n");
	return -1;
    }

    v = target_load_symbol(target,TID_GLOBAL,bs,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load sys_call_table!\n");
	bsymbol_release(bs);
	bs = NULL;
	return -1;
    }

    syscalls_by_num = g_hash_table_new(g_direct_hash,g_direct_equal);
    syscalls_by_addr = g_hash_table_new(g_direct_hash,g_direct_equal);
    syscalls_by_name = g_hash_table_new(g_str_hash,g_str_equal);

    /* Insert them all, but just set one with a
     * target_os_syscall_table_unload() wrapped as a gkv dtor to unload
     * them all.
     */
    target_gkv_insert(target,"os_linux_syscalls_by_num",syscalls_by_num,
		      __os_linux_syscalls_by_num_dtor);
    target_gkv_insert(target,"os_linux_syscalls_by_name",syscalls_by_name,
		      __os_linux_syscalls_by_X_dtor);
    target_gkv_insert(target,"os_linux_syscalls_by_addr",syscalls_by_addr,
		      __os_linux_syscalls_by_X_dtor);

    /*
     * Go through the "array" according to target wordsize and lookup
     * the addrs.
     */
    current = v->buf;
    while ((current - v->buf) < v->bufsiz) {
	sc = calloc(1,sizeof(*sc));
	sc->num = (current - v->buf) / target->wordsize;
	memcpy(&sc->addr,current,target->wordsize);

	sc->bsymbol = target_lookup_sym_addr(target,sc->addr);
	if(sc->bsymbol)
	    sc->args = symbol_get_members(bsymbol_get_symbol(sc->bsymbol),
					  SYMBOL_VAR_TYPE_FLAG_ARG);

	g_hash_table_insert(syscalls_by_num,
			    (gpointer)(uintptr_t)sc->num,sc);
	if (sc->addr)
	    g_hash_table_insert(syscalls_by_addr,
				(gpointer)(uintptr_t)sc->addr,sc);
	if (sc->bsymbol && bsymbol_get_name(sc->bsymbol))
	    g_hash_table_insert(syscalls_by_name,
				(gpointer)bsymbol_get_name(sc->bsymbol),sc);

	if (sc->bsymbol && bsymbol_get_name(sc->bsymbol))
	    vdebug(9,LA_TARGET,LF_XV,"syscall '%s' num %d addr 0x%"PRIxADDR"\n",
		   bsymbol_get_name(sc->bsymbol),sc->num,sc->addr);
	else 
	    vdebug(9,LA_TARGET,LF_XV,"syscall '' num %d addr 0x%"PRIxADDR"\n",
		   sc->num,sc->addr);

	current += target->wordsize;
    }

    value_free(v);
    bsymbol_release(bs);

    return 0;
}

int os_linux_syscall_table_unload(struct target *target) {
    GHashTableIter iter;
    gpointer vp;
    struct target_os_syscall *sc;
    GHashTable *syscalls_by_num;
    GHashTable *syscalls_by_addr;
    GHashTable *syscalls_by_name;

    syscalls_by_num = (GHashTable *) \
	target_gkv_lookup(target,"os_linux_syscalls_by_num");
    syscalls_by_name = (GHashTable *) \
	target_gkv_lookup(target,"os_linux_syscalls_by_name");
    syscalls_by_addr = (GHashTable *) \
	target_gkv_lookup(target,"os_linux_syscalls_by_addr");

    if (syscalls_by_name) {
	g_hash_table_destroy(syscalls_by_name);
	target_gkv_remove(target,"os_linux_syscalls_by_num");
    }
    if (syscalls_by_addr) {
	g_hash_table_destroy(syscalls_by_addr);
	target_gkv_remove(target,"os_linux_syscalls_by_addr");
    }
    if (syscalls_by_num) {
	g_hash_table_iter_init(&iter,syscalls_by_num);
	while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	    sc = (struct target_os_syscall *)vp;

	    if (sc->bsymbol)
		bsymbol_release(sc->bsymbol);
	    if (sc->args)
		array_list_free(sc->args);
	    free(sc);
	}

	g_hash_table_destroy(syscalls_by_num);
	target_gkv_remove(target,"os_linux_syscalls_by_num");
    }

    return 0;
}

GHashTable *os_linux_syscall_table_get(struct target *target) {
    return (GHashTable *)target_gkv_lookup(target,"os_linux_syscalls_by_num");
}

struct target_os_syscall *os_linux_syscall_lookup_name(struct target *target,
						       char *name) {
    GHashTable *syscalls;

    if (!(syscalls = (GHashTable *) \
	      target_gkv_lookup(target,"os_linux_syscalls_by_name"))) {
	if (target_os_syscall_table_load(target))
	    return NULL;
	else
	    syscalls = (GHashTable *) \
		target_gkv_lookup(target,"os_linux_syscalls_by_name");
    }

    return (struct target_os_syscall *)g_hash_table_lookup(syscalls,name);
}

struct target_os_syscall *os_linux_syscall_lookup_num(struct target *target,
						      int num) {
    GHashTable *syscalls;

    if (!(syscalls = (GHashTable *) \
	      target_gkv_lookup(target,"os_linux_syscalls_by_num"))) {
	if (target_os_syscall_table_load(target))
	    return NULL;
	else
	    syscalls = (GHashTable *) \
		target_gkv_lookup(target,"os_linux_syscalls_by_num");
    }

    return (struct target_os_syscall *) \
	g_hash_table_lookup(syscalls,(gpointer)(uintptr_t)num);
}

struct target_os_syscall *os_linux_syscall_lookup_addr(struct target *target,
						       ADDR addr) {
    GHashTable *syscalls;

    if (!(syscalls = (GHashTable *) \
	      target_gkv_lookup(target,"os_linux_syscalls_by_addr"))) {
	if (target_os_syscall_table_load(target))
	    return NULL;
	else
	    syscalls = (GHashTable *) \
		target_gkv_lookup(target,"os_linux_syscalls_by_addr");
    }

    return (struct target_os_syscall *) \
	g_hash_table_lookup(syscalls,(gpointer)(uintptr_t)addr);
}



struct old_linux_syscall_probe_state {
    struct bsymbol *system_call_symbol;
    ADDR system_call_base_addr;
    struct array_list *system_call_ret_idata_list;

    /*
     * We support a couple kinds of syscall probing.  Which is used is
     * up to the user.  By passing NULL to linux_syscall_probe for the
     * @name param, they install probes on the syscall entry/exit path.
     * By passing a specific name to that function, they place a probe
     * on the entry of that specific syscall, as well as on the return
     * path.
     *
     * Hm, it is easier to probe specific syscalls by just probing them
     * internally (i.e., entry instr, and any RET/IRET instrs).  Also a
     * faster option than probing on the generic syscall ret path.  I
     * think we can have three options for now:
     *
     * 1) probe a single syscall only
     * 2) probe a single syscall, but probe the generic return path
     * 3) probe the generic entry/exit paths
     */
    struct probe *syscall_entry_probe;
    struct probe *syscall_ret_probe;

    /* Currently in-flight syscall per-thread. */
    GHashTable *thread_syscall_state_current;
    /* Last completed syscall per-thread. */
    GHashTable *thread_syscall_state_last;
};

static int _os_linux_syscall_probe_init(struct target *target) {
    struct bsymbol *system_call_bsymbol = NULL;
    ADDR system_call_base_addr = 0;
    struct array_list *system_call_ret_idata_list = NULL;
    int caller_should_free = 0;
    ADDR *ap;
    unsigned char *cbuf = NULL;

    /* Check cache to see if we've loaded symbol and code info. */
    if (target_gkv_lookup(target,"os_linux_system_call_bsymbol"))
	return 0;

    /*
     * Do some setup for probing syscall returns.  We disasm
     * system_call, placing probes on IRET and SYSRET; so we need the
     * offsets of any of those instructions within system_call.
     */

    system_call_bsymbol = target_lookup_sym(target,"system_call",NULL,NULL,
					    SYMBOL_TYPE_FLAG_FUNCTION);
    if (!system_call_bsymbol) {
	verror("could not lookup system_call;"
	       " smart syscall probing will fail!\n");
	goto errout;
    }
    else if (location_resolve_function_base(target,
					    system_call_bsymbol->lsymbol,
					    system_call_bsymbol->region,
					    &system_call_base_addr,NULL)) {
	verror("could not resolve base addr of system_call;"
	       " smart syscall probing will fail!\n");
	goto errout;
    }
    else if (!(cbuf = target_load_code(target,system_call_base_addr,
				       symbol_bytesize(bsymbol_get_symbol(system_call_bsymbol)),
				       0,0,&caller_should_free))) {
	verror("could not load code of system_call;"
	       " smart syscall probing will fail!\n");
	goto errout;
    }
    else if (disasm_get_control_flow_offsets(target,
					     INST_CF_IRET | INST_CF_SYSRET,
					     cbuf,symbol_bytesize(bsymbol_get_symbol(system_call_bsymbol)),
					     &system_call_ret_idata_list,
					     system_call_base_addr,1)) {
	verror("could not disassemble system_call in range"
	       " 0x%"PRIxADDR"-0x%"PRIxADDR";"
	       " smart syscall probing will fail!\n",
	       system_call_base_addr,
	       system_call_base_addr				\
	           + symbol_bytesize(bsymbol_get_symbol(system_call_bsymbol)));
	goto errout;
    }
    else if (!system_call_ret_idata_list 
	     || array_list_len(system_call_ret_idata_list) <= 0) {
	verror("no IRETs or SYSRETs in system_call;"
	       " smart syscall probing will fail!\n");
	goto errout;
    }

    /* Cache. */
    target_gkv_insert(target,"os_linux_system_call_bsymbol",system_call_bsymbol,
		      target_gkv_dtor_bsymbol);
    ap = calloc(1,sizeof(*ap));
    memcpy(ap,&system_call_base_addr,sizeof(*ap));
    target_gkv_insert(target,"os_linux_system_call_base_addr",ap,
		      target_gkv_dtor_free);
    target_gkv_insert(target,"os_linux_system_call_ret_idata_list",
		      system_call_ret_idata_list,
		      target_gkv_dtor_alist_deep_free);

    return 0;

 errout:
    if (system_call_ret_idata_list)
	array_list_deep_free(system_call_ret_idata_list);
    if (caller_should_free)
	free(cbuf);
    if (system_call_bsymbol)
	bsymbol_release(system_call_bsymbol);

    return -1;
}

#define SYSCALL_GLOBAL_ENTRY_PROBE "os_linux_syscall_entry_probe"
#define SYSCALL_GLOBAL_RET_PROBE "os_linux_syscall_ret_probe"

static int __global_entry_uncache(struct probe *probe) {
    /* Steal it cause it is getting autofreed if this is getting called. */
    target_gkv_steal(probe->target,SYSCALL_GLOBAL_ENTRY_PROBE);
    return 0;
}
static struct probe_ops __global_entry_probe_ops = {
    .fini = __global_entry_uncache,
};

static int __global_ret_uncache(struct probe *probe) {
    /* Steal it cause it is getting autofreed if this is getting called. */
    target_gkv_steal(probe->target,SYSCALL_GLOBAL_RET_PROBE);
    return 0;
}
static struct probe_ops __global_ret_probe_ops = {
    .fini = __global_ret_uncache,
};

/* "overload" probe_do_sink_pre_handlers . */
static result_t __syscall_entry_handler(struct probe *probe,tid_t tid,
					void *handler_data,
					struct probe *trigger,
					struct probe *base) {
    struct target *target;
    struct target_os_syscall *syscall;
    struct target_os_syscall_state *scs;
    REGVAL scnum;
    struct array_list *regvals;
    struct array_list *argvals;
    struct symbol *argsym;
    struct symbol *datatype;
    int j;
    /*
     * On x86_64 Linux, syscall args are in %rdi, %rsi, %rdx, %r10, %r8, %r9.
     */
    static REG regs_x86_64[6] = { 5,4,1,10,8,9 };
    /*
     * On i386 Linux, syscall args are in %ebx, %ecx, %edx, %esi, %edi, %ebp.
     */
    static REG regs_i386[6] = { 3,1,2,6,7,5 };
    static REG *regs;
    struct value *v;

    target = probe->target;

    scnum = target_read_creg(target,tid,CREG_AX);
    if (!(syscall = target_os_syscall_lookup_num(target,(int)scnum))) {
	vwarn("could not find syscall for eax %d in tid %"PRIiTID"; ignoring!\n",
	      (int)scnum,tid);
	return RESULT_SUCCESS;
    }

    scs = target_os_syscall_record_entry(target,tid,syscall);
    if (!scs) {
	verror("could not record syscall entry in tid %"PRIiTID"!\n",tid);
	return RESULT_SUCCESS;
    }

    /*
     * Read args by type, according to the i386/x86_64 calling
     * convention.  Never more than 6 args; just read all the regs.
     */
    if (target->wordsize == 8) 
	regs = regs_x86_64;
    else 
	regs = regs_i386;

    regvals = array_list_create(6);
    for (j = 0; j < 6; ++j) {
	array_list_append(regvals,
			  (void *)(uintptr_t)target_read_reg(target,tid,regs[j]));
    }

    /*
     * The only values we try to autoderef are char * bufs; we need
     * system-specific info to know if/when it's safe to deref the
     * others.  We don't know generically whether a param is in/out.
     */
    if (syscall->args) {
	argvals = array_list_create(6);
	array_list_foreach(syscall->args,j,argsym) {
	    datatype = symbol_get_datatype(argsym);
	    if (!datatype) {
		array_list_append(argvals,NULL);
		continue;
	    }
	    else if (j < 6) {
		v = target_load_type_regval(target,datatype,tid,regs[j],
					    (REGVAL)array_list_item(regvals,j),
					    LOAD_FLAG_AUTO_STRING);
		array_list_append(argvals,v);
	    }
	    else {
		array_list_append(argvals,NULL);
		continue;
	    }
	}
    }
    else 
	argvals = NULL;

    target_os_syscall_record_argv(target,tid,regvals,argvals);

    /* There, now call the probe's sink pre_handlers! */
    return probe_do_sink_pre_handlers(probe,tid,handler_data,trigger,base);
}

/*
 * Call the sink probes' post_handlers -- but we do it BEFORE the return
 * to userspace -- i.e., before the IRET/SYSRET.
 */
static result_t __syscall_ret_handler(struct probe *probe,tid_t tid,
				      void *handler_data,
				      struct probe *trigger,
				      struct probe *base) {
    struct target *target;
    struct target_os_syscall_state *scs;
    REGVAL scnum;

    target = probe->target;

    scs = target_os_syscall_probe_last(target,tid);
    if (!scs) {
	vwarn("could not find a current syscall tid %"PRIiTID"; ignoring!\n",
	      tid);
	return RESULT_SUCCESS;
    }
    else if (scs->returned) {
	vwarn("current syscall for tid %"PRIiTID" already returned; ignoring!\n",
	      tid);
	return RESULT_SUCCESS;
    }

    target_os_syscall_record_return(target,tid,
				    target_read_creg(target,tid,CREG_AX));

    /* There, now call the probe's sink POST_handlers! */
    return probe_do_sink_post_handlers(probe,tid,handler_data,trigger,base);
}

static struct probe *
os_linux_syscall_probe_init_global_entry(struct target *target) {
    struct bsymbol *system_call_bsymbol;
    ADDR *system_call_base_addr = NULL;
    struct probe *probe;

    if ((probe = (struct probe *) \
	     target_gkv_lookup(target,SYSCALL_GLOBAL_ENTRY_PROBE)))
	return probe;

    if (_os_linux_syscall_probe_init(target))
	return NULL;

    system_call_base_addr = (ADDR *) \
	target_gkv_lookup(target,"os_linux_system_call_base_addr");
    system_call_bsymbol = (struct bsymbol *) \
	target_gkv_lookup(target,"os_linux_system_call_bsymbol");

    /*
     * Place probes on all entries.  For some Linux kernels, this might
     * be system_call, AND ia32_sysenter_target (for i386).
     *
     * XXX: do ia32_sysenter_target eventually!
     */

    probe = probe_create(target,TID_GLOBAL,&__global_entry_probe_ops,
			 "system_call",
			 __syscall_entry_handler,NULL,NULL,1,1);

    if (!probe_register_addr(probe,*system_call_base_addr,
			     PROBEPOINT_BREAK,PROBEPOINT_SW,0,0,
			     system_call_bsymbol)) {
	verror("could not register system_call entry probe at 0x%"PRIxADDR"!\n",
	       *system_call_base_addr);
	probe_free(probe,0);
	return NULL;
    }

    /* Cache it. */
    target_gkv_insert(target,SYSCALL_GLOBAL_ENTRY_PROBE,probe,
		      target_gkv_dtor_probe);

    return probe;
}

static struct probe *
os_linux_syscall_probe_init_global_ret(struct target *target) {
    ADDR *system_call_base_addr;
    struct array_list *system_call_ret_idata_list;
    struct probe *rprobe;
    struct probe *probe;
    int name_len;
    char *name;
    struct cf_inst_data *idata;
    int i;

    if ((probe = (struct probe *) \
	     target_gkv_lookup(target,SYSCALL_GLOBAL_RET_PROBE)))
	return probe;

    if (_os_linux_syscall_probe_init(target))
	return NULL;

    if (!(system_call_ret_idata_list = (struct array_list *) \
	      target_gkv_lookup(target,"os_linux_system_call_ret_idata_list"))) {
	verror("BUG: could not find system_call RET info!\n");
	return NULL;
    }

    system_call_base_addr = (ADDR *) \
	target_gkv_lookup(target,"os_linux_system_call_base_addr");

    /*
     * Place probes on all IRET/SYSRET/SYSEXIT in system_call, and
     * register our probe to listen to them.
     */

    probe = probe_create(target,TID_GLOBAL,&__global_ret_probe_ops,
			 "system_call_ret",
			 NULL,__syscall_ret_handler,NULL,1,1);

    /*
     * Create probes one by one on the IRET/SYSRETs and register
     * the metaprobe on them.
     */
    name_len = sizeof("system_call_SYSRET_+") + 12;
    name = malloc(name_len);

    array_list_foreach(system_call_ret_idata_list,i,idata) {
	snprintf(name,name_len,
		 "system_call_%s_+0x%"PRIxOFFSET,
		 (idata->type == INST_SYSRET) ? "SYSRET" : "IRET",
		 idata->offset);

	/* We call any sink probes' POST handlers from our pre_handler. */
	rprobe = probe_create(target,TID_GLOBAL,NULL,name,
			      probe_do_sink_post_handlers,NULL,NULL,1,1);

	if (!probe_register_addr(rprobe,*system_call_base_addr + idata->offset,
				 PROBEPOINT_BREAK,PROBEPOINT_SW,0,0,NULL)) {
	    verror("could not register probe %s at 0x%"PRIxADDR"!\n",
		   rprobe->name,*system_call_base_addr + idata->offset);
	    probe_free(rprobe,1);
	    rprobe = NULL;
	    goto errout;
	}

	if (!probe_register_source(probe,rprobe)) {
	    verror("could not register probe %s on source %s!\n",
		   probe->name,rprobe->name);
	    probe_free(rprobe,1);
	    rprobe = NULL;
	    goto errout;
	}
    }

    /* Cache it. */
    target_gkv_insert(target,SYSCALL_GLOBAL_RET_PROBE,probe,
		      target_gkv_dtor_probe);
    free(name);
    return probe;

 errout:
    probe_free(probe,1);
    free(name);
    return NULL;
}

struct probe *os_linux_syscall_probe_all(struct target *target,tid_t tid,
					 probe_handler_t pre_handler,
					 probe_handler_t post_handler,
					 void *handler_data) {
    struct probe *probe, *eprobe, *rprobe;

    probe = probe_create(target,tid,&target_os_syscall_ret_probe_ops,
			 "syscall_probe_all",
			 pre_handler,post_handler,handler_data,0,1);

    eprobe = os_linux_syscall_probe_init_global_entry(target);
    if (!eprobe) {
	verror("could not setup global system_call entry probes!\n");
	probe_free(probe,1);
	return NULL;
    }
    probe_register_source(probe,eprobe);
    rprobe = os_linux_syscall_probe_init_global_ret(target);
    if (!rprobe) {
	verror("could not setup global system_call ret probes!\n");
	probe_free(probe,1);
	return NULL;
    }
    probe_register_source(probe,rprobe);

    return probe;
}

struct target_os_ops os_linux_generic_ops = {
    .init = os_linux_init,
    .close = os_linux_close,
    .fini = os_linux_fini,
    .os_type = os_linux_type,
    .os_version = os_linux_version,
    .os_version_string = os_linux_version_string,
    .os_version_cmp = os_linux_version_cmp,
    .syscall_table_load = os_linux_syscall_table_load,
    .syscall_table_unload = os_linux_syscall_table_unload,
    .syscall_table_get = os_linux_syscall_table_get,
    .syscall_lookup_name = os_linux_syscall_lookup_name,
    .syscall_lookup_num = os_linux_syscall_lookup_num,
    .syscall_lookup_addr = os_linux_syscall_lookup_addr,
    .syscall_probe = NULL,
    .syscall_probe_all = os_linux_syscall_probe_all,
};
