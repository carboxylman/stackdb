/*
 * Copyright (c) 2011, 2012, 2013, 2014 The University of Utah
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

#include "config.h"

#include <errno.h>
#include <assert.h>
#include <glib.h>
#include <dlfcn.h>
#include "glib_wrapper.h"
#include "arch.h"
#include "regcache.h"
#include "rfilter.h"
#include "binfile.h"
#include "dwdebug.h"
#include "dwdebug_priv.h"
#include "target_api.h"
#include "target.h"
#include "probe.h"

//#include "target_os.h"
//#include "target_os_linux.h"

#include "target_linux_userproc.h"
#ifdef ENABLE_XENSUPPORT
#include "target_xen_vm.h"
#include "target_xen_vm_process.h"
#endif
#include "target_php.h"
#include "target_gdb.h"

/**
 ** Globals.
 **/
extern void os_linux_generic_register(void);

/*
 * A simple global target ID counter.  Callers of target_instantiate or
 * target_create are free to supply their own IDs; if they do not, we
 * generate IDs starting at 1.
 *
 * The target RPC server makes use of this, but calls it with locks
 * held, so its use in that server is thread-safe.  The reason the
 * counter is here, then, and not there, is because the ID must be
 * strongly associated with the target object.  Silly.
 */
static int next_target_id = 1;

static int init_done = 0;

static GHashTable *target_id_tab = NULL;
static GHashTable *target_personality_tab = NULL;

void target_init(void) {
    if (init_done)
	return;

    dwdebug_init();

    target_id_tab = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					  NULL,NULL);
    target_personality_tab = g_hash_table_new_full(g_str_hash,g_str_equal,
						   NULL,NULL);

    /* Register the default personalities. */
    os_linux_generic_register();

    init_done = 1;
}

void target_fini(void) {
    GHashTableIter iter;
    struct target *t;
    gpointer kp,vp;

    if (!init_done)
	return;

    /* Double-iterate so that internal loop can remove hashtable nodes. */
    while (g_hash_table_size(target_id_tab) > 0) {
	g_hash_table_iter_init(&iter,target_id_tab);
	while (g_hash_table_iter_next(&iter,NULL,(gpointer)&t)) {
	    target_free(t);
	    break;
	}
    }
    g_hash_table_destroy(target_id_tab);
    target_id_tab = NULL;

    /*
     * Don't free the struct target_personality_ops; it should be
     * statically linked in.
     */
    g_hash_table_iter_init(&iter,target_personality_tab);
    while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	free(kp);
	free(vp);
	break;
    }
    g_hash_table_destroy(target_personality_tab);
    target_personality_tab = NULL;

    dwdebug_fini();

    init_done = 0;
}

struct target *target_lookup_target_id(int id) {
    if (!target_id_tab)
	return NULL;

    return (struct target *) \
	g_hash_table_lookup(target_id_tab,(gpointer)(uintptr_t)id);
}

/**
 ** Target argp parsing stuff.  This loosely wraps argp.  The idea is
 ** that target library users want to write target-backend-independent
 ** programs that use the library.  So this function helps them
 ** automatically instantiate a target from standard options.
 **
 ** The reason we can't use exactly the argp style is because 1) child
 ** parsers cannot see arguments (and the Ptrace parser will eat quoted
 ** arguments (i.e., those following '--') if possible, so we want to
 ** make this work); 2) and because the top-level target argp parser
 ** will optionally only include the target backend argp children
 ** according to user choice (i.e., a program might only support ptrace,
 ** not xen) -- and we have to keep track of that state.
 **
 ** For these reasons, it ends up making more sense to use the driver
 ** program's argp parser as the top-level parser, and glue on our
 ** target argp child parsers -- but then to pass all parsers a 
 ** struct target_driver_argp_parser_state as the input.  Clients can
 ** retrieve their state via target_driver_argp_state().
 **/
error_t target_argp_parse_opt(int key,char *arg,struct argp_state *state);

#define TARGET_ARGP_PERSONALITY     0x333333
#define TARGET_ARGP_PERSONALITY_LIB 0x333334

struct argp_option target_argp_opts[] = {
    { "debug",'d',"LEVEL",0,"Set/increase the debugging level.",-3 },
    { "log-flags",'l',"FLAG,FLAG,...",0,"Set the debugging flags",-3 },
    { "warn",'w',"LEVEL",0,"Set/increase the warning level.",-3 },
    { "target-type",'t',"TYPENAME",0,
      "Forcibly set the target type (ptrace"
#ifdef ENABLE_XENSUPPORT
      ",xen,xen-process"
#endif
      "gdb).",-3 },
    { "personality",TARGET_ARGP_PERSONALITY,"PERSONALITY",0,
      "Forcibly set the target personality (linux,process,php).",-3 },
    { "personality-lib",TARGET_ARGP_PERSONALITY_LIB,"PERSONALITY_LIB_FILENAME",0,
      "Specify a shared library where the personality specified by --personality should be loaded from.",-3 },
    { "start-paused",'P',0,0,"Leave target paused after launch.",-3 },
    { "soft-breakpoints",'s',0,0,"Force software breakpoints.",-3 },
    { "debugfile-load-opts",'F',"LOAD-OPTS",0,"Add a set of debugfile load options.",-3 },
    { "breakpoint-mode",'L',"STRICT-LEVEL",0,"Set/increase the breakpoint mode level.",-3 },
    { "target-id",'i',"ID",0,"Specify a numeric ID for the target.",0 },
    { "in-file",'I',"FILE",0,"Deliver contents of FILE to target on stdin (if avail).",-4 },
    { "out-file",'O',"FILE",0,"Log stdout (if avail) to FILE.",-4 },
    { "err-file",'E',"FILE",0,"Log stderr (if avail) to FILE.",-4 },
    { "kill-on-close",'k',NULL,0,"Destroy target on close (SIGKILL).",-4 },
    { "debugfile-root-prefix",'R',"DIR",0,
      "Set an alternate root prefix for debuginfo and binfile resolution.",0 },
    { "active-probing",'a',"FLAG,FLAG,...",0,
      "A list of active probing flags to enable (disabled by default)"
      " (thread_entry thread_exit memory other)",0 },
    { 0,0,0,0,0,0 }
};

int target_spec_to_argv(struct target_spec *spec,char *arg0,
			int *argc,char ***argv) {
    int rc;
    char **backend_argv = NULL;
    int backend_argc = 0;
    char **av = NULL;
    int ac = 0;
    int j;
    int i;
    int len;

    /* Do the backend first. */
    if (spec->target_type == TARGET_TYPE_PTRACE) {
	if ((rc = linux_userproc_spec_to_argv(spec,&backend_argc,&backend_argv))) {
	    verror("linux_userproc_spec_to_argv failed!\n");
	    return -1;
	}
    }
#ifdef ENABLE_XENSUPPORT
    else if (spec->target_type == TARGET_TYPE_XEN) {
	if ((rc = xen_vm_spec_to_argv(spec,&backend_argc,&backend_argv))) {
	    verror("xen_vm_spec_to_argv failed!\n");
	    return -1;
	}
    }
    else if (spec->target_type == TARGET_TYPE_XEN_PROCESS) {
	/*
	 * XXX: xen_vm_spec_process has nothing; don't do anything.
	 */
	/*
	if ((rc = xen_vm_process_spec_to_argv(spec,&backend_argc,&backend_argv))) {
	    verror("xen_vm_process_spec_to_argv failed!\n");
	    return -1;
	}
	*/
    }
#endif
    else if (spec->target_type == TARGET_TYPE_GDB) {
	if ((rc = gdb_spec_to_argv(spec,&backend_argc,&backend_argv))) {
	    verror("gdb_spec_to_argv failed!\n");
	    return -1;
	}
    }
    else {
	verror("unsupported backend type %d!\n",spec->target_type);
	return -1;
    }

    /*
     * Count arg0.
     */
    if (arg0) 
	ac += 1;

    /*
     * Do the backend type.
     */
    ac += 2;

    /*
     * Now count the generic opts.
     *
     * NB: XXX: for now, we don't do debug levels/flags, since the XML
     * server doesn't expose them to the user, and that is the only
     * caller of this function.
     */
    if (spec->start_paused) 
	ac += 1;
    if (spec->style == PROBEPOINT_SW)
	ac += 1;
    if (spec->bpmode > 0)
	ac += 2;
    if (spec->target_id > -1)
	ac += 2;
    if (spec->infile)
	ac += 2;
    if (spec->outfile)
	ac += 2;
    if (spec->errfile)
	ac += 2;
    if (spec->kill_on_close) 
	ac += 1;
    if (spec->personality)
	ac += 2;
    if (spec->personality_lib)
	ac += 2;
    if (spec->debugfile_root_prefix)
	ac += 2;
    if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY
	|| spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT
	|| spec->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY 
	|| spec->active_probe_flags & ACTIVE_PROBE_FLAG_OTHER)
	ac += 2;

    ac += backend_argc;
    av = calloc(ac + 1,sizeof(char *));

    j = 0;

    /*
     * Handle arg0.
     */
    if (arg0) {
	av[j++] = strdup(arg0);
    }

    /*
     * Do the backend type.
     */
    av[j++] = strdup("-t");
    if (spec->target_type == TARGET_TYPE_PTRACE)
	av[j++] = strdup("ptrace");
#ifdef ENABLE_XENSUPPORT
    else if (spec->target_type == TARGET_TYPE_XEN)
	av[j++] = strdup("xen");
    else if (spec->target_type == TARGET_TYPE_XEN_PROCESS)
	av[j++] = strdup("xen-process");
#endif
    else if (spec->target_type == TARGET_TYPE_GDB)
	av[j++] = strdup("gdb");
    else
	av[j++] = strdup("UNKNOWN");

    /* Do the generic opts. */
    if (spec->start_paused) {
	av[j++] = strdup("-P");
    }
    if (spec->style == PROBEPOINT_SW) {
	av[j++] = strdup("-s");
    }
    if (spec->bpmode > 0) {
	av[j++] = strdup("-L");
	av[j] = malloc(11);
	snprintf(av[j],11,"%d",spec->bpmode);
	++j;
    }
    if (spec->target_id > -1) {
	av[j++] = strdup("-i");
	av[j] = malloc(11);
	snprintf(av[j],11,"%d",spec->target_id);
	++j;
    }
    if (spec->infile) {
	av[j++] = strdup("-I");
	av[j++] = strdup(spec->infile);
    }
    if (spec->outfile) {
	av[j++] = strdup("-O");
	av[j++] = strdup(spec->outfile);
    }
    if (spec->errfile) {
	av[j++] = strdup("-E");
	av[j++] = strdup(spec->errfile);
    }
    if (spec->kill_on_close) {
	av[j++] = strdup("-k");
    }
    if (spec->personality) {
	av[j++] = strdup("--personality");
	av[j++] = strdup(spec->personality);
    }
    if (spec->personality_lib) {
	av[j++] = strdup("--personality-lib");
	av[j++] = strdup(spec->personality_lib);
    }
    if (spec->debugfile_root_prefix) {
	av[j++] = strdup("-R");
	av[j++] = strdup(spec->debugfile_root_prefix);
    }
    if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY
	|| spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT
	|| spec->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY 
	|| spec->active_probe_flags & ACTIVE_PROBE_FLAG_OTHER) {
	av[j++] = strdup("-a");
	len = 0;
	if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY)
	    len += sizeof("thread_entry,");
	if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT)
	    len += sizeof("thread_exit,");
	if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY)
	    len += sizeof("memory,");
	if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_OTHER)
	    len += sizeof("other,");
	len += 1;
	av[j] = malloc(len);
	rc = 0;
	if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY)
	    rc += snprintf(av[j] + rc,len - rc,"%s","thread_entry,");
	if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT)
	    rc += snprintf(av[j] + rc,len - rc,"%s","thread_exit,");
	if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY)
	    rc += snprintf(av[j] + rc,len - rc,"%s","memory,");
	if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_OTHER)
	    rc += snprintf(av[j] + rc,len - rc,"%s","other,");

	++j;
    }

    for (i = 0; i < backend_argc; ++i) 
	av[j++] = backend_argv[i];

    av[j] = NULL;

    if (backend_argc > 0)
	free(backend_argv);

    if (argc)
	*argc = ac;
    if (argv)
	*argv = av;

    return 0;
}

/*
 * The children this library will utilize.
 */
extern struct argp linux_userproc_argp;
extern char *linux_userproc_argp_header;
#ifdef ENABLE_XENSUPPORT
extern struct argp xen_vm_argp;
extern char *xen_vm_argp_header;
#endif

struct target_spec *target_argp_target_spec(struct argp_state *state) {
    if (!state)
	return NULL;

    return ((struct target_argp_parser_state *) \
	    state->input)->spec;
}
void *target_argp_driver_state(struct argp_state *state) {
    if (!state)
	return NULL;

    return ((struct target_argp_parser_state *) \
	    state->input)->driver_state;
}

struct target_spec *target_argp_driver_parse(struct argp *driver_parser,
					     void *driver_state,
					     int argc,char **argv,
					     target_type_t target_types,
					     int filter_quoted) {
    error_t retval;
    int i;
    struct target_argp_parser_state tstate;
    /*
     * These are our subparsers.  They are optional, so we have to build
     * them manually.
     */
    struct argp_child target_argp_children[3];
    /*
     * This is the "main" target arg parser, to be used if the caller
     * has no arguments.
     */
    struct argp target_argp = { 
	target_argp_opts,target_argp_parse_opt,
	NULL,NULL,target_argp_children,NULL,NULL
    };
    /*
     * This is the main child target arg parser, to be used if the
     * caller has its own arguments.
     */
    struct argp_child target_argp_child[] = {
	{ &target_argp,0,"Generic Target Options",0 },
	{ 0,0,0,0 },
    };

    if (!target_types) {
	errno = EINVAL;
	return NULL;
    }

    memset(&tstate,0,sizeof(tstate));

    tstate.driver_state = driver_state;
    tstate.spec = target_build_spec(TARGET_TYPE_NONE,TARGET_MODE_NONE);

    if (filter_quoted) {
	for (i = 0; i < argc; ++i) {
	    if (strncmp("--",argv[i],2) == 0 && argv[i][2] == '\0') {
		argv[i] = NULL;
		if (++i < argc) {
		    tstate.quoted_start = i;
		    tstate.quoted_argc = argc - i;
		    tstate.quoted_argv = &argv[i];
		}
		argc = i - 1;
		break;
	    }
	}
    }

    tstate.num_children = 0;
    if (target_types & TARGET_TYPE_PTRACE) {
	target_argp_children[tstate.num_children].argp = &linux_userproc_argp;
	target_argp_children[tstate.num_children].flags = 0;
	target_argp_children[tstate.num_children].header = linux_userproc_argp_header;
	target_argp_children[tstate.num_children].group = 0;
	++tstate.num_children;
    }
#ifdef ENABLE_XENSUPPORT
    if (target_types & TARGET_TYPE_XEN) {
	target_argp_children[tstate.num_children].argp = &xen_vm_argp;
	target_argp_children[tstate.num_children].flags = 0;
	target_argp_children[tstate.num_children].header = xen_vm_argp_header;
	target_argp_children[tstate.num_children].group = 0;
	++tstate.num_children;
    }
#endif
    if (target_types & TARGET_TYPE_GDB) {
	target_argp_children[tstate.num_children].argp = &gdb_argp;
	target_argp_children[tstate.num_children].flags = 0;
	target_argp_children[tstate.num_children].header = gdb_argp_header;
	target_argp_children[tstate.num_children].group = 0;
	++tstate.num_children;
    }

    target_argp_children[tstate.num_children].argp = NULL;
    target_argp_children[tstate.num_children].flags = 0;
    target_argp_children[tstate.num_children].header = NULL;
    target_argp_children[tstate.num_children].group = 0;

    if (driver_parser) {
	driver_parser->children = target_argp_child;

	retval = argp_parse(driver_parser,argc,argv,0,NULL,&tstate);

	driver_parser->children = NULL;
    }
    else {
	retval = argp_parse(&target_argp,argc,argv,0,NULL,&tstate);
    }

    if (retval) {
	if (tstate.spec && tstate.spec->backend_spec)
	    free(tstate.spec->backend_spec);
	if (tstate.spec)
	    free(tstate.spec);
	tstate.spec = NULL;
    }

    return tstate.spec;
}

void target_driver_argp_init_children(struct argp_state *state) {
    state->child_inputs[0] = state->input;
}

error_t target_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct target_argp_parser_state *tstate = \
	(struct target_argp_parser_state *)state->input;
    struct target_spec *spec = NULL;
    char *argcopy;
    struct debugfile_load_opts *opts;
    int i;
    target_type_t tmptype;
    char *saveptr;
    char *token;

    if (tstate)
	spec = tstate->spec;

    switch (key) {
    case ARGP_KEY_ARG:
    case ARGP_KEY_ARGS:
	return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_INIT:
	for (i = 0; i < tstate->num_children; ++i) 
	    state->child_inputs[i] = tstate;
	break;
    case ARGP_KEY_END:
    case ARGP_KEY_NO_ARGS:
    case ARGP_KEY_SUCCESS:
    case ARGP_KEY_ERROR:
	return 0;
    case ARGP_KEY_FINI:
	/*
	 * Check for at least *something*.
	 */
	if (spec && spec->target_type == TARGET_TYPE_NONE) {
	    verror("you must specify at least one kind of target!\n");
	    return EINVAL;
	}
	return 0;

    case 't':
	/*
	 * If the child parser already autoselect a type based on prior
	 * args, error!
	 */
	if (strcmp(arg,"ptrace") == 0)
	    tmptype = TARGET_TYPE_PTRACE;
#ifdef ENABLE_XENSUPPORT
	else if (strcmp(arg,"xen-process") == 0) 
	    tmptype = TARGET_TYPE_XEN_PROCESS;
	else if (strcmp(arg,"xen") == 0) 
	    tmptype = TARGET_TYPE_XEN;
#endif
	else if (strcmp(arg,"php") == 0) 
	    tmptype = TARGET_TYPE_PHP;
	else if (strcmp(arg,"gdb") == 0)
	    tmptype = TARGET_TYPE_GDB;
	else {
	    verror("bad target type %s!\n",arg);
	    return EINVAL;
	}

	if (spec->target_type != TARGET_TYPE_NONE
	    && spec->target_type != tmptype) {
	    verror("target type already inferred or set; cannot set type %s!\n",
		   arg);
	    return EINVAL;
	}
	else if (spec->target_type == TARGET_TYPE_NONE) {
	    spec->target_type = tmptype;
	    if (tmptype == TARGET_TYPE_PTRACE)
		spec->backend_spec = linux_userproc_build_spec();
#ifdef ENABLE_XENSUPPORT
	    else if (strcmp(arg,"xen-process") == 0) 
		spec->backend_spec = xen_vm_process_build_spec();
	    else if (strcmp(arg,"xen") == 0) 
		spec->backend_spec = xen_vm_build_spec();
#endif
	    else if (strcmp(arg,"php") == 0) 
		spec->backend_spec = php_build_spec();
	    else if (tmptype == TARGET_TYPE_GDB)
		spec->backend_spec = gdb_build_spec();
	}

	break;
    case 'd':
	if (arg) {
	    if (*arg == 'd') {
		arg = &arg[1];
		vmi_inc_log_level();
		while (*arg == 'd') {
		    vmi_inc_log_level();
		    arg = &arg[1];
		}
	    }
	    else
		vmi_set_log_level(atoi(arg));
	}
	else
	    vmi_inc_log_level();
	break;
    case 'w':
	if (arg) {
	    if (*arg == 'w') {
		arg = &arg[1];
		vmi_inc_warn_level();
		while (*arg == 'w') {
		    vmi_inc_warn_level();
		    arg = &arg[1];
		}
	    }
	    else
		vmi_set_warn_level(atoi(arg));
	}
	else
	    vmi_inc_warn_level();
	break;
    case 'l':
	if (vmi_add_log_area_flaglist(arg,NULL)) {
	    verror("bad log level flag in '%s'!\n",arg);
	    return EINVAL;
	}
	break;

    case 's':
	spec->style = PROBEPOINT_SW;
	break;
    case 'F':
	argcopy = strdup(arg);

	opts = debugfile_load_opts_parse(argcopy);

	if (!opts) {
	    verror("bad debugfile_load_opts '%s'!\n",argcopy);
	    free(argcopy);
	    for (i = 0; i < array_list_len(spec->debugfile_load_opts_list); ++i)
		debugfile_load_opts_free((struct debugfile_load_opts *) \
					 array_list_item(spec->debugfile_load_opts_list,i));
	    array_list_free(spec->debugfile_load_opts_list);
	    spec->debugfile_load_opts_list = NULL;

	    return EINVAL;
	}
	else {
	    if (!spec->debugfile_load_opts_list) 
		spec->debugfile_load_opts_list = array_list_create(4);
	    array_list_append(spec->debugfile_load_opts_list,opts);
	    break;
	}
    case 'P':
	spec->start_paused = 1;
	break;
    case 'L':
	if (arg)
	    spec->bpmode = atoi(arg);
	else
	    ++spec->bpmode;
	break;
    case 'i':
	spec->target_id = atoi(arg);
	break;
    case 'I':
	spec->infile = strdup(arg);
	break;
    case 'E':
	spec->errfile = strdup(arg);
	break;
    case 'O':
	spec->outfile = strdup(arg);
	break;
    case 'k':
	spec->kill_on_close = 1;
	break;
    case TARGET_ARGP_PERSONALITY:
	spec->personality = strdup(arg);
	break;
    case TARGET_ARGP_PERSONALITY_LIB:
	spec->personality_lib = strdup(arg);
	break;
    case 'R':
	spec->debugfile_root_prefix = strdup(arg);
	break;
    case 'a':
	argcopy = strdup(arg);
	saveptr = NULL;
	while ((token = strtok_r((!saveptr) ? argcopy : NULL,",",&saveptr))) {
	    if (strcmp("thread_entry",token) == 0)
		spec->active_probe_flags |= ACTIVE_PROBE_FLAG_THREAD_ENTRY;
	    else if (strcmp("thread_exit",token) == 0)
		spec->active_probe_flags |= ACTIVE_PROBE_FLAG_THREAD_EXIT;
	    else if (strcmp("memory",token) == 0)
		spec->active_probe_flags |= ACTIVE_PROBE_FLAG_MEMORY;
	    else if (strcmp("other",token) == 0)
		spec->active_probe_flags |= ACTIVE_PROBE_FLAG_OTHER;
	    else {
		verror("unrecognized active probe flag '%s'!\n",token);
		return EINVAL;
	    }
	}
	break;

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct target_gkv_info {
    void *value;
    target_gkv_dtor_t dtor;
};

int target_gkv_insert(struct target *target,char *key,void *value,
		      target_gkv_dtor_t dtor) {
    struct target_gkv_info *gkvi;

    if (g_hash_table_lookup_extended(target->gkv_store,key,NULL,NULL) == TRUE) {
	errno = EEXIST;
	return -1;
    }

    gkvi = calloc(1,sizeof(*gkvi));
    gkvi->value = value;
    gkvi->dtor = dtor;

    g_hash_table_insert(target->gkv_store,strdup(key),gkvi);

    return 0;
}

void *target_gkv_lookup(struct target *target,char *key) {
    struct target_gkv_info *gkvi;

    if (!(gkvi = (struct target_gkv_info *) \
	      g_hash_table_lookup(target->gkv_store,key))) {
	return NULL;
    }

    return gkvi->value;
}

void *target_gkv_steal(struct target *target,char *key) {
    struct target_gkv_info *gkvi;
    void *value;
    gpointer rval;

    if (g_hash_table_lookup_extended(target->gkv_store,key,
				     NULL,&rval) == FALSE) {
	return NULL;
    }
    gkvi = (struct target_gkv_info *)rval;

    g_hash_table_remove(target->gkv_store,key);
    value = gkvi->value;
    free(gkvi);

    return value;
}

void target_gkv_remove(struct target *target,char *key) {
    struct target_gkv_info *gkvi;
    gpointer rval;

    if (g_hash_table_lookup_extended(target->gkv_store,key,
				     NULL,&rval) == FALSE) {
	return;
    }
    gkvi = (struct target_gkv_info *)rval;

    g_hash_table_remove(target->gkv_store,key);
    if (gkvi->dtor)
	gkvi->dtor(target,key,gkvi->value);
    free(gkvi);

    return;
}

void target_gkv_destroy(struct target *target) {
    GHashTableIter iter;
    gpointer kp,vp;
    char *key;
    struct target_gkv_info *gkvi;

    g_hash_table_iter_init(&iter,target->gkv_store);
    while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	gkvi = (struct target_gkv_info *)vp;
	key = (char *)kp;
	/*
	 * Steal it so the key destructor (free()) isn't called before
	 * we pass it to the dtor -- but so that the value is still not in
	 * the hashtable.
	 */
	g_hash_table_iter_steal(&iter);
	if (gkvi->dtor)
	    gkvi->dtor(target,key,gkvi->value);
	free(key);
	free(gkvi);
    }

    g_hash_table_destroy(target->gkv_store);
    target->gkv_store = NULL;
}

struct target_thread_gkv_info {
    void *value;
    tid_t tid;
    target_thread_gkv_dtor_t dtor;
};

int target_thread_gkv_insert(struct target *target,tid_t tid,
			     char *key,void *value,
			     target_thread_gkv_dtor_t dtor) {
    struct target_thread_gkv_info *gkvi;
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	errno = ESRCH;
	verror("could not lookup thread %"PRIiTID"; forgot to load?\n",tid);
	return -1;
    }

    if (g_hash_table_lookup_extended(tthread->gkv_store,key,NULL,NULL) == TRUE) {
	errno = EEXIST;
	return -1;
    }

    gkvi = calloc(1,sizeof(*gkvi));
    gkvi->value = value;
    gkvi->tid = tid;
    gkvi->dtor = dtor;

    g_hash_table_insert(tthread->gkv_store,strdup(key),gkvi);

    return 0;
}

void *target_thread_gkv_lookup(struct target *target,tid_t tid,char *key) {
    struct target_thread_gkv_info *gkvi;
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	errno = ESRCH;
	verror("could not lookup thread %"PRIiTID"; forgot to load?\n",tid);
	return NULL;
    }

    if (!(gkvi = (struct target_thread_gkv_info *) \
	      g_hash_table_lookup(tthread->gkv_store,key))) {
	return NULL;
    }

    return gkvi->value;
}

void *target_thread_gkv_steal(struct target *target,tid_t tid,char *key) {
    struct target_thread_gkv_info *gkvi;
    void *value;
    struct target_thread *tthread;
    gpointer rval;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	errno = ESRCH;
	verror("could not lookup thread %"PRIiTID"; forgot to load?\n",tid);
	return NULL;
    }

    if (g_hash_table_lookup_extended(tthread->gkv_store,key,
				     NULL,&rval) == FALSE) {
	return NULL;
    }
    gkvi = (struct target_thread_gkv_info *)rval;

    g_hash_table_remove(tthread->gkv_store,key);
    value = gkvi->value;
    free(gkvi);

    return value;
}

void target_thread_gkv_remove(struct target *target,tid_t tid,char *key) {
    struct target_thread_gkv_info *gkvi;
    struct target_thread *tthread;
    gpointer rval;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	errno = ESRCH;
	verror("could not lookup thread %"PRIiTID"; forgot to load?\n",tid);
	return;
    }

    if (g_hash_table_lookup_extended(tthread->gkv_store,key,
				     NULL,&rval) == FALSE) {
	return;
    }
    gkvi = (struct target_thread_gkv_info *)rval;

    g_hash_table_remove(tthread->gkv_store,key);
    if (gkvi->dtor)
	gkvi->dtor(target,gkvi->tid,key,gkvi->value);
    free(gkvi);

    return;
}

void target_thread_gkv_destroy(struct target *target,
			       struct target_thread *tthread) {
    GHashTableIter iter;
    gpointer kp,vp;
    char *key;
    struct target_thread_gkv_info *gkvi;

    if (!tthread->gkv_store)
	return;

    g_hash_table_iter_init(&iter,tthread->gkv_store);
    while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	gkvi = (struct target_thread_gkv_info *)vp;
	key = (char *)kp;
	/*
	 * Steal it so the key destructor (free()) isn't called before
	 * we pass it to the dtor -- but so that the value is still not in
	 * the hashtable.
	 */
	g_hash_table_iter_steal(&iter);
	if (gkvi->dtor)
	    gkvi->dtor(target,gkvi->tid,key,gkvi->value);
	free(key);
	free(gkvi);
    }

    g_hash_table_destroy(tthread->gkv_store);
    tthread->gkv_store = NULL;
}

void target_add_state_change(struct target *target,tid_t tid,
			     target_state_change_type_t chtype,
			     unsigned long code,unsigned long data,
			     ADDR start,ADDR end,char *msg) {
    struct target_state_change *retval = calloc(1,sizeof(*retval));

    retval->tid = tid;
    retval->chtype = chtype;
    retval->code = code;
    retval->data = data;
    retval->start = start;
    retval->end = end;
    if (msg)
	retval->msg = strdup(msg);

    vdebug(5,LA_TARGET,LF_TARGET,
	   "state changed (chtype=%d,code=0x%lx,data=0x%lx) on target(%s)\n",
	   chtype,code,data,target->name);

    array_list_append(target->state_changes,retval);
}

void target_clear_state_changes(struct target *target) {
    struct target_state_change *change;
    int i;

    if (!target->state_changes)
	return;

    if (array_list_len(target->state_changes)) {
	vdebug(5,LA_TARGET,LF_TARGET,
	       "clearing %d state changes on target(%s)\n",
	       array_list_len(target->state_changes),target->name);

	array_list_foreach(target->state_changes,i,change) {
	    if (change->msg)
		free(change->msg);
	    free(change);
	}
    }
    array_list_remove_all(target->state_changes,64);
}

void target_free(struct target *target) {
    struct addrspace *space;
    struct addrspace *tmp;
    int rc;
    int i;
    struct action *action;
    struct probe *probe;
    struct array_list *list;
    REFCNT trefcnt;
    void *key;
    GHashTableIter iter;
    struct target *overlay;
    char *tmpname;
    struct target_thread *tthread;

    if (target->opened) {
	vdebug(3,LA_TARGET,LF_TARGET,
	       "target(%s) not closed; closing first!\n",target->name);
	target_close(target);
    }

    vdebug(5,LA_TARGET,LF_TARGET,"freeing target(%s)\n",target->name);

    if (target->state_changes) {
	vwarnopt(4,LA_TARGET,LF_TARGET,
		 "removing %d state change events; backend BUG?\n",
		 array_list_len(target->state_changes));
	target_clear_state_changes(target);
	array_list_free(target->state_changes);
	target->state_changes = NULL;
    }

    /*
     * Free actions, then probes,  We cannot call probe_free/action_free
     * from a GHashTableIter, because those functions call our
     * target_detach_(action|probe) functions -- which remove the
     * action/probe from its hashtable.  So we copy values to a temp
     * list to avoid this problem.
     *
     * BUT, we would then have to check each list item's addr to make
     * sure it is still in the hashtable; it might have been freed
     * already as a side effect -- i.e., freeing a top-level probe that
     * was a sink of an underlying probe could free the underlying probe
     * too.  So, since our tmp list is values -- we cannot get a freed
     * probe's key to check the hashtable.  So we have to iterate over
     * keys!
     */
    list = array_list_create_from_g_hash_table_keys(target->actions);
    array_list_foreach(list,i,key) {
	action = (struct action *)g_hash_table_lookup(target->actions,key);
	if (action) 
	    action_free(action,1);
    }
    g_hash_table_destroy(target->actions);
    array_list_free(list);

    list = array_list_create_from_g_hash_table_keys(target->probes);
    array_list_foreach(list,i,key) {
	probe = (struct probe *)g_hash_table_lookup(target->probes,key);
	if (probe) 
	    probe_free(probe,1);
    }
    g_hash_table_destroy(target->probes);
    array_list_free(list);

    g_hash_table_destroy(target->soft_probepoints);

    /*
     * If we were an overlay, remove ourself from the underlying
     * target.
     */
    if (target->base)
	target_detach_overlay(target->base,target->base_tid);

    /*
     * Do it for all the overlays first.  Since we might be calling
     * target_free either from the underlying target, or the user might
     * have called on this target directly, we need to protect the iter
     * while loop and restart it over and over again.
     */
    while (g_hash_table_size(target->overlays) > 0) {
	g_hash_table_iter_init(&iter,target->overlays);
	g_hash_table_iter_next(&iter,NULL,(gpointer)&overlay);

	tmpname = strdup(target->name);
	vdebug(5,LA_TARGET,LF_TARGET,
	       "freeing overlay target(%s)\n",tmpname);
	target_free(overlay);
	vdebug(5,LA_TARGET,LF_TARGET,
	       "freed overlay target(%s)\n",tmpname);
	free(tmpname);
    }
    g_hash_table_destroy(target->overlays);
    g_hash_table_destroy(target->overlay_aliases);

    /* These were freed when we closed the target. */
    g_hash_table_destroy(target->mmods);
    g_hash_table_destroy(target->phys_mmods);

    /*
     * If the target backend didn't already do it, 
     * delete all the threads except the global thread (which we remove 
     * manually because targets are allowed to "reuse" one of their real
     * threads as the "global" thread.
     */
    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) {
	if (tthread == target->global_thread) {
	    g_hash_table_iter_remove(&iter);
	}
	else {
	    target_delete_thread(target,tthread,1);
	    g_hash_table_iter_remove(&iter);
	}
    }
    if (target->global_thread)
	target_delete_thread(target,target->global_thread,0);

    if (target->personality_ops && target->personality_ops->fini) {
	vdebug(5,LA_TARGET,LF_TARGET,"fini target(%s) (personality)\n",
	       target->name);
	if ((rc = target->personality_ops->fini(target))) {
	    verror("fini target(%s) (personality) failed; not finishing free!\n",
		   target->name);
	    return;
	}
    }

    vdebug(5,LA_TARGET,LF_TARGET,"fini target(%s)\n",target->name);
    if ((rc = target->ops->fini(target))) {
	verror("fini target(%s) failed; not finishing free!\n",target->name);
	return;
    }

    /* Target should not mess with these after close! */
    target->global_thread = NULL;

    g_hash_table_destroy(target->threads);

    /* Unload the debugfiles we might hold, if we can */
    list_for_each_entry_safe(space,tmp,&target->spaces,space) {
	RPUT(space,addrspace,target,trefcnt);
    }

    g_hash_table_destroy(target->config);
    target->config = NULL;

    /* Unload the binfile */
    if (target->binfile) {
	binfile_release(target->binfile);
	target->binfile = NULL;
    }

    if (target->name)
	free(target->name);

    if (target_id_tab)
	g_hash_table_remove(target_id_tab,(gpointer)(uintptr_t)target->id);

    free(target);
}

struct target_ops *target_get_ops(target_type_t target_type) {
    if (target_type == TARGET_TYPE_PTRACE) 
	return &linux_userspace_process_ops;
#ifdef ENABLE_XENSUPPORT
    else if (target_type == TARGET_TYPE_XEN)
	return &xen_vm_ops;
    else if (target_type == TARGET_TYPE_XEN_PROCESS)
	return &xen_vm_process_ops;
#endif
    else if (target_type == TARGET_TYPE_PHP)
	return &php_ops;
    else if (target_type == TARGET_TYPE_GDB)
	return &gdb_ops;
    else
	return NULL;
}

struct target *target_create(char *type,struct target_spec *spec) {
    struct target_ops *ops;
    struct target *retval;

    ops = target_get_ops(spec->target_type);
    if (!ops) {
	verror("could not find target_ops for target type %d!\n",
	       spec->target_type);
	errno = EINVAL;
	return NULL;
    }

    retval = calloc(1,sizeof(*retval));

    if (spec->target_id < 0)
	retval->id = next_target_id++;
    else {
	if (target_id_tab 
	    && g_hash_table_lookup(target_id_tab,
				   (gpointer)(uintptr_t)spec->target_id)) {
	    verror("target with id %d already exists!\n",spec->target_id);
	    free(retval);
	    errno = EINVAL;
	    return NULL;
	}
	retval->id = spec->target_id;
    }

    retval->state_changes = array_list_create(0);

    retval->ops = ops;
    retval->spec = spec;

    retval->infd = retval->outfd = retval->errfd = -1;

    retval->config = g_hash_table_new_full(g_str_hash,g_str_equal,free,free);

    /* Keys are always copied; values get user-custom dtors */
    retval->gkv_store = g_hash_table_new_full(g_str_hash,g_str_equal,free,NULL);

    INIT_LIST_HEAD(&retval->spaces);

    retval->code_ranges = clrange_create();

    retval->overlays = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					     NULL,NULL);
    retval->overlay_aliases = g_hash_table_new_full(g_direct_hash,g_direct_equal,
						    NULL,NULL);

    retval->threads = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					    /* No names to free! */
					    NULL,NULL);

    retval->actions = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					    NULL,NULL);
    retval->probes = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					   NULL,NULL);
    retval->action_id_counter = 1;
    retval->probe_id_counter = 1;

    retval->soft_probepoints = g_hash_table_new_full(g_direct_hash,g_direct_equal,
						     NULL,NULL);

    retval->mmods = g_hash_table_new_full(g_direct_hash,g_direct_equal,NULL,NULL);

    retval->phys_mmods = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					       NULL,NULL);

    //*(((gint *)retval->soft_probepoints)+1) = 1;
    //*(((gint *)retval->soft_probepoints)) = 0;

    if (target_id_tab)
	g_hash_table_insert(target_id_tab,
			    (gpointer)(uintptr_t)retval->id,retval);

    return retval;
}

/*
 * A utility function that loads a debugfile with the given opts.
 */
int target_associate_debugfile(struct target *target,
			       struct memregion *region,
			       struct debugfile *debugfile) {

    /* if they already loaded this debugfile into this region, error */
    if (g_hash_table_lookup(region->debugfiles,debugfile->filename)) {
	verror("debugfile(%s) already in use in region(%s) in space (%s)!\n",
	       debugfile->filename,region->name,region->space->idstr);
	errno = EBUSY;
	return -1;
    }

    RHOLD(debugfile,region);

    g_hash_table_insert(region->debugfiles,debugfile->filename,debugfile);

    vdebug(1,LA_TARGET,LF_TARGET,
	   "loaded and associated debugfile(%s) for region(%s,"
	   "base_phys=0x%"PRIxADDR",base_virt=0x%"PRIxADDR")"
	   " in space (%s,%d)\n",
	   debugfile->filename,region->name,
	   region->base_phys_addr,region->base_virt_addr,
	   region->space->name,region->space->id);

    return 0;
}

struct scope *target_lookup_addr(struct target *target,uint64_t addr) {
    struct addrspace *space;
    struct memregion *region;
    struct symbol *root;
    struct scope *scope;
    GHashTableIter iter, iter2;
    gpointer value;
    ADDR obj_addr;

    if (list_empty(&target->spaces))
	return NULL;

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if (memregion_contains_real(region,addr))
		goto found;
	}
    }

    return NULL;

 found:
    errno = 0;
    obj_addr = memregion_unrelocate(region,addr,NULL);
    if (errno) {
	return NULL;
    }
    g_hash_table_iter_init(&iter,region->debugfiles);
    while (g_hash_table_iter_next(&iter,NULL,&value)) {
	g_hash_table_iter_init(&iter2,((struct debugfile *)value)->srcfiles);
	while (g_hash_table_iter_next(&iter2,NULL,(gpointer *)&root)) {
	    scope = symbol_read_owned_scope(root);
	    if (scope)
		scope = scope_lookup_addr(scope,obj_addr);
	    if (scope)
		return scope;
	}
    }

    return NULL;
}

struct bsymbol *target_lookup_sym_addr(struct target *target,ADDR addr) {
    struct addrspace *space;
    struct memregion *region;
    GHashTableIter iter;
    gpointer key;
    struct debugfile *debugfile;
    struct bsymbol *bsymbol;
    struct lsymbol *lsymbol;
    struct memrange *range;

    if (list_empty(&target->spaces))
	return NULL;

    vdebug(9,LA_TARGET,LF_SYMBOL,
	   "trying to find symbol at address 0x%"PRIxADDR"\n",
	   addr);

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if ((range = memregion_find_range_real(region,addr)))
		goto found;
	}
    }

    return NULL;

 found:
    g_hash_table_iter_init(&iter,region->debugfiles);
    while (g_hash_table_iter_next(&iter,
				  (gpointer)&key,(gpointer)&debugfile)) {
	if ((lsymbol = debugfile_lookup_addr__int(debugfile,
						  memrange_unrelocate(range,addr)))) {
	    bsymbol = bsymbol_create(lsymbol,region);
	    /* Take a ref to bsymbol on the user's behalf, since this is
	     * a lookup function.
	    */
	    RHOLD(bsymbol,bsymbol);
	    return bsymbol;
	}
    }

    return NULL;
}

struct bsymbol *target_lookup_sym(struct target *target,
				  const char *name,const char *delim,
				  char *srcfile,symbol_type_flag_t ftype) {
    struct addrspace *space;
    struct bsymbol *bsymbol;
    struct lsymbol *lsymbol = NULL;
    struct memregion *region;
    struct debugfile *debugfile;
    GHashTableIter iter;
    gpointer key;
    struct rfilter *rf = NULL;

    if (list_empty(&target->spaces))
	return NULL;

    if (srcfile) {
	rf = rfilter_create(RF_REJECT);
	rfilter_add(rf,srcfile,RF_ACCEPT,NULL);
    }

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    g_hash_table_iter_init(&iter,region->debugfiles);
	    while (g_hash_table_iter_next(&iter,(gpointer)&key,
					  (gpointer)&debugfile)) {
		lsymbol = debugfile_lookup_sym__int(debugfile,(char *)name,
						    delim,rf,ftype);
		if (lsymbol) 
		    goto out;
	    }
	}
    }
    if (rf)
	rfilter_free(rf);
    return NULL;

 out:
    bsymbol = bsymbol_create(lsymbol,region);
    /* Take a ref to bsymbol on the user's behalf, since this is
     * a lookup function.
     */
    RHOLD(bsymbol,bsymbol);

    if (rf)
	rfilter_free(rf);
    return bsymbol;
}

struct bsymbol *target_lookup_sym_member(struct target *target,
					 struct bsymbol *bsymbol,
					 const char *name,const char *delim) {
    struct bsymbol *bsymbol_new;
    struct lsymbol *lsymbol;

    lsymbol = lsymbol_lookup_sym__int(bsymbol->lsymbol,name,delim);
    if (!lsymbol)
	return NULL;

    bsymbol_new = bsymbol_create(lsymbol,bsymbol->region);
    /* Take a ref to bsymbol_new on the user's behalf, since this is
     * a lookup function.
     */
    RHOLD(bsymbol_new,bsymbol_new);

    return bsymbol_new;
}

struct bsymbol *target_lookup_sym_line(struct target *target,
				       char *filename,int line,
				       SMOFFSET *offset,ADDR *addr) {
    struct addrspace *space;
    struct bsymbol *bsymbol;
    struct lsymbol *lsymbol = NULL;
    struct memregion *region;
    struct debugfile *debugfile;
    GHashTableIter iter;
    gpointer key;
    ADDR taddr;
    SMOFFSET toffset;

    if (list_empty(&target->spaces))
	return NULL;

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    g_hash_table_iter_init(&iter,region->debugfiles);
	    while (g_hash_table_iter_next(&iter,(gpointer)&key,
					  (gpointer)&debugfile)) {
		lsymbol = debugfile_lookup_sym_line__int(debugfile,filename,line,
							 &toffset,&taddr);
		if (lsymbol) 
		    goto out;
	    }
	}
    }
    return NULL;

 out:
    taddr = memregion_relocate(region,taddr,NULL);
    if (errno) {
	verror("could not relocate obj addr 0x%"PRIxADDR"!\n",taddr);
	lsymbol_release(lsymbol);
	return NULL;
    }
    bsymbol = bsymbol_create(lsymbol,region);
    /* Take a ref to bsymbol on the user's behalf, since this is
     * a lookup function.
     */
    RHOLD(bsymbol,bsymbol);
    if (offset)
	*offset = toffset;
    if (addr) 
	*addr = taddr;

    return bsymbol;
}

int target_lookup_line_addr(struct target *target,char *srcfile,ADDR addr) {
    struct addrspace *space;
    struct memregion *region;
    GHashTableIter iter;
    gpointer key;
    struct debugfile *debugfile;
    struct memrange *range;
    int line = -1;

    if (list_empty(&target->spaces))
	return -1;

    vdebug(9,LA_TARGET,LF_SYMBOL,
	   "trying to find line for address 0x%"PRIxADDR"\n",
	   addr);

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if ((range = memregion_find_range_real(region,addr)))
		goto found;
	}
    }

    return -1;

 found:
    g_hash_table_iter_init(&iter,region->debugfiles);
    while (g_hash_table_iter_next(&iter,
				  (gpointer)&key,(gpointer)&debugfile)) {
	line = debugfile_lookup_line_addr(debugfile,srcfile,
					  memrange_unrelocate(range,addr));
	if (line)
	    return line;
    }

    return -1;
}

/*
 * Thin wrappers around [l]symbol_resolve_bounds[_alt].
 */
int target_symbol_resolve_bounds(struct target *target,
				 struct target_location_ctxt *tlctxt,
				 struct symbol *symbol,
				 ADDR *start,ADDR *end,int *is_noncontiguous,
				 ADDR *alt_start,ADDR *alt_end) {
    if (!tlctxt) {
	errno = EINVAL;
	verror("must supply a context (tid,region) for raw symbol resolution!\n");
	return -1;
    }

    return symbol_resolve_bounds(symbol,tlctxt->lctxt,
				 start,end,is_noncontiguous,alt_start,alt_end);
}

int target_lsymbol_resolve_bounds(struct target *target,
				  struct target_location_ctxt *tlctxt,
				  struct lsymbol *lsymbol,ADDR base_addr,
				  ADDR *start,ADDR *end,int *is_noncontiguous,
				  ADDR *alt_start,ADDR *alt_end) {
    if (!tlctxt) {
	errno = EINVAL;
	verror("must supply a context (tid,region) for raw lsymbol resolution!\n");
	return -1;
    }

    return lsymbol_resolve_bounds(lsymbol,base_addr,tlctxt->lctxt,
				  start,end,is_noncontiguous,alt_start,alt_end);
}

int target_bsymbol_resolve_bounds(struct target *target,
				  struct target_location_ctxt *tlctxt,
				  struct bsymbol *bsymbol,ADDR base_addr,
				  ADDR *start,ADDR *end,int *is_noncontiguous,
				  ADDR *alt_start,ADDR *alt_end) {
    if (!tlctxt) {
	errno = EINVAL;
	verror("must supply a context (tid,region) for bsymbol resolution!\n");
	return -1;
    }

    return lsymbol_resolve_bounds(bsymbol->lsymbol,base_addr,tlctxt->lctxt,
				  start,end,is_noncontiguous,alt_start,alt_end);
}

/*
 * This is a thin wrapper around lsymbol_resolve_location that handles
 * the load_flags_t in flags.
 */
loctype_t target_lsymbol_resolve_location(struct target *target,
					  struct target_location_ctxt *tlctxt,
					  struct lsymbol *lsymbol,
					  ADDR base_addr,
					  load_flags_t flags,
					  struct location *o_loc,
					  struct symbol **o_datatype,
					  struct memrange **o_range) {
    loctype_t rc;
    tid_t tid;
    ADDR addr;
    REG reg;
    struct symbol *symbol;
    struct symbol *datatype;
    struct memrange *range = NULL;
    struct location tloc;

    if (!tlctxt) {
	errno = EINVAL;
	verror("must supply a context (tid,region) for raw lsymbol resolution!\n");
	return LOCTYPE_UNKNOWN;
    }

    tid = tlctxt->thread->tid;

    memset(&tloc,0,sizeof(tloc));
    rc = lsymbol_resolve_location(lsymbol,base_addr,tlctxt->lctxt,&tloc);
    if (rc == LOCTYPE_ADDR) {
	/* Grab the range. */
	addr = LOCATION_ADDR(&tloc);
	if (!target_find_memory_real(target,addr,NULL,NULL,&range)) {
	    verror("could not find memory for 0x%"PRIxADDR
		   " for symbol %s: %s!\n",
		   addr,lsymbol_get_name(lsymbol),strerror(errno));
	    errno = ERANGE;
	    goto errout;
	}
    }
    else if (rc <= LOCTYPE_UNKNOWN) {
	verror("failed to resolve location type %s (%d)!\n",
	       LOCTYPE(-rc),rc);
	goto errout;
    }

    symbol = lsymbol_last_symbol(lsymbol);
    datatype = symbol_get_datatype(symbol);
    if (datatype)
	datatype = symbol_type_skip_qualifiers(datatype);

 again:
    if (datatype && SYMBOL_IST_PTR(datatype)
	&& ((flags & LOAD_FLAG_AUTO_DEREF)
	    || (flags & LOAD_FLAG_AUTO_STRING
		&& symbol_type_is_char(symbol_type_skip_ptrs(datatype))))) {

	if (rc == LOCTYPE_REG) {
	    reg = LOCATION_REG(&tloc);
	    /*
	     * Try to load the ptr value from a register; might or might
	     * not be an address; only is if the current symbol was a
	     * pointer; we handle that below.  There's a termination
	     * condition below this loop that if we end after having
	     * resolved the location to a register, we can't calculate
	     * the address for it.
	     */
	    addr = target_read_reg(target,tid,reg);
	    if (errno) {
		verror("could not read reg %"PRIiREG" that ptr symbol %s"
		       " resolved to: %s!\n",
		       reg,symbol_get_name(symbol),strerror(errno));
		goto errout;
	    }

	    /* We might have changed ranges... */
	    if (!target_find_memory_real(target,addr,NULL,NULL,&range)) {
		vwarnopt(8,LA_TARGET,LF_SYMBOL,
			 "could not find memory for 0x%"PRIxADDR
			 " for symbol %s: %s!\n",
			 addr,symbol_get_name(symbol),strerror(errno));
		goto errout;
	    }

	    vdebug(12,LA_TARGET,LF_SYMBOL,
		   "ptr var (in reg) %s = 0x%"PRIxADDR"\n",
		   symbol_get_name(symbol),addr);

	    /* We have to skip one pointer type */
	    datatype = symbol_get_datatype(datatype);

	    /*
	     * Set loctype to be an addr, since we autoloaded the pointer!
	     */
	    rc = LOCTYPE_ADDR;

	    /* Do we need to keep trying to load through the pointer? */
	    goto again;
	}
	else if (rc == LOCTYPE_IMPLICIT_WORD) {
	    verror("unexpected implicit value instead of pointer!\n");
	    errno = EINVAL;
	    goto errout;
	}
	else if (rc == LOCTYPE_ADDR) {
	    addr = target_autoload_pointers(target,datatype,addr,
					    flags,&datatype,&range);
	    if (errno) {
		verror("could not load pointer for symbol %s\n",
		       symbol_get_name(symbol));
		goto errout;
	    }

	    vdebug(12,LA_TARGET,LF_SYMBOL,
		   "autoloaded pointer(s) for var %s = 0x%"PRIxADDR"\n",
		   symbol_get_name(symbol),addr);

	    /* We might have changed ranges... */
	    if (!target_find_memory_real(target,addr,NULL,NULL,&range)) {
		vwarnopt(8,LA_TARGET,LF_SYMBOL,
			 "could not find memory for 0x%"PRIxADDR
			 " for symbol %s: %s!\n",
			 addr,symbol_get_name(symbol),strerror(errno));
		goto errout;
	    }
	}
	else {
	    verror("unexpected location type %s for pointer!\n",
		   LOCTYPE(rc));
	    errno = EINVAL;
	    goto errout;
	}
    }

    /* Return! */
    if (rc == LOCTYPE_ADDR) {
	if (o_loc)
	    location_set_addr(o_loc,addr);
	if (o_range) 
	    *o_range = range;
	if (o_datatype)
	    *o_datatype = datatype;
    }
    else if (rc == LOCTYPE_REG) {
	if (o_loc)
	    location_set_reg(o_loc,LOCATION_REG(&tloc));
	if (o_datatype)
	    *o_datatype = datatype;
    }
    else if (rc == LOCTYPE_IMPLICIT_WORD) {
	if (o_loc)
	    location_set_implicit_word(o_loc,LOCATION_WORD(&tloc));
	if (o_datatype)
	    *o_datatype = datatype;
    }

    location_internal_free(&tloc);
    return rc;

 errout:
    location_internal_free(&tloc);
    return -rc;
}

int target_bsymbol_resolve_base(struct target *target,
				struct target_location_ctxt *tlctxt,
				struct bsymbol *bsymbol,ADDR *o_addr,
				struct memrange **o_range) {
    loctype_t rc;
    struct location tloc;
    int retval;

    if (!tlctxt) {
	errno = EINVAL;
	verror("must supply a context (tid,region) for bsymbol resolution!\n");
	return LOCTYPE_UNKNOWN;
    }

    memset(&tloc,0,sizeof(tloc));
    rc = target_lsymbol_resolve_location(target,tlctxt,bsymbol->lsymbol,0,
					 LOAD_FLAG_NONE,&tloc,NULL,o_range);
    if (rc != LOCTYPE_ADDR) {
	verror("could not resolve base for symbol %s: %s (%d)\n",
	       lsymbol_get_name(bsymbol->lsymbol),strerror(errno),rc);
	location_internal_free(&tloc);
	retval = -1;
	goto errout;
    }

    retval = 0;
    if (o_addr)
	*o_addr = LOCATION_ADDR(&tloc);

 errout:
    location_internal_free(&tloc);
    return retval;
}

struct value *target_load_type(struct target *target,struct symbol *type,
			       ADDR addr,load_flags_t flags) {
    struct symbol *datatype = type;
    struct value *value;
    struct memregion *region;
    struct memrange *range;
    ADDR ptraddr;
    struct location ptrloc;
    char *offset_buf;

    datatype = symbol_type_skip_qualifiers(type);

    if (!SYMBOL_IS_TYPE(datatype)) {
	verror("symbol %s is not a full type (is %s)!\n",
	       symbol_get_name(type),SYMBOL_TYPE(type->type));
	errno = EINVAL;
	return NULL;
    }

    if (datatype != type)
	vdebug(9,LA_TARGET,LF_TSYMBOL,"skipped from %s to %s for type %s\n",
	       DATATYPE(type->datatype_code),
	       DATATYPE(datatype->datatype_code),symbol_get_name(type));
    else 
	vdebug(9,LA_TARGET,LF_TSYMBOL,"no skip; type for type %s is %s\n",
	       symbol_get_name(type),DATATYPE(datatype->datatype_code));

    /* Get range/region info for the addr. */
    if (!target_find_memory_real(target,addr,NULL,NULL,&range)) {
	verror("could not find range for addr 0x%"PRIxADDR"!\n",addr);
	errno = EFAULT;
	return NULL;
    }

    /* If they want pointers automatically dereferenced, do it! */
    errno = 0;
    ptraddr = target_autoload_pointers(target,datatype,addr,flags,
				       &datatype,&range);
    if (errno) {
	verror("failed to autoload pointers for type %s at addr 0x%"PRIxADDR"\n",
	       symbol_get_name(type),addr);
	return NULL;
    }
    region = range->region;

    if (!ptraddr) {
	verror("last pointer was NULL!\n");
	errno = EFAULT;
	return NULL;
    }

    /*
     * Now allocate the value struct for various cases and return.
     */

    /* If we're autoloading pointers and we want to load char * pointers
     * as strings, do it!
     */
    if (ptraddr != addr
	&& flags & LOAD_FLAG_AUTO_STRING
	&& symbol_type_is_char(datatype)) {
	/* XXX: should we use datatype, or the last pointer to datatype? */
	value = value_create_noalloc(NULL,range,NULL,datatype);
	if (!value) {
	    verror("could not create value: %s\n",strerror(errno));
	    goto errout;
	}

	if (!(value->buf = (char *)__target_load_addr_real(target,range,
							   ptraddr,flags,
							   NULL,0))) {
	    verror("failed to autoload char * for type %s at addr 0x%"PRIxADDR"\n",
		   symbol_get_name(type),addr);
	    goto errout;
	}
	value_set_strlen(value,strlen(value->buf) + 1);
	value_set_addr(value,ptraddr);

	vdebug(9,LA_TARGET,LF_TSYMBOL,
	       "autoloaded char * with len %d\n",value->bufsiz);

	/* success! */
	goto out;
    }
#if 0
    else if (0 && (flags & LOAD_FLAG_MUST_MMAP || !(flags & LOAD_FLAG_NO_MMAP))) {
	ptrloc.loctype = LOCTYPE_REALADDR;
	ptrloc.l.addr = ptraddr != addr ? ptraddr : addr;

	mmap = location_mmap(target,region,&ptrloc,
			     flags,&offset_buf,NULL,&range);
	if (rc && flags & LOAD_FLAG_MUST_MMAP) {
	    goto errout;
	}

	value = value_create_noalloc(NULL,range,NULL,datatype);
	if (!value) {
	    verror("could not create value: %s\n",strerror(errno));
	    goto errout;
	}

	if (!value->mmap) {
	    // fall back to regular load
	    value->bufsiz = symbol_type_full_bytesize(datatype);
	    value->buf = malloc(value->bufsiz);
	    if (!value->buf) {
		value->bufsiz = 0;
		goto errout;
	    }

	    if (!__target_load_addr_real(target,range,ptrloc.l.addr,flags,
					 (unsigned char *)value->buf,
					 value->bufsiz)) 
		goto errout;

	    value_set_addr(value,ptrloc.l.addr);
	}
	else {
	    value_set_mmap(value,ptrloc.l.addr,mmap,offset_buf);
	}

	/* success! */
	goto out;
    }
#endif
    else {
	value = value_create_type(NULL,range,datatype);
	if (!value) {
	    verror("could not create value for type (ptr is %p) %s\n",
		   datatype,datatype ? datatype->name : NULL);
	    goto errout;
	}

	if (!__target_load_addr_real(target,range,ptraddr,flags,
				     (unsigned char *)value->buf,
				     value->bufsiz)) {
	    verror("could not load addr 0x%"PRIxADDR"!\n",ptraddr);
	    goto errout;
	}

	value_set_addr(value,ptraddr);
    }

 out:
    return value;

 errout:
    if (value)
	value_free(value);

    return NULL;

}

struct value *target_load_type_regval(struct target *target,struct symbol *type,
				      tid_t tid,REG reg,REGVAL regval,
				      load_flags_t flags) {
    struct symbol *datatype;
    struct value *value;
    struct memrange *range;
    ADDR ptraddr;
    size_t sz;
    struct target_thread *tthread;

    if (flags & LOAD_FLAG_MUST_MMAP) {
	verror("cannot mmap reg type!\n");
	errno = EINVAL;
	return NULL;
    }

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	errno = EINVAL;
	verror("could not lookup thread %"PRIiTID"; forgot to load?\n",tid);
	return NULL;
    }

    datatype = symbol_type_skip_qualifiers(type);

    if (!SYMBOL_IS_TYPE(datatype)) {
	verror("symbol %s is not a full type (is %s)!\n",
	       symbol_get_name(type),SYMBOL_TYPE(type->type));
	errno = EINVAL;
	return NULL;
    }

    if (datatype != type)
	vdebug(9,LA_TARGET,LF_TSYMBOL,"skipped from %s to %s for type %s\n",
	       DATATYPE(type->datatype_code),
	       DATATYPE(datatype->datatype_code),symbol_get_name(type));
    else 
	vdebug(9,LA_TARGET,LF_TSYMBOL,"no skip; type for type %s is %s\n",
	       symbol_get_name(type),DATATYPE(datatype->datatype_code));

    /*
     * If the user wants pointers deref'd, get range/region info for the
     * regval, and deref.
     */
    if (((flags & LOAD_FLAG_AUTO_DEREF) && SYMBOL_IST_PTR(datatype))
	|| ((flags & LOAD_FLAG_AUTO_STRING) 
	    && SYMBOL_IST_PTR(datatype) 
	    && symbol_type_is_char(symbol_type_skip_ptrs(datatype)))) {
	if (!target_find_memory_real(target,regval,NULL,NULL,&range)) {
	    verror("could not find range for regval addr 0x%"PRIxADDR"\n!",
		   regval);
	    errno = EFAULT;
	    return NULL;
	}
	/* If they want pointers automatically dereferenced, do it! */
	errno = 0;
	ptraddr = target_autoload_pointers(target,datatype,regval,flags,
					   &datatype,&range);
	if (errno) {
	    verror("failed to autoload pointers for type %s"
		   " at regval addr 0x%"PRIxADDR"\n",
		   symbol_get_name(type),regval);
	    return NULL;
	}

	if (!ptraddr) {
	    verror("last pointer was NULL!\n");
	    errno = EFAULT;
	    return NULL;
	}
    }
    else {
	range = NULL;
	ptraddr = 0;
    }

    /*
     * Now allocate the value struct for various cases and return.
     */

    /*
     * If we're autoloading pointers and we want to load char * pointers
     * as strings, do it!
     */
    if (ptraddr
	&& (flags & LOAD_FLAG_AUTO_STRING)
	&& symbol_type_is_char(datatype)) {
	/* XXX: should we use datatype, or the last pointer to datatype? */
	value = value_create_noalloc(tthread,range,NULL,datatype);
	if (!value) {
	    verror("could not create value: %s\n",strerror(errno));
	    goto errout;
	}

	if (!(value->buf = (char *) \
	          __target_load_addr_real(target,range,ptraddr,flags,NULL,0))) {
	    verror("failed to autoload char * for type %s"
		   " at regval ptr addr 0x%"PRIxADDR"\n",
		   symbol_get_name(type),ptraddr);
	    goto errout;
	}
	value_set_strlen(value,strlen(value->buf) + 1);
	value_set_addr(value,ptraddr);

	vdebug(9,LA_TARGET,LF_TSYMBOL,
	       "autoloaded char * with len %d\n",value->bufsiz);

	/* success! */
	goto out;
    }
    else if (ptraddr) {
	value = value_create_type(tthread,range,datatype);
	if (!value) {
	    verror("could not create value for type (ptr is %p) %s\n",
		   datatype,datatype ? datatype->name : NULL);
	    goto errout;
	}

	if (!__target_load_addr_real(target,range,ptraddr,flags,
				     (unsigned char *)value->buf,
				     value->bufsiz)) {
	    verror("could not load addr 0x%"PRIxADDR"!\n",ptraddr);
	    goto errout;
	}

	value_set_addr(value,ptraddr);
    }
    else {
	value = value_create_type(tthread,NULL,datatype);
	if (!value) {
	    verror("could not create value for type (ptr is %p) %s\n",
		   datatype,datatype ? datatype->name : NULL);
	    goto errout;
	}

	if (value->bufsiz > (int)sizeof(REGVAL))
	    sz = sizeof(REGVAL);
	else
	    sz = value->bufsiz;
	memcpy(value->buf,&regval,sz);

	value_set_reg(value,reg);
    }

 out:
    return value;

 errout:
    if (value)
	value_free(value);

    return NULL;
}

struct value *target_load_type_reg(struct target *target,struct symbol *type,
				   tid_t tid,REG reg,load_flags_t flags) {
    REGVAL regval;

    errno = 0;
    regval = target_read_reg(target,tid,reg);

    return target_load_type_regval(target,type,tid,reg,regval,flags);
}

struct value *target_load_symbol_member(struct target *target,
					struct target_location_ctxt *tlctxt,
					struct bsymbol *bsymbol,
					const char *member,const char *delim,
					load_flags_t flags) {
    struct bsymbol *bmember;
    struct value *retval = NULL;

    bmember = target_lookup_sym_member(target,bsymbol,member,delim);
    if (!bmember) {
	verror("could not find member '%s' in symbol %s!\n",
	       member,bsymbol_get_name(bsymbol));
	return NULL;
    }

    retval = target_load_symbol(target,tlctxt,bmember,flags);

    bsymbol_release(bmember);

    return retval;
}

struct value *target_load_value_member(struct target *target,
				       struct target_location_ctxt *tlctxt,
				       struct value *old_value,
				       const char *member,const char *delim,
				       load_flags_t flags) {
    struct value *value = NULL;
    struct symbol *symbol;
    struct symbol *tdatatype;
    struct lsymbol *ls = NULL;
    struct memrange *range;
    struct symbol *datatype;
    char *rbuf = NULL;
    ADDR oldaddr,addr;
    struct target_thread *tthread;
    tid_t tid;
    int rc;
    REG reg;
    REGVAL regval;
    int newlen;
    ADDR word;
    struct location tloc;
    int created = 0;

    tthread = old_value->thread;
    tid = tthread->tid;

    tdatatype = symbol_type_skip_qualifiers(old_value->type);
	
    vdebug(9,LA_TARGET,LF_SYMBOL,
	   "looking up '%s' in type ",member);
    LOGDUMPSYMBOL(9,LA_TARGET,LF_SYMBOL,old_value->type);
    vdebugc(9,LA_TARGET,LF_SYMBOL,
	    " (skipping to type ");
    LOGDUMPSYMBOL_NL(9,LA_TARGET,LF_SYMBOL,tdatatype);

    memset(&tloc,0,sizeof(tloc));

    /*
     * We have to handle two levels of pointers, potentially.  Suppose
     * that the @value's type is a pointer.  Then we have to load that
     * pointer (and any others), then find the member offset inside the
     * pointed-to struct/union, and then... if THAT member is itself a
     * pointer, we read THAT pointer (and any others) until we don't
     * have any more pointers.
     *
     * Of course, that behavior is only enabled when
     * LOAD_FLAG_AUTO_DEREF is set.
     */

    /* If the value's datatype is a pointer, we have to autoload pointers;
     * then try to find a struct/union type that is pointed to!
     */
    if (SYMBOL_IST_PTR(tdatatype)) {
	tdatatype = symbol_type_skip_ptrs(tdatatype);
	oldaddr = v_addr(old_value);

	vdebug(9,LA_TARGET,LF_SYMBOL,
	       "datatype is ptr; skipping to real type ");
	LOGDUMPSYMBOL(9,LA_TARGET,LF_SYMBOL,tdatatype);
	vdebugc(9,LA_TARGET,LF_SYMBOL,
		" starting at addr 0x%"PRIxADDR"\n",oldaddr);
    }
    else {
	oldaddr = old_value->res.addr;

	vdebug(9,LA_TARGET,LF_SYMBOL,
	       "datatype is not ptr; starting at addr 0x%"PRIxADDR"\n",
	       oldaddr);
    }

    if (!SYMBOL_IST_STUNC(tdatatype)) {
	vwarn("symbol %s: not a full struct/union/class type (is %s)!\n",
	      symbol_get_name(tdatatype),SYMBOL_TYPE(tdatatype->type));
	errno = EINVAL;
	goto errout;
    }

    /*
     * Resolve the member symbol within tdatatype, the struct/union real
     * datatype.  Take a self-ref to it, and release it at the end
     * whether we succeed or fail!  If we succeed, value_create takes a
     * ref to it too, and we don't need ours.
     */
    ls = symbol_lookup_sym(tdatatype,member,delim);
    if (!ls)
	goto errout;
    symbol = lsymbol_last_symbol(ls);

    vdebug(9,LA_TARGET,LF_SYMBOL,"found member symbol ");
    LOGDUMPSYMBOL_NL(9,LA_TARGET,LF_SYMBOL,symbol);

    /*
     * If this symbol has a constant value, load that!
     */
    if (SYMBOLX_VAR(symbol) && SYMBOLX_VAR(symbol)->constval) {
	value = value_create_type(tthread,NULL,symbol_get_datatype(symbol));
	memcpy(value->buf,SYMBOLX_VAR(symbol)->constval,value->bufsiz);
	
	vdebug(9,LA_TARGET,LF_SYMBOL,
	       "symbol %s: loaded const value len %d\n",
	       symbol_get_name(symbol),value->bufsiz);

	return value;
    }

    /*
     * Compute either an address or register location, and load!
     */
    if (!tlctxt) {
	tlctxt = target_location_ctxt_create(target,old_value->thread->tid,
					     old_value->range->region);
	created = 1;
    }
    range = NULL;
    reg = -1;
    addr = 0;
    datatype = NULL;
    rc = target_lsymbol_resolve_location(target,tlctxt,ls,oldaddr,
					 flags,&tloc,&datatype,&range);
    if (rc == LOCTYPE_ADDR) {
	addr = LOCATION_ADDR(&tloc);

	tdatatype = symbol_type_skip_qualifiers(datatype);
	newlen = symbol_type_full_bytesize(datatype);

	/*
	 * Check for AUTO_STRING first, before checking if the addr +
	 * newlen is already contained in the original value -- because
	 * an AUTO_STRING'd value will *not* be contained in the
	 * original value anyway.  If we checked that first, we miss the
	 * AUTO_STRING chance.
	 */
	if (flags & LOAD_FLAG_AUTO_STRING
	    && SYMBOL_IST_PTR(symbol_get_datatype(symbol)) 
	    && symbol_type_is_char(tdatatype)) {
	    value = value_create_noalloc(tthread,range,ls,tdatatype);
	    if (!value) {
		verror("symbol %s: could not create value: %s\n",
		       lsymbol_get_name(ls),strerror(errno));
		goto errout;
	    }

	    if (!(value->buf = (char *)__target_load_addr_real(target,range,
							       addr,flags,
							       NULL,0))) {
		vwarnopt(12,LA_TARGET,LF_SYMBOL,
			 "symbol %s: failed to autostring char pointer\n",
			 lsymbol_get_name(ls));
		value_free(value);
		value = NULL;
		goto errout;
	    }
	    value_set_strlen(value,strlen(value->buf) + 1);
	    value_set_addr(value,addr);

	    vdebug(9,LA_TARGET,LF_SYMBOL,
		   "symbol %s: autoloaded char * value with len %d\n",
		   lsymbol_get_name(ls),value->bufsiz);
	}
	/*
	 * If lsymbol_resolve_location returns an address
	 * entirely contained inside of value->buf, we can just clone
	 * the value from within the old value.  Otherwise, we have to
	 * load it from the final address.
	 */
	/*
	 * XXX: this stinks; if you change value_create_type, change
	 * this size calculation too :(.  We do it this way so we don't
	 * create a value needlessly if the member value isn't fully
	 * contained in the parent.
	 */
	else if (addr >= oldaddr
		 && ((addr + newlen) - oldaddr) < (unsigned)old_value->bufsiz) {
	    if (flags & LOAD_FLAG_VALUE_FORCE_COPY) {
		value = value_create(tthread,range,ls,datatype);
		if (!value) {
		    verror("symbol %s: could not create value: %s\n",
			   lsymbol_get_name(ls),strerror(errno));
		    goto errout;
		}
		memcpy(value->buf,old_value->buf + (addr - oldaddr),
		       newlen);
		value_set_addr(value,addr);

		vdebug(9,LA_TARGET,LF_SYMBOL,
		       "symbol %s: forced member value copy with len %d\n",
		       lsymbol_get_name(ls),value->bufsiz);
	    }
	    else {
		value = value_create_noalloc(tthread,range,ls,datatype);
		if (!value) {
		    verror("symbol %s: could not create value: %s\n",
			   lsymbol_get_name(ls),strerror(errno));
		    goto errout;
		}
		value_set_child(value,old_value,addr);

		vdebug(9,LA_TARGET,LF_SYMBOL,
		       "symbol %s: loaded member value as child with len %d\n",
		       lsymbol_get_name(ls),value->bufsiz);
	    }

	    goto out;
	}
	else {
	    value = value_create(tthread,range,ls,tdatatype);
	    if (!value) {
		verror("symbol %s: could not create value: %s\n",
		       lsymbol_get_name(ls),strerror(errno));
		goto errout;
	    }

	    if (!__target_load_addr_real(target,range,addr,flags,
					 (unsigned char *)value->buf,
					 value->bufsiz)) {
		vwarnopt(12,LA_TARGET,LF_SYMBOL,
			 "symbol %s: failed to load value at 0x%"PRIxADDR"\n",
			 lsymbol_get_name(ls),addr);
		value_free(value);
		value = NULL;
		goto errout;
	    }
	    else {
		value_set_addr(value,addr);

		vdebug(9,LA_TARGET,LF_SYMBOL,
		       "symbol %s: loaded value with len %d\n",
		       lsymbol_get_name(ls),value->bufsiz);
	    }
	}
    }
    else if (rc == LOCTYPE_REG) {
	if (flags & LOAD_FLAG_MUST_MMAP) {
	    verror("symbol %s: cannot mmap register value!\n",
		   lsymbol_get_name(ls));
	    errno = EINVAL;
	    goto errout;
	}

	reg = LOCATION_REG(&tloc);

        regval = target_read_reg(target,tid,reg);
        if (errno) {
	    verror("symbol %s: could not read reg %d value in tid %"PRIiTID"\n",
		   lsymbol_get_name(ls),reg,tid);
            goto errout;
	}

	datatype = symbol_get_datatype(symbol);
	rbuf = malloc(symbol_get_bytesize(datatype));

        if (target->arch->wordsize == 4 && __WORDSIZE == 64) {
            /* If the target is 32-bit on 64-bit host, we have to grab
             * the lower 32 bits of the regval.
             */
            memcpy(rbuf,((int32_t *)&regval),symbol_get_bytesize(datatype));
        }
	else if (__WORDSIZE == 32)
	    memcpy(rbuf,&regval,(symbol_get_bytesize(datatype) < 4) \
		   ? symbol_get_bytesize(datatype) : 4);
        else
            memcpy(rbuf,&regval,symbol_get_bytesize(datatype));

	/* Just create the value based on the register value. */
	value = value_create_noalloc(tthread,NULL,ls,datatype);
	if (!value) {
	    verror("symbol %s: could not create value: %s\n",
		   lsymbol_get_name(ls),strerror(errno));
	    goto errout;
	}
	value->buf = rbuf;
	value->bufsiz = symbol_get_bytesize(datatype);

	value_set_reg(value,reg);
    }
    else if (rc == LOCTYPE_IMPLICIT_WORD) {
	if (flags & LOAD_FLAG_MUST_MMAP) {
	    verror("symbol %s: cannot mmap implicit value!\n",
		   lsymbol_get_name(ls));
	    errno = EINVAL;
	    goto errout;
	}

	word = LOCATION_WORD(&tloc);
	datatype = symbol_get_datatype(symbol);
	rbuf = malloc(symbol_get_bytesize(datatype));

        if (target->arch->wordsize == 4 && __WORDSIZE == 64) {
            /* If the target is 32-bit on 64-bit host, we have to grab
             * the lower 32 bits of the regval.
             */
            memcpy(rbuf,((int32_t *)&word),symbol_get_bytesize(datatype));
        }
	else if (__WORDSIZE == 32)
	    memcpy(rbuf,&word,(symbol_get_bytesize(datatype) < 4) \
		   ? symbol_get_bytesize(datatype) : 4);
        else
            memcpy(rbuf,&word,symbol_get_bytesize(datatype));

	/* Just create the value based on the register value. */
	value = value_create_noalloc(tthread,NULL,ls,datatype);
	if (!value) {
	    verror("symbol %s: could not create value: %s\n",
		   lsymbol_get_name(ls),strerror(errno));
	    goto errout;
	}
	value->buf = rbuf;
	value->bufsiz = symbol_get_bytesize(datatype);

	value_set_const(value);
    }
    else if (rc <= 0) {
	verror("symbol %s: failed to compute location (%d %s)\n",
	       lsymbol_get_name(ls),rc,LOCTYPE(-rc));
	goto errout;
    }
    else {
	verror("symbol %s: computed location not register nor address (%d)"
	       " -- BUG!\n",lsymbol_get_name(ls),rc);
	errno = EINVAL;
	goto errout;
    }

 out:
    if (created)
	target_location_ctxt_free(tlctxt);
    lsymbol_release(ls);
    return value;

 errout:
    if (created)
	target_location_ctxt_free(tlctxt);
    if (ls)
	lsymbol_release(ls);
    if (rbuf)
	free(rbuf);
    if (value)
	value_free(value);
    return NULL;
}

struct value *target_load_symbol(struct target *target,
				 struct target_location_ctxt *tlctxt,
				 struct bsymbol *bsymbol,load_flags_t flags) {
    ADDR addr;
    REG reg;
    struct lsymbol *lsymbol;
    struct symbol *symbol;
    struct symbol *datatype;
    struct memrange *range;
    struct value *value = NULL;
    REGVAL regval;
    char *rbuf;
    struct symbol *tdatatype;
    struct target_thread *tthread;
    loctype_t rc;
    ADDR word;
    struct location tloc;
    tid_t tid;

    if (!tlctxt) {
	errno = EINVAL;
	verror("must supply a context (tid,region) for bsymbol load!\n");
	return LOCTYPE_UNKNOWN;
    }
    tthread = tlctxt->thread;
    tid = tlctxt->thread->tid;

    lsymbol = bsymbol->lsymbol;
    symbol = lsymbol_last_symbol(lsymbol);

    if (!SYMBOL_IS_VAR(symbol)) {
	verror("symbol %s is not a variable (is %s)!\n",
	       lsymbol_get_name(lsymbol),SYMBOL_TYPE(symbol->type));
	errno = EINVAL;
	return NULL;
    }

    /*
     * If the target backend can read a symbol directly, do it.
     */
    if (target->ops->read_symbol) 
	return target->ops->read_symbol(target,tlctxt,bsymbol,flags);

    /*
     * If this symbol has a constant value, load that!
     */
    if (SYMBOLX_VAR(symbol) && SYMBOLX_VAR(symbol)->constval) {
	value = value_create_type(tthread,NULL,symbol_get_datatype(symbol));
	memcpy(value->buf,SYMBOLX_VAR(symbol)->constval,value->bufsiz);
	
	vdebug(9,LA_TARGET,LF_SYMBOL,
	       "symbol %s: loaded const value len %d\n",
	       lsymbol_get_name(lsymbol),value->bufsiz);

	return value;
    }

    /*
     * Compute the symbol's location (reg or addr) and load that!
     */
    range = NULL;
    reg = -1;
    addr = 0;
    datatype = NULL;
    memset(&tloc,0,sizeof(tloc));
    rc = target_lsymbol_resolve_location(target,tlctxt,lsymbol,0,
					 flags,&tloc,&datatype,&range);
    if (rc <= LOCTYPE_UNKNOWN) {
	verror("symbol %s: failed to compute location\n",
	       lsymbol_get_name(lsymbol));
	goto errout;
    }
    else if (rc == LOCTYPE_ADDR) {
	addr = LOCATION_ADDR(&tloc);
	tdatatype = symbol_type_skip_qualifiers(datatype);
	if (flags & LOAD_FLAG_AUTO_STRING
	    && SYMBOL_IST_PTR(symbol_get_datatype(symbol)) 
	    && symbol_type_is_char(tdatatype)) {
	    value = value_create_noalloc(tthread,range,lsymbol,tdatatype);
	    if (!value) {
		verror("symbol %s: could not create value: %s\n",
		       lsymbol_get_name(lsymbol),strerror(errno));
		goto errout;
	    }

	    if (!(value->buf = (char *)__target_load_addr_real(target,range,
							       addr,flags,
							       NULL,0))) {
		vwarnopt(12,LA_TARGET,LF_SYMBOL,
			 "symbol %s: failed to autostring char pointer\n",
			 lsymbol_get_name(lsymbol));
		value_free(value);
		value = NULL;
		goto errout;
	    }
	    value_set_strlen(value,strlen(value->buf) + 1);
	    value_set_addr(value,addr);

	    vdebug(9,LA_TARGET,LF_SYMBOL,
		   "symbol %s: autoloaded char * value with len %d\n",
		   lsymbol_get_name(lsymbol),value->bufsiz);
	}
	else {
	    value = value_create(tthread,range,bsymbol->lsymbol,tdatatype);
	    if (!value) {
		verror("symbol %s: could not create value: %s\n",
		       lsymbol_get_name(lsymbol),strerror(errno));
		goto errout;
	    }

	    if (!__target_load_addr_real(target,range,addr,flags,
					 (unsigned char *)value->buf,
					 value->bufsiz)) {
		vwarnopt(12,LA_TARGET,LF_SYMBOL,
			 "symbol %s: failed to load value at 0x%"PRIxADDR"\n",
			 lsymbol_get_name(lsymbol),addr);
		value_free(value);
		value = NULL;
		goto out;
	    }
	    else {
		value_set_addr(value,addr);

		vdebug(9,LA_TARGET,LF_SYMBOL,
		       "symbol %s: loaded value with len %d\n",
		       lsymbol_get_name(lsymbol),value->bufsiz);
	    }
	}
    }
    else if (rc == LOCTYPE_REG) {
	if (flags & LOAD_FLAG_MUST_MMAP) {
	    verror("symbol %s: cannot mmap register value!\n",
		   lsymbol_get_name(lsymbol));
	    errno = EINVAL;
	    goto errout;
	}

	reg = LOCATION_REG(&tloc);

        if (target_location_ctxt_read_reg(tlctxt,reg,&regval)) {
	    verror("symbol %s: could not read reg %d value in tid %"PRIiTID"\n",
		   lsymbol_get_name(lsymbol),reg,tid);
            goto errout;
	}

	datatype = symbol_type_skip_qualifiers(symbol_get_datatype(symbol));
	rbuf = malloc(symbol_get_bytesize(datatype));

        if (target->arch->wordsize == 4 && __WORDSIZE == 64) {
            /* If the target is 32-bit on 64-bit host, we have to grab
             * the lower 32 bits of the regval.
             */
            memcpy(rbuf,((int32_t *)&regval),symbol_get_bytesize(datatype));
        }
	else if (__WORDSIZE == 32)
	    memcpy(rbuf,&regval,(symbol_get_bytesize(datatype) < 4) \
		                 ? symbol_get_bytesize(datatype) : 4);
        else
            memcpy(rbuf,&regval,symbol_get_bytesize(datatype));

	/* Just create the value based on the register value. */
	value = value_create_noalloc(tthread,NULL,bsymbol->lsymbol,datatype);
	if (!value) {
	    verror("symbol %s: could not create value: %s\n",
		   lsymbol_get_name(lsymbol),strerror(errno));
	    goto errout;
	}
	value->buf = rbuf;
	value->bufsiz = symbol_get_bytesize(datatype);

	value_set_reg(value,reg);
    }
    else if (rc == LOCTYPE_IMPLICIT_WORD) {
	if (flags & LOAD_FLAG_MUST_MMAP) {
	    verror("symbol %s: cannot mmap implicit value!\n",
		   lsymbol_get_name(lsymbol));
	    errno = EINVAL;
	    goto errout;
	}

	word = LOCATION_WORD(&tloc);

	datatype = symbol_type_skip_qualifiers(symbol_get_datatype(symbol));
	rbuf = malloc(symbol_get_bytesize(datatype));

        if (target->arch->wordsize == 4 && __WORDSIZE == 64) {
            /* If the target is 32-bit on 64-bit host, we have to grab
             * the lower 32 bits of the regval.
             */
            memcpy(rbuf,((int32_t *)&word),symbol_get_bytesize(datatype));
        }
	else if (__WORDSIZE == 32)
	    memcpy(rbuf,&word,(symbol_get_bytesize(datatype) < 4) \
		                 ? symbol_get_bytesize(datatype) : 4);
        else
            memcpy(rbuf,&word,symbol_get_bytesize(datatype));

	/* Just create the value based on the register value. */
	value = value_create_noalloc(tthread,NULL,bsymbol->lsymbol,datatype);
	if (!value) {
	    verror("symbol %s: could not create value: %s\n",
		   lsymbol_get_name(lsymbol),strerror(errno));
	    goto errout;
	}
	value->buf = rbuf;
	value->bufsiz = symbol_get_bytesize(datatype);

	value_set_const(value);
    }
    else {
	verror("symbol %s: computed location not register nor address (%d)"
	       " -- BUG!\n",
	       lsymbol_get_name(lsymbol),rc);
	errno = EINVAL;
	goto errout;
    }

 out:
    location_internal_free(&tloc);
    return value;

 errout:
    location_internal_free(&tloc);
    if (value)
	value_free(value);
    return NULL;
}

OFFSET target_offsetof_symbol(struct target *target,struct bsymbol *bsymbol,
			      char *member,const char *delim) {
    return symbol_offsetof(bsymbol->lsymbol->symbol,member,delim);
}

ADDR target_addressof_symbol(struct target *target,
			     struct target_location_ctxt *tlctxt,
			     struct bsymbol *bsymbol,load_flags_t flags,
			     struct memrange **o_range) {
    ADDR addr;
    struct lsymbol *lsymbol;
    loctype_t rc;
    struct location tloc;

    lsymbol = bsymbol->lsymbol;

    /*
     * Compute the symbol's location (reg or addr) and load that!
     */
    addr = 0;
    memset(&tloc,0,sizeof(tloc));
    rc = target_lsymbol_resolve_location(target,tlctxt,lsymbol,0,
					 flags,&tloc,NULL,o_range);
    if (rc <= LOCTYPE_UNKNOWN) {
	verror("symbol %s: failed to compute location: %s (%d)\n",
	       lsymbol_get_name(lsymbol),strerror(errno),rc);
	goto errout;
    }
    else if (rc == LOCTYPE_ADDR) {
	addr = LOCATION_ADDR(&tloc);
	location_internal_free(&tloc);
	return addr;
    }
    /*
     * XXX: technically, the register could still be in some address if
     * it was in a previous frame... we should handle that someday.
     */
    else if (rc == LOCTYPE_REG) {
	vwarnopt(5,LA_TARGET,LF_SYMBOL,
		 "symbol %s: computed location is register %"PRIiREG"\n",
		 lsymbol_get_name(lsymbol),LOCATION_REG(&tloc));
	goto errout;
    }
    else if (rc == LOCTYPE_IMPLICIT_WORD) {
	vwarnopt(5,LA_TARGET,LF_SYMBOL,
		 "symbol %s: computed location is implicit value 0x%"PRIxADDR"\n",
		 lsymbol_get_name(lsymbol),LOCATION_WORD(&tloc));
	goto errout;
    }
    else {
	verror("symbol %s: computed location not register nor address (%d)"
	       " -- BUG!\n",
	       lsymbol_get_name(lsymbol),rc);
	goto errout;
    }

 errout:
    location_internal_free(&tloc);
    if (!errno)
	errno = EINVAL;
    return 0;
}

int target_store_value(struct target *target,struct value *value) {
    /*
     * If the target backend can read a symbol directly, do it.
     */
    if (target->ops->write_symbol) 
	return target->ops->write_symbol(target,value);

    /* mmap'd values were stored whenever they were value_update_*'d */
    if (value->ismmap)
	return 0;
    else if (value->isreg) {
	return target_write_reg(target,value->thread->tid,value->res.reg,
				*(REGVAL *)value->buf);
    }
    else if (target_write_addr(target,value->res.addr,
			       (unsigned long)value->bufsiz,
			       (unsigned char *)value->buf)
	     != (unsigned long)value->bufsiz) {
	return -1;
    }

    return 0;
}

int target_find_memory_real(struct target *target,ADDR addr,
			    struct addrspace **space_saveptr,
			    struct memregion **region_saveptr,
			    struct memrange **range_saveptr) {
    struct addrspace *space;

    if (list_empty(&target->spaces))
	return 0;

    list_for_each_entry(space,&target->spaces,space) {
	if (addrspace_find_range_real(space,addr,
				      region_saveptr,range_saveptr)) {
	    if (space_saveptr) 
		*space_saveptr = space;
	    goto out;
	}
    }
    return 0;

 out:
    return 1;
}

int target_contains_real(struct target *target,ADDR addr) {
    struct addrspace *space;
    struct memregion *region;

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if (memregion_contains_real(region,addr))
		return 1;
	}
    }

    return 0;
}

ADDR target_load_pointers(struct target *target,ADDR addr,int count,
			  struct memrange **range_saveptr) {
    ADDR paddr = addr;
    struct memrange *range = NULL;
    int i;

    for (i = 0; i < count; ++i ) {
	if (paddr == 0) {
	    verror("failed to follow NULL pointer #%d\n",i);
	    errno = EFAULT;
	    goto errout;
	}

	vdebug(9,LA_TARGET,LF_SYMBOL,
	       "loading ptr #%d at 0x%"PRIxADDR"\n",i,paddr);

	/*
	 * The pointer may be in another region!  We *have* to
	 * switch regions -- and thus the memrange for the value we
	 * return may not be in @addr's region/range!
	 */
	if (!target_find_memory_real(target,paddr,NULL,NULL,&range)) {
	    verror("could not find range for ptr 0x%"PRIxADDR"\n",paddr);
	    errno = EFAULT;
	    goto errout;
	}

	if (!__target_load_addr_real(target,range,paddr,LOAD_FLAG_NONE,
				     (unsigned char *)&paddr,target->arch->ptrsize)) {
	    verror("could not load ptr #%d at 0x%"PRIxADDR"\n",i,paddr);
	    errno = EFAULT;
	    goto errout;
	}

	vdebug(9,LA_TARGET,LF_SYMBOL,
	       "loaded next ptr value 0x%"PRIxADDR" (#%d)\n",
	       paddr,i);
    }

    if (i == count && range) {
	if (range_saveptr)
	    *range_saveptr = range;
    }

    errno = 0;
    return paddr;

 errout:
    return 0;
}

ADDR target_autoload_pointers(struct target *target,struct symbol *datatype,
			      ADDR addr,load_flags_t flags,
			      struct symbol **datatype_saveptr,
			      struct memrange **range_saveptr) {
    load_flags_t ptrloadflags = flags;
    ADDR paddr = addr;
    struct memrange *range = NULL;
    int nptrs = 0;

    /*
     * Don't allow any load flags through for this!  We don't want
     * to mmap just for pointers.
     */
    ptrloadflags &= ~LOAD_FLAG_MUST_MMAP;
    ptrloadflags |= LOAD_FLAG_NO_MMAP;

    while (SYMBOL_IST_PTR(datatype)) {
	if (((flags & LOAD_FLAG_AUTO_DEREF) && SYMBOL_IST_PTR(datatype))
	    || ((flags & LOAD_FLAG_AUTO_STRING) 
		&& SYMBOL_IST_PTR(datatype) 
		&& symbol_type_is_char(symbol_type_skip_ptrs(datatype)))) {
	    if (paddr == 0) {
		verror("failed to follow NULL pointer #%d\n",nptrs);
		errno = EFAULT;
		goto errout;
	    }

	    vdebug(9,LA_TARGET,LF_TSYMBOL,
		   "loading ptr at 0x%"PRIxADDR"\n",paddr);

	    /*
	     * The pointer may be in another region!  We *have* to
	     * switch regions -- and thus the memrange for the value we
	     * return may not be in @addr's region/range!
	     */
	    if (!target_find_memory_real(target,paddr,NULL,NULL,&range)) {
		verror("could not find range for ptr 0x%"PRIxADDR"\n",paddr);
		errno = EFAULT;
		goto errout;
	    }

	    if (!__target_load_addr_real(target,range,paddr,ptrloadflags,
					 (unsigned char *)&paddr,
					 target->arch->ptrsize)) {
		verror("could not load ptr 0x%"PRIxADDR"\n",paddr);
		errno = EFAULT;
		goto errout;
	    }

	    ++nptrs;
	    vdebug(9,LA_TARGET,LF_TSYMBOL,
		   "loaded next ptr value 0x%"PRIxADDR" (#%d)\n",
		   paddr,nptrs);

	    /* Skip past the pointer we just loaded. */
	    datatype = symbol_get_datatype(datatype);
	}
	else {
	    break;
	}
    }

    if (range) {
	if (range_saveptr)
	    *range_saveptr = range;
	if (datatype_saveptr)
	    *datatype_saveptr = datatype;
    }

    errno = 0;
    return paddr;

 errout:
    return 0;
}

/*
 * Load a raw value (i.e., no symbol or type info) using an object
 * file-based location (i.e., a fixed object-relative address) and a
 * specific region.
 *
 * Note: you cannot mmap raw values; they must be copied from target memory.
 */
struct value *target_load_addr_obj(struct target *target,struct memregion *region,
				   ADDR obj_addr,load_flags_t flags,int len) {
    ADDR real;
    struct memrange *range;

    if (flags & LOAD_FLAG_MUST_MMAP) {
	errno = EINVAL;
	return NULL;
    }

    errno = 0;
    real = memregion_relocate(region,obj_addr,&range);
    if (errno)
	return NULL;

    return target_load_addr_real(target,real,flags,len);
}

/*
 * Load a raw value (i.e., no symbol or type info) using a real address.
 *
 * Note: you cannot mmap raw values; they must be copied from target memory.
 */
struct value *target_load_addr_real(struct target *target,ADDR addr,
				    load_flags_t flags,int len) {
    struct memrange *range;
    struct value *value;

    if (flags & LOAD_FLAG_MUST_MMAP) {
	errno = EINVAL;
	return NULL;
    }

    if (!target_find_memory_real(target,addr,NULL,NULL,&range)) {
	verror("could not find range containing addr 0x%"PRIxADDR"!\n",addr);
	errno = ERANGE;
	return NULL;
    }

    if (!(value = value_create_raw(target,NULL,range,len))) {
	verror("could not create raw value of len %d for addr 0x%"PRIxADDR"!\n",
	       len,addr);
	return NULL;
    }

    if (!__target_load_addr_real(target,range,addr,flags,
				 (unsigned char *)value->buf,value->bufsiz)) {
	value_free(value);
	return NULL;
    }

    value_set_addr(value,addr);

    return value;
}

unsigned char *target_load_raw_addr_real(struct target *target,ADDR addr,
					 load_flags_t flags,
					 unsigned char *buf,int bufsiz) {
    struct memrange *range;

    if (!target_find_memory_real(target,addr,NULL,NULL,&range)) {
	verror("could not find range containing addr 0x%"PRIxADDR"!\n",addr);
	errno = ERANGE;
	return NULL;
    }

    return __target_load_addr_real(target,range,addr,flags,
				   (unsigned char *)buf,bufsiz);
}

unsigned char *__target_load_addr_real(struct target *target,
				       struct memrange *range,
				       ADDR addr,load_flags_t flags,
				       unsigned char *buf,int bufsiz) {
    if (!(flags & LOAD_FLAG_NO_CHECK_BOUNDS)) {
	if (!memrange_contains_real(range,addr)) {
	    verror("addr 0x%"PRIxADDR" not in"
		   " range(0x%"PRIxADDR",0x%"PRIxADDR")!\n",
		   addr,range->start,range->end);
	    errno = ERANGE;
	    return NULL;
	}
	else if (!memrange_contains_real(range,addr+bufsiz-1)) {
	    verror("addr 0x%"PRIxADDR" + bufsiz %d not in"
		   " range(0x%"PRIxADDR",0x%"PRIxADDR")!\n",
		   addr,bufsiz,range->start,range->end);
	    errno = ERANGE;
	    return NULL;
	}
    }

    return target_read_addr(target,addr,bufsiz,buf);
}

int target_lookup_safe_disasm_range(struct target *target,ADDR addr,
				    ADDR *start,ADDR *end,void **data) {
    struct addrspace *space;
    struct memregion *region;
    struct memrange *range = NULL;

    struct clf_range_data *crd;

    /* Find which region contains this address. */
    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if ((range = memregion_find_range_real(region,addr)))
		break;
	}
    }

    if (!range) 
	return -1;

    if ((crd = clrange_find_loosest(&region->binfile->ranges,
				    memrange_unrelocate(range,addr),
				    NULL))) {
	if (start)
	    *start = memrange_relocate(range,crd->start);
	if (end)
	    *end = memrange_relocate(range,crd->end);
	if (data)
	    *data = crd->data;

	return 0;
    }

    return -1;
}

int target_lookup_next_safe_disasm_range(struct target *target,ADDR addr,
					 ADDR *start,ADDR *end,void **data) {
    struct addrspace *space;
    struct memregion *region;
    struct memrange *range = NULL;

    struct clf_range_data *crd;

    /* Find which region contains this address. */
    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if ((range = memregion_find_range_real(region,addr)))
		break;
	}
    }

    if (!range)
	return -1;

    if ((crd = clrange_find_next_loosest(&region->binfile->ranges,
					 memrange_unrelocate(range,addr),
					 NULL))) {
	if (start)
	    *start = memrange_relocate(range,crd->start);
	if (end)
	    *end = memrange_relocate(range,crd->end);
	if (data)
	    *data = crd->data;

	return 0;
    }

    return -1;
}

/*
 * CODE_CACHE_BUF_PAD -- distorm seems to have an off by one error decoding at
 * the end of a buffer supplied to it -- so we always pad our buffers we
 * pass to it with this many NUL bytes.
 */
#define CODE_CACHE_BUF_PAD 5

struct code_cache_entry {
    Word_t start;
    unsigned int len:31,
	         isevictable:1;
    unsigned char *code;
};

unsigned char *target_load_code(struct target *target,
				ADDR start,unsigned int len,
				int nocache,int force_copy,int *caller_free) {
    unsigned char *buf = NULL;
    unsigned int llen = 0;
    struct code_cache_entry *ccd;
    ADDR nextaddr;
    ADDR cstart,cend;
    unsigned int tlen;
    unsigned char *tbuf;

    nextaddr = start;

    if (force_copy) 
	buf = calloc(1,len + CODE_CACHE_BUF_PAD);

    while (llen < len) {
	/*
	 * Check the cache first.  If we find a hit, maybe we can fill
	 * up at least part of our return buffer -- OR maybe even just
	 * return a pointer.
	 */
    checkcache:
	ccd = (struct code_cache_entry *)clrange_find(&target->code_ranges,
						      nextaddr);
	if (ccd) {
	    /* At least some of the code in this cache entry is
	     * relevant; either plop it into our current buf; return a
	     * pointer to it, or an offset of it.
	     */

	    /* If we don't have a buf (i.e., not forcing a copy, and
	     * have not needed a buf because we're not needing to load
	     * multiple segments), and if the code we need is entirely
	     * in this buf, then just return a pointer to the right
	     * place in this buf!
	     */
	    if (!buf && (nextaddr + len) <= (ccd->start + ccd->len)) {
		*caller_free = 0;
		return ccd->code + (nextaddr - ccd->start);
	    }
	    /* Otherwise, we have a buf (or we *must* create one because
	     * we are loading more code than is in this one cache entry)
	     * and we need to copy (at least some) of the data in this
	     * cache entry into it.
	     */
	    else {
		if (!buf) 
		    buf = calloc(1,len + CODE_CACHE_BUF_PAD);

		tlen = ccd->len - (nextaddr - ccd->start);
		if ((len - llen) < tlen)
		    tlen = len - llen;

		memcpy(buf + llen,ccd->code + (nextaddr - ccd->start),tlen);
		llen += tlen;
	    }
	}
	else {
	    /* If it's not in the cache, we need to load the next safe
	     * disasm chunk --- OR FILL IN THE HOLE THAT CONTAINS
	     * nextaddr.
	     */
	    if (target_lookup_safe_disasm_range(target,nextaddr,&cstart,&cend,
						NULL)) {
		verror("no safe disasm range contains 0x%"PRIxADDR"!\n",nextaddr);
		goto errout;
	    }

	    tbuf = target_load_raw_addr_real(target,cstart,
					     LOAD_FLAG_NONE,NULL,cend - cstart);
	    if (!tbuf) {
		verror("could not load code in safe disasm range" 
		       " 0x%"PRIxADDR",0x%"PRIxADDR"!\n",cstart,cend);

		tbuf = target_load_raw_addr_real(target,cstart,
						 LOAD_FLAG_NONE,NULL,1);
		if (!tbuf) {
		    verror("could not load even 1 byte of code in safe disasm range" 
			   " 0x%"PRIxADDR",0x%"PRIxADDR"!\n",cstart,cend);
		}
		else {
		    verror("BUT could load 1 byte of code in safe disasm range" 
			   " 0x%"PRIxADDR",0x%"PRIxADDR"!\n",cstart,cend);
		}
		goto errout;
	    }

	    /* Save it in the cache! */
	    ccd = (struct code_cache_entry *)calloc(1,sizeof(*ccd));
	    ccd->start = cstart;
	    ccd->len = cend - cstart;
	    ccd->code = tbuf;

	    clrange_add(&target->code_ranges,cstart,cend,ccd);

	    /* Just hop back to the top of the loop and let the cache
	     * check succeed this time!
	     */
	    goto checkcache;
	}
    }

    if (caller_free)
	*caller_free = 1;
    return buf;

 errout:
    if (buf)
	free(buf);
    return NULL;
    
}

struct target_thread *target_lookup_thread(struct target *target,tid_t tid) {
    vdebug(16,LA_TARGET,LF_THREAD,"thread %"PRIiTID"\n",tid);
    return (struct target_thread *)g_hash_table_lookup(target->threads,
						       (gpointer)(ptr_t)tid);
}

target_status_t target_get_status(struct target *target) {
    vdebug(8,LA_TARGET,LF_TARGET,"target %s  %s\n",
	   target->name,TSTATUS(target->status));
    return target->status;
}

void target_set_status(struct target *target,target_status_t status) {
    vdebug(8,LA_TARGET,LF_TARGET,"target %s  %s -> %s\n",
	   target->name,TSTATUS(target->status),TSTATUS(status));
    target->status = status;
}

void target_thread_set_status(struct target_thread *tthread,
			      thread_status_t status) {
    vdebug(8,LA_TARGET,LF_THREAD | LF_TARGET,"target %s tid %d  %s -> %s\n",
	   tthread->target->name,tthread->tid,
	   THREAD_STATUS(tthread->status),THREAD_STATUS(status));
    tthread->status = status;
}

void target_tid_set_status(struct target *target,tid_t tid,
			   thread_status_t status) {
    struct target_thread *tthread = (struct target_thread *) \
	g_hash_table_lookup(target->threads,(gpointer)(ptr_t)tid);
    if (!tthread) {
	verror("could not set status for nonexistent tid %d -- BUG!\n",tid);
	return;
    }
    vdebug(8,LA_TARGET,LF_THREAD | LF_TARGET,"target %s tid %d  %s -> %s\n",
	   tthread->target->name,tthread->tid,
	   THREAD_STATUS(tthread->status),THREAD_STATUS(status));
    tthread->status = status;
}

struct target_thread *target_create_thread(struct target *target,tid_t tid,
					   void *tstate,void *tpstate) {
    struct target_thread *t = (struct target_thread *)calloc(1,sizeof(*t));

    vdebug(3,LA_TARGET,LF_THREAD,"thread %"PRIiTID"\n",tid);

    t->target = target;
    t->tid = tid;
    t->state = tstate;
    t->personality_state = tpstate;

    /*
     * Don't *build* the regcaches yet -- just the per-thread_ctxt pointers.
     */
    t->regcaches = (struct regcache **) \
	calloc(target->max_thread_ctxt,sizeof(*t->regcaches));

    t->ptid = -1;
    t->uid = -1;
    t->gid = -1;

    t->hard_probepoints = g_hash_table_new(g_direct_hash,g_direct_equal);

    t->tpc = NULL;
    t->tpc_stack = array_list_create(4);
    INIT_LIST_HEAD(&t->ss_actions);

    /* Keys are always copied; values get user-custom dtors */
    t->gkv_store = g_hash_table_new_full(g_str_hash,g_str_equal,free,NULL);

    g_hash_table_insert(target->threads,(gpointer)(ptr_t)tid,t);

    return t;
}

void target_reuse_thread_as_global(struct target *target,
				   struct target_thread *thread) {
    vdebug(3,LA_TARGET,LF_THREAD,"thread %"PRIiTID" as global %"PRIiTID"\n",
	   thread->tid,TID_GLOBAL);
    g_hash_table_insert(target->threads,(gpointer)TID_GLOBAL,thread);
    target->global_thread = thread;
}

void target_detach_thread(struct target *target,struct target_thread *tthread) {
    GHashTableIter iter;
    struct probepoint *probepoint;
    struct thread_action_context *tac,*ttac;

    /*
     * Destroy any thread generic keys first.
     */
    target_thread_gkv_destroy(target,tthread);

    /*
     * If this thread has an overlay target, detach that first!
     */
    //zzz;

    if (!list_empty(&tthread->ss_actions)) {
	list_for_each_entry_safe(tac,ttac,&tthread->ss_actions,tac) {
	    action_free(tac->action,0);
	    free(tac);
	}
    }

    /* We have to free the probepoints manually, then remove all.  We
     * can't remove an element during an iteration, but we *can* free
     * the data :).
     */
    g_hash_table_iter_init(&iter,tthread->hard_probepoints);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&probepoint)) {
	probepoint_free_ext(probepoint);
    }

    g_hash_table_remove_all(tthread->hard_probepoints);
}

void target_delete_thread(struct target *target,struct target_thread *tthread,
			  int nohashdelete) {
    unsigned int i;

    vdebug(3,LA_TARGET,LF_THREAD,"thread %"PRIiTID"\n",tthread->tid);

    /*
     * If this thread has an overlay target, delete that first!
     */


    /*
     * If this function is being called as a target being detached,
     * these probepoints must be freed *before* this function is called;
     * this is a last-minute check that works well because sometimes
     * this function is called during normal target runtime as threads
     * come and go.
     */

    target_detach_thread(target,tthread);

    /*
     * Once we're done with the underlying target, tell it the overlay
     * is gone!
     */
    if (target->base)
	target_detach_overlay_thread(target->base,target,tthread->tid);

    array_list_free(tthread->tpc_stack);
    tthread->tpc_stack = NULL;

    g_hash_table_destroy(tthread->hard_probepoints);
    tthread->hard_probepoints = NULL;

    if (tthread->personality_state) {
	if (tthread->target->personality_ops
	    && tthread->target->personality_ops->free_thread_state)
	    tthread->target->personality_ops->free_thread_state(tthread->target,
								tthread->personality_state);
	else
	    free(tthread->personality_state);
    }

    for (i = 0; i < target->max_thread_ctxt; ++i) {
	if (tthread->regcaches[i]) {
	    regcache_destroy(tthread->regcaches[i]);
	    tthread->regcaches[i] = NULL;
	}
    }
    free(tthread->regcaches);
    tthread->regcaches = NULL;

    if (tthread->state) {
	if (tthread->target->ops->free_thread_state) 
	    tthread->target->ops->free_thread_state(tthread->target,
						    tthread->state);
	else
	    free(tthread->state);
    }

    if (!nohashdelete) 
	g_hash_table_remove(target->threads,(gpointer)(ptr_t)tthread->tid);

    free(tthread);
}

/*
 * We recognize several keys:
 *   tid -- the thread id
 *   ptid -- the thread's parent thread id
 *   tidhier -- a common-separated list of tids starting with the
 *     current tid, and then moving up the hierarchy to the root.
 *   name -- the thread's name
 *   namehier -- a comma-separated list of tid names starting with the
 *     current tid, and then moving up the hierarchy to the root.
 *   uid -- the thread's uid, if any
 *   gid -- the thread's gid, if any.
 *
 * Eventually, we need to pass any other keys to the backend in question
 * for more powerful filtering.  But this is enough for now.
 */
int target_thread_filter_check(struct target *target,tid_t tid,
			       struct target_nv_filter *tf) {
    struct target_thread *tthread,*tmpthread;
    char vstrbuf[1024];
    int rc;
    int i;
    GSList *gsltmp;
    struct target_nv_filter_regex *tfr;

    if (!tf)
	return 0;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return 1;
    }

    /*
     * Check each filter by loading the value from @trigger.
     */
    v_g_slist_foreach(tf->value_regex_list,gsltmp,tfr) {
	/* NB: notice that longest matches have to be checked first;
	 * else tid will match tidhier.
	 */
	if (strncmp(tfr->value_name,"tidhier",strlen("tidhier")) == 0) {
	    rc = 0;
	    i = 0;
	    tmpthread = tthread;
	    do {
		if (likely(i > 0))
		    rc += snprintf(vstrbuf + rc,sizeof(vstrbuf) - rc,
				   ",%"PRIiTID,tmpthread->tid);
		else
 		    rc += snprintf(vstrbuf + rc,sizeof(vstrbuf) - rc,
				   "%"PRIiTID,tmpthread->tid);
		++i;

		if (tmpthread->ptid == -1)
		    tmpthread = NULL;
		else {
		    /* Don't need to load it; it would have been loaded
		     * because the base child thread was loaded.
		     */
		    tmpthread = target_lookup_thread(target,tmpthread->ptid);
		}
	    } while (tmpthread);
	}
	else if (strncmp(tfr->value_name,"tid",strlen("tid")) == 0) {
	    rc = snprintf(vstrbuf,sizeof(vstrbuf),"%"PRIiTID,tthread->tid);
	}
	else if (strncmp(tfr->value_name,"ptid",strlen("ptid")) == 0) {
	    rc = snprintf(vstrbuf,sizeof(vstrbuf),"%"PRIiTID,tthread->ptid);
	}
	else if (strncmp(tfr->value_name,"namehier",strlen("namehier")) == 0) {
	    rc = 0;
	    i = 0;
	    tmpthread = tthread;
	    do {
		if (likely(i > 0))
		    rc += snprintf(vstrbuf + rc,sizeof(vstrbuf) - rc,
				   ",%s",tmpthread->name ? tmpthread->name : "");
		else
		    rc += snprintf(vstrbuf + rc,sizeof(vstrbuf) - rc,
				   "%s",tmpthread->name ? tmpthread->name : "");
		++i;

		if (tmpthread->ptid == -1)
		    tmpthread = NULL;
		else {
		    /* Don't need to load it; it would have been loaded
		     * because the base child thread was loaded.
		     */
		    tmpthread = target_lookup_thread(target,tmpthread->ptid);
		}
	    } while (tmpthread);
	}
	else if (strncmp(tfr->value_name,"name",strlen("name")) == 0) {
	    rc = snprintf(vstrbuf,sizeof(vstrbuf),"%s",
			  tthread->name ? tthread->name : "");
	}
	else if (strncmp(tfr->value_name,"uid",strlen("uid")) == 0) {
	    rc = snprintf(vstrbuf,sizeof(vstrbuf),"%d",tthread->uid);
	}
	else if (strncmp(tfr->value_name,"gid",strlen("gid")) == 0) {
	    rc = snprintf(vstrbuf,sizeof(vstrbuf),"%d",tthread->gid);
	}
	else {
	    vwarn("unrecognized thread filter key '%s'; skipping!\n",
		  tfr->value_name);
	    continue;
	}

	if (regexec(&tfr->regex,(const char *)vstrbuf,0,NULL,0) == REG_NOMATCH) {
	    vdebug(9,LA_TARGET,LF_THREAD,
		   "failed to match name %s value '%s' with regex!\n",
		   tfr->value_name,vstrbuf);
	    return 1;
	}
	else {
	    vdebug(9,LA_TARGET,LF_THREAD,
		   "matched name %s value '%s' with regex\n",
		   tfr->value_name,vstrbuf);
	}
    }

    return 0;
}

int target_invalidate_thread(struct target *target,
			     struct target_thread *tthread) {
    unsigned int i;

    if (target->ops->invalidate_thread)
	target->ops->invalidate_thread(target,tthread);
    else if (target->personality_ops 
	     && target->personality_ops->invalidate_thread)
	target->personality_ops->invalidate_thread(target,tthread);

    /*
     * XXX: Invalidate any valid regcaches.  Not sure we should do this
     * here...
     */
    for (i = 0; i < target->max_thread_ctxt; ++i) {
	if (tthread->regcaches[i]) {
	    regcache_invalidate(tthread->regcaches[i]);
	}
    }

    tthread->valid = 0;

    if (tthread->dirty)
	vwarn("invalidated dirty thread %"PRIiTID"; BUG?\n",tthread->tid);

    return 0;
}

static int __target_invalidate_all_threads(struct target *target) {
    GHashTableIter iter;
    struct target_thread *tthread;
    unsigned int i;

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) {
	if (target->ops->invalidate_thread)
	    target->ops->invalidate_thread(target,tthread);
	else if (target->personality_ops 
		 && target->personality_ops->invalidate_thread)
	    target->personality_ops->invalidate_thread(target,tthread);

	/*
	 * XXX: Invalidate any valid regcaches.  Not sure we should do this
	 * here...
	 */
	for (i = 0; i < target->max_thread_ctxt; ++i) {
	    if (tthread->regcaches[i]) {
		regcache_invalidate(tthread->regcaches[i]);
	    }
	}

	tthread->valid = 0;

	if (tthread->dirty)
	    vwarn("invalidated dirty thread %"PRIiTID"; BUG?\n",tthread->tid);
    }

    return 0;
}

int target_invalidate_all_threads(struct target *target) {
    GHashTableIter iter;
    struct target *overlay;
    int rc;

    vdebug(8,LA_TARGET,LF_TARGET,
	   "invalidating all target(%s) threads\n",target->name);

    /*
     * Do it for all the overlays first.
     */
    g_hash_table_iter_init(&iter,target->overlays);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&overlay)) {
	vdebug(5,LA_TARGET,LF_TARGET,
	       "invalidating all overlay target(%s) threads\n",overlay->name);
	rc = target_invalidate_all_threads(overlay);
	vdebug(5,LA_TARGET,LF_TARGET,
	       "invalidating all overlay target(%s) threads (%d)\n",overlay->name,rc);
    }

    return __target_invalidate_all_threads(target);
}

target_status_t target_notify_overlay(struct target *overlay,tid_t tid,ADDR ipval,
				      int *again) {
    return overlay->ops->handle_overlay_exception(overlay,tid,ipval,again);
}

struct target *target_lookup_overlay(struct target *target,tid_t tid) {
    struct target *overlay;

    overlay = (struct target *) \
	g_hash_table_lookup(target->overlays,(gpointer)(uintptr_t)tid);
    if (!overlay)
	overlay = (struct target *) \
	    g_hash_table_lookup(target->overlay_aliases,(gpointer)(uintptr_t)tid);

    return overlay;
}

void target_detach_overlay(struct target *base,tid_t overlaytid) {
    GHashTableIter iter;
    struct target *overlay;
    gpointer vp;

    overlay = (struct target *) \
	g_hash_table_lookup(base->overlays,(gpointer)(uintptr_t)overlaytid);
    g_hash_table_remove(base->overlays,(gpointer)(uintptr_t)overlaytid);

    if (overlay) {
	g_hash_table_iter_init(&iter,base->overlay_aliases);
	while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	    if (vp == overlay)
		g_hash_table_iter_remove(&iter);
	}
    }
}

int target_attach_overlay_thread(struct target *base,struct target *overlay,
				 tid_t newtid) {
    int rc;

    if (overlay->base != base || newtid == overlay->base_tid) {
	errno = EINVAL;
	return -1;
    }

    if (!base->ops->attach_overlay_thread) {
	errno = ENOTSUP;
	return -1;
    }

    if (target_lookup_overlay(base,newtid)) {
	errno = EADDRINUSE;
	return -1;
    }

    rc = base->ops->attach_overlay_thread(base,overlay,newtid);
    if (rc == 0)
	g_hash_table_insert(base->overlay_aliases,(gpointer)(uintptr_t)newtid,
			    overlay);

    return rc;
}

int target_detach_overlay_thread(struct target *base,struct target *overlay,
				 tid_t tid) {
    int rc;

    if (tid == overlay->base_tid) {
	errno = EINVAL;
	return -1;
    }

    if (!base->ops->detach_overlay_thread) {
	errno = ENOTSUP;
	return -1;
    }

    rc = base->ops->detach_overlay_thread(base,overlay,tid);
    if (rc == 0)
	g_hash_table_lookup(base->overlay_aliases,(gpointer)(uintptr_t)tid);

    return rc;
}

struct probepoint *target_lookup_probepoint(struct target *target,
					    struct target_thread *tthread,
					    ADDR addr) {
    struct probepoint *retval;

    if (tthread 
	&& (retval = (struct probepoint *) \
	    g_hash_table_lookup(tthread->hard_probepoints,(gpointer)addr))) {
	vdebug(9,LA_PROBE | LA_TARGET,LF_PROBEPOINT | LF_TARGET,"found hard ");
	LOGDUMPPROBEPOINT_NL(9,LA_PROBE | LA_TARGET,LF_PROBEPOINT | LF_TARGET,
			     retval);
    }
    else if ((retval = (struct probepoint *) \
	      g_hash_table_lookup(target->soft_probepoints,(gpointer)addr))) {
	vdebug(9,LA_PROBE | LA_TARGET,LF_PROBEPOINT | LF_TARGET,"found soft ");
	LOGDUMPPROBEPOINT_NL(9,LA_PROBE | LA_TARGET,LF_PROBEPOINT | LF_TARGET,
			     retval);
    }
    else
	vdebug(9,LA_PROBE | LA_TARGET,LF_PROBEPOINT | LF_TARGET,
	       "no probepoint at 0x%"PRIxADDR"\n",addr);

    return retval;
}

int target_insert_probepoint(struct target *target,
			     struct target_thread *tthread,
			     struct probepoint *probepoint) {
    if (probepoint->style == PROBEPOINT_HW) {
	g_hash_table_insert(tthread->hard_probepoints,
			    (gpointer)probepoint->addr,(gpointer)probepoint);
	probepoint->thread = tthread;
    }
    else if (probepoint->style == PROBEPOINT_SW) {
	g_hash_table_insert(target->soft_probepoints,
			    (gpointer)probepoint->addr,(gpointer)probepoint);
	probepoint->thread = tthread;
    }
    else {
	verror("bad probepoint state %d; must be HW/SW!\n",probepoint->state);
	errno = EINVAL;
	return -1;
    }

    vdebug(9,LA_PROBE | LA_TARGET,LF_PROBEPOINT | LF_TARGET,
	   "inserted probepoint at 0x%"PRIxADDR" tid %"PRIiTID"\n",
	   probepoint->addr,tthread->tid);

    return 0;
}

int target_remove_probepoint(struct target *target,
			     struct target_thread *tthread,
			     struct probepoint *probepoint) {
    if (probepoint->style == PROBEPOINT_HW) {
	g_hash_table_remove(tthread->hard_probepoints,(gpointer)probepoint->addr);
	probepoint->thread = NULL;
    }
    else if (probepoint->style == PROBEPOINT_SW) {
	g_hash_table_remove(target->soft_probepoints,(gpointer)probepoint->addr);
	probepoint->thread = NULL;
    }
    else {
	verror("bad probepoint state %d; must be HW/SW!\n",probepoint->state);
	errno = EINVAL;
	return -1;
    }

    vdebug(9,LA_PROBE | LA_TARGET,LF_PROBEPOINT | LF_TARGET,
	   "removed probepoint at 0x%"PRIxADDR" tid %"PRIiTID"\n",
	   probepoint->addr,tthread->tid);

    return 0;
}

int target_attach_probe(struct target *target,struct target_thread *thread,
			struct probe *probe) {
    probe->id = target->probe_id_counter++;
    probe->target = target;
    probe->thread = thread;

    if (probe->tracked)
	g_hash_table_insert(target->probes,(gpointer)(uintptr_t)probe->id,probe);

    return probe->id;
}

int target_detach_probe(struct target *target,struct probe *probe) {
    if (probe->tracked)
	g_hash_table_remove(target->probes,(gpointer)(uintptr_t)probe->id);

    probe->id = -1;
    probe->target = NULL;
    probe->thread = NULL;

    return 0;
}

int target_attach_action(struct target *target,struct action *action) {
    action->id = target->action_id_counter++;
    action->target = target;

    g_hash_table_insert(target->actions,(gpointer)(uintptr_t)action->id,action);

    return action->id;
}

int target_detach_action(struct target *target,struct action *action) {
    g_hash_table_remove(target->actions,(gpointer)(uintptr_t)action->id);

    action->id = -1;
    action->target = NULL;

    return 0;
}

result_t target_memmod_emulate_bp_handler(struct target *target,tid_t tid,
					  struct target_memmod *mmod) {
    struct target_thread *tthread;
    REGVAL ipval;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return RESULT_ERROR;
    }

    if (tthread->emulating_debug_mmod) {
	verror("tid %"PRIiTID" already is emulating a memmod"
	       " at 0x%"PRIxADDR"; cannot do another one!\n",
	       tid,tthread->emulating_debug_mmod->addr);
	errno = EBUSY;
	return RESULT_ERROR;
    }

    tthread->emulating_debug_mmod = mmod;

    /*
     * If we're in BPMODE_STRICT, we have to pause all the other
     * threads.
     */
    if (target->spec->bpmode == THREAD_BPMODE_STRICT) {
	if (target_pause(target)) {
	    vwarn("could not pause the target for blocking thread"
		  " %"PRIiTID"!\n",tthread->tid);
	    return RESULT_ERROR;
	}
	target->blocking_thread = tthread;
    }

    errno = 0;
    ipval = target_read_reg(target,tid,target->ipregno);
    if (!ipval && errno) {
	verror("could not read IP in tid %"PRIiTID"!\n",tid);
	return RESULT_ERROR;
    }

    /* Disable the memmod. */
    if (target_memmod_unset(target,tid,mmod)) {
	verror("could not disable breakpoint before singlestep;"
	       " assuming breakpoint is left in place and"
	       " skipping single step, but badness will ensue!");
	goto errout;
    }

    /* Enable singlestep. */
    if (target_singlestep(target,tid,1)) {
	verror("could not singlestep tid %"PRIiTID"!\n",tid);
	goto errout;
    }

    /* Reset ip. */
    ipval -= target->arch->breakpoint_instrs_len; //target_memmod_length(target,mmod);
    if (target_write_reg(target,tid,target->ipregno,ipval)) {
	verror("could not write IP!\n");
	goto errout;
    }

    /* Temporarily add this thread to the mmod. */
    array_list_append(mmod->threads,tthread);

    return RESULT_SUCCESS;

 errout:
    target_singlestep_end(target,tid);
    if (target->blocking_thread == tthread)
	target->blocking_thread = NULL;
    tthread->emulating_debug_mmod = NULL;

    return RESULT_ERROR;
}

result_t target_memmod_emulate_ss_handler(struct target *target,tid_t tid,
					  struct target_memmod *mmod) {
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return RESULT_ERROR;
    }

    if (tthread->emulating_debug_mmod 
	&& tthread->emulating_debug_mmod != mmod) {
	verror("tid %"PRIiTID" already is emulating a memmod"
	       " at 0x%"PRIxADDR"; cannot do another one!\n",
	       tid,tthread->emulating_debug_mmod->addr);
	errno = EBUSY;
	return RESULT_ERROR;
    }
    else if (!tthread->emulating_debug_mmod)
	vwarn("not set to emulate a debug mmod; trying anyway!\n");

    /* Disable singlestep. */
    target_singlestep_end(target,tid);

    /* Reenable the memmod. */
    target_memmod_set(target,tid,mmod);

    /* Remove this thread from the memmod's list. */
    array_list_remove_item(mmod->threads,tthread);

    if (target->spec->bpmode == THREAD_BPMODE_STRICT) {
	if (target->blocking_thread == tthread)
	    target->blocking_thread = NULL;
    }

    if (tthread->emulating_debug_mmod == mmod)
	tthread->emulating_debug_mmod = NULL;
    else if (tthread->emulating_debug_mmod) {
	verror("tid %"PRIiTID" already is emulating a memmod"
	       " at 0x%"PRIxADDR"; cannot clear it!\n",
	       tid,tthread->emulating_debug_mmod->addr);
    }

    return RESULT_SUCCESS;
}

unsigned long target_memmod_length(struct target *target,
				   struct target_memmod *mmod) {
    switch (mmod->state) {
    case MMS_SUBST:
	return mmod->mod_len;
    case MMS_ORIG:
	return 0;
    case MMS_TMP:
	return mmod->tmp_len;
    default:
	verror("unknown memmod state %d!\n",mmod->state);
	errno = EINVAL;
	return 0;
    }
}

struct target_memmod *target_memmod_create(struct target *target,tid_t tid,
					   ADDR addr,int is_phys,
					   target_memmod_type_t mmt,
					   unsigned char *code,
					   unsigned int code_len) {
    struct target_memmod *mmod;
    unsigned char *ibuf = NULL;
    unsigned int ibuf_len;
    unsigned int rc;
    struct target_thread *tthread;
    unsigned char *rcc;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return NULL;
    }

    mmod = calloc(1,sizeof(*mmod));
    mmod->state = MMS_SUBST;
    mmod->type = mmt;
    mmod->target = target;
    mmod->threads = array_list_create(1);
    mmod->addr = addr;
    mmod->is_phys = is_phys;

    if (code) {
	/*
	 * Backup the original memory.  If debugging, read at least
	 * 8 bytes so we can see what was there and dump it for debug
	 * purposes.  It is a bit wasteful in that case, but no big
	 * deal.
	 */
	if (code_len > 8)
	    ibuf_len = code_len;
	else 
	    ibuf_len = 8;
	ibuf = calloc(1,ibuf_len);

	if (is_phys) 
	    rcc = target_read_physaddr(target,addr,ibuf_len,ibuf);
	else
	    rcc = target_read_addr(target,addr,ibuf_len,ibuf);

	if (!rcc) {
	    array_list_free(mmod->threads);
	    free(ibuf);
	    free(mmod);
	    verror("could not read %u bytes at 0x%"PRIxADDR"!\n",
		   ibuf_len,addr);
	    return NULL;
	}

	mmod->orig_len = code_len;
	mmod->orig = calloc(1,mmod->orig_len);

	memcpy(mmod->orig,ibuf,mmod->orig_len);

	mmod->mod = malloc(code_len);
	mmod->mod_len = code_len;
	memcpy(mmod->mod,code,mmod->mod_len);

	if (is_phys)
	    rc = target_write_physaddr(target,addr,mmod->mod_len,mmod->mod);
	else
	    rc = target_write_addr(target,addr,mmod->mod_len,mmod->mod);

	if (rc != mmod->mod_len) {
	    array_list_free(mmod->threads);
	    free(mmod->mod);
	    free(mmod->orig);
	    free(mmod);
	    verror("could not write %lu subst bytes at 0x%"PRIxADDR"!\n",
		   mmod->orig_len,addr);
	    return NULL;
	}
    }

    if (is_phys)
	g_hash_table_insert(target->phys_mmods,(gpointer)addr,mmod);
    else
	g_hash_table_insert(target->mmods,(gpointer)addr,mmod);

    array_list_append(mmod->threads,tthread);

    if (code) {
	vdebug(5,LA_TARGET,LF_TARGET,
	       "created memmod at 0x%"PRIxADDR" (is_phys=%d) tid %"PRIiTID";"
	       " inserted new bytes (orig mem: %02hhx %02hhx %02hhx %02hhx"
	       " %02hhx %02hhx %02hhx %02hhx)\n",
	       mmod->addr,is_phys,tid,
	       (int)ibuf[0],(int)ibuf[1],(int)ibuf[2],(int)ibuf[3],
	       (int)ibuf[4],(int)ibuf[5],(int)ibuf[6],(int)ibuf[7]);
    }
    else {
	vdebug(5,LA_TARGET,LF_TARGET,
	       "created (fake) memmod at 0x%"PRIxADDR" (is_phys=%d) tid %"PRIiTID"\n",
	       mmod->addr,is_phys,tid);
    }

    if (ibuf)
	free(ibuf);

    return mmod;
}

struct target_memmod *target_memmod_lookup(struct target *target,tid_t tid,
					   ADDR addr,int is_phys) {
    struct target_memmod *mmod;
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return NULL;
    }

    /*
     * Eventually, the virt ->mmods hashtable will be per-thread.
     */
    if (is_phys) 
	mmod = (struct target_memmod *) \
	    g_hash_table_lookup(target->phys_mmods,(gpointer)addr);
    else
	mmod = (struct target_memmod *) \
	    g_hash_table_lookup(target->mmods,(gpointer)addr);

    if (mmod) 
	vdebug(16,LA_TARGET,LF_TARGET,
	       "found mmod 0x%"PRIxADDR" (phys=%d)\n",
	       mmod->addr,mmod->is_phys);
    else 
	vwarnopt(16,LA_TARGET,LF_TARGET,
		 "did not find mmod for 0x%"PRIxADDR" (is_phys=%d)!\n",
		 addr,is_phys);

    return mmod;
}

int target_memmod_release(struct target *target,tid_t tid,
			  struct target_memmod *mmod) {
    struct target_thread *tthread;
    ADDR addr;

    /*
     * Default implementation: just remove it if it is the last using
     * thread.
     */
    addr = mmod->addr;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return -1;
    }

    if (array_list_remove_item(mmod->threads,tthread) != tthread) {
	vwarn("hm, tid %"PRIiTID" not on list for memmod at 0x%"PRIxADDR";"
	      " BUG?!\n",tid,addr);
	errno = ESRCH;
	return -1;
    }

    vdebug(5,LA_TARGET,LF_TARGET,
	   "released memmod 0x%"PRIxADDR" (is_phys=%d) tid %"PRIiTID"\n",
	   mmod->addr,mmod->is_phys,tid);

    /* If this is the last thread using it, be done now! */
    if (array_list_len(mmod->threads) == 0) {
	return target_memmod_free(target,tid,mmod,0);
    }
    else 
	return array_list_len(mmod->threads);
}

int target_memmod_free(struct target *target,tid_t tid,
		       struct target_memmod *mmod,int force) {
    unsigned int rc;
    int retval;
    ADDR addr;
    unsigned long (*writer)(struct target *target,ADDR paddr,
			    unsigned long length,unsigned char *buf);

    if (mmod->is_phys)
	writer = target_write_physaddr;
    else
	writer = target_write_addr;

    retval = array_list_len(mmod->threads);
    addr = mmod->addr;

    /* If this is the last thread using it, be done now! */
    if (force || array_list_len(mmod->threads) == 0) {
	if (mmod->is_phys)
	    g_hash_table_remove(target->phys_mmods,(gpointer)addr);
	else
	    g_hash_table_remove(target->mmods,(gpointer)addr);

	if (mmod->tmp)
	    free(mmod->tmp);
	if (mmod->mod)
	    free(mmod->mod);

	if (mmod->orig) {
	    rc = writer(target,addr,mmod->orig_len,mmod->orig);
	    if (rc != mmod->orig_len) {
		verror("could not restore orig memory at 0x%"PRIxADDR";"
		       " but cannot do anything!\n",addr);
		retval = -1;
	    }
	}

	vdebug(5,LA_TARGET,LF_TARGET,
	       "released memmod 0x%"PRIxADDR" (is_phys=%d) tid %"PRIiTID"\n",
	       mmod->addr,mmod->is_phys,tid);

	array_list_free(mmod->threads);
	free(mmod->orig);
	free(mmod);

	retval = 0;
    }

    return retval;
}

int target_memmod_set(struct target *target,tid_t tid,
		      struct target_memmod *mmod) {
    ADDR addr;
    struct target_thread *tthread;
    unsigned int rc;
    unsigned long (*writer)(struct target *target,ADDR paddr,
			    unsigned long length,unsigned char *buf);

    if (mmod->is_phys)
	writer = target_write_physaddr;
    else
	writer = target_write_addr;

    /*
     * Default implementation: enable it if necessary; swap mod bytes
     * into place, if state is not already SUBST.
     */
    addr = mmod->addr;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	vwarn("tid %"PRIiTID" does not exist!\n",tid);
    }

    if (mmod->owner && mmod->owner != tthread) {
	vwarn("memmod owned by tid %"PRIiTID", not tid %"PRIiTID"; ignoring!\n",
	      mmod->owner->tid,tthread->tid);
    }

    switch (mmod->state) {
    case MMS_SUBST:
	vdebug(8,LA_TARGET,LF_TARGET,
	       "(was already) memmod 0x%"PRIxADDR" (is_phys=%d)"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->is_phys,tid);
	mmod->owner = NULL;
	return 0;
    case MMS_ORIG:
	rc = writer(target,addr,mmod->mod_len,mmod->mod);
	if (rc != mmod->mod_len) {
	    verror("could not insert subst memory at 0x%"PRIxADDR"!\n",addr);
	    return -1;
	}
	mmod->state = MMS_SUBST;
	vdebug(8,LA_TARGET,LF_TARGET,
	       "(was orig) memmod 0x%"PRIxADDR" (is_phys=%d)"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->is_phys,tid);
	mmod->owner = NULL;
	return 0;
    case MMS_TMP:
	if (mmod->tmp) {
	    free(mmod->tmp);
	    mmod->tmp = NULL;
	    mmod->tmp_len = 0;
	}
	rc = writer(target,addr,mmod->mod_len,mmod->mod);
	if (rc != mmod->mod_len) {
	    verror("could not insert subst memory at 0x%"PRIxADDR"!\n",addr);
	    return -1;
	}
	mmod->state = MMS_SUBST;
	vdebug(8,LA_TARGET,LF_TARGET,
	       "(was tmp) memmod 0x%"PRIxADDR" (is_phys=%d)"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->is_phys,tid);
	mmod->owner = NULL;
	return 0;
    default:
	verror("unknown memmod state %d!\n",mmod->state);
	errno = EINVAL;
	return -1;
    }
}

int target_memmod_unset(struct target *target,tid_t tid,
		      struct target_memmod *mmod) {
    ADDR addr;
    struct target_thread *tthread;
    unsigned int rc;
    unsigned long (*writer)(struct target *target,ADDR paddr,
			    unsigned long length,unsigned char *buf);

    if (mmod->is_phys)
	writer = target_write_physaddr;
    else
	writer = target_write_addr;

    if (target->ops->disable_sw_breakpoint)
	return target->ops->disable_sw_breakpoint(target,tid,mmod);

    /*
     * Default implementation: disable it if necessary; swap orig bytes
     * into place, if state is not already ORIG.
     */
    addr = mmod->addr;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	vwarn("tid %"PRIiTID" does not exist!\n",tid);
    }

    if (mmod->owner && mmod->owner != tthread) {
	vwarn("memmod owned by tid %"PRIiTID", not tid %"PRIiTID"; ignoring!\n",
	      mmod->owner->tid,tthread->tid);
    }

    switch (mmod->state) {
    case MMS_ORIG:
	vdebug(8,LA_TARGET,LF_TARGET,
	       "(was already) memmod 0x%"PRIxADDR" (is_phys=%d)"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->is_phys,tid);
	mmod->owner = tthread;
	return 0;
    case MMS_SUBST:
	rc = writer(target,addr,mmod->orig_len,mmod->orig);
	if (rc != mmod->orig_len) {
	    verror("could not restore orig memory at 0x%"PRIxADDR"!\n",addr);
	    return -1;
	}
	mmod->state = MMS_ORIG;
	vdebug(8,LA_TARGET,LF_TARGET,
	       "(was set) memmod 0x%"PRIxADDR" (is_phys=%d)"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->is_phys,tid);
	mmod->owner = tthread;
	return 0;
    case MMS_TMP:
	if (mmod->tmp) {
	    free(mmod->tmp);
	    mmod->tmp = NULL;
	    mmod->tmp_len = 0;
	}
	rc = writer(target,addr,mmod->orig_len,mmod->orig);
	if (rc != mmod->orig_len) {
	    verror("could not restore orig memory at 0x%"PRIxADDR"!\n",addr);
	    return -1;
	}
	mmod->state = MMS_ORIG;
	mmod->owner = tthread;
	return 0;
    default:
	verror("unknown memmod state %d!\n",mmod->state);
	errno = EINVAL;
	return -1;
    }
}

int target_memmod_set_tmp(struct target *target,tid_t tid,
			  struct target_memmod *mmod,
			  unsigned char *code,unsigned long code_len) {
    ADDR addr;
    struct target_thread *tthread;
    unsigned int rc;
    unsigned char *new;
    unsigned int new_len;
    unsigned long (*writer)(struct target *target,ADDR paddr,
			    unsigned long length,unsigned char *buf);

    if (mmod->is_phys)
	writer = target_write_physaddr;
    else
	writer = target_write_addr;

    /*
     * Default implementation: swap custom bytes into tmp, no matter
     * what state is.  If the new @code_len is longer than our currently
     * saved orig_len, we need to extend the saved bytes in orig
     * correspondingly.  Also, if @code_len is *shorter* than whatever
     * has currently been substituted in, we need to write the new
     * thing, plus put the "old" bytes back in.  So, those two cases.
     */
    addr = mmod->addr;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	vwarn("tid %"PRIiTID" does not exist!\n",tid);
    }

    if (mmod->owner && mmod->owner != tthread) {
	vwarn("memmod owned by tid %"PRIiTID", not tid %"PRIiTID"; ignoring!\n",
	      mmod->owner->tid,tthread->tid);
    }

    /*
     * If we are writing more stuff into the memmod than we wrote
     * initially, save more bytes!
     */
    if (code_len > mmod->orig_len) {
	mmod->orig = realloc(mmod->orig,code_len);
	if (!target_read_addr(target,mmod->addr,code_len - mmod->orig_len,
			      mmod->orig + mmod->orig_len)) {
	    verror("could not increase original saved bytes at 0x%"PRIxADDR"!\n",
		   mmod->addr);
	    return -1;
	}
	mmod->orig_len = code_len;
    }

    switch (mmod->state) {
    case MMS_TMP:
	if (code_len < mmod->tmp_len) {
	    new = malloc(mmod->orig_len);
	    new_len = mmod->orig_len;
	    memcpy(new,mmod->orig,new_len);
	}
	else {
	    new = malloc(code_len);
	    new_len = code_len;
	    memcpy(new,code,code_len);
	}
	free(mmod->tmp);
	mmod->tmp_len = 0;
	vdebug(8,LA_TARGET,LF_TARGET,
	       "(was tmp) memmod 0x%"PRIxADDR" (is_phys=%d)"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->is_phys,tid);
	break;
    case MMS_SUBST:
	if (code_len < mmod->mod_len) {
	    new = malloc(mmod->orig_len);
	    new_len = mmod->orig_len;
	    memcpy(new,mmod->orig,new_len);
	}
	else {
	    new = malloc(code_len);
	    new_len = code_len;
	    memcpy(new,code,code_len);
	}
	vdebug(8,LA_TARGET,LF_TARGET,
	       "(was set) memmod 0x%"PRIxADDR" (is_phys=%d)"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->is_phys,tid);
	break;
    case MMS_ORIG:
	new = malloc(code_len);
	new_len = code_len;
	memcpy(new,code,code_len);
	vdebug(8,LA_TARGET,LF_TARGET,
	       "(was orig) memmod 0x%"PRIxADDR" (is_phys=%d)"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->is_phys,tid);
	break;
    default:
	verror("unknown memmod state %d!\n",mmod->state);
	errno = EINVAL;
	return -1;
    }

    rc = writer(target,addr,new_len,new);
    if (rc != new_len) {
	verror("could not write tmp memory at 0x%"PRIxADDR"!\n",addr);
	free(new);
	return -1;
    }

    mmod->tmp = new;
    mmod->tmp_len = new_len;

    mmod->state = MMS_TMP;
    mmod->owner = tthread;

    return 0;
}

struct target_location_ctxt *target_global_tlctxt(struct target *target) {
    return target->global_tlctxt;
}

struct target_location_ctxt *
target_location_ctxt_create(struct target *target,tid_t tid,
			    struct memregion *region) {
    struct target_location_ctxt *tlctxt;

    tlctxt = calloc(1,sizeof(*tlctxt));
    tlctxt->thread = target_lookup_thread(target,tid);
    if (!tlctxt->thread) {
	free(tlctxt);
	verror("could not lookup thread %"PRIiTID"!\n",tid);
	return NULL;
    }
    tlctxt->region = region;
    if (!target->location_ops)
	tlctxt->lctxt = location_ctxt_create(&target_location_ops,tlctxt);
    else
	tlctxt->lctxt = location_ctxt_create(target->location_ops,tlctxt);

    return tlctxt;
}

struct target_location_ctxt *
target_location_ctxt_create_from_bsymbol(struct target *target,tid_t tid,
					 struct bsymbol *bsymbol) {
    struct target_location_ctxt *tlctxt;

    tlctxt = calloc(1,sizeof(*tlctxt));
    tlctxt->thread = target_lookup_thread(target,tid);
    if (!tlctxt->thread) {
	free(tlctxt);
	verror("could not lookup thread %"PRIiTID"!\n",tid);
	return NULL;
    }
    tlctxt->region = bsymbol->region;
    tlctxt->lctxt = location_ctxt_create(&target_location_ops,tlctxt);

    return tlctxt;
}

void 
target_location_ctxt_retarget_bsymbol(struct target_location_ctxt *tlctxt,
				      struct bsymbol *bsymbol) {
    tlctxt->region = bsymbol->region;
}

void target_location_ctxt_free(struct target_location_ctxt *tlctxt) {
    if (tlctxt->lctxt)
	location_ctxt_free(tlctxt->lctxt);
    free(tlctxt);
}

struct target_location_ctxt *target_unwind(struct target *target,tid_t tid) {
    struct target_location_ctxt *tlctxt;
    struct target_location_ctxt_frame *tlctxtf;
    struct target_thread *tthread;
    REGVAL ipval;
    struct bsymbol *bsymbol;

    if (target->ops->unwind)
	return target->ops->unwind(target,tid);

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return NULL;
    }

    errno = 0;
    ipval = target_read_reg(target,tid,target->ipregno);
    if (errno) {
	verror("could not read IP in tid %"PRIiTID"!\n",tid);
	return NULL;
    }

    bsymbol = target_lookup_sym_addr(target,ipval);
    if (!bsymbol) {
	verror("could not find symbol for IP addr 0x%"PRIxADDR"!\n",ipval);
	errno = EADDRNOTAVAIL;
	return NULL;
    }

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
    tlctxtf->registers = g_hash_table_new(g_direct_hash,g_direct_equal);

    g_hash_table_insert(tlctxtf->registers,
			(gpointer)(uintptr_t)tlctxt->thread->target->ipregno,
			(gpointer)(uintptr_t)ipval);

    array_list_append(tlctxt->frames,tlctxtf);

    return tlctxt;
}

int target_location_ctxt_unwind(struct target_location_ctxt *tlctxt) {
    struct target *target;
    tid_t tid;
    struct target_location_ctxt_frame *tlctxtf;
    REGVAL ipval;
    struct bsymbol *bsymbol;

    if (tlctxt->frames) {
	errno = EALREADY;
	return -1;
    }
    if (!tlctxt->thread) {
	errno = EINVAL;
	return -1;
    }
    target = tlctxt->thread->target;
    tid = tlctxt->thread->tid;

    errno = 0;
    ipval = target_read_reg(target,tid,target->ipregno);
    if (errno) {
	verror("could not read IP in tid %"PRIiTID"!\n",tid);
	return -1;
    }

    bsymbol = target_lookup_sym_addr(target,ipval);
    if (!bsymbol) {
	verror("could not find symbol for IP addr 0x%"PRIxADDR"!\n",ipval);
	errno = EADDRNOTAVAIL;
	return -1;
    }

    /* Ok, we have enough info to start unwinding. */

    tlctxt->region = bsymbol->region;
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
    tlctxtf->registers = g_hash_table_new(g_direct_hash,g_direct_equal);

    g_hash_table_insert(tlctxtf->registers,
			(gpointer)(uintptr_t)tlctxt->thread->target->ipregno,
			(gpointer)(uintptr_t)ipval);

    array_list_append(tlctxt->frames,tlctxtf);

    return 0;
}

int target_unwind_snprintf(char *buf,int buflen,struct target *target,tid_t tid,
			   target_unwind_style_t fstyle,
			   char *frame_sep,char *ksep) {
    struct target_location_ctxt *tlctxt;
    struct target_location_ctxt_frame *tlctxtf;
    int i,j,k;
    int rc = 0;
    int retval;
    REG ipreg;
    REGVAL ipval;
    char *srcfile = NULL;
    int srcline;
    char *name;
    struct lsymbol *lsymbol = NULL;
    struct bsymbol *bsymbol = NULL;
    struct value *v;
    char vbuf[1024];
    GSList *args;
    GSList *gsltmp;
    struct symbol *argsym;

    if (!buf) {
	errno = EINVAL;
	return -1;
    }

    if (!frame_sep)
	frame_sep = "|";
    if (!ksep)
	ksep = ",";

    vdebug(16,LA_TARGET,LF_TARGET,"target(%s:%"PRIiTID") thread(%d)\n",
	   target->name,tid);

    tlctxt = target_unwind(target,tid);
    if (!tlctxt)
	return -1;

    if (target_cregno(target,CREG_IP,&ipreg)) {
	verror("target(%s:%"PRIiTID") has no IP reg!\n",target->name,tid);
	return -1;
    }

    j = 0;
    while (1) {
	tlctxtf = target_location_ctxt_current_frame(tlctxt);

	ipval = 0;
	target_location_ctxt_read_reg(tlctxt,ipreg,&ipval);

	if (tlctxtf->bsymbol)
	    srcfile = symbol_get_srcfile(bsymbol_get_symbol(tlctxtf->bsymbol));
	else
	    srcfile = NULL;

	if (tlctxtf->bsymbol)
	    srcline = target_lookup_line_addr(target,srcfile,ipval);
	else
	    srcline = 0;

	if (j > 0) {
	    retval = snprintf(buf + rc,buflen - rc,"%s",frame_sep);
	    if (retval < 0) {
		vwarnopt(3,LA_TARGET,LF_TARGET,
			 "snprintf(frame_sep %d): %s\n",
			 j,strerror(errno));
		goto err;
	    }
	    else
		rc += retval;
	}

	name = (tlctxtf->bsymbol) ? bsymbol_get_name(tlctxtf->bsymbol) : "";
	if (fstyle == TARGET_UNWIND_STYLE_GDB)
	    retval = snprintf(buf + rc,buflen - rc,
			      "#%d 0x%"PRIxFULLADDR" in %s (",
			      j,ipval,name);
	else if (fstyle == TARGET_UNWIND_STYLE_PROG_KEYS)
	    retval = snprintf(buf + rc,buflen - rc,
			      "frame=%d%sip=0x%"PRIxFULLADDR"%sfunction=%s%sargs=(",
			      j,ksep,ipval,ksep,name,ksep);
	else
	    retval = snprintf(buf + rc,buflen - rc,
			      "%d%s0x%"PRIxFULLADDR"%s%s%s(",
			      j,ksep,ipval,ksep,name,ksep);
	if (retval < 0) {
	    vwarnopt(3,LA_TARGET,LF_TARGET,"snprintf(frame header): %s\n",
		     strerror(errno));
	    goto err;
	}
	else
	    rc += retval;

	if (tlctxtf->bsymbol) {
	    args = symbol_get_ordered_members(bsymbol_get_symbol(tlctxtf->bsymbol),
					      SYMBOL_TYPE_FLAG_VAR_ARG);
	    i = 0;
	    v_g_slist_foreach(args,gsltmp,argsym) {
		lsymbol = lsymbol_create_from_member(bsymbol_get_lsymbol(tlctxtf->bsymbol),
						     argsym);

		if (i > 0) {
		    retval = snprintf(buf + rc,buflen - rc,"%s",ksep);
		    if (retval < 0) {
			vwarnopt(3,LA_TARGET,LF_TARGET,
				 "snprintf(ksep %d): %s\n",
				 i,strerror(errno));
			goto err;
		    }
		    else
			rc += retval;
		}

		if (lsymbol)
		    bsymbol = bsymbol_create(lsymbol,tlctxtf->bsymbol->region);
		else
		    bsymbol = NULL;
		name = symbol_get_name(argsym);
		if (!name)
		    name = "?";

		if (bsymbol)
		    v = target_load_symbol(target,tlctxt,bsymbol,
					   //LOAD_FLAG_AUTO_DEREF | 
					   LOAD_FLAG_AUTO_STRING);
		else
		    v = NULL;

		vbuf[0] = '\0';
		if (v) {
		    if (value_snprintf(v,vbuf,sizeof(vbuf)) < 0) {
			vwarnopt(5,LA_TARGET,LF_TARGET,"<value_snprintf error>");

			snprintf(vbuf,sizeof(vbuf),"0x");
			for (k = 0; k < v->bufsiz && k < (int)sizeof(vbuf); ++k) {
			    snprintf(vbuf + 2 + 2 * k,sizeof(vbuf) - 2 - 2 * k,
				     "%02hhx",v->buf[k]);
			}
		    }
		    value_free(v);
		}
		else
		    snprintf(vbuf,sizeof(vbuf),"?");

		if (fstyle == TARGET_UNWIND_STYLE_GDB
		    || fstyle == TARGET_UNWIND_STYLE_PROG_KEYS)
		    retval = snprintf(buf + rc,buflen - rc,"%s=%s",name,vbuf);
		else
		    retval = snprintf(buf + rc,buflen - rc,"%s",vbuf);
		if (retval < 0) {
		    vwarnopt(3,LA_TARGET,LF_TARGET,"snprintf(arg %d): %s\n",
			     i,strerror(errno));
		    goto err;
		}
		else
		    rc += retval;

		++i;

		if (bsymbol)
		    bsymbol_release(bsymbol);
		bsymbol = NULL;
		if (lsymbol)
		    lsymbol_release(lsymbol);
		lsymbol = NULL;
	    }
	}

	if (fstyle == TARGET_UNWIND_STYLE_GDB)
	    retval = snprintf(buf + rc, buflen - rc,
			      ") at %s:%d",srcfile,srcline);
	else if (fstyle == TARGET_UNWIND_STYLE_PROG_KEYS)
	    retval = snprintf(buf + rc, buflen - rc,
			      ")%ssrcfile=%s%ssrcline=%d",
			      ksep,srcfile,ksep,srcline);
	else
	    retval = snprintf(buf + rc, buflen - rc,
			      ")%s%s%s%d",
			      ksep,srcfile,ksep,srcline);
	if (retval < 0) {
	    vwarnopt(3,LA_TARGET,LF_TARGET,"snprintf(arg %d): %s\n",
		     j,strerror(errno));
	    goto err;
	}
	else
	    rc += retval;

	tlctxtf = target_location_ctxt_prev(tlctxt);
	if (!tlctxtf)
	    break;

	++j;
    }
    target_location_ctxt_free(tlctxt);

    return rc;

 err:
    if (bsymbol)
	bsymbol_release(bsymbol);
    if (lsymbol)
	lsymbol_release(lsymbol);

    return retval;
}

struct target_location_ctxt_frame *
target_location_ctxt_get_frame(struct target_location_ctxt *tlctxt,int frame) {
    return (struct target_location_ctxt_frame *) \
	array_list_item(tlctxt->frames,frame);
}

struct target_location_ctxt_frame *
target_location_ctxt_current_frame(struct target_location_ctxt *tlctxt) {

    if (!tlctxt->frames)
	return NULL;
    return (struct target_location_ctxt_frame *) \
	array_list_item(tlctxt->frames,tlctxt->lctxt->current_frame);
}

int target_location_ctxt_read_reg(struct target_location_ctxt *tlctxt,
				  REG reg,REGVAL *o_regval) {
    struct target_location_ctxt_frame *tlctxtf;
    REGVAL regval;
    gpointer v;

    if (tlctxt->thread->target->ops->unwind_read_reg)
	return tlctxt->thread->target->ops->unwind_read_reg(tlctxt,reg,o_regval);

    /*
     * Just use target_read_reg if this is frame 0.
     */
    if (tlctxt->lctxt->current_frame == 0) {
	errno = 0;
	regval = target_read_reg(tlctxt->thread->target,
				 tlctxt->thread->tid,reg);
	if (errno) 
	    return -1;
	if (o_regval)
	    *o_regval = regval;
	return 0;
    }

    tlctxtf = target_location_ctxt_current_frame(tlctxt);

    if (!tlctxtf->registers) {
	errno = EBADSLT;
	return -1;
    }

    /*
     * Check the cache first.
     */
    if (g_hash_table_lookup_extended(tlctxtf->registers,
				     (gpointer)(uintptr_t)reg,NULL,&v) == TRUE) {
	if (o_regval)
	    *o_regval = (REGVAL)v;
	return 0;
    }

    /*
     * Try to read it via location_ctxt_read_reg.
     */
    return location_ctxt_read_reg(tlctxtf->tlctxt->lctxt,reg,o_regval);
}

/*
 * What we want to do is read the current return address register; if it
 * doesn't exist there is no caller frame, this is it; if there is one,
 * "infer" the IP in @frame that called @frame - 1; create a new
 * location_ctxt_frame from the caller's symbol; fill the register cache
 * for @frame based on @frame - 1's CFA program (which determines its
 * return address and callee-saved registers within @frame -1's
 * activation).
 */
struct target_location_ctxt_frame *
target_location_ctxt_prev(struct target_location_ctxt *tlctxt) {
    struct target_location_ctxt_frame *tlctxtf;
    struct target_location_ctxt_frame *new;
    int rc;
    ADDR retaddr;
    struct bsymbol *bsymbol;
    REG rbp;
    REG rsp = -1;
    ADDR bp = 0,sp = 0,old_bp = 0,old_sp = 0;
    int i;
    ADDR tmp;

    if (!tlctxt->frames) {
	errno = EINVAL;
	return NULL;
    }

    if (tlctxt->thread->target->ops->unwind_prev)
	return tlctxt->thread->target->ops->unwind_prev(tlctxt);

    /* Just return it if it already exists. */
    new = (struct target_location_ctxt_frame *) \
	array_list_item(tlctxt->frames,tlctxt->lctxt->current_frame + 1);
    if (new)
	return new;

    tlctxtf = (struct target_location_ctxt_frame *) \
	array_list_item(tlctxt->frames,tlctxt->lctxt->current_frame);

    retaddr = 0;
    if (tlctxtf->bsymbol) {
	rc = location_ctxt_read_retaddr(tlctxt->lctxt,&retaddr);
	if (rc) {
	    vwarnopt(5,LA_TARGET,LF_TUNW,
		     "could not read retaddr in current_frame %d!\n",
		     tlctxt->lctxt->current_frame);
	    return NULL;
	}
    }
    else {
	vwarn("no symbol in current frame; will try to infer it!\n");

	/*
	 * Just read the frame pointer + 8 to get prev frame pointer;
	 * and frame pointer + 16 to reg retaddr.  Check it against what
	 * we have, and feel good hopefully.
	 */
	if (target_cregno(tlctxt->thread->target,CREG_BP,&rbp)) {
	    verror("target %s has no frame pointer register!\n",
		   tlctxt->thread->target->name);
	    return NULL;
	}
	errno = 0;
	rc = location_ctxt_read_reg(tlctxt->lctxt,rbp,&bp);
	if (rc) {
	    vwarn("could not read %%bp to manually unwind; halting!\n");
	    return NULL;
	}
	target_cregno(tlctxt->thread->target,CREG_SP,&rsp);
	errno = 0;
	rc = location_ctxt_read_reg(tlctxt->lctxt,rsp,&sp);

	vdebug(8,LA_TARGET,LF_TUNW,"    current stack:\n");
	for (i = 32; i >= -8; --i) {
	    target_read_addr(tlctxt->thread->target,
			     sp + i * tlctxt->thread->target->arch->wordsize,
			     tlctxt->thread->target->arch->wordsize,
			     (unsigned char *)&tmp);
	    vdebug(8,LA_TARGET,LF_TUNW,"      0x%"PRIxADDR" == %"PRIxADDR"\n",
		   sp + i * tlctxt->thread->target->arch->wordsize,tmp);
	}
	vdebug(8,LA_TARGET,LF_TUNW,"\n");

	/* Get the old bp and retaddr. */
	target_read_addr(tlctxt->thread->target,bp + 16,sizeof(ADDR),
			 (unsigned char *)&old_bp);
	target_read_addr(tlctxt->thread->target,bp + 24,sizeof(ADDR),
			 (unsigned char *)&retaddr);
	/* Adjust the stack pointer. */
	old_sp = bp + 16;

	vdebug(5,LA_TARGET,LF_TUNW,
	       "current bp 0x%"PRIxADDR",sp=0x%"PRIxADDR
	       " => retaddr 0x%"PRIxADDR
	       ",old_bp 0x%"PRIxADDR",old_sp 0x%"PRIxADDR"\n",
	       bp,sp,retaddr,old_bp,old_sp);
    }

    vdebug(8,LA_TARGET,LF_TUNW,
	   "retaddr of current frame %d is 0x%"PRIxADDR"\n",
	   tlctxt->lctxt->current_frame,retaddr);

    /*
     * Look up the new symbol.
     */
    bsymbol = target_lookup_sym_addr(tlctxt->thread->target,retaddr);
    if (!bsymbol) 
	vwarn("could not find symbol for IP addr 0x%"PRIxADDR"!\n",retaddr);

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
    new->registers = g_hash_table_new(g_direct_hash,g_direct_equal);

    g_hash_table_insert(new->registers,
			(gpointer)(uintptr_t)tlctxt->thread->target->ipregno,
			(gpointer)(uintptr_t)retaddr);

    if (!tlctxtf->bsymbol) {
	g_hash_table_insert(new->registers,
			    (gpointer)(uintptr_t)rbp,
			    (gpointer)(uintptr_t)old_bp);
	g_hash_table_insert(new->registers,
			    (gpointer)(uintptr_t)rsp,
			    (gpointer)(uintptr_t)old_sp);
    }

    array_list_append(tlctxt->frames,new);

    if (bsymbol)
	tlctxt->region = bsymbol->region;
    else {
	; /* Don't change it! */
    }

    ++tlctxt->lctxt->current_frame;

    vdebug(8,LA_TARGET,LF_TUNW,
	   "created new previous frame %d with IP 0x%"PRIxADDR"\n",
	   tlctxt->lctxt->current_frame,retaddr);

    return new;
}

/**
 ** Personality stuff.
 **/
int target_personality_load(char *filename) {
    unsigned int current_size;
    void *lib;

    current_size = g_hash_table_size(target_personality_tab);

    /*
     * NB: we want subsequent libraries to be able to reuse symbols from
     * this library if necessary... "overloading".
     */
    lib = dlopen(filename,RTLD_NOW | RTLD_GLOBAL);
    if (!lib) {
	verror("could not load '%s': %s (%s)\n",
	       filename,dlerror(),strerror(errno));
	return -1;
    }

    /* Don't make this fatal, for now... */
    if (g_hash_table_size(target_personality_tab) == current_size) {
	vwarn("loaded library %s, but it did not add itself to the"
	      " personality table!  Duplicate personality ID?\n",filename);
    }

    return 0;
}

int target_personality_register(char *personality,target_personality_t pt,
				struct target_personality_ops *ptops,void *pops) {
    struct target_personality_info *tpi = NULL;

    if (g_hash_table_lookup(target_personality_tab,(gpointer)personality)) {
	verror("Personality %s already registered; cannot register.\n",
	       personality);
	errno = EALREADY;
	return -1;
    }

    tpi = calloc(1,sizeof(*tpi));
    tpi->personality = strdup(personality);
    tpi->ptype = pt;
    tpi->ptops = ptops;
    tpi->pops = pops;
    
    g_hash_table_insert(target_personality_tab,(gpointer)tpi->personality,
			(gpointer)tpi);
    return 0;
}

int target_personality_attach(struct target *target,
			      char *personality,char *personality_lib) {
    struct target_personality_info *tpi;
    char *buf;
    int bufsiz;

    if (!target_personality_tab) {
	verror("Target library improperly initialized -- call target_init!\n");
	errno = EINVAL;
	return -1;
    }

    /*
     * If this is specified, try to load it first!
     */
    if (personality_lib) {
	if (target_personality_load(personality_lib)) {
	    vwarn("failed to load library '%s'; will try to find"
		  " personality '%s' elsewhere!\n",personality_lib,personality);
	}
    }

    tpi = (struct target_personality_info *) \
	g_hash_table_lookup(target_personality_tab,(gpointer)personality);
    if (tpi)
	goto tpinit;
    else if (personality_lib) {
	vwarn("could not find personality '%s' after trying to load"
	      " personality library '%s'\n",personality,personality_lib);
    }

    /*
     * Try to load it from a shared lib.  The shared lib must either
     * provide _init() (or better yet, a routine with
     * __attribute__((constructor)) ); and this routine must register
     * the personality library with the target library.
     *
     * Try several strings.  Just <personality>.so;
     * stackdb_<personality>.so; vmi_<personality>.so .
     */
    bufsiz = strlen(personality) + strlen(".so") + strlen("stackdb") + 1;
    buf = malloc(bufsiz);
    snprintf(buf,bufsiz,"%s.so",personality);
    if (target_personality_load(buf) == 0) {
	if ((tpi = (struct target_personality_info *) \
	     g_hash_table_lookup(target_personality_tab,(gpointer)personality))) {
	    free(buf);
	    goto tpinit;
	}
	else {
	    vwarn("loaded library '%s', but it did not provide personality '%s'!\n",
		  buf,personality);
	}
    }

    snprintf(buf,bufsiz,"stackdb_%s.so",personality);
    if (target_personality_load(buf) == 0) {
	if ((tpi = (struct target_personality_info *) \
	     g_hash_table_lookup(target_personality_tab,(gpointer)personality))) {
	    free(buf);
	    goto tpinit;
	}
	else {
	    vwarn("loaded library '%s', but it did not provide personality '%s'!\n",
		  buf,personality);
	}
    }

    snprintf(buf,bufsiz,"vmi_%s.so",personality);
    if (target_personality_load(buf) == 0) {
	if ((tpi = (struct target_personality_info *) \
	     g_hash_table_lookup(target_personality_tab,(gpointer)personality))) {
	    free(buf);
	    goto tpinit;
	}
	else {
	    vwarn("loaded library '%s', but it did not provide personality '%s'!\n",
		  buf,personality);
	}
    }

    free(buf);
    verror("could not find personality '%s'!\n",personality);
    errno = ESRCH;
    return -1;

 tpinit:
    if (tpi->ptops->attach(target)) {
	vwarn("Failed to attach personality '%s' on target %d!\n",
	      personality,target->id);
	return -1;
    }
    else {
	target->personality_ops = tpi->ptops;
	target->__personality_specific_ops = tpi->pops;

	vdebug(2,LA_TARGET,LF_TARGET,
	       "initialized personality '%s' for target %d!\n",
	       personality,target->id);

	return 0;
    }
}

int target_personality_init(struct target *target) {
    if (target->personality_ops && target->personality_ops->init)
	return target->personality_ops->init(target);
    else
	return 0;
}

/**
 ** Register helpers, for the cases where the target is using our
 ** regcache support.
 **/

#define TARGET_REGCACHE_ALLOC(tctxt,errretval)				\
    do {								\
        if (tctxt > target->max_thread_ctxt) {				\
	    verror("target %d only has max thread ctxt %d (%d specified)!\n", \
		   target->id,target->max_thread_ctxt,tctxt);		\
	    errno = EINVAL;						\
	    return errretval;						\
	}								\
        tthread = target_load_thread(target,tid,0);			\
	if (!tthread) {							\
	    verror("target %d could not load thread %d!\n",target->id,tid);	\
	    errno = ESRCH;						\
	    return (errretval);						\
	}								\
	if (!tthread->regcaches[tctxt]) {				\
	    tthread->regcaches[tctxt] = regcache_create(target->arch);	\
	}								\
	regcache = tthread->regcaches[tctxt];				\
    } while(0)

#define TARGET_REGCACHE_ALLOC_NT(tctxt,errretval)			\
    do {								\
        if (tctxt > target->max_thread_ctxt) {				\
	    verror("target %d only has max thread ctxt %d (%d specified)!\n", \
		   target->id,target->max_thread_ctxt,tctxt);		\
	    errno = EINVAL;						\
	    return errretval;						\
	}								\
	if (!tthread->regcaches[tctxt]) {				\
	    tthread->regcaches[tctxt] = regcache_create(target->arch);	\
	}								\
	regcache = tthread->regcaches[tctxt];				\
    } while(0)

#define TARGET_REGCACHE_GET(tctxt,errretval)				\
    do {								\
        if (tctxt > target->max_thread_ctxt) {				\
	    verror("target %d only has max thread ctxt %d (%d specified)!\n", \
		   target->id,target->max_thread_ctxt,tctxt);		\
	    errno = EINVAL;						\
	    return errretval;						\
	}								\
        tthread = target_load_thread(target,tid,0);			\
	if (!tthread) {							\
	    verror("target %d could not load thread %d!\n",target->id,tid);	\
	    errno = ESRCH;						\
	    return (errretval);						\
	}								\
	if (!tthread->regcaches[tctxt]) {				\
	    verror("target %d could not load thread %d!\n",target->id,tid); \
	    errno = EADDRNOTAVAIL;					\
	    return (errretval);						\
	}								\
	regcache = tthread->regcaches[tctxt];				\
    } while(0)

int target_regcache_init_reg_tidctxt(struct target *target,
				     struct target_thread *tthread,
				     thread_ctxt_t tctxt,
				     REG reg,REGVAL regval) {
    struct regcache *regcache;

    vdebug(16,LA_TARGET,LF_TARGET,
	   "target %d init reg %s in thid %d ctxt %d 0x%"PRIxREGVAL"\n",
	   target->id,target_regname(target,reg),tthread->tid,tctxt,regval);

    TARGET_REGCACHE_ALLOC_NT(tctxt,-1);

    if (regcache_init_reg(regcache,reg,regval)) {
	verror("target %d thread %d reg %d: could not init reg!\n",
	       target->id,tthread->tid,reg);
	return -1;
    }

    return 0;
}

int target_regcache_init_done(struct target *target,
			      tid_t tid,thread_ctxt_t tctxt) {
    struct target_thread *tthread;
    struct regcache *regcache;

    TARGET_REGCACHE_ALLOC(tctxt,-1);

    if (regcache_init_done(regcache)) {
	vwarn("failed -- target %d thid %d tctxt %d\n",target->id,tid,tctxt);
	return -1;
    }
    else {
	vdebug(16,LA_TARGET,LF_TARGET,
	       "target %d thid %d tctxt %d\n",target->id,tid,tctxt);
	return 0;
    }
}

int target_regcache_foreach_dirty(struct target *target,
				  struct target_thread *tthread,
				  thread_ctxt_t tctxt,
				  target_regcache_regval_handler_t regh,
				  target_regcache_rawval_handler_t rawh,
				  void *priv) {
    int i;
    struct regcache *regcache;

    if (tctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (%d specified)!\n",
	       target->id,target->max_thread_ctxt,tctxt);
	errno = EINVAL;
	return 0;
    }

    if (!(regcache = tthread->regcaches[tctxt]))
	return 0;

    /*
     * XXX: too bad, but to make this efficient, this function has to
     * have direct knowledge of the regcache struct.  Otherwise we'd
     * have two layers of callbacks, or some other inefficiency... so
     * just do this for now.
     */
    for (i = 0; i < regcache->arch->regcount; ++i) {
	if (!(regcache->flags[i] & REGCACHE_VALID)
	    || !(regcache->flags[i] & REGCACHE_DIRTY))
	    continue;

	if (regcache->flags[i] & REGCACHE_ALLOC)
	    rawh(target,tthread,tctxt,i,(void *)regcache->values[i],
		 arch_regsize(regcache->arch,i),priv);
	else
	    regh(target,tthread,tctxt,i,regcache->values[i],priv);
    }

    return 0;
}

REGVAL target_regcache_readreg(struct target *target,tid_t tid,REG reg) {
    struct target_thread *tthread;
    struct regcache *regcache;
    REGVAL regval = 0;

    tthread = target_load_thread(target,tid,0);
    if (!tthread) {
	verror("target %d could not load thread %d!\n",target->id,tid);
	errno = ESRCH;
	return 0;
    }

    if (tthread->tidctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (thid %d currently %d)!\n",
	       target->id,target->max_thread_ctxt,tid,tthread->tidctxt);
	errno = EINVAL;
	return 0;
    }

    vdebug(16,LA_TARGET,LF_TARGET,
	   "target %d reading reg %s in thid %d ctxt %d\n",
	   target->id,target_regname(target,reg),tid,tthread->tidctxt);

    if (!tthread->regcaches[tthread->tidctxt]) {
	vwarnopt(9,LA_TARGET,LF_TARGET,
		 "target %d could not load thread %d!\n",target->id,tid);
	errno = EADDRNOTAVAIL;
	return 0;
    }
    regcache = tthread->regcaches[tthread->tidctxt];

    if (regcache_read_reg(regcache,reg,&regval)) {
	vwarnopt(9,LA_TARGET,LF_TARGET,
		 "target %d thread %d reg %d: could not read!\n",
		 target->id,tid,reg);
	return 0;
    }

    return regval;
}

int target_regcache_writereg(struct target *target,tid_t tid,
			     REG reg,REGVAL value) {
    struct target_thread *tthread;
    struct regcache *regcache;

    tthread = target_load_thread(target,tid,0);
    if (!tthread) {
	verror("target %d could not load thread %d!\n",target->id,tid);
	errno = ESRCH;
	return 0;
    }

    if (tthread->tidctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (thid %d currently %d)!\n",
	       target->id,target->max_thread_ctxt,tid,tthread->tidctxt);
	errno = EINVAL;
	return 0;
    }

    vdebug(16,LA_TARGET,LF_TARGET,
	   "target %d reading reg %s in thid %d ctxt %d 0x%"PRIxREGVAL"\n",
	   target->id,target_regname(target,reg),tid,tthread->tidctxt,value);

    if (!tthread->regcaches[tthread->tidctxt]) {
	verror("target %d could not load thread %d!\n",target->id,tid);
	errno = EADDRNOTAVAIL;
	return 0;
    }
    regcache = tthread->regcaches[tthread->tidctxt];

    if (regcache_write_reg(regcache,reg,value)) {
	verror("target %d thread %d reg %d: could not write!\n",
	       target->id,tid,reg);
	return -1;
    }

    tthread->dirty = 1;

    return 0;
}

int target_regcache_readreg_ifdirty(struct target *target,
				    struct target_thread *tthread,
				    thread_ctxt_t tctxt,REG reg,REGVAL *regval) {
    if (tctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (%d specified)!\n",
	       target->id,target->max_thread_ctxt,tctxt);
	errno = EINVAL;
	return 0;
    }

    if (!tthread->regcaches[tctxt])
	return 0;
    else
	return regcache_read_reg_ifdirty(tthread->regcaches[tctxt],reg,regval);
}

int target_regcache_isdirty_reg(struct target *target,
				struct target_thread *tthread,
				thread_ctxt_t tctxt,REG reg) {
    if (tctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (%d specified)!\n",
	       target->id,target->max_thread_ctxt,tctxt);
	errno = EINVAL;
	return 0;
    }

    if (!tthread->regcaches[tctxt])
	return 0;
    else
	return regcache_isdirty_reg(tthread->regcaches[tctxt],reg);
}

int target_regcache_isdirty_reg_range(struct target *target,
				      struct target_thread *tthread,
				      thread_ctxt_t tctxt,REG start,REG end) {
    if (tctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (%d specified)!\n",
	       target->id,target->max_thread_ctxt,tctxt);
	errno = EINVAL;
	return 0;
    }

    if (!tthread->regcaches[tctxt])
	return 0;
    else
	return regcache_isdirty_reg_range(tthread->regcaches[tctxt],start,end);
}

struct regcache *target_regcache_get(struct target *target,
				     struct target_thread *tthread,
				     thread_ctxt_t tctxt) {
    if (tctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (%d specified)!\n",
	       target->id,target->max_thread_ctxt,tctxt);
	errno = EINVAL;
	return 0;
    }

    return tthread->regcaches[tctxt];
}

int target_regcache_snprintf(struct target *target,struct target_thread *tthread,
			     thread_ctxt_t tctxt,char *buf,int bufsiz,
			     int detail,char *sep,char *kvsep,int flags) {
    int rc;
    int nrc;

    if (tctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (%d specified)!\n",
	       target->id,target->max_thread_ctxt,tctxt);
	errno = EINVAL;
	return 0;
    }

    if (!tthread->regcaches[tctxt])
	return 0;
    else {
	rc = snprintf(buf,bufsiz,"%stctxt%s%d",sep,kvsep,tctxt);
	if (rc < 0)
	    return rc;
	nrc = regcache_snprintf(tthread->regcaches[tctxt],
				(rc >= bufsiz) ? NULL : buf + rc,
				(rc >= bufsiz) ? 0 : bufsiz - rc,
				detail,sep,kvsep,flags);
	if (nrc < 0)
	    return nrc;
	else
	    return rc + nrc;
    }
}

int target_regcache_zero(struct target *target,struct target_thread *tthread,
			 thread_ctxt_t tctxt) {
    if (tctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (%d specified)!\n",
	       target->id,target->max_thread_ctxt,tctxt);
	errno = EINVAL;
	return 0;
    }

    if (!tthread->regcaches[tctxt])
	return 0;
    else {
	regcache_zero(tthread->regcaches[tctxt]);
	return 0;
    }
}

int target_regcache_mark_flushed(struct target *target,
				 struct target_thread *tthread,
				 thread_ctxt_t tctxt) {
    if (tctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (%d specified)!\n",
	       target->id,target->max_thread_ctxt,tctxt);
	errno = EINVAL;
	return 0;
    }

    if (!tthread->regcaches[tctxt])
	return 0;

    regcache_mark_flushed(tthread->regcaches[tctxt]);

    return 0;
}

int target_regcache_invalidate(struct target *target,
			       struct target_thread *tthread,
			       thread_ctxt_t tctxt) {
    if (tctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (%d specified)!\n",
	       target->id,target->max_thread_ctxt,tctxt);
	errno = EINVAL;
	return 0;
    }

    if (!tthread->regcaches[tctxt])
	return 0;

    regcache_invalidate(tthread->regcaches[tctxt]);

    return 0;
}

int target_regcache_copy_all(struct target_thread *sthread,
			     thread_ctxt_t stidctxt,
			     struct target_thread *dthread,
			     thread_ctxt_t dtidctxt) {
    struct target *target = sthread->target;

    if (stidctxt > target->max_thread_ctxt
	|| dtidctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (%d/%d specified)!\n",
	       target->id,target->max_thread_ctxt,stidctxt,dtidctxt);
	errno = EINVAL;
	return 0;
    }

    vdebug(16,LA_TARGET,LF_TARGET,
	   "copying thid %d ctxt %d to thid %d ctxt %d\n",
	   sthread->tid,stidctxt,dthread->tid,dtidctxt);

    if (!sthread->regcaches[stidctxt])
	return 0;

    if (!dthread->regcaches[dtidctxt])
	dthread->regcaches[dtidctxt] = regcache_create(dthread->target->arch);

    return regcache_copy_all(sthread->regcaches[stidctxt],
			     dthread->regcaches[dtidctxt]);
}

int target_regcache_copy_all_zero(struct target_thread *sthread,
				  thread_ctxt_t stidctxt,
				  struct target_thread *dthread,
				  thread_ctxt_t dtidctxt) {
    struct target *target = sthread->target;

    if (stidctxt > target->max_thread_ctxt
	|| dtidctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (%d/%d specified)!\n",
	       target->id,target->max_thread_ctxt,stidctxt,dtidctxt);
	errno = EINVAL;
	return 0;
    }

    if (dthread->regcaches[dtidctxt])
	regcache_zero(dthread->regcaches[dtidctxt]);

    return target_regcache_copy_all(sthread,stidctxt,dthread,dtidctxt);
}

int target_regcache_copy_from(struct target_thread *dthread,
			      thread_ctxt_t dtidctxt,
			      struct regcache *sregcache) {
    struct target *target = dthread->target;

    if (dtidctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (%d specified)!\n",
	       target->id,target->max_thread_ctxt,dtidctxt);
	errno = EINVAL;
	return 0;
    }

    vdebug(16,LA_TARGET,LF_TARGET,
	   "copying regcache to thid %d ctxt %d\n",
	   dthread->tid,dtidctxt);

    if (!dthread->regcaches[dtidctxt])
	dthread->regcaches[dtidctxt] = regcache_create(dthread->target->arch);

    return regcache_copy_all(sregcache,dthread->regcaches[dtidctxt]);
}

int target_regcache_copy_dirty_to(struct target_thread *sthread,
				  thread_ctxt_t stidctxt,
				  struct regcache *dregcache) {
    struct target *target = sthread->target;

    if (stidctxt > target->max_thread_ctxt) {
	verror("target %d only has max thread ctxt %d (%d specified)!\n",
	       target->id,target->max_thread_ctxt,stidctxt);
	errno = EINVAL;
	return 0;
    }

    vdebug(16,LA_TARGET,LF_TARGET,
	   "copying regcache to thid %d ctxt %d\n",
	   sthread->tid,stidctxt);

    if (!sthread->regcaches[stidctxt])
	sthread->regcaches[stidctxt] = regcache_create(sthread->target->arch);

    return regcache_copy_dirty(sthread->regcaches[stidctxt],dregcache);
}

GHashTable *target_regcache_copy_registers(struct target *target,tid_t tid) {
    return target_regcache_copy_registers_tidctxt(target,tid,
						  THREAD_CTXT_DEFAULT);
}

GHashTable *target_regcache_copy_registers_tidctxt(struct target *target,
						   tid_t tid,
						   thread_ctxt_t tidctxt) {
    struct target_thread *tthread;
    struct regcache *regcache;

    vdebug(16,LA_TARGET,LF_TARGET,
	   "target %d copying in thid %d ctxt %d\n",
	   target->id,tid,tidctxt);

    TARGET_REGCACHE_GET(tidctxt,0);

    if (!regcache)
	return NULL;

    return regcache_copy_registers(regcache);
}

REGVAL target_regcache_readreg_tidctxt(struct target *target,
				       tid_t tid,thread_ctxt_t tidctxt,
				       REG reg) {
    struct target_thread *tthread;
    struct regcache *regcache;
    REGVAL regval = 0;

    vdebug(16,LA_TARGET,LF_TARGET,
	   "target %d reading reg %s in thid %d ctxt %d\n",
	   target->id,target_regname(target,reg),tid,tidctxt);

    TARGET_REGCACHE_GET(tidctxt,0);

    if (regcache_read_reg(regcache,reg,&regval)) {
	verror("target %d thread %d reg %d ctxt %d: could not read!\n",
	       target->id,tid,reg,tidctxt);
	return 0;
    }

    return regval;
}

int target_regcache_writereg_tidctxt(struct target *target,
				     tid_t tid,thread_ctxt_t tidctxt,
				     REG reg,REGVAL value) {
    struct target_thread *tthread;
    struct regcache *regcache;

    vdebug(16,LA_TARGET,LF_TARGET,
	   "target %d writing reg %s in thid %d ctxt %d 0x%"PRIxREGVAL"\n",
	   target->id,target_regname(target,reg),tid,tidctxt,value);

    TARGET_REGCACHE_GET(tidctxt,0);

    if (regcache_write_reg(regcache,reg,value)) {
	verror("target %d thread %d reg %d ctxt %d: could not write!\n",
	       target->id,tid,reg,tidctxt);
	return -1;
    }

    tthread->dirty = 1;

    return 0;
}

/**
 ** Personality target ops wrappers.  Not called by users; only by
 ** backends if they want to support personalities!
 **/

struct target_thread *target_personality_load_current_thread(struct target *target,
							     int force) {
    if (!target->personality_ops || !target->personality_ops->load_current_thread)
	return NULL;
    return target->personality_ops->load_current_thread(target,force);
}

struct target_thread *target_personality_load_thread(struct target *target,
						     tid_t tid,int force) {
    if (!target->personality_ops || !target->personality_ops->load_thread)
	return NULL;
    return target->personality_ops->load_thread(target,tid,force);
}

int target_personality_flush_current_thread(struct target *target) {
    if (!target->personality_ops 
	|| !target->personality_ops->flush_current_thread)
	return 0;
    return target->personality_ops->flush_current_thread(target);
}

int target_personality_flush_thread(struct target *target,tid_t tid) {
    if (!target->personality_ops 
	|| !target->personality_ops->flush_thread)
	return 0;
    return target->personality_ops->flush_thread(target,tid);
}

struct array_list *target_personality_list_available_tids(struct target *target) {
    if (!target->personality_ops 
	|| !target->personality_ops->list_available_tids)
	return 0;
    return target->personality_ops->list_available_tids(target);
}

int target_personality_load_available_threads(struct target *target,int force) {
    if (!target->personality_ops 
	|| !target->personality_ops->load_available_threads)
	return 0;
    return target->personality_ops->load_available_threads(target,force);
}

int target_personality_invalidate_thread(struct target *target,
					 struct target_thread *tthread) {
    if (!target->personality_ops 
	|| !target->personality_ops->invalidate_thread)
	return 0;
    return target->personality_ops->invalidate_thread(target,tthread);
}

int target_personality_thread_snprintf(struct target_thread *tthread,
				       char *buf,int bufsiz,
				       int detail,char *sep,char *key_val_sep) {
    if (!tthread->target->personality_ops 
	|| !tthread->target->personality_ops->thread_snprintf)
	return 0;
    return tthread->target->personality_ops->thread_snprintf(tthread,buf,bufsiz,
							     detail,sep,
							     key_val_sep);
}

int target_personality_postloadinit(struct target *target) {
    if (!target->personality_ops || !target->personality_ops->postloadinit)
	return 0;
    return target->personality_ops->postloadinit(target);
}

int target_personality_postopened(struct target *target) {
    if (!target->personality_ops || !target->personality_ops->postopened)
	return 0;
    return target->personality_ops->postopened(target);
}

int target_personality_handle_exception(struct target *target) {
    if (!target->personality_ops || !target->personality_ops->handle_exception)
	return 0;
    return target->personality_ops->handle_exception(target);
}

int target_personality_set_active_probing(struct target *target,
					  active_probe_flags_t flags) {
    if (!target->personality_ops || !target->personality_ops->set_active_probing)
	return 0;
    return target->personality_ops->set_active_probing(target,flags);
}

/*
 * Util stuff.
 */
char *TSTATUS_STRINGS[] = {
    "UNKNOWN",
    "RUNNING",
    "PAUSED",
    "ERROR",
    "DONE",
    "EXITING",
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
    "DEAD",
    "STOPPED",
};

char *THREAD_STATUS_STRINGS[] = {
    "UNKNOWN",
    "RUNNING",
    "PAUSED",
    "ERROR",
    "DONE",
    "EXITING",
    NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
    "DEAD",
    "STOPPED",

    "SLEEPING",
    "ZOMBIE",
    "BLOCKEDIO",
    "PAGING",
    "RETURNING_USER",
    "RETURNING_KERNEL",
};

char *POLL_STRINGS[] = {
    "NOTHING",
    "ERROR",
    "SUCCESS",
    "UNKNOWN",
};

char *REGION_TYPE_STRINGS[] = {
    "unknown","heap","stack","vdso","vsyscall","anon","main","lib",
};
