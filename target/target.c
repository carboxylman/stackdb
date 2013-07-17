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

#include "dwdebug.h"
#include "dwdebug_priv.h"
#include "target_api.h"
#include "target.h"
#include "probe.h"

#include "target_linux_userproc.h"
#ifdef ENABLE_XENSUPPORT
#include "target_xen_vm.h"
#include "target_xen_vm_process.h"
#endif

#include <glib.h>

/**
 ** Globals.
 **/

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

void target_init(void) {
    if (init_done)
	return;

    dwdebug_init();

    init_done = 1;
}

void target_fini(void) {
    if (!init_done)
	return;

    dwdebug_fini();

    init_done = 0;
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

struct argp_option target_argp_opts[] = {
    { "debug",'d',"LEVEL",0,"Set/increase the debugging level.",-3 },
    { "log-flags",'l',"FLAG,FLAG,...",0,"Set the debugging flags",-3 },
    { "warn",'w',"LEVEL",0,"Set/increase the warning level.",-3 },
    { "target-type",'t',"TYPENAME",0,
      "Forcibly set the target type (ptrace"
#ifdef ENABLE_XENSUPPORT
      ",xen,xen-process"
#endif
      ").",-3 },
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
#endif
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
    if (spec->debugfile_root_prefix)
	ac += 2;
    if (spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY
	|| spec->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT
	|| spec->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY 
	|| spec->active_probe_flags & ACTIVE_PROBE_FLAG_OTHER)
	ac += 2;

    ac += backend_argc;
    ac += 1;
    av = calloc(ac,sizeof(char *));

    j = 0;

    /*
     * Handle arg0.
     */
    if (arg0) {
	av[j++] = strdup(arg0);
    }

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
	}

	break;
    case 'd':
	if (arg) {
	    vmi_inc_log_level();
	    while (*arg == 'd') {
		vmi_inc_log_level();
		arg = &arg[1];
	    }
	}
	else
	    vmi_inc_log_level();
	break;
    case 'w':
	if (arg)
	    vmi_set_warn_level(atoi(arg));
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

    vdebug(5,LA_TARGET,LF_TARGET,"freeing target(%s)\n",target->name);

    vdebug(5,LA_TARGET,LF_TARGET,"fini target(%s)\n",target->name);
    if ((rc = target->ops->fini(target))) {
	verror("fini target(%s) failed; not finishing free!\n",target->name);
	return;
    }

    if (array_list_len(target->state_changes)) {
	vwarnopt(4,LA_TARGET,LF_TARGET,
		 "removing %d state change events; backend BUG?\n",
		 array_list_len(target->state_changes));
	target_clear_state_changes(target);
    }
    array_list_free(target->state_changes);

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

    /* Do it for all the overlays first. */
    g_hash_table_iter_init(&iter,target->overlays);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&overlay)) {
	tmpname = strdup(target->name);
	vdebug(5,LA_TARGET,LF_TARGET,
	       "freeing overlay target(%s)\n",tmpname);
	target_free(overlay);
	vdebug(5,LA_TARGET,LF_TARGET,
	       "freed overlay target(%s)\n",tmpname);
	free(tmpname);
    }
    g_hash_table_destroy(target->overlays);

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

    /* Target should not mess with these after close! */
    target->global_thread = NULL;

    g_hash_table_destroy(target->threads);

    g_hash_table_destroy(target->mmaps);

    /* Unload the debugfiles we might hold, if we can */
    list_for_each_entry_safe(space,tmp,&target->spaces,space) {
	RPUT(space,addrspace,target,trefcnt);
    }

    g_hash_table_destroy(target->config);
    target->config = NULL;

    /* Unload the binfile */
    if (target->binfile) {
	RPUT(target->binfile,binfile,target,trefcnt);
	target->binfile = NULL;
    }

    if (target->breakpoint_instrs)
	free(target->breakpoint_instrs);

    if (target->ret_instrs)
	free(target->ret_instrs);

    if (target->full_ret_instrs)
	free(target->full_ret_instrs);

    if (target->name)
	free(target->name);

    free(target);
}

void ghash_mmap_entry_free(gpointer data) {
    struct mmap_entry *mme = (struct mmap_entry *)data;

    free(mme);
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
    else
	retval->id = spec->target_id;

    retval->state_changes = array_list_create(0);

    retval->ops = ops;
    retval->spec = spec;

    retval->infd = retval->outfd = retval->errfd = -1;

    retval->config = g_hash_table_new_full(g_str_hash,g_str_equal,free,free);

    INIT_LIST_HEAD(&retval->spaces);

    retval->mmaps = g_hash_table_new_full(g_direct_hash,g_direct_equal,
					  /* No names to free! */
					  NULL,ghash_mmap_entry_free);

    retval->code_ranges = clrange_create();

    retval->overlays = g_hash_table_new_full(g_direct_hash,g_direct_equal,
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

    /*
     * Hm, I think we should do this by default, and let target backends
     * override it if they need.
     */
    retval->bp_handler = probepoint_bp_handler;
    retval->ss_handler = probepoint_ss_handler;

    return retval;
}

struct mmap_entry *target_lookup_mmap_entry(struct target *target,
					    ADDR base_addr) {
    /* XXX: fill later. */
    return NULL;
}

void target_attach_mmap_entry(struct target *target,
			      struct mmap_entry *mme) {
    /* XXX: fill later. */
    return;
}

void target_release_mmap_entry(struct target *target,
			       struct mmap_entry *mme) {
    /* XXX: fill later. */
    return;
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

struct symtab *target_lookup_pc(struct target *target,uint64_t pc) {
    struct addrspace *space;
    struct memregion *region;
    struct symtab *symtab;
    GHashTableIter iter, iter2;
    gpointer key, value;

    if (list_empty(&target->spaces))
	return NULL;

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    if (memregion_contains_real(region,pc))
		goto found;
	}
    }

    return NULL;

 found:
    g_hash_table_iter_init(&iter,region->debugfiles);
    while (g_hash_table_iter_next(&iter,
				  (gpointer)&key,(gpointer)&value)) {
	g_hash_table_iter_init(&iter2,((struct debugfile *)value)->srcfiles);
	while (g_hash_table_iter_next(&iter2,
				      (gpointer)&key,(gpointer)&symtab)) {
	    symtab = symtab_lookup_pc(symtab,pc);
	    if (symtab)
		return symtab;
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

    if (list_empty(&target->spaces))
	return NULL;

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    g_hash_table_iter_init(&iter,region->debugfiles);
	    while (g_hash_table_iter_next(&iter,(gpointer)&key,
					  (gpointer)&debugfile)) {
		lsymbol = debugfile_lookup_sym__int(debugfile,name,
						    delim,NULL,ftype);
		if (lsymbol) 
		    goto out;
	    }
	}
    }
    return NULL;

 out:
    bsymbol = bsymbol_create(lsymbol,region);
    /* Take a ref to bsymbol on the user's behalf, since this is
     * a lookup function.
     */
    RHOLD(bsymbol,bsymbol);

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

    if (list_empty(&target->spaces))
	return NULL;

    list_for_each_entry(space,&target->spaces,space) {
	list_for_each_entry(region,&space->regions,region) {
	    g_hash_table_iter_init(&iter,region->debugfiles);
	    while (g_hash_table_iter_next(&iter,(gpointer)&key,
					  (gpointer)&debugfile)) {
		lsymbol = debugfile_lookup_sym_line__int(debugfile,filename,line,
							 offset,addr);
		if (lsymbol) 
		    goto out;
	    }
	}
    }
    return NULL;

 out:
    bsymbol = bsymbol_create(lsymbol,region);
    /* Take a ref to bsymbol on the user's behalf, since this is
     * a lookup function.
     */
    RHOLD(bsymbol,bsymbol);

    return bsymbol;
}

/*
 * This function traverses a bsymbol chain and returns the address of
 * the final symbol in the chain.  If the final symbol is a function, we
 * return its base address.  Otherwise, for intermediate variables on
 * the chain, if their types are pointers, we load the pointer, and keep
 * loading the chain according to the next type.  If the last var is a
 * pointer, and the AUTO_DEREF flag is set (or if the AUTO_STRING flag
 * is set, and the next type is a char type), we deref the pointer(s)
 * and return the value of the last pointer.  If it is not a pointer, we
 * return the computed address of the last var.  We return the type of
 * the value at the address we return in @final_type_saveptr so that the
 * caller doesn't have to track whether the final pointer was autoloaded
 * or not.
 *
 * @return 1 if the location is an address; 2 if the location is a
 * register; or nonzero on error.
 *
 * If an address and @addr_saveptr is set, the address is placed in
 * @addr_saveptr.  If in a register and @reg_saveptr is set, the
 * register number is placed in @reg_saveptr.
 */
int __target_lsymbol_compute_location(struct target *target,tid_t tid,
				      struct lsymbol *lsymbol,
				      ADDR addr,struct memregion *region,
				      load_flags_t flags,
				      REG *reg_saveptr,ADDR *addr_saveptr,
				      struct symbol **final_type_saveptr,
				      struct memrange **range_saveptr) {
    ADDR retval = addr;
    struct symbol *symbol;
    struct symbol *datatype;
    struct array_list *symbol_chain;
    int alen;
    int i;
    int rc;
    OFFSET offset;
    struct memregion *current_region = region;
    struct memrange *current_range = NULL;
    load_flags_t tflags = flags | LOAD_FLAG_AUTO_DEREF;
    struct array_list *tchain = NULL;
    struct symbol *tdatatype;
    REG reg;
    int in_reg = 0;

    symbol_chain = lsymbol->chain;
    alen = array_list_len(symbol_chain);

    /* 
     * If the last symbol is a function, we only want to return its
     * base address.  So shortcut, and do that.
     *
     * XXX: eventually, do we only want to do this if this function and
     * its parents are currently in scope?  Perhaps... I can see both
     * sides.  After all, in the binary form of the program, one
     * function isn't really nested in another; all functions always
     * have fixed, known code locations -- although of course the
     * compiler is free to assume that the function might not be
     * callable outside the function it was declared in (and thus do
     * optimizations that make an outside call fail).  So perhaps even a
     * debugging entity might not be able to call a nested function, if
     * that's ever meaningful.
     *
     * Oh well... don't restrict for now!
     */
    symbol = (struct symbol *)array_list_item(symbol_chain,alen - 1);
    if (SYMBOL_IS_FULL_FUNCTION(symbol)) {
	datatype = symbol_type_skip_qualifiers(symbol->datatype);
	if ((rc = location_resolve_lsymbol_base(target,tid,lsymbol,current_region,
						&retval,&current_range))) {
	    verror("could not resolve base addr for function %s!\n",
		   symbol_get_name(symbol));
	    errno = rc;
	    goto errout;
	}
	vdebug(12,LA_TARGET,LF_SYMBOL,"function %s at 0x%"PRIxADDR"\n",
	       symbol_get_name(symbol),retval);
	goto out;
    }
    /*
     * If the final symbol on the chain is in a register, we skip
     * immediately to handling it; there is no need to handle anything
     * prior to it.
     */
    else if (SYMBOL_IS_FULL_VAR(symbol) 
	     && LOCATION_IN_REG(&symbol->s.ii->d.v.l)) {
	i = alen - 1;
    }
    else {
	i = 0;
    }


    /*
     * We maintain a "slice" of the lsymbol chain, because we only want
     * to pass the subset of it that is our current value of i -- the
     * part of the list we have traversed.
     */
    tchain = array_list_clone(symbol_chain,i);

    /*
     * We traverse through the lsymbol, loading nested chunks.  If the
     * end of the chain is a function, we return its base address.
     * Otherwise, we do nothing for functions (they may be used to
     * resolve the location of variables, however -- i.e., computing the
     * dwarf frame_base virtual register).  Otherwise, for variables, if
     * their types are pointers, we load the pointer, and keep loading
     * the chain according to the next type.  If the last var is a
     * pointer, and the AUTO_DEREF flag is set (or if the AUTO_STRING
     * flag is set, and the final type is a char type), we deref the
     * pointer(s) and return the value of the last pointer.  If it is
     * not a pointer, we return the computed address of the last var.
     */
    while (1) {
	in_reg = 0;
	symbol = (struct symbol *)array_list_item(symbol_chain,i);
	++i;
	tchain->len = i;

	/* Skip functions -- we may need them in the chain, however, so
	 * that our location resolution functions can obtain the frame
	 * register info they need to resolve, if a subsequent
	 * variable's location is dependent on the frame base register.
	 */
	if (SYMBOL_IS_FUNCTION(symbol))
	    continue;

	/* 
	 * If the symbol is a pointer or struct/union type, we support
	 * those (pointers by autoloading; S/U by skipping).  Otherwise,
	 * it's an error -- i.e., users can't try to compute an address
	 * for 'enum foo_enum.FOO_ENUM_ONE'.
	 */
	if (SYMBOL_IS_TYPE(symbol)) {
	    /* Grab the type's datatype. */
	    tdatatype = symbol_type_skip_qualifiers(symbol);

	    if (SYMBOL_IST_PTR(tdatatype)) {
		datatype = tdatatype;
		goto check_pointer;
	    }
	    else if (SYMBOL_IST_STUN(tdatatype))
		continue;
	    else {
		verror("cannot load intermediate type symbol %s!\n",
		       symbol_get_name(symbol));
		errno = EINVAL;
		goto errout;
	    }
	}

	/* We error on all other symbol types that are not variables. */
	if (!SYMBOL_IS_FULL_VAR(symbol)) {
	    verror("symbol %s of type %s is not a full variable!\n",
		   symbol_get_name(symbol),SYMBOL_TYPE(symbol->type));
	    errno = EINVAL;
	    goto errout;
	}

	/* Grab the symbol's datatype. */
	datatype = symbol_type_skip_qualifiers(symbol->datatype);

	/* If the symbol is a member variable, just add its offset to
	 * our currrent address, and continue.
	 */
	if (symbol->ismember) {
	    if (symbol_get_location_offset(symbol,&offset)) {
		verror("could not get offset for member %s in datatype %s!\n",
		       symbol_get_name(symbol),symbol_get_name(datatype));
		errno = EINVAL;
		goto errout;
	    }
	    retval += offset;
	    vdebug(12,LA_TARGET,LF_SYMBOL,
		   "member %s at offset 0x%"PRIxOFFSET"; addr 0x%"PRIxADDR"\n",
		   symbol_get_name(symbol),offset,retval);
	}
	/* Otherwise, we actually need to resolve its location based on
	 * the info in the symbol.
	 */
	else {
	    rc = location_resolve(target,tid,current_region,&symbol->s.ii->d.v.l,
				  tchain,&reg,&retval,&current_range);
	    if (rc == 2) {
		in_reg = 1;
		/* See below inside the pointer check where we will try
		 * to load the pointer across this register.
		 */
	    }
	    else if (rc == 1) {
		current_region = current_range->region;
		vdebug(12,LA_TARGET,LF_SYMBOL,"var %s at 0x%"PRIxADDR"\n",
		       symbol_get_name(symbol),retval);
	    }
	    else {
		if (errno == ENOTSUP) 
		    vwarnopt(8,LA_TARGET,LF_SYMBOL,
			     "could not resolve location for symbol %s: %s!\n",
			     symbol_get_name(symbol),strerror(errno));
		else
		    verror("could not resolve location for symbol %s: %s!\n",
			   symbol_get_name(symbol),strerror(errno));
		goto errout;
	    }
	}

	/*
	 * If the symbol is a pointer, load it now.  If this is the
	 * final symbol in the chain, and flags & AUTO_DEREF, also load
	 * the final pointer(s), and return the value.  Otherwise, just
	 * return the address of the final pointer.
	 */
    check_pointer:
	if (SYMBOL_IST_PTR(datatype)) {
	    if (i < alen 
		|| (i == alen 
		    && (flags & LOAD_FLAG_AUTO_DEREF
			|| (flags & LOAD_FLAG_AUTO_STRING
			    && symbol_type_is_char(symbol_type_skip_ptrs(datatype)))))) {

		if (in_reg) {
		    /* Try to load the ptr value from a register; might or
		     * might not be an address; only is if the current
		     * symbol was a pointer; we handle that below.  There's
		     * a termination condition below this loop that if we
		     * end after having resolved the location to a register,
		     * we can't calculate the address for it.
		     */
		    retval = target_read_reg(target,tid,reg);
		    if (errno) {
			verror("could not read reg %"PRIiREG" that ptr symbol %s"
			       " resolved to: %s!\n",
			       reg,symbol->name,strerror(errno));
			goto errout;
		    }

		    /* We might have changed ranges... */
		    target_find_memory_real(target,retval,NULL,NULL,
					    &current_range);
		    current_region = current_range->region;
		    vdebug(12,LA_TARGET,LF_SYMBOL,
			   "ptr var (in reg) %s at 0x%"PRIxADDR"\n",
			   symbol_get_name(symbol),retval);

		    /* We have to skip one pointer type */
		    datatype = symbol_type_skip_qualifiers(datatype->datatype);

		    /* Clear the in_reg bit, since we were able to
		     * autoload the pointer!
		     */
		    in_reg = 0;

		    vdebug(12,LA_TARGET,LF_SYMBOL,
			   "autoloaded REG (%d) pointer(s) for var %s ="
			   " 0x%"PRIxADDR"\n",
			   reg,symbol_get_name(symbol),retval);

		    /* Do we need to keep trying to load through the pointer? */
		    if (SYMBOL_IST_PTR(datatype))
			goto check_pointer;
		}
		else {
		    retval = target_autoload_pointers(target,datatype,retval,
						      tflags,&datatype,
						      &current_range);
		    if (errno) {
			verror("could not load pointer for symbol %s\n",
			       symbol_get_name(symbol));
			goto errout;
		    }
		    current_region = current_range->region;

		    vdebug(12,LA_TARGET,LF_SYMBOL,
			   "autoloaded pointer(s) for var %s = 0x%"PRIxADDR"\n",
			   symbol_get_name(symbol),retval);
		}
	    }

	    /*
	    if (i == alen) {
		if (in_reg) {
		    verror("last symbol %s was in a register; cannot compute addr!\n",
			   symbol_get_name(symbol));
		    errno = EINVAL;
		    goto errout;
		}
		goto out;
	    }
	    */
	}

	if (i >= alen) {
	    /*
	    if (in_reg
		&& (SYMBOL_IST_PTR(datatype)
		    && !(flags & LOAD_FLAG_AUTO_DEREF)
		    && !(flags & LOAD_FLAG_AUTO_STRING
			 && symbol_type_is_char(symbol_type_skip_ptrs(datatype))))) {
		verror("last symbol (ptr) %s was in a register and auto deref"
		       " not set; cannot compute addr!\n",
		       symbol_get_name(symbol));
		errno = EINVAL;
		goto errout;
	    }
	    */
	    goto out;
	}
    }

 errout:
    array_list_free(tchain);
    return -1;

 out:
    array_list_free(tchain);

    if (final_type_saveptr)
	*final_type_saveptr = datatype;

    if (in_reg) {
	if (reg_saveptr)
	    *reg_saveptr = reg;
	return 2;
    }
    else {
	if (range_saveptr) {
	    if (!current_range) 
		target_find_memory_real(target,retval,NULL,NULL,&current_range);
	    *range_saveptr = current_range;
	}
	if (addr_saveptr)
	    *addr_saveptr = retval;
	return 1;
    }

    return 0;
}

/*
 * This function traverses a bsymbol chain and returns the address of
 * the final symbol in the chain.  If the final symbol is a function, we
 * return its base address.  Otherwise, for intermediate variables on
 * the chain, if their types are pointers, we load the pointer, and keep
 * loading the chain according to the next type.  If the last var is a
 * pointer, and the AUTO_DEREF flag is set (or if the AUTO_STRING flag
 * is set, and the next type is a char type), we deref the pointer(s)
 * and return the value of the last pointer.  If it is not a pointer, we
 * return the computed address of the last var.  We return the type of
 * the value at the address we return in @final_type_saveptr so that the
 * caller doesn't have to track whether the final pointer was autoloaded
 * or not.
 */
int __target_bsymbol_compute_location(struct target *target,tid_t tid,
				      struct bsymbol *bsymbol,
				      load_flags_t flags,
				      REG *reg_saveptr,ADDR *addr_saveptr,
				      struct symbol **final_type_saveptr,
				      struct memrange **range_saveptr) {
    return __target_lsymbol_compute_location(target,tid,bsymbol->lsymbol,
					     0,bsymbol->region,flags,
					     reg_saveptr,addr_saveptr,
					     final_type_saveptr,range_saveptr);
}

struct value *target_load_type(struct target *target,struct symbol *type,
			       ADDR addr,load_flags_t flags) {
    struct symbol *datatype = type;
    struct value *value;
    struct memregion *region;
    struct memrange *range;
    ADDR ptraddr;
    struct location ptrloc;
    struct mmap_entry *mmap;
    char *offset_buf;

    datatype = symbol_type_skip_qualifiers(type);

    if (!SYMBOL_IS_FULL_TYPE(datatype)) {
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
	verror("could not find range for addr 0x%"PRIxADDR"\n!",addr);
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
    else if (flags & LOAD_FLAG_MUST_MMAP || flags & LOAD_FLAG_SHOULD_MMAP) {
	ptrloc.loctype = LOCTYPE_REALADDR;
	ptrloc.l.addr = ptraddr != addr ? ptraddr : addr;

	mmap = location_mmap(target,region,&ptrloc,
			     flags,&offset_buf,NULL,&range);
	value = value_create_noalloc(NULL,range,NULL,datatype);
	if (!value) {
	    verror("could not create value: %s\n",strerror(errno));
	    goto errout;
	}
	if (!value->mmap && flags & LOAD_FLAG_MUST_MMAP) {
	    value->buf = NULL;
	    goto errout;
	}
	else if (!value->mmap) {
	    /* fall back to regular load */
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

struct value *target_load_symbol_member(struct target *target,tid_t tid,
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

    retval = target_load_symbol(target,tid,bmember,flags);

    bsymbol_release(bmember);

    return retval;
}

struct value *target_load_value_member(struct target *target,
				       struct value *old_value,
				       const char *member,const char *delim,
				       load_flags_t flags) {
    struct value *value = NULL;
    struct symbol *vstartdatatype;
    struct symbol *tdatatype;
    struct symbol *mdatatype;
    struct lsymbol *ls = NULL;
    struct memrange *range;
    struct symbol *symbol;
    struct symbol *datatype;
    char *rbuf = NULL;
    ADDR oldaddr,addr;
    struct target_thread *tthread = old_value->thread;
    tid_t tid = tthread->tid;
    int rc;
    REG reg;
    REGVAL regval;
    int newlen;

    vstartdatatype = symbol_type_skip_qualifiers(old_value->type);
    tdatatype = vstartdatatype;

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

    /* If the value's datatype is a pointer, and we are autoloading pointers,
     * then try to find a struct/union type that is pointed to!
     */
    if (SYMBOL_IST_PTR(vstartdatatype)) {
	if (flags & LOAD_FLAG_AUTO_DEREF) {
	    tdatatype = symbol_type_skip_ptrs(vstartdatatype);
	    oldaddr = v_addr(old_value);
	}
	else {
	    errno = EINVAL;
	    goto errout;
	}
    }
    else
	oldaddr = old_value->res.addr;

    if (!SYMBOL_IST_FULL_STUN(tdatatype)) {
	vwarn("symbol %s is not a full struct/union type (is %s)!\n",
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

    if (ls->symbol->s.ii->d.v.l.loctype != LOCTYPE_MEMBER_OFFSET) {
	verror("loctype for symbol %s is %s, not MEMBER_OFFSET!\n",
	       symbol_get_name(ls->symbol),
	       LOCTYPE(ls->symbol->s.ii->d.v.l.loctype));
	errno = EINVAL;
	goto errout;
    }
    mdatatype = symbol_type_skip_qualifiers(ls->symbol->datatype);

    symbol = ls->symbol;

    /*
     * Compute either an address or register location, and load!
     */

    range = NULL;
    reg = -1;
    addr = 0;
    datatype = NULL;
    rc = __target_lsymbol_compute_location(target,tid,ls,oldaddr,
					   old_value->range->region,flags,
					   &reg,&addr,&datatype,&range);
    if (rc < 0) {
	verror("failed to compute location for var %s\n",
	       symbol_get_name(symbol));
	goto errout;
    }
    else if (rc == 1) {
	/*
	 * If __target_lsymbol_compute_address_at returns an address
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
	newlen = symbol_type_full_bytesize(datatype);
	if (addr >= oldaddr
	    && ((addr + newlen) - oldaddr) < (unsigned)old_value->bufsiz) {
	    if (flags & LOAD_FLAG_VALUE_FORCE_COPY) {
		value = value_create(tthread,range,ls,datatype);
		if (!value) {
		    verror("could not create value: %s\n",strerror(errno));
		    goto errout;
		}
		memcpy(value->buf,old_value->buf + (addr - oldaddr),
		       newlen);
		value_set_addr(value,addr);

		vdebug(9,LA_TARGET,LF_SYMBOL,
		       "forced member value copy with len %d\n",
		       value->bufsiz);
	    }
	    else {
		value = value_create_noalloc(tthread,range,ls,datatype);
		if (!value) {
		    verror("could not create value: %s\n",strerror(errno));
		    goto errout;
		}
		value_set_child(value,old_value,addr);

		vdebug(9,LA_TARGET,LF_SYMBOL,
		       "loaded member value as child with len %d\n",
		       value->bufsiz);
	    }

	    goto out;
	}

	tdatatype = symbol_type_skip_qualifiers(symbol->datatype);
	if (flags & LOAD_FLAG_AUTO_STRING
	    && SYMBOL_IST_PTR(tdatatype) 
	    && symbol_type_is_char(symbol_type_skip_ptrs(tdatatype))) {
	    datatype = symbol_type_skip_ptrs(tdatatype);
	    /* XXX: should we use datatype, or the last pointer to datatype? */
	    value = value_create_noalloc(tthread,range,ls,datatype);
	    if (!value) {
		verror("could not create value: %s\n",strerror(errno));
		goto errout;
	    }

	    if (!(value->buf = (char *)__target_load_addr_real(target,range,
							       addr,flags,
							       NULL,0))) {
		vwarn("failed to autostring char pointer for symbol %s\n",
		      symbol_get_name(symbol));
		value_free(value);
		value = NULL;
		goto errout;
	    }
	    value_set_strlen(value,strlen(value->buf) + 1);
	    value_set_addr(value,addr);

	    vdebug(9,LA_TARGET,LF_SYMBOL,
		   "autoloaded char * value with len %d\n",
		   value->bufsiz);
	}
	else {
	    value = value_create(tthread,range,ls,datatype);
	    if (!value) {
		verror("could not create value: %s\n",strerror(errno));
		goto errout;
	    }

	    if (!__target_load_addr_real(target,range,addr,flags,
					 (unsigned char *)value->buf,
					 value->bufsiz)) {
		verror("failed to load value at 0x%"PRIxADDR"\n",addr);
		value_free(value);
		value = NULL;
		goto errout;
	    }
	    else {
		value_set_addr(value,addr);

		vdebug(9,LA_TARGET,LF_SYMBOL,"loaded value with len %d\n",
		       value->bufsiz);
	    }
	}
    }
    else if (rc == 2) {
	if (flags & LOAD_FLAG_MUST_MMAP) {
	    verror("cannot mmap register value for var %s!\n",
		   symbol_get_name(symbol));
	    errno = EINVAL;
	    goto errout;
	}

        regval = target_read_reg(target,tid,reg);
        if (errno) {
	    verror("could not read reg %d value in tid %"PRIiTID"\n",reg,tid);
            goto errout;
	}

	datatype = symbol_type_skip_qualifiers(symbol->datatype);
	rbuf = malloc(symbol_bytesize(datatype));

        if (target->wordsize == 4 && __WORDSIZE == 64) {
            /* If the target is 32-bit on 64-bit host, we have to grab
             * the lower 32 bits of the regval.
             */
            memcpy(rbuf,((int32_t *)&regval),symbol_bytesize(datatype));
        }
	else if (__WORDSIZE == 32)
	    memcpy(rbuf,&regval,(symbol_bytesize(datatype) < 4) \
		   ? symbol_bytesize(datatype) : 4);
        else
            memcpy(rbuf,&regval,symbol_bytesize(datatype));

	/* Just create the value based on the register value. */
	value = value_create_noalloc(tthread,NULL,ls,datatype);
	if (!value) {
	    verror("could not create value: %s\n",strerror(errno));
	    goto errout;
	}
	value->buf = rbuf;
	value->bufsiz = symbol_bytesize(datatype);

	value_set_reg(value,symbol->s.ii->d.v.l.l.reg);
    }
    else {
	verror("computed location not register nor address (%d) -- BUG!\n",rc);
	errno = EINVAL;
	goto errout;
    }

 out:
    lsymbol_release(ls);
    return value;

 errout:
    if (ls)
	lsymbol_release(ls);
    if (rbuf)
	free(rbuf);
    if (value)
	value_free(value);
    return NULL;
}

struct value *target_load_symbol(struct target *target,tid_t tid,
				 struct bsymbol *bsymbol,load_flags_t flags) {
    ADDR addr;
    REG reg;
    struct symbol *symbol;
    struct symbol *datatype;
    struct memregion *region = bsymbol->region;
    struct memrange *range;
    struct value *value = NULL;
    REGVAL regval;
    char *rbuf;
    struct symbol *tdatatype;
    struct target_thread *tthread;
    struct array_list *symbol_chain;
    int alen;
    int rc;
    struct lsymbol *ii_lsymbol;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	errno = EINVAL;
	verror("could not lookup thread %"PRIiTID"; forgot to load?\n",tid);
	return NULL;
    }

    symbol_chain = bsymbol->lsymbol->chain;
    alen = array_list_len(symbol_chain);
    symbol = (struct symbol *)array_list_item(symbol_chain,alen - 1);

    if (!SYMBOL_IS_FULL_VAR(symbol)) {
	verror("symbol %s is not a full variable (is %s)!\n",
	       symbol_get_name(symbol),SYMBOL_TYPE(symbol->type));
	errno = EINVAL;
	return NULL;
    }

    /*
     * If this is an inlined symbol that has no location info, and it
     * only has one inline instance, try to autoload the inlined instance!!
     */
    if (SYMBOL_IS_FULL_VAR(symbol)
	&& symbol->s.ii->d.v.l.loctype == LOCTYPE_UNKNOWN
	&& array_list_len(symbol->s.ii->inline_instances) == 1) {
	/* Use __int() version to not RHOLD(); bsymbol_create RHOLDS it. */
	ii_lsymbol = lsymbol_create_from_symbol__int((struct symbol *) \
						     array_list_item(symbol->s.ii->inline_instances,0));

	if (ii_lsymbol) {
	    vwarn("trying to load inlined symbol %s with no location info;"
		  " found sole instance %s; will try to load that.\n",
		  symbol_get_name(symbol),symbol_get_name(ii_lsymbol->symbol));
	    bsymbol = bsymbol_create(ii_lsymbol,bsymbol->region);
	    
	    symbol_chain = bsymbol->lsymbol->chain;
	    alen = array_list_len(symbol_chain);
	    symbol = (struct symbol *)array_list_item(symbol_chain,alen - 1);
	}
	else {
	    vwarn("trying to load inlined symbol %s with no location info;"
		  " could not find instance; will fail!\n",
		  symbol_get_name(symbol));
	}
    }
    /*
     * If this symbol has a constant value, load that!
     */
    else if (SYMBOL_IS_FULL_INSTANCE(symbol)
	     && symbol->s.ii->constval) {
	value = value_create(tthread,NULL,bsymbol->lsymbol,symbol->datatype);
	memcpy(value->buf,symbol->s.ii->constval,value->bufsiz);
	
	vdebug(9,LA_TARGET,LF_SYMBOL,
	       "loaded const value len %d\n",value->bufsiz);

	return value;
    }

    /*
     * Compute the symbol's location (reg or addr) and load that!
     */
    rc = __target_bsymbol_compute_location(target,tid,bsymbol,flags,
					   &reg,&addr,&datatype,&range);
    if (rc < 0) {
	if (errno == ENOTSUP)
	    vwarnopt(8,LA_TARGET,LF_SYMBOL,
		     "failed to compute location for var %s\n",
		     symbol_get_name(symbol));
	else
	    verror("failed to compute location for var %s\n",
		   symbol_get_name(symbol));
	goto errout;
    }
    else if (rc == 1) {
	tdatatype = symbol_type_skip_qualifiers(symbol->datatype);
	if (flags & LOAD_FLAG_AUTO_STRING
	    && SYMBOL_IST_PTR(tdatatype) 
	    && symbol_type_is_char(symbol_type_skip_ptrs(tdatatype))) {
	    datatype = symbol_type_skip_ptrs(tdatatype);
	    /* XXX: should we use datatype, or the last pointer to datatype? */
	    value = value_create_noalloc(tthread,range,bsymbol->lsymbol,datatype);
	    if (!value) {
		verror("could not create value: %s\n",strerror(errno));
		goto errout;
	    }

	    if (!(value->buf = (char *)__target_load_addr_real(target,range,
							       addr,flags,
							       NULL,0))) {
		vwarn("failed to autostring char pointer for symbol %s\n",
		      symbol_get_name(symbol));
		value_free(value);
		value = NULL;
		goto errout;
	    }
	    value_set_strlen(value,strlen(value->buf) + 1);
	    value_set_addr(value,addr);

	    vdebug(9,LA_TARGET,LF_SYMBOL,
		   "autoloaded char * value with len %d\n",
		   value->bufsiz);
	}
	else {
	    value = value_create(tthread,range,bsymbol->lsymbol,datatype);
	    if (!value) {
		verror("could not create value: %s\n",strerror(errno));
		goto errout;
	    }

	    if (!__target_load_addr_real(target,range,addr,flags,
					 (unsigned char *)value->buf,
					 value->bufsiz)) {
		verror("failed to load value at 0x%"PRIxADDR"\n",addr);
		value_free(value);
		value = NULL;
		goto out;
	    }
	    else {
		value_set_addr(value,addr);

		vdebug(9,LA_TARGET,LF_SYMBOL,"loaded value with len %d\n",
		       value->bufsiz);
	    }
	}
    }
    else if (rc == 2) {
	if (flags & LOAD_FLAG_MUST_MMAP) {
	    verror("cannot mmap register value for var %s!\n",
		   symbol_get_name(symbol));
	    errno = EINVAL;
	    goto errout;
	}

        regval = target_read_reg(target,tid,reg);
        if (errno) {
	    verror("could not read reg %d value in tid %"PRIiTID"\n",reg,tid);
            goto errout;
	}

	datatype = symbol_type_skip_qualifiers(symbol->datatype);
	rbuf = malloc(symbol_bytesize(datatype));

        if (target->wordsize == 4 && __WORDSIZE == 64) {
            /* If the target is 32-bit on 64-bit host, we have to grab
             * the lower 32 bits of the regval.
             */
            memcpy(rbuf,((int32_t *)&regval),symbol_bytesize(datatype));
        }
	else if (__WORDSIZE == 32)
	    memcpy(rbuf,&regval,(symbol_bytesize(datatype) < 4) \
		                 ? symbol_bytesize(datatype) : 4);
        else
            memcpy(rbuf,&regval,symbol_bytesize(datatype));

	/* Just create the value based on the register value. */
	value = value_create_noalloc(tthread,NULL,bsymbol->lsymbol,datatype);
	if (!value) {
	    verror("could not create value: %s\n",strerror(errno));
	    goto errout;
	}
	value->buf = rbuf;
	value->bufsiz = symbol_bytesize(datatype);

	value_set_reg(value,symbol->s.ii->d.v.l.l.reg);
    }
    else {
	verror("computed location not register nor address (%d) -- BUG!\n",rc);
	errno = EINVAL;
	goto errout;
    }

 out:
    return value;

 errout:
    if (value)
	value_free(value);
    return NULL;
}

int target_resolve_symbol_base(struct target *target,tid_t tid,
			       struct bsymbol *bsymbol,ADDR *addr_saveptr,
			       struct memrange **range_saveptr) {
    return location_resolve_lsymbol_base(target,tid,bsymbol->lsymbol,
					 bsymbol->region,addr_saveptr,
					 range_saveptr);
}

OFFSET target_offsetof_symbol(struct target *target,struct bsymbol *bsymbol,
			      char *member,const char *delim) {
    return symbol_offsetof(bsymbol->lsymbol->symbol,member,delim);
}

/*
 * What we do here is traverse @bsymbol's lsymbol chain.  For each var
 * we encounter, try to resolve its address.  If the chain is
 * interrupted by pointers, load those and continue loading any
 * subsequent variables.
 */
ADDR target_addressof_symbol(struct target *target,tid_t tid,
			     struct bsymbol *bsymbol,load_flags_t flags,
			     struct memrange **range_saveptr) {
    ADDR retval;
    int i = 0;
    int alen;
    int rc;
    struct symbol *symbol;
    struct array_list *symbol_chain;
    struct symbol *datatype;
    OFFSET offset;
    struct memregion *current_region = bsymbol->region;
    struct memrange *current_range;
    load_flags_t tflags = flags | LOAD_FLAG_AUTO_DEREF;
    struct array_list *tchain = NULL;
    REG reg;
    int in_reg;

    symbol_chain = bsymbol->lsymbol->chain;
    alen = array_list_len(symbol_chain);
    symbol = (struct symbol *)array_list_item(symbol_chain,alen - 1);

    /* 
     * If the last symbol is a function, we only want to return its
     * base address.  So do that.
     */
    if (i == alen && SYMBOL_IS_FULL_FUNCTION(symbol)) {
	if ((rc = location_resolve_symbol_base(target,tid,bsymbol,
					       &retval,&current_range))) {
	    verror("could not resolve base addr for function %s!\n",
		   symbol_get_name(symbol));
	    errno = rc;
	    goto errout;
	}
	vdebug(9,LA_TARGET,LF_SYMBOL,"function %s at 0x%"PRIxADDR"\n",
	       symbol_get_name(symbol),retval);
	goto out;
    }

    /*
     * We maintain a "slice" of the lsymbol chain, because we only want
     * to pass the subset of it that is our current value of i -- the
     * part of the list we have traversed.
     */
    tchain = array_list_clone(symbol_chain,0);

    /*
     * We traverse through the lsymbol, loading nested chunks.  If the
     * end of the chain is a function, we return its base address.
     * Otherwise, we do nothing for functions (they may be used to
     * resolve the location of variables, however -- i.e., computing the
     * dwarf frame_base virtual register).  Otherwise, for variables, if
     * their types are pointers, we load the pointer, and keep loading
     * the chain according to the next type.  If the last var is a
     * pointer, and the AUTO_DEREF flag is set, we deref the pointer(s)
     * and return the value of the last pointer.  If it is not a
     * pointer, we return the computed address of the last var.
     *
     * The one weird thing is that if the var is a member that is a
     * struct/union type, we skip it because our location resolution for
     * members automatically goes back up the chain to handle nested
     * struct members.
     */
    while (1) {
	in_reg = 0;
	symbol = (struct symbol *)array_list_item(symbol_chain,i);
	++i; 
	tchain->len = i;

	if (!SYMBOL_IS_FULL_VAR(symbol)) {
	    verror("symbol %s of type %s is not a full variable!\n",
		   symbol_get_name(symbol),SYMBOL_TYPE(symbol->type));
	    errno = EINVAL;
	    goto errout;
	}

	datatype = symbol_type_skip_qualifiers(symbol->datatype);
	if (symbol->ismember && SYMBOL_IST_STUN(datatype)) {
	    vdebug(9,LA_TARGET,LF_SYMBOL,"skipping member %s in stun type %s\n",
		   symbol_get_name(symbol),symbol_get_name(datatype));
	    continue;
	}
	else if (symbol->ismember) {
	    offset = location_resolve_offset(&symbol->s.ii->d.v.l,
					     tchain,NULL,NULL);
	    if (errno) {
		verror("could not resolve offset for member %s\n",
		       symbol_get_name(symbol));
		goto errout;
	    }
	    retval += offset;
	    vdebug(9,LA_TARGET,LF_SYMBOL,
		   "member %s at offset 0x%"PRIxOFFSET"; really at 0x%"PRIxADDR
		   "\n",
		   symbol_get_name(symbol),offset,retval);
	}
	else {
	    rc = location_resolve(target,tid,current_region,&symbol->s.ii->d.v.l,
				  tchain,&reg,&retval,&current_range);
	    if (rc == 2) {
		/* Try to load some value from a register; might or
		 * might not be an address; only is if the current
		 * symbol was a pointer; we handle that below.  There's
		 * a termination condition below this loop that if we
		 * end after having resolved the location to a register,
		 * we can't calculate the address for it.
		 */
		in_reg = 1;
		if (SYMBOL_IST_PTR(datatype)) {
		    retval = target_read_reg(target,tid,reg);
		    if (errno) {
			verror("could not read reg %"PRIiREG" that ptr symbol %s"
			       " resolved to: %s!\n",
			       reg,symbol->name,strerror(errno));
			goto errout;
		    }

		    /* We might have changed ranges... */
		    target_find_memory_real(target,retval,NULL,NULL,
					    &current_range);
		    current_region = current_range->region;
		    vdebug(9,LA_TARGET,LF_SYMBOL,"ptr var (in reg) %s at 0x%"PRIxADDR"\n",
			   symbol_get_name(symbol),retval);
		    /* We have to skip one pointer type */
		    datatype = symbol_type_skip_qualifiers(datatype->datatype);

		    goto check_pointer;
		}
		else {
		    /*
		     * Not sure how this could happen...
		     */
		    verror("could not handle non-ptr symbol %s being in a reg!\n",
			   symbol->name);
		    errno = EINVAL;
		    goto errout;
		}
	    }
	    else if (rc == 1) {
		current_region = current_range->region;
		vdebug(9,LA_TARGET,LF_SYMBOL,"var %s at 0x%"PRIxADDR"\n",
		       symbol_get_name(symbol),retval);
	    }
	    else {
		verror("could not resolve location for symbol %s: %s!\n",
		       symbol_get_name(symbol),strerror(errno));
		goto errout;
	    }
	}

	/*
	 * If the symbol is a pointer, load it now.  If this is the
	 * final symbol in the chain, and flags & AUTO_DEREF, also load
	 * the final pointer(s), and return the value.  Otherwise, just
	 * return the address of the final pointer.
	 */
    check_pointer:
	if (SYMBOL_IST_PTR(datatype)) {
	    if (i < alen 
		|| (i == alen && (flags & LOAD_FLAG_AUTO_DEREF
				  || (flags & LOAD_FLAG_AUTO_STRING
				      && symbol_type_is_char(symbol_type_skip_ptrs(datatype)))))) {
		retval = target_autoload_pointers(target,datatype,retval,tflags,
						  &datatype,&current_range);
		if (errno) {
		    verror("could not load pointer for symbol %s\n",
			   symbol_get_name(symbol));
		    goto errout;
		}
		current_region = current_range->region;
		vdebug(9,LA_TARGET,LF_SYMBOL,
		       "autoloaded pointer(s) for var %s now at 0x%"PRIxADDR"\n",
		       symbol_get_name(symbol),retval);
	    }
	}

	if (i >= alen) {
	    if (in_reg
		&& (SYMBOL_IST_PTR(datatype)
		    && !(flags & LOAD_FLAG_AUTO_DEREF)
		    && !(flags & LOAD_FLAG_AUTO_STRING
			 && symbol_type_is_char(symbol_type_skip_ptrs(datatype))))) {
		verror("last symbol (ptr) %s was in a register and auto deref"
		       " not set; cannot compute addr!\n",
		       symbol_get_name(symbol));
		errno = EINVAL;
		goto errout;
	    }
	    goto out;
	}
    }

 errout:
    retval = 0;

 out:
    array_list_free(tchain);
    if (range_saveptr)
	*range_saveptr = current_range;
    return retval;
}

/*
 * This is deprecated; just keeping code around in case.
 */
#if 0
struct value *bsymbol_load(struct bsymbol *bsymbol,load_flags_t flags) {
    struct value *value = NULL;
    struct symbol *symbol = bsymbol->lsymbol->symbol;
    struct array_list *symbol_chain = bsymbol->lsymbol->chain;
    struct symbol *datatype;
    struct symbol *startdatatype = NULL;
    struct memregion *region = bsymbol->region;
    struct target *target = memregion_target(region);
    struct memrange *range;
    REGVAL ip;
    ADDR ip_addr;
    ADDR ptraddr = 0;
    ADDR finaladdr = 0;
    struct location ptrloc;
    struct memregion *ptrregion = NULL;
    struct memrange *ptrrange = NULL;

    if (!SYMBOL_IS_FULL_VAR(symbol)) {
	vwarn("symbol %s is not a full variable (is %s)!\n",
	      symbol->name,SYMBOL_TYPE(symbol->type));
	errno = EINVAL;
	return NULL;
    }

    /* Get its real type. */

    startdatatype = symbol_get_datatype__int(symbol);
    datatype = symbol_type_skip_qualifiers(startdatatype);

    if (startdatatype != datatype)
	vdebug(9,LA_TARGET,LF_SYMBOL,"skipped from %s to %s for symbol %s\n",
	       DATATYPE(startdatatype->datatype_code),
	       DATATYPE(datatype->datatype_code),symbol->name);
    else 
	vdebug(9,LA_TARGET,LF_SYMBOL,"no skip; type for symbol %s is %s\n",
	       symbol->name,DATATYPE(datatype->datatype_code));

    /* Check if this symbol is currently visible to us! */
    if (!(flags & LOAD_FLAG_NO_CHECK_VISIBILITY)) {
	if (sizeof(REGVAL) == sizeof(ADDR))
	    ip_addr = (ADDR)target_read_reg(target,TID_GLOBAL,target->ipregno);
	else if (sizeof(ADDR) < sizeof(REGVAL)) {
	    ip = target_read_reg(target,TID_GLOBAL,target->ipregno);
	    memcpy(&ip_addr,&ip,sizeof(ADDR));
	}
	else {
	    verror("sizeof(ADDR) > sizeof(REGVAL) -- makes no sense!\n");
	    errno = EINVAL;
	}

	if (errno)
	    return NULL;

	/*
	 * The symbol "visible" range is an object address; so, we need
	 * to check for each range in the region, if the address is
	 * visible inside one of them!
	 */
	range = memregion_find_range_real(region,ip_addr);
	if (!range)
	    verror("could not find range to check symbol visibility at IP 0x%"PRIxADDR" for symbol %s!\n",
		   ip_addr,symbol->name);
	else if (!symbol_visible_at_ip(symbol,
				       memrange_unrelocate(range,ip_addr))) {
	    verror("symbol not visible at IP 0x%"PRIxADDR" for symbol %s!\n",
		   ip_addr,symbol->name);
	    return NULL;
	}
	range = NULL;
    }

    /* If they want pointers automatically dereferenced, do it! */
    if (((flags & LOAD_FLAG_AUTO_DEREF) && SYMBOL_IST_PTR(datatype))
	|| ((flags & LOAD_FLAG_AUTO_STRING) 
	    && SYMBOL_IST_PTR(datatype) 
	    && symbol_type_is_char(datatype->datatype))) {
	vdebug(9,LA_TARGET,LF_SYMBOL,"auto_deref: starting ptr symbol %s\n",
	       symbol->name);

	/* First, load the symbol's primary location -- the pointer
	 * value.  Then, if there are more pointers, keep loading those
	 * addrs.
	 *
	 * Don't allow any load flags through for this!  We don't want
	 * to mmap just for pointers.
	 */
	range = NULL;
	if (!location_load(target,region,&(symbol->s.ii->l),LOAD_FLAG_NONE,
			   &ptraddr,target->ptrsize,symbol_chain,&finaladdr,&range)) {
	    verror("auto_deref: could not load ptr for symbol %s!\n",
		   symbol->name);
	    goto errout;
	}

	vdebug(9,LA_TARGET,LF_SYMBOL,"loaded ptr value 0x%"PRIxADDR"for symbol %s\n",
	       ptraddr,symbol->name);

	/* Skip past the pointer we just loaded. */
	datatype = symbol_get_datatype__int(datatype);

	/* Skip past any qualifiers! */
	datatype = symbol_type_skip_qualifiers(datatype);

	ptraddr = target_autoload_pointers(target,datatype,ptraddr,flags,
					   &datatype,&range);
	if (errno) {
	    vwarn("failed to autoload pointers for symbol %s\n",
		  symbol_get_name(symbol));
	    goto errout;
	}

	if (range)
	    ptrregion = range->region;
	else {
	    /* We might not have a range if the value was in a register;
	     * if we don't have one, find it!
	     */
	    if (!target_find_memory_real(target,ptraddr,NULL,NULL,&range)) {
		errno = EFAULT;
		return NULL;
	    }
	}
    }

    /*
     * Now allocate the value struct for various cases and return.
     */

    /* If we're autoloading pointers and we want to load char * pointers
     * as strings, do it!
     */
    if (ptraddr
	&& flags & LOAD_FLAG_AUTO_STRING
	&& symbol_type_is_char(datatype)) {
	/* XXX: should we use datatype, or the last pointer to datatype? */
	value = value_create_noalloc(bsymbol->lsymbol,datatype);
	if (!value) {
	    verror("could not create value: %s\n",strerror(errno));
	    goto errout;
	}

	if (!(value->buf = (char *)__target_load_addr_real(target,ptrrange,
							   ptraddr,flags,
							   NULL,0))) {
	    vwarn("failed to autoload last pointer for symbol %s\n",
		  symbol->name);
	    goto errout;
	}
	value->bufsiz = strlen(value->buf) + 1;
	value->isstring = 1;
	value->range = ptrrange;
	value->res.addr = ptraddr;

	vdebug(9,LA_TARGET,LF_SYMBOL,
	       "autoloaded char * with len %d\n",value->bufsiz);

	/* success! */
	goto out;
    }
    else if (flags & LOAD_FLAG_MUST_MMAP || flags & LOAD_FLAG_SHOULD_MMAP) {
	ptrloc.loctype = LOCTYPE_REALADDR;
	ptrloc.l.addr = ptraddr;

	value = value_create_noalloc(bsymbol->lsymbol,datatype);
	if (!value) {
	    verror("could not create value: %s\n",strerror(errno));
	    goto errout;
	}

	value->mmap = location_mmap(target,(ptraddr) ? ptrregion : region,
				    (ptraddr) ? &ptrloc : &(symbol->s.ii->l),
				    flags,&value->buf,symbol_chain,NULL);
	if (!value->mmap && flags & LOAD_FLAG_MUST_MMAP) {
	    value->buf = NULL;
	    value_free(value);
	    value = NULL;
	    goto errout;
	}
	else if (!value->mmap) {
	    /* fall back to regular load */
	    value->bufsiz = symbol_type_full_bytesize(datatype);
	    value->buf = malloc(value->bufsiz);
	    if (!value->buf) {
		value->bufsiz = 0;
		goto errout;
	    }

	    if (!location_load(target,(ptraddr) ? ptrregion: region,
			       (ptraddr) ? &ptrloc : &(symbol->s.ii->l),
			       flags,value->buf,value->bufsiz,symbol_chain,
			       &finaladdr,&value->range))
		goto errout;
	}

	value->res.addr = finaladdr;

	/* success! */
	goto out;
    }
    else {
	ptrloc.loctype = LOCTYPE_REALADDR;
	ptrloc.l.addr = ptraddr;

	value = value_create(bsymbol->lsymbol,datatype);
	if (!value) {
	    verror("could not create value for type (ptr is %p); %s\n",
		   datatype,datatype ? datatype->name : NULL);
	    goto errout;
	}

	if (!location_load(target,region,
			   (ptraddr) ? &ptrloc : &(symbol->s.ii->l),
			   flags,value->buf,value->bufsiz,symbol_chain,
			   &finaladdr,&value->range))
	    goto errout;

	value->res.addr = finaladdr;
    }

 out:
    if (value->range)
	value->region_stamp = value->range->region->stamp;

    return value;

 errout:
    if (value)
	value_free(value);

    return NULL;
}
#endif

int target_store_value(struct target *target,struct value *value) {
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
				     (unsigned char *)&paddr,target->ptrsize)) {
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
    ptrloadflags &= ~LOAD_FLAG_SHOULD_MMAP;

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
					 target->ptrsize)) {
		verror("could not load ptr 0x%"PRIxADDR"\n",paddr);
		errno = EFAULT;
		goto errout;
	    }

	    ++nptrs;
	    vdebug(9,LA_TARGET,LF_TSYMBOL,
		   "loaded next ptr value 0x%"PRIxADDR" (#%d)\n",
		   paddr,nptrs);

	    /* Skip past the pointer we just loaded. */
	    datatype = symbol_get_datatype__int(datatype);

	    /* Skip past any qualifiers! */
	    datatype = symbol_type_skip_qualifiers(datatype);
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
	    *start = crd->start;
	if (end)
	    *end = crd->end;
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
	    *start = crd->start;
	if (end)
	    *end = crd->end;
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
					   void *tstate) {
    struct target_thread *t = (struct target_thread *)calloc(1,sizeof(*t));

    vdebug(3,LA_TARGET,LF_THREAD,"thread %"PRIiTID"\n",tid);

    t->target = target;
    t->tid = tid;
    t->state = tstate;

    t->hard_probepoints = g_hash_table_new(g_direct_hash,g_direct_equal);

    t->tpc = NULL;
    t->tpc_stack = array_list_create(4);
    INIT_LIST_HEAD(&t->ss_actions);

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
    vdebug(3,LA_TARGET,LF_THREAD,"thread %"PRIiTID"\n",tthread->tid);

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
    if (target->base) {
	g_hash_table_remove(target->base->overlays,
			    (gpointer)(uintptr_t)tthread->tid);
    }

    array_list_free(tthread->tpc_stack);
    tthread->tpc_stack = NULL;

    g_hash_table_destroy(tthread->hard_probepoints);
    tthread->hard_probepoints = NULL;

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

int target_invalidate_all_threads(struct target *target) {
    GHashTableIter iter;
    struct target_thread *tthread;

    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer)&tthread)) {
	tthread->valid = 0;
	if (tthread->dirty)
	    vwarn("invalidated dirty thread %"PRIiTID"; BUG?\n",tthread->tid);
    }

    return 0;
}

int target_invalidate_thread(struct target *target,
			     struct target_thread *tthread) {
    tthread->valid = 0;
    if (tthread->dirty)
	vwarn("invalidated dirty thread %"PRIiTID"; BUG?\n",tthread->tid);

    return 0;
}

target_status_t target_notify_overlay(struct target *overlay,tid_t tid,ADDR ipval,
				      int *again) {
    return overlay->ops->overlay_event(overlay,tid,ipval,again);
}

struct target *target_lookup_overlay(struct target *target,tid_t tid) {
    return (struct target *) \
	g_hash_table_lookup(target->overlays,(gpointer)(uintptr_t)tid);
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

struct target_memmod *target_memmod_create(struct target *target,tid_t tid,
					   ADDR addr,ADDR paddr,
					   target_memmod_type_t mmt,
					   unsigned char *code,
					   unsigned int code_len) {
    struct target_memmod *mmod;
    unsigned char *ibuf;
    unsigned int ibuf_len;
    unsigned int rc;
    struct target_thread *tthread;

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
    mmod->paddr = paddr;

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

    if (!target_read_addr(target,addr,ibuf_len,ibuf)) {
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

    if (paddr)
	g_hash_table_insert(target->phys_mmods,(gpointer)paddr,mmod);
    else
	g_hash_table_insert(target->mmods,(gpointer)addr,mmod);

    array_list_append(mmod->threads,tthread);

    vdebug(5,LA_TARGET,LF_TARGET,
	   "created memmod at 0x%"PRIxADDR" (p 0x%"PRIxADDR") tid %"PRIiTID";"
	   " inserted new bytes (orig mem: %02hhx %02hhx %02hhx %02hhx"
	   " %02hhx %02hhx %02hhx %02hhx)\n",
	   mmod->addr,mmod->paddr,tid,
	   (int)ibuf[0],(int)ibuf[1],(int)ibuf[2],(int)ibuf[3],
	   (int)ibuf[4],(int)ibuf[5],(int)ibuf[6],(int)ibuf[7]);

    free(ibuf);

    return mmod;
}

struct target_memmod *target_memmod_lookup(struct target *target,tid_t tid,
					   ADDR addr) {
    struct target_memmod *mmod;
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return NULL;
    }

    /*
     * Eventually, this hashtable will be per-thread; for now, just
     * global.
     */
    mmod = (struct target_memmod *) \
	g_hash_table_lookup(target->mmods,(gpointer)addr);

    return mmod;
}

struct target_memmod *target_memmod_lookup_paddr(struct target *target,tid_t tid,
						 ADDR paddr) {
    struct target_memmod *mmod;
    struct target_thread *tthread;

    tthread = target_lookup_thread(target,tid);
    if (!tthread) {
	verror("tid %"PRIiTID" does not exist!\n",tid);
	errno = ESRCH;
	return NULL;
    }

    mmod = (struct target_memmod *) \
	g_hash_table_lookup(target->phys_mmods,(gpointer)paddr);

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
	return 0;
    }

    vdebug(5,LA_TARGET,LF_TARGET,
	   "released memmod 0x%"PRIxADDR" (p 0x%"PRIxADDR") tid %"PRIiTID"\n",
	   mmod->addr,mmod->paddr,tid);

    /* If this is the last thread using it, be done now! */
    if (array_list_len(mmod->threads) == 0) {
	return target_memmod_free(target,tid,mmod,0);
    }

    return 0;
}

int target_memmod_free(struct target *target,tid_t tid,
		       struct target_memmod *mmod,int force) {
    unsigned int rc;
    int retval;
    ADDR addr;

    retval = 0;
    addr = mmod->addr;

    /* If this is the last thread using it, be done now! */
    if (force || array_list_len(mmod->threads) == 0) {
	g_hash_table_remove(target->mmods,(gpointer)addr);

	if (mmod->tmp)
	    free(mmod->tmp);
	if (mmod->mod)
	    free(mmod->mod);

	rc = target_write_addr(target,addr,mmod->orig_len,mmod->orig);
	if (rc != mmod->orig_len) {
	    verror("could not restore orig memory at 0x%"PRIxADDR";"
		   " but cannot do anything!\n",addr);
	    retval = -1;
	}

	vdebug(5,LA_TARGET,LF_TARGET,
	       "released memmod 0x%"PRIxADDR" (p 0x%"PRIxADDR") tid %"PRIiTID"\n",
	       mmod->addr,mmod->paddr,tid);

	array_list_free(mmod->threads);
	free(mmod->orig);
	free(mmod);
    }

    return retval;
}

int target_memmod_set(struct target *target,tid_t tid,
		      struct target_memmod *mmod) {
    ADDR addr;
    struct target_thread *tthread;
    unsigned int rc;

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
	       "(was already) memmod 0x%"PRIxADDR" (p 0x%"PRIxADDR")"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->paddr,tid);
	mmod->owner = NULL;
	return 0;
    case MMS_ORIG:
	rc = target_write_addr(target,addr,mmod->mod_len,mmod->mod);
	if (rc != mmod->mod_len) {
	    verror("could not insert subst memory at 0x%"PRIxADDR"!\n",addr);
	    return -1;
	}
	mmod->state = MMS_SUBST;
	vdebug(8,LA_TARGET,LF_TARGET,
	       "(was orig) memmod 0x%"PRIxADDR" (p 0x%"PRIxADDR")"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->paddr,tid);
	mmod->owner = NULL;
	return 0;
    case MMS_TMP:
	if (mmod->tmp) {
	    free(mmod->tmp);
	    mmod->tmp = NULL;
	    mmod->tmp_len = 0;
	}
	rc = target_write_addr(target,addr,mmod->mod_len,mmod->mod);
	if (rc != mmod->mod_len) {
	    verror("could not insert subst memory at 0x%"PRIxADDR"!\n",addr);
	    return -1;
	}
	mmod->state = MMS_SUBST;
	vdebug(8,LA_TARGET,LF_TARGET,
	       "(was tmp) memmod 0x%"PRIxADDR" (p 0x%"PRIxADDR")"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->paddr,tid);
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
	       "(was already) memmod 0x%"PRIxADDR" (p 0x%"PRIxADDR")"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->paddr,tid);
	mmod->owner = tthread;
	return 0;
    case MMS_SUBST:
	rc = target_write_addr(target,addr,mmod->orig_len,mmod->orig);
	if (rc != mmod->orig_len) {
	    verror("could not restore orig memory at 0x%"PRIxADDR"!\n",addr);
	    return -1;
	}
	mmod->state = MMS_ORIG;
	vdebug(8,LA_TARGET,LF_TARGET,
	       "(was set) memmod 0x%"PRIxADDR" (p 0x%"PRIxADDR")"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->paddr,tid);
	mmod->owner = tthread;
	return 0;
    case MMS_TMP:
	if (mmod->tmp) {
	    free(mmod->tmp);
	    mmod->tmp = NULL;
	    mmod->tmp_len = 0;
	}
	rc = target_write_addr(target,addr,mmod->orig_len,mmod->orig);
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
	       "(was tmp) memmod 0x%"PRIxADDR" (p 0x%"PRIxADDR")"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->paddr,tid);
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
	       "(was set) memmod 0x%"PRIxADDR" (p 0x%"PRIxADDR")"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->paddr,tid);
	break;
    case MMS_ORIG:
	new = malloc(code_len);
	new_len = code_len;
	memcpy(new,code,code_len);
	vdebug(8,LA_TARGET,LF_TARGET,
	       "(was orig) memmod 0x%"PRIxADDR" (p 0x%"PRIxADDR")"
	       " tid %"PRIiTID"\n",
	       mmod->addr,mmod->paddr,tid);
	break;
    default:
	verror("unknown memmod state %d!\n",mmod->state);
	errno = EINVAL;
	return -1;
    }

    rc = target_write_addr(target,addr,new_len,new);
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
