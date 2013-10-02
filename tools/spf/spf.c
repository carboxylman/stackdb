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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <argp.h>

#include "log.h"
#include "glib_wrapper.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"
#include "target_os.h"

#include "probe_api.h"
#include "probe.h"
#include "alist.h"
#include "list.h"

/*
 * Private vdebug flags for LA_USER for us.
 */
#define LF_U_CFG   1 << 1
#define LF_U_PROBE 1 << 2

/*
 * Types.
 */
typedef enum {
    SPF_ACTION_PRINT   = 1,
    SPF_ACTION_ABORT   = 2,
    SPF_ACTION_REPORT  = 3,
    SPF_ACTION_EXIT    = 4,
    SPF_ACTION_ENABLE  = 5,
    SPF_ACTION_DISABLE = 6,
    SPF_ACTION_REMOVE  = 7,
} spf_action_type_t;

struct spf_action {
    spf_action_type_t atype;

    union {
	struct {
	    char rt;
	    char *tn;
	    int tid;
	    char *rv;
	    char *msg;
	    int ttctx;
	} report;
	struct {
	    long int retval;
	} abort;
	struct {
	    long int retval;
	} exit;
	struct {
	    char *id;
	} enable;
	struct {
	    char *id;
	} disable;
	struct {
	    char *id;
	} remove;
    };
};

#define WHEN_PRE	0
#define WHEN_POST	1

struct spf_filter {
    char *id;

    char *symbol;
    struct bsymbol *bsymbol;
    /* When it's applied; pre or post. */
    int when;
    uint8_t disable:1;
    /*
     * symbol value regexps
     */
    struct target_nv_filter *pf;
    /*
     * tid, ptid, tidhier^, uid, gid, name, namehier^...
     */
    struct target_nv_filter *ttf;
    GSList *actions;
};

struct spf_config {
    GSList *spf_filter_list;
};

struct spf_argp_state {
    int argc;
    char **argv;
    char *config_file;
    int config_file_fatal;
    int use_os_syscall_probes;
    char *overlay_name_or_id;
    struct target_spec *overlay_spec;
};

/*
 * Globals.
 */
struct target *target = NULL;
struct target *otarget = NULL;
struct target *rtarget;
struct spf_config *config = NULL;
struct spf_argp_state opts;

GHashTable *sprobes = NULL;
GHashTable *fprobes = NULL;

int needreload = 0;
int needtodie = 0;
int needtodie_exitcode = 0;

int have_syscall_table = 0;
int result_counter = 0;

/* A few prototypes. */
struct spf_config *load_config_file(char *file);
int apply_config_file(struct spf_config *config);
void reload_config_file(void);
void spf_action_free(struct spf_action *spfa);
void spf_filter_free(struct spf_filter *spff);
void spf_config_free(struct spf_config *config);


void cleanup_probes() {
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;

    target_pause(target);

    if (fprobes) {
	g_hash_table_iter_init(&iter,fprobes);
	while (g_hash_table_iter_next(&iter,
				      (gpointer)&key,
				      (gpointer)&probe)) {
	    probe_unregister(probe,1);
	    probe_free(probe,1);
	}
	g_hash_table_destroy(fprobes);
	fprobes = NULL;
    }
    if (sprobes) {
	g_hash_table_iter_init(&iter,sprobes);
	while (g_hash_table_iter_next(&iter,
				      (gpointer)&key,
				      (gpointer)&probe)) {
	    probe_unregister(probe,1);
	    probe_free(probe,1);
	}
	g_hash_table_destroy(sprobes);
	sprobes = NULL;
    }
}

target_status_t cleanup() {
    target_status_t retval = TSTATUS_DONE;

    cleanup_probes();

    if (otarget) {
	target_close(otarget);
	target_free(otarget);
	otarget = NULL;
    }
    if (target) {
	retval = target_close(target);
	target_free(target);
	target = NULL;
    }

    return retval;
}

void sigr(int signo) {
    needreload = 1;
    if (target_is_monitor_handling(target))
	target_monitor_schedule_interrupt(target);
    else {
	target_pause(target);
	reload_config_file();
	target_resume(target);
    }
    signal(signo,sigr);
}

void sigh(int signo) {
    needtodie = 1;
    needtodie_exitcode = 0;
    if (target_is_monitor_handling(target))
	target_monitor_schedule_interrupt(target);
    else {
	cleanup();
	exit(needtodie_exitcode);
    }
    signal(signo,sigh);
}

result_t handler(int when,struct probe *probe,tid_t tid,void *data,
		 struct probe *trigger,struct probe *base) {
    GHashTableIter iter;
    gpointer kp,vp;
    char vstrbuf[1024];
    struct value *v;
    GHashTable *vt;
    struct bsymbol *bsymbol;
    struct symbol *symbol;
    int i;
    int rc;
    struct spf_filter *spff = (struct spf_filter *)data;
    GSList *gsltmp;
    struct spf_action *spfa;
    struct probe *fprobe;
    result_t retval = RESULT_SUCCESS;

    /*
     * Do all the actions.
     */
    v_g_slist_foreach(spff->actions,gsltmp,spfa) {
	if (spfa->atype == SPF_ACTION_ABORT) {
	    /*
	     * Action has to be registered on the base probe!!
	     */
	    struct action *action = action_return(spfa->abort.retval);
	    if (!action) {
		verror("probe %s: could not create action on probe %s !\n",
		       probe_name(probe),probe_name(base));
	    }
	    else if (action_sched(base,action,ACTION_ONESHOT,NULL,NULL)) {
		verror("probe %s: could not schedule action on probe %s!\n",
		       probe_name(probe),probe_name(base));
		action_release(action);
	    }
	    else {
		vdebug(5,LA_USER,LF_U_PROBE,
		       "probe %s: scheduled return action on probe %s\n",
		       probe_name(probe),probe_name(base));
		action_release(action);
	    }
	}
	else if (spfa->atype == SPF_ACTION_ENABLE) {
	    /* Check if it's us.  No need to waste a hashtable lookup. */
	    if (strcmp(spfa->enable.id,probe_name(probe)) == 0) 
		fprobe = probe;
	    else 
		fprobe = (struct probe *)				\
		    g_hash_table_lookup(fprobes,spfa->enable.id);
	    if (!fprobe) {
		vwarn("probe %s: cannot enable nonexisting filter probe %s!\n",
		      probe_name(probe),spfa->enable.id);
	    }
	    else {
		probe_enable(fprobe);
		vdebug(5,LA_USER,LF_U_PROBE,
		       "probe %s: enabled filter probe %s\n",
		       probe_name(probe),spfa->enable.id);
	    }
	}
	else if (spfa->atype == SPF_ACTION_DISABLE) {
	    /* Check if it's us.  No need to waste a hashtable lookup. */
	    if (strcmp(spfa->disable.id,probe_name(probe)) == 0) 
		fprobe = probe;
	    else 
		fprobe = (struct probe *) \
		    g_hash_table_lookup(fprobes,spfa->disable.id);
	    if (!fprobe) {
		vwarn("probe %s: cannot enable nonexisting filter probe %s!\n",
		      probe_name(probe),spfa->disable.id);
	    }
	    else {
		probe_disable(fprobe);
		vdebug(5,LA_USER,LF_U_PROBE,"probe %s: disabled probe %s\n",
		       probe_name(probe),spfa->disable.id);
	    }
	}
	else if (spfa->atype == SPF_ACTION_REMOVE) {
	    /* Check if it's us -- to remove self we have to return special! */
	    if (strcmp(spfa->remove.id,probe_name(probe)) == 0) {
		vdebug(5,LA_USER,LF_U_PROBE,"probe %s: removing self!\n",
		       probe_name(probe));
		retval = RESULT_ABORT;
	    }
	    else { 
		fprobe = (struct probe *) \
		    g_hash_table_lookup(fprobes,spfa->remove.id);
		if (!fprobe) {
		    vwarn("probe %s: cannot remove nonexisting filter probe %s!\n",
			  probe_name(probe),spfa->remove.id);
		}
		else {
		    probe_free(fprobe,0);
		    vdebug(5,LA_USER,LF_U_PROBE,"probe %s: removed probe %s\n",
			   probe_name(probe),spfa->remove.id);
		}
	    }
	}
	else if (spfa->atype == SPF_ACTION_EXIT) {
	    /*
	     * Have to schedule a monitor interrupt to exit!
	     */
	    if (target_is_monitor_handling(target)) {
		target_monitor_schedule_interrupt(target);
		needtodie = 1;
		needtodie_exitcode = spfa->exit.retval;
		vdebug(5,LA_USER,LF_U_PROBE,"probe %s: scheduled exit with %d!\n",
		       probe_name(probe),spfa->exit.retval);
	    }
	    else {
		verror("probe %s: target is in a prehandler but not monitoring -- BUG!\n",
		       probe_name(probe));
	    }
	}
	else if (spfa->atype == SPF_ACTION_REPORT) {
	    ++result_counter;

	    bsymbol = probe->bsymbol;
	    symbol = bsymbol_get_symbol(bsymbol);

	    vt = probe_value_get_table(trigger,tid);
	    if (!vt) {
		vwarn("probe %s: could not get values from probe %s"
		      " (tid %"PRIiTID")!\n",
		      probe_name(probe),probe_name(trigger),tid);
	    }

	    fflush(stderr);
	    fflush(stdout);

	    fprintf(stdout,"RESULT(%c:%d): %s (%d) %s %s (",
		    spfa->report.rt,result_counter,
		    spfa->report.tn ? spfa->report.tn : "",
		    spfa->report.tid,spfa->report.rv ? spfa->report.rv : "",
		    spfa->report.msg ? spfa->report.msg : "");
	    /* Now print the values... */
	    if (vt) {
		i = 0;
		g_hash_table_iter_init(&iter,vt);
		while (g_hash_table_iter_next(&iter,&kp,&vp)) {
		    if (i > 0)
			fprintf(stdout,",");
		    v = (struct value *)vp;
		    rc = value_snprintf(v,vstrbuf,sizeof(vstrbuf));
		    if (rc > 0)
			fprintf(stdout,"%s=%s",(char *)kp,vstrbuf);
		    else
			fprintf(stdout,"%s=?",(char *)kp);
		    ++i;
		}
	    }
	    /* XXX: print target thread context once we have it */
	    fprintf(stdout,")\n");
	    fflush(stdout);
	}
	else if (spfa->atype == SPF_ACTION_PRINT) {
	    bsymbol = probe->bsymbol;
	    symbol = bsymbol_get_symbol(bsymbol);

	    vt = probe_value_get_table(trigger,tid);
	    if (!vt) {
		vwarn("probe %s: could not get values from probe %s"
		      " (tid %"PRIiTID")!\n",
		      probe_name(probe),probe_name(trigger),tid);
	    }

	    fflush(stderr);
	    fflush(stdout);

	    if (SYMBOL_IS_FUNCTION(symbol))
		fprintf(stdout,"%s (",symbol_get_name(symbol));
	    if (vt) {
		i = 0;
		g_hash_table_iter_init(&iter,vt);
		while (g_hash_table_iter_next(&iter,&kp,&vp)) {
		    if (strcmp((char *)kp,PROBE_VALUE_NAME_RETURN) == 0)
			continue;
		    if (i > 0)
			fprintf(stdout,",");
		    v = (struct value *)vp;
		    rc = value_snprintf(v,vstrbuf,sizeof(vstrbuf));
		    if (rc > 0)
			fprintf(stdout,"%s = %s",(char *)kp,vstrbuf);
		    else
			fprintf(stdout,"%s = ?",(char *)kp);
		    ++i;
		}
	    }
	    else {
		if (SYMBOL_IS_FUNCTION(symbol))
		    fprintf(stdout,"?");
		else
		    fprintf(stdout," = ?");
	    }
	    if (SYMBOL_IS_FUNCTION(symbol)) {
		fprintf(stdout,")");
		if (vt) {
		    v = (struct value *) \
			g_hash_table_lookup(vt,PROBE_VALUE_NAME_RETURN);
		    if (v) {
			rc = value_snprintf(v,vstrbuf,sizeof(vstrbuf));
			if (rc > 0)
			    fprintf(stdout," = %s",vstrbuf);
			else
			    fprintf(stdout," = ?");
		    }
		}
	    }
	    /* Thread context. */
	    if (target_thread_tostring(target,tid,1,vstrbuf,sizeof(vstrbuf)))
		fprintf(stdout,"(%s)",vstrbuf);
	    fprintf(stdout,"\n");
	    fflush(stdout);
	}
	else {
	    verror("probe %s: bad action type %d -- BUG!\n",
		   probe_name(probe),spfa->atype);
	}
    }

    return retval;
}

result_t pre_handler(struct probe *probe,tid_t tid,void *data,
		     struct probe *trigger,struct probe *base) {
    return handler(WHEN_PRE,probe,tid,data,trigger,base);
}

result_t post_handler(struct probe *probe,tid_t tid,void *data,
		      struct probe *trigger,struct probe *base) {
    return handler(WHEN_POST,probe,tid,data,trigger,base);
}

#define SPF_CONFIGFILE_FATAL  0x200000
#define SPF_OS_SYSCALL_PROBES 0x200001

struct argp_option spf_argp_opts[] = {
    { "overlay",'V',"<name_or_id>:<spec_opts>",0,"Lookup name or id as an overlay target once the main target is instantiated, and try to open it.  All spec_opts (normal target/dwdebug opts) then apply to the overlay target.",0 },
    { "config-file",'C',"<FILE>",0,"An SPF config file.",0 },
    { "config-file-fatal",SPF_CONFIGFILE_FATAL,NULL,0,
      "Make errors while applying runtime updates (via USR2) to the config file fatal.",0 },
    { "use-os-syscall-probes",SPF_OS_SYSCALL_PROBES,NULL,0,
      "Try to use target_os_syscall probes if symbol is a syscall and target is an OS.",0 },
    { 0,0,0,0,0,0 },
};

error_t spf_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct spf_argp_state *opts = \
	(struct spf_argp_state *)target_argp_driver_state(state);
    struct array_list *argv_list;
    char *argptr;
    char *nargptr;
    char *vargptr;
    int inesc;
    int inquote;
    int quotechar;

    switch (key) {
    case ARGP_KEY_ARG:
	return ARGP_ERR_UNKNOWN;
    case ARGP_KEY_ARGS:
	/* Eat all the remaining args. */
	if (state->quoted > 0)
	    opts->argc = state->quoted - state->next;
	else
	    opts->argc = state->argc - state->next;
	if (opts->argc > 0) {
	    opts->argv = calloc(opts->argc,sizeof(char *));
	    memcpy(opts->argv,&state->argv[state->next],opts->argc*sizeof(char *));
	    state->next += opts->argc;
	}
	return 0;
    case ARGP_KEY_INIT:
	target_driver_argp_init_children(state);
	return 0;
    case ARGP_KEY_END:
    case ARGP_KEY_NO_ARGS:
    case ARGP_KEY_SUCCESS:
	return 0;
    case ARGP_KEY_ERROR:
    case ARGP_KEY_FINI:
	return 0;
    case SPF_CONFIGFILE_FATAL:
	opts->config_file_fatal = 1;
	break;
    case SPF_OS_SYSCALL_PROBES:
	opts->use_os_syscall_probes = 1;
	break;
    case 'C':
	opts->config_file = arg;
	break;
    case 'V':
	/*
	 * We need to split the <name_or_id>:<spec> part; then split
	 * <spec> into an argv.  Simple rules: \ escapes the next char;
	 * space not in ' or " causes us to end the current argv[i] and
	 * start the next one.
	 */
	argptr = index(arg,':');
	if (!argptr) {
	    verror("bad overlay spec!\n");
	    return EINVAL;
	}
	argv_list = array_list_create(32);
	array_list_append(argv_list,"dumptarget_overlay");

	opts->overlay_name_or_id = arg;
	*argptr = '\0';
	++argptr;

	while (*argptr == ' ')
	    ++argptr;

	inesc = 0;
	inquote = 0;
	quotechar = 0;
	nargptr = argptr;
	vargptr = argptr;
	while (*argptr != '\0') {
	    if (*argptr == '\\') {
		if (inesc) {
		    inesc = 0;
		    *nargptr = '\\';
		    ++nargptr;
		}
		else {
		    /* Don't copy the escape char. */
		    inesc = 1;
		    ++argptr;
		    continue;
		}
	    }
	    else if (inesc) {
		inesc = 0;
		/* Just copy it. */
		*nargptr = *argptr;
		++nargptr;
	    }
	    else if (inquote && *argptr == quotechar) {
		/* Ended the quoted sequence; don't copy quotes. */
		inquote = 0;
		quotechar = 0;
		++argptr;
		continue;
	    }
	    else if (*argptr == '\'' || *argptr == '"') {
		inquote = 1;
		quotechar = *argptr;
		++argptr;
		continue;
	    }
	    else if (!inquote && *argptr == ' ') {
		*nargptr = *argptr = '\0';
		if (vargptr) {
		    array_list_append(argv_list,vargptr);
		    //printf("vargptr (%p) = '%s'\n",vargptr,vargptr);
		    vargptr = NULL;
		}
		vargptr = NULL;
		nargptr = ++argptr;
		continue;
	    }
	    else {
		if (!vargptr)
		    vargptr = nargptr;

		*nargptr = *argptr;
		++nargptr;
	    }

	    /* Default increment. */
	    ++argptr;
	}
	if (vargptr) {
	    *nargptr = '\0';
	    array_list_append(argv_list,vargptr);
	    //printf("vargptr (%p) = '%s'\n",vargptr,vargptr);
	}
	array_list_append(argv_list,NULL);

	opts->overlay_spec = target_argp_driver_parse(NULL,NULL,
						      array_list_len(argv_list) - 1,
						      (char **)argv_list->list,
						      TARGET_TYPE_XEN_PROCESS,0);
	if (!opts->overlay_spec) {
	    verror("could not parse overlay spec!\n");
	    array_list_free(argv_list);
	    return EINVAL;
	}

	array_list_free(argv_list);
	break;

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp spf_argp = {
    spf_argp_opts,spf_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};

int main(int argc,char **argv) {
    target_status_t tstat;
    struct target_spec *tspec;
    char targetstr[128];
    int i;
    struct bsymbol *bsymbol;
    int oid;
    tid_t otid;
    char *tmp = NULL;
    struct probe *sprobe, *fprobe;
    char *name, *context;
    char *str;
    char namebuf[128];
    struct target_nv_filter *pre_pf, *post_pf;
    char *pre_filter, *post_filter;
    struct target_os_syscall *syscall;

    target_init();
    atexit(target_fini);

    memset(&opts,0,sizeof(opts));

    tspec = target_argp_driver_parse(&spf_argp,&opts,argc,argv,
				     TARGET_TYPE_PTRACE | TARGET_TYPE_XEN,1);

    if (!tspec) {
	verror("could not parse target arguments!\n");
	exit(-1);
    }

    if (opts.config_file) {
	config = load_config_file(opts.config_file);
	if (!config) {
	    verror("could not read config file %s!\n",opts.config_file);
	    exit(-11);
	}
    }

    rtarget = target = target_instantiate(tspec,NULL);
    if (!target) {
	verror("could not instantiate target!\n");
	exit(-1);
    }
    target_tostring(target,targetstr,sizeof(targetstr));

    if (target_open(target)) {
	fprintf(stderr,"could not open %s!\n",targetstr);
	exit(-4);
    }

    /*
     * Load an overlay target, if there is one.
     */
    if (opts.overlay_name_or_id && opts.overlay_spec) {
	errno = 0;
	oid = (int)strtol(opts.overlay_name_or_id,&tmp,0);
	if (errno || tmp == opts.overlay_name_or_id)
	    otid = 
		target_lookup_overlay_thread_by_name(target,
						     opts.overlay_name_or_id);
	else
	    otid = target_lookup_overlay_thread_by_id(target,oid);
	if (otid < 0) {
	    verror("could not find overlay thread '%s', exiting!\n",
		   opts.overlay_name_or_id);
	    cleanup();
	    exit(-111);
	}
	otarget = target_instantiate_overlay(target,otid,opts.overlay_spec);
	if (!otarget) {
	    verror("could not instantiate overlay target '%s'!\n",
		   opts.overlay_name_or_id);
	    cleanup();
	    exit(-112);
	}

	if (target_open(otarget)) {
	    fprintf(stderr,"could not open overlay target!\n");
	    cleanup();
	    exit(-114);
	}

	target_tostring(target,targetstr,sizeof(targetstr));

	rtarget = otarget;
    }

    signal(SIGINT,sigh);
    signal(SIGQUIT,sigh);
    signal(SIGABRT,sigh);
    signal(SIGSEGV,sigh);
    signal(SIGPIPE,sigh);
    signal(SIGALRM,sigh);
    signal(SIGTERM,sigh);

    signal(SIGHUP,sigr);
    signal(SIGUSR1,sigr);
    signal(SIGUSR2,sigr);

    sprobes = g_hash_table_new(g_direct_hash,g_direct_equal);
    fprobes = g_hash_table_new(g_direct_hash,g_direct_equal);

    if (opts.use_os_syscall_probes && rtarget->kind == TARGET_KIND_OS) {
	if (target_os_syscall_table_load(rtarget))
	    vwarn("could not load the syscall table; target_os_syscall probes"
		  " will not be available!\n");
	else
	    have_syscall_table = 1;
    }

    if (opts.argc > 0) {
	for (i = 0; i < opts.argc; ++i) {
	    pre_filter = post_filter = context = NULL;
	    name = str = opts.argv[i];
	    while (*str != '\0') {
		if (*str == ':' && *(str+1) == ':') {
		    *str = '\0';
		    str += 2;
		    break;
		}
		++str;
	    }
	    if (*str != '\0') {
		if (*str == ':')
		    pre_filter = NULL;
		else
		    pre_filter = str;
	    }
	    while (*str != '\0') {
		if (*str == ':' && *(str+1) == ':') {
		    *str = '\0';
		    str += 2;
		    break;
		}
		++str;
	    }
	    if (*str != '\0') {
		if (*str == ':')
		    post_filter = NULL;
		else
		    post_filter = str;
	    }
	    while (*str != '\0') {
		if (*str == ':' && *(str+1) == ':') {
		    *str = '\0';
		    str += 2;
		    break;
		}
		++str;
	    }
	    if (*str != '\0')
		context = str;

	    sprobe = (struct probe *)g_hash_table_lookup(sprobes,name);
	    if (!sprobe) {
		/*
		 * Create a probe on that symbol:
		 */

		if (opts.use_os_syscall_probes && have_syscall_table) {
		    syscall = target_os_syscall_lookup_name(rtarget,name);
		    if (syscall) {
			sprobe = \
			    target_os_syscall_probe(rtarget,TID_GLOBAL,syscall,
						    probe_do_sink_pre_handlers,
						    probe_do_sink_post_handlers,
						    NULL);
			if (!sprobe) {
			    verror("could not place syscall value probe on %s;"
				   " aborting!\n",name);
			    cleanup();
			    exit(-5);
			}
		    }
		}

		if (!sprobe) {
		    bsymbol = target_lookup_sym(rtarget,name,NULL,NULL,
						SYMBOL_TYPE_FLAG_NONE);
		    if (!bsymbol) {
			verror("could not lookup symbol %s; aborting!\n",name);
			cleanup();
			exit(-3);
		    }
		    sprobe = probe_value_symbol(rtarget,TID_GLOBAL,bsymbol,
						probe_do_sink_pre_handlers,
						probe_do_sink_post_handlers,NULL);
		    if (!sprobe) {
			verror("could not place value probe on %s; aborting!\n",
			       name);
			cleanup();
			exit(-3);
		    }
		}

		g_hash_table_insert(sprobes,name,sprobe);
	    }

	    /* Create either an empty filter probe or parse the filter! */
	    if (pre_filter) {
		pre_pf = target_nv_filter_parse(pre_filter);
		if (!pre_pf) {
		    verror("could not parse pre_filter '%s'!\n",pre_filter);
		    cleanup();
		    exit(-4);
		}
	    }
	    else 
		pre_pf = NULL;
	    if (post_filter) {
		post_pf = target_nv_filter_parse(post_filter);
		if (!post_pf) {
		    verror("could not parse post_filter '%s'!\n",post_filter);
		    cleanup();
		    exit(-4);
		}
	    }
	    else 
		post_pf = NULL;

	    snprintf(namebuf,sizeof(namebuf),"filter_%s_%d",name,i);
	    fprobe = probe_create_filtered(target,TID_GLOBAL,NULL,namebuf,
					   pre_handler,pre_pf,
					   post_handler,post_pf,NULL,NULL,0,1);

	    probe_register_source(fprobe,sprobe);

	    g_hash_table_insert(fprobes,namebuf,fprobe);
	}
    }
    else if (!opts.config_file) {
	/* Try the default config file. */
	if (access("spf.conf",R_OK)) {
	    verror("Must supply some symbols to probe!\n");
	    cleanup();
	    exit(-5);
	}
	else {
	    opts.config_file = strdup("spf.conf");
	    
	    config = load_config_file(opts.config_file);
	    if (!config) {
		verror("could not read default config file %s!\n",
		       opts.config_file);
		exit(-11);
	    }
	}
    }

    /* Now apply the config file.  Always make the first application fatal. */
    int oldfatal = opts.config_file_fatal;
    opts.config_file_fatal = 1;
    if (apply_config_file(config)) {
	verror("could not install config file %s!\n",opts.config_file);
	cleanup();
	exit(-12);
    }
    opts.config_file_fatal = oldfatal;

    if (g_hash_table_size(sprobes) == 0) {
	verror("No symbols to probe; exiting!\n");
	cleanup();
	exit(-1);
    }

    /*
     * The target was paused after instantiation; we have to resume it
     * now that we've registered probes.
     */
    target_resume(target);

    fprintf(stdout,"Starting Symbol Probe Filtering!\n");
    fflush(stdout);

    while (1) {
	tstat = target_monitor(target);
	if (tstat == TSTATUS_INTERRUPTED) {
	    if (needtodie) {
		target_pause(target);
		cleanup_probes();
		target_resume(target);
		cleanup();
		exit(needtodie_exitcode);
	    }
	    if (needreload) 
		reload_config_file();

	    target_resume(target);
	}
	else if (tstat == TSTATUS_PAUSED) {
	    fflush(stderr);
	    fflush(stdout);
	    vwarn("target %s interrupted at 0x%"PRIxREGVAL"; trying resume!\n",
		  targetstr,target_read_creg(target,TID_GLOBAL,CREG_IP));

	    if (target_resume(target)) {
		verror("could not resume target\n");
		tstat = cleanup();
		exit(-16);
	    }
	}
	else if (tstat == TSTATUS_EXITING) {
	    fflush(stderr);
	    fflush(stdout);

	    fprintf(stdout,"target %s exiting, removing probes safely...\n",
		    targetstr);

	    cleanup_probes();

	    if (target_resume(target)) {
		verror("could not resume target!\n");
		tstat = cleanup();
		exit(-16);
	    }
	}
	else if (tstat == TSTATUS_DONE) {
	    fflush(stderr);
	    fflush(stdout);

	    fprintf(stdout,"target %s exited, cleaning up.\n",targetstr);

	    tstat = cleanup();
	    goto out;
	}
	else {
	    fflush(stderr);
	    fflush(stdout);

	    fprintf(stdout,
		    "target %s interrupted at 0x%"PRIxREGVAL
		    " -- bad status (%d), exiting\n",
		    targetstr,target_read_creg(target,TID_GLOBAL,CREG_IP),tstat);

	    goto err;
	}
    }

 err:
    fflush(stderr);
    fflush(stdout);
    tstat = cleanup();

 out:
    fflush(stderr);
    fflush(stdout);
    exit(0);
}

void spf_action_free(struct spf_action *spfa) {
    if (spfa->atype == SPF_ACTION_REPORT) {
	if (spfa->report.tn)
	    free(spfa->report.tn);
	if (spfa->report.rv)
	    free(spfa->report.rv);
	if (spfa->report.msg)
	    free(spfa->report.msg);
    }
    else if (spfa->atype == SPF_ACTION_ENABLE) {
	if (spfa->enable.id)
	    free(spfa->enable.id);
    }
    else if (spfa->atype == SPF_ACTION_DISABLE) {
	if (spfa->disable.id)
	    free(spfa->disable.id);
    }
    else if (spfa->atype == SPF_ACTION_REMOVE) {
	if (spfa->remove.id)
	    free(spfa->remove.id);
    }

    free(spfa);
}

void spf_filter_free(struct spf_filter *spff) {
    GSList *gsltmp;
    struct spf_action *spfa;

    if (spff->id)
	free(spff->id);
    if (spff->symbol)
	free(spff->symbol);
    if (spff->bsymbol)
	bsymbol_release(spff->bsymbol);
    if (spff->pf)
	target_nv_filter_free(spff->pf);
    if (spff->actions) {
	v_g_slist_foreach(spff->actions,gsltmp,spfa) {
	    spf_action_free(spfa);
	}
	g_slist_free(spff->actions);
    }

    free(spff);
}

void spf_config_free(struct spf_config *config) {
    GSList *gsltmp;
    struct spf_filter *spff;

    v_g_slist_foreach(config->spf_filter_list,gsltmp,spff) {
	spf_filter_free(spff);
    }
    g_slist_free(config->spf_filter_list);
}

/*
 * Language is like this.  Single lines of probe filters/actions.
 *
 *  <symbol> [id(<ident>)] [when(pre|post)] [vfilter(<name>=/<regex>/,...)] [cfilter(...)] [action*]
 *  [action] = abort(value) 
 *             | report(rt=(i|f),tn=<tn>,tid=<tid>,rv=<rv>,msg="",ttctx=(self|hier|all),)
 *             | exit(value)
 *             | enable(name) | disable(name)
 *
 * Reports interpreted by the XML server like this:
 *
 *   "RESULT(%c:%d): %ms (%d) %ms \"%m[^\"]\" (%m[^)])",
 *   &rt,&id,&name,&type,&result_value,&msg,&value_str);
 *
 *   rt=(i|f) id=<unique_int> typename typeid result_value "msg" (<meta_kv_pairs>)
 *
 * We often use result_value as a msg subtype field within typename/typeid.
 */

char *_get_next_non_enc_esc(char *s,int c) {
    int wasesc = 0;
    int isesc = 0;
    int isenc = 0;
    int encchar;
    
    while (*s != '\0') {
	wasesc = isesc;
	isesc = 0;
	if (isenc) {
	    if (*s == '\\') {
		if (!wasesc) 
		    isesc = 1;
	    }
	    else if (*s == encchar && !wasesc) {
		encchar = '\0';
		isenc = 0;
	    }
	}
	else if (*s == c) {
	    if (!wasesc)
		break;
	}
	else if (*s == '\\') {
	    if (!wasesc)
		isesc = 1;
	}

	++s;
    }

    if (*s == c)
	return s;
    else
	return NULL;
}

void reload_config_file(void) {
    struct spf_config *newconfig;

    newconfig = load_config_file(opts.config_file);
    if (!newconfig) {
	if (opts.config_file_fatal) {
	    verror("could not reread config file %s!\n",opts.config_file);
	    cleanup();
	    exit(-1);
	}
	else {
	    vwarn("could not reread config file %s; leaving"
		  " existing configuration in place!\n",opts.config_file);
	}
    }
    else {
	apply_config_file(newconfig);
	//spf_config_free(config);
	config = newconfig;
	newconfig = NULL;
	needreload = 0;
    }
}

/*
 * Applies the config file.
 *
 * The easiest thing to do is remove all the filter probes; then see
 * which symbol probes we need to add/remove; then re-add all the
 * filter probes.
 *
 * What happens if we get called while one of our filter probes is
 * running its handler (or the list the probe is on is getting
 * iterated)?
 *
 * Sigh... we're going to have to add this aren't we.  probe_free() will
 * have to schedule a free if the probe is in use...
 */
int apply_config_file(struct spf_config *config) {
    GSList *gsltmp;
    struct spf_filter *spff;
    struct bsymbol *bsymbol;
    GHashTable *needed = NULL;
    GHashTableIter iter;
    gpointer kp,vp;
    struct probe *probe,*sprobe,*fprobe;
    char namebuf[128];
    int i;
    struct target_os_syscall *syscall;

    /* First, destroy all the filter probes. */
    g_hash_table_iter_init(&iter,fprobes);
    while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	probe = (struct probe *)vp;
	probe_free(probe,0);
	g_hash_table_iter_remove(&iter);
    }

    /* Second, build symbol probes for all the probes in the config. */
    needed = g_hash_table_new(g_str_hash,g_str_equal);
    v_g_slist_foreach(config->spf_filter_list,gsltmp,spff) {
	g_hash_table_insert(needed,spff->symbol,NULL);

	if (g_hash_table_lookup(sprobes,spff->symbol))
	    continue;

	/* Create it. */
	bsymbol = target_lookup_sym(rtarget,spff->symbol,NULL,NULL,
				    SYMBOL_TYPE_FLAG_NONE);
	if (!bsymbol) {
	    if (opts.config_file_fatal) {
		verror("could not lookup symbol %s; aborting!\n",spff->symbol);
		cleanup();
		exit(-3);
	    }
	    else {
		vwarn("could not lookup symbol %s; skipping filter!\n",
		      spff->symbol);
		continue;
	    }
	}

	sprobe = NULL;
	if (have_syscall_table) {
	    syscall = target_os_syscall_lookup_name(rtarget,spff->symbol);
	    if (syscall) {
		sprobe = target_os_syscall_probe(rtarget,TID_GLOBAL,syscall,
						 probe_do_sink_pre_handlers,
						 probe_do_sink_post_handlers,
						 NULL);
		if (!sprobe) {
		    if (opts.config_file_fatal) {
			verror("could not place syscall value probe on %s;"
			       " aborting!\n",
			       spff->symbol);
			cleanup();
			exit(-3);
		    }
		    else {
			vwarn("could not place syscall value probe on %s;"
			      " skipping filter!\n",
			      spff->symbol);
			continue;
		    }
		}
	    }
	}

	if (!sprobe) {
	    sprobe = probe_value_symbol(rtarget,TID_GLOBAL,bsymbol,
					probe_do_sink_pre_handlers,
					probe_do_sink_post_handlers,NULL);
	    if (!sprobe) {
		if (opts.config_file_fatal) {
		    verror("could not place value probe on %s; aborting!\n",
			   spff->symbol);
		    cleanup();
		    exit(-3);
		}
		else {
		    vwarn("could not place value probe on %s; skipping filter!\n",
			  spff->symbol);
		    continue;
		}
	    }
	}

	g_hash_table_insert(sprobes,spff->symbol,sprobe);
    }

    /* Third, any sprobe that is *NOT* in needed should be removed. */
    g_hash_table_iter_init(&iter,sprobes);
    while (g_hash_table_iter_next(&iter,&kp,&vp)) {
	if (g_hash_table_lookup_extended(needed,kp,NULL,NULL) == FALSE) {
	    probe_free((struct probe *)vp,0);
	    g_hash_table_iter_remove(&iter);
	}
    }
    g_hash_table_destroy(needed);
    needed = NULL;

    /* Finally, add all the filter probes. */
    v_g_slist_foreach(config->spf_filter_list,gsltmp,spff) {
	g_hash_table_insert(needed,spff->symbol,NULL);

	/* Again, if we failed for any reason to get the symbol, skip here. */
	sprobe = (struct probe *)g_hash_table_lookup(sprobes,spff->symbol);
	if (!sprobe)
	    continue;
	if (!spff->id) {
	    snprintf(namebuf,sizeof(namebuf),"filter_%s_%d",spff->symbol,i);
	    spff->id = strdup(namebuf);
	}
	if (spff->when == WHEN_PRE)
	    fprobe = probe_create_filtered(target,TID_GLOBAL,NULL,spff->id,
					   pre_handler,spff->pf,NULL,NULL,
					   spff->ttf,spff,0,1);
	else
	    fprobe = probe_create_filtered(target,TID_GLOBAL,NULL,spff->id,
					   NULL,NULL,post_handler,spff->pf,
					   spff->ttf,spff,0,1);
	probe_register_source(fprobe,sprobe);

	if (spff->disable)
	    probe_disable(fprobe);

	g_hash_table_insert(fprobes,spff->id,fprobe);
    }

    return 0;
}

/*
 * (Re)reads the configuration file.
 */
struct spf_config *load_config_file(char *file) {
    char *buf;
    char *bufptr;
    char *tbuf;
    int bufsiz = 128;
    int rc = 0;
    FILE *ffile;
    struct spf_filter *spff = NULL;
    struct spf_action *spfa = NULL;
    char *saveptr;
    char *token = NULL, *token2 = NULL;
    char *tptr;
    char errbuf[128];
    long int numval;
    struct spf_config *retval = NULL;
    int spff_count = 0;
    int lineno = 0;

    if (strcmp(file,"-") == 0)
	ffile = stdin;
    else {
	ffile = fopen(file,"r");
	if (!ffile) {
	    verror("could not fopen config file %s: %s\n",file,strerror(errno));
	    return NULL;
	}
    }

    retval = calloc(1,sizeof(*retval));

    /* Read directives line by line. */
    buf = malloc(bufsiz);
    while (1) {
	rc = 0;
	while (1) {
	    errno = 0;
	    tbuf = fgets(buf + rc,bufsiz - rc,ffile);
	    if (tbuf && (rc += strlen(buf + rc)) == (bufsiz - 1) 
		&& buf[bufsiz - 2] != '\n') {
		/* We filled up the buf; malloc more and keep going. */
		tbuf = malloc(bufsiz + 128);
		memcpy(tbuf,buf,bufsiz);
		free(buf);
		buf = tbuf;
		bufsiz += 128;
	    }
	    else if (tbuf && rc < bufsiz) {
		/* We have our line. */
		break;
	    }
	    else if (errno) {
		verror("fgets: %s (aborting filter file read)\n",
		       strerror(errno));
		goto errout;
	    }
	    else {
		/* EOF. */
		free(buf);
		buf = NULL;
		break;
	    }
	}

	if (!buf)
	    break;

	++lineno;
	vdebug(2,LA_USER,LF_U_CFG,"read line %d: '%s'\n",lineno,buf);

	if (*buf == '#')
	    continue;

	if (buf[strlen(buf) - 1] == '\n') {
	    if (*buf == '\n')
		continue;
	    buf[strlen(buf) - 1] = '\0';
	}

	/*
	 * ProbeFilter.
	 */
	if (strncmp(buf,"ProbeFilter",strlen("ProbeFilter")) == 0) {
	    bufptr = buf + strlen("ProbeFilter");
	    while (isspace(*bufptr)) ++bufptr;

	    spff = (struct spf_filter *)calloc(1,sizeof(*spff));
	    /* Default. */
	    spff->when = WHEN_PRE;

	    /*
	     * Parse the line.  We can't use strtok to split it up,
	     * because there are strings and regexps, and we don't want
	     * to place any restrictions on them.  So we just manually
	     * lex it... forgotten too much flex yystuff to do it fast.
	     */

	    /* symbol name */
	    token = bufptr;
	    while (isalnum(*bufptr) || *bufptr == '_') ++bufptr;
	    *bufptr = '\0';
	    spff->symbol = strdup(token);
	    ++bufptr;

	    /* These are all optional; take them in any order. */
	    while (*bufptr != '\0') {
		while (isspace(*bufptr)) ++bufptr;
		if (*bufptr == '\0')
		    goto err;

		token = bufptr;
		while (isalnum(*bufptr) || *bufptr == '_') ++bufptr;
		if (*bufptr == '(') {
		    *bufptr = '\0';
		    ++bufptr;
		}
		else {
		    *bufptr = '\0';
		    ++bufptr;
		    while (isspace(*bufptr)) ++bufptr;
		    if (*bufptr != '(')
			goto err;
		    ++bufptr;
		}

		if (strcmp(token,"id") == 0) {
		    token = bufptr;
		    while (isalnum(*bufptr) || *bufptr == '_') ++bufptr;
		    if (*bufptr != ')')
			goto err;
		    *bufptr = '\0';
		    ++bufptr;
		    if (spff->id)
			goto err;
		    else
			spff->id = strdup(token);
		}
		else if (strcmp(token,"when") == 0) {
		    if (strncmp(bufptr,"pre",strlen("pre")) == 0) {
			spff->when = WHEN_PRE;
			bufptr += strlen("pre");
		    }
		    else if (strncmp(bufptr,"post",strlen("post")) == 0) {
			spff->when = WHEN_POST;
			bufptr += strlen("post");
		    }
		    else
			goto err;
		    if (*bufptr != ')')
			goto err;
		    ++bufptr;
		}
		else if (strcmp(token,"disable") == 0) {
		    if (*bufptr != ')')
			goto err;
		    ++bufptr;

		    spff->disable = 1;
		}
		else if (strcmp(token,"vfilter") == 0) {
		    if (spff->pf)
			goto err;
		    token = bufptr;
		    /* Find the enclosing ')' */
		    int isescaped = 0;
		    char *nextbufptr = NULL;
		    while (*bufptr != '\0') {
			if (*bufptr == '\\') {
			    if (!isescaped)
				isescaped = 1;
			    else 
				isescaped = 0;
			}
			else if (*bufptr == ')' && !isescaped) {
			    nextbufptr = bufptr + 1;
			    *bufptr = '\0';
			    break;
			}
			++bufptr;
		    }
		    if (!nextbufptr)
			goto err;
		    spff->pf = target_nv_filter_parse(token);
		    if (!spff->pf)
			goto err;
		    bufptr = nextbufptr;
		}
		else if (strcmp(token,"tfilter") == 0) {
		    if (spff->ttf)
			goto err;
		    token = bufptr;
		    /* Find the enclosing ')' */
		    int isescaped = 0;
		    char *nextbufptr = NULL;
		    while (*bufptr != '\0') {
			if (*bufptr == '\\') {
			    if (!isescaped)
				isescaped = 1;
			    else 
				isescaped = 0;
			}
			else if (*bufptr == ')' && !isescaped) {
			    nextbufptr = bufptr + 1;
			    *bufptr = '\0';
			    break;
			}
			++bufptr;
		    }
		    if (!nextbufptr)
			goto err;
		    spff->ttf = target_nv_filter_parse(token);
		    if (!spff->ttf)
			goto err;
		    bufptr = nextbufptr;
		}
		else if (strcmp(token,"abort") == 0) {
		    token = bufptr;
		    while (*bufptr == '-' || isdigit(*bufptr)) ++bufptr;
		    if (*bufptr != ')')
			goto err;
		    *bufptr = '\0';
		    ++bufptr;
		    errno = 0;
		    numval = strtol(token,NULL,0);
		    if (errno)
			goto err;

		    spfa = calloc(1,sizeof(*spfa));
		    spfa->atype = SPF_ACTION_ABORT;
		    spfa->abort.retval = numval;

		    spff->actions = g_slist_append(spff->actions,spfa);
		    spfa = NULL;
		}
		else if (strcmp(token,"print") == 0) {
		    if (*bufptr != ')')
			goto err;
		    ++bufptr;

		    spfa = calloc(1,sizeof(*spfa));
		    spfa->atype = SPF_ACTION_PRINT;

		    spff->actions = g_slist_append(spff->actions,spfa);
		    spfa = NULL;
		}
		else if (strcmp(token,"report") == 0) {
		    spfa = calloc(1,sizeof(*spfa));
		    spfa->atype = SPF_ACTION_REPORT;

		    /* Set some defaults. */
		    spfa->report.rt = 'i';

		    /*
		     * XXX: use strtok here ignore the possibility that
		     * the msg field has a comma in it.  Time is not on
		     * my side...
		     */
		    char *nextbufptr = NULL;
		    nextbufptr = _get_next_non_enc_esc(bufptr,')');
		    if (!nextbufptr)
			goto err;
		    *nextbufptr = '\0';
		    ++nextbufptr;
		    token = NULL;
		    token2 = NULL;
		    saveptr = NULL;
		    while ((token = strtok_r((!token) ? bufptr : NULL,",",
					     &saveptr))) {
			tptr = token;
			while (*tptr != '\0') {
			    if (*tptr == '=') {
				*tptr = '\0';
				token2 = ++tptr;
				break;
			    }
			    ++tptr;
			}
			if (!token2)
			    goto err;

			if (strcmp(token,"rt") == 0) {
			    if (*token2 == 'f')
				spfa->report.rt = *token2;
			    else if (*token2 == 'i')
				spfa->report.rt = *token2;
			    else
				goto err;
			}
			else if (strcmp(token,"tn") == 0) {
			    spfa->report.tn = strdup(token2);
			}
			else if (strcmp(token,"tid") == 0) {
			    errno = 0;
			    spfa->report.tid = strtol(token2,NULL,0);
			    if (errno)
				goto err;
			}
			else if (strcmp(token,"rv") == 0) {
			    spfa->report.rv = strdup(token2);
			}
			else if (strcmp(token,"msg") == 0) {
			    spfa->report.msg = strdup(token2);
			}
			else if (strcmp(token,"ttctx") == 0) {
			    if (strcmp(token2,"none") == 0)
				spfa->report.ttctx = 0;
			    else if (strcmp(token2,"self") == 0)
				spfa->report.ttctx = 1;
			    else if (strcmp(token2,"hier") == 0)
				spfa->report.ttctx = 2;
			    else if (strcmp(token2,"all") == 0)
				spfa->report.ttctx = 3;
			    else
				goto err;
			}
			else 
			    goto err;
		    }
		    bufptr = nextbufptr;

		    spff->actions = g_slist_append(spff->actions,spfa);
		    spfa = NULL;
		}
		else if (strcmp(token,"exit") == 0) {
		    token = bufptr;
		    while (*bufptr == '-' || isdigit(*bufptr)) ++bufptr;
		    if (*bufptr != ')')
			goto err;
		    *bufptr = '\0';
		    ++bufptr;
		    errno = 0;
		    numval = strtol(token,NULL,0);
		    if (errno)
			goto err;

		    spfa = calloc(1,sizeof(*spfa));
		    spfa->atype = SPF_ACTION_EXIT;
		    spfa->exit.retval = numval;

		    spff->actions = g_slist_append(spff->actions,spfa);
		    spfa = NULL;
		}
		else if (strcmp(token,"enable") == 0) {
		    token = bufptr;
		    while (isalnum(*bufptr) || *bufptr == '_') ++bufptr;
		    if (*bufptr != ')')
			goto err;
		    *bufptr = '\0';
		    ++bufptr;
		    spfa = calloc(1,sizeof(*spfa));
		    spfa->atype = SPF_ACTION_ENABLE;
		    spfa->enable.id = strdup(token);

		    spff->actions = g_slist_append(spff->actions,spfa);
		    spfa = NULL;
		}
		else if (strcmp(token,"disable") == 0) {
		    token = bufptr;
		    while (isalnum(*bufptr) || *bufptr == '_') ++bufptr;
		    if (*bufptr != ')')
			goto err;
		    *bufptr = '\0';
		    ++bufptr;
		    spfa = calloc(1,sizeof(*spfa));
		    spfa->atype = SPF_ACTION_DISABLE;
		    spfa->disable.id = strdup(token);

		    spff->actions = g_slist_append(spff->actions,spfa);
		    spfa = NULL;
		}
		else if (strcmp(token,"remove") == 0) {
		    token = bufptr;
		    while (isalnum(*bufptr) || *bufptr == '_') ++bufptr;
		    if (*bufptr != ')')
			goto err;
		    *bufptr = '\0';
		    ++bufptr;
		    spfa = calloc(1,sizeof(*spfa));
		    spfa->atype = SPF_ACTION_REMOVE;
		    spfa->remove.id = strdup(token);

		    spff->actions = g_slist_append(spff->actions,spfa);
		    spfa = NULL;
		}
		else 
		    goto err;
	    }

	    retval->spf_filter_list =
		g_slist_append(retval->spf_filter_list,spff);
	    spff = NULL;
	    ++spff_count;
	}
	else {
	    /*
	     * Invalid rule
	     */
	    fprintf(stderr,"ERROR: unknown config directive line %d:\n",lineno);
	    fprintf(stderr,"%s\n", buf);
	    goto errout;
	}
    }

    fclose(ffile);

    if (buf)
	free(buf);

    vdebug(2,LA_USER,LF_U_CFG,"configfile: %d probefilters.\n",spff_count);

    return retval;

 err:
    verror("parse error at line %d col %d: '%.48s ...'\n",
	   lineno,(int)(bufptr - buf),bufptr);

 errout:
    fclose(ffile);

    if (spfa)
	spf_action_free(spfa);
    if (spff)
	spf_filter_free(spff);
    if (retval)
	spf_config_free(retval);

    if (buf)
	free(buf);

    return NULL;
}
