#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>

#include <glib.h>
#include "glib_wrapper.h"

#include "common.h"
#include "target_api.h"
#include "probe_api.h"
#include "target_linux_userproc.h"

/**
 ** This is a more complex program that probes multiple Linux userspace
 ** processes via the ptrace driver.  Skip on down to main() so you get
 ** an idea of what's going on; then read through the rest as necessary.
 **
 ** Also, the comments in this file only address the new things in this
 ** program relative to ptrace.c ; so read those first!
 **/

/*
 * Globals.
 */
GList *targets = NULL;
GHashTable *probes = NULL;

int needtodie = 0;
int needtodie_exitcode = 0;

void cleanup_probes() {
    GList *tmp;
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;
    struct target *target;

    if (targets) {
	v_g_list_foreach(targets,tmp,target) {
	    target_pause(target);
	}
    }

    if (probes) {
	g_hash_table_iter_init(&iter,probes);
	while (g_hash_table_iter_next(&iter,
				      (gpointer)&key,
				      (gpointer)&probe)) {
	    probe_unregister(probe,1);
	    probe_free(probe,1);
	}
	g_hash_table_destroy(probes);
	probes = NULL;
    }
}

void cleanup() {
    static int cleaning = 0;
    GList *tmp;
    struct target *target;

    if (cleaning)
	return;
    cleaning = 1;

    cleanup_probes();

    if (targets) {
	v_g_list_foreach(targets,tmp,target) {
	    target_close(target);
	    target_finalize(target);
	    target = NULL;
	}
    }

    g_list_free(targets);
    targets = NULL;
}

void sigh(int signo) {
    GList *tmp;
    struct target *target;
    int was_handling = 0;

    needtodie = 1;
    needtodie_exitcode = 0;

    if (targets) {
	v_g_list_foreach(targets,tmp,target) {
	    if (target_monitor_handling_exception(target)) {
		target_monitor_schedule_interrupt(target);
		was_handling = 1;
	    }
	}
    }

    if (!was_handling) {
	cleanup();
	exit(needtodie_exitcode);
    }

    signal(signo,sigh);
}

result_t handler(struct probe *probe,tid_t tid,void *data,
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
    result_t retval = RESULT_SUCCESS;
    char buf[1024];
    struct target *target = probe_target(probe);

    bsymbol = probe_symbol(probe);
    symbol = bsymbol_get_symbol(bsymbol);

    vt = probe_value_get_table(probe,tid);
    if (!vt) {
	vwarn("probe %s: could not get values from probe %s"
	      " (tid %"PRIiTID")!\n",
	      probe_name(probe),probe_name(trigger),tid);
    }

    fflush(stderr);
    fflush(stdout);

    if (symbol_type_flags_match(symbol,SYMBOL_TYPE_FLAG_FUNC))
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
	    if (v) {
		rc = value_snprintf(v,vstrbuf,sizeof(vstrbuf));
		if (rc > 0)
		    fprintf(stdout,"%s = %s",(char *)kp,vstrbuf);
		else
		    fprintf(stdout,"%s = ?",(char *)kp);
	    }
	    else
		fprintf(stdout,"%s = ?",(char *)kp);
	    ++i;
	}
    }
    else {
	if (symbol_type_flags_match(symbol,SYMBOL_TYPE_FLAG_FUNC))
	    fprintf(stdout,"?");
	else
	    fprintf(stdout," = ?");
    }
    if (symbol_type_flags_match(symbol,SYMBOL_TYPE_FLAG_FUNC)) {
	fprintf(stdout,")");
	if (vt) {
	    v = (struct value *)					\
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
    fputs(" ",stdout);

    fputs("[",stdout);
    if (target_thread_snprintf(target,tid,buf,sizeof(buf),
			       2,":","=") < 0) 
	fprintf(stdout,"tid=%"PRIiTID"",tid);
    else
	fprintf(stdout,"%s",buf);

    rc = target_unwind_snprintf(buf,sizeof(buf),target,tid,
				TARGET_UNWIND_STYLE_PROG_KEYS,"|",",");
    if (rc < 0)
	fprintf(stdout," backtrace=[error!]");
    else if (rc == 0)
	fprintf(stdout," backtrace=[empty]");
    else
	fprintf(stdout," backtrace=[%s]",buf);

    fprintf(stdout,"]");

    fputs("\n",stdout);
    fflush(stdout);

    return retval;
}

int main(int argc,char **argv) {
    char targetstr[128];
    struct bsymbol *bsymbol;
    struct probe *probe;
    char *name;
    int i;
    int id = 1;
    int pid;
    char *tmp;
    struct target_spec *tspec;
    struct linux_userproc_spec *luspec;
    struct target *target;
    GList *tmplist;

    target_init();
    atexit(target_fini);

    /*
     * Turn on debugging, lots of it!  You can capture it and then
     * later grep it out via 'cat logfile | grep -v ^V | less' or
     * similar.
     */
    vmi_set_log_level(20);
    vmi_set_warn_level(20);
    vmi_set_log_area_flags(LA_TARGET,LF_T_ALL | LF_LUP | LF_P_ALL);

    /*
     * Create targets for each PID specified.  If prefixed with a
     * '<number>:', then use <number> as the ID of the target.  If this
     * is specified, then symbol names to probe can be prefixed with
     * <number> and the probe will only be placed on that target id.
     */
    for (i = 1; i < argc; ++i) {
	/* Default to letting the target lib choose our id. */
	id = -1;

	if (!isdigit(*argv[i])
	    || ((tmp = index(argv[i],':')) && !isdigit(*(tmp + 1))))
	    break;

	tmp = index(argv[i],':');
	if (tmp) {
	    *tmp = '\0';
	    id = atoi(argv[i]);
	    argv[i] = tmp + 1;
	}

	pid = atoi(argv[i]);

	luspec = (struct linux_userproc_spec *)calloc(1,sizeof(*luspec));
	luspec->pid = pid;

	tspec = (struct target_spec *)calloc(1,sizeof(*tspec));
	tspec->target_id = id;
	tspec->target_type = TARGET_TYPE_PTRACE;

	tspec->backend_spec = luspec;

	target = target_instantiate(tspec,NULL);
	if (!target) {
	    fprintf(stderr,
		    "Could not instantiate target for pid %d; aborting!\n",pid);
	    cleanup();
	    exit(-1);
	}
	else
	    targets = g_list_append(targets,target);
    }

    signal(SIGINT,sigh);
    signal(SIGQUIT,sigh);
    signal(SIGABRT,sigh);
    signal(SIGSEGV,sigh);
    signal(SIGPIPE,sigh);
    signal(SIGALRM,sigh);
    signal(SIGTERM,sigh);

    /*
     * v_g_list_foreach is a convenient macro allowing you to loop
     * through a GList quickly.  tmplist is just a placeholder; you
     * don't ever use it.
     */
    v_g_list_foreach(targets,tmplist,target) {
	target_snprintf(target,targetstr,sizeof(targetstr));

	if (target_open(target)) {
	    fprintf(stderr,"could not open %s!\n",targetstr);
	    cleanup();
	    exit(-4);
	}

	fprintf(stdout,"Opened target '%s'.\n",targetstr);
    }

    probes = g_hash_table_new(g_direct_hash,g_direct_equal);

    for ( ; i < argc; ++i) {
	id = -1;

	name = argv[i];
	tmp = index(name,':');
	if (tmp) {
	    *tmp = '\0';
	    id = atoi(name);
	    name = tmp + 1;
	}

	if (id > -1) {
	    /* Lookup the target by id. */
	    target = target_lookup_target_id(id);
	    if (!target) {
		verror("Could not find target with id '%d'; aborting!\n",id);
		cleanup();
		exit(-5);
	    }

	    target_snprintf(target,targetstr,sizeof(targetstr));

	    bsymbol = target_lookup_sym(target,name,NULL,NULL,
					SYMBOL_TYPE_FLAG_NONE);
	    if (!bsymbol) {
		fprintf(stderr,
			"could not lookup symbol %s on target '%s'; aborting!\n",
			name,targetstr);
		cleanup();
		exit(-3);
	    }

	    probe = probe_value_symbol(target,TID_GLOBAL,bsymbol,
				       handler,handler,NULL);
	    if (!probe) {
		fprintf(stderr,"could not place value probe on %s; aborting!\n",
			name);
		cleanup();
		exit(-3);
	    }

	    g_hash_table_insert(probes,name,probe);

	    bsymbol_release(bsymbol);
	}
	else {
	    v_g_list_foreach(targets,tmplist,target) {
		target_snprintf(target,targetstr,sizeof(targetstr));

		bsymbol = target_lookup_sym(target,name,NULL,NULL,
					    SYMBOL_TYPE_FLAG_NONE);
		if (!bsymbol) {
		    fprintf(stderr,
			    "could not lookup symbol %s on target '%s'; aborting!\n",
			    name,targetstr);
		    cleanup();
		    exit(-3);
		}

		probe = probe_value_symbol(target,TID_GLOBAL,bsymbol,
					   handler,handler,NULL);
		if (!probe) {
		    fprintf(stderr,
			    "could not place value probe on %s; aborting!\n",
			    name);
		    cleanup();
		    exit(-3);
		}

		g_hash_table_insert(probes,name,probe);

		bsymbol_release(bsymbol);
	    }
	}
    }

    if (g_hash_table_size(probes) == 0) {
	fprintf(stderr,"No symbols to probe; exiting!\n");
	cleanup();
	exit(0);
    }

    v_g_list_foreach(targets,tmplist,target) {
	target_resume(target);
    }

    fprintf(stdout,"Starting Probing!\n");
    fflush(stdout);

    /*
     * This time, we use polling to monitor the multiple targets!
     */
    while (1) {
	v_g_list_foreach(targets,tmplist,target) {
	    target_snprintf(target,targetstr,sizeof(targetstr));

	    /*
	     * Make the timeout value tiny so we don't leave the
	     * target(s) paused too long after they've hit an exception.
	     * Of course, this can eat up CPU!
	     */
	    struct timeval tv = { 0,50 };
	    target_status_t tstat;

	    tstat = target_poll(target,&tv,NULL,NULL);
	
	    if (tstat == TSTATUS_INTERRUPTED) {
		if (needtodie) {
		    cleanup();
		    exit(needtodie_exitcode);
		}

		target_resume(target);
	    }
	    else if (tstat == TSTATUS_PAUSED) {
		fflush(stderr);
		fflush(stdout);
		vwarn("target %s interrupted at 0x%"PRIxREGVAL";"
		      " trying resume!\n",
		      targetstr,target_read_creg(target,TID_GLOBAL,CREG_IP));

		if (target_resume(target)) {
		    fprintf(stderr,"could not resume target\n");
		    cleanup();
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
		    fprintf(stderr,"could not resume target!\n");
		    cleanup();
		    exit(-16);
		}
	    }
	    else if (tstat == TSTATUS_DONE) {
		fflush(stderr);
		fflush(stdout);

		fprintf(stdout,"target %s exited, cleaning up.\n",targetstr);

		cleanup();
		goto out;
	    }
	}
    }

 err:
    fflush(stderr);
    fflush(stdout);
    cleanup();

 out:
    fflush(stderr);
    fflush(stdout);
    exit(0);
}
