#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>

#include <glib.h>

#include "common.h"
#include "target_api.h"
#include "probe_api.h"
#include "target_linux_userproc.h"

/**
 ** This is a simple program that probes Linux userspace processes via
 ** the ptrace driver.  Skip on down to main() so you get an idea of
 ** what's going on; then read through the rest as necessary.
 **/

/*
 * Globals.
 */
struct target *target = NULL;
GHashTable *probes = NULL;

int needtodie = 0;
int needtodie_exitcode = 0;

void cleanup_probes() {
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;

    target_pause(target);

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

    if (cleaning)
	return;
    cleaning = 1;

    cleanup_probes();

    if (target) {
	target_close(target);
	target_finalize(target);
	target = NULL;
    }
}

void sigh(int signo) {
    needtodie = 1;
    needtodie_exitcode = 0;
    if (target_monitor_handling_exception(target))
	target_monitor_schedule_interrupt(target);
    else {
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

    /* Grab the symbol associated with the probe. */
    bsymbol = probe_symbol(probe);

    /* bsymbols are wrappers for the underlying symbol; get that. */
    symbol = bsymbol_get_symbol(bsymbol);

    /* Get the current value table: the current values for this probe hit. */
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

    /* Loop through and print the values by stringifying them. */
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

    /*
     * Print the return value using the special name, the macro
     * PROBE_VALUE_NAME_RETURN .
     */
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

    /* Print a dump of the current thread info, like registers. */
    fputs("[",stdout);
    if (target_thread_snprintf(target,tid,buf,sizeof(buf),
			       2,":","=") < 0) 
	fprintf(stdout,"tid=%"PRIiTID"",tid);
    else
	fprintf(stdout,"%s",buf);

    /* Unwind the current thread and print it too. */
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

    /*
     * Return!  Be careful what you return from probe handlers -- some
     * return values will cause the probe to be removed!!!
     */
    return retval;
}

int main(int argc,char **argv) {
    char targetstr[128];
    struct bsymbol *bsymbol;
    struct probe *probe;
    char *name;

    struct target_spec tspec;
    struct linux_userproc_spec luspec;

    /* Init the library; and schedule its cleanup. */
    target_init();
    atexit(target_fini);

    vmi_set_log_level(20);
    vmi_set_warn_level(20);
    vmi_set_log_area_flags(LA_TARGET,LF_T_ALL | LF_LUP);
    vmi_set_log_area_flags(LA_PROBE,LF_P_ALL);

    /* Connect to the process that is the first PID on the command line. */
    memset(&luspec,0,sizeof(luspec));
    luspec.pid = atoi(argv[1]);

    /* Using the PTRACE target and software breakpoints only. */
    memset(&tspec,0,sizeof(tspec));
    tspec.target_id = 1;
    tspec.target_type = TARGET_TYPE_PTRACE;
    /* We could force software breakpoints only if we wanted... */
    //tspec.style = PROBEPOINT_SW;
    tspec.backend_spec = &luspec;

    /*
     * Install some signal handlers so we can safely disconnect from the
     * target process!
     */
    signal(SIGINT,sigh);
    signal(SIGQUIT,sigh);
    signal(SIGABRT,sigh);
    signal(SIGSEGV,sigh);
    signal(SIGPIPE,sigh);
    signal(SIGALRM,sigh);
    signal(SIGTERM,sigh);

    /*
     * Create a target object based on our tspec.  This creates a
     * detached target object that is ready to be attached via
     * target_open().
     */
    target = target_instantiate(&tspec,NULL);
    if (!target) {
	fprintf(stderr,"could not instantiate target!\n");
	exit(-1);
    }
    /*
     * Get a descriptive name for the target.
     */
    target_snprintf(target,targetstr,sizeof(targetstr));

    /*
     * Attach to the target program.  This leaves the target program
     * paused.
     */
    if (target_open(target)) {
	fprintf(stderr,"could not open %s!\n",targetstr);
	exit(-4);
    }

    /*
     * Track the probes we are going to create so we can safely remove
     * them on exit or detach.  If we don't remove them, we will
     * probably crash the target program!
     */
    probes = g_hash_table_new(g_direct_hash,g_direct_equal);

    /*
     * Look up a symbol!
     */
    name = argv[2];
    bsymbol = target_lookup_sym(target,name,NULL,NULL,SYMBOL_TYPE_FLAG_NONE);
    if (!bsymbol) {
	fprintf(stderr,"could not lookup symbol %s; aborting!\n",name);
	cleanup();
	exit(-3);
    }

    /*
     * Place a value probe on the symbol.  If this is a function, the
     * value probe will collect the function arguments when the function
     * is entered; and on return from the function, it will collect the
     * return value.  You can get all these values, stringified, in a
     * GHashTable, like we do in our probe handler above!
     */
    probe = probe_value_symbol(target,TID_GLOBAL,bsymbol,
			       handler,handler,NULL);
    if (!probe) {
	fprintf(stderr,"could not place value probe on %s; aborting!\n",
		name);
	cleanup();
	exit(-3);
    }

    /* Track it. */
    g_hash_table_insert(probes,name,probe);

    /*
     * Currently, the target library's symbol wrappers are
     * reference-counted.  That means you have to release them when you
     * are done with them.
     */
    bsymbol_release(bsymbol);

    if (g_hash_table_size(probes) == 0) {
	fprintf(stderr,"No symbols to probe; exiting!\n");
	cleanup();
	exit(-1);
    }

    /*
     * The target was paused after instantiation; we have to resume it
     * now that we've registered probes.
     */
    target_resume(target);

    fprintf(stdout,"Starting Probing!\n");
    fflush(stdout);

    /*
     * A basic handling loop.
     */
    while (1) {
	/*
	 * target_monitor() only returns when there is a problem it
	 * can't handle, or when the target is exiting or is otherwise
	 * no longer available.  In other words, it doesn't return if
	 * one of your probes is hits.
	 */
	target_status_t tstat = target_monitor(target);

	if (tstat == TSTATUS_INTERRUPTED) {
	    /*
	     * Check if we were interrupted and need to die and exit
	     * (i.e., on SIGINT!).
	     */
	    if (needtodie) {
		/*
		 * Pause the target before we remove its probes, of
		 * course!  cleanup_probes() does this too, but just so
		 * you know...
		 */
		target_pause(target);
		cleanup_probes();
		cleanup();
		exit(needtodie_exitcode);
	    }

	    target_resume(target);
	}
	else if (tstat == TSTATUS_PAUSED) {
	    /*
	     * If the target is left in a paused state, there was an
	     * internal problem bad enough, or an unrecognized or
	     * unsupported exception (like a breakpoint we didn't
	     * place!) that the driver couldn't handle.  You have to do
	     * your best in this case... you can always just try to
	     * resume.
	     */
	    fflush(stderr);
	    fflush(stdout);
	    vwarn("target %s interrupted at 0x%"PRIxREGVAL"; trying resume!\n",
		  targetstr,target_read_creg(target,TID_GLOBAL,CREG_IP));

	    if (target_resume(target)) {
		fprintf(stderr,"could not resume target\n");
		cleanup();
		exit(-16);
	    }
	}
	else if (tstat == TSTATUS_EXITING) {
	    /*
	     * A clean exit is to remove probes!
	     */
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
	    /*
	     * Then when it's done, cleanup.
	     */
	    fflush(stderr);
	    fflush(stdout);

	    fprintf(stdout,"target %s exited, cleaning up.\n",targetstr);

	    cleanup();
	    goto out;
	}
	else {
	    /*
	     * Just in case there's something else, error and cleanup.
	     */
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
    cleanup();

 out:
    fflush(stderr);
    fflush(stdout);
    exit(0);
}
