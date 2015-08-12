/*
 * Copyright (c) 2013, 2014, 2015 The University of Utah
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
    SPF_ACTION_BT      = 8,
    SPF_ACTION_SIGNAL  = 9,
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
	    int ttdetail;
	    int bt;
	    int overlay_levels;
	    char *overlay_debuginfo_prefix;
	} report;
	struct {
	    int ttctx;
	    int ttdetail;
	} print;
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
	struct {
	    int tid;
	    char *thid;
	    int overlay_levels;
	    char *overlay_debuginfo_prefix;
	} bt;
	struct {
	    int tid;
	    char *thid;
	    char *sigdesc;
	} signal;
    };
};

#define WHEN_PRE	0
#define WHEN_POST	1

struct spf_filter {
    char *id;

    char *srcfile;
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

struct overlay_spec {
    char *base_target_id;
    char *base_thread_name_or_id;
    struct target_spec *spec;
};

struct spf_argp_state {
    int argc;
    char **argv;
    char *config_file;
    int config_file_fatal;
    int use_os_syscall_probes;
    int ospecs_len;
    struct overlay_spec **ospecs;
};

/*
 * Globals.
 */
GList *targets;
struct spf_config *config = NULL;
struct spf_argp_state opts;

GHashTable *sprobes = NULL;
GHashTable *fprobes = NULL;

int needtodie = 0;
int needtodie_exitcode = 0;

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
    GList *t1;
    struct target *target;

    v_g_list_foreach(targets,t1,target) {
	target_pause(target);
    }

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

sigset_t ignored,interrupt,exitset;

void sigh_cleanup_probes(int signo,siginfo_t *siginfo,void *x) {
    if (sigismember(&exitset,signo)) {
	cleanup_probes();
    }
}

void print_thread_context(FILE *stream,struct target *target,tid_t tid,
			  int ttctx,int ttdetail,int bt,int overlay_levels,
			  char *overlay_debuginfo_prefix,char *sep,char *kvsep,
			  char *tprefix,char *tsep) {
    struct target_thread *tthread;
    char buf[8192];
    struct array_list *tids;
    int i,j;
    int rc;
    int didmaintid = 0;
    tid_t ttid;
    struct target *overlay;
    struct array_list *otl;
    struct target_spec *ospec;

    if (ttctx == 0) 
	return;
    else if (ttctx == 1) {
	tids = array_list_create(1);
	array_list_append(tids,(void *)(uintptr_t)tid);
    }
    else if (ttctx == 2) {
	tids = array_list_create(8);
	/* Just walk up the parent hierarchy. */
	ttid = tid;
	while (1) {
	    tthread = target_lookup_thread(target,ttid);
	    if (!tthread)
		break;
	    array_list_append(tids,(void *)(uintptr_t)ttid);
	    ttid = tthread->ptid;
	}
    }
    else if (ttctx == 3) {
	tids = target_list_available_tids(target);
	/* Make sure selected tid is first; skip it later. */
	if (!tids)
	    tids = array_list_create(1);
	array_list_prepend(tids,(void *)(uintptr_t)tid);
    }
    else
	return;

    array_list_foreach_fakeptr_t(tids,i,ttid,uintptr_t) {
	tthread = target_lookup_thread(target,ttid);
	if (!tthread)
	    continue;

	if (tthread->tid == tid && didmaintid)
	    continue;
	else if (tthread->tid == tid)
	    didmaintid = 1;

	fprintf(stream,"%s",tsep);

	if (target_thread_snprintf(target,tthread->tid,buf,sizeof(buf),
				   ttdetail,sep,kvsep) < 0) 
	    fprintf(stream,"%s[tid=%"PRIiTID"",tprefix,tthread->tid);
	else
	    fprintf(stream,"%s[%s",tprefix,buf);

	if (bt) {
	    rc = target_unwind_snprintf(buf,sizeof(buf),target,tthread->tid,
					TARGET_UNWIND_STYLE_PROG_KEYS,"|",",");
	    if (rc < 0)
		fprintf(stream,"%sbacktrace=[error!]",sep);
	    else if (rc == 0)
		fprintf(stream,"%sbacktrace=[empty]",sep);
	    else
		fprintf(stream,"%sbacktrace=[%s]",sep,buf);
	}

	fprintf(stream,"]");

	/*
	 * Handle overlay levels!  Woot!
	 */
	otl = array_list_create(8);
	overlay = target;
	ttid = tthread->tid;
	while (overlay_levels != 0) {
	    ospec = target_build_default_overlay_spec(overlay,ttid);
	    if (!ospec)
		break;

	    if (overlay_debuginfo_prefix)
		ospec->debugfile_root_prefix = strdup(overlay_debuginfo_prefix);

	    overlay = target_instantiate_overlay(overlay,ttid,ospec);
	    if (!overlay)
		break;

	    target_open(overlay);

	    fprintf(stream,"%s",tsep);

	    if (target_thread_snprintf(overlay,ttid,buf,sizeof(buf),
				       ttdetail,sep,kvsep) < 0) 
		fprintf(stream,"%s[overlay=%s%stid=%"PRIiTID"",
			tprefix,overlay->name,sep,ttid);
	    else
		fprintf(stream,"%s[overlay=%s%s%s",
			tprefix,overlay->name,sep,buf);

	    if (bt) {
		rc = target_unwind_snprintf(buf,sizeof(buf),overlay,ttid,
					    TARGET_UNWIND_STYLE_PROG_KEYS,
					    "|",",");
		if (rc < 0)
		    fprintf(stream,"%sbacktrace=[error!]",sep);
		else if (rc == 0)
		    fprintf(stream,"%sbacktrace=[empty]",sep);
		else
		    fprintf(stream,"%sbacktrace=[%s]",sep,buf);
	    }

	    fprintf(stream,"]");

	    --overlay_levels;

	    array_list_prepend(otl,overlay);
	}

	array_list_foreach(otl,j,overlay) {
	    target_close(overlay);
	    target_finalize(overlay);
	}

	array_list_free(otl);
	otl = NULL;
    }

    array_list_free(tids);
}

void spf_backtrace(struct target *t,tid_t ctid,char *tiddesc,
		   int overlay_levels,char *overlay_debuginfo_prefix) {
    struct array_list *tids;
    tid_t tid;
    int i;
    tid_t stid = -1;
    struct target_thread *tthread;
    char *endptr = NULL;
    int rc;
    char buf[8192];
    struct target *overlay;
    struct array_list *otl;
    struct target_spec *ospec;

    if (tiddesc) {
	stid = (int)strtol(tiddesc,&endptr,10);
	if (tiddesc == endptr) 
	    stid = -1;
	else
	    tiddesc = NULL;
    }
    else 
	stid = -1;

    /*
     * If stid == 0 or tiddesc, do them all.
     *
     * If it == -1 && !tiddesc, do ctid.
     *
     * If it >= 0, do that one.
     */

    if (stid == -1 && !tiddesc) {
	tids = array_list_create(1);
	array_list_append(tids,(void *)(uintptr_t)ctid);
    
	printf("Backtracing target '%s' (current thread %d):\n\n",t->name,ctid);
    }
    else if (stid > 0) {
	tids = array_list_create(1);
	array_list_append(tids,(void *)(uintptr_t)stid);
    
	printf("Backtracing target '%s' (thread %d):\n\n",t->name,stid);
    }
    else if (tiddesc) {
	tids = target_list_tids(t);
    
	printf("Backtracing target '%s' (thread name %s):\n\n",t->name,tiddesc);
    }
    else {
	tids = target_list_tids(t);
    
	printf("Backtracing target '%s' (all threads):\n\n",t->name);
    }

    array_list_foreach_fakeptr_t(tids,i,tid,uintptr_t) {
	tthread = target_lookup_thread(t,tid);
	if (!tthread)
	    continue;

	if ((tiddesc && !tthread->name)
	    || (tiddesc && strcmp(tiddesc,tthread->name)))
	    continue;

	rc = target_unwind_snprintf(buf,sizeof(buf),t,tid,
				    TARGET_UNWIND_STYLE_GDB,"\n",",");
	if (rc < 0)
	    fprintf(stdout,"\ntarget %s thread %"PRIiTID": (error!)\n",
		    t->name,tid);
	else if (rc == 0)
	    fprintf(stdout,"\ntarget %s thread %"PRIiTID": (nothing)\n",
		    t->name,tid);
	else
	    fprintf(stdout,"\ntarget %s thread %"PRIiTID": \n%s\n",
		    t->name,tid,buf);

	if (overlay_levels == 0)
	    continue;

	/*
	 * Handle overlay levels!
	 */
	otl = array_list_create(8);
	overlay = t;
	while (overlay_levels != 0) {
	    ospec = target_build_default_overlay_spec(overlay,tid);
	    if (!ospec)
		break;

	    /* Try read-only, because we don't want any of the extra gunk */
	    ospec->read_only = 1;

	    if (overlay_debuginfo_prefix)
		ospec->debugfile_root_prefix = strdup(overlay_debuginfo_prefix);

	    overlay = target_instantiate_overlay(overlay,tid,ospec);
	    if (!overlay)
		break;

	    target_open(overlay);

	    rc = target_unwind_snprintf(buf,sizeof(buf),overlay,tid,
					TARGET_UNWIND_STYLE_GDB,"\n",",");
	    if (rc < 0)
		fprintf(stdout,"\ntarget %s thread %"PRIiTID": (error!)\n",
			overlay->name,tid);
	    else if (rc == 0)
		fprintf(stdout,"\ntarget %s thread %"PRIiTID": (nothing)\n",
			overlay->name,tid);
	    else
		fprintf(stdout,"\ntarget %s thread %"PRIiTID": \n%s\n",
			overlay->name,tid,buf);

	    --overlay_levels;

	    array_list_prepend(otl,overlay);
	}

	array_list_foreach(otl,i,overlay) {
	    target_close(overlay);
	    target_finalize(overlay);
	}

	array_list_free(otl);
	otl = NULL;
    }

    fputs("\n",stdout);
    fflush(stdout);
}

int spf_signal(struct target *t,tid_t ctid,char *tiddesc,char *sigdesc) {
    struct array_list *tids;
    tid_t tid;
    int i;
    tid_t stid = -1;
    struct target_thread *tthread;
    char *endptr = NULL;
    int rc;
    int signo;

    signo = target_os_signal_from_name(t,sigdesc);

    if (tiddesc) {
	stid = (int)strtol(tiddesc,&endptr,10);
	if (tiddesc == endptr) 
	    stid = -1;
	else
	    tiddesc = NULL;
    }
    else 
	stid = -1;

    /*
     * If stid == 0 or tiddesc, do them all.
     *
     * If it == -1 && !tiddesc, do ctid.
     *
     * If it >= 0, do that one.
     */

    if (stid == -1 && !tiddesc) {
	tids = array_list_create(1);
	array_list_append(tids,(void *)(uintptr_t)ctid);
    
	printf("Signaling target '%s' (current thread %d):\n\n",t->name,ctid);
    }
    else if (stid > 0) {
	tids = array_list_create(1);
	array_list_append(tids,(void *)(uintptr_t)stid);
    
	printf("Signaling target '%s' (thread %d):\n\n",t->name,stid);
    }
    else if (tiddesc) {
	tids = target_list_tids(t);
    
	printf("Signaling target '%s' (thread name %s):\n\n",t->name,tiddesc);
    }
    else {
	tids = target_list_tids(t);
    
	printf("Signaling target '%s' (all threads):\n\n",t->name);
    }

    array_list_foreach_fakeptr_t(tids,i,tid,uintptr_t) {
	tthread = target_lookup_thread(t,tid);
	if (!tthread)
	    continue;

	if ((tiddesc && !tthread->name)
	    || (tiddesc && strcmp(tiddesc,tthread->name)))
	    continue;

	rc = target_os_signal_enqueue(t,tid,signo,NULL);
	if (rc < 0)
	    fprintf(stdout,"thread %"PRIiTID": (error!)\n",tid);
	else if (rc == 0)
	    fprintf(stdout,"thread %"PRIiTID": success\n",tid);
	else
	    fprintf(stdout,"thread %"PRIiTID": unknown status %d\n",tid,rc);
    }

    fflush(stdout);

    return 0;
}

result_t handler(int when,struct probe *probe,tid_t tid,void *data,
		 struct probe *trigger,struct probe *base) {
    GHashTableIter iter;
    gpointer kp,vp;
    char vstrbuf_static[1024];
    char *vstrbuf = NULL;
    char *vstrbuf_dynamic = NULL;
    int vstrbuf_dynamic_size = 0;
    struct value *v;
    GHashTable *vt;
    struct bsymbol *bsymbol;
    struct symbol *symbol;
    int i,j;
    int rc;
    struct spf_filter *spff = (struct spf_filter *)data;
    GSList *gsltmp;
    struct spf_action *spfa;
    struct probe *fprobe;
    result_t retval = RESULT_SUCCESS;
    struct target *btt,*st;

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
	    if (spfa->exit.retval == -69) {
		cleanup_probes();
		exit(-69);
	    }

	    /*
	     * We don't need to actually interrupt the monitor, though,
	     * because we're in a handler -- so some driver is handling
	     * us.
	     */
	    target_monitor_schedule_global_interrupt();
	    needtodie = 1;
	    needtodie_exitcode = spfa->exit.retval;
	    vdebug(5,LA_USER,LF_U_PROBE,"probe %s: scheduled exit with %d!\n",
		   probe_name(probe),spfa->exit.retval);
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

	    fprintf(stdout,"RESULT:: (%c:%d) %s (%d) %s %s (",
		    spfa->report.rt,result_counter,
		    spfa->report.tn ? spfa->report.tn : "",
		    spfa->report.tid,spfa->report.rv ? spfa->report.rv : "",
		    spfa->report.msg ? spfa->report.msg : "\"\"");
	    /* Now print the values... */
	    if (vt) {
		i = 0;
		g_hash_table_iter_init(&iter,vt);
		while (g_hash_table_iter_next(&iter,&kp,&vp)) {
		    if (i > 0)
			fprintf(stdout,",");
		    v = (struct value *)vp;
		    if (v) {
			rc = value_snprintf(v,vstrbuf_static,
					    sizeof(vstrbuf_static));
			vstrbuf = vstrbuf_static;
			if (rc >= (int)sizeof(vstrbuf_static)) {
			    vstrbuf_dynamic_size = rc + 1;
			    vstrbuf_dynamic = malloc(vstrbuf_dynamic_size);
			    rc = value_snprintf(v,vstrbuf_dynamic,
						vstrbuf_dynamic_size);
			    vstrbuf = vstrbuf_dynamic;
			}

			if (rc > 0) {
			    int unprintable = 0;
			    for (j = 0; vstrbuf[j] != '\0'; ++j) {
				if (!isgraph(vstrbuf[j]) && !isspace(vstrbuf[j])) {
				    unprintable = 1;
				    break;
				}
			    }

			    if (unprintable) {
				vwarn("unprintable raw value for key %s = 0x",
				      (char *)kp);
				for (j = 0; vstrbuf[j] != '\0'; ++j) {
				    vwarnc("%hhx",vstrbuf[j]);
				}
				vwarnc("\n");

				fprintf(stdout,"%s=??",(char *)kp);
			    }
			    else {
				fprintf(stdout,"%s=%s",(char *)kp,vstrbuf);
			    }
			}
			else
			    fprintf(stdout,"%s=?",(char *)kp);

			if (vstrbuf_dynamic) {
			    free(vstrbuf_dynamic);
			    vstrbuf_dynamic = NULL;
			    vstrbuf_dynamic_size = 0;
			}
		    }
		    else
			fprintf(stdout,"%s=?",(char *)kp);
		    ++i;
		}
	    }
	    fputs(",",stdout);
	    print_thread_context(stdout,bsymbol->region->space->target,tid,
				 spfa->report.ttctx,spfa->report.ttdetail,
				 spfa->report.bt,spfa->report.overlay_levels,
				 spfa->report.overlay_debuginfo_prefix,
				 ";",":","thread=",",");
	    fprintf(stdout,") ::RESULT\n");
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
			rc = value_snprintf(v,vstrbuf_static,
					    sizeof(vstrbuf_static));
			vstrbuf = vstrbuf_static;
			if (rc >= (int)sizeof(vstrbuf_static)) {
			    vstrbuf_dynamic_size = rc + 1;
			    vstrbuf_dynamic = malloc(vstrbuf_dynamic_size);
			    rc = value_snprintf(v,vstrbuf_dynamic,
						vstrbuf_dynamic_size);
			    vstrbuf = vstrbuf_dynamic;
			}

			if (rc > 0)
			    fprintf(stdout,"%s = %s",(char *)kp,vstrbuf);
			else
			    fprintf(stdout,"%s = ?",(char *)kp);

			if (vstrbuf_dynamic) {
			    free(vstrbuf_dynamic);
			    vstrbuf_dynamic = NULL;
			    vstrbuf_dynamic_size = 0;
			}
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
		    v = (struct value *) \
			g_hash_table_lookup(vt,PROBE_VALUE_NAME_RETURN);
		    if (v) {
			rc = value_snprintf(v,vstrbuf_static,
					    sizeof(vstrbuf_static));
			vstrbuf = vstrbuf_static;
			if (rc >= (int)sizeof(vstrbuf_static)) {
			    vstrbuf_dynamic_size = rc + 1;
			    vstrbuf_dynamic = malloc(vstrbuf_dynamic_size);
			    rc = value_snprintf(v,vstrbuf_dynamic,
						vstrbuf_dynamic_size);
			    vstrbuf = vstrbuf_dynamic;
			}

			if (rc > 0)
			    fprintf(stdout," = %s",vstrbuf_static);
			else
			    fprintf(stdout," = ?");

			if (vstrbuf_dynamic) {
			    free(vstrbuf_dynamic);
			    vstrbuf_dynamic = NULL;
			    vstrbuf_dynamic_size = 0;
			}
		    }
		}
	    }
	    fputs(" ",stdout);
	    print_thread_context(stdout,bsymbol->region->space->target,tid,
				 spfa->print.ttctx,spfa->print.ttdetail,
				 0,0,NULL,NULL,NULL,"",",");
	    fputs("\n",stdout);
	    fflush(stdout);
	}
	else if (spfa->atype == SPF_ACTION_BT) {
	    if (spfa->bt.tid > 1) {
		btt = target_lookup_target_id(spfa->bt.tid);
		if (!btt) {
		    verror("no existing target with id '%d'!\n",spfa->bt.tid);
		    return RESULT_SUCCESS;
		}
	    }
	    else
		btt = probe->target;

	    spf_backtrace(btt,tid,spfa->bt.thid,spfa->bt.overlay_levels,
			  spfa->bt.overlay_debuginfo_prefix);
	}
	else if (spfa->atype == SPF_ACTION_SIGNAL) {
	    if (spfa->signal.tid > 1) {
		st = target_lookup_target_id(spfa->signal.tid);
		if (!st) {
		    verror("no existing target with id '%d'!\n",
			   spfa->signal.tid);
		    return RESULT_SUCCESS;
		}
	    }
	    else
		st = probe->target;

	    spf_signal(st,tid,spfa->signal.thid,spfa->signal.sigdesc);
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

/*
 * This just makes sure values get loaded at the appropriate phases of
 * the value probes so they are always available even if the probe is
 * pre/post.
 */
result_t null_handler(struct probe *probe,tid_t tid,void *data,
		      struct probe *trigger,struct probe *base) {
    probe_value_get_table(trigger,tid);
    return RESULT_SUCCESS;
}

#define __TARGET_OVERLAY      0x200000
#define SPF_CONFIGFILE_FATAL  0x200001
#define SPF_OS_SYSCALL_PROBES 0x200002

struct argp_option spf_argp_opts[] = {
    { "overlay",__TARGET_OVERLAY,"[<target_id>:]<thread_name_or_id>:<spec_opts>",0,"Lookup name or id as an overlay target once the main target is instantiated, and try to open it.  All dumptarget options then apply to the overlay.",0 },
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

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp spf_argp = {
    spf_argp_opts,spf_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};

int main(int argc,char **argv) {
    int i;
    struct bsymbol *bsymbol;
    struct probe *sprobe, *fprobe;
    char *name, *context;
    char *str;
    char namebuf[128];
    struct target_nv_filter *pre_pf, *post_pf;
    char *pre_filter, *post_filter;
    struct target_os_syscall *syscall;

    struct target_spec *primary_target_spec = NULL;
    GList *base_target_specs = NULL;
    GList *overlay_target_specs = NULL;
    struct target *target;
    int rc;
    struct evloop *evloop;
    GList *t1;

    target_init();
    atexit(target_fini);

    /*
     * We need to handle SIGUSR1, SIGUSR2, and SIGHUP specially so we
     * can reload our config file as necessary.
     */
    sigemptyset(&ignored);
    sigemptyset(&exitset);
    sigemptyset(&interrupt);

    sigaddset(&exitset,SIGINT);
    sigaddset(&exitset,SIGALRM);
    sigaddset(&exitset,SIGQUIT);
    sigaddset(&exitset,SIGILL);
    sigaddset(&exitset,SIGABRT);
    sigaddset(&exitset,SIGFPE);
    sigaddset(&exitset,SIGSEGV);
    sigaddset(&exitset,SIGPIPE);
    sigaddset(&exitset,SIGTERM);
    sigaddset(&exitset,SIGBUS);
    sigaddset(&exitset,SIGXCPU);
    sigaddset(&exitset,SIGXFSZ);

    sigaddset(&interrupt,SIGUSR1);
    sigaddset(&interrupt,SIGUSR2);
    sigaddset(&interrupt,SIGHUP);

    target_install_custom_sighandlers(&ignored,&interrupt,&exitset,
				      sigh_cleanup_probes);

    memset(&opts,0,sizeof(opts));
    rc = target_argp_driver_parse(&spf_argp,&opts,argc,argv,
				  TARGET_TYPE_PTRACE 
				      | TARGET_TYPE_XEN | TARGET_TYPE_GDB,1,
				  &primary_target_spec,&base_target_specs,
				  &overlay_target_specs);

    if (rc) {
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

    evloop = evloop_create(NULL);

    targets = target_instantiate_and_open(primary_target_spec,
					  base_target_specs,overlay_target_specs,
					  evloop,NULL);
    if (!targets) {
	verror("could not instantiate and open targets!\n");
	exit(-1);
    }

    /*
     * Setup probes from command line or load config file.
     */
    sprobes = g_hash_table_new(g_direct_hash,g_direct_equal);
    fprobes = g_hash_table_new(g_direct_hash,g_direct_equal);

    if (opts.use_os_syscall_probes) {
	v_g_list_foreach(targets,t1,target) {
	    if (target->personality != TARGET_PERSONALITY_OS)
		continue;

	    if (target_os_syscall_table_load(target))
		vwarn("could not load the syscall table for target %s;"
		      " target_os_syscall probes will not be available!\n",
		      target->name);
	}
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

		bsymbol = NULL;
		v_g_list_foreach(targets,t1,target) {
		    if (opts.use_os_syscall_probes
			&& target->personality == TARGET_PERSONALITY_OS)
			syscall = target_os_syscall_lookup_name(target,name);
		    else
			syscall = NULL;
		    if (syscall) {
			sprobe = \
			    target_os_syscall_probe(target,TID_GLOBAL,syscall,
						    probe_do_sink_pre_handlers,
						    probe_do_sink_post_handlers,
						    NULL);
			if (!sprobe) {
			    verror("could not place syscall value probe on %s;"
				   " aborting!\n",name);
			    rc = -5;
			    goto exit;
			}
			else
			    break;
		    }
		    else {
			bsymbol = target_lookup_sym(target,name,NULL,NULL,
						    SYMBOL_TYPE_FLAG_NONE);
			if (!bsymbol)
			    continue;

			sprobe =
			    probe_value_symbol(bsymbol->region->space->target,
					       TID_GLOBAL,bsymbol,
					       probe_do_sink_pre_handlers,
					       probe_do_sink_post_handlers,
					       NULL);
			if (!sprobe) {
			    verror("could not place value probe on %s;"
				   " aborting!\n",name);
			    rc = -3;
			    goto exit;
			}
			else
			    break;
		    }
		}

		if (!sprobe) {
		    verror("could not probe symbol %s; aborting!\n",name);
		    rc = -3;
		    goto exit;
		}
		else
		    g_hash_table_insert(sprobes,name,sprobe);
	    }

	    /* Create either an empty filter probe or parse the filter! */
	    if (pre_filter) {
		pre_pf = target_nv_filter_parse(pre_filter);
		if (!pre_pf) {
		    verror("could not parse pre_filter '%s'!\n",pre_filter);
		    rc = -4;
		    goto exit;
		}
	    }
	    else 
		pre_pf = NULL;
	    if (post_filter) {
		post_pf = target_nv_filter_parse(post_filter);
		if (!post_pf) {
		    verror("could not parse post_filter '%s'!\n",post_filter);
		    rc = -4;
		    goto exit;
		}
	    }
	    else 
		post_pf = NULL;

	    snprintf(namebuf,sizeof(namebuf),"filter_%s_%d",name,i);
	    fprobe = probe_create_filtered(sprobe->target,TID_GLOBAL,NULL,namebuf,
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
	    rc = -5;
	    goto exit;
	}
	else {
	    opts.config_file = strdup("spf.conf");
	    
	    config = load_config_file(opts.config_file);
	    if (!config) {
		verror("could not read default config file %s!\n",
		       opts.config_file);
		rc = -11;
		goto exit;
	    }
	}
    }

    /* Now apply the config file.  Always make the first application fatal. */
    int oldfatal = opts.config_file_fatal;
    opts.config_file_fatal = 1;
    if (apply_config_file(config)) {
	verror("could not install config file %s!\n",opts.config_file);
	rc = -12;
	goto exit;
    }
    opts.config_file_fatal = oldfatal;

    if (g_hash_table_size(sprobes) == 0) {
	verror("No symbols to probe; exiting!\n");
	rc = -1;
	goto exit;
    }

    /*
     * The targets were paused after instantiation; we have to resume them
     * now that we've registered probes.
     */
    v_g_list_foreach(targets,t1,target) {
	target_resume(target);
    }

    fprintf(stdout,"Starting Symbol Probe Filtering!\n");
    fflush(stdout);

    fprintf(stdout,"Starting thread watch loop!\n");
    fflush(stdout);

    while (1) {
	tid_t tid = 0;
	struct target *t;
	target_status_t tstat;
	char *tname;
	siginfo_t siginfo;

	rc = target_monitor_evloop(evloop,NULL,&t,&tstat);

	/*
	 * Did we get interrupted safely?  We need to check if we were
	 * told to either die, or if we need to reload the config file.
	 */
	if (target_monitor_was_interrupted(&siginfo)) {
	    if (needtodie) {
		rc = 0;
		goto exit;
	    }
	    else if (siginfo.si_signo == SIGUSR1
		     || siginfo.si_signo == SIGUSR2
		     || siginfo.si_signo == SIGHUP) {
		reload_config_file();
	    }

	    target_monitor_clear_global_interrupt();

	    v_g_list_foreach(targets,t1,target) {
		target_resume(target);
	    }
	}
	/* Did we experience an error in select() or in evloop? */
	else if (rc < 0) {
	    fprintf(stderr,"error in target_monitor_evloop (%d): %s; aborting!\n",
		    rc,strerror(errno));
	    rc = -3;
	    goto exit;
	}
	/* Did we experience a significant event on a target? */
	else if (rc == 0 && evloop_maxsize(evloop) < 0) {
	    break;
	}
	else if (rc == 0) {
	    tid = target_gettid(t);
	    tname = target_name(t);

	    if (tstat == TSTATUS_ERROR) {
		fprintf(stderr,
			"Error handling target '%s'; closing and finalizing!\n",
			tname);

		target_close(t);
		target_finalize(t);
		targets = g_list_remove(targets,t);
	    }
	    else if (tstat == TSTATUS_DONE) {
		fprintf(stderr,
			"Target '%s' finished; finalizing!\n",
			tname);

		target_close(t);
		target_finalize(t);
		targets = g_list_remove(targets,t);
	    }
	    else if (tstat == TSTATUS_EXITING) {
		fprintf(stderr,"Target '%s' exiting...\n",tname);
	    }
	    else if (tstat == TSTATUS_INTERRUPTED) {
		fprintf(stderr,"Target '%s' interrupted, resuming...\n",tname);
		if (target_resume(t)) {
		    fprintf(stderr,"Could not resume target %s tid %"PRIiTID"\n",
			tname,tid);

		    target_close(t);
		    target_finalize(t);
		    targets = g_list_remove(targets,t);
		}
	    }
	    else {
		fprintf(stderr,
			"Target '%s' tid %d received unexpected status '%s'"
			" at 0x%"PRIxADDR"; attempting to continue!\n",
			tname,tid,TSTATUS(tstat),target_read_reg(t,tid,CREG_IP));
		if (target_resume(t)) {
		    fprintf(stderr,"Could not resume target %s tid %"PRIiTID"\n",
			tname,tid);

		    target_close(t);
		    target_finalize(t);
		    targets = g_list_remove(targets,t);
		}
	    }
	}
    }

    rc = 0;

 exit:
    fflush(stderr);
    fflush(stdout);
    cleanup_probes();
    target_default_cleanup();
    if (rc < 0)
	exit(rc);
    else
	exit(needtodie_exitcode);
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
 *   [ see README.spf.txt ]
 *
 * Reports interpreted by the XML server like this:
 *
 *   "RESULT:: (%c:%d) %ms (%d) %ms \"%m[^\"]\" (%m[^)]) ::RESULT\n",
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
	    cleanup_probes();
	    target_default_cleanup();
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
    struct bsymbol *bsymbol = NULL;
    GHashTable *needed = NULL;
    GHashTableIter iter;
    gpointer kp,vp;
    struct probe *probe,*sprobe,*fprobe;
    char namebuf[128];
    int i;
    struct target_os_syscall *syscall;
    GList *t1;
    struct target *target;

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
	bsymbol = NULL;
	v_g_list_foreach(targets,t1,target) {
	    bsymbol = target_lookup_sym(target,spff->symbol,NULL,spff->srcfile,
					SYMBOL_TYPE_FLAG_NONE);
	    if (bsymbol)
		break;
	}

	if (!bsymbol) 
	    bsymbol = target_lookup_sym(target,spff->symbol,NULL,spff->srcfile,
					SYMBOL_TYPE_FLAG_NONE);

	if (!bsymbol) {
	    if (opts.config_file_fatal) {
		verror("could not lookup symbol %s; aborting!\n",
		       spff->symbol);
		cleanup_probes();
		target_default_cleanup();
		exit(-3);
	    }
	    else {
		vwarn("could not lookup symbol %s; skipping filter!\n",
		      spff->symbol);
		continue;
	    }
	}

	sprobe = NULL;
	if (opts.use_os_syscall_probes) {
	    v_g_list_foreach(targets,t1,target) {
		if (target->personality != TARGET_PERSONALITY_OS)
		    continue;

		syscall = target_os_syscall_lookup_name(target,spff->symbol);
		if (syscall) {
		    sprobe = target_os_syscall_probe(target,TID_GLOBAL,syscall,
						     probe_do_sink_pre_handlers,
						     probe_do_sink_post_handlers,
						     NULL);
		    if (!sprobe) {
			if (opts.config_file_fatal) {
			    verror("could not place syscall value probe on %s;"
				   " aborting!\n",
				   spff->symbol);
			    cleanup_probes();
			    target_default_cleanup();
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
	}

	if (!sprobe) {
	    sprobe = probe_value_symbol(bsymbol->region->space->target,
					TID_GLOBAL,bsymbol,
					probe_do_sink_pre_handlers,
					probe_do_sink_post_handlers,NULL);
	    if (!sprobe) {
		if (opts.config_file_fatal) {
		    verror("could not place value probe on %s; aborting!\n",
			   spff->symbol);
		    cleanup_probes();
		    target_default_cleanup();
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
	/* Again, if we failed for any reason to get the symbol, skip here. */
	sprobe = (struct probe *)g_hash_table_lookup(sprobes,spff->symbol);
	if (!sprobe)
	    continue;
	if (!spff->id) {
	    snprintf(namebuf,sizeof(namebuf),"filter_%s_%d",spff->symbol,i);
	    spff->id = strdup(namebuf);
	}
	if (spff->when == WHEN_PRE)
	    fprobe = probe_create_filtered(sprobe->target,TID_GLOBAL,NULL,spff->id,
					   pre_handler,spff->pf,null_handler,NULL,
					   spff->ttf,spff,0,1);
	else
	    fprobe = probe_create_filtered(sprobe->target,TID_GLOBAL,NULL,spff->id,
					   null_handler,NULL,post_handler,spff->pf,
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
    long int numval;
    struct spf_config *retval = NULL;
    int spff_count = 0;
    int lineno = 0;
    char *tmp;

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
	    while (!isspace(*bufptr)) ++bufptr;
	    *bufptr = '\0';
	    spff->symbol = strdup(token);
	    if ((tmp = index(spff->symbol,':'))) {
		spff->srcfile = spff->symbol;
		*tmp = '\0';
		spff->symbol = strdup(tmp+1);
	    }
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
		    spfa = calloc(1,sizeof(*spfa));
		    spfa->atype = SPF_ACTION_PRINT;

		    if (*bufptr == ')') {
			++bufptr;
		    }
		    else {
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

			    if (strcmp(token,"ttctx") == 0) {
				if (strcmp(token2,"none") == 0)
				    spfa->print.ttctx = 0;
				else if (strcmp(token2,"self") == 0)
				    spfa->print.ttctx = 1;
				else if (strcmp(token2,"hier") == 0)
				    spfa->print.ttctx = 2;
				else if (strcmp(token2,"all") == 0)
				    spfa->print.ttctx = 3;
				else
				    goto err;
			    }
			    else if (strcmp(token,"ttdetail") == 0) {
				spfa->print.ttdetail = atoi(token2);
			    }
			    else 
				goto err;
			}
			bufptr = nextbufptr;
		    }

		    spff->actions = g_slist_append(spff->actions,spfa);
		    spfa = NULL;
		}
		else if (strcmp(token,"report") == 0) {
		    spfa = calloc(1,sizeof(*spfa));
		    spfa->atype = SPF_ACTION_REPORT;

		    /* Set some defaults. */
		    spfa->report.rt = 'i';
		    spfa->report.overlay_levels = 0;
		    spfa->report.overlay_debuginfo_prefix = NULL;

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
			    if (*token2 != '"') {
				spfa->report.msg = malloc(2+1+strlen(token2));
				snprintf(spfa->report.msg,2+1+strlen(token2),
					 "\"%s\"",token2);
			    }
			    else
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
			else if (strcmp(token,"ttdetail") == 0) {
			    spfa->report.ttdetail = atoi(token2);
			}
			else if (strcmp(token,"bt") == 0) {
			    spfa->report.bt = atoi(token2);
			}
			else if (strcmp(token,"overlay_levels") == 0) {
			    spfa->report.overlay_levels = atoi(token2);
			}
			else if (strcmp(token,"overlay_debuginfo_root_prefix") == 0) {
			    spfa->report.overlay_debuginfo_prefix =
				strdup(token2);
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
		else if (strcmp(token,"bt") == 0) {
		    spfa = calloc(1,sizeof(*spfa));
		    spfa->atype = SPF_ACTION_BT;

		    /* Set some defaults. */
		    spfa->bt.tid = -1;
		    spfa->bt.thid = NULL;
		    spfa->bt.overlay_levels = 0;
		    spfa->bt.overlay_debuginfo_prefix = NULL;

		    char *nextbufptr = NULL;
		    nextbufptr = _get_next_non_enc_esc(bufptr,')');
		    if (!nextbufptr)
			goto err;
		    *nextbufptr = '\0';
		    ++nextbufptr;
		    token = NULL;
		    token2 = NULL;
		    saveptr = NULL;

		    int lpc = 0;
		    while ((token = strtok_r((!token) ? bufptr : NULL,",",
					     &saveptr))) {
			if (lpc == 0)
			    spfa->bt.tid = atoi(token);
			else if (lpc == 1)
			    spfa->bt.thid = strdup(token);
			else if (lpc == 2)
			    spfa->bt.overlay_levels = atoi(token);
			else if (lpc == 3)
			    spfa->bt.overlay_debuginfo_prefix = strdup(token);
			else 
			    goto err;

			++lpc;
		    }
		    bufptr = nextbufptr;

		    spff->actions = g_slist_append(spff->actions,spfa);
		    spfa = NULL;
		}
		else if (strcmp(token,"signal") == 0) {
		    spfa = calloc(1,sizeof(*spfa));
		    spfa->atype = SPF_ACTION_SIGNAL;

		    /* Set some defaults. */
		    spfa->signal.tid = -1;
		    spfa->signal.thid = NULL;

		    char *nextbufptr = NULL;
		    nextbufptr = _get_next_non_enc_esc(bufptr,')');
		    if (!nextbufptr)
			goto err;
		    *nextbufptr = '\0';
		    ++nextbufptr;
		    token = NULL;
		    token2 = NULL;
		    saveptr = NULL;

		    int lpc = 0;
		    while ((token = strtok_r((!token) ? bufptr : NULL,",",
					     &saveptr))) {
			if (lpc == 0)
			    spfa->signal.tid = atoi(token);
			else if (lpc == 1)
			    spfa->signal.thid = strdup(token);
			else if (lpc == 2)
			    spfa->signal.sigdesc = strdup(token);
			else
			    goto err;

			++lpc;
		    }
		    bufptr = nextbufptr;

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
