/*
 * Copyright (c) 2011, 2012 The University of Utah
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

#include <sys/user.h>
#include <sys/ptrace.h>
#include <inttypes.h>

#include <signal.h>

#include <argp.h>

#include "log.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"
#include "target_xen_vm.h"

#include "probe_api.h"
#include "probe.h"
#include "alist.h"
#include "list.h"

struct target *t = NULL;

GHashTable *probes = NULL;

target_status_t cleanup() {
    GHashTableIter iter;
    gpointer key;
    struct probe *probe;
    target_status_t retval;

    if (probes) {
	g_hash_table_iter_init(&iter,probes);
	while (g_hash_table_iter_next(&iter,
				      (gpointer)&key,
				      (gpointer)&probe)) {
	    probe_unregister(probe,1);
	    probe_free(probe,1);
	}
    }
    retval = target_close(t);
    target_free(t);

    if (probes) 
	g_hash_table_destroy(probes);

    return retval;
}

void sigh(int signo) {
    if (t) {
	target_pause(t);
	cleanup();
    }
    exit(0);
}

int pslist_list(struct target *target,struct value *value,void *data) {
    struct value *pid_v;
    struct value *uid_v;
    struct value *name_v;

    pid_v = target_load_value_member(target,value,"pid",NULL,LOAD_FLAG_NONE);
    name_v = target_load_value_member(target,value,"comm",NULL,LOAD_FLAG_NONE);
    uid_v = target_load_value_member(target,value,"uid",NULL,LOAD_FLAG_NONE);

    printf("%d\t%d\t%s\n",v_u32(pid_v),v_u32(uid_v),name_v->buf);

    value_free(pid_v);
    value_free(uid_v);
    value_free(name_v);

    return 0;
}

int pslist_check(struct target *target,struct value *value,void *data) {
    struct value *pid_v;
    struct value *uid_v;
    struct value *name_v;
    struct rfilter *rf = (struct rfilter *)data;
    int accept;

    name_v = target_load_value_member(target,value,"comm",NULL,LOAD_FLAG_NONE);
    rfilter_check(rf,name_v->buf,&accept,NULL);
    if (accept == RF_ACCEPT) {
	value_free(name_v);
	return 0;
    }

    pid_v = target_load_value_member(target,value,"pid",NULL,LOAD_FLAG_NONE);
    uid_v = target_load_value_member(target,value,"uid",NULL,LOAD_FLAG_NONE);

    printf("Check found bad %d\t%d\t%s\n",v_u32(pid_v),v_u32(uid_v),name_v->buf);

    value_free(pid_v);
    value_free(uid_v);
    value_free(name_v);

    return 0;
}

int pslist_zombie(struct target *target,struct value *value,void *data) {
    struct value *pid_v;
    struct value *uid_v;
    struct value *name_v;
    struct rfilter *rf = (struct rfilter *)data;
    int accept;
    struct value *v;

    name_v = target_load_value_member(target,value,"comm",NULL,LOAD_FLAG_NONE);
    rfilter_check(rf,name_v->buf,&accept,NULL);
    if (accept == RF_REJECT) {
	value_free(name_v);
	return 0;
    }

    pid_v = target_load_value_member(target,value,"pid",NULL,LOAD_FLAG_NONE);
    uid_v = target_load_value_member(target,value,"uid",NULL,LOAD_FLAG_NONE);

    printf("Zombifying %d\t%d\t%s\n",v_u32(pid_v),v_u32(uid_v),name_v->buf);

    value_free(pid_v);
    value_free(uid_v);
    value_free(name_v);

    /* Set task_struct->state = -1 */
    v = target_load_value_member(target,value,"state",NULL,LOAD_FLAG_NONE);
    value_update_num(v,-1);
    target_store_value(target,v);
    value_free(v);

    return 0;
}

#define LOCAL_NSIG           64
#define LOCAL_NSIG_BPW       32
#define LOCAL_NSIG_WORDS     (LOCAL_NSIG / LOCAL_NSIG_BPW)
typedef struct {
    unsigned long sig[LOCAL_NSIG_WORDS];
} local_sigset_t;

int pslist_stop(struct target *target,struct value *value,void *data) {
    struct value *pid_v;
    struct value *uid_v;
    struct value *name_v;
    struct rfilter *rf = (struct rfilter *)data;
    int accept;
    struct value *signal_v;
    struct value *signal_pending_v;
    struct value *signal_pending_signal_v;
    struct value *v;
    uint32_t sigstopmask = 1 << 17;
    struct value *thread_info_v;

    name_v = target_load_value_member(target,value,"comm",NULL,LOAD_FLAG_NONE);
    rfilter_check(rf,name_v->buf,&accept,NULL);
    if (accept == RF_REJECT) {
	value_free(name_v);
	return 0;
    }

    pid_v = target_load_value_member(target,value,"pid",NULL,LOAD_FLAG_NONE);
    uid_v = target_load_value_member(target,value,"uid",NULL,LOAD_FLAG_NONE);

    printf("Killing %d\t%d\t%s\n",v_u32(pid_v),v_u32(uid_v),name_v->buf);

    value_free(pid_v);
    value_free(uid_v);
    value_free(name_v);

    /* Load task_struct.signal (which is a struct signal_struct *) */
    signal_v = target_load_value_member(target,value,"signal",NULL,
					LOAD_FLAG_AUTO_DEREF);
    /* Load task_struct.signal->shared_pending */
    signal_pending_v = target_load_value_member(target,signal_v,"shared_pending",
						NULL,LOAD_FLAG_NONE);
    /* Load task-struct.signal->shared_pending.signal, which is
     * technically a struct containing an array, but we know what parts
     * of it to update, so we do it "raw".
     */
    signal_pending_signal_v = target_load_value_member(target,signal_pending_v,
						       "signal",
						       NULL,LOAD_FLAG_NONE);
    /* Set a pending SIGSTOP in the pending sigset. */
    if (value_update_zero(signal_pending_signal_v,(char *)&sigstopmask,
			  sizeof(uint32_t))) {
	printf("  ERROR: could not stop!\n");
	return 0;
    }
    target_store_value(target,signal_pending_signal_v);
    value_free(signal_pending_signal_v);
    value_free(signal_pending_v);

    /* Now, set some junk in the signal struct.  We really should do
     * these three things for each thread in the process, but for now,
     * assume single-threaded processes!
     */
#define LOCAL_SIGNAL_GROUP_EXIT       0x00000008
    v = target_load_value_member(target,signal_v,"flags",NULL,LOAD_FLAG_NONE);
    value_update_u32(v,LOCAL_SIGNAL_GROUP_EXIT);
    target_store_value(target,v);
    value_free(v);

    v = target_load_value_member(target,signal_v,"group_exit_code",
				 NULL,LOAD_FLAG_NONE);
    value_update_i32(v,17);
    target_store_value(target,v);
    value_free(v);

    v = target_load_value_member(target,signal_v,"group_stop_count",
				 NULL,LOAD_FLAG_NONE);
    value_update_i32(v,0);
    target_store_value(target,v);
    value_free(v);

    value_free(signal_v);

#define LOCAL_TIF_SIGPENDING          2

    /* Finally, set SIGPENDING in the task_struct's thread_info struct. */
    thread_info_v = target_load_value_member(target,value,"thread_info",NULL,
					     LOAD_FLAG_AUTO_DEREF);
    v = target_load_value_member(target,signal_v,"flags",NULL,LOAD_FLAG_NONE);
    value_update_u32(v,v_u32(v) | LOCAL_TIF_SIGPENDING);
    target_store_value(target,v);
    value_free(v);

    value_free(thread_info_v);

    return 0;
}

int __ps_kill(struct target *target,struct value *value) {
    struct value *pid_v;
    struct value *uid_v;
    struct value *name_v;
    struct value *signal_v;
    struct value *signal_pending_v;
    struct value *signal_pending_signal_v;
    struct value *v;
    uint32_t sigkillmask = 1 << 9;
    struct value *thread_info_v;

    name_v = target_load_value_member(target,value,"comm",NULL,LOAD_FLAG_NONE);
    pid_v = target_load_value_member(target,value,"pid",NULL,LOAD_FLAG_NONE);
    uid_v = target_load_value_member(target,value,"uid",NULL,LOAD_FLAG_NONE);

    printf("Killing %d\t%d\t%s\n",v_u32(pid_v),v_u32(uid_v),name_v->buf);

    value_free(pid_v);
    value_free(uid_v);
    value_free(name_v);

    /* Load task_struct.signal (which is a struct signal_struct *) */
    signal_v = target_load_value_member(target,value,"signal",NULL,
					LOAD_FLAG_AUTO_DEREF);
    /* Load task_struct.signal->shared_pending */
    signal_pending_v = target_load_value_member(target,signal_v,"shared_pending",
						NULL,LOAD_FLAG_NONE);
    /* Load task-struct.signal->shared_pending.signal, which is
     * technically a struct containing an array, but we know what parts
     * of it to update, so we do it "raw".
     */
    signal_pending_signal_v = target_load_value_member(target,signal_pending_v,
						       "signal",
						       NULL,LOAD_FLAG_NONE);
    /* Set a pending SIGKILL in the pending sigset. */
    if (value_update_zero(signal_pending_signal_v,(char *)&sigkillmask,
			  sizeof(uint32_t))) {
	printf("  ERROR: could not kill!\n");
	return 0;
    }
    target_store_value(target,signal_pending_signal_v);
    value_free(signal_pending_signal_v);
    value_free(signal_pending_v);

    /* Now, set some junk in the signal struct.  We really should do
     * these three things for each thread in the process, but for now,
     * assume single-threaded processes!
     */
#define LOCAL_SIGNAL_GROUP_EXIT       0x00000008
    v = target_load_value_member(target,signal_v,"flags",NULL,LOAD_FLAG_NONE);
    value_update_u32(v,LOCAL_SIGNAL_GROUP_EXIT);
    target_store_value(target,v);
    value_free(v);

    v = target_load_value_member(target,signal_v,"group_exit_code",
				 NULL,LOAD_FLAG_NONE);
    value_update_i32(v,9);
    target_store_value(target,v);
    value_free(v);

    v = target_load_value_member(target,signal_v,"group_stop_count",
				 NULL,LOAD_FLAG_NONE);
    value_update_i32(v,0);
    target_store_value(target,v);
    value_free(v);

    value_free(signal_v);

#define LOCAL_TIF_SIGPENDING          2

    /* Finally, set SIGPENDING in the task_struct's thread_info struct. */
    thread_info_v = target_load_value_member(target,value,"thread_info",NULL,
					     LOAD_FLAG_AUTO_DEREF);
    v = target_load_value_member(target,signal_v,"flags",NULL,LOAD_FLAG_NONE);
    value_update_u32(v,v_u32(v) | LOCAL_TIF_SIGPENDING);
    target_store_value(target,v);
    value_free(v);

    value_free(thread_info_v);

    return 0;
}

int pslist_kill(struct target *target,struct value *value,void *data) {
    struct value *name_v;
    struct rfilter *rf = (struct rfilter *)data;
    int accept;

    name_v = target_load_value_member(target,value,"comm",NULL,LOAD_FLAG_NONE);
    rfilter_check(rf,name_v->buf,&accept,NULL);
    if (accept == RF_REJECT) {
	value_free(name_v);
	return 0;
    }
    value_free(name_v);

    return __ps_kill(target,value);
}

struct linux_task_struct {
    long state;
    unsigned long flags;
    int pid;
    int tgid;
    ADDR parent_addr;
    ADDR real_parent_addr;
    int uid;
    int euid;
    int suid;
    int fsuid;
    int gid;
    int egid;
    int sgid;
    int fsgid;

    char *comm;

    ADDR self;

    struct list_head tasks;

    struct value *value;

    struct linux_task_struct *real_parent;
    struct linux_task_struct *parent;

    char *comm_hier;
};

int pslist_load(struct target *target,struct value *value,void *data) {
    struct value *v;

    struct linux_task_struct **head = ((struct linux_task_struct **)data);
    struct linux_task_struct *current = \
	(struct linux_task_struct *)malloc(sizeof(struct linux_task_struct));
    memset(current,0,sizeof(struct linux_task_struct));
    INIT_LIST_HEAD(&current->tasks);

    if (!*head) {
	*head = current;
    }
    else
	list_add_tail(&current->tasks,&((*head)->tasks));

    current->self = value_addr(value);

    v = target_load_value_member(target,value,"comm",NULL,LOAD_FLAG_NONE);
    current->comm = strdup(v->buf);
    value_free(v);

    v = target_load_value_member(target,value,"state",NULL,LOAD_FLAG_NONE);
    current->state = v_i32(v);
    value_free(v);

    v = target_load_value_member(target,value,"flags",NULL,LOAD_FLAG_NONE);
    current->flags = v_u32(v);
    value_free(v);
    
    v = target_load_value_member(target,value,"pid",NULL,LOAD_FLAG_NONE);
    current->pid = v_i32(v);
    value_free(v);
    
    v = target_load_value_member(target,value,"parent",NULL,LOAD_FLAG_NONE);
    current->parent_addr = v_addr(v);
    value_free(v);
    
    v = target_load_value_member(target,value,"real_parent",NULL,
				 LOAD_FLAG_NONE);
    current->real_parent_addr = v_addr(v);
    value_free(v);
    
    v = target_load_value_member(target,value,"tgid",NULL,LOAD_FLAG_NONE);
    current->tgid = v_i32(v);
    value_free(v);
    
    v = target_load_value_member(target,value,"uid",NULL,LOAD_FLAG_NONE);
    current->uid = v_i32(v);
    value_free(v);
    
    v = target_load_value_member(target,value,"euid",NULL,LOAD_FLAG_NONE);
    current->euid = v_i32(v);
    value_free(v);
    
    v = target_load_value_member(target,value,"suid",NULL,LOAD_FLAG_NONE);
    current->suid = v_i32(v);
    value_free(v);
    
    v = target_load_value_member(target,value,"fsuid",NULL,LOAD_FLAG_NONE);
    current->fsuid = v_i32(v);
    value_free(v);
    
    v = target_load_value_member(target,value,"gid",NULL,LOAD_FLAG_NONE);
    current->gid = v_i32(v);
    value_free(v);
    
    v = target_load_value_member(target,value,"egid",NULL,LOAD_FLAG_NONE);
    current->egid = v_i32(v);
    value_free(v);
    
    v = target_load_value_member(target,value,"sgid",NULL,LOAD_FLAG_NONE);
    current->sgid = v_i32(v);
    value_free(v);
    
    v = target_load_value_member(target,value,"fsgid",NULL,LOAD_FLAG_NONE);
    current->fsgid = v_i32(v);
    value_free(v);

    current->value = value;

    return 0;
}

struct psa_argp_state {
    int argc;
    char **argv;
    /* Grab this from the child parser. */
    struct target_spec *tspec;
};

struct psa_argp_state opts;

struct argp_option psa_argp_opts[] = {
    { 0,0,0,0,0,0 },
};

error_t psa_argp_parse_opt(int key,char *arg,struct argp_state *state) {
    struct psa_argp_state *opts = \
	(struct psa_argp_state *)target_argp_driver_state(state);

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
	opts->tspec = target_argp_target_spec(state);
	return 0;
    case ARGP_KEY_ERROR:
    case ARGP_KEY_FINI:
	return 0;

    default:
	return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

struct argp psa_argp = {
    psa_argp_opts,psa_argp_parse_opt,NULL,NULL,NULL,NULL,NULL,
};

int main(int argc,char **argv) {
    char *command;
    target_status_t tstat;
    struct rfilter *rf = NULL;

    struct bsymbol *init_task_bsymbol;

    struct bsymbol *bs;
    struct value *v;
    int i;

    regex_t *preg;
    int rc;
    char errbuf[64];
    struct array_list *regexp_list;

    struct dump_info udn = {
	.stream = stderr,
	.prefix = "",
	.detail = 1,
	.meta = 1,
    };

    struct linux_task_struct *init_task = NULL;
    struct linux_task_struct *ti;
    struct linux_task_struct *tj;
    unsigned int csize;
    unsigned int clen;

    struct target_spec *tspec;
    char targetstr[128];

    dwdebug_init();
    atexit(dwdebug_fini);

    memset(&opts,0,sizeof(opts));

    tspec = target_argp_driver_parse(&psa_argp,&opts,argc,argv,TARGET_TYPE_XEN,1);

    if (!tspec) {
	verror("could not parse target arguments!\n");
	exit(-1);
    }

    if (!opts.argc) {
	fprintf(stderr,"ERROR: must supply a command!\n");
	exit(-5);
    }

    command = opts.argv[0];

    if (strcmp(command,"list") == 0 
	|| strcmp(command,"watch") == 0)
	;
    else if (strcmp(command,"check") == 0
	     || strcmp(command,"zombie") == 0
	     || strcmp(command,"stop") == 0
	     || strcmp(command,"kill") == 0) {
	if (opts.argc < 2) {
	    fprintf(stderr,"ERROR: check|zombie|stop|kill commands must"
		    " be followed by an rfilter!\n");
	    exit(-5);
	}
	rf = rfilter_create_parse(opts.argv[1]);
	if (!rf) {
	    fprintf(stderr,"ERROR: bad rfilter '%s'!\n",opts.argv[1]);
	    exit(-7);
	}
    }
    else if (strcmp(command,"hiercheck") == 0
	     || strcmp(command,"hierkill") == 0) {
	if (opts.argc < 2) {
	    fprintf(stderr,"ERROR: hiercheck|hierkill commands must"
		    " be followed by one or more process hierarchy regexps!\n");
	    exit(-5);
	}
	regexp_list = array_list_create(opts.argc - 1);
	i = 1;
	while (i < opts.argc) {
	    preg = (regex_t *)malloc(sizeof(regex_t));
	    if ((rc = regcomp(preg,opts.argv[i],REG_EXTENDED | REG_NOSUB))) {
		regerror(rc,preg,errbuf,64);
		fprintf(stderr,"ERROR: bad regexp '%s': %s\n",opts.argv[i],errbuf);
		exit(-12);
	    }
	    array_list_append(regexp_list,preg);
	    ++i;
	}
    }
    else if (strcmp(command,"dump") == 0) {
	if (opts.argc < 2) {
	    fprintf(stderr,"ERROR: dump command must"
		    " be followed by a list of variables to dump!\n");
	    exit(-5);
	}
    }
    else {
	fprintf(stderr,"ERROR: command must be one of"
		" list|dump|check|zombie|stop|kill!\n");
	exit(-6);
    }

    t = target_instantiate(tspec);
    if (!t) {
	verror("could not instantiate target!\n");
	exit(-1);
    }
    target_tostring(t,targetstr,sizeof(targetstr));

    if (target_open(t)) {
	fprintf(stderr,"could not open %s!\n",targetstr);
	exit(-4);
    }

    if (strcmp(command,"dump") == 0) {
	for (i = 1 ; i < opts.argc; ++i) {
	    bs = target_lookup_sym(t,opts.argv[i],NULL,NULL,SYMBOL_TYPE_FLAG_VAR);
	    if (!bs) {
		fprintf(stderr,"ERROR: could not lookup %s!\n",opts.argv[i]);
	    }
	    else {
		v = target_load_symbol(t,TID_GLOBAL,bs,
					LOAD_FLAG_AUTO_STRING
					| LOAD_FLAG_AUTO_DEREF);
		if (!v) {
		    fprintf(stderr,"ERROR: could not load value for %s!\n",
			    opts.argv[i]);
		}
		else {
		    value_dump(v,&udn);
		    fprintf(udn.stream,"\n");
		    value_free(v);
		}
		bsymbol_release(bs);
	    }
	}

	goto exit;
    }

    init_task_bsymbol = target_lookup_sym(t,"init_task",NULL,NULL,
					  SYMBOL_TYPE_FLAG_VAR);
    if (!init_task_bsymbol) {
	fprintf(stderr,"ERROR: could not find init_task symbol!\n");
	goto exit;
    }

    /*
     * If we are just doing list|check|filter, we don't need to install probes.
     */
    if (strcmp(command,"list") == 0) {
	printf("PID\tUID\tProcess Name\n");
	linux_list_for_each_struct(t,init_task_bsymbol,"tasks",0,
				   pslist_list,NULL);
	goto exit;
    }
    else if (strcmp(command,"check") == 0) {
	linux_list_for_each_struct(t,init_task_bsymbol,"tasks",0,
				   pslist_check,rf);
	goto exit;
    }
    else if (strcmp(command,"zombie") == 0) {
	linux_list_for_each_struct(t,init_task_bsymbol,"tasks",0,
				   pslist_zombie,rf);
	goto exit;
    }
    else if (strcmp(command,"stop") == 0) {
	linux_list_for_each_struct(t,init_task_bsymbol,"tasks",0,
				   pslist_stop,rf);
	goto exit;
    }
    else if (strcmp(command,"kill") == 0) {
	linux_list_for_each_struct(t,init_task_bsymbol,"tasks",0,
				   pslist_kill,rf);
	goto exit;
    }
    else if (strcmp(command,"hiercheck") == 0
	     || strcmp(command,"hierkill") == 0) {
	/* Load the process list into our structs. */
	linux_list_for_each_struct(t,init_task_bsymbol,"tasks",1,
				   pslist_load,&init_task);

	/* Setup the parent pointers in our structs. */
	list_for_each_entry(ti,&init_task->tasks,tasks) {
	    list_for_each_entry(tj,&init_task->tasks,tasks) {
		if (ti->parent_addr == tj->self) {
		    //printf("parent of %s is %s\n",ti->comm,tj->comm);
		    ti->parent = tj;
		    break;
		}
	    }
	    if (ti->parent_addr == ti->real_parent_addr) 
		ti->real_parent = ti->parent;
	    else {
		list_for_each_entry(tj,&init_task->tasks,tasks) {
		    if (ti->real_parent_addr == tj->self) {
			//printf("real parent of %s is %s\n",ti->comm,tj->comm);
			ti->real_parent = tj;
			break;
		    }
		}
	    }
	}

	/* Build the comm_hier values for each pid. */
	list_for_each_entry(ti,&init_task->tasks,tasks) {
	    csize = 32;
	    clen = 0;
	    ti->comm_hier = malloc(csize);
	    ti->comm_hier[0] = '\0';

	    tj = ti;
	    while (tj) {
		if ((csize - clen) < (strlen(tj->comm) + 2)) {
		    csize += 32;
		    realloc(ti->comm_hier,csize);
		}
		if (ti != tj)
		    rc = snprintf(ti->comm_hier + clen,csize - clen,":%s",
				  tj->comm);
		else
		    rc = snprintf(ti->comm_hier + clen,csize - clen,"%s",
				  tj->comm);
		clen += rc;
		tj = tj->parent;
	    }

	    printf("hier: %s\n",ti->comm_hier);
	}
	
	/* Check each pid's comm_hier against our regexps; if we don't find
	 * a match, either print (hiercheck) the process, or kill
	 * (hierkill).
	 */
	list_for_each_entry(ti,&init_task->tasks,tasks) {
	    for (i = 0; i < array_list_len(regexp_list); ++i) {
		preg = (regex_t *)array_list_item(regexp_list,i);
		if (regexec(preg,ti->comm_hier,0,NULL,0) == 0) 
		    break;
	    }
	    if (i == array_list_len(regexp_list)) {
		if (strcmp(command,"hiercheck") == 0) {
		    printf("Disallowed process: %d\t%d\t%s (not killing)\n",
			   ti->pid,ti->uid,ti->comm);
		}
		else {
		    __ps_kill(t,ti->value);
		}
	    }
	}

	goto exit;
    }

    /*
     * If we are going to watch for processes, set up monitoring.
     */
    signal(SIGHUP,sigh);
    signal(SIGINT,sigh);
    signal(SIGQUIT,sigh);
    signal(SIGABRT,sigh);
    signal(SIGKILL,sigh);
    signal(SIGSEGV,sigh);
    signal(SIGPIPE,sigh);
    signal(SIGALRM,sigh);
    signal(SIGTERM,sigh);
    signal(SIGUSR1,sigh);
    signal(SIGUSR2,sigh);

    /* Install probes... */

    // XXX fill in...

    /* The target is paused after the attach; we have to resume it now
     * that we've registered probes.
     */
    target_resume(t);

    fprintf(stdout,"Starting watch loop!\n");
    fflush(stdout);

    while (1) {
	tstat = target_monitor(t);
	if (tstat == TSTATUS_PAUSED) {
	    fflush(stderr);
	    fflush(stdout);
	    printf("%s interrupted at 0x%" PRIxREGVAL "\n",targetstr,
		   target_read_reg(t,TID_GLOBAL,t->ipregno));
	    goto resume;


	resume:
	    if (target_resume(t)) {
		fprintf(stderr,"could not resume target domain %s\n",targetstr);
		cleanup();
		exit(-16);
	    }
	}
	else {
	    goto exit;
	}
    }

 exit:
    fflush(stderr);
    fflush(stdout);
    tstat = cleanup();
    if (tstat == TSTATUS_DONE)  {
	printf("%s finished.\n",targetstr);
	exit(0);
    }
    else if (tstat == TSTATUS_ERROR) {
	printf("%s monitoring failed!\n",targetstr);
	exit(-9);
    }
    else {
	printf("%s monitoring failed with %d!\n",targetstr,tstat);
	exit(-10);
    }
}
