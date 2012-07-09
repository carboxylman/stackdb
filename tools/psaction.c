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
#include <getopt.h>
#include <errno.h>
#include <string.h>

#include <sys/user.h>
#include <sys/ptrace.h>
#include <inttypes.h>

#include <signal.h>

#include "log.h"
#include "dwdebug.h"
#include "target_api.h"
#include "target.h"
#include "target_xen_vm.h"

#include "probe_api.h"
#include "probe.h"
#include "alist.h"
#include "list.h"

extern char *optarg;
extern int optind, opterr, optopt;

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

    current->self = value->addr;

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

extern char **environ;    

int main(int argc,char **argv) {
    char *domain = NULL;
    char *command;
    char ch;
    int debug = -1;
    char *optargc;
    target_status_t tstat;
    log_flags_t flags;
    probepoint_style_t style = PROBEPOINT_FASTEST;
    struct debugfile_load_opts **dlo_list = NULL;
    int dlo_idx = 0;
    struct debugfile_load_opts *opts;
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

    while ((ch = getopt(argc, argv, "m:dvsl:Po:UF:")) != -1) {
	switch (ch) {
	case 'd':
	    ++debug;
	    break;
	case 'm':
	    domain = optarg;
	    break;
	case 's':
	    style = PROBEPOINT_SW;
	    break;
	case 'l':
	    if (vmi_log_get_flag_mask(optarg,&flags)) {
		fprintf(stderr,"ERROR: bad debug flag in '%s'!\n",optarg);
		exit(-1);
	    }
	    vmi_set_log_flags(flags);
	    break;
	case 'F':
	    optargc = strdup(optarg);

	    opts = debugfile_load_opts_parse(optarg);

	    if (!opts)
		goto dlo_err;

	    dlo_list = realloc(dlo_list,sizeof(opts)*(dlo_idx + 2));
	    dlo_list[dlo_idx] = opts;
	    ++dlo_idx;
	    dlo_list[dlo_idx] = NULL;
	    break;
	dlo_err:
	    fprintf(stderr,"ERROR: bad debugfile_load_opts '%s'!\n",optargc);
	    free(optargc);
	    exit(-1);
	default:
	    fprintf(stderr,"ERROR: unknown option %c!\n",ch);
	    exit(-1);
	}
    }

    argc -= optind;
    argv += optind;

    if (!argc) {
	fprintf(stderr,"ERROR: must supply a command!\n");
	exit(-5);
    }

    command = argv[0];

    if (strcmp(command,"list") == 0 
	|| strcmp(command,"watch") == 0)
	;
    else if (strcmp(command,"check") == 0
	     || strcmp(command,"zombie") == 0
	     || strcmp(command,"stop") == 0
	     || strcmp(command,"kill") == 0) {
	if (argc < 2) {
	    fprintf(stderr,"ERROR: check|zombie|stop|kill commands must"
		    " be followed by an rfilter!\n");
	    exit(-5);
	}
	rf = rfilter_create_parse(argv[1]);
	if (!rf) {
	    fprintf(stderr,"ERROR: bad rfilter '%s'!\n",argv[1]);
	    exit(-7);
	}
    }
    else if (strcmp(command,"hiercheck") == 0
	     || strcmp(command,"hierkill") == 0) {
	if (argc < 2) {
	    fprintf(stderr,"ERROR: hiercheck|hierkill commands must"
		    " be followed by one or more process hierarchy regexps!\n");
	    exit(-5);
	}
	regexp_list = array_list_create(argc - 1);
	i = 1;
	while (i < argc) {
	    preg = (regex_t *)malloc(sizeof(regex_t));
	    if ((rc = regcomp(preg,argv[i],REG_EXTENDED | REG_NOSUB))) {
		regerror(rc,preg,errbuf,64);
		fprintf(stderr,"ERROR: bad regexp '%s': %s\n",argv[i],errbuf);
		exit(-12);
	    }
	    array_list_append(regexp_list,preg);
	    ++i;
	}
    }
    else if (strcmp(command,"dump") == 0) {
	if (argc < 2) {
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

    dwdebug_init();

    atexit(dwdebug_fini);

    vmi_set_log_level(debug);
#if defined(ENABLE_XENACCESS) && defined(XA_DEBUG)
    xa_set_debug_level(debug);
#endif

    if (domain) {
	t = xen_vm_attach(domain,dlo_list);
	if (!t) {
	    fprintf(stderr,"could not attach to dom %s!\n",domain);
	    exit(-3);
	}
    }
    else {
	fprintf(stderr,"ERROR: must specify a target!\n");
	exit(-2);
    }

    if (target_open(t)) {
	fprintf(stderr,"could not open domain %s!\n",domain);
	exit(-4);
    }

    if (strcmp(command,"dump") == 0) {
	for (i = 1 ; i < argc; ++i) {
	    bs = target_lookup_sym(t,argv[i],NULL,NULL,SYMBOL_TYPE_FLAG_VAR);
	    if (!bs) {
		fprintf(stderr,"ERROR: could not lookup %s!\n",argv[i]);
	    }
	    else {
		v = target_load_symbol(t,bs,
					LOAD_FLAG_AUTO_STRING
					| LOAD_FLAG_AUTO_DEREF);
		if (!v) {
		    fprintf(stderr,"ERROR: could not load value for %s!\n",
			    argv[i]);
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
	    printf("domain %s interrupted at 0x%" PRIxREGVAL "\n",domain,
		   target_read_reg(t,t->ipregno));
	    goto resume;


	resume:
	    if (target_resume(t)) {
		fprintf(stderr,"could not resume target domain %s\n",domain);
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
	printf("domain %s finished.\n",domain);
	exit(0);
    }
    else if (tstat == TSTATUS_ERROR) {
	printf("domain %s monitoring failed!\n",domain);
	exit(-9);
    }
    else {
	printf("domain %s monitoring failed with %d!\n",domain,tstat);
	exit(-10);
    }
}
