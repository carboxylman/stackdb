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
char * base_fact_file = NULL;



int ps_garther(struct target *target, struct value * value, void * data) {

    struct value *pid_v;
    int pid;
    struct value *uid_v;
    int uid;
    struct value *name_v;
    char name[35];
    struct value *euid_v;
    int euid;
    struct value *suid_v;
    int suid;
    struct value *fsuid_v;
    int fsuid;
    struct value *gid_v;
    int gid;
    struct value *egid_v;
    int egid;
    struct value *sgid_v;
    int sgid;
    struct value * fsgid_v;
    int fdgid;
    FILE * fp;

    pid_v = target_load_value_member(target, NULL, value, "pid", NULL, LOAD_FLAG_NONE);
    pid = v_i32(pid_v);
    name_v = target_load_value_member(target, NULL, value, "comm", NULL, LOAD_FLAG_NONE);
    name = strdup(name_v->buf);
    //not sure if this is going to work for latest kernel version becuse of the new cred structure
    uid_v = target_load_value_member(target, NULL, value, "uid", NULL, LOAD_FLAG_NONE);
    uid = v_i32(uid_v);
    euid_v = target_load_value_member(target, NULL, value, "euid", NULL, LOAD_FLAG_NONE);
    euid = v_i32(euid_v);
    suid_v = target_load_value_member(target, NULL, value, "suid", NULL, LOAD_FLAG_NONE);
    suid = v_i32(suid_v);
    fsuid_v = target_load_value_member(target, NULL, value, "fsuid", NULL, LOAD_FLAG_NONE);
    fsuid = v_i32(fsuid_v);
    gid_v = target_load_value_member(target, NULL, value, "gid", NULL, LOAD_FLAG_NONE);
    gid = v_i32(gid_v);
    egid_v = target_load_value_member(target, NULL, value, "egid", NULL, LOAD_FLAG_NONE);
    egid = v_i32(egid_v);
    sgid_v = target_load_value_member(target, NULL, value, "sgid", NULL, LOAD_FLAG_NONE);
    sgid = v_i32(sgid_v);
    fsgid_v = target_load_value_member(target, NULL, value, "fsgid" NULL, LOAD_FLAG_NONE);
    fsgid = v_i32(fsgid_v);
    // now populate the base fact into the file.

    fp = fopen(base_fact_file, "a+");
    if(fp ==NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	exit(0);
    }
    // first write the template of for the fact
    // OR should this go into the application knowledge file ???
    fprintf(fp,"(deftemplate task-struct\n
			\t(slot comm (type STRING))\n
			\t(slot pid (type INTEGER))\n
			\t(slot uid (type INTEGER))\n
			\t(slot euid (type INTEGER))\n
			\t(slot suid (type INTEGER))\n
			\t(slot fsuid (type INTEGER))\n
			\t(slot gid (type INTEGER))\n
			\t(slot egid (type INTEGER))\n
			\t(slot sgid (type INTEGER))\n
			\t(slot fsgid (type INTEGER))\n
		    )");
    // Now populate the base fact
    fprintf(fp,"(task-struct\n
		    \t(comm \"%s\")\n
		    \t(pid %d)\n
		    \t(uid %d)\n
		    \t(euid %d)\n
		    \t(suid %d)\n
		    \t(fsuid %d)\n
		    \t(gid %d)\n
		    \t(egid %d)\n
		    \t(sgid %d)\n
		    \t(fsgid %d)\n",name,pid,gid,uid,euid,suid,fsuid,gid,egid,sgid,fsgid);
    
    fclose(fp);

    return 0;
}


int process_info() {
    
    struct bsymbol *init_task_bsymbol;

    init_task_bsymbol = target_lookup_symbol(t,"init_task",NULL,NULL,
						    SYMBOL_TYPE_FLAG_VAR);
    if(!init_task_bsymbol) {
	fprintf(stdout,"ERROR: Could not lookup the init_task symbol\n");
	return 1;
    }

    linux_list_for_each_struct(t, init_task_bsymbol, "tasks",0,ps_gather, NULL);

    return 0;

}





int generate_snapshot(char* file_name) {
    
    int result;
    struct target_spec * tspec;

    base_fact_file = filename;
    tspec = target_argp_driver_parse(NULL, NULL, argc, argv,
	                TARGET_TYPE_XEN, 1);

    if (!tspec) {
	fprintf(stdout,"ERROR: Could not parse target arguments!\n");
	exit(-1);
    }

    dwdebug_init();
    atexit(dwdebug_fini);

    /* Initialize the target */
    t = target_instantiate(tspec,NULL);
    if (!t) {
	fprintf(stdout,"ERROR: Count not instantiate target.\n");
	exit(-1);
    }
    target_snprintf(t,targetstr,sizeof(targetstr));

    /* Open connection to the target.*/
    if (target_open(t)) {
	fprintf(stdout, "ERROR: Connection to target failed.\n");
	exit(-1);
    }

    // start making calls to each of the VMI function 
    result = process_info();
    if(result) {
	fprintf(stdout,"ERROR: process_info function failed\n");
	goto exit
    }




exit:
    fflush(stderr);
    fflush(stdout);
    tstat = cleanup();
    if(tstat == TSTATUS_DONE) {
         printf("%s finished.\n",targetstr);
	 return 0;
    }
    else if (tstat == TSTATUS_ERROR) {
	printf("%s monitoring failed!\n",targetstr);
	return 1;
    }
    else {
	printf("%s monitoring failed with %d!\n",targetstr,tstat);
	return 1;
    }

}
