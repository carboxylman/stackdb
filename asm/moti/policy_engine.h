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



extern struct target *target;    
extern char base_fact_file[100]; 

int ps_gather(struct target *target, struct value * value, void * data) {

    struct value *pid_v;
    unsigned int pid;
    struct value *uid_v;
    unsigned int uid;
    struct value *name_v;
    char *name;
    struct value *euid_v;
    unsigned int euid;
    struct value *suid_v;
    unsigned int suid;
    struct value *fsuid_v;
    unsigned int fsuid;
    struct value *gid_v;
    unsigned int gid;
    struct value *egid_v;
    unsigned int egid;
    struct value *sgid_v;
    unsigned int sgid;
    struct value * fsgid_v;
    unsigned int fsgid;

    struct value * real_cred_v;
    ADDR real_cred_addr;
    struct symbol *cred_struct_type = NULL;
    struct value *new_value;
    FILE * fp;

    pid_v = target_load_value_member(target, NULL, value, "pid", NULL, LOAD_FLAG_NONE);
    pid = v_i32(pid_v);
    name_v = target_load_value_member(target, NULL, value, "comm", NULL, LOAD_FLAG_NONE);
    name = strdup(name_v->buf);
    
    real_cred_v = target_load_value_member(target, NULL, value, "real_cred", NULL, LOAD_FLAG_NONE);
    real_cred_addr = value_addr(real_cred_v);

    cred_struct_type = bsymbol_get_symbol(target_lookup_sym(target, "struct cred",
			NULL, "cred", SYMBOL_TYPE_FLAG_TYPE));
    
    new_value = target_load_type(target, cred_struct_type,real_cred_addr, LOAD_FLAG_NONE);
    if(!new_value) {
	fprintf(stdout,"ERROR: Failed to load type of struct cred.\n");
	return 1;
    }


    uid_v = target_load_value_member(target, NULL, new_value, "uid", NULL, LOAD_FLAG_NONE);
    uid = v_u32(uid_v);
    euid_v = target_load_value_member(target, NULL, new_value, "euid", NULL, LOAD_FLAG_NONE);
    euid = v_u32(euid_v);
    suid_v = target_load_value_member(target, NULL, new_value, "suid", NULL, LOAD_FLAG_NONE);
    suid = v_u32(suid_v);
    fsuid_v = target_load_value_member(target, NULL, new_value, "fsuid", NULL, LOAD_FLAG_NONE);
    fsuid = v_u32(fsuid_v);
    gid_v = target_load_value_member(target, NULL, new_value, "gid", NULL, LOAD_FLAG_NONE);
    gid = v_u32(gid_v);
    egid_v = target_load_value_member(target, NULL, new_value, "egid", NULL, LOAD_FLAG_NONE);
    egid = v_u32(egid_v);
    sgid_v = target_load_value_member(target, NULL, new_value, "sgid", NULL, LOAD_FLAG_NONE);
    sgid = v_u32(sgid_v);
    fsgid_v = target_load_value_member(target, NULL, new_value, "fsgid", NULL, LOAD_FLAG_NONE);
    fsgid = v_u32(fsgid_v);
   
    // now populate the base fact into the file.


    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	exit(0);
    }
    // first write the template of for the fact
    // OR should this go into the application knowledge file ???
    fprintf(fp,"\n(deftemplate task-struct\n \
			\t(slot comm (type STRING))\n \
			\t(slot pid (type INTEGER))\n \
			\t(slot uid (type INTEGER))\n \
			\t(slot euid (type INTEGER))\n \
			\t(slot suid (type INTEGER))\n \
			\t(slot fsuid (type INTEGER))\n \
			\t(slot gid (type INTEGER))\n \
			\t(slot egid (type INTEGER))\n \
			\t(slot sgid (type INTEGER))\n \
			\t(slot fsgid (type INTEGER)))");
    // Now populate the base fact
    fprintf(fp,"\n(task-struct\n \
		    \t(comm \"%s\")\n \
		    \t(pid %u)\n \
		    \t(uid %u)\n \
		    \t(euid %u)\n \
		    \t(suid %u)\n \
		    \t(fsuid %u)\n \
		    \t(gid %u)\n \
		    \t(egid %u)\n \
		    \t(sgid %u)\n \
		    \t(fsgid %u)\n",name,pid,uid,euid,suid,fsuid,gid,egid,sgid,fsgid);
    
    fclose(fp);

    return 0;
}


int process_info() {
    
    int ret_val; 
    struct bsymbol *init_task_bsymbol;

    init_task_bsymbol = target_lookup_sym(target,"init_task",NULL,NULL,
						    SYMBOL_TYPE_FLAG_VAR);
    if(!init_task_bsymbol) {
	fprintf(stdout,"ERROR: Could not lookup the init_task symbol\n");
	return 1;
    }

    fprintf(stdout," file name = %s\n", base_fact_file);

    ret_val = linux_list_for_each_struct(target, init_task_bsymbol, "tasks",0,ps_gather, NULL);
    
    return ret_val;

}


