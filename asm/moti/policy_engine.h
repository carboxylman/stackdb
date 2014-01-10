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
    int pid;
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
    real_cred_addr = v_addr(real_cred_v);

    cred_struct_type = bsymbol_get_symbol(target_lookup_sym(target, "struct cred",
			NULL, "cred", SYMBOL_TYPE_FLAG_TYPE));
    
    new_value = target_load_type(target, cred_struct_type,real_cred_addr, LOAD_FLAG_NONE);
    if(!new_value) {
	fprintf(stdout,"ERROR: Failed to load type of struct cred.\n");
	return 1;
    }


    uid_v = target_load_value_member(target, NULL, new_value, "uid", NULL, LOAD_FLAG_NONE);
    uid = v_u16(uid_v);
    euid_v = target_load_value_member(target, NULL, new_value, "euid", NULL, LOAD_FLAG_NONE);
    euid = v_u16(euid_v);
    suid_v = target_load_value_member(target, NULL, new_value, "suid", NULL, LOAD_FLAG_NONE);
    suid = v_u16(suid_v);
    fsuid_v = target_load_value_member(target, NULL, new_value, "fsuid", NULL, LOAD_FLAG_NONE);
    fsuid = v_u16(fsuid_v);
    gid_v = target_load_value_member(target, NULL, new_value, "gid", NULL, LOAD_FLAG_NONE);
    gid = v_u16(gid_v);
    egid_v = target_load_value_member(target, NULL, new_value, "egid", NULL, LOAD_FLAG_NONE);
    egid = v_u16(egid_v);
    sgid_v = target_load_value_member(target, NULL, new_value, "sgid", NULL, LOAD_FLAG_NONE);
    sgid = v_u16(sgid_v);
    fsgid_v = target_load_value_member(target, NULL, new_value, "fsgid", NULL, LOAD_FLAG_NONE);
    fsgid = v_u16(fsgid_v);
   
    // now populate the base fact into the file.


    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	exit(0);
    }
    /* first write the template of for the fact
     OR should this go into the application knowledge file ???
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
    */
    // Now populate the base fact
    fprintf(fp,"\n(task-struct\n \
		    \t(comm \"%s\")\n \
		    \t(pid %d)\n \
		    \t(uid %hu)\n \
		    \t(euid %hu)\n \
		    \t(suid %hu)\n \
		    \t(fsuid %hu)\n \
		    \t(gid %hu)\n \
		    \t(egid %hu)\n \
		    \t(sgid %hu)\n \
		    \t(fsgid %hu))\n",name,pid,uid,euid,suid,fsuid,gid,egid,sgid,fsgid);
    
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

    ret_val = linux_list_for_each_struct(target, init_task_bsymbol, "tasks",0,ps_gather, NULL);
    
    return ret_val;

}



int gather_file_info(struct target *target, struct value * value, void * data) {

    struct value *files_value;
    struct value *fdt_value;
    struct value *max_fds_value;
    struct value *fd_value;
    struct value *file_value;
    struct value *path_value;
    struct value *dentry_value;
    struct value *name_value;
    struct value *d_name_value;
    struct value *len_name_value;
    struct value *file_name_value;
    struct value *pid_value;
    struct value *next_fd_value;
    struct value *fversion_value;
    struct value *dcount_value;


    int max_fds, i, pid, next_fd;
    char *addr = NULL;
    char *file_name, *process_name;
    ADDR file_addr;
    struct symbol *file_struct_type;
    FILE *fp = NULL;


    fprintf(stdout,"INFO: Gathering list of open files\n");
    pid_value = target_load_value_member(target, NULL, value, "pid", NULL, LOAD_FLAG_NONE);
    if(!pid_value) {
	fprintf(stdout," ERROR: failed to load the pid value.\n");
	return 1;
    }
    pid = v_i32(pid_value);
    name_value = target_load_value_member(target, NULL, value, "comm", NULL, LOAD_FLAG_NONE);
    if(!name_value) {
	fprintf(stdout," ERROR: failed to load the process name.\n");
	exit(0);
    }   

    process_name = strdup(name_value->buf);
 
    /* Load the files struct from the task_struct */
    fprintf(stdout,"INFO: Loading files struct\n");
    files_value = target_load_value_member(target, NULL, value, "files", NULL, 
						LOAD_FLAG_AUTO_DEREF);
     if(!files_value) {
	fprintf(stdout," ERROR: failed to load the files struct member.\n");
	exit(0);
    }   

     next_fd_value =  target_load_value_member(target, NULL, files_value,"next_fd", 
						NULL,LOAD_FLAG_NONE);
    if(!next_fd_value) {
	fprintf(stdout," ERROR: Failed to load the next_fd member.\n");
	exit(0);
    }

    next_fd = v_i32(next_fd_value);

    fprintf(stdout,"INFO: Maximum number of files ever opened by process %s are %d\n",process_name, next_fd);

    /* Load the fdtable struct */
    fprintf(stdout,"INFO: Loading fdt struct\n");
    fdt_value =  target_load_value_member( target, NULL, files_value, "fdt", 
						NULL, LOAD_FLAG_AUTO_DEREF);
     if(!fdt_value) {
	fprintf(stdout," ERROR: failed to load the fdt struct member.\n");
	exit(0);
    }   


    /* Load the  max_fds member of the ftable struct */
    fprintf(stdout,"INFO: Loading max_fds member\n");
    max_fds_value = target_load_value_member( target, NULL, fdt_value, 
						"max_fds", NULL, LOAD_FLAG_NONE);
     if(!max_fds_value) {
	fprintf(stdout," ERROR: failed to load the max_fds member.\n");
	exit(0);
    }   

    max_fds = v_i32(max_fds_value);
    fprintf(stdout,"INFO: max_fds_value for process %s = %d\n", process_name, max_fds);
    /*Open the base fact file */

    fprintf(stdout,"INFO: Opening base fact file: %s\n",base_fact_file);
    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	exit(0);
    }
    
    /* Start encoding the fact */
    fprintf(stdout,"INFO: Encode the base facts.\n");
    fprintf(fp,"\n(opened-files\n \
    		    \t(comm \"%s\")\n \
    		    \t(pid %d)\n \
    		    \t(file_count %d)\n \ 
		    \t(files ", process_name, pid, next_fd);

 
    for( i = 0; i < next_fd; i++) {

	/* Load the array of file descriptors */
	fprintf(stdout,"INFO: Loading fd struct\n");
	fd_value =  target_load_value_member(target, NULL, fdt_value, "fd", NULL, 
						LOAD_FLAG_NONE);
	if(!fd_value) {
	    fprintf(stdout," ERROR: failed to load the fd struct memeber.\n");
	    exit(0);
	}
	fprintf(stdout," fd_value = %p \n",fd_value->buf);

	fprintf(stdout,"INFO: Loading fs struct\n");
	/* This is the base address */
	file_addr = v_addr(fd_value);
	file_addr = file_addr + ( target->ptrsize * i);
	fprintf(stdout,"INFO: file_addr = %p\n",file_addr);
	if( !file_addr ) {
	    fprintf(stdout,"INFO: Null value for file descriptor table entry.\n");
	    exit(0);
	}
	/* Load the type of symbol */
	file_struct_type = bsymbol_get_symbol(target_lookup_sym(target, 
			    "struct file", NULL, NULL, SYMBOL_TYPE_FLAG_TYPE));
	if(!file_struct_type) {
	    fprintf(stdout,"INFO: Could not load the file struct type\n");
	    exit(0);
	}

	/* Finally load the array memeber */
	fprintf(stdout,"INFO: Loading file struct\n");
	file_value = target_load_type(target, file_struct_type, file_addr, 
					LOAD_FLAG_NONE);
	if(!file_value) {
	    fprintf(stdout," ERROR: failed to load the file struct member.\n");
	    exit(0);
	}   

	fversion_value = target_load_value_member(target, NULL, file_value, "f_version",
							NULL, LOAD_FLAG_NONE);
	if(!fversion_value) {
	    fprintf(stdout,"ERROR: Failed to load the file version\n");
	    exit(0);
	}
	unsigned long f_version;
	f_version = v_u64(fversion_value);
	fprintf(stdout,"INFO: File version = %ul\n",f_version);

	/* Load the path the variable from the files struct*/
	fprintf(stdout,"INFO: Loading f_path struct\n");
	path_value = target_load_value_member( target, NULL, file_value, "f_path",
						    NULL, LOAD_FLAG_NONE);
	if(!path_value) {
	    fprintf(stdout," ERROR: failed to load the path struct member.\n");
	    exit(0);
	}   

	/* Load the dentry struct  member from the path */
	fprintf(stdout,"INFO: Loading dentry struct\n");
	dentry_value = target_load_value_member(target, NULL, path_value, "dentry",
							NULL, LOAD_FLAG_AUTO_DEREF);
	if(!dentry_value){
	    fprintf(stdout," INFO: dentry member is NULL\n");
	    continue;
	}
	fprintf(stdout,"INFO: Loading the d_count value \n");
	dcount_value = target_load_value_member(target, NULL, dentry_value, "d_count",
							NULL, LOAD_FLAG_NONE);
	if(!dcount_value) {
	    fprintf(stdout,"ERROR: failed to load the d_count value\n");
	    exit(0);
	}
	unsigned int d_count = v_u32(dcount_value);
	fprintf(stdout,"INFO: d_count value = %u\n",d_count);

	/*
	fprintf(stdout,"INFO: Loading the d_iname member\n");
	file_name_value = target_load_value_member(target, NULL, dentry_value, "d_iname",
						    NULL, LOAD_FLAG_AUTO_STRING);
	if(!file_name_value) {
	    fprintf(stdout," ERROR: Failed to load the d_iname member\n");
	    exit(0);
	}
	*/
	/* Load the d_name struct */
	fprintf(stdout,"INFO: Loading d_name struct\n");
	d_name_value = target_load_value_member(target, NULL, dentry_value, "d_name",
						NULL, LOAD_FLAG_NONE);
         if(!d_name_value) {
	    fprintf(stdout," ERROR: failed to load the d_name struct member.\n");
	    exit(0);
	}   

	/* Finally load thei lenght of  name string */
	fprintf(stdout,"INFO: Loading the length of name string\n");
	len_name_value = target_load_value_member( target, NULL, d_name_value, "len",
						NULL, LOAD_FLAG_NONE);
        if(!len_name_value) {
	    fprintf(stdout," ERROR: failed to load the name string.\n");
	    exit(0);
	}
	unsigned long len = v_u64(len_name_value);
	fprintf(stdout," The length of the name string is %ul \n",len);

	
	file_name_value = target_load_value_member(target, NULL, d_name_value, "name",
					    NULL, LOAD_FLAG_AUTO_STRING);
	if(!file_name_value) {
	    fprintf(stdout,"ERROR: Could not load name of the file\n");
	    continue;
	}
	

	file_name = strdup(file_name_value->buf);
	fprintf(stdout," -----File name: %s\n", file_name);
	fprintf(fp," %s", file_name);
	
	value_free(fd_value);
	value_free(file_value);
	value_free(fversion_value);
	value_free(path_value);
	value_free(dentry_value);
	value_free(d_name_value);
	value_free(file_name_value);
	
						
    }
    fprintf(fp,"))\n");

    fclose(fp);
    value_free(name_value);
    value_free(pid_value);
    value_free(files_value);
    value_free(next_fd_value);
    value_free(fdt_value);
    value_free(max_fds_value);
    
    
    return(0);
}



int file_info() {
    int ret_val;
    struct bsymbol * init_task_bsymbol;

    init_task_bsymbol = target_lookup_sym(target, "init_task", NULL, NULL,
						SYMBOL_TYPE_FLAG_VAR);
    if(!init_task_bsymbol) {
	fprintf(stdout,"ERROR: Could not lookup the init_task_symbol\n");
	return 1;
    }

    ret_val = linux_list_for_each_struct(target, init_task_bsymbol, "tasks", 0,
					    gather_file_info, NULL);
    return ret_val;
}



