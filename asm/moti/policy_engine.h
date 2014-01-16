/*
 * Copyright (c) 2011, 2012, 2013, 2014  The University of Utah
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

#define FSHIFT 11
#define FIXED_1 (1<<FSHIFT)
#define LOAD_INT(x) ((x) >> FSHIFT)
#define LOAD_FRAC(x) LOAD_INT(((x) & (FIXED_1-1)) * 100)


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

    /* Now populate the base fact into the file. */
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
    struct value *count_value;
    struct value *counter_value;

    struct bsymbol *file_struct_bsymbol = NULL;
    int max_fds, i, pid, next_fd, counter;
    char *addr = NULL;
    char *file_name = NULL , *process_name = NULL, mem_buf = NULL;
    ADDR file_addr, mem_addr;
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

    fprintf(stdout,"INFO: Load the count memeber\n");
    count_value = target_load_value_member(target, NULL, files_value, "count",
	    NULL, LOAD_FLAG_NONE);
    if(!count_value) {
	fprintf(stdout,"ERROR: Failed to load the count member\n");
	exit(0);
    }

    fprintf(stdout,"INFO: Load the counter value\n");

    counter_value = target_load_value_member(target, NULL, count_value, "counter",
	    NULL, LOAD_FLAG_NONE);
    if(!counter_value) {
	fprintf(stdout,"ERROR: Failed to load the counter value\n");
	exit(0);
    }
    counter = v_i32(counter_value);
    fprintf(stdout,"INFO: Counter value = %d\n",counter);

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

    for( i = 0; i < max_fds; i++) {
	fprintf(stdout,"INFO: Loading fd struct\n");
	fd_value =  target_load_value_member(target, NULL, fdt_value, "fd", NULL, 
		LOAD_FLAG_NONE);
	if(!fd_value) {
	    fprintf(stdout," ERROR: failed to load the fd struct memeber.\n");
	    exit(0);
	}
	fprintf(stdout," fd_value = 0x%"PRIxADDR" \n", fd_value->buf);

	/* Load the array of file descriptors */
	fprintf(stdout,"INFO: Loading fs struct\n");
	/* This is the base address */
	mem_addr = v_addr(fd_value);
	fprintf(stdout,"INFO: mem_addr = 0x%"PRIxADDR"\n",mem_addr);

	mem_addr = mem_addr + (target->ptrsize * i);
	if(!target_read_addr(target, mem_addr, target->ptrsize, 
			(unsigned char *)&file_addr)) {
	    fprintf(stdout,"ERROR: target_read_addr failed.\n");
	    exit(0);
	}
	if(!file_addr) {
	    fprintf(stdout," INFO: File table entry is NULL\n");
	    continue;
	}

	fprintf(stdout,"INFO: file_addr = 0x%"PRIxADDR"\n",file_addr);
	
	/* Load the type of symbol */
	file_struct_bsymbol = target_lookup_sym(target, "struct file", NULL,
		    NULL, SYMBOL_TYPE_FLAG_TYPE);
	if(!file_struct_bsymbol) {
	    fprintf(stdout,"ERROR: Failed to lookup the struct file bsymbol.\n");
	    exit(0);
	}

	file_struct_type = bsymbol_get_symbol(file_struct_bsymbol);
	if(!file_struct_type) {
	    fprintf(stdout,"INFO: Could not load the file struct type\n");
	    exit(0);
	}

	/* Finally load the array memeber */
	fprintf(stdout,"INFO: Loading file struct\n");
	file_value = target_load_type(target, file_struct_type, file_addr, 
		    LOAD_FLAG_AUTO_DEREF);
	if(!file_value) {
	    fprintf(stdout," ERROR: failed to load the file struct member.\n");
	    exit(0);
	}

	/*    
	fprintf(stdout,"INFO: Calling linux_file_get_path.\n");
	file_name = malloc(100);
	file_name = linux_file_get_path(target, value, file_value, file_name, 100);
	if(!file_name) {
	    fprintf(stdout,"ERROR: failed to load the file name.\n");
	    continue;
	}
	fprintf(stdout,"--------------INFO: File name  = %s\n-------------", file_name);
	*/

	fversion_value = target_load_value_member(target, NULL, file_value, "f_version", NULL, LOAD_FLAG_NONE);
	if(!fversion_value) {
	    fprintf(stdout,"ERROR: Failed to load the file version\n");
	    exit(0);
	}
	unsigned long f_version;
	f_version = v_u64(fversion_value);
	fprintf(stdout,"INFO: File version = %lu\n",f_version);
	
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
	    fprintf(stdout,"INFO: dentry member is NULL\n");
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

	fprintf(stdout,"INFO: Loading the d_iname member\n");
	file_name_value = target_load_value_member(target, NULL, dentry_value, "d_iname",
	       NULL, LOAD_FLAG_NONE);
	if(!file_name_value) {
	    fprintf(stdout," ERROR: Failed to load the d_iname member\n");
	    exit(0);
	}
    


	/* Load the d_name struct */
	fprintf(stdout,"INFO: Loading d_name struct\n");
	d_name_value = target_load_value_member(target, NULL, dentry_value, "d_name",
		    NULL, LOAD_FLAG_NONE);
	if(!d_name_value) {
	    fprintf(stdout," ERROR: failed to load the d_name struct member.\n");
	    exit(0);
	} 
	/* Finally load the lenght of  name string */
	fprintf(stdout,"INFO: Loading the length of name string\n");
	len_name_value = target_load_value_member( target, NULL, d_name_value, "len",
		    NULL, LOAD_FLAG_NONE);
	if(!len_name_value) {
	    fprintf(stdout," ERROR: failed to load the name string.\n");
	    exit(0);
	}
	unsigned int len = v_u32(len_name_value);
	fprintf(stdout,"INFO: Length of the name string is %u \n.",len);
	if(len == 0) {
	    fprintf(stdout,"INFO: File name length is 0 hence continuing with the loop\n");
	    continue;
	}


	file_name_value = target_load_value_member(target, NULL, d_name_value, "name",
		    NULL, LOAD_FLAG_AUTO_STRING);
	if(!file_name_value) {
	    fprintf(stdout,"ERROR: Could not load name of the file\n");
	    continue;
	}

	file_name = strdup(file_name_value->buf);

	fprintf(stdout,"INFO: File name: %s\n", file_name);
	fprintf(fp," \"%s\"", file_name);

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




int gather_module_info(struct target *target, struct value * value, void * data) {


    struct value *name_value;
    char *module_name;
    FILE *fp = NULL;

    fprintf(stdout,"INFO: Gathering information of open modules\n");
    
    fprintf(stdout,"INFO: Loading the name of the module.\n");
    name_value = target_load_value_member(target, NULL, value, "name", NULL, LOAD_FLAG_NONE);
    if(!name_value) {
	fprintf(stdout," ERROR: failed to load the process name.\n");
	exit(0);
    }   

    module_name = strdup(name_value->buf);
    fprintf(stdout,"INFO: Module name: %s.\n",module_name);
    
    fprintf(stdout,"INFO: Opening base fact file: %s\n",base_fact_file);
    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	exit(0);
    }

    /* Start encoding the fact */
    fprintf(stdout,"INFO: Encode the base facts.\n");
    fprintf(fp," \"%s\" ", module_name);    
    fclose(fp);

}


int module_info() {
    int ret_val;
    FILE *fp = NULL;

    struct bsymbol *module_bsymbol;
    struct bsymbl *listhead_bsymbol;

    module_bsymbol = target_lookup_sym(target,"struct module", NULL, NULL,
						SYMBOL_TYPE_FLAG_TYPE);
    if(!module_bsymbol) {
	fprintf(stdout," ERROR: Could not look up the struct module bsymbol.\n");
	return 1;
    }

    listhead_bsymbol = target_lookup_sym(target,"modules", NULL, NULL,
						SYMBOL_TYPE_FLAG_VAR);
    if(!listhead_bsymbol) {
	fprintf(stdout,"ERROR: Could not lookup the modules bsymbol.\n");
	return 1;
    }

    fprintf(stdout,"INFO: Opening base fact file: %s\n",base_fact_file);
    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	exit(0);
    }

    /* Start encoding the fact */
    fprintf(stdout,"INFO: Encode the base facts.\n");
    fprintf(fp,"\n(loaded-modules\n \
	    \t(name ");
    fclose(fp);

    ret_val =  linux_list_for_each_entry(target, module_bsymbol, listhead_bsymbol,
					    "list",0, gather_module_info, NULL);
    
    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	exit(0);
    }

    fprintf(fp,"))\n");
    fclose(fp);
   
    return ret_val;
}

int cpu_load_info()
{
    int ret_val = 0;
    unsigned long avenrun0, avenrun1, avenrun2;
    struct bsymbol *avenrun_bsymbol;
    struct value *avenrun_value;
    ADDR base_addr;
    struct target_location_ctxt *tlctxt;
    FILE *fp;
    
    fprintf(stdout,"INFO: Gathering the CPU load information.\n");
    avenrun_bsymbol = target_lookup_sym(target, "avenrun", NULL, NULL,
						    SYMBOL_TYPE_FLAG_VAR);
    if(!avenrun_bsymbol) {
	fprintf(stdout,"ERROR: filed to load the avenrun symbol.\n");
	exit(0);
    }

    tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,avenrun_bsymbol);

    avenrun_value = target_load_symbol(target, tlctxt, avenrun_bsymbol, LOAD_FLAG_NONE);
    if(!avenrun_value) {
	fprintf(stdout,"ERROR: Could not load the avenrun array.\n");
	exit(0);
    }

    /* copy the array items */
    memcpy( (void *)&avenrun0, avenrun_value->buf, 8);
    avenrun0 = avenrun0 + (FIXED_1/200);
    fprintf(stdout,"INFO: CPU load during the last 1 minute %lu.%02lu\n",
	    LOAD_INT(avenrun0), LOAD_FRAC(avenrun0)); 

    memcpy( (void *)&avenrun1, (avenrun_value->buf + 8), 8);
    avenrun1 = avenrun1 + (FIXED_1/200);
    fprintf(stdout,"INFO: CPU load during the last 5 minutes %lu.%02lu\n",
	    LOAD_INT(avenrun1), LOAD_FRAC(avenrun1));     

    memcpy( (void *)&avenrun2, (avenrun_value->buf + 16), 8);
    avenrun2 = avenrun2 + (FIXED_1/200);
    fprintf(stdout,"INFO: CPU load during the last 15 minutes %lu.%02lu\n",
	    LOAD_INT(avenrun2), LOAD_FRAC(avenrun2)); 

    fprintf(stdout,"INFO: Opening base fact file: %s\n",base_fact_file);
    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	exit(0);
    }

    /* Start encoding the fact */
    fprintf(stdout,"INFO: Encode the base facts.\n");
    fprintf(fp,"\n(cpu-load\n \
	    \t(one-min  %lu.%02lu)\n \
	    \t(five-min %lu.%02lu)\n \
	    \t(fifteen-min %lu.%02lu))\n", 
	    LOAD_INT(avenrun0), LOAD_FRAC(avenrun0),
	    LOAD_INT(avenrun1), LOAD_FRAC(avenrun1),
	    LOAD_INT(avenrun2), LOAD_FRAC(avenrun2));
    
    fclose(fp);
    return ret_val;
}



	


    


