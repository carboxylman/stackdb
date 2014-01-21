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

/* Macros for caomputing the CPU LOAD */
#define FSHIFT 11
#define FIXED_1 (1<<FSHIFT)
#define LOAD_INT(x) ((x) >> FSHIFT)
#define LOAD_FRAC(x) LOAD_INT(((x) & (FIXED_1-1)) * 100)

/* Macros for determining the file is a socket */
#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000

#define S_ISLNK(m)      (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)      (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)      (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)      (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)      (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)     (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)     (((m) & S_IFMT) == S_IFSOCK)




struct target *target;    
extern char base_fact_file[100];

#define NSEC_PER_SEC    1000000000L
#define HZ 100


unsigned long  div_u64(unsigned long dividend, unsigned int divisor) {
    return dividend / divisor;
}
 unsigned long div64_u64( unsigned long dividend, unsigned long divisor) {
    return dividend / divisor; 
}


unsigned long nsec_to_jiffies(unsigned long n) {
    return div_u64(n, NSEC_PER_SEC/HZ);
}

unsigned long scale_utime(unsigned long utime, unsigned long rtime, unsigned long total) {
    unsigned long temp;
    temp *= (unsigned long) utime;
    temp = div64_u64(temp, (unsigned long) total);
    return (unsigned long) temp;
}



/* timeval struct and  functions need to convert jiffies into sec 
struct time_val {
    long tv_sec;
    long tv_usec;
};
unsigned long tick_nsec = 0;


void jiffies_to_timeval(const unsigned long jiffies, struct timeval *value) {

    unsigned int  rem;
    value->tv_sec = div_u64_rem((unsigned long) jiffies * tick_nsec, 
							NSEC_PER_SEC, &rem);
    value->tv_usec = rem/NSEC_PER_SEC;
}
*/




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
    struct value *d_inode_value;
    struct value *i_mode_value;

    struct bsymbol *file_struct_bsymbol = NULL;
    int max_fds, i, pid, next_fd, counter;
    char *file_name = NULL , *process_name = NULL;
    ADDR file_addr, mem_addr;
    struct symbol *file_struct_type;
    unsigned short i_mode;

    FILE *fp = NULL;

    char lnk_file[64][100];
    int lnk = 0;
    char reg_file[64][100];
    int reg = 0;
    char dir_file[64][100];
    int dir = 0;
    char chr_file[64][100];
    int chr = 0;
    char blk_file[64][100];
    int blk = 0;
    char fifo_file[64][100];
    int fifo = 0;
    char sock_file[64][100];
    int sock = 0;


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
	    \t(pid %d)\n", process_name, pid);

    for( i = 0; i < max_fds; i++) {
	fprintf(stdout,"INFO: Loading fd struct\n");
	fd_value =  target_load_value_member(target, NULL, fdt_value, "fd", NULL, 
		LOAD_FLAG_NONE);
	if(!fd_value) {
	    fprintf(stdout," ERROR: failed to load the fd struct memeber.\n");
	    exit(0);
	}
	//fprintf(stdout," fd_value = 0x%"PRIxADDR" \n", fd_value->buf);

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

	/* Load the inode struct */
	fprintf(stdout,"INFO: Loading the d_inode struct.\n");
	d_inode_value = target_load_value_member(target, NULL, dentry_value, "d_inode",
						NULL, LOAD_FLAG_AUTO_DEREF);
	if(!d_inode_value) {
	    fprintf(stdout,"ERROR: failed to load the d_inode member.\n");
	    exit(0);
	}

	/*Load the i_mode member */
	fprintf(stdout,"INFO: Load the i_mode member.\n");
	i_mode_value = target_load_value_member(target, NULL, d_inode_value, "i_mode",
						NULL, LOAD_FLAG_NONE);
	i_mode = v_u16(i_mode_value);

	/* Now check for the type of the file*/
	
	if(S_ISLNK(i_mode)) {
	    fprintf(stdout,"INFO: The file is a link.\n");
	    strcpy(lnk_file[lnk++], file_name);
	}
	else if(S_ISREG(i_mode)) {
	    fprintf(stdout,"INFO: The file is a regular file.\n");
	    strcpy(reg_file[reg++], file_name);
	}
	else if(S_ISDIR(i_mode)){
	    fprintf(stdout,"INFO: The file is a directory.\n");
	    strcpy(dir_file[dir++], file_name);
	}
	else if(S_ISCHR(i_mode)) {
	    fprintf(stdout,"INFO: The file is a character file.\n");
	    strcpy(chr_file[chr++], file_name);
	}
	else if(S_ISFIFO(i_mode)){
	    fprintf(stdout,"INFO: The file is a FIFO file.\n");
	    strcpy(fifo_file[fifo++], file_name);
	}
	else if(S_ISSOCK(i_mode)) {
	    fprintf(stdout,"INFO: The file is a SOCKET.\n");
	    strcpy(sock_file[sock++], file_name);
	}
	else if(S_ISBLK(i_mode)) {
	    fprintf(stdout,"INFO: The file is a block file.\n");
	    strcpy(blk_file[blk++], file_name);
	}
	else {
	    fprintf(stdout,"INFO: Unknown file type for %s.\n", file_name);
	}

	value_free(fd_value);
	value_free(file_value);	
	value_free(path_value);
	value_free(dentry_value);
	value_free(d_inode_value);
	value_free(i_mode_value);
	value_free(d_name_value);
	value_free(file_name_value);

    }

    /* Write this infomation into the file as base facts  */
    int c = 0;
    if(lnk) {
	fprintf(fp,"\t (lnk_count %d) \n \
		    \t (lnk_files ",(lnk));
	for(c = 0; c < lnk; c++) {
	    fprintf(fp," \"%s\" ", lnk_file[c]);
	}
	fprintf(fp," )\n");
    }
    if(reg) {
	fprintf(fp,"\t (reg_count %d) \n \
	       \t (reg_files ",(reg));
	for(c = 0; c < reg; c++) {
	    fprintf(fp," \"%s\" ", reg_file[c]);
	}
	fprintf(fp," )\n");
    }

    if(dir) {
	fprintf(fp,"\t (dir_count %d) \n \
	       \t (dir_files ",(dir));
	for(c = 0; c < dir; c++) {
	    fprintf(fp," \"%s\" ", dir_file[c]);
	}
	 fprintf(fp," )\n");
    }

    if(chr) {
	fprintf(fp,"\t (chr_count %d) \n \
	       \t (chr_files ",(chr));
	for(c = 0; c < chr; c++) {
	    fprintf(fp," \"%s\" ", chr_file[c]);
	}
	fprintf(fp," )\n");
    }

    if(blk) {
	fprintf(fp,"\t (blk_count %d) \n \
	       \t (blk_files ",(blk));
	for(c = 0; c < blk; c++) {
	    fprintf(fp," \"%s\" ", blk_file[c]);
	}
	fprintf(fp," )\n");
    }

    if(fifo) {
	fprintf(fp,"\t (fifo_count %d) \n \
	       \t (fifo_files ",(fifo));
	for(c = 0; c < fifo; c++) {
	    fprintf(fp," \"%s\" ", fifo_file[c]);
	}
	fprintf(fp," )\n");
    }

    if(sock) {
	fprintf(fp,"\t (sock_count %d) \n \
	       \t (sock_files ",(sock));
	for(c = 0; c < sock; c++) {
	    fprintf(fp," \"%s\" ", sock_file[c]);
	}
	fprintf(fp," )\n");
    }

    fprintf(fp,"\t (num_opened_files %d ))\n",(lnk + reg + dir 
		+ chr + blk + fifo + sock ));
    
    fclose(fp);

    value_free(name_value);
    value_free(pid_value);
    value_free(files_value);
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



int gather_cpu_utilization(struct target *target, struct value *value, void * data) {

    struct value *sched_entity_value;
    struct value *pid_value;
    struct value *comm_value;
    struct value *utime_value;
    struct value *utimescaled_value;
    struct value *stimescaled_value;
    struct value *stime_value;
    struct value *sum_exec_runtime_value;
    struct value *vruntime_value;
    struct value *prev_cputime_value;
    struct value *prev_utime_value;
    struct value *prev_stime_value;
    struct value *jiffies_value;

    struct target_location_ctxt *tlctxt;
    struct bsysmbol *jiffies_bsymbol;
    target_status_t status;
    FILE * fp;
    int pid, i = 0;
    float cpu_utilization;
    char *process_name;
    unsigned long utime, stime, sum_exec_runtime, rtime, total;
    unsigned long prev_utime, prev_stime, jiffies;
    unsigned long vruntime, utimescaled, stimescaled;
    struct timeval utime_timeval, stime_timeval;
    unsigned long load[2], jiffy[2];

    pid_value = target_load_value_member(target, NULL, value, "pid", NULL, LOAD_FLAG_NONE);
    if(!pid_value) {
	fprintf(stdout,"ERROR: Failed to load the pid value.\n");
	exit(0);
    }
    pid = v_i32(pid_value);
    fprintf(stdout,"INFO: Pid %d\n",pid);

    comm_value = target_load_value_member(target, NULL, value, "comm", NULL, LOAD_FLAG_NONE);
    if(!comm_value) {
	fprintf(stdout,"ERROR: Failed to load the process name.\n");
	exit(0);
    }
    process_name = strdup(comm_value->buf);
    fprintf(stdout,"INFO: Process name %s\n",process_name);

    while(i < 2) {
	/* load the utime and stime  */
        utime_value = target_load_value_member(target, NULL, value, "utime", NULL, LOAD_FLAG_NONE);
	if(!utime_value) {
	    fprintf(stdout,"ERROR: Failed to load the utime value.\n");
	    exit(0);
	}
	utime = v_u64(utime_value);
	fprintf(stdout,"INFO: utime value %lu \n",utime);

	utimescaled_value = target_load_value_member(target, NULL, value, "utimescaled", NULL, LOAD_FLAG_NONE);
	if(!utimescaled_value) {
	    fprintf(stdout,"ERROR: Failed to load the utimescaled value.\n");
	   exit(0);
	}
	utimescaled= v_u64(utimescaled_value);
	fprintf(stdout,"INFO: utimescaled value %lu \n",utimescaled);


	stime_value = target_load_value_member(target, NULL, value, "stime", NULL, LOAD_FLAG_NONE);
	if(!stime_value) {
	    fprintf(stdout,"ERROR: Failed to load the stime value.\n");
	    exit(0);
	}
	stime = v_u64(stime_value);
	fprintf(stdout,"INFO: stime value %lu \n",stime);

	stimescaled_value = target_load_value_member(target, NULL, value, "stimescaled", NULL, LOAD_FLAG_NONE);
	if(!stimescaled_value) {
	    fprintf(stdout,"ERROR: Failed to load the stimescaled value.\n");
	    exit(0);
	}
	stimescaled = v_u64(stimescaled_value);
	fprintf(stdout,"INFO: stimescaled value %lu \n",stimescaled);

	/*Load the prev_cputime struct */
	prev_cputime_value = target_load_value_member(target, NULL, value, 
					"prev_cputime", NULL, LOAD_FLAG_NONE);
	if(!prev_cputime_value) {
	    fprintf(stdout,"ERROR: Filed to load the prev_cputime_value.\n");
	    exit(0);
	}

	/* Load the prev_utime and prev_stime members */

	prev_utime_value = target_load_value_member(target, NULL, prev_cputime_value,
	    					"utime",NULL, LOAD_FLAG_NONE);
	prev_utime = v_u64(prev_utime_value);
	fprintf(stdout,"INFO: prev_utime value %lu.\n",prev_utime);

	prev_stime_value = target_load_value_member(target, NULL, prev_cputime_value,
						    "stime",NULL, LOAD_FLAG_NONE);
	prev_stime = v_u64(prev_stime_value);
	fprintf(stdout,"INFO: prev_utime value %lu.\n",prev_stime);

	/* load the sched_entity struct */
	sched_entity_value = target_load_value_member(target, NULL, value, "se", NULL, LOAD_FLAG_NONE);
	if(!sched_entity_value) {
	    fprintf(stdout,"ERROR: Failed to load the sched_entity struct.\n");
	    exit(0);
	}

	/* load the sum_exec_runtime member */
	sum_exec_runtime_value = target_load_value_member(target, NULL, 
		sched_entity_value, "sum_exec_runtime", NULL, LOAD_FLAG_NONE);
	if(!sum_exec_runtime_value) {
	    fprintf(stdout,"ERROR: Failed to load the sum_exec_runtime.\n");
	    exit(0);
	}
	sum_exec_runtime = v_u64(sum_exec_runtime_value);
	fprintf(stdout,"INFO: sum_exec_runtime %lu \n",sum_exec_runtime);
 
	/* load the vruntime member */
	vruntime_value = target_load_value_member(target, NULL, sched_entity_value,
						"vruntime", NULL, LOAD_FLAG_NONE);
	if(!vruntime_value) {
	    fprintf(stdout,"ERROR: Failed to load the vruntime value,\n");
	    exit(0);
	}
	vruntime  = v_u64(vruntime_value);
	fprintf(stdout,"INFO: vruntime %lu.\n",vruntime);

	/* compute the adjusted cpu time */
	/*convert the runtime from nsec to jiffies */
	rtime = nsec_to_jiffies(sum_exec_runtime);
	fprintf(stdout,"INFO: rtime in jiffies %lu \n",rtime);
    
	/* total of utime and stime */
	total = utime + stime;
    
	if(total) 
	    utime = scale_utime(utime, rtime, total);
	else
	    utime = rtime;


	utime = (utime > prev_utime)? utime : prev_utime;
	stime = (stime > (rtime - utime))? stime : (rtime - utime);

	fprintf(stdout,"INFO: Scaled utime %lu\n",utime);
	fprintf(stdout,"INFO: Scaled stime %lu\n",stime);
	load[i] = utime + stime;

	fprintf(stdout,"INFO: Gather the current jiffies value.\n");
	jiffies_bsymbol = target_lookup_sym(target, "jiffies", NULL, NULL,
						SYMBOL_TYPE_FLAG_VAR);
	if(!jiffies_bsymbol) {
	    fprintf(stdout,"ERROR: filed to load the jiffies symbol.\n");
	    exit(0);
	}

	tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,jiffies_bsymbol);

	jiffies_value = target_load_symbol(target, tlctxt, jiffies_bsymbol, LOAD_FLAG_NONE);
	if(!jiffies_value) {
	    fprintf(stdout,"ERROR: Could not load the jifffies value.\n");
	    exit(0);
	}
	jiffies = v_u64(jiffies_value);
	fprintf(stdout,"INFO: The current jiffies value %lu. \n",jiffies);
	jiffy[i] = jiffies;

	/* now unpause the target and let it execute for 2 sec */
	if(i == 1) break;
	fprintf(stdout,"INFO: Resuming the target for 2 seconds.\n");
	if ((status = target_status(target)) == TSTATUS_PAUSED) {
	    if(target_resume(target)) {
		fprintf(stdout, "ERROR: Failed to resume the target.\n");
		exit(0);
	    }
	}

	sleep(2);
	
	if ((status = target_status(target)) != TSTATUS_PAUSED) {
	    if (target_pause(target)) {
		fprintf(stdout,"ERROR: Failed to pause the target \n");
		exit(0);
	    }
	}
	i = i + 1;

	value_free(utime_value);
	value_free(stime_value);

    }

    cpu_utilization = (float) (load[1] - load[0])/(jiffy[1]-jiffy[0]);
    fprintf(stdout,"INFO: CPU utilization for the process %f.\n",
						cpu_utilization);
	
	

    /* Now encode these values as facts */
    fprintf(stdout,"INFO: Opening base fact file: %s\n",base_fact_file);
    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	exit(0);
    }
    
    fprintf(fp,"( cpu_utilization \n    \
		    \t( comm \"%s\")\n    \
		    \t( pid %d)\n     \
		    \t( utime %lu)\n   \
		    \t( utimescaled %lu)\n \
		    \t( stime %lu) \n  \
		    \t( stimescaled %lu)\n \
		    \t( sum_exec_runtime %lu)\n \
		    \t( vruntime %lu))\n",
		    process_name, pid, utime, utimescaled,
		    stime, stimescaled, sum_exec_runtime, vruntime);

    fclose(fp);
    value_free(pid_value);
    value_free(comm_value);
    value_free(utime_value);
    value_free(utimescaled_value);
    value_free(stime_value);
    value_free(stimescaled_value);
    value_free(sum_exec_runtime_value);
    value_free(vruntime_value);

}

int process_cpu_utilization() {

    int ret_val;
    struct bsymbol * init_task_bsymbol;

    init_task_bsymbol = target_lookup_sym(target, "init_task", NULL, NULL,
	    SYMBOL_TYPE_FLAG_VAR);
    if(!init_task_bsymbol) {
	fprintf(stdout,"ERROR: Could not lookup the init_task_symbol\n");
	return 1;
    }

    ret_val = linux_list_for_each_struct(target, init_task_bsymbol, "tasks", 0,
	    gather_cpu_utilization, NULL);
    return ret_val;
}


