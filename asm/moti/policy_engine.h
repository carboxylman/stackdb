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


#include "target_os.h"
#include "target_os_linux_generic.h"
#include <unistd.h>

/* Macros for caomputing the CPU LOAD */
#define FSHIFT 11
#define FIXED_1 (1<<FSHIFT)
#define LOAD_INT(x) ((x) >> FSHIFT)
#define LOAD_FRAC(x) LOAD_INT(((x) & (FIXED_1-1)) * 100)

#ifndef S_IFMT
/* Macros for distuinguishing between different kinds of files */
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
#endif

/* Macros to covert between priority and nice values*/
#define LINUX_MAX_RT_PRIO 100
#define LINUX_NICE_TO_PRIO(nice)      (LINUX_MAX_RT_PRIO + (nice) + 20)
#define LINUX_PRIO_TO_NICE(prio)      ((prio) - LINUX_MAX_RT_PRIO - 20)

/* Per proces flags */
#define LINUX_PF_VCPU         0x00000010  
#define LINUX_PF_WQ_WORKER    0x00000020
#define LINUX_PF_SUPERPRIV    0x00000100
#define LINUX_PF_KTHREAD      0x00200000
#define LINUX_PF_KSWAPD       0x00040000


struct pe_argp_state {
    char *app_file_path;
    char *recovery_rules_file;
    int wait_time;
    int dump_timing;
    int dump_debug;
    int disable_recovery;
#ifdef ENABLE_A3
    char *a3_server;
#endif
			    
    int argc;
    char **argv;
    /* Grab this from the child parser. */
    struct target_spec *tspec;
};

struct pe_argp_state opts;


struct target *target;    
extern char base_fact_file[100];
extern unsigned long *sys_call_table;
extern char **sys_call_names;
extern unsigned long **function_prologue;

#define NSEC_PER_SEC    1000000000L
#define HZ 100

#define VALUE_FREE(v)	{ value_free(v); v = NULL; }

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
    temp = (unsigned long )rtime;
    temp *= (unsigned long) utime;
    temp = div64_u64(temp, (unsigned long) total);
    return (unsigned long) temp;
}

/*
int gather_child_process_info(struct target* target, struct value* value, void *data) {

    struct value *pid_v;
    int pid;
    struct value *name_v;
    char *name;

    pid_v = target_load_value_member(target, NULL, value, "pid", NULL, LOAD_FLAG_NONE);
    pid = v_i32(pid_v);
    VALUE_FREE(pid_v);
    name_v = target_load_value_member(target, NULL, value, "comm", NULL, LOAD_FLAG_NONE);
    name = strdup(name_v->buf);
    VALUE_FREE(name_v);

    fprintf(stdout,"INFO: Child process name %s, pid %d\n",name, pid); 
    return 0;
}
*/


int ps_gather(struct target *target, struct value * value, void * data) {

    struct value *tval;
    int pid;
    unsigned int uid;
    char *name;
    unsigned int euid;
    unsigned int suid;
    unsigned int fsuid;
    unsigned int gid;
    unsigned int egid;
    unsigned int sgid;
    unsigned int fsgid;
    int prio;
    int static_prio;
    int normal_prio;
    int rt_priority;
    int parent_pid;
    char *parent_name;
    int tgid;
    unsigned int flags;
    int nice;
    int vcpu = 0 , wq_worker = 0, kswapd = 0;
    int kthread = 0, used_superpriv = 0;

    ADDR real_cred_addr;
    struct symbol *cred_struct_type = NULL;
    struct bsymbol *bsym;
    struct value *cred_struct_v;
    struct value *parent_task_struct_v;
    FILE * fp;

    tval = target_load_value_member(target, NULL, value, "pid", NULL, LOAD_FLAG_NONE);
    pid = v_i32(tval);
    VALUE_FREE(tval);
    
    tval = target_load_value_member(target, NULL, value, "comm", NULL, LOAD_FLAG_NONE);
    name = strdup(tval->buf);
    VALUE_FREE(tval);

    tval = target_load_value_member(target, NULL, value, "tgid", NULL, LOAD_FLAG_NONE);
    tgid = v_i32(tval);
    VALUE_FREE(tval);

    /* load the process priorities */
    tval = target_load_value_member(target, NULL, value, "prio", NULL, LOAD_FLAG_NONE);
    prio = v_i32(tval);
    VALUE_FREE(tval);

    tval = target_load_value_member(target, NULL, value, "static_prio", NULL, LOAD_FLAG_NONE);
    static_prio = v_i32(tval);
    VALUE_FREE(tval);

    tval = target_load_value_member(target, NULL, value, "normal_prio", NULL, LOAD_FLAG_NONE);
    normal_prio = v_i32(tval);
    VALUE_FREE(tval);

    tval = target_load_value_member(target, NULL, value, "rt_priority", NULL, LOAD_FLAG_NONE);
    rt_priority = v_i32(tval);
    VALUE_FREE(tval);


    /* Compute the NICE value based on the priority */
    nice = LINUX_PRIO_TO_NICE(static_prio);
    
    /* Load the per-process flags */
    tval = target_load_value_member(target, NULL, value, "flags", NULL, LOAD_FLAG_NONE);
    flags = v_u32(tval);
    VALUE_FREE(tval);

    /* check if the process is a vcpu */
    if(flags & LINUX_PF_VCPU)
	vcpu = 1;
    /* check if the process is a work queue worker */
    if(flags & LINUX_PF_WQ_WORKER)
	wq_worker = 1;
    /* Check if the process has used super user privileges */
    if(flags & LINUX_PF_SUPERPRIV)
	used_superpriv = 1;
    /* check if the process is a kswap daemon */
    if(flags & LINUX_PF_KSWAPD)
	kswapd = 1;
    /* check if the process is a kernel thread */
    if(flags & LINUX_PF_KTHREAD)
	kthread = 1;

    tval = target_load_value_member(target, NULL, value, "real_cred", NULL, LOAD_FLAG_NONE);
    if (!tval)
	real_cred_addr = 0;
    else {
	real_cred_addr = v_addr(tval);
	VALUE_FREE(tval);
    }
    bsym = target_lookup_sym(target, "struct cred", NULL, "cred", SYMBOL_TYPE_FLAG_TYPE);
    cred_struct_type = bsymbol_get_symbol(bsym);

    cred_struct_v = target_load_type(target, cred_struct_type,real_cred_addr, LOAD_FLAG_NONE);
    if(!cred_struct_v) {
	fprintf(stdout,"ERROR: Failed to load type of struct cred.\n");
	if (bsym)
	    bsymbol_release(bsym);
	free(name);
	return 1;
    }

    tval = target_load_value_member(target, NULL, cred_struct_v, "uid", NULL, LOAD_FLAG_NONE);
    uid = v_u16(tval);
    VALUE_FREE(tval);
    tval = target_load_value_member(target, NULL, cred_struct_v, "euid", NULL, LOAD_FLAG_NONE);
    euid = v_u16(tval);
    VALUE_FREE(tval);
    tval = target_load_value_member(target, NULL, cred_struct_v, "suid", NULL, LOAD_FLAG_NONE);
    suid = v_u16(tval);
    VALUE_FREE(tval);
    tval = target_load_value_member(target, NULL, cred_struct_v, "fsuid", NULL, LOAD_FLAG_NONE);
    fsuid = v_u16(tval);
    VALUE_FREE(tval);
    tval = target_load_value_member(target, NULL, cred_struct_v, "gid", NULL, LOAD_FLAG_NONE);
    gid = v_u16(tval);
    VALUE_FREE(tval);
    tval = target_load_value_member(target, NULL, cred_struct_v, "egid", NULL, LOAD_FLAG_NONE);
    egid = v_u16(tval);
    VALUE_FREE(tval);
    tval = target_load_value_member(target, NULL, cred_struct_v, "sgid", NULL, LOAD_FLAG_NONE);
    sgid = v_u16(tval);
    VALUE_FREE(tval);
    tval = target_load_value_member(target, NULL, cred_struct_v, "fsgid", NULL, LOAD_FLAG_NONE);
    fsgid = v_u16(tval);
    VALUE_FREE(tval);
    VALUE_FREE(cred_struct_v);
    if (bsym)
	bsymbol_release(bsym);

    /* Load information about the parent process */
    parent_task_struct_v = target_load_value_member(target, NULL, value, "real_parent", NULL, LOAD_FLAG_AUTO_DEREF);

    tval = target_load_value_member(target, NULL, parent_task_struct_v, "pid", NULL, LOAD_FLAG_NONE);
    parent_pid = v_i32(tval);
    VALUE_FREE(tval);

    tval = target_load_value_member(target, NULL, parent_task_struct_v, "comm", NULL, LOAD_FLAG_NONE);
    parent_name = strdup(tval->buf);
    VALUE_FREE(tval);
    VALUE_FREE(parent_task_struct_v);

    /* Now populate the base fact into the file. */
    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	free(name);
	free(parent_name);
	return 1;
    }
    
    fprintf(fp,"\n(task-struct\n \
	    \t(comm \"%s\")\n\
	    \t(pid %d)\n\
	    \t(tgid %d)\n\
            \t(is_vcpu %d)\n\
	    \t(is_wq_worker %d)\n\
	    \t(used_superpriv %d)\n\
	    \t(is_kswapd %d)\n\
	    \t(is_kthread %d)\n\
	    \t(prio %d)\n\
	    \t(static_prio %d)\n\
	    \t(normal_prio %d)\n\
	    \t(rt_priority %d)\n\
	    \t(nice %d)\n\
	    \t(uid %hu)\n\
	    \t(euid %hu)\n\
	    \t(suid %hu)\n\
	    \t(fsuid %hu)\n\
	    \t(gid %hu)\n\
	    \t(egid %hu)\n\
	    \t(sgid %hu)\n\
	    \t(fsgid %hu)\n\
	    \t(parent_pid %d)\n\
	    \t(parent_name \"%s\"))\n",name,pid,tgid,vcpu,wq_worker,used_superpriv,kswapd,kthread,
	    prio,static_prio,normal_prio,rt_priority,
	    nice,uid,euid,suid,fsuid,gid,egid,sgid,fsgid,
	    parent_pid, parent_name);

    fclose(fp);
    free(name);
    free(parent_name);
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

    ret_val = os_linux_list_for_each_struct(target, init_task_bsymbol, "tasks",0,ps_gather, NULL);
    bsymbol_release(init_task_bsymbol);
    return ret_val;
}

int gather_file_info(struct target *target, struct value * value, void * data) {

    struct value *files_value = NULL;
    struct value *fdt_value = NULL;
    struct value *max_fds_value = NULL;
    struct value *fd_value;
    struct value *file_value = NULL;
    struct value *path_value = NULL;
    struct value *dentry_value = NULL;
    struct value *name_value;
    struct value *d_name_value = NULL;
    struct value *len_name_value;
    struct value *file_name_value;
    struct value *pid_value;
    struct value *d_inode_value;
    struct value *i_mode_value;
    struct bsymbol *file_struct_bsymbol = NULL;
    int max_fds, i, pid;
    char *file_name = NULL, *process_name = NULL;
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

    if (opts.dump_debug)
	fprintf(stdout,"INFO: Gathering list of open files\n");
    pid_value = target_load_value_member(target, NULL, value, "pid", NULL, LOAD_FLAG_NONE);
    if(!pid_value) {
	fprintf(stdout," ERROR: failed to load the pid value.\n");
	return 1;
    }
    pid = v_i32(pid_value);
    VALUE_FREE(pid_value);
    name_value = target_load_value_member(target, NULL, value, "comm", NULL, LOAD_FLAG_NONE);
    if(!name_value) {
	fprintf(stdout," ERROR: failed to load the process name for pid %d.\n", pid);
	return 1;
    }   
    process_name = strdup(name_value->buf);
    VALUE_FREE(name_value);
    if (opts.dump_debug)
	fprintf(stdout,"INFO: Loading open file info for pid %d (%s).\n", pid, process_name);

    /* Load the files struct from the task_struct */
    if (opts.dump_debug)
	fprintf(stdout,"INFO: Loading files struct\n");
    files_value = target_load_value_member(target, NULL, value, "files", NULL, 
					   LOAD_FLAG_NONE);
    if (!files_value) {
	fprintf(stdout," ERROR: failed to load the files struct member.\n");
	goto fail;
    }   
    if (!v_addr(files_value)) {
	/* NULL address indicates a zombie/dead process */
	max_fds = 0;
    } else {
	VALUE_FREE(files_value);
	files_value = target_load_value_member(target, NULL, value, "files", NULL, 
					       LOAD_FLAG_AUTO_DEREF);
	if(!files_value) {
	    fprintf(stdout," ERROR: failed to load the files struct member.\n");
	    goto fail;
	}   

	/* Load the fdtable struct */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading fdt struct\n");
	fdt_value =  target_load_value_member( target, NULL, files_value, "fdt", 
					       NULL, LOAD_FLAG_AUTO_DEREF);
	if(!fdt_value) {
	    fprintf(stdout," ERROR: failed to load the fdt struct member.\n");
	    goto fail;
	}   

	/* Load the  max_fds member of the ftable struct */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading max_fds member\n");
	max_fds_value = target_load_value_member( target, NULL, fdt_value, 
						  "max_fds", NULL, LOAD_FLAG_NONE);
	if(!max_fds_value) {
	    fprintf(stdout," ERROR: failed to load the max_fds member.\n");
	    goto fail;
	}   
	max_fds = v_i32(max_fds_value);
	VALUE_FREE(max_fds_value);
    }
    if (opts.dump_debug)	
	fprintf(stdout,"INFO: max_fds_value for process %s = %d\n", process_name, max_fds);
    
    /*Open the base fact file */
    if (opts.dump_debug)
	fprintf(stdout,"INFO: Opening base fact file: %s\n",base_fact_file);
    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	goto fail;
    }

    /* Start encoding the fact */
    fprintf(fp,"\n(opened-files\n \
	    \t(comm \"%s\")\n \
	    \t(pid %d)\n", process_name, pid);

    free(process_name);
    process_name = NULL;

    for( i = 0; i < max_fds; i++) {
	unsigned int len;

	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading fd struct\n");
	fd_value =  target_load_value_member(target, NULL, fdt_value, "fd", NULL, 
					     LOAD_FLAG_NONE);
	if(!fd_value) {
	    fprintf(stdout," ERROR: failed to load the fd struct memeber.\n");
	    goto fail;
	}

	/* Load the array of file descriptors */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading fs struct\n");
	mem_addr = v_addr(fd_value);
	VALUE_FREE(fd_value);
	mem_addr = mem_addr + (target->arch->wordsize * i);
	if(!target_read_addr(target, mem_addr, target->arch->wordsize, 
			(unsigned char *)&file_addr)) {
	    fprintf(stdout,"ERROR: target_read_addr failed.\n");
	    goto fail;
	}
	if(!file_addr) {
	    if (opts.dump_debug)
		fprintf(stdout," INFO: File table entry is NULL\n");
	    continue;
	}
	
	/* Load the type of symbol */
	file_struct_bsymbol = target_lookup_sym(target, "struct file", NULL,
						NULL, SYMBOL_TYPE_FLAG_TYPE);
	if(!file_struct_bsymbol) {
	    fprintf(stdout,"ERROR: Failed to lookup the struct file bsymbol.\n");
	    goto fail;
	}

	file_struct_type = bsymbol_get_symbol(file_struct_bsymbol);
	if(!file_struct_type) {
	    fprintf(stdout,"INFO: Could not load the file struct type\n");
	    goto fail;
	}

	/* Finally load the array memeber */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading file struct\n");
	file_value = target_load_type(target, file_struct_type, file_addr, 
				      LOAD_FLAG_AUTO_DEREF);
	if(!file_value) {
	    fprintf(stdout," ERROR: failed to load the file struct member.\n");
	    goto fail;
	}

	/* Load the path the variable from the files struct*/
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading f_path struct\n");
	path_value = target_load_value_member( target, NULL, file_value, "f_path",
					       NULL, LOAD_FLAG_NONE);
	if(!path_value) {
	    fprintf(stdout," ERROR: failed to load the path struct member.\n");
	    goto fail;
	} 

	/* Load the dentry struct  member from the path */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading dentry struct\n");
	dentry_value = target_load_value_member(target, NULL, path_value, "dentry",
		    NULL, LOAD_FLAG_AUTO_DEREF);
	if(!dentry_value){
	    VALUE_FREE(path_value);
	    VALUE_FREE(file_value);
	    bsymbol_release(file_struct_bsymbol);
	    fprintf(stdout,"INFO: dentry member is NULL\n");
	    continue;
	}

	/* Load the d_name struct */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading d_name struct\n");
	d_name_value = target_load_value_member(target, NULL, dentry_value, "d_name",
		    NULL, LOAD_FLAG_NONE);
	if(!d_name_value) {
	    fprintf(stdout," ERROR: failed to load the d_name struct member.\n");
	    goto fail;
	} 

	/* Finally load the length of  name string */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading the length of name string\n");
	len_name_value = target_load_value_member( target, NULL, d_name_value, "len",
		    NULL, LOAD_FLAG_NONE);
	if(!len_name_value) {
	    fprintf(stdout," ERROR: failed to load the name string.\n");
	    goto fail;
	}
	len = v_u32(len_name_value);
	VALUE_FREE(len_name_value);
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Length of the name string is %u \n.",len);
	if(len == 0) {
	    if (opts.dump_debug)
		fprintf(stdout,"INFO: File name length is 0 hence continuing with the loop\n");
	    VALUE_FREE(d_name_value);
	    VALUE_FREE(dentry_value);
	    VALUE_FREE(path_value);
	    VALUE_FREE(file_value);
	    bsymbol_release(file_struct_bsymbol);
	    continue;
	}

	file_name_value = target_load_value_member(target, NULL, d_name_value, "name",
		    NULL, LOAD_FLAG_AUTO_STRING);
	if(!file_name_value) {
	    fprintf(stdout,"ERROR: Could not load name of the file\n");
	    VALUE_FREE(d_name_value);
	    VALUE_FREE(dentry_value);
	    VALUE_FREE(path_value);
	    VALUE_FREE(file_value);
	    bsymbol_release(file_struct_bsymbol);
	    continue;
	}

	file_name = strdup(file_name_value->buf);
	VALUE_FREE(file_name_value);
	VALUE_FREE(d_name_value);

	/* Load the inode struct */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading the d_inode struct.\n");
	d_inode_value = target_load_value_member(target, NULL, dentry_value, "d_inode",
						 NULL, LOAD_FLAG_AUTO_DEREF);
	if(!d_inode_value) {
	    fprintf(stdout,"ERROR: failed to load the d_inode member.\n");
	    goto fail;
	}

	/*Load the i_mode member */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Load the i_mode member.\n");
	i_mode_value = target_load_value_member(target, NULL, d_inode_value, "i_mode",
						NULL, LOAD_FLAG_NONE);
	if(!i_mode_value) {
	    fprintf(stdout,"ERROR: failed to load the i_mode value.\n");
	    VALUE_FREE(d_inode_value);
	    goto fail;
	}
	i_mode = v_u16(i_mode_value);
	VALUE_FREE(i_mode_value);
	VALUE_FREE(d_inode_value);

	VALUE_FREE(dentry_value);
	VALUE_FREE(path_value);
	VALUE_FREE(file_value);
	bsymbol_release(file_struct_bsymbol);
	file_struct_bsymbol = NULL;

	/* Now check for the type of the file*/
	if(S_ISLNK(i_mode)) {
	    //fprintf(stdout,"INFO: The file is a link.\n");
	    strcpy(lnk_file[lnk++], file_name);
	}
	else if(S_ISREG(i_mode)) {
	    //fprintf(stdout,"INFO: The file is a regular file.\n");
	    strcpy(reg_file[reg++], file_name);
	}
	else if(S_ISDIR(i_mode)){
	    //fprintf(stdout,"INFO: The file is a directory.\n");
	    strcpy(dir_file[dir++], file_name);
	}
	else if(S_ISCHR(i_mode)) {
	    //fprintf(stdout,"INFO: The file is a character file.\n");
	    strcpy(chr_file[chr++], file_name);
	}
	else if(S_ISFIFO(i_mode)){
	    //fprintf(stdout,"INFO: The file is a FIFO file.\n");
	    strcpy(fifo_file[fifo++], file_name);
	}
	else if(S_ISSOCK(i_mode)) {
	    //fprintf(stdout,"INFO: The file is a SOCKET.\n");
	    strcpy(sock_file[sock++], file_name);
	}
	else if(S_ISBLK(i_mode)) {
	    //fprintf(stdout,"INFO: The file is a block file.\n");
	    strcpy(blk_file[blk++], file_name);
	}
	else {
	    //fprintf(stdout,"INFO: Unknown file type for %s.\n", file_name);
	}

	free(file_name);
	file_name = NULL;
    }

    if (fdt_value)
	VALUE_FREE(fdt_value);
    if (files_value)
	VALUE_FREE(files_value);

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

    return(0);

 fail:
    if (d_name_value)
	VALUE_FREE(d_name_value);
    if (dentry_value)
	VALUE_FREE(dentry_value);
    if (path_value)
	VALUE_FREE(path_value);
    if (file_value)
	VALUE_FREE(file_value);
    if (file_struct_bsymbol)
	bsymbol_release(file_struct_bsymbol);
    if (fp)
	fclose(fp);
    if (fdt_value)
	VALUE_FREE(fdt_value);
    if (files_value)
	VALUE_FREE(files_value);
    if (process_name)
	free(process_name);

    return 1;
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

    ret_val = os_linux_list_for_each_struct(target, init_task_bsymbol, "tasks", 0,
	    gather_file_info, NULL);
    bsymbol_release(init_task_bsymbol);
    return ret_val;
}




int gather_module_info(struct target *target, struct value * value, void * data) {


    struct value *name_value;
    char *module_name;
    FILE *fp = NULL;

    if(opts.dump_debug) 
	fprintf(stdout,"INFO: Gathering information about the loaded modules\n");
    
    if (opts.dump_debug)
	fprintf(stdout,"INFO: Loading the name of the module.\n");
    name_value = target_load_value_member(target, NULL, value, "name", NULL, LOAD_FLAG_NONE);
    if(!name_value) {
	fprintf(stdout," ERROR: failed to load the process name.\n");
	return 1;
    }   

    module_name = strdup(name_value->buf);
    VALUE_FREE(name_value);
    if (opts.dump_debug)
	fprintf(stdout,"INFO: Module name: %s.\n",module_name);
    
    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	free(module_name);
	return 1;
    }

    /* Start encoding the fact */
    fprintf(fp,"\n(loaded-module\n \
	    \t(name  \"%s\"))\n",module_name); 
    
    fclose(fp);
    free(module_name);
    return 0;
}


int module_info() {
    int ret_val;

    struct bsymbol *module_bsymbol;
    struct bsymbol *listhead_bsymbol;

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

    ret_val =  os_linux_list_for_each_entry(target, module_bsymbol, listhead_bsymbol,
					    "list",0, gather_module_info, NULL);
    
    bsymbol_release(listhead_bsymbol);
    bsymbol_release(module_bsymbol);

    return ret_val;
}

int cpu_load_info()
{
    unsigned long avenrun0, avenrun1, avenrun2;
    struct bsymbol *avenrun_bsymbol;
    struct value *avenrun_value;
    struct target_location_ctxt *tlctxt;
    FILE *fp;
    
    if (opts.dump_debug)
	fprintf(stdout,"INFO: Gathering the CPU load information.\n");
    avenrun_bsymbol = target_lookup_sym(target, "avenrun", NULL, NULL,
					SYMBOL_TYPE_FLAG_VAR);
    if(!avenrun_bsymbol) {
	fprintf(stdout,"ERROR: filed to load the avenrun symbol.\n");
	return 1;
    }

    tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,avenrun_bsymbol);

    avenrun_value = target_load_symbol(target, tlctxt, avenrun_bsymbol, LOAD_FLAG_NONE);
    if(!avenrun_value) {
	fprintf(stdout,"ERROR: Could not load the avenrun array.\n");
	target_location_ctxt_free(tlctxt);
	bsymbol_release(avenrun_bsymbol);
	return 1;
    }

    /* copy the array items */
    memcpy( (void *)&avenrun0, avenrun_value->buf, 8);
    avenrun0 = avenrun0 + (FIXED_1/200);

    memcpy( (void *)&avenrun1, (avenrun_value->buf + 8), 8);
    avenrun1 = avenrun1 + (FIXED_1/200);
    
    memcpy( (void *)&avenrun2, (avenrun_value->buf + 16), 8);
    avenrun2 = avenrun2 + (FIXED_1/200);

    VALUE_FREE(avenrun_value);

    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	target_location_ctxt_free(tlctxt);
	bsymbol_release(avenrun_bsymbol);
	return 1;
    }

    /* Start encoding the fact */
    fprintf(fp,"\n(cpu-load\n \
	    \t(one-min  %lu.%02lu)\n \
	    \t(five-min %lu.%02lu)\n \
	    \t(fifteen-min %lu.%02lu))\n", 
	    LOAD_INT(avenrun0), LOAD_FRAC(avenrun0),
	    LOAD_INT(avenrun1), LOAD_FRAC(avenrun1),
	    LOAD_INT(avenrun2), LOAD_FRAC(avenrun2));
    
    fclose(fp);

    target_location_ctxt_free(tlctxt);
    bsymbol_release(avenrun_bsymbol);
    return 0;
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
    struct value *jiffies_value;

    struct target_location_ctxt *tlctxt;
    struct bsymbol *jiffies_bsymbol;
    target_status_t status;
    FILE * fp;
    int pid, i = 0;
    float cpu_utilization;
    char *process_name;
    unsigned long utime, stime, sum_exec_runtime, jiffies;
    unsigned long vruntime, utimescaled, stimescaled;
    struct timeval;
    unsigned long load[2], jiffy[2];

    pid_value = target_load_value_member(target, NULL, value, "pid", NULL, LOAD_FLAG_NONE);
    if(!pid_value) {
	fprintf(stdout,"ERROR: Failed to load the pid value.\n");
	return 1;
    }
    pid = v_i32(pid_value);
    VALUE_FREE(pid_value);

    comm_value = target_load_value_member(target, NULL, value, "comm", NULL, LOAD_FLAG_NONE);
    if(!comm_value) {
	fprintf(stdout,"ERROR: Failed to load the process name.\n");
	return 1;
    }
    process_name = strdup(comm_value->buf);
    VALUE_FREE(comm_value);

    while(i < 2) {
	utime = stime = 0;
	/* load the utime and stime  */
        utime_value = target_load_value_member(target, NULL, value, "utime", NULL, LOAD_FLAG_NONE);
	if(!utime_value) {
	    fprintf(stdout,"ERROR: Failed to load the utime value.\n");
	    free(process_name);
	    return 1;
	}
	utime = v_u64(utime_value);
	VALUE_FREE(utime_value);

	utimescaled_value = target_load_value_member(target, NULL, value, "utimescaled", NULL, LOAD_FLAG_NONE);
	if(!utimescaled_value) {
	    fprintf(stdout,"ERROR: Failed to load the utimescaled value.\n");
	    free(process_name);
	    return 1;
	}
	utimescaled= v_u64(utimescaled_value);
	VALUE_FREE(utimescaled_value);

	stime_value = target_load_value_member(target, NULL, value, "stime", NULL, LOAD_FLAG_NONE);
	if(!stime_value) {
	    fprintf(stdout,"ERROR: Failed to load the stime value.\n");
	    free(process_name);
	    return 1;
	}
	stime = v_u64(stime_value);
	VALUE_FREE(stime_value);

	stimescaled_value = target_load_value_member(target, NULL, value, "stimescaled", NULL, LOAD_FLAG_NONE);
	if(!stimescaled_value) {
	    fprintf(stdout,"ERROR: Failed to load the stimescaled value.\n");
	    free(process_name);
	    return 1;
	}
	stimescaled = v_u64(stimescaled_value);
	VALUE_FREE(stimescaled_value);

	/*Load the prev_cputime struct */
	prev_cputime_value = target_load_value_member(target, NULL, value, 
						      "prev_cputime", NULL, LOAD_FLAG_NONE);
	if(!prev_cputime_value) {
	    fprintf(stdout,"ERROR: Filed to load the prev_cputime_value.\n");
	    free(process_name);
	    return 1;
	}
	VALUE_FREE(prev_cputime_value);

	/* load the sched_entity struct */
	sched_entity_value = target_load_value_member(target, NULL, value, "se", NULL, LOAD_FLAG_NONE);
	if(!sched_entity_value) {
	    fprintf(stdout,"ERROR: Failed to load the sched_entity struct.\n");
	    free(process_name);
	    return 1;
	}

	/* load the sum_exec_runtime member */
	sum_exec_runtime_value = target_load_value_member(target, NULL, 
		sched_entity_value, "sum_exec_runtime", NULL, LOAD_FLAG_NONE);
	if(!sum_exec_runtime_value) {
	    fprintf(stdout,"ERROR: Failed to load the sum_exec_runtime.\n");
	    VALUE_FREE(sched_entity_value);
	    free(process_name);
	    return 1;
	}
	sum_exec_runtime = v_u64(sum_exec_runtime_value);
	VALUE_FREE(sum_exec_runtime_value);
 
	/* load the vruntime member */
	vruntime_value = target_load_value_member(target, NULL, sched_entity_value,
						"vruntime", NULL, LOAD_FLAG_NONE);
	if(!vruntime_value) {
	    fprintf(stdout,"ERROR: Failed to load the vruntime value,\n");
	    VALUE_FREE(sched_entity_value);
	    free(process_name);
	    return 1;
	}
	vruntime  = v_u64(vruntime_value);
	VALUE_FREE(vruntime_value);
	VALUE_FREE(sched_entity_value);

	/* total of utime and stime */
	load[i] = utime + stime;

	jiffies_bsymbol = target_lookup_sym(target, "jiffies", NULL, NULL,
						SYMBOL_TYPE_FLAG_VAR);
	if(!jiffies_bsymbol) {
	    fprintf(stdout,"ERROR: failed to load the jiffies symbol.\n");
	    free(process_name);
	    return 1;
	}

	tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,jiffies_bsymbol);

	jiffies_value = target_load_symbol(target, tlctxt, jiffies_bsymbol, LOAD_FLAG_NONE);
	if(!jiffies_value) {
	    fprintf(stdout,"ERROR: Could not load the jifffies value.\n");
	    target_location_ctxt_free(tlctxt);
	    bsymbol_release(jiffies_bsymbol);
	    free(process_name);
	    return 1;
	}
	jiffies = v_u64(jiffies_value);
	jiffy[i] = jiffies;
	VALUE_FREE(jiffies_value);

	target_location_ctxt_free(tlctxt);
	bsymbol_release(jiffies_bsymbol);

	if(i == 1) break;

	/* now unpause the target and let it execute for 2 sec */
	if ((status = target_status(target)) == TSTATUS_PAUSED) {
	    if(target_resume(target)) {
		fprintf(stdout, "ERROR: Failed to resume the target.\n");
		free(process_name);
		return 1;
	    }
	}

	usleep(10000);
	
	if ((status = target_status(target)) != TSTATUS_PAUSED) {
	    if (target_pause(target)) {
		fprintf(stdout,"ERROR: Failed to pause the target \n");
		/* XXX we leave this as a fatal error */
		exit(0);
	    }
	}
	i = i + 1;

	/* Reload the task_struct value */
	if(value_refresh(value , 0)) {
	    fprintf(stdout,"ERROR: Failed to refresh the task_struct value.\n");
	    free(process_name);
	    return 1;
	}
    }

    cpu_utilization = (float) (load[1] - load[0])/(jiffy[1]-jiffy[0])* 100;
    if (opts.dump_debug)
	fprintf(stdout,"INFO: CPU utilization for the process %s %f\n",
    				         process_name, cpu_utilization);
	
    /* Now encode these values as facts */
    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	free(process_name);
	return 1;
    }
    
    fprintf(fp,"( cpu_utilization \n    \
		    \t( comm \"%s\")\n    \
		    \t( pid %d)\n     \
		    \t( utime %lu)\n   \
		    \t( utimescaled %lu)\n \
		    \t( stime %lu) \n  \
		    \t( stimescaled %lu)\n \
		    \t( sum_exec_runtime %lu)\n \
		    \t( vruntime %lu)\n \
		    \t( utilization %f))\n",
		    process_name, pid, utime, utimescaled,
		    stime, stimescaled, sum_exec_runtime, vruntime, cpu_utilization);

    fclose(fp);
    free(process_name);

    return 0;
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

    ret_val = os_linux_list_for_each_struct(target, init_task_bsymbol, "tasks", 0,
	    gather_cpu_utilization, NULL);
    return ret_val;
}


int gather_object_info(struct target *target, struct value *value, void * data) {

    struct value *pid_value;
    struct value *comm_value;
    struct value *mm_value;
    struct value *vm_area_value;
    struct value *file_value;
    struct value *path_value;
    struct value *dentry_value;
    struct value *d_name_value;
    struct value *len_name_value;
    struct value *file_name_value;
    struct value *next_vm_area_value; 
    FILE * fp;
    ADDR next_vm_area_addr, file_value_addr;
    char *file_name, *process_name;
    int pid;
    char prev_name[50];
    
    pid_value = target_load_value_member(target, NULL, value, "pid", NULL, LOAD_FLAG_NONE);
    if(!pid_value) {
	fprintf(stdout,"ERROR: Failed to load the pid value.\n");
	return 1;
    }
    pid = v_i32(pid_value);
    VALUE_FREE(pid_value);

    comm_value = target_load_value_member(target, NULL, value, "comm", NULL, LOAD_FLAG_NONE);
    if(!comm_value) {
	fprintf(stdout,"ERROR: Failed to load the process name.\n");
	return 1;
    }
    process_name = strdup(comm_value->buf);
    VALUE_FREE(comm_value);


    /* first check if the pointer to the mm struct is NULL*/
    mm_value = target_load_value_member(target, NULL, value, "mm", NULL,
					LOAD_FLAG_NONE);
    if (!mm_value || !(v_addr(mm_value))) {
	//fprintf(stdout, "INFO: Pointer to the mm struct is NULL \n");
	if (mm_value)
	    VALUE_FREE(mm_value);
	return 0;
    }
    VALUE_FREE(mm_value);

    mm_value = target_load_value_member(target, NULL, value, "mm", NULL,
					LOAD_FLAG_AUTO_DEREF);
    if(!mm_value) {
	//fprintf(stdout,"INFO: mm member is NULL.\n");
	return 0;
    }

    vm_area_value = target_load_value_member(target, NULL, mm_value, "mmap",
					     NULL, LOAD_FLAG_AUTO_DEREF);
    if(!vm_area_value) {
	fprintf(stdout,"ERROR: Failed to load the mmap member value. \n");
	VALUE_FREE(mm_value);
	return 1;
    }
    
    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	VALUE_FREE(vm_area_value);
	VALUE_FREE(mm_value);
	return 1;
    }
    
    fprintf(fp,"( loaded-objects \n    \
		    \t( comm \"%s\")\n \
		    \t( pid %d)\n      \
		    \t( objects ",process_name, pid);
    free(process_name);
     
    /* Traverse through the entire list of vm_area
     * struct to get the name of loaded oobjects.
     */
    prev_name[0] = '\0';
    while(1) {
	unsigned int len;

	/* Firct check if the pointer to the vm_file struct is NULL */
	file_value = target_load_value_member(target, NULL, vm_area_value, "vm_file",
					      NULL, LOAD_FLAG_NONE);
	if (!file_value || !(file_value_addr = v_addr(file_value))) {
	    //fprintf(stdout,"INFO: vm_file value is null, so continuing . . \n");
	    if (file_value)
		VALUE_FREE(file_value);
	    goto nextptr;
	}
	VALUE_FREE(file_value);

	file_value = target_load_value_member(target, NULL, vm_area_value, "vm_file",
					      NULL, LOAD_FLAG_AUTO_DEREF);

	/* Load the path the variable from the files struct*/
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading f_path struct\n");
	path_value = target_load_value_member( target, NULL, file_value, "f_path",
		    NULL, LOAD_FLAG_NONE);
	if(!path_value) {
	    fprintf(stdout," ERROR: failed to load the path struct member.\n");
	    VALUE_FREE(file_value);
	    fclose(fp);
	    VALUE_FREE(vm_area_value);
	    VALUE_FREE(mm_value);
	    return 1;
	} 

	/* Load the dentry struct  member from the path */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading dentry struct\n");
	dentry_value = target_load_value_member(target, NULL, path_value, "dentry",
		    NULL, LOAD_FLAG_AUTO_DEREF);
	if(!dentry_value){
	    VALUE_FREE(path_value);
	    VALUE_FREE(file_value);
	    fprintf(stdout,"INFO: dentry member is NULL\n");
	    goto nextptr;
	}

	/* Load the d_name struct */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading d_name struct\n");
	d_name_value = target_load_value_member(target, NULL, dentry_value, "d_name",
		    NULL, LOAD_FLAG_NONE);
	if(!d_name_value) {
	    fprintf(stdout," ERROR: failed to load the d_name struct member.\n");
	    VALUE_FREE(path_value);
	    VALUE_FREE(file_value);
	    fclose(fp);
	    VALUE_FREE(vm_area_value);
	    VALUE_FREE(mm_value);
	    return 1;
	} 

	/* Finally load the length of  name string */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading the length of name string\n");
	len_name_value = target_load_value_member( target, NULL, d_name_value, "len",
						   NULL, LOAD_FLAG_NONE);
	if(!len_name_value) {
	    fprintf(stdout," ERROR: failed to load the name string.\n");
	    VALUE_FREE(d_name_value);
	    VALUE_FREE(path_value);
	    VALUE_FREE(file_value);
	    fclose(fp);
	    VALUE_FREE(vm_area_value);
	    VALUE_FREE(mm_value);
	    return 1;
	}
	len = v_u32(len_name_value);
	VALUE_FREE(len_name_value);
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Length of the name string is %u \n.",len);
	if(len == 0) {
	    if (opts.dump_debug)
		fprintf(stdout,"INFO: File name length is 0 hence continuing with the loop\n");
	    VALUE_FREE(d_name_value);
	    VALUE_FREE(dentry_value);
	    VALUE_FREE(path_value);
	    VALUE_FREE(file_value);
	    goto nextptr;
	}

	file_name_value = target_load_value_member(target, NULL, d_name_value, "name",
		    NULL, LOAD_FLAG_AUTO_STRING);
	if(!file_name_value) {
	    fprintf(stdout,"ERROR: Could not load name of the file\n");
	    VALUE_FREE(d_name_value);
	    VALUE_FREE(dentry_value);
	    VALUE_FREE(path_value);
	    VALUE_FREE(file_value);
	    goto nextptr;
	}

	file_name = strdup(file_name_value->buf);
	VALUE_FREE(file_name_value);
	if(strcmp(file_name, prev_name)) {
	    if (opts.dump_debug)
		fprintf(stdout,"INFO: Loaded object name %s\n",file_name);
	    fprintf(fp," \"%s\" ",file_name);
	}
	strcpy(prev_name,file_name);
	free(file_name);

	VALUE_FREE(d_name_value);
	VALUE_FREE(dentry_value);
	VALUE_FREE(path_value);
	VALUE_FREE(file_value);

nextptr:
	
	/* first check if the vm_next pointer is null */
	next_vm_area_value = target_load_value_member(target, NULL, vm_area_value,
						"vm_next", NULL, LOAD_FLAG_NONE);
	if(!next_vm_area_value) {
	    fprintf(stdout,"ERROR: Failed to load the next_vm_area_value.\n");
	    fclose(fp);
	    VALUE_FREE(vm_area_value);
	    VALUE_FREE(mm_value);
	    return 1;
	}

	next_vm_area_addr = v_addr(next_vm_area_value);
        if(!next_vm_area_addr) {
	    if (opts.dump_debug)
		fprintf(stdout,"INFO: Reached the end of the linked list.\n");
	    VALUE_FREE(next_vm_area_value);
	    VALUE_FREE(vm_area_value);
	    break;
	}
	VALUE_FREE(next_vm_area_value);

	next_vm_area_value = target_load_value_member(target, NULL, vm_area_value,
						      "vm_next", NULL, LOAD_FLAG_AUTO_DEREF);
	VALUE_FREE(vm_area_value);
	vm_area_value = next_vm_area_value;
    }
    fprintf(fp," ))\n");
    fclose(fp);

    VALUE_FREE(mm_value);
    return 0;
}

int object_info() {

    int ret_val;
    struct bsymbol * init_task_bsymbol;

    if(opts.dump_debug)
	fprintf(stdout, "INFO: Gathering information about the loaded objects \n");
    init_task_bsymbol = target_lookup_sym(target, "init_task", NULL, NULL,
	    SYMBOL_TYPE_FLAG_VAR);
    if(!init_task_bsymbol) {
	fprintf(stdout,"ERROR: Could not lookup the init_task_symbol\n");
	return 1;
    }

    ret_val = os_linux_list_for_each_struct(target, init_task_bsymbol, "tasks", 0,
	    gather_object_info, NULL);
    bsymbol_release(init_task_bsymbol);

    return ret_val;
}


int syscalltable_info() {

    int max_num = 0;
    int i;
    
    FILE *fp;
    struct target_os_syscall *sc;
    struct bsymbol *bs;
    struct value *v;
    ADDR syscall_table;

    struct target_location_ctxt *tlctxt;

    /* Load the syscall table */
    bs = target_lookup_sym(target,"sys_call_table",NULL,NULL,
			   SYMBOL_TYPE_FLAG_VAR);
    if (!bs) {
	fprintf(stdout, "ERROR: Could not lookup symbol sys_call_table!\n");
	return 1;
    }	

    tlctxt = target_location_ctxt_create_from_bsymbol(target, TID_GLOBAL,bs);

    v = target_load_symbol(target,tlctxt,bs,LOAD_FLAG_NONE);
    if (!v) {
	fprintf(stdout,"ERROR: Could not load sys_call_table!\n");
	target_location_ctxt_free(tlctxt);
	bsymbol_release(bs);
	return 1;
    }

    syscall_table = value_addr(v);
    if (opts.dump_debug)
	fprintf(stdout,"INFO: Symbol syscall_table is at address %lx\n",
		    syscall_table);

    VALUE_FREE(v);
    target_location_ctxt_free(tlctxt);
    bsymbol_release(bs);
    bs = NULL;

    if (opts.dump_debug)
	fprintf(stdout,"INFO: Loading the syscall table.\n");
    if(target_os_syscall_table_load(target)) {
	fprintf(stdout,"ERROR: Failed to load the syscall table.\n");
	return 1;
    }

    max_num = target_os_syscall_table_get_max_num(target);
    if(max_num < 0) {
	fprintf(stdout,"ERROR: Failed to get the max number of target sysscalls.\n");
	return 1;
    }
    if (opts.dump_debug)
	fprintf(stdout,"INFO: maximum number of system calls %d \n",max_num);

    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout,"ERROR: Failed to open the base_fact_file.\n");
	return 1;
    }

    for(i = 0; i < max_num; i++) {
	sc = target_os_syscall_lookup_num(target, i);
	if(!sc) {
	    continue;
	}
	if(sc->bsymbol) {
	    if (opts.dump_debug)
		fprintf(stdout,"%d\t %"PRIxADDR"\t%s\n", sc->num, sc->addr, 
	    				    bsymbol_get_name(sc->bsymbol));
	    if(sc->addr != sys_call_table[sc->num]) {
		fprintf(fp,"(tampered_sys_call\n \
			\t( name  \"%s\")\n \
			\t( original %lu )\n \
			\t( current %lu )\n \
			\t( index %d )\n \
 			\t( base_address %lu))\n",
			bsymbol_get_name(sc->bsymbol),
			sys_call_table[sc->num],
			sc->addr,
			sc->num,
			syscall_table);
	    }

	}
    }
    fclose(fp);
    return 0;
}


int gather_commandline_info(struct target *target, struct value *value, void * data) {
    
    struct value *pid_value;
    int pid;
    struct value *comm_value;
    struct value *mm_value;
    struct value *arg_start_value;
    unsigned long arg_start;
    struct value *arg_end_value;
    unsigned long arg_end;
    unsigned long length = 0;
    struct value *env_start_value;
    unsigned long env_start;
    struct value *env_end_value;
    unsigned long env_end;

    ADDR paddr;
    unsigned char *command_line, *ret, *environment;
    FILE *fp;

    pid_value = target_load_value_member(target, NULL, value, "pid", NULL, LOAD_FLAG_NONE);
    if(!pid_value) {
	fprintf(stdout,"ERROR: Failed to load the pid value.\n");
	return 1;
    }
    pid = v_i32(pid_value);
    VALUE_FREE(pid_value);

    comm_value = target_load_value_member(target, NULL, value, "comm", NULL, LOAD_FLAG_NONE);
    if(!comm_value) {
	fprintf(stdout,"ERROR: Failed to load the process name.\n");
	return 1;
    }
    VALUE_FREE(comm_value);

    /* Check if the mm strcuture is NULL */
    mm_value = target_load_value_member(target, NULL, value, "mm", NULL,
					LOAD_FLAG_NONE);
    if(!mm_value || !(v_addr(mm_value))) {
	if (opts.dump_debug)
	    fprintf(stdout, "INFO: Pointer to the mm struct is NULL \n");
	if (mm_value)
	    VALUE_FREE(mm_value);
	return 0;
    }               
    VALUE_FREE(mm_value);
    
    /* Load the mm member */
    mm_value = target_load_value_member(target, NULL, value,"mm", NULL, LOAD_FLAG_AUTO_DEREF);
    if(!mm_value) {
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Pointer to the mm struct is null.\n");
	return 0;
    }
    arg_start_value = target_load_value_member(target, NULL, mm_value, "arg_start",
						NULL, LOAD_FLAG_NONE);
    if(!arg_start_value) {
	fprintf(stdout,"ERROR: Failed to load the arg_start memeber.\n");
	VALUE_FREE(mm_value);
	return 1;
    }
    arg_start = v_u64(arg_start_value);
    VALUE_FREE(arg_start_value);

    arg_end_value = target_load_value_member(target, NULL, mm_value, "arg_end",
						NULL, LOAD_FLAG_NONE);
    if(!arg_end_value) {
	fprintf(stdout,"ERROR: Failed to load the arg_end memeber.\n");
	VALUE_FREE(mm_value);
	return 1;
    }
    arg_end = v_u64(arg_end_value);
    VALUE_FREE(arg_end_value);

    length = arg_end - arg_start;
    if(!length) {
	fprintf(stdout," INFO: No command line for the process with pid %d\n",pid);
    }

    /* Now convert the virtual address into physical address */
    if(target_addr_v2p(target,pid, arg_start, &paddr)) {
	fprintf(stdout,"ERROR: could not translate virtual address 0x%"PRIxADDR"\n", arg_start);
	VALUE_FREE(mm_value);
	return 1;
    }
    if (opts.dump_debug)
	fprintf(stdout,"INFO: virtual address 0x%"PRIxADDR" translates to 0x%"PRIxADDR"\n",
    								arg_start,paddr);
    
    /* Now read the buffer contents from the physical address*/
    command_line = calloc(100+1, sizeof (char));

    ret = target_read_physaddr(target, paddr, 100, command_line);
    if(!ret) {
	fprintf(stdout,"ERROR: Failed to load the commandline buffer.\n");
	free(command_line);
	VALUE_FREE(mm_value);
	return 1;
    }


    /* Gather information reagarding the environment of the process. */
     env_start_value = target_load_value_member(target, NULL, mm_value, "env_start",
						NULL, LOAD_FLAG_NONE);
    if(!env_start_value) {
	fprintf(stdout,"ERROR: Failed to load the env_start memeber.\n");
	free(command_line);
	VALUE_FREE(mm_value);
	return 1;
    }
    env_start = v_u64(env_start_value);
    VALUE_FREE(env_start_value);

    env_end_value = target_load_value_member(target, NULL, mm_value, "env_end",
						NULL, LOAD_FLAG_NONE);
    if(!env_end_value) {
	fprintf(stdout,"ERROR: Failed to load the env_end memeber.\n");
	free(command_line);
	VALUE_FREE(mm_value);
	return 1;
    }
    env_end = v_u64(env_end_value);
    VALUE_FREE(env_end_value);
    VALUE_FREE(mm_value);

    if (env_end <= env_start) {
	fprintf(stdout," INFO: No command line for the process with pid %d\n",pid);
	length = 0;
    }
    length = env_end - env_start;

    /* Now convert the virtual address into physical address */
    if(target_addr_v2p(target,pid, env_start, &paddr)) {
	fprintf(stdout,"ERROR: could not translate virtual address 0x%"PRIxADDR"\n", env_start);
	free(command_line);
	return 1;
    }
  
    /* Now read the buffer contents from the physical address*/
    environment = calloc(100+1, sizeof (char));
    if (length > 100)
	    length = 100;

    ret = target_read_physaddr(target, paddr, length, environment);
    if(!ret) {
	fprintf(stdout,"ERROR: Failed to load the environment buffer.\n");
	free(environment);
	free(command_line);
	return 1;
    }

    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	free(environment);
	free(command_line);
	return 1;
    }
    
    fprintf(fp,"( command_line \n    \
		\t( command \"%s\")\n \
		\t( environment \"%s\"))\n", command_line, environment);
    
    fclose(fp);
    free(environment);
    free(command_line);
    return 0;
}


int commandline_info() {

    int ret_val;
    struct bsymbol * init_task_bsymbol;

    init_task_bsymbol = target_lookup_sym(target, "init_task", NULL, NULL,
	    SYMBOL_TYPE_FLAG_VAR);
    if(!init_task_bsymbol) {
	fprintf(stdout,"ERROR: Could not lookup the init_task_symbol\n");
	return 1;
    }
    ret_val = os_linux_list_for_each_struct(target, init_task_bsymbol, "tasks", 0,
	    gather_commandline_info, NULL);
    return ret_val;
}


int syscall_hooking_info() {

    int ret_val = 0;
    int max_num = 0;
    int i;
    
    FILE *fp;
    struct target_os_syscall *sc;
#if 0
    struct dump_info ud = { .stream = stdout,.prefix = "",.detail = 0,.meta = 0 };
#endif
    unsigned char prologue[16];
    unsigned char *res = NULL;


    /* Load the syscall table */
    if (opts.dump_debug)
	fprintf(stdout,"INFO: Loading the syscall table.\n");
    if(target_os_syscall_table_load(target)) {
	fprintf(stdout,"ERROR: Failed to load the syscall table.\n");
	return 1;
    }

    max_num = target_os_syscall_table_get_max_num(target);
    if(max_num < 0) {
	fprintf(stdout,"ERROR: Failed to get the max number of target sysscalls.\n");
	return 1;
    }
    if (opts.dump_debug)
	fprintf(stdout,"INFO: maximum number of system calls %d \n",max_num);

    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout,"ERROR: Failed to open the base_fact_file.\n");
	return 1;
    }

    for(i = 0; i < max_num; i++) {
	sc = target_os_syscall_lookup_num(target, i);
	if(!sc) {
	    continue;
	}
	if(sc->bsymbol) {

	    res = target_read_addr(target,sc->addr,16, prologue);
	    if(!res) {
		fprintf(stdout, "ERROR: Could not read 16 bytes at 0x%"PRIxADDR"!\n",sc->addr);
		fclose(fp);
		return 1;
	    }

	    if(memcmp(function_prologue[sc->num], prologue, 16)) {
		fprintf(fp,"(hooked_sys_call\n   \
			\t( name  \"%s\")\n \
			\t( original-0-8 \"%lx\" )\n \
			\t( original-8-16 \"%lx\" )\n \
			\t( address \"%lx\" ))\n",
			bsymbol_get_name(sc->bsymbol),
			function_prologue[sc->num][0],
			function_prologue[sc->num][1],
			sc->addr);
	    }

	}
    }
    fclose(fp);
    return ret_val;
}



int gather_socket_info(struct target *target, struct value * value, void * data) {

    struct value *files_value = NULL;
    struct value *fdt_value = NULL;
    struct value *max_fds_value = NULL;
    struct value *fd_value;
    struct value *file_value = NULL;
    struct value *path_value = NULL;
    struct value *dentry_value = NULL;
    struct value *name_value;
    struct value *d_name_value = NULL;
    struct value *len_name_value;
    struct value *file_name_value;
    struct value *pid_value;
    struct value *d_inode_value;
    struct value *i_mode_value;
    struct value *sock_addr_value;
    struct value *sock_value = NULL;
    struct value *sock_common_value = NULL;
    struct value *skc_dport_value;
    struct bsymbol *file_struct_bsymbol = NULL;
    int max_fds, i, pid;
    char *file_name = NULL, *process_name = NULL;
    ADDR file_addr, mem_addr, sock_addr;
    struct symbol *file_struct_type;
    unsigned short i_mode, port_number;
    FILE *fp = NULL;
    struct target_location_ctxt *tlctxt = NULL;
    struct bsymbol *bs = NULL;
    struct symbol *sock_struct_type = NULL;



    if (opts.dump_debug)
	fprintf(stdout,"INFO: Gathering information in open sockets.\n");
    pid_value = target_load_value_member(target, NULL, value, "pid", NULL, LOAD_FLAG_NONE);
    if(!pid_value) {
	fprintf(stdout," ERROR: failed to load the pid value.\n");
	return 1;
    }
    pid = v_i32(pid_value);
    VALUE_FREE(pid_value);
    name_value = target_load_value_member(target, NULL, value, "comm", NULL, LOAD_FLAG_NONE);
    if(!name_value) {
	fprintf(stdout," ERROR: failed to load the process name for pid %d.\n", pid);
	return 1;
    }   
    process_name = strdup(name_value->buf);
    VALUE_FREE(name_value);
    if (opts.dump_debug)
	fprintf(stdout,"INFO: Loading open file info for pid %d (%s).\n", pid, process_name);

    /* Load the files struct from the task_struct */
    if (opts.dump_debug)
	fprintf(stdout,"INFO: Loading files struct\n");
    files_value = target_load_value_member(target, NULL, value, "files", NULL, 
					   LOAD_FLAG_NONE);
    if (!files_value) {
	fprintf(stdout," ERROR: failed to load the files struct member.\n");
	goto fail;
    }   
    if (!v_addr(files_value)) {
	/* NULL address indicates a zombie/dead process */
	max_fds = 0;
    } else {
	VALUE_FREE(files_value);
	files_value = target_load_value_member(target, NULL, value, "files", NULL, 
					       LOAD_FLAG_AUTO_DEREF);
	if(!files_value) {
	    fprintf(stdout," ERROR: failed to load the files struct member.\n");
	    goto fail;
	}   

	/* Load the fdtable struct */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading fdt struct\n");
	fdt_value =  target_load_value_member( target, NULL, files_value, "fdt", 
					       NULL, LOAD_FLAG_AUTO_DEREF);
	if(!fdt_value) {
	    fprintf(stdout," ERROR: failed to load the fdt struct member.\n");
	    goto fail;
	}   

	/* Load the  max_fds member of the ftable struct */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading max_fds member\n");
	max_fds_value = target_load_value_member( target, NULL, fdt_value, 
						  "max_fds", NULL, LOAD_FLAG_NONE);
	if(!max_fds_value) {
	    fprintf(stdout," ERROR: failed to load the max_fds member.\n");
	    goto fail;
	}   
	max_fds = v_i32(max_fds_value);
	VALUE_FREE(max_fds_value);
    }
    if (opts.dump_debug)	
	fprintf(stdout,"INFO: max_fds_value for process %s = %d\n", process_name, max_fds);
    
    /*Open the base fact file */
    if (opts.dump_debug)
	fprintf(stdout,"INFO: Opening base fact file: %s\n",base_fact_file);
    fp = fopen(base_fact_file, "a+");
    if(fp == NULL) {
	fprintf(stdout," ERROR: Failed to open the base fact file\n");
	goto fail;
    }

    for( i = 0; i < max_fds; i++) {
	unsigned int len;

	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading fd struct\n");
	fd_value =  target_load_value_member(target, NULL, fdt_value, "fd", NULL, 
					     LOAD_FLAG_NONE);
	if(!fd_value) {
	    fprintf(stdout," ERROR: failed to load the fd struct memeber.\n");
	    goto fail;
	}

	/* Load the array of file descriptors */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading fs struct\n");
	mem_addr = v_addr(fd_value);
	VALUE_FREE(fd_value);
	mem_addr = mem_addr + (target->arch->wordsize * i);
	if(!target_read_addr(target, mem_addr, target->arch->wordsize, 
			(unsigned char *)&file_addr)) {
	    fprintf(stdout,"ERROR: target_read_addr failed.\n");
	    goto fail;
	}
	if(!file_addr) {
	    if (opts.dump_debug)
		fprintf(stdout," INFO: File table entry is NULL\n");
	    continue;
	}
	
	/* Load the type of symbol */
	file_struct_bsymbol = target_lookup_sym(target, "struct file", NULL,
						NULL, SYMBOL_TYPE_FLAG_TYPE);
	if(!file_struct_bsymbol) {
	    fprintf(stdout,"ERROR: Failed to lookup the struct file bsymbol.\n");
	    goto fail;
	}

	file_struct_type = bsymbol_get_symbol(file_struct_bsymbol);
	if(!file_struct_type) {
	    fprintf(stdout,"INFO: Could not load the file struct type\n");
	    goto fail;
	}

	/* Finally load the array memeber */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading file struct\n");
	file_value = target_load_type(target, file_struct_type, file_addr, 
				      LOAD_FLAG_AUTO_DEREF);
	if(!file_value) {
	    fprintf(stdout," ERROR: failed to load the file struct member.\n");
	    goto fail;
	}

	/* Load the path the variable from the files struct*/
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading f_path struct\n");
	path_value = target_load_value_member( target, NULL, file_value, "f_path",
					       NULL, LOAD_FLAG_NONE);
	if(!path_value) {
	    fprintf(stdout," ERROR: failed to load the path struct member.\n");
	    goto fail;
	} 

	/* Load the dentry struct  member from the path */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading dentry struct\n");
	dentry_value = target_load_value_member(target, NULL, path_value, "dentry",
		    NULL, LOAD_FLAG_AUTO_DEREF);
	if(!dentry_value){
	    VALUE_FREE(path_value);
	    VALUE_FREE(file_value);
	    bsymbol_release(file_struct_bsymbol);
	    fprintf(stdout,"INFO: dentry member is NULL\n");
	    continue;
	}

	/* Load the d_name struct */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading d_name struct\n");
	d_name_value = target_load_value_member(target, NULL, dentry_value, "d_name",
		    NULL, LOAD_FLAG_NONE);
	if(!d_name_value) {
	    fprintf(stdout," ERROR: failed to load the d_name struct member.\n");
	    goto fail;
	} 

	/* Finally load the length of  name string */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading the length of name string\n");
	len_name_value = target_load_value_member( target, NULL, d_name_value, "len",
		    NULL, LOAD_FLAG_NONE);
	if(!len_name_value) {
	    fprintf(stdout," ERROR: failed to load the name string.\n");
	    goto fail;
	}
	len = v_u32(len_name_value);
	VALUE_FREE(len_name_value);
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Length of the name string is %u \n.",len);
	if(len == 0) {
	    if (opts.dump_debug)
		fprintf(stdout,"INFO: File name length is 0 hence continuing with the loop\n");
	    VALUE_FREE(d_name_value);
	    VALUE_FREE(dentry_value);
	    VALUE_FREE(path_value);
	    VALUE_FREE(file_value);
	    bsymbol_release(file_struct_bsymbol);
	    continue;
	}

	file_name_value = target_load_value_member(target, NULL, d_name_value, "name",
		    NULL, LOAD_FLAG_AUTO_STRING);
	if(!file_name_value) {
	    fprintf(stdout,"ERROR: Could not load name of the file\n");
	    VALUE_FREE(d_name_value);
	    VALUE_FREE(dentry_value);
	    VALUE_FREE(path_value);
	    VALUE_FREE(file_value);
	    bsymbol_release(file_struct_bsymbol);
	    continue;
	}

	file_name = strdup(file_name_value->buf);
	VALUE_FREE(file_name_value);
	VALUE_FREE(d_name_value);

	fprintf(stdout,"INFO: FIle name - %s\n",file_name);
	free(file_name);

	/* Load the inode struct */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Loading the d_inode struct.\n");
	d_inode_value = target_load_value_member(target, NULL, dentry_value, "d_inode",
						 NULL, LOAD_FLAG_AUTO_DEREF);
	if(!d_inode_value) {
	    fprintf(stdout,"ERROR: failed to load the d_inode member.\n");
	    goto fail;
	}

	/*Load the i_mode member */
	if (opts.dump_debug)
	    fprintf(stdout,"INFO: Load the i_mode member.\n");
	i_mode_value = target_load_value_member(target, NULL, d_inode_value, "i_mode",
						NULL, LOAD_FLAG_NONE);
	if(!i_mode_value) {
	    fprintf(stdout,"ERROR: failed to load the i_mode value.\n");
	    VALUE_FREE(d_inode_value);
	    goto fail;
	}
	i_mode = v_u16(i_mode_value);
	VALUE_FREE(i_mode_value);
	VALUE_FREE(d_inode_value);

	if (S_ISSOCK(i_mode)) {
	    fprintf(stdout,"INFO: The file is a SOCKET.\n");
	    
	    /* Load the path the variable from the files struct*/
	    if (opts.dump_debug)
		fprintf(stdout,"INFO: Loading private_data  struct\n");
	    sock_addr_value = target_load_value_member( target, NULL, file_value, "private_data",
							NULL, LOAD_FLAG_NONE);
	    if(!sock_addr_value) {
		fprintf(stdout," ERROR: failed to load the sock struct member.\n");
		goto fail;
	    }

	    sock_addr = v_addr(sock_addr_value);
	    VALUE_FREE(sock_addr_value);
	    
	    fprintf(stdout,"INFO: private_data addr = %lu\n",sock_addr);

	    /* Get the type for the socket structure  and load it*/
	    bs = target_lookup_sym(target,"struct sock", NULL,
			"sock", SYMBOL_TYPE_FLAG_TYPE);
	    if(!bs) {
		fprintf(stdout,"ERROR: Failed to lookup symbol sock.\n");
		goto fail;
	    }

	    tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,bs);
	    if(!tlctxt) {
		fprintf(stdout,"ERROR: Could not create the target location context.\n");
		goto fail;
	    }

	    sock_struct_type = bsymbol_get_symbol(bs);
	    if(!sock_struct_type){
		fprintf(stdout,"ERROR:Target_lookup_symbol failed for struct sock.\n");
		goto fail;
	    }
    
	    sock_value = target_load_type(target, sock_struct_type, sock_addr, LOAD_FLAG_NONE);
	    if(!sock_value){
		fprintf(stdout,"ERROR: Failed to load sock structure . \n");
		goto fail;
	    }
	    
	    sock_common_value = target_load_value_member( target, tlctxt, sock_value, "__sk_common",
							  NULL, LOAD_FLAG_NONE);
	    if(!sock_common_value) {
		fprintf(stdout," ERROR: failed to load the sock_common struct member.\n");
		goto fail;
	    }

	    skc_dport_value = target_load_value_member( target, NULL, sock_common_value, "skc_dport",
							NULL, LOAD_FLAG_NONE);
	    if(!skc_dport_value) {
		fprintf(stdout," ERROR: failed to load the skc_dport struct member.\n");
		goto fail;
	    }
	    port_number = v_u16(skc_dport_value);
	    VALUE_FREE(skc_dport_value);
	    fprintf(stdout,"INFO:Port number %u\n",port_number);

	    VALUE_FREE(sock_common_value);
	    VALUE_FREE(sock_value);

	    /*Start encoding the fact */
	    fprintf(fp,"\n(opened-sockets \n \
			    \t(comm \"%s\")\n \
			    \t(pid %d)\n \
			    \t(port %u))\n", process_name, pid, port_number);

	    target_location_ctxt_free(tlctxt);
	    tlctxt = NULL;
	    bsymbol_release(bs);
	    bs = NULL;

	    free(process_name);
	    process_name = NULL;
	}
	VALUE_FREE(dentry_value);
	VALUE_FREE(path_value);
	VALUE_FREE(file_value);
	bsymbol_release(file_struct_bsymbol);
	file_struct_bsymbol = NULL;
    }

    fclose(fp);
    if (fdt_value)
	VALUE_FREE(fdt_value);
    if (files_value)
	VALUE_FREE(files_value);
    return(0);

 fail:
    if (sock_common_value)
	VALUE_FREE(sock_common_value);
    if (sock_value)
	VALUE_FREE(sock_value);
    if (tlctxt)
	target_location_ctxt_free(tlctxt);
    if (bs)
	bsymbol_release(bs);
    if (d_name_value)
	VALUE_FREE(d_name_value);
    if (dentry_value)
	VALUE_FREE(dentry_value);
    if (path_value)
	VALUE_FREE(path_value);
    if (file_value)
	VALUE_FREE(file_value);
    if (file_struct_bsymbol)
	bsymbol_release(file_struct_bsymbol);
    if (fp)
	fclose(fp);
    if (fdt_value)
	VALUE_FREE(fdt_value);
    if (files_value)
	VALUE_FREE(files_value);
    if (process_name)
	free(process_name);

    return 1;
}

int socket_info() {
    int ret_val;
    struct bsymbol * init_task_bsymbol;

    init_task_bsymbol = target_lookup_sym(target, "init_task", NULL, NULL,
					  SYMBOL_TYPE_FLAG_VAR);
    if(!init_task_bsymbol) {
	fprintf(stdout,"ERROR: Could not lookup the init_task_symbol\n");
	return 1;
    }

    ret_val = os_linux_list_for_each_struct(target, init_task_bsymbol, "tasks", 0,
	    gather_socket_info, NULL);
    bsymbol_release(init_task_bsymbol);
    return ret_val;
}

