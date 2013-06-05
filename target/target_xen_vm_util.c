/*
 * Copyright (c) 2012, 2013 The University of Utah
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

#include "target_api.h"
#include "target.h"
#include "dwdebug.h"
#include "dwdebug_priv.h"
#include "target_xen_vm.h"

#include <limits.h>
#include <assert.h>

num_t linux_get_preempt_count(struct target *target) {
    struct target_thread *tthread;
    struct xen_vm_thread_state *tstate;

    tthread = target->current_thread;
    if (!tthread) {
	verror("no current thread!\n");
	errno = EINVAL;
	return 0;
    }
    else if (!tthread->valid) {
	verror("current thread not valid; forgot to load it?\n");
	errno = EINVAL;
	return 0;
    }

    tstate = (struct xen_vm_thread_state *)tthread->state;

    return tstate->thread_info_preempt_count;
}

/*
 * The bottom of each kernel stack has the thread_info struct; the first
 * pointer in the thread info struct is to the task_struct associated
 * with the thread_info (i.e., thread_info->task).  So, if we want
 * thread_info, just load the value at current_thread_ptr; if we want
 * the current task_struct, load the first pointer at
 * current_thread_ptr, and deref it to load the current task_struct's
 * value.
 */
#define current_thread_ptr(esp) ((esp) & ~(THREAD_SIZE - 1))

struct symbol *linux_get_task_struct_type(struct target *target) {
    struct xen_vm_state *xstate;

    xstate = (struct xen_vm_state *)target->state;
    if (!xstate || !xstate->task_struct_type) {
	verror("target does not seem to be loaded!\n");
	return NULL;
    }

    RHOLD(xstate->task_struct_type,xstate->task_struct_type);

    return xstate->task_struct_type;
}

struct symbol *linux_get_task_struct_type_ptr(struct target *target) {
    struct xen_vm_state *xstate;

    xstate = (struct xen_vm_state *)target->state;
    if (!xstate || !xstate->task_struct_type_ptr) {
	verror("target does not seem to be loaded!\n");
	return NULL;
    }

    RHOLD(xstate->task_struct_type_ptr,xstate->task_struct_type_ptr);

    return xstate->task_struct_type_ptr;
}

struct symbol *linux_get_thread_info_type(struct target *target) {
    struct xen_vm_state *xstate;

    xstate = (struct xen_vm_state *)target->state;
    if (!xstate || !xstate->thread_info_type) {
	verror("target does not seem to be loaded!\n");
	return NULL;
    }

    RHOLD(xstate->thread_info_type,xstate->thread_info_type);

    return xstate->thread_info_type;
}

struct value *linux_load_current_task_as_type(struct target *target,
					      struct symbol *datatype,
					      REGVAL kernel_esp) {
    struct value *value;
    ADDR tptr;
    REGVAL esp;

    if (kernel_esp) 
	esp = kernel_esp;
    else {
	errno = 0;
	esp = target_read_reg(target,TID_GLOBAL,target->spregno);
	if (errno) {
	    verror("could not read ESP!\n");
	    return NULL;
	}
    }

    tptr = current_thread_ptr(esp);

    value = target_load_type(target,datatype,tptr,LOAD_FLAG_AUTO_DEREF);

    return value;
}

struct value *linux_load_current_task(struct target *target,
				      REGVAL kernel_esp) {
    struct value *value;
    ADDR itptr;
    REGVAL esp;
    struct symbol *itptr_type;

    itptr_type = linux_get_task_struct_type_ptr(target);
    if (!itptr_type) {
	verror("could not find type for struct task_struct!\n");
	return NULL;
    }

    if (kernel_esp) 
	esp = kernel_esp;
    else {
	errno = 0;
	esp = target_read_reg(target,TID_GLOBAL,target->spregno);
	if (errno) {
	    verror("could not read ESP!\n");
	    symbol_release(itptr_type);
	    return NULL;
	}
    }

    itptr = current_thread_ptr(esp);

    value = target_load_type(target,itptr_type,itptr,
			     LOAD_FLAG_AUTO_DEREF);

    symbol_release(itptr_type);

    return value;
}

struct value *linux_load_current_thread_as_type(struct target *target,
						struct symbol *datatype,
						REGVAL kernel_esp) {
    struct value *value;
    ADDR tptr;
    REGVAL esp;

    if (kernel_esp) 
	esp = kernel_esp;
    else {
	errno = 0;
	esp = target_read_reg(target,TID_GLOBAL,target->spregno);
	if (errno) {
	    verror("could not read ESP!\n");
	    return NULL;
	}
    }

    tptr = current_thread_ptr(esp);

    value = target_load_type(target,datatype,tptr,LOAD_FLAG_NONE);

    return value;
}

int linux_get_task_pid(struct target *target,struct value *task) {
    struct value *value;
    int pid;

    if (!task)
	return -1;

    value = target_load_value_member(target,task,"pid",NULL,
				     LOAD_FLAG_NONE);
    if (!value) {
	verror("could not load 'pid' of task!\n");
	return -2;
    }
    pid = v_i32(value);

    value_free(value);

    return pid;
}

struct match_pid_data {
    tid_t tid;
    struct value *match;
};

static int match_pid(struct target *target,struct value *value,void *data) {
    struct match_pid_data *mpd = (struct match_pid_data *)data;
    struct value *mv = NULL;

    mv = target_load_value_member(target,value,"pid",NULL,
				  LOAD_FLAG_NONE);
    if (!mv) {
	vwarn("could not load pid from task; skipping!\n");
	return 0;
    }
    else if (mpd->tid != v_i32(mv)) {
	value_free(mv);
	return 0;
    }
    else {
	mpd->match = value;
	value_free(mv);
	return -1;
    }
}

struct value *linux_get_task(struct target *target,tid_t tid) {
    struct xen_vm_state *xstate = (struct xen_vm_state *)target->state;
    struct match_pid_data mpd;

    mpd.tid = tid;
    mpd.match = NULL;
    linux_list_for_each_struct(target,xstate->init_task,"tasks",0,match_pid,&mpd);

    if (!mpd.match) {
	vwarn("no task matching %"PRIiTID"\n",tid);

	return NULL;
    }

    return mpd.match;
}

/*
 * d_flags entries -- from include/linux/dcache.h
 */
#define DCACHE_AUTOFS_PENDING         0x0001
#define DCACHE_NFSFS_RENAMED          0x0002
#define	DCACHE_DISCONNECTED           0x0004
#define DCACHE_REFERENCED             0x0008
#define DCACHE_UNHASHED               0x0010	
#define DCACHE_INOTIFY_PARENT_WATCHED 0x0020

/*
 * This function fills in @buf from the end!  @return is a ptr to
 * somewhere inside @buf, consequently.
 */
char *linux_d_path(struct target *target,
		   struct value *dentry,struct value *vfsmnt,
		   struct value *root_dentry,struct value *root_vfsmnt,
		   char *buf,int buflen) {
    ADDR dentry_addr;
    ADDR vfsmnt_addr;
    ADDR root_dentry_addr;
    ADDR root_vfsmnt_addr;
    unum_t dentry_flags;
    ADDR parent_addr;
    ADDR mnt_root_addr;
    struct value *vfsmnt_mnt_parent;
    ADDR vfsmnt_mnt_parent_addr;
    struct value *orig_dentry = dentry;
    struct value *orig_vfsmnt = vfsmnt;
    struct value *ph;
    char *retval;
    char *end;
    num_t namelen;
    ADDR nameaddr;
    char *namebuf;

    assert(buf != NULL);

    dentry_addr = v_addr(dentry);
    vfsmnt_addr = v_addr(vfsmnt);
    root_dentry_addr = v_addr(root_dentry);
    root_vfsmnt_addr = v_addr(root_vfsmnt);

    /*
     * Basically from fs/dcache.c:__d_path, except VMI-ified.
     */
    end = buf + buflen;
    *--end = '\0';
    buflen--;
    VLV(target,dentry,"d_parent",LOAD_FLAG_NONE,&parent_addr,NULL,err_vmiload);
    VLV(target,dentry,"d_flags",LOAD_FLAG_NONE,&dentry_flags,NULL,err_vmiload);
    if (dentry_addr != parent_addr && dentry_flags & DCACHE_UNHASHED) {
	buflen -= 10;
	end -= 10;
	if (buflen < 0)
	    goto err_toolong;
	memcpy(end, " (deleted)", 10);
    }

    if (buflen < 1)
	goto err_toolong;
    /* Get '/' right */
    retval = end - 1;
    *retval = '/';

    while (1) {
	if (dentry_addr == root_dentry_addr && vfsmnt_addr == root_vfsmnt_addr)
	    break;
	VLV(target,vfsmnt,"mnt_root",LOAD_FLAG_NONE,&mnt_root_addr,NULL,
	    err_vmiload);
	if (dentry_addr == mnt_root_addr || dentry_addr == parent_addr) {
	    vfsmnt_mnt_parent = NULL;
	    VL(target,vfsmnt,"mnt_parent",LOAD_FLAG_AUTO_DEREF,
	       &vfsmnt_mnt_parent,err_vmiload);
	    vfsmnt_mnt_parent_addr = v_addr(vfsmnt_mnt_parent);

	    /* Global root? */
	    if (vfsmnt_mnt_parent_addr == vfsmnt_addr) {
		value_free(vfsmnt_mnt_parent);
		vfsmnt_mnt_parent = NULL;
		goto global_root;
	    }
	    if (dentry != orig_dentry) {
		value_free(dentry);
		dentry = NULL;
	    }
	    VL(target,vfsmnt,"mnt_mountpoint",LOAD_FLAG_AUTO_DEREF,&dentry,
	       err_vmiload);
	    dentry_addr = v_addr(dentry);
	    if (vfsmnt != orig_vfsmnt) {
		value_free(vfsmnt);
	    }
	    vfsmnt = vfsmnt_mnt_parent;
	    vfsmnt_addr = v_addr(vfsmnt);
	    vfsmnt_mnt_parent = NULL;
	    continue;
	}
	namelen = 0;
	VLV(target,dentry,"d_name.len",LOAD_FLAG_NONE,&namelen,NULL,err_vmiload);
	buflen -= namelen + 1;
	if (buflen < 0)
	    goto err_toolong;
	end -= namelen;
	VLV(target,dentry,"d_name.name",LOAD_FLAG_NONE,&nameaddr,NULL,err_vmiload);
	namebuf = NULL;
	VLA(target,nameaddr,LOAD_FLAG_NONE,&namebuf,namelen,NULL,err_vmiload);
	memcpy(end,namebuf,namelen);
	free(namebuf);
	namebuf = NULL;
	*--end = '/';
	retval = end;
	
	ph = dentry;
	VL(target,ph,"d_parent",LOAD_FLAG_AUTO_DEREF,&dentry,err_vmiload);
	if (ph != orig_dentry) {
	    value_free(ph);
	}
	dentry_addr = v_addr(dentry);
    }

    goto out;

 global_root:
    namelen = 0;
    VLV(target,dentry,"d_name.len",LOAD_FLAG_NONE,&namelen,NULL,err_vmiload);
    buflen -= namelen;
    if (buflen < 0)
	goto err_toolong;
    retval -= namelen - 1;	/* hit the slash */
    namebuf = NULL;
    VLA(target,nameaddr,LOAD_FLAG_NONE,&namebuf,namelen,NULL,err_vmiload);
    memcpy(retval,namebuf,namelen);
    free(namebuf);
    namebuf = NULL;

    goto out;

 err_toolong:
 err_vmiload:

    retval = NULL;

 out:
    /* Free intermediate dentry/vfsmnt values left, if any. */
    if (dentry && dentry != orig_dentry) {
	value_free(dentry);
	dentry = NULL;
    }
    if (vfsmnt && vfsmnt != orig_vfsmnt) {
	value_free(vfsmnt);
	vfsmnt = NULL;
    }

    return retval;
}

char *linux_file_get_path(struct target *target,struct value *task,
			  struct value *file,char *ibuf,int buflen) {
    struct value *dentry = NULL;
    struct value *vfsmnt = NULL;
    struct value *root_dentry = NULL;
    struct value *root_vfsmnt = NULL;
    char buf[PATH_MAX];
    char *bufptr;
    int len;
    int didalloc = 0;
    char *retval;

    VL(target,file,"f_vfsmnt",LOAD_FLAG_AUTO_DEREF,&vfsmnt,err_vmiload);
    VL(target,file,"f_dentry",LOAD_FLAG_AUTO_DEREF,&dentry,err_vmiload);
    VL(target,task,"fs.rootmnt",LOAD_FLAG_AUTO_DEREF,&root_vfsmnt,err_vmiload);
    VL(target,task,"fs.root",LOAD_FLAG_AUTO_DEREF,&root_dentry,err_vmiload);

    bufptr = linux_d_path(target,dentry,vfsmnt,root_dentry,root_vfsmnt,
			  buf,PATH_MAX);
    if (!bufptr) 
	goto err;

    if (!ibuf) {
	ibuf = malloc(PATH_MAX);
	buflen = PATH_MAX;
	didalloc = 1;
    }

    len = sizeof(buf) - (bufptr - buf);
    memcpy(ibuf,bufptr,(len < buflen) ? len : buflen);

    retval = ibuf;
    goto out;

 err:
 err_vmiload:
    retval = NULL;
    goto out;

 out:
    if (dentry)
	value_free(dentry);
    if (vfsmnt)
	value_free(vfsmnt);
    if (root_dentry)
	value_free(root_dentry);
    if (root_vfsmnt)
	value_free(root_vfsmnt);

    return retval;
}

/*
 * Since linux linked lists are formed by chaining C structs together
 * using struct members as the list next/prev pointers, we provide a
 * generic function to traverse them.
 *
 * Basically, we calculate the offset of the list head member name in
 * the type, and then, starting with the struct at the @head - offset,
 * we load that value.  We then continue looping by loading the next
 * struct specified in the list head member's next field.
 */
int linux_list_for_each_struct(struct target *t,struct bsymbol *bsymbol,
			       char *list_head_member_name,int nofree,
			       linux_list_iterator_t iterator,void *data) {
    struct symbol *symbol;
    struct symbol *type;
    struct symbol *list_head_member_symbol = NULL;
    OFFSET list_head_member_offset;
    ADDR head;
    ADDR next_head;
    ADDR current_struct_addr;
    struct value *value = NULL;
    int i = 0;
    int retval = -1;
    int rc;

    struct dump_info udn = {
	.stream = stderr,
	.prefix = "",
	.detail = 1,
	.meta = 1,
    };

    symbol = bsymbol_get_symbol(bsymbol);
    type = symbol_get_datatype__int(symbol);
    if (!type) {
	verror("no type for bsymbol %s!\n",bsymbol_get_name(bsymbol));
	goto out;
    }

    list_head_member_symbol = symbol_get_one_member(type,
						    list_head_member_name);
    if (!list_head_member_symbol) {
	verror("no such member %s in symbol %s!\n",list_head_member_name,
	       symbol_get_name(type));
	goto out;
    }

    if (symbol_get_location_offset(list_head_member_symbol,
				   &list_head_member_offset)) {
	verror("could not get offset for member %s in symbol %s!\n",
	       symbol_get_name(list_head_member_symbol),symbol_get_name(type));
	symbol_dump(symbol,&udn);
	goto out;
    }

    /* We just blindly use TID_GLOBAL because init_task is the symbol
     * they are supposed to pass, and resolving that is not going to
     * depend on any registers, so it doesn't matter which thread we
     * use.
     */
    current_struct_addr = head = \
	target_addressof_symbol(t,TID_GLOBAL,bsymbol,LOAD_FLAG_NONE,NULL);
    if (errno) {
	verror("could not get the address of bsymbol %s!\n",
	       bsymbol_get_name(bsymbol));
	goto out;
    }
    /* The real head is plus the member offset. */
    head += list_head_member_offset;

    /* Now, start loading the struct values one by one, starting with
     * the symbol arg itself.
     */
    while (1) {
	value = target_load_type(t,type,current_struct_addr,LOAD_FLAG_NONE);
	if (!value) {
	    verror("could not load value in list position %d, aborting!\n",i);
	    goto out;
	}

	rc = iterator(t,value,data);
	if (rc == 1)
	    break;
	else if (rc == -1) {
	    nofree = 1;
	    break;
	}

	next_head = *((ADDR *)(value->buf + list_head_member_offset));

	if (!nofree) {
	    value_free(value);
	    value = NULL;
	}

	if (next_head == head)
	    break;

	current_struct_addr = next_head - list_head_member_offset;
	++i;
    }

    retval = 0;

 out:
    if (list_head_member_symbol)
	symbol_release(list_head_member_symbol);
    if (!nofree && value)
	value_free(value);

    return retval;
}

/*
 * Since linux linked lists are formed by chaining C structs together
 * using struct members as the list next/prev pointers, we provide a
 * generic function to traverse them.
 *
 * This function is different from the one above in the sense that the
 * input to this one is a struct type, plus a list_head variable
 * (instead of having a struct instance that is the "head" of the
 * list).  So, for the task list, whose head is the init_task
 * task_struct, the above function is more appropriate.  For the modules
 * list_head, which might have nothing in it, this function is more
 * appropriate.
 *
 * Basically, we calculate the offset of the list head member name in
 * the type, and then, starting with the struct at the @head - offset,
 * we load that value.  We then continue looping by loading the next
 * struct specified in the list head member's next field.
 */
int linux_list_for_each_entry(struct target *t,struct bsymbol *btype,
			      struct bsymbol *list_head,
			      char *list_head_member_name,int nofree,
			      linux_list_iterator_t iterator,void *data) {
    struct symbol *type;
    struct symbol *list_head_member_symbol = NULL;
    OFFSET list_head_member_offset;
    ADDR head;
    ADDR next_head;
    ADDR current_struct_addr;
    struct value *value = NULL;
    struct value *value_next;
    int i = 0;
    int retval = -1;
    int rc;

    type = bsymbol_get_symbol(btype);

    list_head_member_symbol = symbol_get_one_member(type,
						    list_head_member_name);
    if (!list_head_member_symbol) {
	verror("no such member %s in symbol %s!\n",list_head_member_name,
	       symbol_get_name(type));
	goto out;
    }

    if (symbol_get_location_offset(list_head_member_symbol,
				   &list_head_member_offset)) {
	verror("could not get offset for member %s in symbol %s!\n",
	       symbol_get_name(list_head_member_symbol),symbol_get_name(type));
	goto out;
    }

    /*
     * We just blindly use TID_GLOBAL because init_task is the symbol
     * they are supposed to pass, and resolving that is not going to
     * depend on any registers, so it doesn't matter which thread we
     * use.
     */

    value = target_load_symbol(t,TID_GLOBAL,list_head,LOAD_FLAG_NONE);
    if (!value) {
	verror("could not load list_head for symbol %s!\n",bsymbol_get_name(list_head));
	goto out;
    }
    head = value_addr(value);
    value_next = target_load_value_member(t,value,"next",NULL,LOAD_FLAG_NONE);
    next_head = *((ADDR *)value->buf);

    value_free(value_next);
    value_free(value);
    value = NULL;

    /*
     * Now, start loading the struct values one by one, starting with next_head.
     */
    while (next_head != head) {
	/* The real head is plus the member offset. */
	current_struct_addr = next_head - list_head_member_offset;

	value = target_load_type(t,type,current_struct_addr,LOAD_FLAG_NONE);
	if (!value) {
	    verror("could not load value in list position %d, aborting!\n",i);
	    goto out;
	}

	rc = iterator(t,value,data);
	if (rc == 1)
	    break;
	else if (rc == -1) {
	    nofree = 1;
	    break;
	}

	next_head = *((ADDR *)(value->buf + list_head_member_offset));

	if (!nofree) {
	    value_free(value);
	    value = NULL;
	}

	if (next_head == head)
	    break;

	current_struct_addr = next_head - list_head_member_offset;
	++i;
    }

    retval = 0;

 out:
    if (list_head_member_symbol)
	symbol_release(list_head_member_symbol);
    if (!nofree && value)
	value_free(value);

    return retval;
}
