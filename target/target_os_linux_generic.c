/*
 * Copyright (c) 2013, 2014 The University of Utah
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

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <glib.h>

#include "common.h"
#include "glib_wrapper.h"
#include "arch.h"
#include "arch_x86.h"
#include "arch_x86_64.h"
#include "binfile.h"
#include "target.h"
#include "target_os.h"
#include "target_os_linux_generic.h"

/**
 ** Prototypes.
 **/
struct target_thread *os_linux_load_thread_from_value(struct target *target,
						      struct value *taskv);
struct target_thread *os_linux_load_current_thread(struct target *target,
						   int force);
static int os_linux_updateregions(struct target *target,
				  struct addrspace *space);

/*
 * We don't keep any local storage, so there is nothing to init or free!
 * All of our storage is based on target_gkv_*().
 */

int os_linux_attach(struct target *target) {
    struct os_linux_state *lstate;
    char *major = NULL,*minor = NULL,*patch = NULL;
    REFCNT trefcnt;
    unsigned int slen,i;
    char pbuf[PATH_MAX];
    char *k,*v;
    FILE *cf;
    char *tmp;

    lstate = (struct os_linux_state *)calloc(1,sizeof(*lstate));
    target->personality_state = lstate;

    lstate->kernel_filename = (char *) \
	g_hash_table_lookup(target->config,"OS_KERNEL_FILENAME");

    /*
     * First, parse out its version.  We look for the first number
     * followed by a dot.
     */
    slen = strlen(lstate->kernel_filename);
    for (i = 0; i < slen; ++i) {
	if (isdigit(lstate->kernel_filename[i])
	    && (i + 1) < slen && lstate->kernel_filename[i + 1] == '.') {
	    lstate->kernel_version = strdup(&lstate->kernel_filename[i]);
	    break;
	}
    }

    if (!lstate->kernel_version) {
	verror("could not parse kernel version info for %s!\n",
	       lstate->kernel_filename);
	goto errout;
    }

    /*
     * Figure out where the real ELF file is.  We look in four
     * places:
     *   /usr/lib/debug/lib/modules/<kernel_version>/vmlinux
     *   /usr/lib/debug/boot/vmlinux-<kernel_version>
     *   /boot/vmlinux-<kernel_version>
     *   /boot/vmlinux-syms-<kernel_version> (old A3 style)
     */
    lstate->kernel_elf_filename = malloc(PATH_MAX);
    lstate->kernel_elf_filename[0] = '\0';

    if (lstate->kernel_elf_filename[0] == '\0') {
	snprintf(lstate->kernel_elf_filename,PATH_MAX,
		 "%s/usr/lib/debug/lib/modules/%s/vmlinux",
		 (target->spec->debugfile_root_prefix)			\
		     ? target->spec->debugfile_root_prefix : "",
		 lstate->kernel_version);
	if (access(lstate->kernel_elf_filename,R_OK))
	    lstate->kernel_elf_filename[0] = '\0';
    }
    if (lstate->kernel_elf_filename[0] == '\0') {
	snprintf(lstate->kernel_elf_filename,PATH_MAX,
		 "%s/usr/lib/debug/boot/vmlinux-%s",
		 (target->spec->debugfile_root_prefix)			\
		 ? target->spec->debugfile_root_prefix : "",
		 lstate->kernel_version);
	if (access(lstate->kernel_elf_filename,R_OK))
	    lstate->kernel_elf_filename[0] = '\0';
    }
    if (lstate->kernel_elf_filename[0] == '\0') {
	snprintf(lstate->kernel_elf_filename,PATH_MAX,
		 "%s/boot/vmlinux-%s",
		 (target->spec->debugfile_root_prefix)			\
		 ? target->spec->debugfile_root_prefix : "",
		 lstate->kernel_version);
	if (access(lstate->kernel_elf_filename,R_OK))
	    lstate->kernel_elf_filename[0] = '\0';
    }
    if (lstate->kernel_elf_filename[0] == '\0') {
	snprintf(lstate->kernel_elf_filename,PATH_MAX,
		 "%s/boot/vmlinux-syms-%s",
		 (target->spec->debugfile_root_prefix)			\
		 ? target->spec->debugfile_root_prefix : "",
		 lstate->kernel_version);
	if (access(lstate->kernel_elf_filename,R_OK))
	    lstate->kernel_elf_filename[0] = '\0';
    }

    if (lstate->kernel_elf_filename[0] == '\0') {
	verror("could not find vmlinux binary for %s!\n",
	       lstate->kernel_version);
	goto errout;
    }

    /*
     * Replace the kernel file name with the real ELF one so that the
     * target loaddebugfiles() op can load it trivially!
     */
    g_hash_table_insert(target->config,strdup("OS_KERNEL_FILENAME"),
			strdup(lstate->kernel_elf_filename));
    lstate->kernel_filename = lstate->kernel_elf_filename;

    /*
     * Figure out where the System.map file is.  We look in two
     * places:
     *   /lib/modules/<kernel_version>/System.map 
     *   /boot/System.map-<kernel_version>
     */
    lstate->kernel_sysmap_filename = malloc(PATH_MAX);
    lstate->kernel_sysmap_filename[0] = '\0';

    if (lstate->kernel_sysmap_filename[0] == '\0') {
	snprintf(lstate->kernel_sysmap_filename,PATH_MAX,
		 "%s/lib/modules/%s/System.map",
		 (target->spec->debugfile_root_prefix)			\
		 ? target->spec->debugfile_root_prefix : "",
		 lstate->kernel_version);
	if (access(lstate->kernel_sysmap_filename,R_OK))
	    lstate->kernel_sysmap_filename[0] = '\0';
    }
    if (lstate->kernel_sysmap_filename[0] == '\0') {
	snprintf(lstate->kernel_sysmap_filename,PATH_MAX,
		 "%s/boot/System.map-%s",
		 (target->spec->debugfile_root_prefix)			\
		 ? target->spec->debugfile_root_prefix : "",
		 lstate->kernel_version);
	if (access(lstate->kernel_sysmap_filename,R_OK))
	    lstate->kernel_sysmap_filename[0] = '\0';
    }

    if (lstate->kernel_sysmap_filename[0] == '\0') {
	verror("could not find System.map file for %s!\n",
	       lstate->kernel_version);
	goto errout;
    }
    else {
	g_hash_table_insert(target->config,strdup("OS_KERNEL_SYSMAP_FILE"),
			    strdup(lstate->kernel_sysmap_filename));
    }

    /* Figure out where the modules are. */
    if ((tmp = strstr(lstate->kernel_filename,"vmlinuz-"))) {
	lstate->kernel_module_dir = malloc(PATH_MAX);
	snprintf(lstate->kernel_module_dir,PATH_MAX,
		 "/lib/modules/%s",tmp+strlen("vmlinuz-"));
    }
    else if ((tmp = strstr(lstate->kernel_filename,"vmlinux-syms-"))) {
	lstate->kernel_module_dir = malloc(PATH_MAX);
	snprintf(lstate->kernel_module_dir,PATH_MAX,
		 "/lib/modules/%s",tmp+strlen("vmlinux-syms-"));
    }
    else if ((tmp = strstr(lstate->kernel_filename,"vmlinux-"))) {
	lstate->kernel_module_dir = malloc(PATH_MAX);
	snprintf(lstate->kernel_module_dir,PATH_MAX,
		 "/lib/modules/%s",tmp+strlen("vmlinux-"));
    }

    if (sscanf(lstate->kernel_version,"%m[0-9].%m[0-9].%m[0-9]",
	       &major,&minor,&patch) == 3) {
	g_hash_table_insert(target->config,strdup("__VERSION_MAJOR"),major);
	g_hash_table_insert(target->config,strdup("__VERSION_MINOR"),minor);
	g_hash_table_insert(target->config,strdup("__VERSION_PATCH"),patch);
    }
    else {
	if (major) 
	    free(major);
	if (minor)
	    free(minor);
	if (patch)
	    free(patch);
    }

    /*
     * Load the config file.  We look only in /boot .
     */
    snprintf(pbuf,sizeof(pbuf),"/boot/config-%s",lstate->kernel_version);
    if (access(pbuf,R_OK) == 0) {
	cf = fopen(pbuf,"r");
	if (!cf) 
	    verror("fopen(%s): %s\n",pbuf,strerror(errno));
	else {
	    /* scanf to look for normal lines. */
	    while (1) {
		if (!fgets(pbuf,sizeof(pbuf),cf))
		    break;
		if (*pbuf == '#')
		    continue;

		k = v = NULL;
		if (sscanf(pbuf,"%m[^ \t=]=\"%ms\"",&k,&v) == 2) {
		    g_hash_table_insert(target->config,k,v);
		    continue;
		}
		else {
		    if (k)
			free(k);
		    if (v) 
			free(v);
		}

		k = v = NULL;
		if (sscanf(pbuf,"%m[^ \t=]=%ms",&k,&v) == 2) {
		    g_hash_table_insert(target->config,k,v);
		    continue;
		}
		else {
		    if (k)
			free(k);
		    if (v) 
			free(v);
		}
	    }
	    fclose(cf);
	}
    }
    else {
	vwarn("could not read kernel config from %s; strange errors may result!\n",
	      pbuf);
    }

    if (!lstate->kernel_elf_filename) {
	verror("could not infer kernel ELF file (vmlinux) from %s; aborting!\n",
	       lstate->kernel_filename);
	goto errout;
    }

    /* Then grab stuff from the ELF binary itself. */
    if (!target->binfile) {
	target->binfile = 
	    binfile_open(lstate->kernel_elf_filename,
			 target->spec->debugfile_root_prefix,NULL);
	if (!target->binfile) {
	    verror("binfile_open %s: %s\n",
		   lstate->kernel_elf_filename,strerror(errno));
	    goto errout;
	}

	RHOLD(target->binfile,target);
	/* Drop the self-ref that binfile_open held on our behalf. */
	RPUT(target->binfile,binfile,target->binfile,trefcnt);

	vdebug(3,LA_TARGET,LF_OSLINUX,
	       "loaded ELF arch info for %s (wordsize=%d;endian=%s)\n",
	       lstate->kernel_elf_filename,target->binfile->arch->wordsize,
	       (target->binfile->arch->endian == ENDIAN_LITTLE ? "LSB" : "MSB"));
    }

    lstate->task_struct_addr_to_thread = 
	g_hash_table_new(g_direct_hash,g_direct_equal);

    target->personality = TARGET_PERSONALITY_OS;

    return 0;

 errout:
    if (lstate->task_struct_addr_to_thread) 
	g_hash_table_destroy(lstate->task_struct_addr_to_thread);
    if (lstate->kernel_version)
	free(lstate->kernel_version);
    if (lstate->kernel_filename)
	free(lstate->kernel_filename);
    if (lstate->kernel_elf_filename)
	free(lstate->kernel_elf_filename);
    if (lstate->kernel_sysmap_filename)
	free(lstate->kernel_sysmap_filename);
    if (lstate->kernel_module_dir)
	free(lstate->kernel_module_dir);

    return -1;
}

int os_linux_fini(struct target *target) {
    struct os_linux_state *lstate = \
	(struct os_linux_state *)target->personality_state;
    REFCNT trefcnt;

    if (lstate->task_struct_addr_to_thread) {
	g_hash_table_destroy(lstate->task_struct_addr_to_thread);
	lstate->task_struct_addr_to_thread = NULL;
    }

    if (lstate->init_task)
	bsymbol_release(lstate->init_task);
    if (lstate->task_struct_type)
	symbol_release(lstate->task_struct_type);
    if (lstate->thread_struct_type)
	symbol_release(lstate->thread_struct_type);
    if (lstate->task_struct_type_ptr)
	symbol_release(lstate->task_struct_type_ptr);
    if (lstate->mm_struct_type)
	symbol_release(lstate->mm_struct_type);
    if (lstate->pt_regs_type)
	symbol_release(lstate->pt_regs_type);
    if (lstate->thread_info_type)
	RPUT(lstate->thread_info_type,symbol,target,trefcnt);
    if (lstate->modules)
	bsymbol_release(lstate->modules);
    if (lstate->module_type)
	bsymbol_release(lstate->module_type);

    if (lstate->kernel_version)
	free(lstate->kernel_version);
    if (lstate->kernel_elf_filename)
	free(lstate->kernel_elf_filename);
    if (lstate->kernel_sysmap_filename)
	free(lstate->kernel_sysmap_filename);
    if (lstate->kernel_module_dir)
	free(lstate->kernel_module_dir);

    return 0;
}

int os_linux_postloadinit(struct target *target) {
    struct os_linux_state *lstate = \
	(struct os_linux_state *)target->personality_state;
    struct bsymbol *thread_info_type;
    struct bsymbol *mm_struct_type;
    struct lsymbol *tmpls;
    struct bsymbol *tmpbs;
    OFFSET offset;
    char buf[128];
    struct target_location_ctxt *tlctxt = target_global_tlctxt(target);

    /*
     * Assume if we did this, we've done it all.
     */
    if (lstate->init_task) 
	return 0;

    /*
     * Finally: initialize our state in the target's global thread!
     */
    target->global_thread->personality_state = \
	calloc(1,sizeof(struct os_linux_thread_state));

    /*
     * Try to load some debuginfo stuff so we can provide better
     * functionality!  We have to do this in target_attach because only
     * at that point can we know that the debuginfo sources have been
     * loaded.
     */

    /*
     * Find the kernel start address.
     */
    
    /* Try .text first (and fake the delimiter!!!) */
    if (lstate->kernel_start_addr == 0) {
	tmpbs = target_lookup_sym(target,".text","|",NULL,
				  SYMBOL_TYPE_FLAG_FUNC);
	if (tmpbs) {
	    if (target_bsymbol_resolve_base(target,tlctxt,tmpbs,
					    &lstate->kernel_start_addr,NULL)) {
		vwarnopt(1,LA_TARGET,LF_OSLINUX,
			 "could not resolve addr of .text;"
			 " trying startup_(32|64)!\n");
	    }
	    bsymbol_release(tmpbs);
	    tmpbs = NULL;
	}
	else {
	    vwarnopt(1,LA_TARGET,LF_OSLINUX,
		     "could not find symbol .text; trying startup_(32|64)!\n");
	}
    }

    /* If we didn't find .text, try startup_(32|64). */
    if (lstate->kernel_start_addr == 0) {
	if (target->arch->wordsize == 4) {
	    tmpbs = target_lookup_sym(target,"startup_32",NULL,NULL,
				      SYMBOL_TYPE_FLAG_FUNC);
	    if (tmpbs) {
		if (target_bsymbol_resolve_base(target,tlctxt,
						tmpbs,&lstate->kernel_start_addr,
						NULL)) {
		    vwarnopt(1,LA_TARGET,LF_OSLINUX,
			     "could not resolve addr of startup_32!\n");
		}
		bsymbol_release(tmpbs);
		tmpbs = NULL;
	    }
	    else {
		vwarnopt(1,LA_TARGET,LF_OSLINUX,
			 "could not find symbol startup_32!\n");
	    }
	}
	else {
	    tmpbs = target_lookup_sym(target,"startup_64",NULL,NULL,
				      SYMBOL_TYPE_FLAG_FUNC);
	    if (tmpbs) {
		if (target_bsymbol_resolve_base(target,tlctxt,
						tmpbs,&lstate->kernel_start_addr,
						NULL)) {
		    vwarnopt(1,LA_TARGET,LF_OSLINUX,
			     "could not resolve addr of startup_64!\n");
		}
		bsymbol_release(tmpbs);
		tmpbs = NULL;
	    }
	    else {
		vwarnopt(1,LA_TARGET,LF_OSLINUX,
			 "could not find symbol startup_64!\n");
	    }
	}
    }

    /* If we still didn't find it... */
    if (lstate->kernel_start_addr == 0) {
	vwarn("could not find addr of .text nor startup_(32|64);"
	      " using defaults!\n");

	if (target->arch->wordsize == 4) 
	    lstate->kernel_start_addr = 0xC0000000;
#if __WORDSIZE == 64
	else if (target->arch->wordsize == 8)
	    lstate->kernel_start_addr = 0xFFFFFFFF81000000ULL;
#endif
    }
    else {
	snprintf(buf,sizeof(buf),"0x%"PRIxADDR,lstate->kernel_start_addr);
	g_hash_table_insert(target->config,
			    strdup("OS_KERNEL_START_ADDR"),strdup(buf));
    }

    vdebug(3,LA_TARGET,LF_OSLINUX,"kernel start addr is 0x%"PRIxREGVAL"\n",
	   lstate->kernel_start_addr);

    /*
     * Find init_task.
     */
    lstate->init_task = target_lookup_sym(target,"init_task",NULL,NULL,
					  SYMBOL_TYPE_FLAG_VAR);
    if (!lstate->init_task) {
	vwarn("could not lookup init_task in debuginfo; no multithread support!\n");
	/* This is not an error, so we don't return error -- it
	 * would upset target_open.
	 */
	return 0;
    }
    if (target_bsymbol_resolve_base(target,tlctxt,
				    lstate->init_task,
				    &lstate->init_task_addr,NULL)) {
	vwarn("could not resolve addr of init_task!\n");
    }
    else {
	snprintf(buf,sizeof(buf),"0x%"PRIxADDR,lstate->init_task_addr);
	g_hash_table_insert(target->config,
			    strdup("OS_KERNEL_INIT_TASK_ADDR"),strdup(buf));
    }

    /*
     * Save the 'struct task_struct' type.  Hold a ref to it since it
     * might be an autofollowed abstract origin type!
     */
    lstate->task_struct_type = \
	symbol_get_datatype(lstate->init_task->lsymbol->symbol);
    RHOLD(lstate->task_struct_type,target);

    mm_struct_type = target_lookup_sym(target,"struct mm_struct",
				       NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);
    if (!mm_struct_type) {
	vwarn("could not lookup 'struct mm_struct' in debuginfo;"
	      " userspace vm access might fail!\n");
	/* This is not an error, so we don't return error -- it
	 * would upset target_open.
	 */
	return 0;
    }
    lstate->mm_struct_type = bsymbol_get_symbol(mm_struct_type);
    RHOLD(lstate->mm_struct_type,target);
    bsymbol_release(mm_struct_type);

    /* We might also want to load tasks from pointers (i.e., the
     * current task.
     */
    lstate->task_struct_type_ptr =				\
	target_create_synthetic_type_pointer(target,lstate->task_struct_type);

    /*
     * Find some offsets inside typeof(init_task).
     */
    offset = symbol_offsetof(lstate->task_struct_type,"tasks",NULL);
    if (errno) 
	vwarn("could not resolve offset of task_struct.tasks!\n");
    else {
	snprintf(buf,sizeof(buf),"0x%"PRIxOFFSET,offset);
	g_hash_table_insert(target->config,
			    strdup("OS_KERNEL_TASKS_OFFSET"),strdup(buf));
    }
    errno = 0;
    offset = symbol_offsetof(lstate->task_struct_type,"pid",NULL);
    if (errno) 
	vwarn("could not resolve offset of task_struct.pid!\n");
    else {
	snprintf(buf,sizeof(buf),"0x%"PRIxOFFSET,offset);
	g_hash_table_insert(target->config,
			    strdup("OS_KERNEL_PID_OFFSET"),strdup(buf));
    }
    errno = 0;
    offset = symbol_offsetof(lstate->task_struct_type,"mm",NULL);
    if (errno) 
	vwarn("could not resolve offset of task_struct.mm!\n");
    else {
	snprintf(buf,sizeof(buf),"0x%"PRIxOFFSET,offset);
	g_hash_table_insert(target->config,
			    strdup("OS_KERNEL_MM_OFFSET"),strdup(buf));
    }
    errno = 0;
    offset = symbol_offsetof(lstate->mm_struct_type,"pgd",NULL);
    if (errno) 
	vwarn("could not resolve offset of mm_struct.pgd!\n");
    else {
	snprintf(buf,sizeof(buf),"0x%"PRIxOFFSET,offset);
	    g_hash_table_insert(target->config,
				strdup("OS_KERNEL_MM_PGD_OFFSET"),strdup(buf));
    }

    /*
     * Find swapper_pg_dir.
     */
    tmpbs = target_lookup_sym(target,"swapper_pg_dir",NULL,NULL,
			      SYMBOL_TYPE_FLAG_NONE);
    if (!tmpbs) 
	vwarn("could not find 'swapper_pg_dir'; userspace vm access will fail!\n");
    else {
	if (target_bsymbol_resolve_base(target,tlctxt,tmpbs,&lstate->pgd_addr,NULL)) {
	    vwarn("could not resolve addr of swapper_pg_dir!\n");
	}
	else {
	    snprintf(buf,sizeof(buf),"0x%"PRIxADDR,lstate->pgd_addr);
	    g_hash_table_insert(target->config,
				strdup("OS_KERNEL_PGD_ADDR"),strdup(buf));
	}
	bsymbol_release(tmpbs);
	tmpbs = NULL;
    }

    /*
     * For x86_64, current_thread_ptr depends on this value -- so just
     * load it once and keep it around forever.
     * target_xen_vm_util::current_thread_ptr refreshes it as needed.
     */
    if (target->arch->wordsize == 8) {
	vdebug(3,LA_TARGET,LF_OSLINUX,
	       "attempting to find per-cpu kernel stack offset\n");

	if ((tmpbs = target_lookup_sym(target,"kernel_stack",NULL,NULL,
				       SYMBOL_TYPE_FLAG_VAR))) {
	    errno = 0;
	    lstate->kernel_stack_percpu_offset = 
		target_addressof_symbol(target,tlctxt,tmpbs,
					LOAD_FLAG_NONE,NULL);
	    bsymbol_release(tmpbs);
	    if (errno) {
		verror("could not load kernel_stack percpu offset;"
		       " cannot continue!\n");
		return -1;
	    }
	}
	else if ((tmpbs = target_lookup_sym(target,"struct x8664_pda",NULL,NULL,
					    SYMBOL_TYPE_FLAG_TYPE))) {
	    errno = 0;
	    lstate->kernel_stack_percpu_offset = 
		symbol_offsetof(bsymbol_get_symbol(tmpbs),"kernelstack",NULL);
	    if (errno) {
		verror("could not get offsetof struct x8664_pda.kernelstack;"
		       " cannot continue!\n");
		return -1;
	    }
	}
	else {
	    verror("could not find x86_64 kernel stack percpu var in debuginfo;"
		   " cannot continue!\n");
	    return -1;
	}
    }

    /* Fill in the init_task addr in the default thread. */
    ((struct os_linux_thread_state *)(target->global_thread->personality_state))->task_struct_addr = \
	lstate->init_task_addr;

    /*
     * Save the 'struct pt_regs' type.
     */
    tmpbs = target_lookup_sym(target,"struct pt_regs",NULL,NULL,
			      SYMBOL_TYPE_FLAG_TYPE);
    if (!tmpbs) {
	vwarn("could not lookup 'struct pt_regs' in debuginfo;"
	      " no multithread support!\n");
	/* This is not an error, so we don't return error -- it
	 * would upset target_open.
	 */
	return 0;
    }
    lstate->pt_regs_type = bsymbol_get_symbol(tmpbs);
    RHOLD(lstate->pt_regs_type,target);
    bsymbol_release(tmpbs);

    /*
     * Find out if pt_regs has ds/es (only i386 should have it; old i386
     * has xds/xes; new i386 has ds/es).
     */
    if ((tmpls = symbol_lookup_sym(lstate->pt_regs_type,"ds",NULL))
	|| (tmpls = symbol_lookup_sym(lstate->pt_regs_type,"xds",NULL))) {
	lsymbol_release(tmpls);
	lstate->pt_regs_has_ds_es = 1;
    }
    else
	lstate->pt_regs_has_ds_es = 0;

    /*
     * Find out if pt_regs has fs/gs (only i386 should have it).
     */
    if ((tmpls = symbol_lookup_sym(lstate->pt_regs_type,"fs",NULL))) {
	lsymbol_release(tmpls);
	lstate->pt_regs_has_fs_gs = 1;
    }
    else
	lstate->pt_regs_has_fs_gs = 0;

    /*
     * Find the offset of the (r|e)ip member in pt_regs (we use this for
     * faster loading/saving).
     */
    errno = 0;
    lstate->pt_regs_ip_offset = 
	(int)symbol_offsetof(lstate->pt_regs_type,"ip",NULL);
    if (errno) {
	errno = 0;
	lstate->pt_regs_ip_offset = 
	    (int)symbol_offsetof(lstate->pt_regs_type,"eip",NULL);
	if (errno) {
	    errno = 0;
	    lstate->pt_regs_ip_offset = 
		(int)symbol_offsetof(lstate->pt_regs_type,"rip",NULL);
	    if (errno) {
		vwarn("could not find (r|e)ip in pt_regs; things will break!\n");
	    }
	}
    }

    /*
     * Find out if task_struct has a thread_info member (older), or if
     * it just has a void * stack (newer).  As always, either way, the
     * thread_info struct is at the "bottom" of the stack; the stack top
     * is either a page or two up.
     */
    if ((tmpls = symbol_lookup_sym(lstate->task_struct_type,"thread_info",NULL))) {
	lstate->task_struct_has_thread_info = 1;
	lsymbol_release(tmpls);
    }
    else if ((tmpls = symbol_lookup_sym(lstate->task_struct_type,"stack",NULL))) {
	lstate->task_struct_has_stack = 1;
	lsymbol_release(tmpls);
    }
    else {
	vwarn("could not find thread_info nor stack member in struct task_struct;"
	      " no multithread support!\n");
	return 0;
    }

    /*
     * Find out the name of the uid/gid members.
     */
    if ((tmpls = symbol_lookup_sym(lstate->task_struct_type,"uid",NULL))) {
	lstate->task_uid_member_name = "uid";
	lstate->task_gid_member_name = "gid";
	lsymbol_release(tmpls);
    }
    else if ((tmpls = symbol_lookup_sym(lstate->task_struct_type,
					"cred.uid",NULL))) {
	lstate->task_uid_member_name = "cred.uid";
	lstate->task_gid_member_name = "cred.gid";
	lsymbol_release(tmpls);
    }
    else {
	vwarn("could not find uid/gid info in struct task_struct;"
	      " no uid/gid thread context support!\n");
    }

    /*
     * Save the 'struct thread_struct' type.
     */
    tmpbs = target_lookup_sym(target,"struct thread_struct",NULL,NULL,
			      SYMBOL_TYPE_FLAG_TYPE);
    if (!tmpbs) {
	vwarn("could not lookup 'struct thread_struct' in debuginfo;"
	      " no multithread support!\n");
	/* This is not an error, so we don't return error -- it
	 * would upset target_open.
	 */
	return 0;
    }
    lstate->thread_struct_type = bsymbol_get_symbol(tmpbs);
    RHOLD(lstate->thread_struct_type,target);
    bsymbol_release(tmpbs);
    /* Now figure out if the member is esp/sp. */
    if ((tmpls = symbol_lookup_sym(lstate->thread_struct_type,"esp0",NULL))) {
	lstate->thread_sp_member_name = "esp";
	lstate->thread_sp0_member_name = "esp0";
	lsymbol_release(tmpls);
    }
    else if ((tmpls = symbol_lookup_sym(lstate->thread_struct_type,"sp",NULL))) {
	lstate->thread_sp_member_name = "sp";
	lstate->thread_sp0_member_name = "sp0";
	lsymbol_release(tmpls);
    }
    else if ((tmpls = symbol_lookup_sym(lstate->thread_struct_type,"rsp0",NULL))) {
	lstate->thread_sp_member_name = "rsp";
	lstate->thread_sp0_member_name = "rsp0";
	lsymbol_release(tmpls);
    }
    else {
	vwarn("could not find 'struct thread_struct.(esp0|sp|rsp0)';"
	      " will cause problems!\n");
	lstate->thread_sp_member_name = NULL;
	lstate->thread_sp0_member_name = NULL;
    }

    /* Now figure out if thread_struct has an eip/ip member. */
    if ((tmpls = symbol_lookup_sym(lstate->thread_struct_type,"eip",NULL))) {
	lstate->thread_ip_member_name = "eip";
	lsymbol_release(tmpls);
    }
    else if ((tmpls = symbol_lookup_sym(lstate->thread_struct_type,"ip",NULL))) {
	lstate->thread_ip_member_name = "ip";
	lsymbol_release(tmpls);
    }
    else if ((tmpls = symbol_lookup_sym(lstate->thread_struct_type,"rip",NULL))) {
	lstate->thread_ip_member_name = "rip";
	lsymbol_release(tmpls);
    }
    else {
	lstate->thread_ip_member_name = NULL;
    }

    /*
     * Find out if thread_struct has ds/es (x86_64).
     */
    if ((tmpls = symbol_lookup_sym(lstate->thread_struct_type,"es",NULL))) {
	lsymbol_release(tmpls);
	lstate->thread_struct_has_ds_es = 1;
    }
    else
	lstate->thread_struct_has_ds_es = 0;

    /*
     * Find out if thread_struct has fs (x86_64 only -- it's on the
     * pt_regs stack for i386).
     *
     * Also, gs is always in the thread_struct, as far as I can tell.
     */
    if ((tmpls = symbol_lookup_sym(lstate->thread_struct_type,"fs",NULL))) {
	lsymbol_release(tmpls);
	lstate->thread_struct_has_fs = 1;
    }
    else
	lstate->thread_struct_has_fs = 0;

    /*
     * Find out if thread_struct has debugreg, debugreg0, or perf_event.
     */
    if ((tmpls = symbol_lookup_sym(lstate->thread_struct_type,"debugreg",
				   NULL))) {
	lsymbol_release(tmpls);
	lstate->thread_struct_has_debugreg = 1;
    }
    else
	lstate->thread_struct_has_debugreg = 0;
    if ((tmpls = symbol_lookup_sym(lstate->thread_struct_type,"debugreg0",
				   NULL))) {
	lsymbol_release(tmpls);
	lstate->thread_struct_has_debugreg0 = 1;
    }
    else
	lstate->thread_struct_has_debugreg0 = 0;
    if ((tmpls = symbol_lookup_sym(lstate->thread_struct_type,"ptrace_bps",
				   NULL))) {
	lsymbol_release(tmpls);
	lstate->thread_struct_has_perf_debugreg = 1;
    }
    else
	lstate->thread_struct_has_perf_debugreg = 0;

    /*
     * Load in thread_info struct type.
     */
    thread_info_type = target_lookup_sym(target,"struct thread_info",
					 NULL,NULL,SYMBOL_TYPE_FLAG_TYPE);
    if (!thread_info_type) {
	vwarn("could not lookup 'struct thread_info' in debuginfo;"
	      " no multithread support!\n");
	/* This is not an error, so we don't return error -- it
	 * would upset target_open.
	 */
	return 0;
    }
    lstate->thread_info_type = bsymbol_get_symbol(thread_info_type);
    RHOLD(lstate->thread_info_type,target);
    bsymbol_release(thread_info_type);

    if (!(lstate->module_type = target_lookup_sym(target,"struct module",
						  NULL,NULL,
						  SYMBOL_TYPE_FLAG_TYPE))) {
	vwarn("could not lookup 'struct module'; no module debuginfo support!\n");
    }
    else if (!(lstate->modules = target_lookup_sym(target,"modules",NULL,NULL,
						   SYMBOL_TYPE_FLAG_VAR))) {
	vwarn("could not lookup modules; not updating modules list!\n");
	return 0;
    }

    /*
     * Lookup symbols for active probing, here, regardless of
     * target->spec->active_probe_flags ; user may change active probing
     * settings later!
     */
    if (!(lstate->module_free_symbol = 
	  target_lookup_sym(target,"module_free",NULL,NULL,
			    SYMBOL_TYPE_NONE))) {
	vwarn("could not lookup module_free; active memory updates"
	      " cannot function!\n");
    }
    else if (!(lstate->module_free_mod_symbol = 
	           target_lookup_sym(target,"module_free.mod",NULL,NULL,
				     SYMBOL_TYPE_NONE))) {
	bsymbol_release(lstate->module_free_symbol);
	lstate->module_free_symbol = NULL;

	vwarn("could not lookup module_free.mod; active memory updates"
	      " cannot function!\n");
    }
    else {
	VLS(target,tlctxt,"MODULE_STATE_LIVE",LOAD_FLAG_NONE,
	    &lstate->MODULE_STATE_LIVE,NULL,err_vmiload_meminfo);
	vdebug(8,LA_TARGET,LF_OSLINUX,
	       "MODULE_STATE_LIVE = %d\n",lstate->MODULE_STATE_LIVE);
	VLS(target,tlctxt,"MODULE_STATE_COMING",LOAD_FLAG_NONE,
	    &lstate->MODULE_STATE_COMING,NULL,err_vmiload_meminfo);
	vdebug(8,LA_TARGET,LF_OSLINUX,
	       "MODULE_STATE_COMING = %d\n",lstate->MODULE_STATE_COMING);
	VLS(target,tlctxt,"MODULE_STATE_GOING",LOAD_FLAG_NONE,
	    &lstate->MODULE_STATE_GOING,NULL,err_vmiload_meminfo);
	vdebug(8,LA_TARGET,LF_OSLINUX,
	       "MODULE_STATE_GOING = %d\n",lstate->MODULE_STATE_GOING);

	if (0) {
	err_vmiload_meminfo:
	    bsymbol_release(lstate->module_free_symbol);
	    lstate->module_free_symbol = NULL;
	    bsymbol_release(lstate->module_free_mod_symbol);
	    lstate->module_free_mod_symbol = NULL;

	    vwarn("could not lookup MODULE_STATE_* var; active memory updates"
		  " cannot function!\n");
	}
    }

#ifdef ENABLE_DISTORM
    if (!(lstate->thread_entry_f_symbol = 
	      target_lookup_sym(target,"copy_process",NULL,NULL,
				SYMBOL_TYPE_NONE))) {
	vwarn("could not lookup copy_process;"
	      " active thread entry updates cannot function!\n");
    }
    /*
    if (!(lstate->thread_entry_v_symbol = 
	      target_lookup_sym(target,"copy_process.p",NULL,NULL,
				SYMBOL_TYPE_NONE))) {
	bsymbol_release(lstate->thread_entry_f_symbol);
	lstate->thread_entry_f_symbol = NULL;

	vwarn("could not lookup copy_process.p;"
	      " active thread entry updates might not function!\n");
    }
    */
#endif

    if (!(lstate->thread_exit_f_symbol = 
	      target_lookup_sym(target,"sched_exit",NULL,NULL,
				SYMBOL_TYPE_NONE))) {
	vwarn("could not lookup sched_exit; trying __unhash_process!\n");

	if (!(lstate->thread_exit_f_symbol = 
	      target_lookup_sym(target,"__unhash_process",NULL,NULL,
				SYMBOL_TYPE_NONE))) {
	    vwarn("could not lookup __unhash_process;"
		  " active thread exit updates cannot function!\n");
	}
	else if (!(lstate->thread_exit_v_symbol = 
		   target_lookup_sym(target,"__unhash_process.p",NULL,NULL,
				     SYMBOL_TYPE_NONE))) {
	    bsymbol_release(lstate->thread_exit_f_symbol);
	    lstate->thread_exit_f_symbol = NULL;
	    vwarn("could not lookup __unhash_process.p;"
		  " active thread exit updates cannot function!\n");
	}
    }
    else if (!(lstate->thread_exit_v_symbol = 
	      target_lookup_sym(target,"sched_exit.p",NULL,NULL,
				SYMBOL_TYPE_NONE))) {
	bsymbol_release(lstate->thread_exit_f_symbol);
	lstate->thread_exit_f_symbol = NULL;
	vwarn("could not lookup sched_exit.p;"
	      " active thread exit updates cannot function!\n");
    }

    return 0;
}

int os_linux_postopened(struct target *target) {
    struct addrspace *space;
    int rc = 0;

    list_for_each_entry(space,&target->spaces,space) {
	rc |= os_linux_updateregions(target,space);
    }

    return rc;
}

int os_linux_handle_exception(struct target *target) {
    struct addrspace *space;

    /*
     * If not active probing memory, we kind of want to update our
     * addrspaces aggressively (by checking the module list) so that
     * if a user lookups a module symbol, we already have it.
     *
     * Active probing memory for the Xen target is a big win.
     */
    if (!(target->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY)) {
	list_for_each_entry(space,&target->spaces,space) {
	    os_linux_updateregions(target,space);
	}
    }

    return 0;
}

target_os_type_t os_linux_type(struct target *target) {
    return TARGET_OS_TYPE_LINUX;
}

/*
 * Lookup version by reading either 'system_utsname.release' OR
 * 'init_uts_ns.release' (if namespace support).  We don't care if we
 * read current's namespace uts struct or just init's uts namespace,
 * because we want the base OS's release.  I don't even know if the
 * kernel allows a process's UTS namespace to override the release info :).
 */
uint64_t os_linux_version(struct target *target) {
    uint64_t retval = 0;
    char *vstring;
    struct bsymbol *bs;
    struct value *v;
    char *endptr;
    char *next;
    unsigned long int vnum;
    uint64_t *sretval;
    struct target_location_ctxt *tlctxt;

    /* Check cache. */
    if ((vstring = (char *)target_gkv_lookup(target,"os_linux_version_string"))
	&& (sretval = (uint64_t *)target_gkv_lookup(target,"os_linux_version")))
	return *sretval;

    /* Otherwise load it. */
    if (!(bs = target_lookup_sym(target,"system_utsname.release",NULL,NULL,
				 SYMBOL_TYPE_FLAG_VAR))
	&& !(bs = target_lookup_sym(target,"init_uts_ns.name.release",NULL,NULL,
				    SYMBOL_TYPE_FLAG_VAR))) {
	verror("could not find system_utsname.release"
	       " nor init_uts_ns.name.release!\n");
	return 0;
    }
    else {
	tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,bs);
	v = target_load_symbol(target,tlctxt,bs,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load %s!\n",
		   symbol_get_name(bsymbol_get_symbol(bs)));
	    target_location_ctxt_free(tlctxt);
	    return 0;
	}
	target_location_ctxt_free(tlctxt);
    }

    bsymbol_release(bs);

    /* NULL out the last byte of the .release char array just to be safe */
    v->buf[v->bufsiz - 1] = '\0';

    /* Release is always, always <major>.<minor>.<patchlevel> */
    next = v->buf;
    endptr = NULL;
    vnum = strtoul(next,&endptr,10);
    if (endptr == next) {
	verror("could not determine major release number from '%s'!\n",v->buf);
	retval = 0;
	goto out;
    }
    retval |= vnum << 16;

    next = endptr + 1;
    endptr = NULL;
    vnum = strtoul(next,&endptr,10);
    if (endptr == next) {
	verror("could not determine minor release number from '%s'!\n",v->buf);
	retval = 0;
	goto out;
    }
    retval |= vnum << 8;

    next = endptr + 1;
    endptr = NULL;
    vnum = strtoul(next,&endptr,10);
    if (endptr == next) {
	verror("could not determine patchlevel release number from '%s'!\n",
	       v->buf);
	retval = 0;
	goto out;
    }
    retval |= vnum;

    vdebug(5,LA_TARGET,LF_OS,
	   "version number %"PRIu64" (0x%"PRIx64") from '%s'",
	   retval,v->buf);

    /* Cache it. */
    target_gkv_insert(target,"os_linux_version_string",strdup(v->buf),
		      target_gkv_dtor_free);
    sretval = malloc(sizeof(*sretval));
    *(uint64_t *)sretval = retval;
    target_gkv_insert(target,"os_linux_version",sretval,
		      target_gkv_dtor_free);

 out:
    bsymbol_release(bs);
    value_free(v);

    return retval;
}

int os_linux_version_cmp(struct target *target,uint64_t vers) {
    uint64_t ourvers;

    ourvers = target_os_version(target);

    if (ourvers == vers)
	return 0;
    else if (ourvers < vers)
	return -1;
    else
	return 1;
}

char *os_linux_version_string(struct target *target) {
    target_os_version(target);
    return (char *)target_gkv_lookup(target,"os_linux_version");
}

int os_linux_thread_get_pgd_phys(struct target *target,
				 struct target_thread *tthread,ADDR *pgdp) {
    struct os_linux_thread_state *ltstate =
	(struct os_linux_thread_state *)tthread->personality_state;

    return target_addr_v2p(target,TID_GLOBAL,ltstate->pgd,pgdp);
}

int os_linux_thread_is_user(struct target *target,
			    struct target_thread *tthread) {
    struct os_linux_thread_state *ltstate =
	(struct os_linux_thread_state *)tthread->personality_state;

    if (ltstate->mm_addr)
	return 1;
    else
	return 0;
}

struct target_thread *os_linux_thread_get_leader(struct target *target,
						 struct target_thread *tthread) {
    struct target_thread *leader;
    struct os_linux_state *lstate =
	(struct os_linux_state *)target->personality_state;
    struct os_linux_thread_state *ltstate =
	(struct os_linux_thread_state *)tthread->personality_state;
    struct array_list *tlist;
    struct os_linux_thread_state *tmp_ltstate;
    struct value *value;
    int i;

    /* The only reason this should be NULL is if it's a kernel thread. */
    if (!ltstate->task_struct) {
	vwarnopt(5,LA_TARGET,LF_OSLINUX,
		 "thread %d did not have a task struct value!\n",tthread->tid);
	return NULL;
    }

    /* If we are the group leader, return ourself. */
    if (value_addr(ltstate->task_struct) == ltstate->group_leader)
	return tthread;

    /*
     * Otherwise, see if our group_leader is already loaded, and return
     * it if it is.
     */
    tlist = target_list_threads(target);
    array_list_foreach(tlist,i,leader) {
	tmp_ltstate = (struct os_linux_thread_state *)leader->personality_state;
	if (tmp_ltstate->task_struct 
	    && value_addr(tmp_ltstate->task_struct) == ltstate->group_leader) {
	    array_list_free(tlist);
	    return leader;
	}
    }
    array_list_free(tlist);
    leader = NULL;

    /* Otherwise, load it. */
    vdebug(5,LA_TARGET,LF_OSLINUX,
	   "trying to load tid %d's group_leader at 0x%"PRIxADDR"\n",
	   tthread->tid,ltstate->group_leader);

    value = target_load_type(target,lstate->task_struct_type,
			     ltstate->group_leader,LOAD_FLAG_NONE);
    if (!value) {
	vwarn("could not load tid %d's group_leader at 0x%"PRIxADDR"; BUG?!\n",
	      tthread->tid,ltstate->group_leader);
	return NULL;
    }

    if (!(leader = os_linux_load_thread_from_value(target,value))) {
	verror("could not load thread from task value at 0x%"PRIxADDR"; BUG?\n",
	       ltstate->group_leader);
	value_free(value);
	return NULL;
    }

    vdebug(5,LA_TARGET,LF_OSLINUX,
	   "new group leader loaded (%"PRIiTID",%s)\n",
	   leader->tid,leader->name);

    return leader;
}

static void __os_linux_syscalls_by_num_dtor(struct target *target,
					    char *key,void *value) {
    GHashTableIter iter;
    gpointer vp;
    struct target_os_syscall *sc;
    GHashTable *syscalls_by_num;

    syscalls_by_num = (GHashTable *)value;

    if (syscalls_by_num) {
	g_hash_table_iter_init(&iter,syscalls_by_num);
	while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	    sc = (struct target_os_syscall *)vp;

	    if (sc->bsymbol)
		bsymbol_release(sc->bsymbol);
	    free(sc);
	}

	g_hash_table_destroy(syscalls_by_num);
    }
}

static void __os_linux_syscalls_by_X_dtor(struct target *target,
					  char *key,void *value) {
    GHashTable *syscalls_by_X;

    syscalls_by_X = (GHashTable *)value;

    if (syscalls_by_X) 
	g_hash_table_destroy(syscalls_by_X);
}

int os_linux_syscall_table_load(struct target *target) {
    struct bsymbol *bs = NULL;
    struct value *v = NULL;
    char *current;
    struct target_os_syscall *sc;
    GHashTable *syscalls_by_num;
    GHashTable *syscalls_by_addr;
    GHashTable *syscalls_by_name;
    char *name;
    char *wrapped_name;
    struct target_location_ctxt *tlctxt;

    if (target_gkv_lookup(target,"os_linux_syscalls_by_num")) 
	return 0;

    /*
     * Lookup and load the value of sys_call_table.  For x86[_64], the
     * values are the addresses of the system call functions.  We look
     * up those addrs in debuginfo and fill in the tables.
     */
    bs = target_lookup_sym(target,"sys_call_table",NULL,NULL,
			   SYMBOL_TYPE_FLAG_VAR);
    if (!bs) {
	verror("could not lookup symbol sys_call_table!\n");
	return -1;
    }

    tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,bs);
    v = target_load_symbol(target,tlctxt,bs,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load sys_call_table!\n");
	target_location_ctxt_free(tlctxt);
	bsymbol_release(bs);
	bs = NULL;
	return -1;
    }
    target_location_ctxt_free(tlctxt);

    syscalls_by_num = g_hash_table_new(g_direct_hash,g_direct_equal);
    syscalls_by_addr = g_hash_table_new(g_direct_hash,g_direct_equal);
    syscalls_by_name = g_hash_table_new(g_str_hash,g_str_equal);

    /* Insert them all, but just set one with a
     * target_os_syscall_table_unload() wrapped as a gkv dtor to unload
     * them all.
     */
    target_gkv_insert(target,"os_linux_syscalls_by_num",syscalls_by_num,
		      __os_linux_syscalls_by_num_dtor);
    target_gkv_insert(target,"os_linux_syscalls_by_name",syscalls_by_name,
		      __os_linux_syscalls_by_X_dtor);
    target_gkv_insert(target,"os_linux_syscalls_by_addr",syscalls_by_addr,
		      __os_linux_syscalls_by_X_dtor);

    /*
     * Go through the "array" according to target wordsize and lookup
     * the addrs.
     */
    current = v->buf;
    while ((current - v->buf) < v->bufsiz) {
	sc = calloc(1,sizeof(*sc));
	sc->num = (current - v->buf) / target->arch->wordsize;
	memcpy(&sc->addr,current,target->arch->wordsize);

	sc->bsymbol = target_lookup_sym_addr(target,sc->addr);
	if(sc->bsymbol) {
	    name = bsymbol_get_name(sc->bsymbol);
	    if (strncmp("stub_",name,strlen("stub_")) == 0) {
		wrapped_name = malloc(strlen(name));
		sprintf(wrapped_name,"sys_%s",name + strlen("stub_"));
		sc->wrapped_bsymbol = 
		    target_lookup_sym(target,wrapped_name,
				      NULL,NULL,SYMBOL_TYPE_FLAG_FUNC);
		free(wrapped_name);
	    }
	    sc->args = symbol_get_members(bsymbol_get_symbol(sc->bsymbol),
					  SYMBOL_TYPE_FLAG_VAR_ARG);
	}

	g_hash_table_insert(syscalls_by_num,
			    (gpointer)(uintptr_t)sc->num,sc);
	if (sc->addr)
	    g_hash_table_insert(syscalls_by_addr,
				(gpointer)(uintptr_t)sc->addr,sc);
	if (sc->bsymbol && bsymbol_get_name(sc->bsymbol))
	    g_hash_table_insert(syscalls_by_name,
				(gpointer)bsymbol_get_name(sc->bsymbol),sc);

	if (sc->bsymbol && bsymbol_get_name(sc->bsymbol))
	    vdebug(9,LA_TARGET,LF_OSLINUX,"syscall '%s' num %d addr 0x%"PRIxADDR"\n",
		   bsymbol_get_name(sc->bsymbol),sc->num,sc->addr);
	else 
	    vdebug(9,LA_TARGET,LF_OSLINUX,"syscall '' num %d addr 0x%"PRIxADDR"\n",
		   sc->num,sc->addr);

	current += target->arch->wordsize;
    }

    value_free(v);
    bsymbol_release(bs);

    return 0;
}

int os_linux_syscall_table_unload(struct target *target) {
    GHashTableIter iter;
    gpointer vp;
    struct target_os_syscall *sc;
    GHashTable *syscalls_by_num;
    GHashTable *syscalls_by_addr;
    GHashTable *syscalls_by_name;

    syscalls_by_num = (GHashTable *) \
	target_gkv_lookup(target,"os_linux_syscalls_by_num");
    syscalls_by_name = (GHashTable *) \
	target_gkv_lookup(target,"os_linux_syscalls_by_name");
    syscalls_by_addr = (GHashTable *) \
	target_gkv_lookup(target,"os_linux_syscalls_by_addr");

    if (syscalls_by_name) {
	g_hash_table_destroy(syscalls_by_name);
	target_gkv_remove(target,"os_linux_syscalls_by_num");
    }
    if (syscalls_by_addr) {
	g_hash_table_destroy(syscalls_by_addr);
	target_gkv_remove(target,"os_linux_syscalls_by_addr");
    }
    if (syscalls_by_num) {
	g_hash_table_iter_init(&iter,syscalls_by_num);
	while (g_hash_table_iter_next(&iter,NULL,&vp)) {
	    sc = (struct target_os_syscall *)vp;

	    if (sc->bsymbol)
		bsymbol_release(sc->bsymbol);
	    if (sc->args)
		g_slist_free(sc->args);
	    free(sc);
	}

	g_hash_table_destroy(syscalls_by_num);
	target_gkv_remove(target,"os_linux_syscalls_by_num");
    }

    return 0;
}

GHashTable *os_linux_syscall_table_get(struct target *target) {
    return (GHashTable *)target_gkv_lookup(target,"os_linux_syscalls_by_num");
}

struct target_os_syscall *os_linux_syscall_lookup_name(struct target *target,
						       char *name) {
    GHashTable *syscalls;

    if (!(syscalls = (GHashTable *) \
	      target_gkv_lookup(target,"os_linux_syscalls_by_name"))) {
	if (target_os_syscall_table_load(target))
	    return NULL;
	else
	    syscalls = (GHashTable *) \
		target_gkv_lookup(target,"os_linux_syscalls_by_name");
    }

    return (struct target_os_syscall *)g_hash_table_lookup(syscalls,name);
}

struct target_os_syscall *os_linux_syscall_lookup_num(struct target *target,
						      int num) {
    GHashTable *syscalls;

    if (!(syscalls = (GHashTable *) \
	      target_gkv_lookup(target,"os_linux_syscalls_by_num"))) {
	if (target_os_syscall_table_load(target))
	    return NULL;
	else
	    syscalls = (GHashTable *) \
		target_gkv_lookup(target,"os_linux_syscalls_by_num");
    }

    return (struct target_os_syscall *) \
	g_hash_table_lookup(syscalls,(gpointer)(uintptr_t)num);
}

struct target_os_syscall *os_linux_syscall_lookup_addr(struct target *target,
						       ADDR addr) {
    GHashTable *syscalls;

    if (!(syscalls = (GHashTable *) \
	      target_gkv_lookup(target,"os_linux_syscalls_by_addr"))) {
	if (target_os_syscall_table_load(target))
	    return NULL;
	else
	    syscalls = (GHashTable *) \
		target_gkv_lookup(target,"os_linux_syscalls_by_addr");
    }

    return (struct target_os_syscall *) \
	g_hash_table_lookup(syscalls,(gpointer)(uintptr_t)addr);
}



struct old_linux_syscall_probe_state {
    struct bsymbol *system_call_symbol;
    ADDR system_call_base_addr;
    struct array_list *system_call_ret_idata_list;

    /*
     * We support a couple kinds of syscall probing.  Which is used is
     * up to the user.  By passing NULL to linux_syscall_probe for the
     * @name param, they install probes on the syscall entry/exit path.
     * By passing a specific name to that function, they place a probe
     * on the entry of that specific syscall, as well as on the return
     * path.
     *
     * Hm, it is easier to probe specific syscalls by just probing them
     * internally (i.e., entry instr, and any RET/IRET instrs).  Also a
     * faster option than probing on the generic syscall ret path.  I
     * think we can have three options for now:
     *
     * 1) probe a single syscall only
     * 2) probe a single syscall, but probe the generic return path
     * 3) probe the generic entry/exit paths
     */
    struct probe *syscall_entry_probe;
    struct probe *syscall_ret_probe;

    /* Currently in-flight syscall per-thread. */
    GHashTable *thread_syscall_state_current;
    /* Last completed syscall per-thread. */
    GHashTable *thread_syscall_state_last;
};

static int _os_linux_syscall_probe_init(struct target *target) {
    struct bsymbol *system_call_bsymbol = NULL;
    ADDR system_call_base_addr = 0;
    ADDR end = 0;
    struct array_list *system_call_ret_idata_list = NULL;
    int caller_should_free = 0;
    ADDR *ap;
    unsigned char *cbuf = NULL;
    struct target_location_ctxt *tlctxt = NULL;

    /* Check cache to see if we've loaded symbol and code info. */
    if (target_gkv_lookup(target,"os_linux_system_call_bsymbol"))
	return 0;

    /*
     * Do some setup for probing syscall returns.  We disasm
     * system_call, placing probes on IRET and SYSRET; so we need the
     * offsets of any of those instructions within system_call.
     */

    system_call_bsymbol = target_lookup_sym(target,"system_call",NULL,NULL,
					    SYMBOL_TYPE_FLAG_FUNC);
    if (!system_call_bsymbol) {
	verror("could not lookup system_call;"
	       " smart syscall probing will fail!\n");
	goto errout;
    }
    tlctxt = target_location_ctxt_create_from_bsymbol(target,TID_GLOBAL,
						      system_call_bsymbol);
    if (target_lsymbol_resolve_bounds(target,tlctxt,
				      system_call_bsymbol->lsymbol,0,
				      &system_call_base_addr,&end,NULL,
				      NULL,NULL)) {
	verror("could not resolve base addr of system_call;"
	       " smart syscall probing will fail!\n");
	goto errout;
    }
    target_location_ctxt_free(tlctxt);
    tlctxt = NULL;
    if (!(cbuf = target_load_code(target,system_call_base_addr,
				  end - system_call_base_addr,
				  0,0,&caller_should_free))) {
	verror("could not load code of system_call;"
	       " smart syscall probing will fail!\n");
	goto errout;
    }
    if (disasm_get_control_flow_offsets(target,
					INST_CF_IRET | INST_CF_SYSRET,
					cbuf,end - system_call_base_addr,
					&system_call_ret_idata_list,
					system_call_base_addr,1)) {
	verror("could not disassemble system_call in range"
	       " 0x%"PRIxADDR"-0x%"PRIxADDR";"
	       " smart syscall probing will fail!\n",
	       system_call_base_addr,end);
	goto errout;
    }
    if (!system_call_ret_idata_list 
	|| array_list_len(system_call_ret_idata_list) <= 0) {
	verror("no IRETs or SYSRETs in system_call;"
	       " smart syscall probing will fail!\n");
	goto errout;
    }

    /* Cache. */
    target_gkv_insert(target,"os_linux_system_call_bsymbol",system_call_bsymbol,
		      target_gkv_dtor_bsymbol);
    ap = calloc(1,sizeof(*ap));
    memcpy(ap,&system_call_base_addr,sizeof(*ap));
    target_gkv_insert(target,"os_linux_system_call_base_addr",ap,
		      target_gkv_dtor_free);
    target_gkv_insert(target,"os_linux_system_call_ret_idata_list",
		      system_call_ret_idata_list,
		      target_gkv_dtor_alist_deep_free);

    return 0;

 errout:
    if (tlctxt)
	target_location_ctxt_free(tlctxt);
    if (system_call_ret_idata_list)
	array_list_deep_free(system_call_ret_idata_list);
    if (caller_should_free)
	free(cbuf);
    if (system_call_bsymbol)
	bsymbol_release(system_call_bsymbol);

    return -1;
}

#define SYSCALL_GLOBAL_ENTRY_PROBE "os_linux_syscall_entry_probe"
#define SYSCALL_GLOBAL_RET_PROBE "os_linux_syscall_ret_probe"

static int __global_entry_uncache(struct probe *probe) {
    /* Steal it cause it is getting autofreed if this is getting called. */
    target_gkv_steal(probe->target,SYSCALL_GLOBAL_ENTRY_PROBE);
    return 0;
}
static struct probe_ops __global_entry_probe_ops = {
    .fini = __global_entry_uncache,
};

static int __syscall_entry_uncache(struct probe *probe) {
    /* Steal it cause it is getting autofreed if this is getting called. */
    target_gkv_steal(probe->target,probe->name);
    return 0;
}
static struct probe_ops __syscall_entry_probe_ops = {
    .fini = __syscall_entry_uncache,
};

static int __global_ret_uncache(struct probe *probe) {
    /* Steal it cause it is getting autofreed if this is getting called. */
    target_gkv_steal(probe->target,SYSCALL_GLOBAL_RET_PROBE);
    return 0;
}
static struct probe_ops __global_ret_probe_ops = {
    .fini = __global_ret_uncache,
};

/* "overload" probe_do_sink_pre_handlers . */
static result_t __syscall_entry_handler(struct probe *probe,tid_t tid,
					void *handler_data,
					struct probe *trigger,
					struct probe *base) {
    struct target *target;
    struct target_os_syscall *syscall;
    struct target_os_syscall_state *scs;
    GSList *args;
    struct array_list *argvals;
    GSList *gsltmp;
    struct symbol *argsym;
    struct symbol *symbol;
    struct value *v;
    char *name;
    struct target_location_ctxt *tlctxt;

    target = probe->target;

    syscall = (struct target_os_syscall *)handler_data;

    scs = target_os_syscall_record_entry(target,tid,syscall);
    if (!scs) {
	verror("could not record syscall entry in tid %"PRIiTID"!\n",tid);
	return RESULT_SUCCESS;
    }

    /*
     * The only values we try to autoderef are char * bufs; we need
     * system-specific info to know if/when it's safe to deref the
     * others.  We don't know generically whether a param is in/out.
     */
    argvals = array_list_create(6);
    symbol = bsymbol_get_symbol(probe->bsymbol);
    args = symbol_get_members(symbol,SYMBOL_TYPE_FLAG_VAR_ARG);
    if (args) {
	/*
	 * Load each argument if it hasn't already been loaded.
	 */
	tlctxt = target_location_ctxt_create_from_bsymbol(target,
							  probe->thread->tid,
							  probe->bsymbol);
	v_g_slist_foreach(args,gsltmp,argsym) {
	    name = symbol_get_name(argsym);
	    v = target_load_symbol_member(probe->target,tlctxt,probe->bsymbol,
					  name,NULL,LOAD_FLAG_AUTO_DEREF);
	    array_list_append(argvals,v);
	}
	target_location_ctxt_free(tlctxt);
    }

    target_os_syscall_record_argv(target,tid,NULL,argvals);

    /* There, now call the probe's sink pre_handlers! */
    return probe_do_sink_pre_handlers(probe,tid,handler_data,trigger,base);
}

/* "overload" probe_do_sink_pre_handlers . */
static result_t __global_entry_handler(struct probe *probe,tid_t tid,
				       void *handler_data,
				       struct probe *trigger,
				       struct probe *base) {
    struct target *target;
    struct target_os_syscall *syscall;
    struct target_os_syscall_state *scs;
    REGVAL scnum;
    struct array_list *regvals;
    struct array_list *argvals;
    GSList *gsltmp;
    struct symbol *argsym;
    struct symbol *datatype;
    int j;
    /*
     * On x86_64 Linux, syscall args are in %rdi, %rsi, %rdx, %r10, %r8, %r9.
     */
    static REG regs_x86_64[6] = { 5,4,1,10,8,9 };
    /*
     * On i386 Linux, syscall args are in %ebx, %ecx, %edx, %esi, %edi, %ebp.
     */
    static REG regs_i386[6] = { 3,1,2,6,7,5 };
    static REG *regs;
    struct value *v;

    target = probe->target;

    scnum = target_read_creg(target,tid,CREG_RET);
    if (!(syscall = target_os_syscall_lookup_num(target,(int)scnum))) {
	vwarn("could not find syscall for eax %d in tid %"PRIiTID"; ignoring!\n",
	      (int)scnum,tid);
	return RESULT_SUCCESS;
    }

    scs = target_os_syscall_record_entry(target,tid,syscall);
    if (!scs) {
	verror("could not record syscall entry in tid %"PRIiTID"!\n",tid);
	return RESULT_SUCCESS;
    }

    /*
     * Read args by type, according to the i386/x86_64 calling
     * convention.  Never more than 6 args; just read all the regs.
     */
    if (target->arch->wordsize == 8) 
	regs = regs_x86_64;
    else 
	regs = regs_i386;

    regvals = array_list_create(6);
    for (j = 0; j < 6; ++j) {
	array_list_append(regvals,
			  (void *)(uintptr_t)target_read_reg(target,tid,regs[j]));
    }

    /*
     * The only values we try to autoderef are char * bufs; we need
     * system-specific info to know if/when it's safe to deref the
     * others.  We don't know generically whether a param is in/out.
     */
    if (syscall->args) {
	argvals = array_list_create(6);
	v_g_slist_foreach(syscall->args,gsltmp,argsym) {
	    datatype = symbol_get_datatype(argsym);
	    if (!datatype) {
		array_list_append(argvals,NULL);
		continue;
	    }
	    else if (j < 6) {
		v = target_load_type_regval(target,datatype,tid,regs[j],
					    (REGVAL)array_list_item(regvals,j),
					    LOAD_FLAG_AUTO_STRING);
		array_list_append(argvals,v);
	    }
	    else {
		array_list_append(argvals,NULL);
		continue;
	    }
	}
    }
    else 
	argvals = NULL;

    target_os_syscall_record_argv(target,tid,regvals,argvals);

    /* There, now call the probe's sink pre_handlers! */
    return probe_do_sink_pre_handlers(probe,tid,handler_data,trigger,base);
}

/*
 * Call the sink probes' post_handlers -- but we do it BEFORE the return
 * to userspace -- i.e., before the IRET/SYSRET.
 */
static result_t __syscall_ret_handler(struct probe *probe,tid_t tid,
				      void *handler_data,
				      struct probe *trigger,
				      struct probe *base) {
    struct target *target;
    struct target_os_syscall_state *scs;

    target = probe->target;

    scs = target_os_syscall_probe_last(target,tid);
    if (!scs) {
	vwarnopt(5,LA_TARGET,LF_OS,
		 "could not find a current syscall tid %"PRIiTID"; ignoring!\n",
		 tid);
	return RESULT_SUCCESS;
    }
    else if (scs->returned) {
	vwarnopt(5,LA_TARGET,LF_OS,
		 "current syscall for tid %"PRIiTID" already returned; ignoring!\n",
		 tid);
	return RESULT_SUCCESS;
    }

    target_os_syscall_record_return(target,tid,
				    target_read_creg(target,tid,CREG_RET));

    /* There, now call the probe's sink POST_handlers! */
    return probe_do_sink_post_handlers(probe,tid,handler_data,trigger,base);
}

static struct probe *
os_linux_syscall_probe_init_syscall_entry(struct target *target,
					  struct target_os_syscall *syscall) {
    struct probe *probe;
    char namebuf[128];
    struct bsymbol *bs;

    if (syscall->isstub && syscall->wrapped_bsymbol) 
	bs = syscall->wrapped_bsymbol;
    else
	bs = syscall->bsymbol;

    snprintf(namebuf,sizeof(namebuf),"os_linux_%s_probe",
	     bsymbol_get_name(bs));

    if ((probe = (struct probe *)target_gkv_lookup(target,namebuf)))
	return probe;

    if (_os_linux_syscall_probe_init(target))
	return NULL;

    probe = probe_create(target,TID_GLOBAL,&__syscall_entry_probe_ops,
			 namebuf,__syscall_entry_handler,NULL,syscall,1,1);

    if (!probe_register_symbol(probe,bs,PROBEPOINT_SW,0,0)) {
	verror("could not register %s!\n",namebuf);
	probe_free(probe,0);
	return NULL;
    }

    /* Cache it. */
    target_gkv_insert(target,namebuf,probe,target_gkv_dtor_probe);

    return probe;
}

static struct probe *
os_linux_syscall_probe_init_global_entry(struct target *target) {
    struct bsymbol *system_call_bsymbol;
    ADDR *system_call_base_addr = NULL;
    struct probe *probe;

    if ((probe = (struct probe *) \
	     target_gkv_lookup(target,SYSCALL_GLOBAL_ENTRY_PROBE)))
	return probe;

    if (_os_linux_syscall_probe_init(target))
	return NULL;

    system_call_base_addr = (ADDR *) \
	target_gkv_lookup(target,"os_linux_system_call_base_addr");
    system_call_bsymbol = (struct bsymbol *) \
	target_gkv_lookup(target,"os_linux_system_call_bsymbol");

    /*
     * Place probes on all entries.  For some Linux kernels, this might
     * be system_call, AND ia32_sysenter_target (for i386).
     *
     * XXX: do ia32_sysenter_target eventually!
     */

    probe = probe_create(target,TID_GLOBAL,&__global_entry_probe_ops,
			 "system_call",
			 __global_entry_handler,NULL,NULL,1,1);

    if (!probe_register_addr(probe,*system_call_base_addr,
			     PROBEPOINT_BREAK,PROBEPOINT_SW,0,0,
			     system_call_bsymbol)) {
	verror("could not register system_call entry probe at 0x%"PRIxADDR"!\n",
	       *system_call_base_addr);
	probe_free(probe,0);
	return NULL;
    }

    /* Cache it. */
    target_gkv_insert(target,SYSCALL_GLOBAL_ENTRY_PROBE,probe,
		      target_gkv_dtor_probe);

    return probe;
}

static struct probe *
os_linux_syscall_probe_init_global_ret(struct target *target) {
    ADDR *system_call_base_addr;
    struct array_list *system_call_ret_idata_list;
    struct probe *rprobe;
    struct probe *probe;
    int name_len;
    char *name;
    struct cf_inst_data *idata;
    int i;

    if ((probe = (struct probe *) \
	     target_gkv_lookup(target,SYSCALL_GLOBAL_RET_PROBE)))
	return probe;

    if (_os_linux_syscall_probe_init(target))
	return NULL;

    if (!(system_call_ret_idata_list = (struct array_list *) \
	      target_gkv_lookup(target,"os_linux_system_call_ret_idata_list"))) {
	verror("BUG: could not find system_call RET info!\n");
	return NULL;
    }

    system_call_base_addr = (ADDR *) \
	target_gkv_lookup(target,"os_linux_system_call_base_addr");

    /*
     * Place probes on all IRET/SYSRET/SYSEXIT in system_call, and
     * register our probe to listen to them.
     */

    probe = probe_create(target,TID_GLOBAL,&__global_ret_probe_ops,
			 "system_call_ret",
			 NULL,__syscall_ret_handler,NULL,1,1);

    /*
     * Create probes one by one on the IRET/SYSRETs and register
     * the metaprobe on them.
     */
    name_len = sizeof("system_call_SYSRET_+") + 12;
    name = malloc(name_len);

    array_list_foreach(system_call_ret_idata_list,i,idata) {
	snprintf(name,name_len,
		 "system_call_%s_+0x%"PRIxOFFSET,
		 (idata->type == INST_SYSRET) ? "SYSRET" : "IRET",
		 idata->offset);

	/* We call any sink probes' POST handlers from our pre_handler. */
	rprobe = probe_create(target,TID_GLOBAL,NULL,name,
			      probe_do_sink_post_handlers,NULL,NULL,1,1);

	if (!probe_register_addr(rprobe,*system_call_base_addr + idata->offset,
				 PROBEPOINT_BREAK,PROBEPOINT_SW,0,0,NULL)) {
	    verror("could not register probe %s at 0x%"PRIxADDR"!\n",
		   rprobe->name,*system_call_base_addr + idata->offset);
	    probe_free(rprobe,1);
	    rprobe = NULL;
	    goto errout;
	}

	if (!probe_register_source(probe,rprobe)) {
	    verror("could not register probe %s on source %s!\n",
		   probe->name,rprobe->name);
	    probe_free(rprobe,1);
	    rprobe = NULL;
	    goto errout;
	}
    }

    /* Cache it. */
    target_gkv_insert(target,SYSCALL_GLOBAL_RET_PROBE,probe,
		      target_gkv_dtor_probe);
    free(name);
    return probe;

 errout:
    probe_free(probe,1);
    free(name);
    return NULL;
}

/*
 * Syscall probe type.
 *
 * These per-syscall probes are exposed to the probe value API.
 *
 * The global probe is not, for now, because it doesn't have a fixed
 * bsymbol backing it; it changes.  Also, since we're not technically
 * *in* the bsymbol (syscall) when the pre/post handlers are called
 * (we're in the global sysenter/sysret path), faking it could result in
 * some oddities!
 */
static const char *_os_linux_syscall_probe_gettype(struct probe *probe) {
    return "os_linux_syscall_probe";
}

struct probe_ops os_linux_syscall_ret_probe_ops = {
    .gettype = _os_linux_syscall_probe_gettype,

    .summarize = target_os_syscall_probe_summarize,
    .summarize_tid = target_os_syscall_probe_summarize_tid,

    .get_value_table = probe_value_get_table_function_ee,
    .get_raw_value_table = probe_value_get_raw_table_function_ee,
    .get_last_value_table = probe_value_get_last_table_function_ee,
    .get_last_raw_value_table = probe_value_get_last_raw_table_function_ee,
    .get_value = probe_value_get_function_ee,
    .get_raw_value = probe_value_get_raw_function_ee,
    .get_last_value = probe_value_get_last_function_ee,
    .get_last_raw_value = probe_value_get_last_raw_function_ee,
    .values_notify_phase = probe_value_notify_phase_function_ee,
    .values_free = probe_values_free_stacked,
};

struct probe *os_linux_syscall_probe(struct target *target,tid_t tid,
				     struct target_os_syscall *syscall,
				     probe_handler_t pre_handler,
				     probe_handler_t post_handler,
				     void *handler_data) {
    struct probe *probe, *eprobe, *rprobe;
    char namebuf[128];

    snprintf(namebuf,sizeof(namebuf),"os_linux_syscall_probe_%s",
	     bsymbol_get_name(syscall->bsymbol));

    probe = probe_create(target,tid,&os_linux_syscall_ret_probe_ops,
			 namebuf,pre_handler,post_handler,handler_data,0,1);

    eprobe = os_linux_syscall_probe_init_syscall_entry(target,syscall);
    if (!eprobe) {
	verror("could not setup syscall entry probe!\n");
	probe_free(probe,1);
	return NULL;
    }
    probe_register_source(probe,eprobe);
    rprobe = os_linux_syscall_probe_init_global_ret(target);
    if (!rprobe) {
	verror("could not setup global system_call ret probes!\n");
	probe_free(probe,1);
	return NULL;
    }
    probe_register_source(probe,rprobe);

    return probe;
}

/*
 * Global syscall probe type.
 */
static const char *_os_linux_global_syscall_probe_gettype(struct probe *probe) {
    return "os_linux_global_syscall_probe";
}

struct probe_ops os_linux_global_syscall_ret_probe_ops = {
    .gettype = _os_linux_global_syscall_probe_gettype,

    .summarize = target_os_syscall_probe_summarize,
    .summarize_tid = target_os_syscall_probe_summarize_tid,
};

struct probe *os_linux_syscall_probe_all(struct target *target,tid_t tid,
					 probe_handler_t pre_handler,
					 probe_handler_t post_handler,
					 void *handler_data) {
    struct probe *probe, *eprobe, *rprobe;

    probe = probe_create(target,tid,&os_linux_global_syscall_ret_probe_ops,
			 "os_linux_global_syscall_probe",
			 pre_handler,post_handler,handler_data,0,1);

    eprobe = os_linux_syscall_probe_init_global_entry(target);
    if (!eprobe) {
	verror("could not setup global system_call entry probes!\n");
	probe_free(probe,1);
	return NULL;
    }
    probe_register_source(probe,eprobe);
    rprobe = os_linux_syscall_probe_init_global_ret(target);
    if (!rprobe) {
	verror("could not setup global system_call ret probes!\n");
	probe_free(probe,1);
	return NULL;
    }
    probe_register_source(probe,rprobe);

    return probe;
}

struct target_os_ops os_linux_generic_os_ops = {
    /* All this work is done in attach and fini of the personality_ops. */
    .init = NULL,
    .fini = NULL,

    .os_type = os_linux_type,
    .os_version = os_linux_version,
    .os_version_string = os_linux_version_string,
    .os_version_cmp = os_linux_version_cmp,

    .thread_get_pgd_phys = os_linux_thread_get_pgd_phys,
    .thread_is_user = os_linux_thread_is_user,
    .thread_get_leader = os_linux_thread_get_leader,

    .syscall_table_load = os_linux_syscall_table_load,
    .syscall_table_unload = os_linux_syscall_table_unload,
    .syscall_table_get = os_linux_syscall_table_get,
    .syscall_lookup_name = os_linux_syscall_lookup_name,
    .syscall_lookup_num = os_linux_syscall_lookup_num,
    .syscall_lookup_addr = os_linux_syscall_lookup_addr,
    .syscall_probe = os_linux_syscall_probe,
    .syscall_probe_all = os_linux_syscall_probe_all,
};


num_t os_linux_get_preempt_count(struct target *target) {
    struct target_thread *tthread;
    struct os_linux_thread_state *ltstate;

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

    ltstate = (struct os_linux_thread_state *)tthread->personality_state;
    if (!ltstate) {
	verror("no personality info for thread %d!\n",tthread->tid);
	errno = EINVAL;
	return 0;
    }

    return ltstate->thread_info_preempt_count;
}

/*
 * For i386/x86:
 *
 * The bottom of each kernel stack has the thread_info struct; the first
 * pointer in the thread info struct is to the task_struct associated
 * with the thread_info (i.e., thread_info->task).  So, if we want
 * thread_info, just load the value at current_thread_ptr; if we want
 * the current task_struct, load the first pointer at
 * current_thread_ptr, and deref it to load the current task_struct's
 * value.
 *
 * For x86_64:
 *
 * kernel_stacks are always per_cpu unsigned long "pointers", even if
 * there is only one CPU.  The value of
 * lstate->kernel_stack_percpu_offset is an offset from the kernel's
 * %gs.  So we have to grab the saved %gs (which Xen places in
 * target->global_thread->personality_state->context.gs_base_kernel), then apply the
 * offset, then we have our pointer.
 */
ADDR os_linux_current_thread_ptr(struct target *target,REGVAL kernel_esp) {
    struct os_linux_state *lstate =
	(struct os_linux_state *)target->personality_state;
    REGVAL sp;
    ADDR kernel_stack_addr;
    ADDR gs_base = 0;
    ADDR ipval;

    errno = 0;

    if (target->arch->wordsize == 4) {
	if (kernel_esp) 
	    sp = kernel_esp;
	else {
	    errno = 0;
	    sp = target_read_reg_ctxt(target,TID_GLOBAL,THREAD_CTXT_KERNEL,
				      target->spregno);
	    if (errno) {
		verror("could not read ESP!\n");
		return 0;
	    }
	}

	vdebug(8,LA_TARGET,LF_OSLINUX,"current->thread_info at 0x%"PRIxADDR"\n",
	       sp & ~(THREAD_SIZE - 1));

	return (sp & ~(THREAD_SIZE - 1));
    }
    else {
#ifndef __x86_64__
	/*
	 * This is impossible; a 64-bit guest on a 32-bit host.  We just
	 * ifdef the 64-bit stuff away in case the host is 32-bit.
	 */
#else
	ipval = target_read_reg(target,TID_GLOBAL,target->ipregno);
	sp = target_read_reg(target,TID_GLOBAL,target->spregno);
	gs_base = target_read_reg(target,TID_GLOBAL,REG_X86_64_GS_BASE_KERNEL);

	if (!gs_base) {
	    gs_base = target_read_reg(target,TID_GLOBAL,REG_X86_64_GS_BASE_USER);
	    if (gs_base) {
		if (!(ipval < lstate->kernel_start_addr
		      || sp < lstate->kernel_start_addr))
		    gs_base = 0;
	    }
	}

	if (!gs_base) {
	    vwarn("invalid gs_base_kernel=0x%"PRIxADDR"/gs_base_user=0x%"PRIxADDR
		  " for rip=0x%"PRIxADDR"/rsp=0x%"PRIxADDR"; will not be able"
		  " to load current thread info!\n",
		  target_read_reg(target,TID_GLOBAL,REG_X86_64_GS_BASE_KERNEL),
		  target_read_reg(target,TID_GLOBAL,REG_X86_64_GS_BASE_USER),
		  ipval,sp);
	}

	if (gs_base == 0) {
	    if (ipval >= lstate->kernel_start_addr) {
		kernel_stack_addr = sp & ~(THREAD_SIZE - 1);

		vdebug(8,LA_TARGET,LF_OSLINUX,
		       "current->thread_info at 0x%"PRIxADDR"\n",
		       kernel_stack_addr);

		return kernel_stack_addr;
	    }
	    else {
		verror("%%gs is 0x0; VM not in kernel (ip 0x%"PRIxADDR");"
		       " cannot infer current thread!\n",
		       ipval);
		errno = EINVAL;
		return 0;
	    }
	}
	else if (!target_read_addr(target,
				   gs_base + lstate->kernel_stack_percpu_offset,
				   target->arch->wordsize,
				   (unsigned char *)&kernel_stack_addr)) {
	    verror("could not read %%gs:kernel_stack"
		   " (0x%"PRIxADDR":%"PRIiOFFSET"); cannot continue!\n",
		   (ADDR)gs_base,lstate->kernel_stack_percpu_offset);
	    if (!errno)
		errno = EFAULT;
	    return 0;
	}

	vdebug(8,LA_TARGET,LF_OSLINUX,"current->thread_info at 0x%"PRIxADDR"\n",
	       kernel_stack_addr + KERNEL_STACK_OFFSET - THREAD_SIZE);

	/* XXX: somehow errno is getting set incorrectly on this path. */
	errno = 0;

	return kernel_stack_addr + KERNEL_STACK_OFFSET - THREAD_SIZE;
#endif
    }
}

struct symbol *os_linux_get_task_struct_type(struct target *target) {
    struct os_linux_state *lstate;

    lstate = (struct os_linux_state *)target->personality_state;
    if (!lstate || !lstate->task_struct_type) {
	verror("target does not seem to be loaded!\n");
	return NULL;
    }

    RHOLD(lstate->task_struct_type,lstate->task_struct_type);

    return lstate->task_struct_type;
}

struct symbol *os_linux_get_task_struct_type_ptr(struct target *target) {
    struct os_linux_state *lstate;

    lstate = (struct os_linux_state *)target->personality_state;
    if (!lstate || !lstate->task_struct_type_ptr) {
	verror("target does not seem to be loaded!\n");
	return NULL;
    }

    RHOLD(lstate->task_struct_type_ptr,lstate->task_struct_type_ptr);

    return lstate->task_struct_type_ptr;
}

/*
struct symbol *os_linux_get_thread_info_type(struct target *target) {
    struct os_linux_state *lstate;

    lstate = (struct os_linux_state *)target->personality_state;
    if (!lstate || !lstate->thread_info_type) {
	verror("target does not seem to be loaded!\n");
	return NULL;
    }

    RHOLD(lstate->thread_info_type,lstate->thread_info_type);

    return lstate->thread_info_type;
}
*/

/*
struct value *os_linux_load_current_task_as_type(struct target *target,
					      struct symbol *datatype,
					      REGVAL kernel_esp) {
    struct value *value;
    ADDR tptr;

    errno = 0;
    tptr = os_linux_current_thread_ptr(target,kernel_esp);
    if (errno)
	return NULL;

    value = target_load_type(target,datatype,tptr,LOAD_FLAG_AUTO_DEREF);

    return value;
}

struct value *os_linux_load_current_task(struct target *target,
				      REGVAL kernel_esp) {
    struct value *value;
    ADDR itptr;
    struct symbol *itptr_type;

    itptr_type = os_linux_get_task_struct_type_ptr(target);
    if (!itptr_type) {
	verror("could not find type for struct task_struct!\n");
	return NULL;
    }

    errno = 0;
    itptr = os_linux_current_thread_ptr(target,kernel_esp);
    if (errno)
	return NULL;

    value = target_load_type(target,itptr_type,itptr,
			     LOAD_FLAG_AUTO_DEREF);

    symbol_release(itptr_type);

    return value;
}
*/

struct value *os_linux_load_current_thread_as_type(struct target *target,
						struct symbol *datatype,
						REGVAL kernel_esp) {
    struct value *value;
    ADDR tptr;

    errno = 0;
    tptr = os_linux_current_thread_ptr(target,kernel_esp);
    if (errno) {
	verror("could not get current_thread_ptr!\n");
	return NULL;
    }

    value = target_load_type(target,datatype,tptr,LOAD_FLAG_NONE);

    return value;
}

int os_linux_get_task_pid(struct target *target,struct value *task) {
    struct value *value;
    int pid;
    struct target_location_ctxt *tlctxt = target_global_tlctxt(target);

    if (!task)
	return -1;

    value = target_load_value_member(target,tlctxt,
				     task,"pid",NULL,LOAD_FLAG_NONE);
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
    struct target_location_ctxt *tlctxt = target_global_tlctxt(target);

    mv = target_load_value_member(target,tlctxt,value,"pid",NULL,
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

struct value *os_linux_get_task(struct target *target,tid_t tid) {
    struct os_linux_state *lstate =
	(struct os_linux_state *)target->personality_state;
    struct match_pid_data mpd;

    mpd.tid = tid;
    mpd.match = NULL;
    os_linux_list_for_each_struct(target,lstate->init_task,"tasks",0,
				  match_pid,&mpd);

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
char *os_linux_d_path(struct target *target,
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
    uint32_t namelen;
    ADDR nameaddr;
    char *namebuf;
    struct value *smnamevalue;
    struct target_location_ctxt *tlctxt = target_global_tlctxt(target);

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
    VLV(target,tlctxt,dentry,"d_parent",LOAD_FLAG_NONE,
	&parent_addr,NULL,err_vmiload);
    VLV(target,tlctxt,dentry,"d_flags",LOAD_FLAG_NONE,
	&dentry_flags,NULL,err_vmiload);
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
	VLV(target,tlctxt,vfsmnt,"mnt_root",LOAD_FLAG_NONE,
	    &mnt_root_addr,NULL,err_vmiload);
	if (dentry_addr == mnt_root_addr || dentry_addr == parent_addr) {
	    vfsmnt_mnt_parent = NULL;
	    VL(target,tlctxt,vfsmnt,"mnt_parent",
	       LOAD_FLAG_AUTO_DEREF,&vfsmnt_mnt_parent,err_vmiload);
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
	    VL(target,tlctxt,vfsmnt,"mnt_mountpoint",
	       LOAD_FLAG_AUTO_DEREF,&dentry,err_vmiload);
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
	VLV(target,tlctxt,dentry,"d_name.len",LOAD_FLAG_NONE,
	    &namelen,NULL,err_vmiload);

	/*
	 * Newer linux keeps a "small dentry name" cache inside the
	 * dentry itself; so, if namelen == 0, check dentry.d_iname
	 * instead of dentry.d_name.name .
	 */
	smnamevalue = target_load_value_member(target,tlctxt,
					       dentry,"d_iname",
					       NULL,LOAD_FLAG_NONE);

	VLV(target,tlctxt,dentry,"d_name.name",LOAD_FLAG_NONE,
	    &nameaddr,NULL,err_vmiload);

	if (!nameaddr || (smnamevalue && nameaddr == value_addr(smnamevalue))) {
	    if (!smnamevalue) {
		verror("dentry.d_name.name invalid!!\n");
		goto err_vmiload;
	    }

	    namelen = strnlen(smnamevalue->buf,smnamevalue->bufsiz);

	    buflen -= namelen + 1;
	    if (buflen < 0)
		goto err_toolong;
	    end -= namelen;

	    memcpy(end,smnamevalue->buf,namelen);
	    value_free(smnamevalue);
	    smnamevalue = NULL;
	    namebuf = NULL;
	    *--end = '/';
	    retval = end;
	}
	else if (namelen > 0) {
	    buflen -= namelen + 1;
	    if (buflen < 0)
		goto err_toolong;
	    end -= namelen;

	    namebuf = NULL;
	    VLA(target,nameaddr,LOAD_FLAG_NONE,&namebuf,namelen,NULL,err_vmiload);
	    memcpy(end,namebuf,namelen);
	    free(namebuf);
	    namebuf = NULL;
	    *--end = '/';
	    retval = end;
	}
	else {
	    verror("dentry.d_name.len (%"PRIu32") was invalid!\n",namelen);
	    goto err_vmiload;
	}

	ph = dentry;
	VL(target,tlctxt,ph,"d_parent",LOAD_FLAG_AUTO_DEREF,
	   &dentry,err_vmiload);
	if (ph != orig_dentry) {
	    value_free(ph);
	}
	dentry_addr = v_addr(dentry);
    }

    goto out;

 global_root:
    namelen = 0;
    VLV(target,tlctxt,dentry,"d_name.len",LOAD_FLAG_NONE,
	&namelen,NULL,err_vmiload);

    smnamevalue = target_load_value_member(target,tlctxt,
					   dentry,"d_iname",NULL,LOAD_FLAG_NONE);

    if (!nameaddr || (smnamevalue && nameaddr == value_addr(smnamevalue))) {
	if (!smnamevalue) {
	    verror("global_root dentry.d_name.name invalid!!\n");
	    goto err_vmiload;
	}

	namelen = strnlen(smnamevalue->buf,smnamevalue->bufsiz);

	buflen -= namelen;
	if (buflen < 0)
	    goto err_toolong;
	retval -= namelen - 1;	/* hit the slash */

	memcpy(retval,smnamevalue->buf,namelen);
	value_free(smnamevalue);
	smnamevalue = NULL;
	namebuf = NULL;
    }
    else if (namelen > 0) {
	buflen -= namelen;
	if (buflen < 0)
	    goto err_toolong;
	retval -= namelen - 1;	/* hit the slash */
	namebuf = NULL;
	VLA(target,nameaddr,LOAD_FLAG_NONE,&namebuf,namelen,NULL,err_vmiload);
	memcpy(retval,namebuf,namelen);
	free(namebuf);
	namebuf = NULL;
    }
    else {
	verror("dentry.d_name.len (%"PRIu32") was invalid!\n",namelen);
	goto err_vmiload;
    }

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

char *os_linux_file_get_path(struct target *target,struct value *task,
			  struct value *file,char *ibuf,int buflen) {
    struct value *dentry = NULL;
    struct value *vfsmnt = NULL;
    struct value *root_dentry = NULL;
    struct value *root_vfsmnt = NULL;
    char buf[PATH_MAX];
    char *bufptr;
    int len;
    char *retval;
    struct lsymbol *tmpls;
    struct target_location_ctxt *tlctxt = target_global_tlctxt(target);

    /*
     * See if we're into the newer struct file::f_path stuff, or if we
     * still have the older struct file::{f_dentry,f_vfsmnt}.
     */
    if (!(tmpls = symbol_lookup_sym(file->type,"f_path",NULL))) {
	VL(target,tlctxt,file,"f_vfsmnt",LOAD_FLAG_AUTO_DEREF,
	   &vfsmnt,err_vmiload);
	VL(target,tlctxt,file,"f_dentry",LOAD_FLAG_AUTO_DEREF,
	   &dentry,err_vmiload);
	VL(target,tlctxt,task,"fs.rootmnt",LOAD_FLAG_AUTO_DEREF,
	   &root_vfsmnt,err_vmiload);
	VL(target,tlctxt,task,"fs.root",LOAD_FLAG_AUTO_DEREF,
	   &root_dentry,err_vmiload);
    }
    else {
	lsymbol_release(tmpls);
	VL(target,tlctxt,file,"f_path.mnt",LOAD_FLAG_AUTO_DEREF,
	   &vfsmnt,err_vmiload);
	VL(target,tlctxt,file,"f_path.dentry",LOAD_FLAG_AUTO_DEREF,
	   &dentry,err_vmiload);
	VL(target,tlctxt,task,"fs.root.mnt",LOAD_FLAG_AUTO_DEREF,
	   &root_vfsmnt,err_vmiload);
	VL(target,tlctxt,task,"fs.root.dentry",LOAD_FLAG_AUTO_DEREF,
	   &root_dentry,err_vmiload);
    }

    bufptr = os_linux_d_path(target,dentry,vfsmnt,root_dentry,root_vfsmnt,
			  buf,PATH_MAX);
    if (!bufptr) 
	goto err;

    if (!ibuf) {
	ibuf = malloc(PATH_MAX);
	buflen = PATH_MAX;
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
int os_linux_list_for_each_struct(struct target *t,struct bsymbol *bsymbol,
				  char *list_head_member_name,int nofree,
				  os_linux_list_iterator_t iterator,void *data) {
    struct symbol *symbol;
    struct symbol *type;
    OFFSET list_head_member_offset;
    ADDR head;
    ADDR next_head;
    ADDR current_struct_addr;
    struct value *value = NULL;
    int i = 0;
    int retval = -1;
    int rc;
    struct target_location_ctxt *tlctxt = target_global_tlctxt(t);

    symbol = bsymbol_get_symbol(bsymbol);
    type = symbol_get_datatype(symbol);
    if (!type) {
	verror("no type for bsymbol %s!\n",bsymbol_get_name(bsymbol));
	goto out;
    }

    errno = 0;
    list_head_member_offset = 
	symbol_offsetof(type,list_head_member_name,NULL);
    if (errno) {
	verror("could not get offset for %s in symbol %s!\n",
	       list_head_member_name,symbol_get_name(type));
	ERRORDUMPSYMBOL_NL(symbol);
	goto out;
    }

    /* We just blindly use TID_GLOBAL because init_task is the symbol
     * they are supposed to pass, and resolving that is not going to
     * depend on any registers, so it doesn't matter which thread we
     * use.
     */
    current_struct_addr = head = \
	target_addressof_symbol(t,tlctxt,bsymbol,LOAD_FLAG_NONE,
				NULL);
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
int os_linux_list_for_each_entry(struct target *t,struct bsymbol *btype,
			      struct bsymbol *list_head,
			      char *list_head_member_name,int nofree,
			      os_linux_list_iterator_t iterator,void *data) {
    struct symbol *type;
    OFFSET list_head_member_offset;
    ADDR head;
    ADDR next_head;
    ADDR current_struct_addr;
    struct value *value = NULL;
    struct value *value_next;
    int i = 0;
    int retval = -1;
    int rc;
    struct target_location_ctxt *tlctxt = target_global_tlctxt(t);

    type = bsymbol_get_symbol(btype);

    errno = 0;
    list_head_member_offset = 
	symbol_offsetof(type,list_head_member_name,NULL);
    if (errno) {
	verror("could not get offset for %s in symbol %s!\n",
	       list_head_member_name,symbol_get_name(type));
	ERRORDUMPSYMBOL_NL(type);
	goto out;
    }

    /*
     * We just blindly use TID_GLOBAL because init_task is the symbol
     * they are supposed to pass, and resolving that is not going to
     * depend on any registers, so it doesn't matter which thread we
     * use.
     */

    value = target_load_symbol(t,tlctxt,list_head,LOAD_FLAG_NONE);
    if (!value) {
	verror("could not load list_head for symbol %s!\n",bsymbol_get_name(list_head));
	goto out;
    }
    head = value_addr(value);
    value_next = target_load_value_member(t,tlctxt,value,"next",
					  NULL,LOAD_FLAG_NONE);
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
    if (!nofree && value)
	value_free(value);

    return retval;
}

static int __value_get_append_tid(struct target *target,struct value *value,
				  void *data) {
    struct array_list *list = (struct array_list *)data;
    struct value *v;

    v = target_load_value_member(target,target_global_tlctxt(target),
				 value,"pid",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load pid in task; BUG?\n");
	/* errno should be set for us. */
	return -1;
    }
    array_list_append(list,(void *)(uintptr_t)v_i32(v));
    value_free(v);

    return 0;
}

struct array_list *os_linux_list_available_tids(struct target *target) {
    struct array_list *retval;
    struct os_linux_state *lstate =
	(struct os_linux_state *)target->personality_state;

    /*
     * If we are tracking threads, we don't have scan the list!
     */
    if ((target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY)
	&& (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT)) {
	vdebug(8,LA_TARGET,LF_OSLINUX,
	       "active probing thread entry/exit, so just reloading cache!\n");
	return target_list_tids(target);
    }

    /* Try to be smart about the size of the list we create. */
    if (lstate->last_thread_count)
	retval = array_list_create((lstate->last_thread_count + 16) & ~15);
    else
	retval = array_list_create(64);

    if (os_linux_list_for_each_struct(target,lstate->init_task,"tasks",0,
				      __value_get_append_tid,retval)) {
	verror("could not load all tids in task list (did %d tasks)\n",
	       array_list_len(retval));
	array_list_free(retval);
	return NULL;
    }

    lstate->last_thread_count = array_list_len(retval);

    vdebug(5,LA_TARGET,LF_OSLINUX | LF_THREAD,"%d current threads\n",
	   lstate->last_thread_count);

    return retval;
}

static int __value_load_thread(struct target *target,struct value *value,
			       void *data) {
    struct target_thread *tthread;
    int *load_counter = (int *)data;

    if (!(tthread = os_linux_load_thread_from_value(target,value))) {
	verror("could not load thread from task value; BUG?\n");
	value_free(value);
	return -1;
    }

    if (vdebug_is_on(8,LA_TARGET,LF_OSLINUX)) {
	char buf[512];
	target_thread_snprintf(target,tthread->tid,buf,sizeof(buf),
			       1,NULL,NULL);
	vdebug(8,LA_TARGET,LF_OSLINUX,
	       "loaded tid(%d) (%s)\n",tthread->tid,tthread->name,buf);
    }

    if (load_counter)
	++*load_counter;

    return 0;
}

int os_linux_load_available_threads(struct target *target,int force) {
    int rc = 0;
    struct os_linux_state *xstate =
	(struct os_linux_state *)target->personality_state;
    int i = 0;
    struct array_list *cthreads;
    struct target_thread *tthread;

    /*
     * If we are tracking threads, we don't have scan the list!
     */
    if ((target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY)
	&& (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT)) {
	vdebug(8,LA_TARGET,LF_OSLINUX,
	       "active probing thread entry/exit, so just reloading cache!\n");
	return target_load_all_threads(target,force);
    }

    if (os_linux_list_for_each_struct(target,xstate->init_task,"tasks",1,
				      __value_load_thread,&i)) {
	verror("could not load all threads in task list (did %d tasks)\n",i);
	rc = -1;
    }
    /*
     * If there are still any invalid threads, they are no longer live
     * -- so delete them!
     */
    else {
	cthreads = target_list_threads(target);
	for (i = 0; i < array_list_len(cthreads); ++i) {
	    tthread = (struct target_thread *)array_list_item(cthreads,i);
	    if (!tthread->valid) {
		vdebug(5,LA_TARGET,LF_OSLINUX | LF_THREAD,
		       "evicting invalid thread %"PRIiTID"; no longer exists\n",
		       tthread->tid);
		target_add_state_change(target,tthread->tid,
					TARGET_STATE_CHANGE_THREAD_EXITED,
					0,0,0,0,NULL);
		target_delete_thread(target,tthread,0);
	    }
	}
	array_list_free(cthreads);
    }

    return rc;
}

struct target_thread *os_linux_load_thread(struct target *target,
						   tid_t tid,int force) {
    struct target_thread *tthread = NULL;
    struct os_linux_thread_state *ltstate;
    int taskv_loaded;
    struct value *taskv = NULL;

    /* 
     * We need to find the task on the kernel's task list that matches
     * @tid.  If no match, but we had a thread with a matching @tid in
     * our cache, we need to nuke that thread.  If there is a match, but
     * its core data is different than what's in the cache, we have to
     * nuke the old task from the cache and build a new one.  If the
     * match matches, just reload its volatile data and context.
     */

    if (target_status(target) != TSTATUS_PAUSED) {
	verror("target not paused; cannot load thread id %d!\n",tid);
	errno = EBUSY;
	return NULL;
    }

    tthread = target_lookup_thread(target,tid);

    /*
     * If we didn't find a cached thread, or we're not live-tracking
     * thread exit, check for stale thread!  If we have a cached thread,
     * and we are tracking EXITs, we don't need to walk the task list.
     */
    if (!tthread 
	|| !(target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT)) {
	taskv = os_linux_get_task(target,tid);
	taskv_loaded = 1;

	if (!taskv) {
	    vwarn("no task matching %"PRIiTID"\n",tid);

	    if (tthread) {
		vdebug(3,LA_TARGET,LF_OSLINUX,
		       "evicting old thread %"PRIiTID"; no longer exists!\n",tid);
		target_add_state_change(target,tthread->tid,
					TARGET_STATE_CHANGE_THREAD_EXITED,
					0,0,0,0,NULL);
		target_delete_thread(target,tthread,0);
	    }

	    return NULL;
	}
    }
    else {
	taskv_loaded = 0;
	ltstate = (struct os_linux_thread_state *)tthread->personality_state;

	if (!value_refresh(ltstate->task_struct,1)) {
	    verror("could not refresh cached struct; aborting to manual update!\n");

	    taskv = os_linux_get_task(target,tid);
	    taskv_loaded = 1;

	    if (!taskv) {
		vwarn("no task matching %"PRIiTID"\n",tid);

		if (tthread) {
		    vdebug(3,LA_TARGET,LF_OSLINUX,
			   "evicting old thread %"PRIiTID"; no longer exists!\n",
			   tid);
		    target_add_state_change(target,tthread->tid,
					    TARGET_STATE_CHANGE_THREAD_EXITED,
					    0,0,0,0,NULL);
		    target_delete_thread(target,tthread,0);
		}

		return NULL;
	    }
	}
    }

    if (!(tthread = os_linux_load_thread_from_value(target,taskv)))
	goto errout;

    return tthread;

 errout:
    if (taskv_loaded && taskv)
	value_free(taskv);

    return NULL;
}

static struct target_thread *
__os_linux_load_current_thread_from_userspace(struct target *target,int force) {
    GHashTableIter iter;
    gpointer vp;
    struct target_thread *tthread = NULL;
    struct os_linux_thread_state *ltstate;
    uint64_t cr3;
    REGVAL ipval;

#if __WORDSIZE == 64
    /*
     * libxc claims that for x86_64, pagetable is in CR1.
     */
    if (__WORDSIZE == 64 || target->arch->wordsize == 8)
	cr3 = (uint64_t)target_read_reg(target,TID_GLOBAL,REG_X86_64_CR1);
    else
	cr3 = (uint64_t)target_read_reg(target,TID_GLOBAL,REG_X86_CR3);
#endif

    ipval = target_read_reg(target,TID_GLOBAL,target->ipregno);

    vdebug(5,LA_TARGET,LF_OSLINUX,
	   "ip 0x%"PRIxADDR"; cr3/pgd = 0x%"PRIx64"\n",ipval,cr3);

    /*
     * First, we scan our current cache; if we find a cr3 hit, we're
     * money.  Otherwise, we have load all tasks (well, at least until
     * we find what we need).
     */
    g_hash_table_iter_init(&iter,target->threads);
    while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&vp)) {
	tthread = (struct target_thread *)vp;
	ltstate = (struct os_linux_thread_state *)tthread->personality_state;

	if (ltstate->pgd == cr3) 
	    break;
	else {
	    tthread = NULL;
	    ltstate = NULL;
	}
    }

    if (!tthread) {
	vdebug(5,LA_TARGET,LF_OSLINUX,
	       "could not find task match for cr3 0x%"PRIx64";"
	       " loading all tasks!\n",cr3);

	/*
	 * We really should just use a reverse init_task list traversal
	 * here.  The task is most likely to be nearer the end.
	 */
	if (target_load_available_threads(target,force)) {
	    verror("could not load all threads to match on cr3!\n");
	    return NULL;
	}

	/* Search again. */
	g_hash_table_iter_init(&iter,target->threads);
	while (g_hash_table_iter_next(&iter,NULL,(gpointer *)&vp)) {
	    tthread = (struct target_thread *)vp;
	    ltstate = (struct os_linux_thread_state *)tthread->personality_state;

	    if (ltstate->pgd == cr3) 
		break;
	    else {
		vdebug(8,LA_TARGET,LF_OSLINUX,
		       "thread %"PRIiTID" with pgd 0x%"PRIx64" did not match!\n",
		       tthread->tid,ltstate->pgd);
		tthread = NULL;
		ltstate = NULL;
	    }
	}

	if (!tthread) {
	    verror("could not find task match for cr3 0x%"PRIx64
		   " after loading all tasks!\n",cr3);
	    errno = ESRCH;
	    return NULL;
	}
    }
    else {
	/* Reload its value. */
	if (!tthread->valid) {
	    tthread = os_linux_load_thread_from_value(target,
						      ltstate->task_struct);
	    if (!tthread) {
		verror("could not load cached thread %"PRIiTID" from value!",
		       tthread->tid);
		return NULL;
	    }
	}
    }

    vdebug(5,LA_TARGET,LF_OSLINUX,
	   "ip 0x%"PRIxADDR"; cr3/pgd = 0x%"PRIx64" --> thread %"PRIiTID"\n",
	   ipval,cr3,tthread->tid);

    return tthread;
}

struct target_thread *os_linux_load_current_thread(struct target *target,
						   int force) {
    struct os_linux_state *lstate = (struct os_linux_state *)target->personality_state;
    tid_t tid = 0;
    struct value *threadinfov = NULL;
    int preempt_count;
    unum_t tiflags;
    struct value *taskv = NULL;
    num_t tgid;
    unum_t task_flags = 0;
    ADDR group_leader;
    struct target_thread *tthread = NULL;
    struct os_linux_thread_state *ltstate = NULL;
    struct os_linux_thread_state *gtstate;
    struct value *v = NULL;
    REGVAL ipval;
    ADDR mm_addr = 0;
    uint64_t pgd = 0;
    REGVAL kernel_esp = 0;
    char *comm = NULL;
    struct target_thread *ptthread;
    tid_t ptid = -1;
    int uid = -1;
    int gid = -1;
    struct target_location_ctxt *tlctxt = target_global_tlctxt(target);
    thread_ctxt_t ctidctxt;

    /*
     * Load EIP for later user-mode check.
     */
    errno = 0;
    ipval = target_read_reg(target,TID_GLOBAL,target->ipregno);
    if (errno) {
	vwarn("could not read EIP for user-mode check; continuing anyway.\n");
	errno = 0;
    }

    //if (ipval < lstate->kernel_start_addr) 
    //    ctidctxt = THREAD_CTXT_USER;
    //else
    //	ctidctxt = THREAD_CTXT_KERNEL;

    ctidctxt = target->global_thread->tidctxt;

    /*
     * We used to not load the current thread in this case, but now we
     * do.  This is sort of misleading, because the thread is not
     * exactly in kernel context.  BUT, the important thing to realize
     * is that this target does not only provide service for in-kernel
     * operations.  The difference between this target and the
     * xen-process target is that the xen-process target has *extra*
     * functionality for inspecting the guts of a process, using its
     * symbols; this target can manipulate a process's CPU state, and it
     * can write virtual memory that is paged in; but that's it.
     *
     * So -- this target has to realize that its CPU state currently
     * corresponds to user state.  That means tricks like using the
     * current esp to find the current thread, and the task, do not
     * work.
     *
     * I'm not 100% happy about this; you have to check which context a
     * thread is in before you access its stack, etc.  But it's good
     * enough for now.
     *
     * Once we have loaded the global thread above, in this case, we
     * call a different function.  We actually try to infer which task
     * is running by checking cr3; we compare it to our existing, cached
     * tasks, and try to load the cached thread that matches.  If there
     * is no match, we have no choice but to load all the threads again
     * so we find the match.
     *
     * Anyway, we do that in another function.
     */
    if (ctidctxt == THREAD_CTXT_USER) {
	/*
	vdebug(9,LA_TARGET,LF_OSLINUX,
	       "at user-mode EIP 0x%"PRIxADDR"; not loading current thread;"
	       " returning global thread.\n",
	       ipval);
	return __os_linux_load_current_thread_from_userspace(target,force);
	*/

	kernel_esp = target_read_reg_ctxt(target,TID_GLOBAL,THREAD_CTXT_KERNEL,
					  target->spregno);
	vdebug(9,LA_TARGET,LF_OSLINUX,
	       "at user-mode EIP 0x%"PRIxADDR"; trying to load current kernel"
	       " thread with kernel_sp 0x%"PRIxADDR"\n",
	       ipval,kernel_esp);
    }

    /* We need to load in the current task_struct, AND if it's already
     * in target->threads, CHECK if it really matches one of our cached
     * threads.  If not, and there is an old thread in the cache, nuke
     * that one and build a new one -- TIDs can of course be reused in
     * Linux.
     */

    /*
     * But first, we need to see if we're handling a hard or soft IRQ
     * (and are ksoftirqd (?) -- but how do we check *which* kind of
     * soft IRQ we are??).
     *
     * If we are, we just set out TID to TID_GLOBAL, and load state
     * from Xen.
     *
     * If we are not, then, we can be safe to check the kernel's
     * task_struct to see which thread we are.  But wait, since the
     * kernel runs all softirqs in interrupt context, the current task
     * is really pretty irrelevant (unless it's ksoftirqd; we could
     * check and make a note of that...).
     *
     * So, we always set TID to TID_GLOBAL, and load state from Xen.
     */

    threadinfov = os_linux_load_current_thread_as_type(target,
						       lstate->thread_info_type,
						       kernel_esp);
    if (!threadinfov) {
	verror("could not load current thread info!  cannot get current TID!\n");
	/* errno should be set for us. */
	goto errout;
    }

    v = target_load_value_member(target,tlctxt,
				 threadinfov,"preempt_count",NULL,
				 LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread_info->preempt_count (to check IRQ status)!\n");
	/* errno should be set for us. */
	goto errout;
    }
    preempt_count = v_num(v);
    value_free(v);
    v = NULL;

    if (SOFTIRQ_COUNT(preempt_count) || HARDIRQ_COUNT(preempt_count)) {
	vdebug(3,LA_TARGET,LF_OSLINUX,"in interrupt context (hardirq=%d,softirq=%d)\n",
	       HARDIRQ_COUNT(preempt_count),SOFTIRQ_COUNT(preempt_count));
	tid = TID_GLOBAL;
	tgid = TID_GLOBAL;
	taskv = NULL;

	vdebug(5,LA_TARGET,LF_OSLINUX,
	       "loading global thread cause in hard/soft irq (0x%"PRIx64")\n",
	       preempt_count);
    }
    else {
	/* Now, load the current task_struct. */
	taskv = target_load_value_member(target,tlctxt,
					 threadinfov,"task",NULL,
					 LOAD_FLAG_AUTO_DEREF);

	if (!taskv) {
	    verror("could not load current task!  cannot get current TID!\n");
	    /* errno should be set for us. */
	    goto errout;
	}

	v = target_load_value_member(target,tlctxt,
				     taskv,"pid",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load pid in current task; BUG?\n");
	    /* errno should be set for us. */
	    goto errout;
	}
	tid = v_i32(v);
	value_free(v);
	v = NULL;

	v = target_load_value_member(target,tlctxt,
				     taskv,"parent",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load parent in task value; BUG?\n");
	    /* errno should be set for us. */
	    goto errout;
	}
	else if (v_addr(v) != value_addr(taskv)) {
	    ptthread = (struct target_thread *)				\
		g_hash_table_lookup(lstate->task_struct_addr_to_thread,
				    (gpointer)v_addr(v));
	    if (!ptthread) {
		/* Gotta load it. */
		value_free(v);
		v = target_load_value_member(target,tlctxt,
					     taskv,"parent",NULL,
					     LOAD_FLAG_AUTO_DEREF);
		if (!v) {
		    verror("could not load parent value from task;"
			   " ptid will be invalid!\n");
		}
		else {
		    ptthread = os_linux_load_thread_from_value(target,v);
		    if (!ptthread) {
			verror("could not load parent thread from value;"
			       " ptid will be invalid!\n");
		    }
		    else {
			vdebug(9,LA_TARGET,LF_OSLINUX,
			       "loaded tid %"PRIiTID" parent %"PRIiTID"\n",
			       tid,ptthread->tid);
			/* Don't free it! */
			v = NULL;
		    }
		}
	    }
	    else 
		vdebug(9,LA_TARGET,LF_OSLINUX,
		       "tid %"PRIiTID" parent %"PRIiTID" already loaded\n",
		       tid,ptthread->tid);

	    if (ptthread)
		ptid = ptthread->tid;
	}
	else if (tid != 0) {
	    vwarn("tid %"PRIiTID" ->parent is itself!\n",tid);
	}
	if (v) {
	    value_free(v);
	    v = NULL;
	}

	v = target_load_value_member(target,tlctxt,
				     taskv,lstate->task_uid_member_name,
				     NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load %s in task value; BUG?\n",
		   lstate->task_uid_member_name);
	    uid = -1;
	}
	else {
	    uid = v_i32(v);
	    value_free(v);
	    v = NULL;
	}

	v = target_load_value_member(target,tlctxt,
				     taskv,lstate->task_gid_member_name,
				     NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load %s in task value; BUG?\n",
		   lstate->task_gid_member_name);
	    gid = -1;
	}
	else {
	    gid = v_i32(v);
	    value_free(v);
	    v = NULL;
	}

	v = target_load_value_member(target,tlctxt,
				     taskv,"comm",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load comm in current task; BUG?\n");
	    /* errno should be set for us. */
	    goto errout;
	}
	comm = strndup(v->buf,v->bufsiz);
	value_free(v);
	v = NULL;

	vdebug(5,LA_TARGET,LF_OSLINUX,"loading thread %"PRIiTID"\n",tid);

	v = target_load_value_member(target,tlctxt,
				     taskv,"tgid",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load tgid in current task; BUG?\n");
	    /* errno should be set for us. */
	    goto errout;
	}
	tgid = v_num(v);
	value_free(v);
	v = NULL;

	v = target_load_value_member(target,tlctxt,
				     taskv,"flags",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load flags in task %"PRIiTID" current task; BUG?\n",
		   tid);
	    /* errno should be set for us. */
	    goto errout;
	}
	task_flags = v_unum(v);
	value_free(v);
	v = NULL;

	v = target_load_value_member(target,tlctxt,
				     taskv,"group_leader",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load group_leader in task %"PRIiTID" current task; BUG?\n",
		   tid);
	    /* errno should be set for us. */
	    goto errout;
	}
	group_leader = v_addr(v);
	value_free(v);
	v = NULL;

	v = target_load_value_member(target,tlctxt,
				     taskv,"mm",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not see if thread %"PRIiTID" was kernel or user\n",tid);
	    goto errout;
	}
	mm_addr = v_addr(v);
	value_free(v);
	v = NULL;

	if (mm_addr) {
	    v = target_load_value_member(target,tlctxt,
					 taskv,"mm.pgd",NULL,LOAD_FLAG_NONE);
	    if (!v) {
		verror("could not load thread %"PRIiTID" pgd (for cr3 tracking)\n",
		       tid);
		goto errout;
	    }
	    /* Load a unum, so we get the right number of bytes read. */
	    pgd = (uint64_t)v_unum(v);
	    value_free(v);
	    v = NULL;

	    /* If pgd was NULL, try task_struct.active_mm.pgd */
	    if (pgd == 0) {
		v = target_load_value_member(target,tlctxt,
					     taskv,"active_mm.pgd",NULL,
					     LOAD_FLAG_NONE);
		if (!v) {
		    vwarn("could not load thread %"PRIiTID" (active_mm) pgd (for cr3 tracking)\n",
			 tid);
		    goto errout;
		}
		/* Load a unum, so we get the right number of bytes read. */
		pgd = (uint64_t)v_unum(v);
		value_free(v);
		v = NULL;
	    }
	}
    }

    v = target_load_value_member(target,tlctxt,
				 threadinfov,"flags",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread_info->flags in current thread; BUG?\n");
	/* errno should be set for us. */
	goto errout;
    }
    tiflags = v_unum(v);
    value_free(v);
    v = NULL;

    /*
     * Now, update the current thread with the value info we just
     * loaded.  If it's not the global thread (irq context), we check
     * our cache, and create/delete as needed.
     */

    /* Check the cache: */
    if ((tthread = (struct target_thread *) \
	 g_hash_table_lookup(target->threads,(gpointer)(uintptr_t)tid))) {
	ltstate = (struct os_linux_thread_state *)tthread->personality_state;
	/*
	 * Check if this is a cached entry for an old task.  Except
	 * don't check if the thread is TID_GLOBAL, since we must
	 * always leave that meta-thread in the cache; it doesn't
	 * represent a real system thread.
	 */
	if (tid != TID_GLOBAL 
	    && (ltstate->tgid != tgid 
		|| (taskv && ltstate->task_struct_addr != value_addr(taskv)))) {
	    vdebug(5,LA_TARGET,LF_OSLINUX,
		   "deleting non-matching cached old thread %"PRIiTID
		   " (thread %p, tpc %p)\n",
		   tid,tthread,tthread->tpc);
	    target_add_state_change(target,tthread->tid,
				    TARGET_STATE_CHANGE_THREAD_EXITED,
				    0,0,0,0,NULL);
	    target_delete_thread(target,tthread,0);
	    ltstate = NULL;
	    tthread = NULL;
	}
	else {
	    vdebug(5,LA_TARGET,LF_OSLINUX,
		   "found matching cached thread %"PRIiTID" (thread %p, tpc %p)\n",
		   tid,tthread,tthread->tpc);
	}
    }

    if (!tthread) {
	/* Build a new one. */
	ltstate = (struct os_linux_thread_state *)calloc(1,sizeof(*ltstate));
	tthread = target_create_thread(target,tid,NULL,ltstate);
	g_hash_table_insert(lstate->task_struct_addr_to_thread,
			    (gpointer)value_addr(taskv),tthread);

	target_add_state_change(target,tid,TARGET_STATE_CHANGE_THREAD_CREATED,
				0,0,0,0,NULL);

	vdebug(5,LA_TARGET,LF_OSLINUX,
	       "built new thread %"PRIiTID" (thread %p, tpc %p)\n",
		   tid,tthread,tthread->tpc);
    }

    /*
     * Just conform the current thread to the global thread's context.
     */
    tthread->tidctxt = ctidctxt;

    /*
     * If this is a user-level thread that is in the kernel, pull our
     * user level-saved regs off the stack and put them in alt_context.
     */
    if (mm_addr && tthread->tidctxt == THREAD_CTXT_KERNEL) {
	ADDR stack_top = value_addr(threadinfov) + THREAD_SIZE;
	ADDR ptregs_stack_addr;
	ADDR gs_base_kernel;
	ADDR old_rsp = 0;

	if (target->arch->wordsize == 8) {
	    ptregs_stack_addr = 
		stack_top - 0 - symbol_get_bytesize(lstate->pt_regs_type);
	}
	else {
	    ptregs_stack_addr = 
		stack_top - 8 - symbol_get_bytesize(lstate->pt_regs_type);
	}

	vdebug(5,LA_TARGET,LF_OSLINUX,
	       "loading userspace regs from kernel stack for user tid %d"
	       " currently in kernel!\n",
	       tid);

	v = target_load_addr_real(target,ptregs_stack_addr,
				  LOAD_FLAG_NONE,
				  symbol_get_bytesize(lstate->pt_regs_type));
	if (!v) {
	    verror("could not load stack register save frame task %"PRIiTID"!\n",
		   tid);
	    goto errout;
	}

	/* Copy the first range. */
	if (target->arch->wordsize == 8) {
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_R15,((uint64_t *)v->buf)[0]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_R14,((uint64_t *)v->buf)[1]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_R13,((uint64_t *)v->buf)[2]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_R12,((uint64_t *)v->buf)[3]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_RBP,((uint64_t *)v->buf)[4]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_RBX,((uint64_t *)v->buf)[5]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_R11,((uint64_t *)v->buf)[6]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_R10,((uint64_t *)v->buf)[7]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_R9,((uint64_t *)v->buf)[8]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_R8,((uint64_t *)v->buf)[9]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_RAX,((uint64_t *)v->buf)[10]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_RCX,((uint64_t *)v->buf)[11]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_RDX,((uint64_t *)v->buf)[12]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_RSI,((uint64_t *)v->buf)[13]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_64_RDI,((uint64_t *)v->buf)[14]);
	    //memcpy(&ltstate->alt_context.user_regs,v->buf,8 * 15);
	}
	else {
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_EBX,((uint32_t *)v->buf)[0]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_ECX,((uint32_t *)v->buf)[1]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_EDX,((uint32_t *)v->buf)[2]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_ESI,((uint32_t *)v->buf)[3]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_EDI,((uint32_t *)v->buf)[4]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_EBP,((uint32_t *)v->buf)[5]);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
				     REG_X86_EAX,((uint32_t *)v->buf)[6]);
	    //memcpy(&ltstate->alt_context.user_regs,v->buf,4 * 7);
	}

	/* Copy the second range. */
	/**
	 ** WARNING: esp and ss may not be valid if the sleeping thread was
	 ** interrupted while it was in the kernel, because the interrupt
	 ** gate does not push ss and esp; see include/asm-i386/processor.h .
	 **/
	ADDR ssp;
	int ip_offset = lstate->pt_regs_ip_offset;
	if (__WORDSIZE == 64 || target->arch->wordsize == 8) {
	    uint64_t rv;
	    rv = ((uint64_t *)(v->buf + ip_offset))[0];
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_64_RIP,rv);
	    rv = ((uint64_t *)(v->buf + ip_offset))[1];
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_64_CS,rv);
	    rv = ((uint64_t *)(v->buf + ip_offset))[2];
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_64_RFLAGS,rv);
	    ssp = rv = ((uint64_t *)(v->buf + ip_offset))[3];
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_64_RSP,rv);
	    rv = ((uint64_t *)(v->buf + ip_offset))[4];
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_64_SS,rv);
	}
	else {
	    uint32_t rv;
	    rv = ((uint32_t *)(v->buf + ip_offset))[0];
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_EIP,rv);
	    rv = ((uint32_t *)(v->buf + ip_offset))[1];
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_CS,rv);
	    rv = ((uint32_t *)(v->buf + ip_offset))[2];
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_EFLAGS,rv);
	    ssp = rv = ((uint32_t *)(v->buf + ip_offset))[3];
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_ESP,rv);
	    rv = ((uint32_t *)(v->buf + ip_offset))[4];
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_SS,rv);
	}

	/*
	 * ds, es, fs, gs are all special; see other comments.
	 */
	if (target->arch->type == ARCH_X86
	    && !lstate->thread_struct_has_ds_es && lstate->pt_regs_has_ds_es) {
	    uint32_t rv;
	    /* XXX: this works because we know the location of (x)ds/es;
	     * it's only on i386/x86; and because Xen pads its
	     * cpu_user_regs structs from u16s to ulongs for segment
	     * registers.  :)
	     */
	    rv = *(uint32_t *)(v->buf + 7 * target->arch->wordsize);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_DS,rv);
	    rv = *(uint32_t *)(v->buf + 8 * target->arch->wordsize);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_ES,rv);
	}
	if (target->arch->type == ARCH_X86
	    && !lstate->thread_struct_has_fs && lstate->pt_regs_has_fs_gs) {
	    uint32_t rv;
	    /* XXX: this is only true on newer x86 stuff; x86_64 and old
	     * i386 stuff did not save it on the stack.
	     */
	    rv = *(uint32_t *)(v->buf + 9 * target->arch->wordsize);
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_FS,rv);
	}

	gs_base_kernel = target_read_reg(target,TID_GLOBAL,
					 REG_X86_64_GS_BASE_KERNEL);
	if (!target_read_addr(target,gs_base_kernel + 0xbf00,
			      target->arch->wordsize,
			      (unsigned char *)&old_rsp)) {
	    verror("could not read %%gs:old_rsp (%%gs+0xbf00)"
		   " (0x%"PRIxADDR":%"PRIxOFFSET"); cannot continue!\n",
		   gs_base_kernel,0xbf00UL);
	    if (!errno)
		errno = EFAULT;
	    return 0;
	}

	vdebug(5,LA_TARGET,LF_OSLINUX,
	       "stacked rsp 0x%"PRIxADDR", old_rsp 0x%"PRIxADDR"\n",
	       ssp,old_rsp);

	if (target->arch->wordsize == 8 || __WORDSIZE == 64) 
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_64_RSP,old_rsp);
	else
	    target_regcache_init_reg_tidctxt(target,tthread,THREAD_CTXT_USER,
					     REG_X86_ESP,old_rsp);

	/*	
#if __WORDSIZE == 64
	int r_offset = offsetof(struct vcpu_guest_context,user_regs.r12);
	vdebug(5,LA_TARGET,LF_OSLINUX,
	       "stacked r12 0x%"PRIxADDR", adjusting\n",
	       *(ADDR *)(((char *)&ltstate->alt_context) + r_offset));
	*(ADDR *)(((char *)&ltstate->alt_context) + r_offset) += 8;
#endif
	*/

	value_free(v);
	v = NULL;
    }

    if (taskv) { //!(SOFTIRQ_COUNT(preempt_count) || HARDIRQ_COUNT(preempt_count))) {
	if (ltstate->task_struct) {
	    vwarn("stale task_struct for thread %"PRIiTID"!\n",tid);
	    value_free(ltstate->task_struct);
	    ltstate->task_struct = NULL;
	}
	ltstate->task_struct_addr = value_addr(taskv);
	ltstate->task_struct = taskv;
	ltstate->tgid = tgid;
	ltstate->task_flags = task_flags;
	ltstate->group_leader = group_leader;
    }

    /*
     * Check for stale cached values.  These should not be here, but... !
     */
    if (ltstate->thread_struct) {
	vwarn("stale thread_struct for thread %"PRIiTID"!\n",tid);
	value_free(ltstate->thread_struct);
	ltstate->thread_struct = NULL;
    }
    if (ltstate->thread_info) {
	vwarn("stale thread_info for thread %"PRIiTID"!\n",tid);
	value_free(ltstate->thread_info);
	ltstate->thread_info = NULL;
    }

    ltstate->thread_info = threadinfov;
    ltstate->thread_info_flags = tiflags;
    ltstate->thread_info_preempt_count = preempt_count;

    /*
     * We don't bother loading this, because it's our "current" thread
     * -- all the state in the thread_struct is directly accessible from
     * hardware.
     */
    ltstate->thread_struct = NULL;
    ltstate->ptregs_stack_addr = 0;
    ltstate->mm_addr = mm_addr;
    ltstate->pgd = pgd;
    /*
     * If the current thread is not the global thread, fill in a little
     * bit more info for the global thread.
     */
    if (tthread != target->global_thread) {
	gtstate = (struct os_linux_thread_state *) \
	    target->global_thread->personality_state;

	/*
	 * Don't copy in any of the other per-xen thread state; we want
	 * to force users to load and operate on real threads for any
	 * other information.  The global thread only has thread_info in
	 * interrupt context.
	 */
	gtstate->task_struct_addr = 0;
	gtstate->task_struct = NULL;
	gtstate->task_flags = 0;
	gtstate->group_leader = 0;
	gtstate->thread_struct = NULL;
	gtstate->ptregs_stack_addr = 0;
	gtstate->mm_addr = 0;
	gtstate->pgd = 0;

	/* BUT, do copy in thread_info. */
	if (gtstate->thread_info) {
	    vwarn("stale thread_info for global thread %"PRIiTID"!\n",TID_GLOBAL);
	    value_free(gtstate->thread_info);
	    gtstate->thread_info = NULL;
	}
	gtstate->thread_info = value_clone(threadinfov);
	gtstate->thread_info_flags = tiflags;
	gtstate->thread_info_preempt_count = preempt_count;

	if (mm_addr) 
	    tthread->supported_overlay_types = TARGET_TYPE_XEN_PROCESS;
	else
	    tthread->supported_overlay_types = TARGET_TYPE_NONE;

	if (tthread->name)
	    free(tthread->name);
	tthread->name = comm;
	tthread->ptid = ptid;
	tthread->uid = uid;
	tthread->gid = gid;
	comm = NULL;
    }

    if (v)
	value_free(v);
    if (comm)
	free(comm);

    return tthread;

 errout:
    if (v)
	value_free(v);
    if (comm)
	free(comm);
    if (threadinfov)
	value_free(threadinfov);
    if (taskv)
	value_free(taskv);
    if (ltstate) {
	ltstate->thread_info = NULL;
	ltstate->thread_struct = NULL;
	ltstate->task_struct = NULL;
    }

    /* XXX: should we really set this here? */
    target->current_thread = target->global_thread;

    vwarn("error loading current thread; trying to use default thread\n");
    errno = 0;

    return target->global_thread;
}

void os_linux_free_thread_state(struct target *target,void *state) {
    struct os_linux_state *lstate =
	(struct os_linux_state *)target->personality_state;
    struct os_linux_thread_state *ltstate =
	(struct os_linux_thread_state *)state;

    /*
     * XXX: this stinks, but it's the only time we have to remove a
     * thread from our hash cache of task_struct_addrs_to_thread .
     */
    if (lstate->task_struct_addr_to_thread)
	g_hash_table_remove(lstate->task_struct_addr_to_thread,
			    (gpointer)ltstate->task_struct_addr);

    if (ltstate->thread_struct) {
	value_free(ltstate->thread_struct);
	ltstate->thread_struct = NULL;
    }
    if (ltstate->thread_info) {
	value_free(ltstate->thread_info);
	ltstate->thread_info = NULL;
    }
    if (ltstate->task_struct) {
	value_free(ltstate->task_struct);
	ltstate->task_struct = NULL;
    }

    free(state);
}

struct target_thread *os_linux_load_thread_from_value(struct target *target,
						      struct value *taskv) {
    struct os_linux_state *lstate =
	(struct os_linux_state *)target->personality_state;
    struct target_thread *tthread;
    struct target_thread *ptthread;
    struct os_linux_thread_state *ltstate = NULL;
    tid_t tid;
    tid_t ptid = -1;
    num_t tgid = 0;
    unum_t task_flags = 0;
    ADDR group_leader;
    struct value *threadinfov = NULL;
    unum_t tiflags = 0;
    num_t preempt_count = 0;
    struct value *threadv = NULL;
    struct value *v = NULL;
    int iskernel = 0;
    ADDR stack_top;
    char *comm = NULL;
    ADDR stack_member_addr;
    int i;
    int ip_offset;
    int uid;
    int gid;
    struct target_location_ctxt *tlctxt = target_global_tlctxt(target);
    thread_ctxt_t ptregs_tidctxt;

    vdebug(5,LA_TARGET,LF_OSLINUX,"loading\n");

    v = target_load_value_member(target,tlctxt,
				 taskv,"pid",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load pid in task value; BUG?\n");
	/* errno should be set for us. */
	goto errout;
    }
    tid = v_i32(v);
    value_free(v);
    v = NULL;

    v = target_load_value_member(target,tlctxt,
				 taskv,"parent",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load parent in task value; BUG?\n");
	/* errno should be set for us. */
	goto errout;
    }
    else if (v_addr(v) != value_addr(taskv)) {
	ptthread = (struct target_thread *)			\
	    g_hash_table_lookup(lstate->task_struct_addr_to_thread,
				(gpointer)v_addr(v));
	if (!ptthread) {
	    /* Gotta load it. */
	    value_free(v);
	    v = target_load_value_member(target,tlctxt,
					 taskv,"parent",NULL,
					 LOAD_FLAG_AUTO_DEREF);
	    if (!v) {
		verror("could not load parent value from task;"
		       " ptid will be invalid!\n");
	    }
	    else {
		ptthread = os_linux_load_thread_from_value(target,v);
		if (!ptthread) {
		    verror("could not load parent thread from value;"
			   " ptid will be invalid!\n");
		}
		else {
		    vdebug(9,LA_TARGET,LF_OSLINUX,
			   "loaded tid %"PRIiTID" parent %"PRIiTID"\n",
			   tid,ptthread->tid);
		    /* Don't free it! */
		    v = NULL;
		}
	    }
	}
	else 
	    vdebug(9,LA_TARGET,LF_OSLINUX,
		   "tid %"PRIiTID" parent %"PRIiTID" already loaded\n",
		   tid,ptthread->tid);

	if (ptthread)
	    ptid = ptthread->tid;
    }
    else if (tid != 0) {
	/* The parent of 0 is 0, so that is ok. */
	vwarn("tid %"PRIiTID" ->parent is itself!\n",tid);
    }
    if (v) {
	value_free(v);
	v = NULL;
    }

    v = target_load_value_member(target,tlctxt,
				 taskv,lstate->task_uid_member_name,
				 NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load %s in task value; BUG?\n",
	       lstate->task_uid_member_name);
	uid = -1;
    }
    else {
	uid = v_i32(v);
	value_free(v);
	v = NULL;
    }

    v = target_load_value_member(target,tlctxt,
				 taskv,lstate->task_gid_member_name,
				 NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load %s in task value; BUG?\n",
	       lstate->task_gid_member_name);
	gid = -1;
    }
    else {
	gid = v_i32(v);
	value_free(v);
	v = NULL;
    }

    v = target_load_value_member(target,tlctxt,
				 taskv,"comm",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load comm in task value; BUG?\n");
	/* errno should be set for us. */
	goto errout;
    }
    comm = strndup(v->buf,v->bufsiz);
    value_free(v);
    v = NULL;

    v = target_load_value_member(target,tlctxt,
				 taskv,"tgid",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load tgid in task %"PRIiTID"; BUG?\n",tid);
	/* errno should be set for us. */
	goto errout;
    }
    tgid = v_num(v);
    value_free(v);
    v = NULL;

    v = target_load_value_member(target,tlctxt,
				 taskv,"flags",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load flags in task %"PRIiTID"; BUG?\n",tid);
	/* errno should be set for us. */
	goto errout;
    }
    task_flags = v_unum(v);
    value_free(v);
    v = NULL;

    v = target_load_value_member(target,tlctxt,
				 taskv,"group_leader",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load group_leader in task %"PRIiTID"; BUG?\n",tid);
	/* errno should be set for us. */
	goto errout;
    }
    group_leader = v_addr(v);
    value_free(v);
    v = NULL;

    /*
     * Before loading anything else, check the cache.
     */
    tthread = target_lookup_thread(target,tid);
    if (tthread) {
	ltstate = (struct os_linux_thread_state *)tthread->personality_state;

	/* Check if this is a cached entry for an old task */
	if (ltstate->tgid != tgid 
	    || ltstate->task_struct_addr != value_addr(taskv)) {
	    target_add_state_change(target,tid,TARGET_STATE_CHANGE_THREAD_EXITED,
				    0,0,0,0,NULL);
	    target_delete_thread(target,tthread,0);
	    ltstate = NULL;
	    tthread = NULL;
	}
    }

    if (!tthread) {
	/* Build a new one. */
	ltstate = (struct os_linux_thread_state *)calloc(1,sizeof(*ltstate));

	/* XXX: how to init backend's state??? */
	tthread = target_create_thread(target,tid,NULL,ltstate);
	g_hash_table_insert(lstate->task_struct_addr_to_thread,
			    (gpointer)value_addr(taskv),tthread);

	target_add_state_change(target,tid,TARGET_STATE_CHANGE_THREAD_CREATED,
				0,0,0,0,NULL);
    }
    else {
	/*
	 * If this is the current thread, we cannot load it from its
	 * task_struct value (especially its register state!).  The
	 * current_thread should have been loaded by now, so if it has
	 * been loaded, don't reload from the thread stack (because the
	 * thread stack does not have saved registers because the thread
	 * is running!).
	 *
	 * XXX: to support SMP, we would have to check the task_struct's
	 * running status, and only load from CPU in those cases.
	 */
	if (tthread == target->current_thread
	    && target->current_thread->valid) {
	    vdebug(8,LA_TARGET,LF_OSLINUX,
		   "not loading running, valid current thread %"PRIiTID" from"
		   " task_struct 0x%"PRIxADDR"; loaded from CPU of course\n",
		   tid,value_addr(taskv));
	    return target->current_thread;
	}
    }

    if (lstate->task_struct_has_thread_info) {
	threadinfov = target_load_value_member(target,tlctxt,
					       taskv,"thread_info",NULL,
					       LOAD_FLAG_AUTO_DEREF);
	if (!threadinfov) {
	    verror("could not load thread_info in task %"PRIiTID"; BUG?\n",tid);
	    /* errno should be set for us. */
	    goto errout;
	}
    }
    else if (lstate->task_struct_has_stack) {
	v = target_load_value_member(target,tlctxt,
				     taskv,"stack",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load stack (thread_info) in task %"PRIiTID";"
		   " BUG?\n",tid);
	    /* errno should be set for us. */
	    goto errout;
	}
	stack_member_addr = v_addr(v);
	value_free(v);
	v = NULL;

	threadinfov = target_load_type(target,lstate->thread_info_type,
				       stack_member_addr,LOAD_FLAG_NONE);
	if (!threadinfov) {
	    verror("could not load stack (thread_info) in task %"PRIiTID";"
		   " BUG?\n",tid);
	    goto errout;
	}
    }
    else {
	verror("cannot load thread_info/stack; no thread support!\n");
	goto errout;
    }

    v = target_load_value_member(target,tlctxt,
				 threadinfov,"flags",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread_info.flags in task %"PRIiTID"; BUG?\n",tid);
	/* errno should be set for us. */
	goto errout;
    }
    tiflags = v_unum(v);
    value_free(v);
    v = NULL;

    v = target_load_value_member(target,tlctxt,
				 threadinfov,"preempt_count",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread_info.preempt_count in task %"PRIiTID";"
	       " BUG?\n",tid);
	/* errno should be set for us. */
	goto errout;
    }
    preempt_count = v_num(v);
    value_free(v);
    v = NULL;

    ltstate->task_struct_addr = value_addr(taskv);
    ltstate->task_struct = taskv;
    tthread->ptid = ptid;
    tthread->uid = uid;
    tthread->gid = gid;
    ltstate->tgid = tgid;
    ltstate->task_flags = task_flags;
    ltstate->group_leader = group_leader;
    ltstate->thread_info = threadinfov;
    ltstate->thread_info_flags = tiflags;
    ltstate->thread_info_preempt_count = preempt_count;

    /*
     * If we have the thread, we can load as much of the stuff in the
     * vcpu_guest_context struct as the kernel contains!
     */

    v = target_load_value_member(target,tlctxt,
				 taskv,"mm",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not see if thread %"PRIiTID" was kernel or user\n",tid);
	goto errout;
    }
    ltstate->mm_addr = v_addr(v);
    if (ltstate->mm_addr == 0)
	iskernel = 1;
    value_free(v);
    v = NULL;

    if (ltstate->mm_addr) {
	v = target_load_value_member(target,tlctxt,
				     taskv,"mm.pgd",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    verror("could not load thread %"PRIiTID" (mm) pgd (for cr3 tracking)\n",
		   tid);
	    goto errout;
	}
	/* Load a unum, so we get the right number of bytes read. */
	ltstate->pgd = (uint64_t)v_unum(v);
	value_free(v);
	v = NULL;

	/* If pgd was NULL, try task_struct.active_mm.pgd */
	if (ltstate->pgd == 0) {
	    v = target_load_value_member(target,tlctxt,
					 taskv,"active_mm.pgd",NULL,
					 LOAD_FLAG_NONE);
	    if (!v) {
		vwarn("could not load thread %"PRIiTID" (active_mm) pgd (for cr3 tracking)\n",
		      tid);
		goto errout;
	    }
	    /* Load a unum, so we get the right number of bytes read. */
	    ltstate->pgd = (uint64_t)v_unum(v);
	    value_free(v);
	    v = NULL;
	}
    }

    /*
     * In our world, a Linux thread will not be executing an interrupt
     * top/bottom half (ISR or softirq) if it is not running (i.e.,
     * ISRs/softirqs are not preemptible).  So, if the sleeping thread
     * is in kernel context, the task's state (registers) are on the
     * stack in the right place, unless we are in a section of the code
     * that is setting up the stack or tearing it down (i.e., preempted
     * during syscall init or something -- unless this is not possible
     * if the kernel disables interrupts in those critical
     * sections...).  BUT, even if this is true, the current machine
     * state will have been pushed on the stack to handle the interrupt
     * (and perhaps the following context switch, if there is one after
     * servicing the ISR/softirq(s)).
     *
     * Thus, we don't have to check what the thread is executing.
     *
     * It doesn't matter whether the thread is a kernel thread or not.
     */
    if (iskernel) {
	target_thread_set_status(tthread,THREAD_STATUS_RETURNING_KERNEL);
	tthread->supported_overlay_types = TARGET_TYPE_NONE;

	tthread->tidctxt = THREAD_CTXT_KERNEL;
	ptregs_tidctxt = THREAD_CTXT_KERNEL;
	//thi_tidctxt = THREAD_CTXT_KERNEL;
    }
    else {
	target_thread_set_status(tthread,THREAD_STATUS_RETURNING_USER);
	tthread->supported_overlay_types = TARGET_TYPE_XEN_PROCESS;

	tthread->tidctxt = THREAD_CTXT_KERNEL;
	ptregs_tidctxt = THREAD_CTXT_USER;
	//thi_tidctxt = THREAD_CTXT_USER;
    }

    /* We are entirely loading this thread, not the backend, so nuke it. */
    target_regcache_zero(target,tthread,THREAD_CTXT_KERNEL);
    target_regcache_zero(target,tthread,THREAD_CTXT_USER);

    if (tthread->name)
	free(tthread->name);
    tthread->name = comm;
    comm = NULL;

    /*
     * Load the stored registers from the kernel stack; except fs/gs and
     * the debug regs are in the task_struct->thread thread_struct
     * struct.
     */
    threadv = target_load_value_member(target,tlctxt,
				       taskv,"thread",NULL,LOAD_FLAG_NONE);
    if (!threadv) {
	verror("could not load thread_struct for task %"PRIiTID"!\n",tid);
	goto errout;
    }

    ltstate->thread_struct = threadv;

    v = target_load_value_member(target,tlctxt,
				 threadv,lstate->thread_sp_member_name,
				 NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread.%s for task %"PRIiTID"!\n",
	       lstate->thread_sp_member_name,tid);
	goto errout;
    }
    ltstate->esp = v_addr(v);
    value_free(v);
    v = NULL;

    /* The stack base is also the value of the task_struct->thread_info ptr. */
    ltstate->stack_base = value_addr(threadinfov);
    stack_top = ltstate->stack_base + THREAD_SIZE;

    /* See include/asm-i386/processor.h .  And since it doesn't explain
     * why it is subtracting 8, it's because fs/gs are not pushed on the
     * stack, so the ptrace regs struct doesn't really match with what's
     * on the stack ;).
     */
    if (iskernel && preempt_count) {
	if (target->arch->wordsize == 8) {
	    ltstate->ptregs_stack_addr = 
		stack_top - 0 - symbol_get_bytesize(lstate->pt_regs_type);
	}
	else {
	    ltstate->ptregs_stack_addr = 
		stack_top - 8 - symbol_get_bytesize(lstate->pt_regs_type);
	}
	//ltstate->ptregs_stack_addr = ltstate->esp - 8 - 15 * 4;
	// + 8 - 7 * 4; // - 8 - 15 * 4;
    }
    /*
     * Registers are not saved if it's a sleeping, non-preempted kernel
     * thread.  All that was saved is the esp and eip, and fs/gs, in the
     * thread struct.  Registers are only saved on kernel interrupt, or
     * mode switch from user to kernel mode.  The best we could do is
     * look into schedule()'s frame and look at its saved registers so
     * that we could see what schedule's caller will have -- and then
     * look and see what the caller saved.  Anything else is trashed.
     */
    else if (iskernel) {
	ltstate->ptregs_stack_addr = 0;
	/*
	v = target_load_addr_real(target,esp0,LOAD_FLAG_NONE,32*4);
	int i;
	for (i = 0; i < 32; ++i) {
	    vwarn("%d esp[%d] = 0x%x\n",tid,i,((int *)v->buf)[i]);
	}
	value_free(v);
	v = NULL;
	*/
    }
    else if (target->arch->wordsize == 8) {
	ltstate->ptregs_stack_addr = 
	    stack_top - 0 - symbol_get_bytesize(lstate->pt_regs_type);
    }
    else {
	ltstate->ptregs_stack_addr = 
	    stack_top - 8 - symbol_get_bytesize(lstate->pt_regs_type);
    }

    vdebug(5,LA_TARGET,LF_OSLINUX,
	   "esp=%"PRIxADDR",stack_base=%"PRIxADDR",stack_top=%"PRIxADDR
	   ",ptregs_stack_addr=%"PRIxADDR"\n",
	   ltstate->esp,stack_top,ltstate->stack_base,ltstate->ptregs_stack_addr);

    v = target_load_value_member(target,tlctxt,
				 threadv,lstate->thread_sp0_member_name,
				 NULL,LOAD_FLAG_NONE);
    if (!v) 
	vwarn("could not load thread.%s for task %"PRIiTID"!\n",
	      lstate->thread_sp0_member_name,tid);
    ltstate->esp0 = v_addr(v);
    value_free(v);
    v = NULL;

    /*
     * On x86_64, %ip is not tracked -- there's no point anyway --
     * either it's in the scheduler at context switch, or it's at
     * ret_from_fork -- no point loading.  But still, it's on the kernel
     * stack at *(thread.sp - 8).  That's how we load it.
     */
    if (lstate->thread_ip_member_name) {
	v = target_load_value_member(target,tlctxt,
				     threadv,lstate->thread_ip_member_name,
				     NULL,LOAD_FLAG_NONE);
	if (!v) 
	    vwarn("could not load thread.%s for task %"PRIiTID"!\n",
		  lstate->thread_ip_member_name,tid);
	else {
	    ltstate->eip = v_addr(v);
	    value_free(v);
	    v = NULL;
	}
    }
    else {
	v = target_load_addr_real(target,ltstate->esp + 3 * target->arch->wordsize,
				  LOAD_FLAG_NONE,target->arch->wordsize);
	if (!v) 
	    vwarn("could not 64-bit IP (thread.ip) for task %"PRIiTID"!\n",
		  tid);
	else {
	    ltstate->eip = v_addr(v);
	    value_free(v);
	    v = NULL;
	}
    }

    /*
     * For old i386 stuff, fs/gs are in the thread data structure.
     * For newer x86 stuff, only gs is saved in thread_struct; fs is on
     * the stack.
     *
     * For x86_64, ds/es are saved in thread_struct; some threads have
     * 64-bit fs/gs bases in thread_struct; the fs/gs segment selectors
     * are saved in fsindex/gsindex.  Not sure how to expose fs/gs in
     * this model... for now we ignore fsindex/gsindex.
     */
    REG reg;
    if (target->arch->type == ARCH_X86)
	reg = REG_X86_FS;
    else
	reg = REG_X86_64_FS;
    if (lstate->thread_struct_has_fs) {
	v = target_load_value_member(target,tlctxt,
				     threadv,"fs",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    vwarn("could not load thread.fs for task %"PRIiTID"!\n",tid);
	    goto errout;
	}
	else {
	    ltstate->fs = v_u16(v);
	    value_free(v);
	    v = NULL;
	}
    }
    else {
	/* Load this from pt_regs below if we can. */
	ltstate->fs = 0;
    }
    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     reg,ltstate->fs);

    /* Everybody always has gs. */
    if (target->arch->type == ARCH_X86)
	reg = REG_X86_GS;
    else
	reg = REG_X86_64_GS;
    v = target_load_value_member(target,tlctxt,
				 threadv,"gs",NULL,LOAD_FLAG_NONE);
    if (!v) {
	verror("could not load thread.gs for task %"PRIiTID"!\n",tid);
	goto errout;
    }
    else {
	ltstate->gs = v_u16(v);
	value_free(v);
	v = NULL;
    }
    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     reg,ltstate->gs);

    if (lstate->thread_struct_has_ds_es) {
	v = target_load_value_member(target,tlctxt,
				     threadv,"ds",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    vwarn("could not load thread.ds for task %"PRIiTID"!\n",tid);
	    goto errout;
	}
	else {
	    if (target->arch->type == ARCH_X86_64)
		target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
						 REG_X86_64_DS,v_u64(v));
	    else 
		target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
						 REG_X86_DS,v_u32(v));
	    value_free(v);
	    v = NULL;
	}

	v = target_load_value_member(target,tlctxt,
				     threadv,"es",NULL,LOAD_FLAG_NONE);
	if (!v) {
	    vwarn("could not load thread.es for task %"PRIiTID"!\n",tid);
	    goto errout;
	}
	else {
	    if (target->arch->type == ARCH_X86_64)
		target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
						 REG_X86_64_ES,v_u64(v));
	    else 
		target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
						 REG_X86_ES,v_u32(v));
	    value_free(v);
	    v = NULL;
	}
    }
    else {
	/* Load this from pt_regs below if we can. */
	if (target->arch->type == ARCH_X86_64) {
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_DS,0);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_ES,0);
	}
	else {
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_DS,0);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_ES,0);
	}
    }

    if (ltstate->ptregs_stack_addr) {
	/*
	 * The xen cpu_user_regs struct, and pt_regs struct, tend to
	 * align (no pun intended) reasonably well.  On i386, we can
	 * copy pt_regs::(e)bx--(e)ax directly to cpu_user_regs::ebx--eax;
	 * then copy pt_regs::(e)ip--(x)ss to cpu_user_regs::eip--ss.
	 * For x86_64, the same is basically true; the ranges are
	 * r15--(r)di, and (r)ip--ss.
	 *
	 * (The (X) prefixes are because the Linux kernel x86 and x86_64
	 * struct pt_regs member names have changed over the years; but
	 * by just doing this brutal copying, we can ignore all that --
	 * which is faster from a value-loading perspective.)
	 *
	 * (This all works because Xen's cpu_user_regs has been
	 * carefully mapped to x86 and x86_64 pt_regs structs, in the
	 * specific register ranges listed (the Xen structs have some
	 * other things in the middle and es/ds/fs/gs regs at the end,
	 * so it's not a complete alignment.)
	 */
	v = target_load_addr_real(target,ltstate->ptregs_stack_addr,
				  LOAD_FLAG_NONE,
				  symbol_get_bytesize(lstate->pt_regs_type));
	if (!v) {
	    verror("could not load stack register save frame task %"PRIiTID"!\n",
		   tid);
	    goto errout;
	}

	/* Copy the first range. */
	if (target->arch->wordsize == 8) {
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_R15,((uint64_t *)v->buf)[0]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_R14,((uint64_t *)v->buf)[1]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_R13,((uint64_t *)v->buf)[2]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_R12,((uint64_t *)v->buf)[3]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_RBP,((uint64_t *)v->buf)[4]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_RBX,((uint64_t *)v->buf)[5]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_R11,((uint64_t *)v->buf)[6]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_R10,((uint64_t *)v->buf)[7]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_R9,((uint64_t *)v->buf)[8]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_R8,((uint64_t *)v->buf)[9]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_RAX,((uint64_t *)v->buf)[10]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_RCX,((uint64_t *)v->buf)[11]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_RDX,((uint64_t *)v->buf)[12]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_RSI,((uint64_t *)v->buf)[13]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_64_RDI,((uint64_t *)v->buf)[14]);
	    //memcpy(&lltstate->alt_context.user_regs,v->buf,8 * 15);
	}
	else {
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_EBX,((uint32_t *)v->buf)[0]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_ECX,((uint32_t *)v->buf)[1]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_EDX,((uint32_t *)v->buf)[2]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_ESI,((uint32_t *)v->buf)[3]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_EDI,((uint32_t *)v->buf)[4]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_EBP,((uint32_t *)v->buf)[5]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
				     REG_X86_EAX,((uint32_t *)v->buf)[6]);
	    //memcpy(&ltstate->alt_context.user_regs,v->buf,4 * 7);
	}

	/* Copy the second range. */
	/**
	 ** WARNING: esp and ss may not be valid if the sleeping thread was
	 ** interrupted while it was in the kernel, because the interrupt
	 ** gate does not push ss and esp; see include/asm-i386/processor.h .
	 **/
	//ADDR ssp;
	int ip_offset = lstate->pt_regs_ip_offset;
	if (__WORDSIZE == 64 || target->arch->wordsize == 8) {
	    uint64_t rv;
	    rv = ((uint64_t *)(v->buf + ip_offset))[0];
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_RIP,rv);
	    rv = ((uint64_t *)(v->buf + ip_offset))[1];
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_CS,rv);
	    rv = ((uint64_t *)(v->buf + ip_offset))[2];
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_RFLAGS,rv);
	    //ssp = rv = ((uint64_t *)(v->buf + ip_offset))[3];
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_RSP,rv);
	    rv = ((uint64_t *)(v->buf + ip_offset))[4];
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_SS,rv);
	}
	else {
	    uint32_t rv;
	    rv = ((uint32_t *)(v->buf + ip_offset))[0];
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_EIP,rv);
	    rv = ((uint32_t *)(v->buf + ip_offset))[1];
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_CS,rv);
	    rv = ((uint32_t *)(v->buf + ip_offset))[2];
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_EFLAGS,rv);
	    //ssp = rv = ((uint32_t *)(v->buf + ip_offset))[3];
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_ESP,rv);
	    rv = ((uint32_t *)(v->buf + ip_offset))[4];
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_SS,rv);
	}

	/*
	 * ds, es, fs, gs are all special; see other comments.
	 */

	if (target->arch->type == ARCH_X86
	    && !lstate->thread_struct_has_ds_es && lstate->pt_regs_has_ds_es) {
	    uint32_t rv;
	    /* XXX: this works because we know the location of (x)ds/es;
	     * it's only on i386/x86; and because Xen pads its
	     * cpu_user_regs structs from u16s to ulongs for segment
	     * registers.  :)
	     */
	    rv = *(uint32_t *)(v->buf + 7 * target->arch->wordsize);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_DS,rv);
	    rv = *(uint32_t *)(v->buf + 8 * target->arch->wordsize);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_ES,rv);
	}
	if (target->arch->type == ARCH_X86
	    && !lstate->thread_struct_has_fs && lstate->pt_regs_has_fs_gs) {
	    uint32_t rv;
	    /* XXX: this is only true on newer x86 stuff; x86_64 and old
	     * i386 stuff did not save it on the stack.
	     */
	    rv = *(uint32_t *)(v->buf + 9 * target->arch->wordsize);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_FS,rv);
	}

	value_free(v);
	v = NULL;
    }
    else {
	/*
	 * Either we could not load pt_regs due to lack of type info; or
	 * this thread was just context-switched out, not interrupted
	 * nor preempted, so we can't get its GP registers.  Get what we
	 * can...
	 */

	if (target->arch->type == ARCH_X86) {
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_EIP,ltstate->eip);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_ESP,ltstate->esp);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_FS,ltstate->fs);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_GS,ltstate->gs);
	}
	else {
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_RIP,ltstate->eip);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_RSP,ltstate->esp);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_FS,ltstate->fs);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_GS,ltstate->gs);
	}

	/* eflags and ebp are on the stack. */
	v = target_load_addr_real(target,ltstate->esp,LOAD_FLAG_NONE,
				  target->arch->wordsize * 2);
	if (target->arch->wordsize == 8) {
	    ltstate->eflags = ((uint64_t *)v->buf)[1];
	    ltstate->ebp = ((uint64_t *)v->buf)[0];
	}
	else {
	    ltstate->eflags = ((uint32_t *)v->buf)[1];
	    ltstate->ebp = ((uint32_t *)v->buf)[0];
	}		
	value_free(v);
	v = NULL;

	if (target->arch->type == ARCH_X86) {
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_EFLAGS,ltstate->eflags);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_EBP,ltstate->ebp);
	}
	else {
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_RFLAGS,ltstate->eflags);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_RBP,ltstate->ebp);
	}
    }

    /*
     * Load the current debug registers from the thread.
     */
    if (lstate->thread_struct_has_debugreg) {
	v = target_load_value_member(target,tlctxt,
				     threadv,"debugreg",NULL,
				     LOAD_FLAG_AUTO_DEREF);
	if (!v) {
	    verror("could not load thread->debugreg for task %"PRIiTID"\n",tid);
	    goto errout;
	}
	if (target->arch->type == ARCH_X86_64) {
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_DR0,
					     ((uint64_t *)v->buf)[0]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_DR1,
					     ((uint64_t *)v->buf)[1]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_DR2,
					     ((uint64_t *)v->buf)[2]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_DR3,
					     ((uint64_t *)v->buf)[3]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_DR6,
					     ((uint64_t *)v->buf)[6]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_DR7,
					     ((uint64_t *)v->buf)[7]);
	}
	else {
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_DR0,
					     ((uint32_t *)v->buf)[0]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_DR1,
					     ((uint32_t *)v->buf)[1]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_DR2,
					     ((uint32_t *)v->buf)[2]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_DR3,
					     ((uint32_t *)v->buf)[3]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_DR6,
					     ((uint32_t *)v->buf)[6]);
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_DR7,
					     ((uint32_t *)v->buf)[7]);
	}
	value_free(v);
	v = NULL;
    }
    else if (lstate->thread_struct_has_debugreg0) {
	/*
	 * This is old x86_64 style.
	 */
	static const char *dregmembers[8] = {
	    "debugreg0","debugreg1","debugreg2","debugreg3",
	    NULL,NULL,
	    "debugreg6","debugreg7"
	};

	for (i = 0; i < 8; ++i) {
	    if (!dregmembers[i])
		continue;

	    v = target_load_value_member(target,tlctxt,
					 threadv,dregmembers[i],NULL,
					 LOAD_FLAG_AUTO_DEREF);
	    if (!v) {
		verror("could not load thread->%s for task %"PRIiTID"\n",
		       dregmembers[i],tid);
		goto errout;
	    }
	    if (target->arch->type == ARCH_X86_64) 
		target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
						 REG_X86_64_DR0 + i,
						 *(uint64_t *)v->buf);
	    else
		target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
						 REG_X86_DR0 + i,
						 *(uint32_t *)v->buf);
	    value_free(v);
	    v = NULL;
	}
    }
    else if (lstate->thread_struct_has_perf_debugreg) {
	/*
	 * XXX: still need to load perf_events 0-3.
	 */

	v = target_load_value_member(target,tlctxt,
				     threadv,"debugreg6",NULL,
				     LOAD_FLAG_AUTO_DEREF);
	if (!v) {
	    verror("could not load thread->debugreg6 for task %"PRIiTID"\n",tid);
	    goto errout;
	}
	if (target->arch->type == ARCH_X86_64) 
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_DR6,*(uint64_t *)v->buf);
	else
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_DR6,*(uint32_t *)v->buf);
	value_free(v);
	v = NULL;

	v = target_load_value_member(target,tlctxt,
				     threadv,"ptrace_dr7",NULL,
				     LOAD_FLAG_AUTO_DEREF);
	if (!v) {
	    verror("could not load thread->ptrace_dr7 for task %"PRIiTID"\n",tid);
	    goto errout;
	}
	if (target->arch->type == ARCH_X86_64) 
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_64_DR7,*(uint64_t *)v->buf);
	else
	    target_regcache_init_reg_tidctxt(target,tthread,ptregs_tidctxt,
					     REG_X86_DR7,*(uint32_t *)v->buf);
	value_free(v);
	v = NULL;

    }
    else {
	vwarn("could not load debugreg for tid %d; no debuginfo!\n",tid);
    }

    if (vdebug_is_on(4,LA_TARGET,LF_OSLINUX)) {
	REGVAL drs[8];
	if (target->arch->type == ARCH_X86_64) {
	    drs[0] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     ptregs_tidctxt,
						     REG_X86_64_DR0);
	    drs[1] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     ptregs_tidctxt,
						     REG_X86_64_DR1);
	    drs[2] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     ptregs_tidctxt,
						     REG_X86_64_DR2);
	    drs[3] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     ptregs_tidctxt,
						     REG_X86_64_DR3);
	    drs[6] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     ptregs_tidctxt,
						     REG_X86_64_DR6);
	    drs[7] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     ptregs_tidctxt,
						     REG_X86_64_DR7);
	}
	else {
	    drs[0] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     ptregs_tidctxt,
						     REG_X86_DR0);
	    drs[1] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     ptregs_tidctxt,
						     REG_X86_DR1);
	    drs[2] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     ptregs_tidctxt,
						     REG_X86_DR2);
	    drs[3] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     ptregs_tidctxt,
						     REG_X86_DR3);
	    drs[6] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     ptregs_tidctxt,
						     REG_X86_DR6);
	    drs[7] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     ptregs_tidctxt,
						     REG_X86_DR7);
	}

	vdebug(4,LA_TARGET,LF_OSLINUX,
	       "debug registers (context %d): 0x%"PRIxADDR",0x%"PRIxADDR
	       ",0x%"PRIxADDR",0x%"PRIxADDR",0,0,0x%"PRIxADDR",0x%"PRIxADDR"\n",
	       ptregs_tidctxt,drs[0],drs[1],drs[2],drs[3],drs[6],drs[7]);
    }

    if (v) 
	value_free(v);
    if (comm)
	free(comm);

    tthread->valid = 1;

    return tthread;

 errout:
    if (v) 
	value_free(v);
    if (comm)
	free(comm);
    if (threadinfov) 
	value_free(threadinfov);
    if (threadv)
	value_free(threadv);
    if (ltstate) {
	ltstate->thread_info = NULL;
	ltstate->thread_struct = NULL;
	ltstate->task_struct = NULL;
    }

    return NULL;
}

int os_linux_flush_current_thread(struct target *target) {
    struct target_thread *tthread;
    struct os_linux_thread_state *ltstate;
    struct value *v;
    tid_t tid;
    struct target_location_ctxt *tlctxt = target_global_tlctxt(target);

    if (!target->current_thread) {
	verror("current thread not loaded!\n");
	errno = EINVAL;
	return -1;
    }

    tthread = target->current_thread;
    tid = tthread->tid;
    ltstate = (struct os_linux_thread_state *)tthread->personality_state;

    vdebug(5,LA_TARGET,LF_OSLINUX,"tid %d thid %"PRIiTID"\n",target->id,tid);

    if (!tthread->valid || !tthread->dirty) {
	vdebug(8,LA_TARGET,LF_OSLINUX,
	       "tid %d thid %"PRIiTID" not valid (%d) or not dirty (%d)\n",
	       target->id,tid,tthread->valid,tthread->dirty);
	return 0;
    }

    vdebug(3,LA_TARGET,LF_OSLINUX,
	   "EIP is 0x%"PRIxREGVAL" before flush (tid %d thid %"PRIiTID")\n",
	   target_read_reg(target,TID_GLOBAL,target->ipregno),
	   target->id,tid);

    /*
     * Flush PCB state -- task_flags, thread_info_flags.
     *
     * NOTE: might not be able to flush this if the current thread is
     * the global thread...
     */
    if (ltstate->thread_info) {
	v = target_load_value_member(target,tlctxt,
				     ltstate->thread_info,"flags",NULL,
				     LOAD_FLAG_NONE);
	value_update_unum(v,ltstate->thread_info_flags);
	target_store_value(target,v);
	value_free(v);
    }

    /* Can only flush this if we weren't in interrupt context. */
    if (ltstate->task_struct) {
	v = target_load_value_member(target,tlctxt,
				     ltstate->task_struct,"flags",NULL,
				     LOAD_FLAG_NONE);
	value_update_unum(v,ltstate->task_flags);
	target_store_value(target,v);
	value_free(v);
    }

    /* Mark cached copy as clean. */
    tthread->dirty = 0;

    return 0;
}

int os_linux_flush_thread(struct target *target,tid_t tid) {
    struct os_linux_state *lstate =
	(struct os_linux_state *)target->personality_state;
    struct target_thread *tthread;
    struct os_linux_thread_state *ltstate = NULL;
    struct value *v;
    int ip_offset;
    int i;
    struct target_location_ctxt *tlctxt = target_global_tlctxt(target);
    REG reg;
    REGVAL regval;

    /*
     * Try to lookup thread @tid.
     */
    if ((tthread = target_lookup_thread(target,tid)))
	ltstate = (struct os_linux_thread_state *)tthread->personality_state;

    if (tthread == target->current_thread)
	return os_linux_flush_current_thread(target);

    if (!tthread) {
	verror("cannot flush unknown thread %"PRIiTID"; you forgot to load?\n",
	       tid);
	errno = EINVAL;
	return -1;
    }

    if (!tthread->valid || !tthread->dirty) {
	vdebug(8,LA_TARGET,LF_OSLINUX,
	       "target %d tid %"PRIiTID" not valid (%d) or not dirty (%d)\n",
	       target->id,tthread->tid,tthread->valid,tthread->dirty);
	return 0;
    }

    /*
     * Ok, we can finally flush this thread's state to memory.
     */

    /*
     * Flush (fake) Xen machine context loaded from stack, back to
     * stack.
     *
     * NB: this is a duplicate of the loading procedure!  See all the
     * comments there.
     */

    if (lstate->thread_ip_member_name) {
	v = target_load_value_member(target,tlctxt,
				     ltstate->thread_struct,
				     lstate->thread_ip_member_name,
				     NULL,LOAD_FLAG_NONE);
	if (!v) 
	    vwarn("could not store thread.%s for task %"PRIiTID"!\n",
		  lstate->thread_ip_member_name,tid);
	else {
	    value_update(v,(const char *)&ltstate->eip,v->bufsiz);
	    target_store_value(target,v);
	    value_free(v);
	    v = NULL;
	}
    }
    else {
	v = target_load_addr_real(target,ltstate->esp + 3 * target->arch->wordsize,
				  LOAD_FLAG_NONE,target->arch->wordsize);
	if (!v) 
	    vwarn("could not store 64-bit IP (thread.ip) for task %"PRIiTID"!\n",
		  tid);
	else {
	    value_update(v,(const char *)&ltstate->eip,v->bufsiz);
	    target_store_value(target,v);
	    value_free(v);
	    v = NULL;
	}
    }

    /*
     * GS is always in the thread data structure:
     */
    if (target->arch->type == ARCH_X86_64)
	reg = REG_X86_64_GS;
    else
	reg = REG_X86_GS;
    regval = 0;
    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					reg,&regval) == 1) {
	v = target_load_value_member(target,tlctxt,
				     ltstate->thread_struct,"gs",NULL,
				     LOAD_FLAG_NONE);
	value_update_unum(v,regval);
	target_store_value(target,v);
	value_free(v);
	v = NULL;
    }

    if (target->arch->type == ARCH_X86_64)
	reg = REG_X86_64_GS;
    else
	reg = REG_X86_GS;
    regval = 0;
    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					reg,&regval) == 1) {
	if (lstate->thread_struct_has_fs) {
	    v = target_load_value_member(target,tlctxt,
					 ltstate->thread_struct,"fs",NULL,
					 LOAD_FLAG_NONE);
	    if (!v) {
		vwarn("could not store thread.fs for task %"PRIiTID"!\n",tid);
		goto errout;
	    }
	    else {
		value_update(v,(const char *)&regval,v->bufsiz);
		target_store_value(target,v);
		value_free(v);
		v = NULL;
	    }
	}
	else {
	    /* Load this to pt_regs below if we can. */
	}
    }

    if (lstate->thread_struct_has_ds_es) {
	if (target->arch->type == ARCH_X86_64)
	    reg = REG_X86_64_DS;
	else
	    reg = REG_X86_DS;
	regval = 0;
	if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					    reg,&regval) == 1) {
	    v = target_load_value_member(target,tlctxt,
					 ltstate->thread_struct,"ds",NULL,
					 LOAD_FLAG_NONE);
	    if (!v) {
		vwarn("could not store thread.ds for task %"PRIiTID"!\n",tid);
		goto errout;
	    }
	    else {
		value_update(v,(const char *)&regval,v->bufsiz);
		target_store_value(target,v);
		value_free(v);
		v = NULL;
	    }
	}

	if (target->arch->type == ARCH_X86_64)
	    reg = REG_X86_64_ES;
	else
	    reg = REG_X86_ES;
	regval = 0;
	if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					    reg,&regval) == 1) {
	    v = target_load_value_member(target,tlctxt,
					 ltstate->thread_struct,"es",NULL,
					 LOAD_FLAG_NONE);
	    if (!v) {
		vwarn("could not store thread.es for task %"PRIiTID"!\n",tid);
		goto errout;
	    }
	    else {
		value_update(v,(const char *)&regval,v->bufsiz);
		target_store_value(target,v);
		value_free(v);
		v = NULL;
	    }
	}
	else {
	    /* Load this to pt_regs below if we can. */
	}
    }

    if (ltstate->ptregs_stack_addr) {
	v = target_load_addr_real(target,ltstate->ptregs_stack_addr,
				  LOAD_FLAG_NONE,
				  symbol_get_bytesize(lstate->pt_regs_type));
	if (!v) {
	    verror("could not store stack register save frame task %"PRIiTID"!\n",
		   tid);
	    goto errout;
	}

	/* Copy the first range. */
	if (target->arch->type == ARCH_X86_64) {
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_R15,&(((uint64_t *)v->buf)[0]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_R14,&(((uint64_t *)v->buf)[1]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_R13,&(((uint64_t *)v->buf)[2]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_R12,&(((uint64_t *)v->buf)[3]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_RBP,&(((uint64_t *)v->buf)[4]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_RBX,&(((uint64_t *)v->buf)[5]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_R11,&(((uint64_t *)v->buf)[6]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_R10,&(((uint64_t *)v->buf)[7]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_R9,&(((uint64_t *)v->buf)[8]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_R8,&(((uint64_t *)v->buf)[9]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_RAX,&(((uint64_t *)v->buf)[10]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_RCX,&(((uint64_t *)v->buf)[11]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_RDX,&(((uint64_t *)v->buf)[12]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_RSI,&(((uint64_t *)v->buf)[13]));
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
				     REG_X86_64_RDI,&(((uint64_t *)v->buf)[14]));
	}
	else {
	    REGVAL rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_EBX,&rv) == 1)
		((uint32_t *)v->buf)[0] = (uint32_t)rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_ECX,&rv) == 1)
		((uint32_t *)v->buf)[1] = (uint32_t)rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_EDX,&rv) == 1)
		((uint32_t *)v->buf)[2] = (uint32_t)rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_ESI,&rv) == 1)
		((uint32_t *)v->buf)[3] = (uint32_t)rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_EDI,&rv) == 1)
		((uint32_t *)v->buf)[4] = (uint32_t)rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_EBP,&rv) == 1)
		((uint32_t *)v->buf)[5] = (uint32_t)rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_EAX,&rv) == 1)
		((uint32_t *)v->buf)[6] = (uint32_t)rv;
	}
	/*
	if (target->arch->wordsize == 8)
	    memcpy(v->buf,&ltstate->context.user_regs,8 * 15);
	else
	    memcpy(v->buf,&ltstate->context.user_regs,4 * 7);
	*/

	/* Copy the second range. */
	/**
	 ** WARNING: esp and ss may not be valid if the sleeping thread was
	 ** interrupted while it was in the kernel, because the interrupt
	 ** gate does not push ss and esp; see include/asm-i386/processor.h .
	 **/
	//ADDR ssp;
	int ip_offset = lstate->pt_regs_ip_offset;
	if (__WORDSIZE == 64 || target->arch->wordsize == 8) {
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					    REG_X86_64_RIP,
					    ((uint64_t *)(v->buf + ip_offset)) + 0);
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					    REG_X86_64_CS,
					    ((uint64_t *)(v->buf + ip_offset)) + 1);
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					    REG_X86_64_RFLAGS,
					    ((uint64_t *)(v->buf + ip_offset)) + 2);
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					    REG_X86_64_RSP,
					    ((uint64_t *)(v->buf + ip_offset)) + 3);
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					    REG_X86_64_SS,
					    ((uint64_t *)(v->buf + ip_offset)) + 4);
	}
	else {
	    REGVAL rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_EIP,&rv) == 1)
		((uint32_t *)(v->buf + ip_offset))[0] = (uint32_t)rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_CS,&rv) == 1)
		((uint32_t *)(v->buf + ip_offset))[1] = (uint32_t)rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_EFLAGS,&rv) == 1)
		((uint32_t *)(v->buf + ip_offset))[2] = (uint32_t)rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_ESP,&rv) == 1)
		((uint32_t *)(v->buf + ip_offset))[3] = (uint32_t)rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_SS,&rv) == 1)
		((uint32_t *)(v->buf + ip_offset))[4] = (uint32_t)rv;
	}

	/*
	 * ds, es, fs, gs are all special; see other comments.
	 */
	if (target->arch->type == ARCH_X86
	    && !lstate->thread_struct_has_ds_es && lstate->pt_regs_has_ds_es) {
	    REGVAL rv;
	    /* XXX: this works because we know the location of (x)ds/es;
	     * it's only on i386/x86; and because Xen pads its
	     * cpu_user_regs structs from u16s to ulongs for segment
	     * registers.  :)
	     */
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_DS,&rv) == 1)
		*(uint32_t *)(v->buf + 7 * target->arch->wordsize) = (uint32_t)rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_ES,&rv) == 1)
		*(uint32_t *)(v->buf + 8 * target->arch->wordsize) = (uint32_t)rv;
	}
	if (target->arch->type == ARCH_X86
	    && !lstate->thread_struct_has_fs && lstate->pt_regs_has_fs_gs) {
	    REGVAL rv;
	    /* XXX: this is only true on newer x86 stuff; x86_64 and old
	     * i386 stuff did not save it on the stack.
	     */
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_FS,&rv) == 1)
		*(uint32_t *)(v->buf + 9 * target->arch->wordsize) = (uint32_t)rv;
	}

	target_store_value(target,v);

	value_free(v);
	v = NULL;
    }
    else {
	/*
	 * Either we could not load pt_regs due to lack of type info; or
	 * this thread was just context-switched out, not interrupted
	 * nor preempted, so we can't get its GP registers.  Get what we
	 * can...
	 */

	/** XXX: what the heck??
	memset(&ltstate->context,0,sizeof(vcpu_guest_context_t));
	ltstate->context.user_regs.eip = ltstate->eip;
	ltstate->context.user_regs.esp = ltstate->esp;
	ltstate->context.user_regs.fs = ltstate->fs;
	ltstate->context.user_regs.gs = ltstate->gs;
	*/

	/* eflags and ebp are on the stack. */
	v = target_load_addr_real(target,ltstate->esp,LOAD_FLAG_NONE,
				  2 * target->arch->wordsize);
	if (target->arch->wordsize == 8) {
	    ((uint64_t *)v->buf)[1] = ltstate->eflags;
	    ((uint64_t *)v->buf)[0] = ltstate->ebp;
	}
	else {
	    ((uint32_t *)v->buf)[1] = ltstate->eflags;
	    ((uint32_t *)v->buf)[0] = ltstate->ebp;
	}

	target_store_value(target,v);

	value_free(v);
	v = NULL;
    }


    
    if (lstate->thread_struct_has_debugreg) {
	v = target_load_value_member(target,tlctxt,
				     ltstate->thread_struct,"debugreg",
				     NULL,LOAD_FLAG_AUTO_DEREF);
	if (!v) {
	    verror("could not store thread->debugreg for task %"PRIiTID"\n",tid);
	    goto errout;
	}
	if (target->arch->type == ARCH_X86_64) {
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					     REG_X86_64_DR0,
					     ((uint64_t *)v->buf) + 0);
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					     REG_X86_64_DR1,
					     ((uint64_t *)v->buf) + 1);
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					     REG_X86_64_DR2,
					     ((uint64_t *)v->buf) + 2);
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					     REG_X86_64_DR3,
					     ((uint64_t *)v->buf) + 3);
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					     REG_X86_64_DR6,
					     ((uint64_t *)v->buf) + 6);
	    target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					     REG_X86_64_DR7,
					     ((uint64_t *)v->buf) + 7);
	}
	else {
	    REGVAL rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_DR0,&rv) == 1)
		((uint32_t *)v->buf)[0] = rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_DR1,&rv) == 1)
		((uint32_t *)v->buf)[1] = rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_DR2,&rv) == 1)
		((uint32_t *)v->buf)[2] = rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_DR3,&rv) == 1)
		((uint32_t *)v->buf)[3] = rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_DR6,&rv) == 1)
		((uint32_t *)v->buf)[6] = rv;
	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						REG_X86_DR7,&rv) == 1)
		((uint32_t *)v->buf)[7] = rv;
	}

	target_store_value(target,v);

	value_free(v);
	v = NULL;
    }
    else if (lstate->thread_struct_has_debugreg0) {
	/*
	 * This is old x86_64 style.
	 */
	static const char *dregmembers[8] = {
	    "debugreg0","debugreg1","debugreg2","debugreg3",
	    NULL,NULL,
	    "debugreg6","debugreg7"
	};

	REG reg;
	REGVAL rv;
	if (target->arch->type == ARCH_X86_64)
	    reg = REG_X86_64_DR0;
	else
	    reg = REG_X86_DR0;
	for (i = 0; i < 8; ++i) {
	    if (!dregmembers[i])
		continue;

	    if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
						reg + i,&rv) < 1)
		continue;

	    v = target_load_value_member(target,tlctxt,
					 ltstate->thread_struct,
					 dregmembers[i],NULL,
					 LOAD_FLAG_AUTO_DEREF);
	    if (!v) {
		verror("could not store thread->%s for task %"PRIiTID"\n",
		       dregmembers[i],tid);
		goto errout;
	    }
	    if (target->arch->type == ARCH_X86_64)
		*(uint64_t *)v->buf = rv;
	    else
		*(uint32_t *)v->buf = (uint32_t)rv;

	    target_store_value(target,v);

	    value_free(v);
	    v = NULL;
	}
    }
    else if (lstate->thread_struct_has_perf_debugreg) {
	/*
	 * XXX: still need to store perf_events 0-3.
	 */
	REG reg;
	REGVAL rv;

	if (target->arch->type == ARCH_X86_64)
	    reg = REG_X86_64_DR6;
	else
	    reg = REG_X86_DR6;
	if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					    reg,&rv) == 1) {
	    v = target_load_value_member(target,tlctxt,
					 ltstate->thread_struct,"debugreg6",
					 NULL,LOAD_FLAG_AUTO_DEREF);
	    if (!v) {
		verror("could not store thread->debugreg6 for task %"PRIiTID"\n",
		       tid);
		goto errout;
	    }
	    if (target->arch->type == ARCH_X86_64)
		*(uint64_t *)v->buf = rv;
	    else
		*(uint32_t *)v->buf = rv;

	    target_store_value(target,v);

	    value_free(v);
	    v = NULL;
	}

	if (target->arch->type == ARCH_X86_64)
	    reg = REG_X86_64_DR7;
	else
	    reg = REG_X86_DR7;
	if (target_regcache_readreg_ifdirty(target,tthread,tthread->tidctxt,
					    reg,&rv) == 1) {
	    v = target_load_value_member(target,tlctxt,
					 ltstate->thread_struct,"ptrace_dr7",
					 NULL,LOAD_FLAG_AUTO_DEREF);
	    if (!v) {
		verror("could not store thread->ptrace_dr7 for task %"PRIiTID"\n",
		       tid);
		goto errout;
	    }
	    if (target->arch->type == ARCH_X86_64)
		*(uint64_t *)v->buf = rv;
	    else
		*(uint32_t *)v->buf = (uint32_t)rv;

	    target_store_value(target,v);

	    value_free(v);
	    v = NULL;
	}
    }
    else {
	vwarn("could not store debugreg for tid %d; no debuginfo!\n",tid);
    }

    /*
     * Flush PCB state -- task_flags, thread_info_flags.
     */
    v = target_load_value_member(target,tlctxt,
				 ltstate->thread_info,"flags",NULL,
				 LOAD_FLAG_NONE);
    value_update_unum(v,ltstate->thread_info_flags);
    target_store_value(target,v);
    value_free(v);

    /* Can only flush this if we weren't in interrupt context. */
    if (ltstate->task_struct) {
	v = target_load_value_member(target,tlctxt,
				     ltstate->task_struct,"flags",NULL,
				     LOAD_FLAG_NONE);
	value_update_unum(v,ltstate->task_flags);
	target_store_value(target,v);
	value_free(v);
    }

    tthread->dirty = 0;

    return 0;

 errout:
    return -1;

}

int os_linux_invalidate_thread(struct target *target,
			       struct target_thread *tthread) {
    struct os_linux_thread_state *ltstate;

    vdebug(5,LA_TARGET,LF_OSLINUX,"target %d thid %d\n",target->id,tthread->tid);

    ltstate = (struct os_linux_thread_state *)tthread->personality_state;

    //if (!tthread->valid) 
    //    continue;

    if (ltstate->thread_struct) {
	value_free(ltstate->thread_struct);
	ltstate->thread_struct = NULL;
    }
    if (ltstate->thread_info) {
	value_free(ltstate->thread_info);
	ltstate->thread_info = NULL;
    }
    if (ltstate->task_struct) {
	value_free(ltstate->task_struct);
	ltstate->task_struct = NULL;
    }

    tthread->valid = 0;

    return 0;
}

int os_linux_thread_snprintf(struct target_thread *tthread,
			     char *buf,int bufsiz,
			     int detail,char *sep,char *kvsep) {
    struct os_linux_thread_state *ltstate;
    int rc = 0;
    struct target *target = tthread->target;
    int nrc;
    thread_ctxt_t othertidctxt;

    if (detail < 0)
	return 0;

    ltstate = (struct os_linux_thread_state *)tthread->personality_state;

    if (detail >= 0) {
	rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
		       (rc >= bufsiz) ? 0 : bufsiz - rc,
		       "%stgid%s%"PRIiNUM "%s" "task_flags%s0x%"PRIxNUM "%s"
		       "thread_info_flags%s0x%"PRIxNUM "%s"
		       "preempt_count%s0x%"PRIiNUM "%s"
		       "task%s0x%"PRIxADDR "%s" 
		       "stack_base%s0x%"PRIxADDR "%s" 
		       "pgd%s0x%"PRIx64 "%s" "mm%s0x%"PRIxADDR,
		       sep,
		       kvsep,ltstate->tgid,sep,kvsep,ltstate->task_flags,sep,
		       kvsep,ltstate->thread_info_flags,sep,
		       kvsep,ltstate->thread_info_preempt_count,sep,
		       kvsep,ltstate->task_struct ? value_addr(ltstate->task_struct) : 0x0UL,sep,
		       kvsep,ltstate->stack_base,sep,
		       kvsep,ltstate->pgd,sep,kvsep,ltstate->mm_addr);
    }

    /*
     * If this thread was not the current thread, assume we loaded all
     * its contexts' states from memory -- so print both contexts.
     * Otherwise, print 
     */
    if (tthread != target->current_thread && tthread != target->global_thread) {
	nrc = target_regcache_snprintf(target,tthread,tthread->tidctxt,
				       (rc >= bufsiz) ? NULL : buf + rc,
				       (rc >= bufsiz) ? 0 : bufsiz - rc,
				       detail,sep,kvsep,0);
	if (nrc < 0)
	    return nrc;
	else
	    rc += nrc;
    }

    /*
     * We always loaded the non-current context from memory as much as
     * possible, so print that here.
     */
    if (tthread->tidctxt == THREAD_CTXT_KERNEL)
	othertidctxt = THREAD_CTXT_USER;
    else
	othertidctxt = THREAD_CTXT_KERNEL;
    nrc = target_regcache_snprintf(target,tthread,othertidctxt,
				   (rc >= bufsiz) ? NULL : buf + rc,
				   (rc >= bufsiz) ? 0 : bufsiz - rc,
				   detail,sep,kvsep,0);
    if (nrc < 0)
	return nrc;
    else
	rc += nrc;

    return rc;
}

/**
 ** The arch-based thread snprintf is slower, so keep this older version
 ** around for now, but don't build it.
 **/
#if 0
#if __WORDSIZE == 64
#define RF "lx"
#define RIF "lu"
#define DRF "lx"
#else
#define RF "x"
#define RIF "u"
#define DRF "lx"
#endif

int os_linux_thread_snprintf(struct target_thread *tthread,
			     char *buf,int bufsiz,
			     int detail,char *sep,char *kvsep) {
    struct os_linux_thread_state *ltstate;
    int rc = 0;
    struct target *target = tthread->target;
    int nrc;

    if (detail < 0)
	return 0;

    ltstate = (struct os_linux_thread_state *)tthread->personality_state;

    if (detail >= 0) {
	rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
		       (rc >= bufsiz) ? 0 :bufsiz - rc,
		       "tgid%s%"PRIiNUM "%s" "task_flags%s0x%"PRIxNUM "%s"
		       "thread_info_flags%s0x%"PRIxNUM "%s"
		       "preempt_count%s0x%"PRIiNUM "%s"
		       "task%s0x%"PRIxADDR "%s" 
		       "stack_base%s0x%"PRIxADDR "%s" 
		       "pgd%s0x%"PRIx64 "%s" "mm%s0x%"PRIxADDR,
		       kvsep,ltstate->tgid,sep,kvsep,ltstate->task_flags,sep,
		       kvsep,ltstate->thread_info_flags,sep,
		       kvsep,ltstate->thread_info_preempt_count,sep,
		       kvsep,ltstate->task_struct ? value_addr(ltstate->task_struct) : 0x0UL,sep,
		       kvsep,ltstate->stack_base,sep,
		       kvsep,ltstate->pgd,sep,kvsep,ltstate->mm_addr);
    }

    if (detail >= 1)
	rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
		       (rc >= bufsiz) ? 0 :bufsiz - rc,
		       "%s" "ip%s%"RF "%s" "bp%s%"RF "%s" "sp%s%"RF "%s" 
		       "flags%s%"RF "%s" "ax%s%"RF "%s" "bx%s%"RF "%s"
		       "cx%s%"RF "%s" "dx%s%"RF "%s" "di%s%"RF "%s" 
		       "si%s%"RF "%s" "cs%s%"RIF "%s" "ss%s%"RIF "%s"
		       "ds%s%"RIF "%s" "es%s%"RIF "%s"
		       "fs%s%"RF "%s" "gs%s%"RF,
#if __WORDSIZE == 64
		       sep,kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_RIP),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_RBP),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_RSP),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_RFLAGS),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_RAX),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_RBX),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_RCX),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_RDX),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_RDI),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_RSI),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_CS),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_SS),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_DS),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_ES),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_FS),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_64_GS)
#else
		       sep,kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_EIP),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_EBP),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_ESP),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_EFLAGS),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_EAX),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_EBX),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_ECX),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_EDX),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_EDI),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_ESI),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_CS),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_SS),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_DS),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_ES),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_FS),sep,
		       kvsep,target_regcache_readreg_tidctxt(target,tthread->tid,tthread->tidctxt,REG_X86_GS)
#endif
		       );
    if (detail >= 2) {
	REGVAL drs[8];
	if (target->arch->type == ARCH_X86_64) {
	    drs[0] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     tthread->tidctxt,
						     REG_X86_64_DR0);
	    drs[1] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     tthread->tidctxt,
						     REG_X86_64_DR1);
	    drs[2] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     tthread->tidctxt,
						     REG_X86_64_DR2);
	    drs[3] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     tthread->tidctxt,
						     REG_X86_64_DR3);
	    drs[6] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     tthread->tidctxt,
						     REG_X86_64_DR6);
	    drs[7] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     tthread->tidctxt,
						     REG_X86_64_DR7);
	}
	else {
	    drs[0] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     tthread->tidctxt,
						     REG_X86_DR0);
	    drs[1] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     tthread->tidctxt,
						     REG_X86_DR1);
	    drs[2] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     tthread->tidctxt,
						     REG_X86_DR2);
	    drs[3] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     tthread->tidctxt,
						     REG_X86_DR3);
	    drs[6] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     tthread->tidctxt,
						     REG_X86_DR6);
	    drs[7] = target_regcache_readreg_tidctxt(target,tthread->tid,
						     tthread->tidctxt,
						     REG_X86_DR7);
	}

	rc += snprintf((rc >= bufsiz) ? NULL : buf + rc,
		       (rc >= bufsiz) ? 0 :bufsiz - rc,
		       "%s" "dr0%s%"DRF "%s" "dr1%s%"DRF 
		       "%s" "dr2%s%"DRF "%s" "dr3%s%"DRF 
		       "%s" "dr6%s%"DRF "%s" "dr7%s%"DRF,
		       sep,kvsep,drs[0],sep,kvsep,drs[1],
		       sep,kvsep,drs[1],sep,kvsep,drs[2],
		       sep,kvsep,drs[6],sep,kvsep,drs[7]);
    }

    return rc;
}
#endif /* 0 */

/**
 ** Active thread/memory probing.
 **/

struct __update_module_data {
    struct addrspace *space;
    struct memregion *region;
    GHashTable *moddep;
    GHashTable *config;
};

static int __update_module(struct target *target,struct value *value,void *data) {
    struct value *mod_name = NULL;
    struct value *vt = NULL;
    ADDR mod_core_addr;
    ADDR mod_init_addr;
    unum_t mod_core_size;
    unum_t mod_init_size;
    struct __update_module_data *ud = (struct __update_module_data *)data;
    struct list_head *pos;
    struct memregion *tregion = NULL;
    struct memrange *range;
    char *modfilename = NULL;
    int retval;
    struct binfile_instance *bfi = NULL;
    struct debugfile *debugfile = NULL;
    struct addrspace *space = ud->space;
    struct target_location_ctxt *tlctxt = target_global_tlctxt(target);

    if (!ud) {
	errno = EINVAL;
	return -1;
    }

    mod_name = target_load_value_member(target,tlctxt,
					value,"name",NULL,LOAD_FLAG_NONE);
    if (!mod_name) {
	verror("could not load name for module!\n");
	goto errout;
    }

    vt = target_load_value_member(target,tlctxt,
				  value,"module_core",NULL,LOAD_FLAG_NONE);
    if (!vt) {
	verror("could not load module_core addr!\n");
	goto errout;
    }
    mod_core_addr = v_addr(vt);
    value_free(vt);

    vt = target_load_value_member(target,tlctxt,
				  value,"module_init",NULL,LOAD_FLAG_NONE);
    if (!vt) {
	verror("could not load module_init addr!\n");
	goto errout;
    }
    mod_init_addr = v_addr(vt);
    value_free(vt);

    vt = target_load_value_member(target,tlctxt,
				  value,"core_size",NULL,LOAD_FLAG_NONE);
    if (!vt) {
	verror("could not load module core_size!\n");
	goto errout;
    }
    mod_core_size = v_unum(vt);
    value_free(vt);

    vt = target_load_value_member(target,tlctxt,
				  value,"init_size",NULL,LOAD_FLAG_NONE);
    if (!vt) {
	verror("could not load module init_size!\n");
	goto errout;
    }
    mod_init_size = v_unum(vt);
    value_free(vt);

    vdebug(2,LA_TARGET,LF_OSLINUX,
	   "module %s (core=0x%"PRIxADDR"(%u),init=0x%"PRIxADDR"(%u))\n",
	   v_string(mod_name),mod_core_addr,(unsigned)mod_core_size,
	   mod_init_addr,(unsigned)mod_init_size);

    if (!ud->moddep) {
	vwarnopt(8,LA_TARGET,LF_OSLINUX,
		 "no moddep info for %s; cannot load binfile info!\n",
		 v_string(mod_name));
    }
    else {
	modfilename = g_hash_table_lookup(ud->moddep,v_string(mod_name));
	if (!modfilename) {
	    vwarnopt(8,LA_TARGET,LF_OSLINUX,
		     "no moddep info for %s; cannot load binfile info!\n",
		     v_string(mod_name));
	}
    }

    list_for_each(pos,&space->regions) {
	tregion = list_entry(pos,typeof(*tregion),region);
	if (strcmp(tregion->name,
		   (modfilename) ? modfilename : v_string(mod_name)) == 0) {
	    if (tregion->base_load_addr == mod_core_addr)
		break;
	}
	tregion = NULL;
    }

    if (tregion) {
	tregion->exists = 1;
    }
    else {
	/*
	 * Create a new one!  Anything could have happened.
	 */
	tregion = memregion_create(ud->space,REGION_TYPE_LIB,
				   (modfilename) ? strdup(modfilename) \
				                 : strdup(v_string(mod_name)));
	tregion->new = 1;

	/*
	 * Create a new range for the region.
	 */
	range = memrange_create(tregion,mod_core_addr,
				mod_core_addr + mod_core_size,0,0);
	if (!range) {
	    verror("could not create range for module addr 0x%"PRIxADDR"!\n",
		   mod_core_addr);
	    retval = -1;
	    goto errout;
	}

	if (modfilename) {
	    /*
	     * Load its debuginfo.
	     */
	    bfi = binfile_infer_instance(tregion->name,
					 target->spec->debugfile_root_prefix,
					 mod_core_addr,target->config);
	    if (!bfi) {
		verror("could not infer instance for module %s!\n",tregion->name);
		retval = -1;
		goto errout;
	    }

	    debugfile = 
		debugfile_from_instance(bfi,target->spec->debugfile_load_opts_list);
	    if (!debugfile) {
		retval = -1;
		goto errout;
	    }

	    if (target_associate_debugfile(target,tregion,debugfile)) {
		retval = -1;
		goto errout;
	    }

	    /* The debugfile, etc, hold it now; we don't care. */
	    binfile_instance_release(bfi);
	    bfi = NULL;
	}
    }

    ud->region = tregion;
    retval = 0;

    if (mod_name)
	value_free(mod_name);

    return retval;

 errout:
    if (mod_name)
	value_free(mod_name);
    if (debugfile)
	debugfile_release(debugfile);
    if (bfi)
	binfile_instance_release(bfi);
    if (tregion)
	memregion_free(tregion);

    return retval;
}

static int os_linux_reload_modules_dep(struct target *target) {
    struct os_linux_state *lstate = \
	(struct os_linux_state *)target->personality_state;
    GHashTable *moddep = NULL;
    FILE *moddep_file;
    char moddep_path[PATH_MAX];
    char buf[PATH_MAX * 2];
    char *colon;
    char *slash;
    char *newline;
    char *extension;
    char *modname;
    char *modfilename;
    struct stat statbuf;
    time_t moddep_mtime;

    snprintf(moddep_path,PATH_MAX,"%s/modules.dep",lstate->kernel_module_dir);

    /*
     * Stat it and see if our cached copy (if there is one) is still
     * valid.
     */
    if (stat(moddep_path,&statbuf)) {
	vwarnopt(8,LA_TARGET,LF_OSLINUX,
		 "stat(%s): %s; aborting!\n",moddep_path,strerror(errno));
	return -1;
    }
    moddep_mtime = statbuf.st_mtime;

    if (lstate->moddep && lstate->last_moddep_mtime == moddep_mtime) {
	vdebug(16,LA_TARGET,LF_OSLINUX,
	       "cached moddep is valid\n");
	return 0;
    }

    /*
     * Read the current modules.dep file and build up the name->file map.
     */
    if (!(moddep_file = fopen(moddep_path,"r"))) {
	verror("fopen(%s): %s\n",moddep_path,strerror(errno));
	return -1;
    }

    moddep = g_hash_table_new_full(g_str_hash,g_str_equal,free,free);

    while (fgets(buf,sizeof(buf),moddep_file)) {
	newline = index(buf,'\n');

	/*
	 * Find lines starting with "<module_filename>:", and split them
	 * into a map of <module_name> -> <module_filename>
	 */
	if (!(colon = index(buf,':'))) 
	    goto drain;

	*colon = '\0';
	if (!(slash = rindex(buf,'/'))) 
	    goto drain;

	/* Check relative and abs paths. */
	modfilename = strdup(buf);
	if (stat(modfilename,&statbuf)) {
	    vwarnopt(8,LA_TARGET,LF_OSLINUX,
		     "could not find modules.dep file %s; trying abs path\n",
		     modfilename);
	    free(modfilename);

	    modfilename = calloc(1,sizeof(char)*(strlen(lstate->kernel_module_dir)
						 +1+strlen(buf)+1));
	    sprintf(modfilename,"%s/%s",lstate->kernel_module_dir,buf);
	    if (stat(modfilename,&statbuf)) {
		vwarnopt(7,LA_TARGET,LF_OSLINUX,
			 "could not find modules.dep file %s at all!\n",
			 modfilename);
		free(modfilename);
		modfilename = NULL;
		goto drain;
	    }
	}
	/* If we have one, insert it. */
	if (modfilename) {
	    modname = strdup(slash+1);
	    if ((extension = rindex(modname,'.')))
		*extension = '\0';

	    g_hash_table_insert(moddep,modname,modfilename);

	    vdebug(8,LA_TARGET,LF_OSLINUX,
		   "modules.dep: %s -> %s\n",modname,modfilename);
	}

	/*
	 * Drain until we get a newline.
	 */
    drain:
	if (!newline) {
	    while (fgets(buf,sizeof(buf),moddep_file)) {
		if (index(buf,'\n'))
		    break;
	    }
	}
    }
    fclose(moddep_file);

    /*
     * Update our cache.
     */
    if (lstate->moddep)
	g_hash_table_destroy(lstate->moddep);
    lstate->moddep = moddep;
    lstate->last_moddep_mtime = moddep_mtime;

    vdebug(5,LA_TARGET,LF_OSLINUX,
	   "updated modules.dep cache (%d entries from %s)\n",
	   g_hash_table_size(lstate->moddep),moddep_path);

    return 0;
}

/*
 * Only called if active memory probing is disabled, or if it fails.
 */
static int os_linux_updateregions(struct target *target,
				  struct addrspace *space) {
    struct os_linux_state *lstate = \
	(struct os_linux_state *)target->personality_state;
    struct __update_module_data ud;
    struct memregion *region,*tregion;
    struct memrange *range,*trange;

    vdebug(5,LA_TARGET,LF_OSLINUX,"target %d\n",target->id);

    /*
     * We never update the main kernel region.  Instead, we update the
     * module subregions as needed.
     *
     * XXX: in this first version, we don't worry about module init
     * sections that can be removed after the kernel initializes the
     * module.
     */

    if (!lstate->module_type || !lstate->modules || !lstate->kernel_module_dir) {
	/*	
	 * Don't return an error; would upset target_open.
	 */
	return 0;
    }

    if (os_linux_reload_modules_dep(target)) 
	vwarnopt(8,LF_TARGET,LF_OSLINUX,
		 "failed to reload modules.dep; trying to continue!\n");

    ud.space = space;
    ud.moddep = lstate->moddep;

    /*
     * Clear out the current modules region bits.
     *
     * We don't bother checking ranges.  No need.
     */
    list_for_each_entry(region,&space->regions,region) {
	if (region->type == REGION_TYPE_LIB) {
	    region->exists = 0;
	    region->new = 0;
	}
    }

    /*
     * Handle the modules via callback via iterator.
     */
    os_linux_list_for_each_entry(target,lstate->module_type,lstate->modules,
				 "list",0,__update_module,&ud);

    /*
     * Now, for all the regions, check if they were newly added
     * or still exist; if none of those, then they vanished
     * and we have to purge them.
     */

    list_for_each_entry_safe(region,tregion,&space->regions,region) {
	/* Skip anything not a kernel module. */
	if (region->type != REGION_TYPE_LIB)
	    continue;

	if (!region->exists && !region->new) {
	    list_for_each_entry_safe(range,trange,&region->ranges,range) {
		vdebug(3,LA_TARGET,LF_OSLINUX,
		       "removing stale range 0x%"PRIxADDR"-0x%"PRIxADDR":%"PRIiOFFSET"\n",
		       range->start,range->end,range->offset);

		target_add_state_change(target,TID_GLOBAL,
					TARGET_STATE_CHANGE_RANGE_DEL,
					0,range->prot_flags,
					range->start,range->end,region->name);
		memrange_free(range);
	    }

	    vdebug(3,LA_TARGET,LF_OSLINUX,"removing stale region (%s:%s:%s)\n",
		   region->space->idstr,region->name,REGION_TYPE(region->type));

	    target_add_state_change(target,TID_GLOBAL,
				    TARGET_STATE_CHANGE_REGION_DEL,
				    0,0,region->base_load_addr,0,region->name);
	    memregion_free(region);
	}
	else if (region->new) {
	    list_for_each_entry_safe(range,trange,&region->ranges,range) {
		vdebug(3,LA_TARGET,LF_LUP,
		       "new range 0x%"PRIxADDR"-0x%"PRIxADDR":%"PRIiOFFSET"\n",
		       range->start,range->end,range->offset);

		target_add_state_change(target,TID_GLOBAL,
					TARGET_STATE_CHANGE_RANGE_NEW,
					0,range->prot_flags,
					range->start,range->end,region->name);
	    }

	    target_add_state_change(target,TID_GLOBAL,
				    TARGET_STATE_CHANGE_REGION_NEW,
				    0,0,region->base_load_addr,0,region->name);
	}

	region->new = region->exists = 0;
    }

    return 0;
}

result_t os_linux_active_memory_handler(struct probe *probe,tid_t tid,
					void *handler_data,
					struct probe *trigger,
					struct probe *base) {
    struct target *target;
    struct os_linux_state *lstate;
    struct value *mod = NULL;
    struct addrspace *space;
    int state = -1;
    struct __update_module_data ud;
    char *modfilename;
    struct list_head *pos;
    struct memregion *region;
    struct memrange *range,*trange;
    char *name;
    struct value *name_value = NULL;
    struct target_location_ctxt *tlctxt;

    target = probe->target;
    tlctxt = target_global_tlctxt(target);
    lstate = (struct os_linux_state *)target->personality_state;
    space = list_entry(target->spaces.next,typeof(*space),space);

    /*
     * For kernels that have do_init_module(), we can simply place a
     * probe on the entry of that function.  If we cannot read the first
     * arg, the module is already on the list, so just scan the list
     * manually.
     *
     * For older kernels, it is not as good.  We cannot catch the
     * incoming module once it is guaranteed to be on the list UNLESS we
     * use return probes on one of a few functions (__link_module would
     * work), but that requires disasm, which we want to avoid.
     *
     * So -- the only strategy that works for all kernels is to place a
     * probe on module_free(), and look at both the addr being freed,
     * and the module->state field.  If ->state is MODULE_STATE_LIVE,
     * we know the module is new.  If mod->state is MODULE_STATE_GOING,
     * we know the module is being removed (or failed to initialize).
     * If mod->state is MODULE_STATE_COMING, we know the module failed
     * to initialize.
     *
     * This way, if we fail to load module_free's mod arg -- we can just
     * rescan the list.  By the time this function is called, whether
     * the module is coming or going, the module is either on the list
     * or off it.
     *
     * NB: module_free is called multiple times per module (for the
     * init_text section, and the core_text section).  So, we just
     * handle those cases and ignore them.
     *
     *   NB: we *could* utilize this to track the presence/absence of
     *   the init_text section too; but we don't for now.
     */

    /*
     * Load mod.
     */
    mod = target_load_symbol(target,tlctxt,
			     lstate->module_free_mod_symbol,LOAD_FLAG_AUTO_DEREF);
    if (!mod) {
	/*
	 * Again, the module is either on the list if it's coming; or
	 * off the list if it's going.  By the time module_free is
	 * called, its state is known based on whether it is on the list
	 * or off the list.
	 *
	 * So, it is safe to manually update regions.
	 */
	vwarn("could not load mod in module_free; manually updating"
	      " modules!\n");
	goto manual_update;
    }

    /*
     * Load mod->state, so we know what is happening.
     */
    VLV(target,tlctxt,mod,"state",LOAD_FLAG_NONE,&state,NULL,
	err_vmiload_state);

    /*
     * Update modules.dep, just in case; don't worry if it fails, just
     * do our best.
     */
    os_linux_reload_modules_dep(target);

    if (state == lstate->MODULE_STATE_LIVE) {
	ud.space = space;
	ud.moddep = lstate->moddep;

	__update_module(target,mod,&ud);
	region = ud.region;

	list_for_each_entry_safe(range,trange,&region->ranges,range) {
	    vdebug(3,LA_TARGET,LF_LUP,
		   "new range 0x%"PRIxADDR"-0x%"PRIxADDR":%"PRIiOFFSET"\n",
		   range->start,range->end,range->offset);

	    target_add_state_change(target,TID_GLOBAL,
				    TARGET_STATE_CHANGE_RANGE_NEW,
				    0,range->prot_flags,
				    range->start,range->end,region->name);
	}

	target_add_state_change(target,TID_GLOBAL,
				TARGET_STATE_CHANGE_REGION_NEW,
				0,0,region->base_load_addr,0,region->name);
    }
    else if (state == lstate->MODULE_STATE_COMING
	     || state == lstate->MODULE_STATE_GOING) {
	/*
	 * Look up and destroy it if it's one of our regions.
	 */
	VLV(target,tlctxt,mod,"name",LOAD_FLAG_AUTO_STRING,
	    NULL,&name_value,err_vmiload_name);
	name = v_string(name_value);

	modfilename = g_hash_table_lookup(lstate->moddep,name);
	if (!modfilename) {
	    verror("could not find modfilename for module '%s'; aborting to"
		   " manual update!\n",
		   name);
	    goto manual_update;
	}

	list_for_each(pos,&space->regions) {
	    region = list_entry(pos,typeof(*region),region);
	    if (strcmp(region->name,modfilename) == 0) 
		break;
	    region = NULL;
	}

	if (region) {
	    list_for_each_entry_safe(range,trange,&region->ranges,range) {
		vdebug(3,LA_TARGET,LF_OSLINUX,
		       "removing stale range 0x%"PRIxADDR"-0x%"PRIxADDR":%"PRIiOFFSET"\n",
		       range->start,range->end,range->offset);

		target_add_state_change(target,TID_GLOBAL,
					TARGET_STATE_CHANGE_RANGE_DEL,
					0,range->prot_flags,
					range->start,range->end,region->name);
		memrange_free(range);
	    }

	    vdebug(3,LA_TARGET,LF_OSLINUX,"removing stale region (%s:%s:%s)\n",
		   region->space->idstr,region->name,REGION_TYPE(region->type));

	    target_add_state_change(target,TID_GLOBAL,
				    TARGET_STATE_CHANGE_REGION_DEL,
				    0,0,region->base_load_addr,0,region->name);
	    memregion_free(region);
	}
	else {
	    vdebug(5,LA_TARGET,LF_OSLINUX,
		   "ignoring untracked departing module '%s'\n",name);
	}
    }
    else {
	verror("unexpected module state %d; reverting to manual update!\n",state);
	goto manual_update;
    }

    if (name_value)
	value_free(name_value);
    if (mod)
	value_free(mod);

    return RESULT_SUCCESS;

 err_vmiload_state:
    verror("could not load mod->state; aborting to manual update!\n");
    goto manual_update;

 err_vmiload_name:
    verror("could not load mod->name for departing module; aborting to manual"
	   " update!\n");
    goto manual_update;

 manual_update:
    if (name_value)
	value_free(name_value);
    if (mod)
	value_free(mod);

    if (os_linux_updateregions(target,space)) {
	verror("manual module update failed; regions may be wrong!\n");
	return RESULT_SUCCESS;
    }

    return RESULT_SUCCESS;
}

/*
 * NB: this was hard!
 *
 * It is very, very hard to find an available function to place a probe
 * on, that is not either optimized out of existence (well, it may
 * exist, but either the instances are not available or the parameters
 * have no locations at the inlined site).
 *
 * And we really want to try hard to only probe *after* (but very near
 * to) the place where the task is placed on the tasks list; this way,
 * if we fail to read the new task out of target memory, we can abort to
 * scanning the task list.  I guess that doesn't matter so much though.
 * Anyway, the list add happens in copy_process, so that is our target.
 *
 * I worked very hard to avoid requiring disasm support (so that I could
 * register probes on the RETs from copy_process); but ultimately I
 * could not manage it.  proc_fork_connector() is the only
 * copy_process()-specific hook just before the success RET in
 * copy_process.  We could also have caught the increment of total_forks
 * via watchpoint, but I want to avoid wasting a watchpoint if I can!
 *
 * I tried to catch proc_fork_connector() inside copy_process() (but of
 * course, silly me, that is only really defined if CONFIG_CONNECTOR;
 * otherwise it's just declared) because it is the last "hook" in
 * copy_process; by that time, we know that the new task is on the tasks
 * list.
 *
 * Another option might have been to catch the new task just after the
 * invocations of copy_process() in fork_idle() or do_fork(); but this
 * would basically require us to use debuginfo variable availability
 * (when does the `task' local var in those functions become
 * available!), and then place a probe on that exact location.  But, of
 * course that doesn't work; you have no idea what code is where, or the
 * debuginfo might be wrong/incomplete.
 *
 * So -- the best options all involve requiring disasm support.  Once we
 * have this, the easiest thing to do is catch the RETs in copy_process;
 * if the local var 'p' is !IS_ERR(), we know we have a new task.  If we
 * fail to load memory, or something goes wrong, we can fall back to
 * manually walking the task list.
 */

#define _LINUX_MAX_ERRNO 4095
#define _LINUX_IS_ERR(x) unlikely((x) >= (REGVAL)-_LINUX_MAX_ERRNO)

result_t os_linux_active_thread_entry_handler(struct probe *probe,tid_t tid,
					      void *handler_data,
					      struct probe *trigger,
					      struct probe *base) {
    struct target *target = probe->target;
    struct os_linux_state *lstate =
	(struct os_linux_state *)target->personality_state;
    struct target_thread *tthread;
    REGVAL ax;
    struct value *value;

    /*
     * Load task from retval in %ax
     */
    errno = 0;
    ax = target_read_creg(target,tid,CREG_RET);
    if (errno) {
	verror("could not read %%ax to get copy_process retval!\n");
	return RESULT_SUCCESS;
    }

    if (_LINUX_IS_ERR(ax)) {
	vwarnopt(5,LA_TARGET,LF_OSLINUX,"copy_process failed internally!\n");
	return RESULT_SUCCESS;
    }

    vdebug(5,LA_TARGET,LF_OSLINUX,"copy_process returned 0x%"PRIxADDR"\n",ax);

    value = target_load_type(target,lstate->task_struct_type,ax,LOAD_FLAG_NONE);
    if (!value) {
	/*
	 * This target does not require thread entry tracking; so ignore
	 * it.  We just load threads as they appear; it's stale threads
	 * we really prefer to avoid -- or for overlay targets, we need
	 * to know when a overlay thread disappears.
	 */
	vwarn("could not load retval in %s; ignoring new thread!\n",
	      bsymbol_get_name(lstate->thread_entry_f_symbol));
	return RESULT_SUCCESS;
    }

    if (!(tthread = os_linux_load_thread_from_value(target,value))) {
	verror("could not load thread from task value; BUG?\n");
	value_free(value);
	return RESULT_SUCCESS;
    }

    vdebug(5,LA_TARGET,LF_OSLINUX,
	   "new task %"PRIiTID" (%s)\n",tthread->tid,tthread->name);

    return RESULT_SUCCESS;
}

/*
 * NB: this was hard!
 *
 * It is very, very hard to find an available function to place a probe
 * on, that is not either optimized out of existence (well, it may
 * exist, but either the instances are not available or the parameters
 * have no locations at the inlined site).  __unhash_process, the
 * function that takes the pid off the list, is the ideal place, but
 * that doesn't work.  release_task also does not work, but that is
 * because it contains a loop that reaps zombie group leaders (if they
 * exist) -- so we would miss some zombies.  Thus we are left with
 * sched_exit, which is (unfortunately) well after the process is off
 * the task list.  BUT -- every exiting task hits it.  Another
 * alternative (of course) is to probe inside of schedule(), but that is
 * tricky because it adds tons of unnecessary overhead,
 *
 * Of course, then the problem becomes that in release_task, the task IS
 * exiting, but it is still running on its kernel stack (at least when
 * called from the normal do_exit() exit path; this means that although
 * we want to delete our thread, we cannot delete it because it may
 * "reappear".
 *
 * One strategy, for kernels that do NOT support CONFIG_PREEMPT, is to
 * mark the thread "exiting", and when the next debug exception hits,
 * clear out any such threads if the exception is not for one of them!
 * Why does this work?  An exiting task will simply not be preempted
 * until it calls schedule().
 *
 * For kernels that do support CONFIG_PREEMPT, the only "safe" places to
 * *know* that a task is exiting, but preemption has been disabled, is
 * the call to preempt_disable() inside do_exit().  And we can't catch
 * that -- it is really just a write to a field in the task struct,
 * followed by an MFENCE instruction (on x86).  So, we really have to
 * catch the call to schedule() inside do_exit() -- or the call to
 * release_task() inside wait_task_zombie().  This makes sure we catch
 * all the paths leading to release_task().
 *
 * NB: therefore, this version does not support CONFIG_PREEMPT very well
 * -- it could be racy.  We need support for placing probes on function
 * invocations; this requires disasm support.
 */
result_t os_linux_active_thread_exit_handler(struct probe *probe,tid_t tid,
					     void *handler_data,
					     struct probe *trigger,
					     struct probe *base) {
    struct target *target = probe->target;
    struct os_linux_state *lstate =
	(struct os_linux_state *)target->personality_state;
    struct target_thread *tthread;
    struct value *value;
    struct target_location_ctxt *tlctxt = target_global_tlctxt(target);

    /*
     * Load task.
     */
    value = target_load_symbol(target,tlctxt,
			       lstate->thread_exit_v_symbol,LOAD_FLAG_AUTO_DEREF);

    if (!value) {
	/*
	 * We need avoid stale threads for overlay targets; we need to
	 * know when a overlay thread disappears.
	 */
	vwarn("could not load %s in %s; ignoring new thread!\n",
	      bsymbol_get_name(lstate->thread_exit_v_symbol),
	      bsymbol_get_name(lstate->thread_exit_f_symbol));
	return RESULT_SUCCESS;
    }

    if (!(tthread = os_linux_load_thread_from_value(target,value))) {
	verror("could not load thread from task value; BUG?\n");
	value_free(value);
	return RESULT_SUCCESS;
    }

    tthread->exiting = 1;

    vdebug(5,LA_TARGET,LF_OSLINUX,
	   "exiting task %"PRIiTID" (%s)\n",tthread->tid,tthread->name);

    return RESULT_SUCCESS;
}

int os_linux_set_active_probing(struct target *target,
				active_probe_flags_t flags) {
    struct os_linux_state *lstate = \
	(struct os_linux_state *)target->personality_state;
    struct probe *probe;
    char *name;
    int forced_load = 0;
    int retval = 0;

    if ((flags & ACTIVE_PROBE_FLAG_MEMORY) 
	!= (target->active_probe_flags & ACTIVE_PROBE_FLAG_MEMORY)) {
	if (flags & ACTIVE_PROBE_FLAG_MEMORY) {
	    probe = probe_create(target,TID_GLOBAL,NULL,
				 bsymbol_get_name(lstate->module_free_symbol),
				 os_linux_active_memory_handler,NULL,NULL,0,1);
	    /* NB: always use this; it should be the default! */
	    if (!probe_register_inlined_symbol(probe,lstate->module_free_symbol,
					       1,PROBEPOINT_SW,0,0)) {
		probe_free(probe,1);
		probe = NULL;

		vwarn("could not probe module_free; not enabling"
		      " active memory updates!\n");

		lstate->active_memory_probe = NULL;
		target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_MEMORY;

		--retval;
	    }
	    else {
		lstate->active_memory_probe = probe;
		target->active_probe_flags |= ACTIVE_PROBE_FLAG_MEMORY;
	    }
	}
	else {
	    if (lstate->active_memory_probe) {
		probe_free(lstate->active_memory_probe,0);
		lstate->active_memory_probe = NULL;
	    }
	    target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_MEMORY;
	}
    }

    if ((flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY) 
	!= (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY)) {
	if (flags & ACTIVE_PROBE_FLAG_THREAD_ENTRY) {
#ifdef ENABLE_DISTORM
	    /*
	     * Make sure all threads loaded first!
	     */
	    if (!forced_load) {
		target_load_available_threads(target,0);
		forced_load = 1;
	    }

	    name = bsymbol_get_name(lstate->thread_entry_f_symbol);
	    /*
	     * Create it with only a post handler so that we only probe
	     * on the RETs from copy_process().
	     */
	    probe = probe_create(target,TID_GLOBAL,NULL,name,
				 NULL,os_linux_active_thread_entry_handler,
				 NULL,0,1);
	    if (!probe_register_function_ee(probe,PROBEPOINT_SW,
					    lstate->thread_entry_f_symbol,0,0,1)) {
		probe_free(probe,1);
		probe = NULL;

		vwarn("could not probe %s entry/exits; not enabling"
		      " active thread entry updates!\n",name);

		lstate->active_thread_entry_probe = NULL;
		target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_THREAD_ENTRY;

		--retval;
	    }
	    else {
		lstate->active_thread_entry_probe = probe;
		target->active_probe_flags |= ACTIVE_PROBE_FLAG_THREAD_ENTRY;
	    }
#else
	    verror("cannot enable active thread_entry probes; distorm (disasm)"
		   " support not built in!");
	    --retval;
#endif
	}
	else {
	    if (lstate->active_thread_entry_probe) {
		probe_free(lstate->active_thread_entry_probe,0);
		lstate->active_thread_entry_probe = NULL;
	    }
	    target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_THREAD_ENTRY;
	}
    }

    if ((flags & ACTIVE_PROBE_FLAG_THREAD_EXIT) 
	!= (target->active_probe_flags & ACTIVE_PROBE_FLAG_THREAD_EXIT)) {
	if (flags & ACTIVE_PROBE_FLAG_THREAD_EXIT) {
	    /*
	     * Make sure all threads loaded first!
	     */
	    if (!forced_load) {
		target_load_available_threads(target,0);
		forced_load = 1;
	    }

	    name = bsymbol_get_name(lstate->thread_exit_f_symbol);
	    probe = probe_create(target,TID_GLOBAL,NULL,name,
				 os_linux_active_thread_exit_handler,
				 NULL,NULL,0,1);
	    /* NB: always use this; it should be the default! */
	    if (!probe_register_inlined_symbol(probe,
					       lstate->thread_exit_f_symbol,
					       1,PROBEPOINT_SW,0,0)) {
		probe_free(probe,1);
		probe = NULL;

		vwarn("could not probe %s; not enabling"
		      " active thread exit updates!\n",name);

		lstate->active_thread_exit_probe = NULL;
		target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_THREAD_EXIT;

		--retval;
	    }
	    else {
		lstate->active_thread_exit_probe = probe;
		target->active_probe_flags |= ACTIVE_PROBE_FLAG_THREAD_EXIT;
	    }
	}
	else {
	    if (lstate->active_thread_exit_probe) {
		probe_free(lstate->active_thread_exit_probe,0);
		lstate->active_thread_exit_probe = NULL;
	    }
	    target->active_probe_flags &= ~ACTIVE_PROBE_FLAG_THREAD_EXIT;
	}
    }

    return retval;
}

struct target_personality_ops os_linux_generic_personality_ops = {
    .attach = os_linux_attach,
    .init = NULL,
    .fini = os_linux_fini,

    .postloadinit = os_linux_postloadinit,
    .postopened = os_linux_postopened,
    .set_active_probing = os_linux_set_active_probing,

    .free_thread_state = os_linux_free_thread_state,
    .list_available_tids = os_linux_list_available_tids,
    .load_thread = os_linux_load_thread,
    .load_current_thread = os_linux_load_current_thread,
    .load_available_threads = os_linux_load_available_threads,

    .flush_thread = os_linux_flush_thread,
    .flush_current_thread = os_linux_flush_current_thread,
    .invalidate_thread = os_linux_invalidate_thread,

    .thread_snprintf = os_linux_thread_snprintf,

    .readreg = target_regcache_readreg,
    .writereg = target_regcache_writereg,
    .copy_registers = target_regcache_copy_registers,
    .readreg_tidctxt = target_regcache_readreg_tidctxt,
    .writereg_tidctxt = target_regcache_writereg_tidctxt,
};

void os_linux_generic_register(void) {
    target_personality_register("os_linux_generic",TARGET_PERSONALITY_OS,
				&os_linux_generic_personality_ops,
				&os_linux_generic_os_ops);
}
