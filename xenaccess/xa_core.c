/*
 * The libxa library provides access to resources in domU machines.
 * 
 * Copyright (C) 2005 - 2007  Bryan D. Payne (bryan@thepaynes.cc)
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * --------------------
 * This file contains core functions that are responsible for
 * initialization and destruction of the libxa instance.
 *
 * File: xa_core.c
 *
 * Author(s): Bryan D. Payne (bryan@thepaynes.cc)
 *
 * $Id$
 * $Date$
 */

#include "xenaccess.h"
#include "xa_private.h"
#include "config/config_parser.h"

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <fnmatch.h>

#ifdef ENABLE_XEN
#include <xs.h>
#include <xen/arch-x86/xen.h>
#endif /* ENABLE_XEN */

char *strndup(const char *s, size_t n);

int get_memory_size (xa_instance_t *instance)
{
    int ret = XA_SUCCESS;

    if (XA_MODE_XEN == instance->mode){
#ifdef ENABLE_XEN
        struct xs_handle *xsh = NULL;
        xs_transaction_t xth = XBT_NULL;
        char *tmp = malloc(100);
        if (NULL == tmp){
            printf("ERROR: failed to allocate memory for tmp variable\n");
            ret = XA_FAILURE;
            goto error_exit;
        }
        memset(tmp, 0, 100);
        sprintf(tmp, "/local/domain/%d/memory/target",
            instance->m.xen.domain_id);
        xsh = xs_domain_open();
        instance->m.xen.size =
            strtol(xs_read(xsh, xth, tmp, NULL), NULL, 10) * 1000;
	free(tmp);
        if (0 == instance->m.xen.size){
            printf("ERROR: failed to get memory size for Xen domain.\n");
            ret = XA_FAILURE;
            goto error_exit;
        }
        xa_dbprint(0,"**set instance->m.xen.size = %d\n", instance->m.xen.size);
        if (xsh) xs_daemon_close(xsh);
#endif /* ENABLE_XEN */
    }
    else if (XA_MODE_FILE == instance->mode){
        struct stat s;

        if (fstat(fileno(instance->m.file.fhandle), &s) == -1){
            printf("ERROR: Failed to stat file\n");
            ret = XA_FAILURE;
            goto error_exit;
        }
        instance->m.file.size = (uint32_t) s.st_size;
        xa_dbprint(0,"**set instance->m.file.size = %d\n", instance->m.file.size);
    }

error_exit:
    return ret;
}

#if 0
int read_config_file (xa_instance_t *instance)
{
    extern FILE *yyin;
    int ret = XA_SUCCESS;
    xa_config_entry_t *entry;
#ifdef ENABLE_XEN
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
#endif /* ENABLE_XEN */
    char *tmp = NULL;

    yyin = fopen("/etc/xenaccess.conf", "r");
    if (NULL == yyin){
        printf("ERROR: config file not found at /etc/xenaccess.conf\n");
        ret = XA_FAILURE;
        goto error_exit;
    }

    /* convert domain id to domain name for Xen mode */
    if (XA_MODE_XEN == instance->mode){
#ifdef ENABLE_XEN
        tmp = malloc(100);
        if (NULL == tmp){
            printf("ERROR: failed to allocate memory for tmp variable\n");
            ret = XA_FAILURE;
            goto error_exit;
        }
        memset(tmp, 0, 100);
        sprintf(tmp, "/local/domain/%d/name", instance->m.xen.domain_id);
        xsh = xs_domain_open();
        instance->image_type = xs_read(xsh, xth, tmp, NULL);
        if (NULL == instance->image_type){
            printf("ERROR: domain id %d is not running\n",
                    instance->m.xen.domain_id);
            ret = XA_FAILURE;
            goto error_exit;
        }
        xa_dbprint(0,"--got domain name from id (%d ==> %s).\n",
                    instance->m.xen.domain_id, instance->image_type);
#endif /* ENABLE_XEN */
    }

    if (xa_parse_config(instance->image_type)){
        printf("ERROR: failed to read config file\n");
        ret = XA_FAILURE;
        goto error_exit;
    }
    entry = xa_get_config();

    /* copy the values from entry into instance struct */
    instance->sysmap = strdup(entry->sysmap);
    xa_dbprint(0,"--got sysmap from config (%s).\n", instance->sysmap);
    
    if (strncmp(entry->ostype, "Linux", CONFIG_STR_LENGTH) == 0){
        instance->os_type = XA_OS_LINUX;
    }
    else if (strncmp(entry->ostype, "Windows", CONFIG_STR_LENGTH) == 0){
        instance->os_type = XA_OS_WINDOWS;
    }
    else{
        printf("ERROR: Unknown or undefined OS type.\n");
        ret = XA_FAILURE;
        goto error_exit;
    }

    /* Copy config info based on OS type */
    if(XA_OS_LINUX == instance->os_type){
        xa_dbprint(0,"--reading in linux offsets from config file.\n");
        if(entry->offsets.linux_offsets.tasks){
            instance->os.linux_instance.tasks_offset =
                 entry->offsets.linux_offsets.tasks;
        }

        if(entry->offsets.linux_offsets.mm){
            instance->os.linux_instance.mm_offset =
                entry->offsets.linux_offsets.mm;
        }

        if(entry->offsets.linux_offsets.pid){
            instance->os.linux_instance.pid_offset =
                entry->offsets.linux_offsets.pid;
        }

        if(entry->offsets.linux_offsets.pgd){
            instance->os.linux_instance.pgd_offset =
                entry->offsets.linux_offsets.pgd;
        }

        if(entry->offsets.linux_offsets.addr){
            instance->os.linux_instance.addr_offset =
                entry->offsets.linux_offsets.addr;
        }
    }
    else if (XA_OS_WINDOWS == instance->os_type){
        xa_dbprint(0,"--reading in windows offsets from config file.\n");
        if(entry->offsets.windows_offsets.tasks){
            instance->os.windows_instance.tasks_offset =
                entry->offsets.windows_offsets.tasks;
        }

        if(entry->offsets.windows_offsets.pdbase){ 
            instance->os.windows_instance.pdbase_offset =
                entry->offsets.windows_offsets.pdbase;
        }

        if(entry->offsets.windows_offsets.pid){
            instance->os.windows_instance.pid_offset =
                entry->offsets.windows_offsets.pid;
        }

        if(entry->offsets.windows_offsets.peb){
            instance->os.windows_instance.peb_offset =
                entry->offsets.windows_offsets.peb;
        }

        if(entry->offsets.windows_offsets.iba){
            instance->os.windows_instance.iba_offset =
                entry->offsets.windows_offsets.iba;
        }

        if(entry->offsets.windows_offsets.ph){
            instance->os.windows_instance.ph_offset =
                entry->offsets.windows_offsets.ph;
        }
    }

#ifdef XA_DEBUG
    xa_dbprint(0,"--got ostype from config (%s).\n", entry->ostype);
    if (instance->os_type == XA_OS_LINUX){
        xa_dbprint(0,"**set instance->os_type to Linux.\n");
    }
    else if (instance->os_type == XA_OS_WINDOWS){
        xa_dbprint(0,"**set instance->os_type to Windows.\n");
    }
    else{
        xa_dbprint(0,"**set instance->os_type to unknown.\n");
    }
#endif

error_exit:
    if (tmp) free(tmp);
    if (yyin) fclose(yyin);
#ifdef ENABLE_XEN
    if (xsh) xs_daemon_close(xsh);
#endif /* ENABLE_XEN */

    return ret;
}
#endif

/* check that this domain uses a paging method that we support */
int get_page_info_xen (xa_instance_t *instance)
{
    int ret = XA_SUCCESS;
#ifdef ENABLE_XEN
#ifdef HAVE_CONTEXT_ANY
    vcpu_guest_context_any_t ctxt_any;
#endif /* HAVE_CONTEXT_ANY */
    vcpu_guest_context_t ctxt;
    struct xs_handle *xsh = NULL;
    xs_transaction_t xth = XBT_NULL;
    char buf[128];
    char *xsres = NULL;

#ifdef HAVE_CONTEXT_ANY
    if ((ret = xc_vcpu_getcontext(
                instance->m.xen.xc_handle,
                instance->m.xen.domain_id,
                0, /*TODO vcpu, assuming only 1 for now */
                &ctxt_any)) != 0){
#else
    if ((ret = xc_vcpu_getcontext(
                instance->m.xen.xc_handle,
                instance->m.xen.domain_id,
                0, /*TODO vcpu, assuming only 1 for now */
                &ctxt)) != 0){
#endif /* HAVE_CONTEXT_ANY */
        printf("ERROR: failed to get context information.\n");
        ret = XA_FAILURE;
        goto error_exit;
    }

#ifdef HAVE_CONTEXT_ANY
    ctxt = ctxt_any.c;
#endif /* HAVE_CONTEXT_ANY */

    /* For details on the registers involved in the x86 paging configuation
       see the Intel 64 and IA-32 Architectures Software Developer's Manual,
       Volume 3A: System Programming Guide, Part 1. */

    /* PG Flag --> CR0, bit 31 == 1 --> paging enabled */
    if (!xa_get_bit(ctxt.ctrlreg[0], 31)){
        printf("ERROR: Paging disabled for this VM, not supported.\n");
        ret = XA_FAILURE;
        goto error_exit;
    }
    /* PAE Flag --> CR4, bit 5 == 0 --> pae disabled */
    if (!instance->pae)
        instance->pae = xa_get_bit(ctxt.ctrlreg[4], 5);

    memset(buf, 0, sizeof(buf));
    sprintf(buf, "/local/domain/%d/image/pae-mode",
            instance->m.xen.domain_id);
    xsh = xs_domain_open();
    xsres = xs_read(xsh, xth, buf, NULL);
    if (xsres) {
	if (strcmp("yes",xsres) == 0)
	    instance->pae = 1;
	else 
	    instance->pae = 0;
	free(xsres);
    }
    else {
	printf("ERROR: failed to get PAE setting for Xen domain, assuming 0.\n");
	instance->pae = 0;
    }
    xs_daemon_close(xsh);
    xa_dbprint(0,"**set instance->pae = %d\n", instance->pae);

    /* PSE Flag --> CR4, bit 4 == 0 --> pse disabled */
    instance->pse = xa_get_bit(ctxt.ctrlreg[4], 4);
    xa_dbprint(0,"**set instance->pse = %d\n", instance->pse);

    /* testing to see CR3 value */
    instance->cr3 = ctxt.ctrlreg[3];
    xa_dbprint(0,"**set instance->cr3 = 0x%.8x\n", instance->cr3);
#endif /* ENABLE_XEN */

error_exit:
    return ret;
}

void init_page_offset (xa_instance_t *instance)
{
    if (XA_OS_LINUX == instance->os_type){
        instance->page_offset = 0xc0000000;
    }
    else if (XA_OS_WINDOWS == instance->os_type){
        instance->page_offset = 0x80000000;
    }
    else{
        instance->page_offset = 0;
    }
    xa_dbprint(0,"**set instance->page_offset = 0x%.8x\n", instance->page_offset);

    /* assume 4k pages for now, update when 4M page is found */
    instance->page_shift = 12;
    instance->page_size = 1 << instance->page_shift;
    xa_dbprint(0,"**set instance->page_size = 0x%.8x\n", instance->page_size);
}

void init_xen_version (xa_instance_t *instance)
{
#ifdef ENABLE_XEN
#define VERSION_STR_LEN 100
    char versionStr[VERSION_STR_LEN];
    int versions;
    int major;
    int minor;
    xen_extraversion_t extra;
    int cmd0 = XENVER_version;
    int cmd1 = XENVER_extraversion;

    /* get the major and minor versions */
    versions = xc_version(instance->m.xen.xc_handle, cmd0, NULL);
    major = versions >> 16;
    minor = versions & ((1 << 16) - 1);
    xa_dbprint(0,"--major = %d\n", major);
    xa_dbprint(0,"--minor = %d\n", minor);

    /* get the extra version */
    xc_version(instance->m.xen.xc_handle, cmd1, &extra);
    xa_dbprint(0,"--extra = %s\n", (char *) extra);

    /* put everything together for easy comparison testing */
    memset(versionStr, 0, VERSION_STR_LEN);
    sprintf(versionStr, "%d.%d%s", major, minor, (char *)extra);

    /* see if we recognize this version */
    instance->m.xen.xen_version = XA_XENVER_UNKNOWN;
    if (fnmatch("3.0.4*", versionStr, 0) == 0){
        instance->m.xen.xen_version = XA_XENVER_3_0_4;
        xa_dbprint(0,"**set instance->m.xen.xen_version = 3.0.4\n");
    }
    else if (fnmatch("3.1.0*", versionStr, 0) == 0){
        instance->m.xen.xen_version = XA_XENVER_3_1_0;
        xa_dbprint(0,"**set instance->m.xen.xen_version = 3.1.0\n");
    }
    else if (fnmatch("3.1.1*", versionStr, 0) == 0){
        instance->m.xen.xen_version = XA_XENVER_3_1_1;
        xa_dbprint(0,"**set instance->m.xen.xen_version = 3.1.1\n");
    }
    else if (fnmatch("3.1.2*", versionStr, 0) == 0){
        instance->m.xen.xen_version = XA_XENVER_3_1_2;
        xa_dbprint(0,"**set instance->m.xen.xen_version = 3.1.2\n");
    }
    else if (fnmatch("3.1.3*", versionStr, 0) == 0){
        instance->m.xen.xen_version = XA_XENVER_3_1_3;
        xa_dbprint(0,"**set instance->m.xen.xen_version = 3.1.3\n");
    }
    else if (fnmatch("3.1.4*", versionStr, 0) == 0){
        instance->m.xen.xen_version = XA_XENVER_3_1_4;
        xa_dbprint(0,"**set instance->m.xen.xen_version = 3.1.4\n");
    }
    else if (fnmatch("3.2.0*", versionStr, 0) == 0){
        instance->m.xen.xen_version = XA_XENVER_3_2_0;
        xa_dbprint(0,"**set instance->m.xen.xen_version = 3.2.0\n");
    }
    else if (fnmatch("3.2.1*", versionStr, 0) == 0){
        instance->m.xen.xen_version = XA_XENVER_3_2_1;
        xa_dbprint(0,"**set instance->m.xen.xen_version = 3.2.1\n");
    }
    else if (fnmatch("3.2.2*", versionStr, 0) == 0){
        instance->m.xen.xen_version = XA_XENVER_3_2_2;
        xa_dbprint(0,"**set instance->m.xen.xen_version = 3.2.2\n");
    }
    else if (fnmatch("3.3.0*", versionStr, 0) == 0){
        instance->m.xen.xen_version = XA_XENVER_3_3_0;
        xa_dbprint(0,"**set instance->m.xen.xen_version = 3.3.0\n");
    }
#ifdef CONFIG_DETERMINISTIC_TIMETRAVEL
    else if (fnmatch("3.0-unstable", versionStr, 0) == 0){
        instance->m.xen.xen_version = XA_XENVER_3_1_4;
        xa_dbprint(0,"**set instance->m.xen.xen_version = 3.1.4 for the time-traveling Xen\n");
    }
#endif


    if (instance->m.xen.xen_version == XA_XENVER_UNKNOWN){
        printf("WARNING: This Xen version not supported by XenAccess ");
        printf("(%s).\n", versionStr);
    }
#endif /* ENABLE_XEN */
}

/* given a xa_instance_t struct with the xc_handle and the
 * domain_id filled in, this function will fill in the rest
 * of the values using queries to libxc. */
 int helper_init (xa_instance_t *instance,int noos)
{
    int ret = XA_SUCCESS;

    if (XA_MODE_XEN == instance->mode){
#ifdef ENABLE_XEN
        /* init instance->m.xen.xc_handle */
        if (xc_domain_getinfo(
                instance->m.xen.xc_handle, instance->m.xen.domain_id,
                1, &(instance->m.xen.info)
            ) != 1){
            printf("ERROR: Failed to get domain info\n");
            ret = xa_report_error(instance, 0, XA_ECRITICAL);
            if (XA_FAILURE == ret) goto error_exit;
        }
        xa_dbprint(0,"--got domain info.\n");

        /* find the version of xen that we are running */
        init_xen_version(instance);
#endif /* ENABLE_XEN */
    }

#if 0
    /* read in configure file information */
    if (read_config_file(instance) == XA_FAILURE){
        ret = xa_report_error(instance, 0, XA_EMINOR);
        if (XA_FAILURE == ret) goto error_exit;
    }
#endif

    /* determine the page sizes and layout for target OS */
    if (XA_MODE_XEN == instance->mode){
#ifdef ENABLE_XEN
        if (get_page_info_xen(instance) == XA_FAILURE){
            printf("ERROR: memory layout not supported\n");
            ret = xa_report_error(instance, 0, XA_ECRITICAL);
            if (XA_FAILURE == ret) goto error_exit;
        }
#endif /* ENABLE_XEN */
    }
    else{
        /*TODO add memory layout discovery here for file */
        instance->hvm = 1; /* assume nonvirt image or hvm image for now */
        instance->pae = 0; /* assume no pae for now */
	xa_dbprint(0,"**set instance->hvm true, instance->pae false.\n");
    }
    xa_dbprint(0,"--got memory layout.\n");

    /* setup the correct page offset size for the target OS */
    init_page_offset(instance);

    if (XA_MODE_XEN == instance->mode){
#ifdef ENABLE_XEN
        /* init instance->hvm */
        instance->hvm = xa_ishvm(instance->m.xen.domain_id);
#ifdef XA_DEBUG
        if (instance->hvm){
            xa_dbprint(0,"**set instance->hvm to true (HVM).\n");
        }
        else{
            xa_dbprint(0,"**set instance->hvm to false (PV).\n");
        }
#endif /* XA_DEBUG */
#endif /* ENABLE_XEN */
    }

    /* get the memory size */
    if (get_memory_size(instance) == XA_FAILURE){
        printf("ERROR: Failed to get memory size.\n");
        ret = xa_report_error(instance, 0, XA_ECRITICAL);
        if (XA_FAILURE == ret) goto error_exit;
    }

    /* setup OS specific stuff */
    if (!noos && instance->os_type == XA_OS_LINUX){
        ret = linux_init(instance);
    }
    else if (!noos && instance->os_type == XA_OS_WINDOWS){
        ret = windows_init(instance);
    }

error_exit:
    return ret;
}

/* cleans up any information in the xa_instance_t struct other
 * than the xc_handle and the domain_id */
int helper_destroy (xa_instance_t *instance)
{
#ifdef ENABLE_XEN
    if (instance->m.xen.live_pfn_to_mfn_table){
        munmap(instance->m.xen.live_pfn_to_mfn_table,
               instance->m.xen.nr_pfns * 4);
    }
#endif /* ENABLE_XEN */

    xa_destroy_cache(instance);
    xa_destroy_pid_cache(instance);

    return XA_SUCCESS;
}

/* common code for all init functions */
void xa_init_common (xa_instance_t *instance)
{
    xa_dbprint(0,"XenAccess Version 0.5\n");
    instance->cache_head = NULL;
    instance->cache_tail = NULL;
    instance->current_cache_size = 0;
    instance->pid_cache_head = NULL;
    instance->pid_cache_tail = NULL;
    instance->current_pid_cache_size = 0;
}

/* initialize to view an actively running Xen domain */
int xa_init_vm_private
    (uint32_t domain_id, xa_instance_t *instance, uint32_t error_mode)
{
#ifdef ENABLE_XEN
    int xc_handle;
    instance->mode = XA_MODE_XEN;
    xa_dbprint(0,"XenAccess Mode Xen\n");
    instance->error_mode = error_mode;
    xa_dbprint(0,"XenAccess Error Mode = %d\n", instance->error_mode);

    /* open handle to the libxc interface */
    if ((xc_handle = xc_interface_open()) == -1){
        printf("ERROR: Failed to open libxc interface\n");
        return XA_FAILURE;
    }
    instance->m.xen.xc_handle = xc_handle;

    xa_init_common(instance);
    instance->m.xen.domain_id = domain_id;
    instance->m.xen.live_pfn_to_mfn_table = NULL;
    instance->m.xen.nr_pfns = 0;
    return helper_init(instance,0);
#else
    return XA_FAILURE;
#endif /* ENABLE_XEN */
}

/* Initialize to view an actively running Xen domain but don't call
 * OS-specific init helper.
 */
int xa_init_vm_private_noos
    (uint32_t domain_id, xa_instance_t *instance, uint32_t error_mode)
{
#ifdef ENABLE_XEN
    int xc_handle;
    instance->mode = XA_MODE_XEN;
    xa_dbprint(0,"XenAccess Mode Xen\n");
    instance->error_mode = error_mode;
    xa_dbprint(0,"XenAccess Error Mode = %d\n", instance->error_mode);

    /* open handle to the libxc interface */
    if ((xc_handle = xc_interface_open()) == -1){
        printf("ERROR: Failed to open libxc interface\n");
        return XA_FAILURE;
    }
    instance->m.xen.xc_handle = xc_handle;

    xa_init_common(instance);
    instance->m.xen.domain_id = domain_id;
    instance->m.xen.live_pfn_to_mfn_table = NULL;
    instance->m.xen.nr_pfns = 0;
    return helper_init(instance,1);
#else
    return XA_FAILURE;
#endif /* ENABLE_XEN */
}

/* initialize to view a file image (currently only dd images supported) */
int xa_init_file_private (
    char *filename,
    char *image_type,
    xa_instance_t *instance,
    uint32_t error_mode)
{
#define MAX_IMAGE_TYPE_LEN 256
    FILE *fhandle = NULL;
    instance->mode = XA_MODE_FILE;
    xa_dbprint(0,"XenAccess Mode File\n");
    instance->error_mode = error_mode;
    xa_dbprint(0,"XenAccess Error Mode = %d\n", instance->error_mode);

    /* open handle to memory file */
    if ((fhandle = fopen(filename, "rb")) == NULL){
        printf("ERROR: Failed to open file for reading\n");
        return XA_FAILURE;
    }
    instance->m.file.fhandle = fhandle;

    xa_init_common(instance);
    instance->image_type = strndup(image_type, MAX_IMAGE_TYPE_LEN);
    return helper_init(instance,0);
}

/* below are stub init functions that are called by library users */
#ifdef ENABLE_XEN
int xa_init_vm_name_strict (char *domain_name, xa_instance_t *instance)
{
    uint32_t domain_id = xa_get_domain_id(domain_name);
    xa_dbprint(0,"--got domid from name (%s --> %d)\n", domain_name, domain_id);
    return xa_init_vm_private(domain_id, instance, XA_FAILHARD);
}
int xa_init_vm_name_lax (char *domain_name, xa_instance_t *instance)
{
    uint32_t domain_id = xa_get_domain_id(domain_name);
    xa_dbprint(0,"--got domid from name (%s --> %d)\n", domain_name, domain_id);
    return xa_init_vm_private(domain_id, instance, XA_FAILSOFT);
}
int xa_init_vm_id_strict (uint32_t domain_id, xa_instance_t *instance)
{
    return xa_init_vm_private(domain_id, instance, XA_FAILHARD);
}
int xa_init_vm_id_strict_noos (uint32_t domain_id, xa_instance_t *instance)
{
    return xa_init_vm_private_noos(domain_id, instance, XA_FAILHARD);
}
int xa_init_vm_id_lax (uint32_t domain_id, xa_instance_t *instance)
{
    return xa_init_vm_private(domain_id, instance, XA_FAILSOFT);
}
#endif /* ENABLE_XEN */

int xa_init_file_strict
    (char *filename, char *image_type, xa_instance_t *instance)
{
    return xa_init_file_private(filename, image_type, instance, XA_FAILHARD);
}
int xa_init_file_lax
    (char *filename, char *image_type, xa_instance_t *instance)
{
    return xa_init_file_private(filename, image_type, instance, XA_FAILSOFT);
}

int xa_destroy (xa_instance_t *instance)
{
    int ret1, ret2;

#ifdef ENABLE_XEN
    instance->m.xen.domain_id = 0;
#endif /* ENABLE_XEN */

    ret1 = helper_destroy(instance);

#ifdef ENABLE_XEN
    ret2 = xc_interface_close(instance->m.xen.xc_handle);
#endif /* ENABLE_XEN */

    if (XA_FAILURE == ret1 || XA_FAILURE == ret2){
        return XA_FAILURE;
    }
    return XA_SUCCESS;
}
