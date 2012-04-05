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

#ifndef _XEN_VMTAP_PRIVATE_H
#define _XEN_VMTAP_PRIVATE_H

#include <xenctrl.h>
#include <vmprobes/vmprobes.h>
#include <xenaccess/xenaccess.h>
#include "vmtap.h"

/*
 * vmtap_probe -- represents a single vmtap probe.
 */
struct vmtap_probe
{
    /* Domain name */
    char *domain;    

    /* Symbol name */
    char *symbol;

    /* Offset from symbol to target address */
    unsigned long offset;

    /* User handler in python */
    void *pyhandler;

    /* VMprobe handle (also used as an identifier to indicate this probe) */
    vmprobe_handle_t vp_handle;

    /* XenAccess instance borrowed from domains in VMprobes */
    xa_instance_t *xa_instance;
    
    /* Register values */
    struct cpu_user_regs *regs;
};

/* Internal function that does probe injection 
   NOTE: Python user is supposed to call probe() instead of this function. */
bool
__probe(const char *probepoint, vmtap_callback_t callback, void *pyhandler);

/* Internal function that parses a probepoint string using Flex */
bool
__parse_probepoint(const char *probepoint,
                   char *domain,
                   char *symbol,
                   unsigned long *offset,
                   domid_t *domid);

/* Returns strlen(s), if that is less than maxlen, or maxlen if there is no 
   '\0' character among the first maxlen characters pointed to by s. 
   NOTE: old version of string.h does not expose this function. */
static inline
size_t strnlen(const char *s, size_t maxlen)
{
    size_t i;
    for (i = 0; i < maxlen && s[i]; i++);
    return i;
}

#endif /* _XEN_VMTAP_PRIVATE_H */
