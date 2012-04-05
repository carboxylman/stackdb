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

#ifndef _VMTAP_H
#define _VMTAP_H

typedef int (*VMTAP_CALLBACK) (void *);

extern
int __register_vmtap(const char *domain,
                     const char *symbol, 
                     VMTAP_CALLBACK callback, 
                     void *prefunc,
                     void *postfunc);

extern
int loop_vmtap(void);

extern
void unregister_vmtap(void);

extern
const char *domain_name(void);

extern
unsigned int *domain_id(void);

extern
const char *symbol_name(void);

extern
unsigned long symbol_addr(void);

extern
unsigned long arg(int num);

extern
const char *read_path(unsigned long addr);

#endif /*_VMTAP_H */
