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

/* 
 * File:   examples/vmprobebio.c
 * Author: Chung Hwan Kim
 * E-mail: chunghwn@cs.utah.edu
 */

#include <stdio.h>
#include <limits.h> // for PATH_MAX
#include <vmprobes/vmprobes.h>

static int count_sys_open = 0;

static int pre_handler(struct vmprobe *p, struct pt_regs *regs)
{
    printf("[%d] sys_open() called\n", ++count_sys_open);
    
    //dump_regs(regs);
    const char *filename = (const char *)regs->ebx;
    int flags = regs->ecx;
    int mode = regs->edx;

    /* read filename string in userspace */
    char buf[PATH_MAX+1] = {0,};
    char *str = NULL;
    if (read_vmprobe(p, (uint32_t)filename, buf, PATH_MAX))
        fprintf(stderr, "Error: failed to read filename at %08x\n", filename);
    else
        str = buf;

    printf(" -- filename: %08x (%s)\n", filename, (!str)?"":str);
    printf(" -- flags: %08x\n", flags);
    printf(" -- mode: %08x\n", mode);
    
    return 0;   // return value 0 indicates instrumented instruction should be 
                // handled normally.
}

static int post_handler(struct vmprobe *p, struct pt_regs *regs, 
    unsigned long flags)
{
    //if (count_sys_open == 5)
    //    return 1;   // return value non-zero indicates stopping instrumentation.
    
    return 0;
}

static struct vmprobe vp = {
    .domain_name = "a3guest", 
    .symbol_name = "sys_open", 
    .pre_handler = pre_handler, 
    .post_handler = post_handler
};

int main(int argc, char *argv[])
{
    if (register_vmprobe(&vp)) {
        fprintf(stderr, "failed to register vmprobe\n");
        return 1;
    }
    printf("vmprobe registered\n");

    /* this function continues instrumentation until pre_handler or post_handler
       returns non-zero. */
    loop_vmprobe(&vp);
    
    unregister_vmprobe(&vp);
    printf("vmprobe unregistered\n");
    printf("sys_open() called %d times.\n", count_sys_open);
    
    return 0;
}
