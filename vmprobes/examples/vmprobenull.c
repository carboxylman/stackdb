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

/* vmprobenull.c
   This is a simple module to benchmark vmprobes with null probes.
   Chung Hwan Kim
*/
#include <stdio.h>
#include <stdlib.h>
#include <vmprobes.h>

int main(int argc, char *argv[])
{
    domid_t domid = 1; // default guest domain
    unsigned long vaddr = 0xc0167b10; // default sys_open()
    vmprobe_handle_t vp;

    if (argc > 1)
	{
        domid = atoi(argv[1]);
        if (argc > 2)
		    vaddr = atoi(argv[2]);
	}

    vp = register_vmprobe(domid, vaddr, NULL, NULL);
    if (vp < 0)
    {
        fprintf(stderr, "failed to register probe\n");
        return 1;
    }

    run_vmprobes();

    unregister_vmprobe(vp);
    return 0;
}
