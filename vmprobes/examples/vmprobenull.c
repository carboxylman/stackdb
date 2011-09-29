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
