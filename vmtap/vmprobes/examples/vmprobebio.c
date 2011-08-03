/* vmprobebio.c
   This is a simple module to get information about block io operations.
   Chung Hwan Kim
*/
#include <stdio.h>
#include <stdlib.h>
#include <vmprobes.h>

static int count;

static int on_generic_make_request(vmprobe_handle_t vp, 
                                   struct cpu_user_regs *regs)
{   
    printf("[%d] block io request in domain %d\n", ++count, vmprobe_domid(vp));
	if (count == 10)
		stop_vmprobes();
    return 0;
}

int main(int argc, char *argv[])
{
    domid_t domid = 1; // default guest domain
    unsigned long vaddr = 0xc021f660; // default generic_make_request()
    vmprobe_handle_t vp;
    
	if (argc > 1)
	{
        domid = atoi(argv[1]);
        if (argc > 2)
		    vaddr = atoi(argv[2]);
	}
    
    vp = register_vmprobe(domid, vaddr, on_generic_make_request, NULL);
    if (vp < 0)
    {
        fprintf(stderr, "failed to register probe\n");
        return 1;
    }

    run_vmprobes();

    unregister_vmprobe(vp);
    printf("total %d block io requests\n", count);
    return 0;
}
