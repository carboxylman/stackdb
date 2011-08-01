/* vmprobebio.c
   This is a simple module to get information about block io operations.
   Chung Hwan Kim
*/
#include <stdio.h>
#include <vmprobes.h>

static int count;

static int on_generic_make_request(vmprobe_handle_t vp, struct pt_regs *regs)
{   
    printf("[%d] block io request in domain %d\n", ++count, vmprobe_domid(vp));
	if (count == 10)
		stop_vmprobes();
    return 0;
}

int main(int argc, char *argv[])
{
    const domid_t domid = 2; // a3guest
    const unsigned long vaddr = 0xc021f660; // generic_make_request()
    vmprobe_handle_t vp;
    
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
