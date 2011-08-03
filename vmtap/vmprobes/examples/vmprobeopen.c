/* vmprobeopen.c
   This is a simple module to instrument sys_open kernel function.
   Chung Hwan Kim
*/
#include <stdio.h>
#include <stdlib.h>
#include <vmprobes.h>

static int count;

static int on_sys_open_pre(vmprobe_handle_t vp, 
                           struct cpu_user_regs *regs)
{   
    printf("[%d] sys_open() called in domain %d\n", ++count, 
	    vmprobe_domid(vp));
    return 0;
}

static int on_sys_open_post(vmprobe_handle_t vp, 
                            struct cpu_user_regs *regs)
{   
    if (count == 10)
        stop_vmprobes();
    return 0;
}

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

    vp = register_vmprobe(domid, vaddr, on_sys_open_pre, on_sys_open_post);
    if (vp < 0)
    {
        fprintf(stderr, "failed to register probe\n");
        return 1;
    }

    run_vmprobes();

    unregister_vmprobe(vp);
    printf("sys_open called %d times\n", count);
    return 0;
}
