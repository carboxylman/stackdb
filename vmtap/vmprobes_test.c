#include <stdio.h>
#include "vmprobes.h"

static int count;

static int pre_handler(vmprobe_handle_t vp, struct pt_regs *regs)
{   
    if (vp == 0) ++count;
    printf("[%d] sys_open() called - probe(%d), vaddr(%lx), domid(%d)\n", 
        count, vp, vmprobe_vaddr(vp), vmprobe_domid(vp));
    return 0;
}

static int post_handler(vmprobe_handle_t vp, struct pt_regs *regs)
{   
    if (vp > 0 && count == 5)
        return 1;
    if (vp == 0 && count == 10)
        stop_vmprobes();
    return 0;
}

int main(int argc, char *argv[])
{
    const domid_t domid = 2; // a3guest
    const unsigned long vaddr = 0xc0167b10; // sys_open()
    vmprobe_handle_t vps[3];
    int i;
    
    for (i = 0; i < 3; i++)
    {
        vps[i] = register_vmprobe(domid, vaddr, pre_handler, post_handler);
        if (vps[i] < 0)
        {
            fprintf(stderr, "failed to register probe\n");
            return 1;
        }
    }
    
    run_vmprobes();

    for (i = 0; i < 3; i++)
        unregister_vmprobe(vps[i]);

    printf("sys_open() called %d times.\n", count);
    return 0;
}
