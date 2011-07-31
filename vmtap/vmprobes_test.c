#include <stdio.h>
#include "vmprobes.h"

static int count;

static int pre_handler(vmprobe_handle_t vp_handle, struct pt_regs *regs)
{   
    if (vp_handle == 0) ++count;
    printf("[%d] sys_open() called - vmprobe %d\n", count, vp_handle);
    return 0;
}

static int post_handler(vmprobe_handle_t vp_handle, struct pt_regs *regs)
{   
    if (vp_handle == 0 && count == 10)
        stop_vmprobes();
    return 0;
}

int main(int argc, char *argv[])
{
    const domid_t domid = 2; // a3guest
    const unsigned long vaddr = 0xc0167b10; // sys_open()
    vmprobe_handle_t vp_handles[3];
    int i;
    
    for (i = 0; i < 3; i++)
    {
        vp_handles[i] = register_vmprobe(domid, 
                                         vaddr, 
                                         pre_handler, 
                                         post_handler);
        if (vp_handles[i] < 0)
        {
            fprintf(stderr, "failed to register probe\n");
            return 1;
        }
        printf("vmprobe %d registered\n", vp_handles[i]);
    }
    
    run_vmprobes();

    for (i = 0; i < 3; i++)
    {
        unregister_vmprobe(vp_handles[i]);
        printf("vmprobe %d unregistered\n", vp_handles[i]);
    }

    printf("sys_open() called %d times\n", count);
    return 0;
}
