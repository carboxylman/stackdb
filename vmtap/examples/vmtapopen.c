#include <stdio.h>
#include <vmtap.h>

static int count;

static void sys_open_call(int p, void *reserved)
{   
    printf("[%d] %s() called - domain(%s)\n", ++count, symbol(p), domain(p));
}
/*
static void sys_open_return(int p, void *reserved)
{   
    printf("[%d] %s() returned - domain(%s)\n", count, symbol(p), domain(p));
}
*/
int main(int argc, char *argv[])
{
    probe("a3guest.kernel.function(sys_open).call", sys_open_call);
    //probe("a3guest.kernel.function(sys_open).return", sys_open_return);
    
    run();
    
    printf("sys_open() called %d times.\n", count);
    return 0;
}
