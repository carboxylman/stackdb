#define _GNU_SOURCE

#include <sys/mman.h>
#include <dlfcn.h>

/*
 * Wrap __libc_start_main so that we mlockall/munlockall before
 * executing anything.  This is a best-effort, least-intrusion attempt
 * to force all of the process's virtual address text pages to be loaded
 * before main().  They may later be *unloaded*, but by default main()
 * will begin with all pages loaded into RAM and in the page table.
 * Well, of course it's not guaranteed; but it should work on any
 * reasonable kernel that is not experiencing memory pressure.
 */
int __libc_start_main(int (*main) (int,char **,char **),
		      int argc,char **ubp_av,
		      void (*init) (void),
		      void (*fini)(void),
		      void (*rtld_fini)(void),
		      void (*stack_end)) {
    int (*original__libc_start_main)(int (*main) (int,char **,char **),
				    int argc,char **ubp_av,
				    void (*init) (void),
				    void (*fini)(void),
				    void (*rtld_fini)(void),
				    void (*stack_end));

    mlockall(MCL_CURRENT);
    munlockall();

    original__libc_start_main = dlsym(RTLD_NEXT,"__libc_start_main");
    return original__libc_start_main(main,argc,ubp_av,
				     init,fini,rtld_fini,stack_end);
}
