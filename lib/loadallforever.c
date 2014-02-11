#define _GNU_SOURCE

#include <sys/mman.h>
#include <dlfcn.h>

/*
 * Wrap __libc_start_main so that we mlockall to force all pages, both
 * now and future, to be loaded into RAM and stay there... unless the
 * process itself changes that policy down the road.  Best-effort, of
 * course.
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

    mlockall(MCL_CURRENT | MCL_FUTURE);

    original__libc_start_main = dlsym(RTLD_NEXT,"__libc_start_main");
    return original__libc_start_main(main,argc,ubp_av,
				     init,fini,rtld_fini,stack_end);
}
