#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>

#include <dlfcn.h>

pid_t gettid() {
    return syscall(SYS_gettid);
}

typedef char *(*zlibVersion)(void);

int main(int argc,char **argv) {
    char *libpath;
    void *lib;
    void *sym;
    char *version;
    int interval = 8;
    int i;

    if (argc > 1) {
	interval = atoi(argv[1]);
	if (interval <= 0)
	    interval = 8;
    }

    if (access("/lib64/libz.so.1",R_OK) == 0)
	libpath = "/lib64/libz.so.1";
    else if (access("/lib/libz.so.1",R_OK) == 0)
	libpath = "/lib/libz.so.1";
    else if (access("/lib/x86_64-linux-gnu/libz.so.1",R_OK) == 0)
	libpath = "/lib/x86_64-linux-gnu/libz.so.1";
    else if (access("/lib/x86-linux-gnu/libz.so.1",R_OK) == 0)
	libpath = "/lib/x86-linux-gnu/libz.so.1";
    else {
	fprintf(stderr,"ERROR: could not find libz.so.1 anywhere!\n");
	exit(-1);
    }

    while (1) {
	printf("Sleeping before linking in libz... ");
	fflush(stdout);
	i = interval;
	while (i) {
	    printf("%d ",i--);
	    fflush(stdout);
	    sleep(1);
	}
	printf("\n");
	fflush(stdout);

	lib = dlopen(libpath,RTLD_NOW | RTLD_GLOBAL);
	sym = dlsym(lib,"zlibVersion");

	version = ((zlibVersion)sym)();
	printf("  zlib version %s\n",version);

	printf("Sleeping before unlinking libz... ");
	fflush(stdout);
	i = interval;
	while (i) {
	    printf("%d ",i--);
	    fflush(stdout);
	    sleep(1);
	}
	printf("\n");
	fflush(stdout);

	dlclose(lib);
	lib = NULL;
	sym = NULL;
	version = NULL;
    }

    return 0;
}
