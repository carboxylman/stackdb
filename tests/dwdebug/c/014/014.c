#ifdef WITH_RUNNABLE
#define _GNU_SOURCE
#endif

#include "tests.h"

#ifdef WITH_RUNNABLE
#include <unistd.h>
#include <sys/syscall.h>
#include <signal.h>
#endif

int baz;
int bar = 0;

struct foo_struct {
    int argc;
    char **argv;
    int sx;
    int sy;
};

int f10(int p,int x,int y,int *z) {
    struct foo_struct foo = {
	.sx = x,
	.sy = y,
    };

    int f10_subfunc(int psub) {
	struct foo_struct foosub = {
	    .sx = x + psub,
	    .sy = y + psub,
	};
	PRINTF("f10_subfunc -> %d",psub);
	return psub;
    }

    bar = bar + 4;

    PRINTF("f10 -> %d %d ",p,*z);
    f10_subfunc(p + 1);
    PRINTF("\n");
    return p;
}

int f9(int p,int x,int y,int *z) {
    PRINTF("f9 -> ");
    int retval = p;
    *z *= 4;
    retval += f10(p + 1,p*2,p*3,z);
    *z /= 4;
    return retval - p;
}

int f8(int p,int x,int y,int *z) {
    PRINTF("f8 -> ");
    int retval = p;
    *z *= 4;
    retval += f9(p + 1,p*2,p*3,z);
    *z /= 4;
    return retval - p;
}

int f7(int p,int x,int y,int *z) {
    PRINTF("f7 -> ");
    int retval = p;
    *z *= 4;
    retval += f8(p + 1,p*2,p*3,z);
    *z /= 4;
    return retval - p;
}

int f6(int p,int x,int y,int *z) {
    PRINTF("f6 -> ");
    int retval = p;
    *z *= 4;
    retval += f7(p + 1,p*2,p*3,z);
    *z /= 4;
    return retval - p;
}

int f5(int p,int x,int y,int *z) {
    PRINTF("f5 -> ");
    int retval = p;
    *z *= 4;
    retval += f6(p + 1,p*2,p*3,z);
    *z /= 4;
    return retval - p;
}

int f4(int p,int x,int y,int *z) {
    PRINTF("f4 -> ");
    int retval = p;
    *z *= 4;
    retval += f5(p + 1,p*2,p*3,z);
    *z /= 4;
    return retval - p;
}

int f3(int p,int x,int y,int *z) {
    PRINTF("f3 -> ");
    int retval = p;
    *z *= 4;
    retval += f4(p + 1,p*2,p*3,z);
    *z /= 4;
    return retval - p;
}

int f2(int p,int x,int y,int *z) {
    PRINTF("f2 -> ");
    int retval = p;
    *z *= 4;
    retval += f3(p + 1,p*2,p*3,z);
    *z /= 4;
    return retval - p;
}

int f1(int p,int x,int y,int *z) {
    PRINTF("f1 -> ");
    int retval = p;
    *z *= 4;
    retval += f2(p + 1,p*2,p*3,z);
    *z /= 4;
    return retval - p;
}

#ifdef WITH_RUNNABLE
int gettid() {
    return syscall(SYS_gettid);
}

void sigh(int signo) {
    PRINTF("caught signal %d\n",signo);
    return; //exit(1);
}

int dosmash = 0;

void sigu(int signo) {
    dosmash = 1;
}
#endif

int main(int argc,char **argv) {
    volatile int i = 0;
    int max = -1;

    PRINTHEADER();

    baz = 0;

    if (argc > 1)
	max = atoi(argv[1]);

    PRINTF("argc %d at %p; argv at %p; i at %p; max %d at %p\n",
	   argc,&argc,argv,&i,max,&max);

#ifdef WITH_RUNNABLE
    signal(SIGTRAP,sigh);
    signal(SIGUSR1,sigu);
#endif

    sleep(2);

    for (i = 0; max <= 0 || i < max; i += 4) {
	bar = baz = i;
        //asm("int $3");
	sleep(4);
	PRINTF("tid %d slept %d (%d) (%d)\n",
	       gettid(),i,bar,baz);
	f1(i,i,i,&baz);
    }

    return 0;
}
