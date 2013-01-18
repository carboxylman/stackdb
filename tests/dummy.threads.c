#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

#include <stdio.h>
//#include <locale.h>
#include <wchar.h>
//#include <wctype.h>
#include <inttypes.h>

#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <string.h>

#include <sys/types.h>
#include <pthread.h>

typedef void *(myfunctype_t)(int ft1,char ft2);

struct funnyst {
    struct {
	char fy1;
	char fy2;
	struct {
	    int x;
	};
    };
    char str[0];
    struct {
	struct {
	    unsigned int y;
	};
    };
} funnyu;

struct sss {
    int sfoo;
    int **sppfoo;
};

typedef struct mystruct {
    myfunctype_t *ftf;
    char *header;
    struct {
	int x;
	int y;
    } xys;
    int bar;
    short bf1:5,
	bf2:8,
	bf3:2,
	bf4:1;
    struct sss *sssarr[5];
    struct sss *sssp;
} mystruct;

struct mystruct ms1 = {
    .header = "hello, world!",
    .bf1 = 4,
    .bf2 = 3,
    .bf3 = 2,
    .bf4 = 1,
};

typedef enum foo_enum {
    FOO_ONE = 1,
    FOO_TWO = 2,
} foo_enum;

enum foo_enum X;

static int foo = offsetof(mystruct,xys.x);
volatile int bar;

typedef void myvoid;
typedef void * myvoidptr_t;

void inline __attribute__ ((always_inline)) voidfunc(int vfa) {
    printf("voidfunc1\n");
    //asm("int $3");
    printf("voidfunc1\n");
    return;
}

char xarr[3][2] = { { 'a','A' }, { 'b','B' }, { 'c','C' } };

void sigh(int signo) {
    printf("caught signal %d\n",signo);
    return; //exit(1);
}

int dosmash = 0;

void sigu(int signo) {
    dosmash = 1;
}

char *baz = "bazzzz";

myvoidptr_t voidptrfunc();

int silly(int x,int y) {
    printf("silly: x = %d (%p), y = %d (%p)\n",
	   x,&x,y,&y);
    voidptrfunc();

    ++**ms1.sssp->sppfoo;

    return x + y;
}

myvoidptr_t voidptrfunc() {
    char c[8];
    //asm("int $3");
    if (dosmash) {
#if __WORDSIZE == 64
	uint64_t s = (uint64_t)silly;
	memcpy(c+sizeof(uint64_t)*3,&s,sizeof(uint64_t));
#else
	uint32_t s = (uint32_t)silly;
	memcpy(c+sizeof(uint32_t)*3,&s,sizeof(uint32_t));

#endif
	dosmash = 0;
    }
    printf("voidptrfunc %c\n",c[0]);
    return NULL;
}

int f10(int p,int x,int y,int z) {
    struct mystruct msfoo = {
	.header = "f10 mystruct",
    };

    int f10_subfunc(int psub) {
	struct mystruct msfoosub = {
	    .header = "f10_subfunc mystruct",
	};
	printf("f10_subfunc -> %d\n",psub);
	return psub;
    }

    printf("f10 -> %d\n",p);
    f10_subfunc(p+1);
    return p;
}

int f9(int p,int x,int y,int z) {
    printf("f9 -> ");
    return f10(p + 1,p*2,p*3,p*4);
}

int f8(int p,int x,int y,int z) {
    printf("f8 -> ");
    return f9(p + 1,p*2,p*3,p*4);
}

int f7(int p,int x,int y,int z) {
    printf("f7 -> ");
    return f8(p + 1,p*2,p*3,p*4);
}

int f6(int p,int x,int y,int z) {
    printf("f6 -> ");
    return f7(p + 1,p*2,p*3,p*4);
}

int f5(int p,int x,int y,int z) {
    printf("f5 -> ");
    return f6(p + 1,p*2,p*3,p*4);
}

int f4(int p,int x,int y,int z) {
    printf("f4 -> ");
    return f5(p + 1,p*2,p*3,p*4);
}

int f3(int p,int x,int y,int z) {
    printf("f3 -> ");
    return f4(p + 1,p*2,p*3,p*4);
}

int f2(int p,int x,int y,int z) {
    printf("f2 -> ");
    return f3(p + 1,p*2,p*3,p*4);
}

int f1(int p,int x,int y,int z) {
    printf("f1 -> ");
    return f2(p + 1,p*2,p*3,p*4);
}

pid_t gettid() {
    return syscall(SYS_gettid);
}

void *looper(void *istart) {
    volatile int i = *(int *)istart;

    while (1) {
	bar = i += 4;
        //asm("int $3");
	sleep(4);
	printf("thread %d slept %d (%d) (%d)\n",
	       gettid(),i,foo,**ms1.sssp->sppfoo);
	silly(i,i * 10);
	f1(i,i,i,i);

	voidfunc(bar);
    }

    return NULL;
}

int main(int argc,char **argv) {
    const volatile int j;
    //wchar_t *ustr = L"\u201cHello unicoded world\u201d";
    wchar_t euro = 0x20ac;
    pthread_t pthread_id;

    //unsigned long ti = 0x01020304;

    //for (i = 0; i < sizeof(ti); ++i) {
    //	printf("%hhx ",*(((char *)&ti)+i));
    //}
    //printf("\n");

    //setlocale(LC_ALL, "");

    //printf("what a euro looks like: %lc",euro);
    //printf("\n");

    funnyu.fy1 = 'a';
    funnyu.x = 88;
    funnyu.y = 34;

    printf("arg at %p\n",&argc);

    signal(SIGTRAP,sigh);
    signal(SIGUSR1,sigu);

    ms1.sssp = (struct sss *)malloc(sizeof(*ms1.sssp));
    ms1.sssp->sfoo = 23;
    ms1.sssp->sppfoo = (int **)malloc(sizeof(int **));
    *ms1.sssp->sppfoo = (int *)malloc(sizeof(int *));
    **ms1.sssp->sppfoo = 47;

    pthread_create(&pthread_id,NULL,looper,&argc);

    sleep(2);

    argc *= 10;
    looper(&argc);

    return 0;
}
