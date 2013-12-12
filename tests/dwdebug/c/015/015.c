#include "tests.h"

struct global_struct {
    int x;
    float y;
};

INLINE int foo_func(int p,int x,int y,int argc,char **argv) {
    const volatile int i;
    struct global_struct gs1 = { .x = x, .y = y };
    struct global_struct *pgs1 = &gs1;

    struct foo_func_struct {
	char **argv;
	int argc;
    };

    INLINE int foo_nested_func(int pinc,struct foo_func_struct *ffs) {
	struct foo_func_struct ffscopy;
	volatile int j;

	if (ffs)
	    ffscopy = *ffs;

#ifdef WITH_STDIO
	printf("f10_nested_func -> %d %d\n",pinc,ffscopy.argc);
#endif
	if (ffscopy.argc > 0 && ffscopy.argv) {
	    for (j = 0; j < ffscopy.argc; ++j) {
#ifdef WITH_STDIO
		printf(" '%s'",ffscopy.argv[j]);
#endif
		ffscopy.argv[argc - 1 - j] = ffscopy.argv[j];
	    }
	}

	++pinc;

	return pinc;
    }

    ++p;

#ifdef WITH_STDIO
    printf("f10 -> %d\n",p);
#endif

    struct foo_func_struct ffsarg = { argv,argc };

    foo_nested_func(p,&ffsarg);

    return p;
}

int main(int argc,char **argv) {
    int i;

    PRINTHEADER();

    for (i = 0; i < 8; ++i) {
	foo_func(i,i*2,i*3,argc,argv);
    }

    return 0;
}
