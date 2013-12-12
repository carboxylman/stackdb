#include "tests.h"

typedef char *(*printf_t)(char *fmt,...);

int main(int argc,char **argv) {
    volatile int i;
    printf_t spf;

    PRINTHEADER();

#ifdef WITH_RUNNABLE
    spf = printf;
#endif

    for (i = 0; i < argc; ++i) {
	if (spf)
	    spf("%d='%s' ",i,argv[i]);
    }

    return 0;
}
