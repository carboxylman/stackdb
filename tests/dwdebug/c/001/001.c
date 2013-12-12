#include "tests.h"

#include <stdint.h>

uint64_t u64 = 33;
long int i64 = -33;
int i32 = 11;
float f = 11.1;
double d = 33.3;
char hhd = 'a';
char *string = "foobar";

int main(int argc,char **argv) {
    volatile int i;

    PRINTHEADER();

    for (i = 0; i < argc; ++i) {
	PRINTF("%d='%s' ",i,argv[i]);
    }
    PRINTF("\n");

    double result = i + u64 + i64 + i32 + f + d + hhd;

    PRINTF("result = %lf\n",result);

    return 0;
}
