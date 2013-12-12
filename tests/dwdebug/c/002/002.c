#include "tests.h"

#include <stdint.h>

typedef uint64_t blahtype_t;

const blahtype_t u64 = 33;
volatile long int i64 = -33;
int i32 = 11;
const float f = 11.1;
double d = 33.3;
volatile char hhd = 'a';
char *string = "foobar";

int main(int argc,char **argv) {
    volatile int i;
    const volatile char **pstring = (const volatile char **)&string;

    PRINTHEADER();

    for (i = 0; i < argc; ++i) {
	PRINTF("%d='%s' ",i,argv[i]);
    }
    PRINTF("\n");

    double result = i + u64 + i64 + i32 + f + d + hhd;

    PRINTF("result = %lf\n",result);

    return 0;
}
