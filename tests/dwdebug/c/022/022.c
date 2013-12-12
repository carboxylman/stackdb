#include "tests.h"

typedef const long unsigned clu_t;
typedef volatile long int vli_t;

clu_t cult = 33;
const long unsigned cul = 33;
long unsigned lu = 33;

vli_t vilt = -33;
volatile long int vli = -33;
long int li = -33;

int i = 11;

extern int tc1_main(int argc,char **argv);
extern int tc2_main(int argc,char **argv);

int main(int argc,char **argv) {
    PRINTHEADER();

    tc1_main(argc,argv);
    tc2_main(argc,argv);

    return 0;
}
