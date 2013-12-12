#include "tests.h"

typedef const long unsigned clu_t;
typedef volatile long int vli_t;

static clu_t cult = 33 * 3;
static const long unsigned cul = 33 * 3;
static long unsigned lu = 33 * 3;

static vli_t vilt = -33 * 3;
static volatile long int vli = -33 * 3;
static long int li = -33 * 3;

static int i = 11 * 3;

int tc2_main(int argc,char **argv) {
    PRINTFHEADER("tc1");

    return 0;
}
