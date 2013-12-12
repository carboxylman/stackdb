#include "tests.h"

typedef const long unsigned clu_t;
typedef volatile long int vli_t;

static clu_t cult = 33 * 2;
static const long unsigned cul = 33 * 2;
static long unsigned lu = 33 * 2;

static vli_t vilt = -33 * 2;
static volatile long int vli = -33 * 2;
static long int li = -33 * 2;

static int i = 11 * 2;

int tc1_main(int argc,char **argv) {
    PRINTFHEADER("tc1");

    return 0;
}
