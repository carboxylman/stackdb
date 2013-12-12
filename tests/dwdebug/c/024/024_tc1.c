#include "tests.h"

struct foo_struct_1 {
    struct foo_struct_nested {
	int xx;
	int yy;
    } fsn1;

    struct {
	int a;
	int b;
    } abs;

    struct foo_struct_nested *pfsn1;
    struct foo_struct_1 *pfs1;
};

static struct foo_struct_1 fs1;

union foo_union_1 {
    int x;
    int y;
    struct foo_struct_1 *pfs1;
    struct foo_struct_1 fs1;
};

static struct foo_struct_1 fu1;

int tc1_main(int argc,char **argv) {
    PRINTHEADER();

    return 0;
}
