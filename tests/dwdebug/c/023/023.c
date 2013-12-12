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

struct foo_struct_1 fs1;

union foo_union_1 {
    int x;
    int y;
    struct foo_struct_1 *pfs1;
    struct foo_struct_1 fs1;
};

struct foo_struct_1 fu1;

extern int tc1_main(int argc,char **argv);
extern int tc2_main(int argc,char **argv);

int main(int argc,char **argv) {
    PRINTHEADER();

    tc1_main(argc,argv);
    tc2_main(argc,argv);

    return 0;
}
