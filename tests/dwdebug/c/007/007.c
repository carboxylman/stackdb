#include "tests.h"

union foo_union_2 {
    int sfoo;
    int **sppfoo;

    union foo_union_1 {
	int a;
	long b;
	char str[44];
    } x;

    union foo_union_1 fs1;
    union foo_union_1 *pfs1;
} fs2;

typedef union foo_union_3 {
    char *(*snprintf)(char *fmt,...);
    char *header;
    int fileno;

    union xys_union {
	int x;
	int y;
    } xys;

    union foo_union_2 fs2;
    union foo_union_2 *pfs2;
} foo_union_3_t;

int main(int argc,char **argv) {
    foo_union_3_t fs3t;

    PRINTHEADER();

    return 0;
}
