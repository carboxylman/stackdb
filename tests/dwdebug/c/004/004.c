#include "tests.h"

struct foo_struct_2 {
    int sfoo;
    int **sppfoo;

    struct foo_struct_1 {
	int a;
	long b;
	char str[44];

	struct xys_struct_1 {
	    int x;
	    int y;
	} xys;
    } x;

    struct foo_struct_1 fs1;
    struct foo_struct_1 *pfs1;
} fs2;

typedef struct foo_struct_3 {
    char *(*snprintf)(char *fmt,...);
    char *header;
    int fileno;

    struct xys_struct_2 {
	int x;
	int y;
    } xys;

    struct foo_struct_2 fs2;
    struct foo_struct_2 *pfs2;
} foo_struct_3_t;

int main(int argc,char **argv) {
    foo_struct_3_t fs3t;

    PRINTHEADER();

    return 0;
}
