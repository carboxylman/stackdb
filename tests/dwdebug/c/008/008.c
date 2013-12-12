#include "tests.h"

union foo_union_2 {
    int sfoo;
    int **sppfoo;

    union foo_union_1 {
	int a;
	long b;
	char str[44];
	union {
	    unsigned int z;
	    union {
		unsigned int y;
	    };
	};
    } fs1_inline;

    union foo_union_1 fs1;
    union foo_union_1 *pfs1;
} fs2;

union foo_union_3 {
    char *(*snprintf)(char *fmt,...);
    char *header;
    int fileno;

    union foo_union_1_2 {
	int aa;
	long bb;
	char strstr[44];
	union {
	    union {
		unsigned int yy;
	    } y;
	    unsigned int zz;
	} z;
    } x;

    union foo_union_1 fs1t1;
    union foo_union_1_2 *pfs1t1;
} fs3;

int main(int argc,char **argv) {
    union foo_union_3 fs3 = { 0 };

    PRINTHEADER();

    return 0;
}
