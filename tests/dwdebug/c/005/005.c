#include "tests.h"

struct foo_struct_2 {
    int sfoo;
    int **sppfoo;

    struct foo_struct_1 {
	int a;
	long b;
	char str[44];
	struct {
	    unsigned int z;
	    struct {
		unsigned int y;
	    };
	};
    } fs1_inline;

    struct foo_struct_1 fs1;
    struct foo_struct_1 *pfs1;
} fs2;

struct foo_struct_3 {
    char *(*snprintf)(char *fmt,...);
    char *header;
    int fileno;

    struct foo_struct_1_2 {
	int aa;
	long bb;
	char strstr[44];
	struct {
	    struct {
		unsigned int yy;
	    } y;
	    unsigned int zz;
	} z;
    };

    struct foo_struct_1 fs1t1;
    struct foo_struct_1_2 *pfs1t1;
} fs3;

int main(int argc,char **argv) {
    struct foo_struct_3 fs3 = { 0 };

    PRINTHEADER();

    return 0;
}
