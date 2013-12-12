#include "tests.h"

struct foo_struct_1 {
    int a;
    long b;
    char str[44];
    short bf1:5,
	bf2:8,
	bf3:2,
	bf4:1;
} fs1;

struct foo_struct_2 {
    int sfoo;
    int **sppfoo;
};

typedef struct foo_struct_3 {
    char *(*snprintf)(char *fmt,...);
    char *header;
    int fileno;
} foo_struct_3_t;

int main(int argc,char **argv) {
    foo_struct_3_t fs3t;

    PRINTHEADER();

    return 0;
}
