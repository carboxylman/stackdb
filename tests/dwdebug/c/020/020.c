#include "tests.h"

unsigned long ul = 33;
long int il = -33;
int i = 11;
float f = 11.1;
double d = 33.3;
char hhd = 'a';
char *string = "foobar";

extern int tc1_main(int argc,char **argv);
extern int tc2_main(int argc,char **argv);

int main(int argc,char **argv) {
    PRINTHEADER();

    tc1_main(argc,argv);
    tc2_main(argc,argv);

    return 0;
}
