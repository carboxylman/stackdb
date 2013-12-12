#include "tests.hpp"

namespace {
    int x;
    int y;

    int set(int xn,int yn) {
	x = xn;
	y = yn;
    }
}

int main(int argc,char **argv) {
    int x;
    int xn;
    volatile int result;

    PRINTHEADER();

    set(1,2);

    result = x + y;

    PRINTF("result = %d\n",result);

    return 0;
}
