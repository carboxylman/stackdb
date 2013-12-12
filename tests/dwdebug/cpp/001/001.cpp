#include "tests.hpp"

namespace n1 {
    int x;
    int y;

    int set(int x,int y);
}

namespace n2 {
    int x2;
    int y2;

    int set(int x,int y);
}

int n1::set(int x,int y) {
    n1::x = x;
    n1::y = y;
}

int n2::set(int x,int y) {
    n2::x2 = x;
    n2::y2 = y;
}

int main(int argc,char **argv) {
    volatile int result;

    using n1::x;
    using n2::y2;

    PRINTHEADER();

    n1::set(1,2);
    n2::set(2,1);

    result = x + y2;

    PRINTF("result = %d\n",result);

    return 0;
}
