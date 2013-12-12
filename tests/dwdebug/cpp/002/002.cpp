#include "tests.hpp"
#include "002.hpp"

namespace n1 {
    int x;
    int y;

    namespace n2 {
	int x2;
	int y2;
    }
}

int n1::set(int sx,int sy) {
    x = sx;
    y = sy;
}

int n1::n2::set(int sx,int sy) {
    x2 = sx;
    y2 = sy;
    x += sx;
}

int main(int argc,char **argv) {
    volatile int result;

    using n1::x;
    using n1::n2::y2;

    PRINTHEADER();

    n1::set(1,2);
    n1::n2::set(2,1);

    n1::ext_set(1,2);
    n1::n2::ext_set(2,1);

    result = x + y2;

    PRINTF("result = %d\n",result);

    return 0;
}
