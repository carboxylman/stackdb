#include "tests.hpp"

namespace n1 {
    int x;
    int y;

    /*
    void setspecial(void) {
	s = 44;
    }
    */

    int set(int x,int y);

    namespace n2 {
	int x2;
	int y2;

	int set(int x,int y);
    }

    namespace {
	int ax;
	int ay;

	int set(int axn,int ayn) {
	    ax = axn;
	    ay = ayn;
	}
    }

    int aset(int x,int y) {
	ax = x * 2;
	ay = y * 2;
    }
}

namespace special {
    int s;
}

namespace n1 {
    int foo;
}

using namespace special;

int n1::set(int x,int y) {
    n1::x = x;
    n1::y = y;

    n1::foo = n1::x + n1::y;

    s = 33;

    aset(x,y);
}

int n1::n2::set(int x,int y) {
    n1::n2::x2 = x;
    n1::n2::y2 = y;
}

int main(int argc,char **argv) {
    volatile int result;

    using n1::x;
    using n1::n2::y2;

    PRINTHEADER();

    n1::set(1,2);
    n1::n2::set(2,1);

    result = x + y2;

    PRINTF("result = %d\n",result);

    return 0;
}
