#include "tests.hpp"
#include "002.hpp"

using namespace n1;

int n1::ext_set(int ex,int ey) {
    x = ex;
    y = ey;
}

int n1::n2::ext_set(int ex,int ey) {
    x2 = ex;
    y2 = ey;
}
