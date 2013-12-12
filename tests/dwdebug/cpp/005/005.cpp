#include "tests.hpp"
#include "005.hpp"

int Foo::setFbe(enum Bar be) {
    this->fbe = be;

    return 0;
}
int Foo::getFbe(void) {
    return this->fbe;
}

int main(int argc,char **argv) {
    Foo f;

    PRINTHEADER();

    f.setFbe(Foo::FooBarTwo);

#ifdef WITH_RUNNABLE
    std::cout << "fbe = " << f.getFbe() << std::endl;
#endif

    return 0;
}
