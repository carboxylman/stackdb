#include "tests.hpp"
#include "006.hpp"

/*
 * This is fun test case.  Basically, if we do
 *   using namespace N1;
 * then everything that follows get put into N1, even the anonymous
 * file-local namespace!  If we instead wrap the functions in namespace
 * N1 { ... }, or define them with fully-qualified names (the preferred
 * solution, to me), then things are good and main() ends up in the
 * non-namespace.
 */

//using namespace N1;

//namespace N1 {
//    class Foo;
int N1::Foo::setFbe(enum Bar be) {
    this->fbe = be;

    return 0;
}
int N1::Foo::getFbe(void) {
    return this->fbe;
}
//}

/* Don't want main() in N1.  Undo the 'using' above. */
/* This doesn't work -- main ends up in N1 anyway!  The unnamed
 * namespace goes into N1 :).  Not sure that is legal, but...
 */
//namespace { };

int main(int argc,char **argv) {
    N1::Foo f;

    PRINTHEADER();

    f.setFbe(N1::Foo::FooBarTwo);

#ifdef WITH_RUNNABLE
    std::cout << "fbe = " << f.getFbe() << std::endl;
#endif

    return 0;
}
