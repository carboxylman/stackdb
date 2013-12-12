#ifndef __002_HPP__
#define __002_HPP__

namespace n1 {
    extern int x;
    extern int y;

    int set(int sx,int sy);
    int ext_set(int ex,int ey);

    namespace n2 {
	using n1::x;
	extern int x2;
	extern int y2;

	int set(int sx,int sy);
	int ext_set(int ex,int ey);
    }
}

#endif
