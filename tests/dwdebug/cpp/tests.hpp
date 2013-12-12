#ifdef __GNUC__
#define NOINLINE  __attribute__ ((noinline))
#define INLINE  __attribute__ ((always_inline))
#else
#define NOINLINE noinline
#define INLINE inline
#endif

#ifdef WITH_RUNNABLE
#include <iostream>
#include <cstdio>
#define PRINTF(fmt,...)  std::printf(fmt, ## __VA_ARGS__)
#else
#define PRINTF(fmt,...) 
#endif

#ifdef TESTNAME
#ifdef WITH_RUNNABLE
#define PRINTHEADER() std::cout << "Running test '" << TESTNAME << "'" << std::endl
#else
#define PRINTHEADER()
#endif
#define PRINTFHEADER(fmt,...) PRINTF("Running test '%s': " fmt "\n", \
				     TESTNAME, ## __VA_ARGS__)
#else
#ifdef WITH_RUNNABLE
#define PRINTHEADER() std::cout << "Running test '" << TESTNUM << "'" << std::endl
#else
#define PRINTHEADER()
#endif
#define PRINTFHEADER(fmt,...) PRINTF("Running test '%d': " fmt "\n", \
				     TESTNUM, ## __VA_ARGS__)
#endif
