#ifdef __GNUC__
#define NOINLINE  __attribute__ ((noinline))
#define INLINE  __attribute__ ((always_inline))
#else
#define NOINLINE noinline
#define INLINE inline
#endif

#ifdef WITH_RUNNABLE
#include <stdio.h>
#define PRINTF(fmt,...)  printf(fmt, ## __VA_ARGS__)
#else
#define PRINTF(fmt,...) 
#endif

#ifdef TESTNAME
#define PRINTHEADER() PRINTF("Running test '%s'\n",TESTNAME)
#define PRINTFHEADER(fmt,...) PRINTF("Running test '%s': " fmt "\n", \
				     TESTNAME, ## __VA_ARGS__)
#else
#define PRINTHEADER() PRINTF("Running test '%d'\n",TESTNUM)
#define PRINTFHEADER(fmt,...) PRINTF("Running test '%d': " fmt "\n", \
				     TESTNUM, ## __VA_ARGS__)
#endif
