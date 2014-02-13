#define _GNU_SOURCE

#include <sys/mman.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

/*
 * Wrap __libc_start_main so that we mlockall/munlockall before
 * executing anything.  This is a best-effort, least-intrusion attempt
 * to force all of the process's virtual address text pages to be loaded
 * before main().  They may later be *unloaded*, but by default main()
 * will begin with all pages loaded into RAM and in the page table.
 * Well, of course it's not guaranteed; but it should work on any
 * reasonable kernel that is not experiencing memory pressure.
 */

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#ifndef PROT_SHARED
#define PROT_SHARED 0x8
#endif

/*
 * Linux has long defaulted RLIMIT_MEMLOCK to 32KB, "for gpg".  Shoot
 * for that and fall back to a page if it doesn't work...
 */
#define MAX_MLOCK_BYTES 32 * 1024

static size_t mlock_len = MAX_MLOCK_BYTES;

int mlock_page_range(unsigned long start,unsigned long end) {
    unsigned long current;
    int retval = 0;

    current = start;
    while (current < end) {
	if (mlock((const void *)current,mlock_len)) {
	    if (mlock_len < MAX_MLOCK_BYTES) {
		++retval;
	    }
	    else {
		/* Adjust lower to single page, try again */
		mlock_len = PAGE_SIZE;
		continue;
	    }
	}
	else
	    munlockall();
	    //munlock((const void *)current,mlock_len);

	current += mlock_len;
    }

    return retval;
}

typedef enum {
    REGION_TYPE_FILE = 1,
    REGION_TYPE_HEAP,
    REGION_TYPE_STACK,
    REGION_TYPE_VDSO,
    REGION_TYPE_VSYSCALL,
    REGION_TYPE_ANON,
} region_type_t;

int __libc_start_main(int (*main) (int,char **,char **),
		      int argc,char **ubp_av,
		      void (*init) (void),
		      void (*fini)(void),
		      void (*rtld_fini)(void),
		      void (*stack_end)) {
    int (*original__libc_start_main)(int (*main) (int,char **,char **),
				    int argc,char **ubp_av,
				    void (*init) (void),
				    void (*fini)(void),
				    void (*rtld_fini)(void),
				    void (*stack_end));
    /*
     * We pick 512 on purpose -- it should not force us to require a new
     * stack page yet -- and it should be big enough to read "any
     * conceivable" /proc/pid/maps line.  We could use PATH_MAX+n, but
     * PATH_MAX is really big (i.e., a page, I think).  So arbitrarily
     * split the difference and try to play nice for the stack.
     * Obviously we could check the stack pointer and really play nice,
     * but eh.
     */
#define LBUFSIZ 512
    char buf[LBUFSIZ];
    char buf2[LBUFSIZ];
    FILE *f;
    int errors = 0;
    region_type_t rt;
    int pf;
    unsigned long long start,end,offset;
    int rc;
    char p[4];

    /* Open the maps file... */
    snprintf(buf,LBUFSIZ,"/proc/%d/maps",getpid());
    f = fopen(buf,"r");
    if (!f)
	goto errout;

    /* Read the maps file and mlock in chunks. */
    while (1) {
	rt = 0;
	pf = 0;

	errno = 0;
	/*
	 * If it was an error, try to inform the user if they care.  If
	 * error or just EOF, quit; this is best-effort.
	 */
	if (!fgets(buf,LBUFSIZ,f)) {
	    if (errno)
		errors *= 100000;
	    break;
	}

	//fprintf(stderr,"scanning mmap line %s",buf);

	rc = sscanf(buf,"%Lx-%Lx %c%c%c%c %Lx %*x:%*x %*d %s",&start,&end,
		    &p[0],&p[1],&p[2],&p[3],&offset,buf2);
	if (rc == 8 || rc == 7) {
	    rt = 0;
	    if (rc == 8) {
		/* we got the whole thing, including a path */
		if (strcmp(buf,"[heap]") == 0) 
		    rt |= REGION_TYPE_HEAP;
		else if (strcmp(buf,"[stack]") == 0) 
		    rt |= REGION_TYPE_STACK;
		else if (strcmp(buf,"[vdso]") == 0) 
		    rt |= REGION_TYPE_VDSO;
		else if (strcmp(buf,"[vsyscall]") == 0) 
		    rt |= REGION_TYPE_VSYSCALL;
		else
		    rt |= REGION_TYPE_FILE;
	    }
	    else {
		rt |= REGION_TYPE_ANON;
	    }

	    pf = 0;
	    if (p[0] == 'r')
		pf |= PROT_READ;
	    if (p[1] == 'w')
		pf |= PROT_WRITE;
	    if (p[2] == 'x')
		pf |= PROT_EXEC;
	    if (p[3] == 's')
		pf |= PROT_SHARED;

	    /*
	     * XXX: in the future, check LOADALL_REGIONS env var to see
	     * which regions we should "lock and load"...
	     */
	    errors += mlock_page_range(start,end);
	}
	else if (rc > 0 && !errno) {
	    errors *= 10000;
	    //fprintf(stderr,"weird content in /proc/pid/maps (%d)!\n",rc);
	}
	else if (rc > 0 && errno) {
	    errors *= 10000;
	    //fprintf(stderr,"weird content in /proc/pid/maps (%d): %s!\n",rc,strerror(errno));
	}
    }
    fclose(f);

    goto out;

 errout:
    snprintf(buf,64,"LOADALL_ERR=%d",errors);
    putenv(buf);

 out:
    original__libc_start_main = dlsym(RTLD_NEXT,"__libc_start_main");
    return original__libc_start_main(main,argc,ubp_av,
				     init,fini,rtld_fini,stack_end);
}
