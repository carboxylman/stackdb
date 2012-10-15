/*
 * Given a BTS trace file, create a control flow trace.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <bts.h>

static void bts_trace(const char *fname);
static void printone(FILE *fd, int depth, char *str, struct bts_rec *rec, int src);
static void printboth(FILE *fd, int depth, char *str, struct bts_rec *rec);

struct symmap symmap[] = {
    /* user space */
    {
	.symfile = NULL,
	.prefix  = "User:",
	.loaddr	 = 0x00000000,
	.hiaddr	 = 0xBFFFFFFF
    },
    /* Linux kernel */
    {
	.symfile = "/boot/vmlinux-syms-2.6.18-xenU",
	.prefix  = "",
	.loaddr	 = 0xC0000000,
	.hiaddr	 = 0xF67FFFFF
    },
    /* Xen */
    {
	.symfile = "/boot/xen-syms-3.0-unstable",
	.prefix  = "Xen:",
	.loaddr	 = 0xF6800000,
	.hiaddr	 = 0xFFFFFFFF
    }
};

int debug = 0;
int doinlined = 0;
char *userbin = NULL;

int main(int argc, char **argv)
{
    char ch;

    while ((ch = getopt(argc, argv, "dIU:")) != -1) {
	switch(ch) {
	case 'd':
	    debug++;
	    break;
	case 'I':
	    doinlined++;
	    break;
	case 'U':
	    userbin = optarg;
	    break;
	}
    }
    argc -= optind;
    argv += optind;

    if (argc < 1) {
	fprintf(stderr, "Usage: bts-trace [-dI] [-U userbin] filename ...\n");
	exit(1);
    }

    if (userbin)
	symmap[0].symfile = userbin;

    /*
     * Open symbol files.
     */
    if (symlist_init(symmap, sizeof(symmap)/sizeof(symmap[0])))
	exit(1);

    bts_trace(*argv);
    exit(0);
}

#define MAXDEPTH 1024

struct funccall {
    char *name;
    uint32_t calladdr;
    uint32_t loaddr;
    uint32_t hiaddr;
    int flags;
};
#define F_IS_INLINED 1

static struct funccall callstack[MAXDEPTH];
static int depth = 0;
static int extended = 0;

extern int symlist_isfunc_2(uint32_t addr, char **namep,
			    int *isinlined, uint32_t *lo, uint32_t *hi);

static void
bts_trace(const char *file)
{
    struct bts_rec recs[1024];
    int n, i;
    long long tot = 0;
    uint32_t curlo = 0, curhi = ~0;
    int currangedepth = 0;

    BTSFD fd = bts_open(file);
    if (fd == 0) {
	fprintf(stderr, "Could not open stream\n");
	return;
    }

    while (1) {
	n = bts_read(fd, recs, 1024);
	if (n == 0)
	    break;

	i = 0;

	/* see if this is extended format */
	if (tot == 0 && recs[0].from == UINT64_MAX &&
	    recs[0].to == UINT64_MAX && recs[0].format == UINT64_MAX) {
	    if (debug)
		fprintf(stderr, "Dump file in extended format\n");
	    extended++;
	    i++;
	}

	callstack[0].name = strdup("<TOP>");

	while (i < n) {
	    int inlined = 0;
	    uint32_t lo, hi;
	    uint32_t addr = recs[i].to;
	    char *name = NULL;

	    /*
	     * Check it the target of the branch is a function entry point.
	     * If so, push another level on the call stack.
	     */
	    if (symlist_isfunc_2(addr, &name, &inlined, &lo, &hi)) {
		/* ignore inlined functions */
		if (inlined && !doinlined) {
		    if (debug) {
			fprintf(stderr, "[%d]: Ignoring inlined function ",
				depth);
			printone(stderr, 0, "", &recs[i], 0);
			fprintf(stderr, "\n");
		    }
		} else {
		    if (debug) {
			fprintf(stderr, "[%d]: Found function ", depth);
			printone(stderr, 0, "", &recs[i], 0);
			fprintf(stderr, "\n");
		    }
		    printone(stdout, depth, "Call to ", &recs[i], 0);
		    fprintf(stdout, "\n");
		    callstack[depth].calladdr = recs[i].from;
		    depth++;
		    callstack[depth].name = name;
		    name = NULL;
		    if (lo != 0 || hi != 0) {
			callstack[depth].loaddr = curlo = lo;
			callstack[depth].hiaddr = curhi = hi;
			currangedepth = depth;
			if (debug) {
			    fprintf(stderr, "[%d]: Range is [0x%x-0x%x]\n",
				    depth, curlo, curhi);
			}
		    } else {
			if (debug) {
			    fprintf(stderr,
				    "WARNING: no range info for func@0x%x\n",
				    addr);
			}
		    }
		    if (inlined)
			callstack[depth].flags |= F_IS_INLINED;
		}
		goto next;
	    }

	    /*
	     * If we are not at the top level, see if the branch might
	     * be a return. A "return" is a branch to anywhere within
	     * 5 bytes following a higher-level call site. We check more
	     * that just one level up to catch tail-call optimization.
	     */
	    if (depth > 0) {
		int d;

		/*
		 * See if the destination is on our call stack
		 */
		if (debug > 1)
		    fprintf(stderr, "Compare 0x%x:\n", addr);
		for (d = depth - 1; d >= 0; d--) {
		    uint32_t raddr = callstack[d].calladdr;
		    if (debug > 1)
			fprintf(stderr, "  rstack[%d]=0x%x (in %s)\n",
				d, raddr, callstack[d].name);
		    if (addr > raddr && addr <= raddr+5) {
			if (debug) {
			    fprintf(stderr, "[%d]: Found return to depth %d (%x in %s) ",
				    depth, d, raddr, callstack[d].name);
			    printone(stderr, 0, "", &recs[i], 0);
			    fprintf(stderr, "\n");
			}
			printone(stdout, depth, "Return from ", &recs[i], 1);
			fprintf(stdout, "\n");
			while (depth > d) {
			    if (callstack[depth].name)
				free(callstack[depth].name);
			    depth--;
			}
			curlo = callstack[d].loaddr;
			curhi = callstack[d].hiaddr;
			currangedepth = d;
			if (debug > 1)
			    fprintf(stderr, "[%d]: Range is [0x%x-0x%x]\n",
				    depth, curlo, curhi);
			break;
		    }
		}

		/*
		 * Didn't find it, probably just a normal branch.
		 * Make sure it is in-scope for the current call level.
		 */
		if (d == -1) {
		    if (debug > 1)
			fprintf(stderr,
				"[%d]: checking branch 0x%x against range [0x%x-0x%x] (from depth %d (%s))\n",
				depth, addr, curlo, curhi, currangedepth,
				callstack[currangedepth].name);
		    if (addr < curlo || addr >= curhi) {
			printboth(stdout, depth, "*** branch ", &recs[i]);
			printf(" out of range [0x%x-0x%x]\n", curlo, curhi-1);
		    }
		}
	    }

	next:
	    if (name)
		free(name);
	    i++;
	}
	tot += n;
    }

    bts_close(fd);
}

static void
printone(FILE *fd, int depth, char *str, struct bts_rec *rec, int src)
{
    char buf[256];

    if (!doinlined)
	symlist_gdb_string(src ? rec->from :rec->to, buf, sizeof(buf));
    else
	symlist_string(src ? rec->from :rec->to, buf, sizeof(buf));
    while (depth-- > 0)
	fprintf(fd, "  ");
    fprintf(fd, "%s%s", str, buf);
    if (extended)
	fprintf(fd, " (bctr=%012llu)", rec->format);
}

static void
printboth(FILE *fd, int depth, char *str, struct bts_rec *rec)
{
    char buf1[256], buf2[256];

    if (!doinlined) {
	symlist_gdb_string(rec->from, buf1, sizeof(buf1));
	symlist_gdb_string(rec->to, buf2, sizeof(buf2));
    } else {
	symlist_string(rec->from, buf1, sizeof(buf1));
	symlist_string(rec->to, buf2, sizeof(buf2));
    }
    while (depth-- > 0)
	fprintf(fd, "  ");
    fprintf(fd, "%sfrom %s to %s", str, buf1, buf2);
    if (extended)
	fprintf(fd, " (bctr=%012llu)", rec->format);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
