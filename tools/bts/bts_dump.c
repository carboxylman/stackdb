#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <bts.h>

static void bts_show(const char *fname);

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
int symbolic = 0;

int main(int argc, char **argv)
{
    char ch;

    while ((ch = getopt(argc, argv, "dS")) != -1) {
	switch(ch) {
	case 'd':
	    debug++;
	    break;
	case 'S':
	    symbolic++;
	    break;
	}
    }
    argc -= optind;
    argv += optind;

    if (argc < 1) {
	fprintf(stderr, "Usage: bts-dump [-dS] filename ...\n");
	exit(1);
    }

    /*
     * Open symbol files.
     */
    if (symbolic && symbol_init(symmap, sizeof(symmap)/sizeof(symmap[0])))
	exit(1);

    while (argc) {
	bts_show(*argv);
	argc--, argv++;
    }
}

static void bts_show(const char *fname)
{
    struct bts_rec recs[1024];
    int n, i, extended = 0;
    long long tot = 0;

    BTSFD fd = bts_open(fname);
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

	while (i < n) {
	    if (extended)
		printf("%012d: ", recs[i].format);
	    else
		printf("%lld: ", tot+i);
	    if (symbolic) {
		char s1[256], s2[256];
		symbol_string(recs[i].from, s1, sizeof(s1));
		symbol_string(recs[i].to, s2, sizeof(s2));
		printf("%s -> %s\n", s1, s2);
	    } else {
		printf("0x%08llx -> 0x%08llx\n", recs[i].from, recs[i].to);
	    }
	    i++;
	}
	tot += n;
    }

    bts_close(fd);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
