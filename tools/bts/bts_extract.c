/*
 * Extract a BTS trace from a Xen TT event log.
 */
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <xen/xen.h>
#include <xen/time_travel.h>

#include <bts.h>
#include <xentt.h>

static void bts_dump(const char *infile, char *outfile);
static int bts_dump_branch(struct ttd_rec *rec, FILE *fd);

struct brctr_val {
    uint64_t value;
    uint64_t radius;
};

int extended = 0;
int debug = 0;
struct brctr_val startat = { .value = 0, .radius = 0 };
struct brctr_val endat = { .value = UINT64_MAX, .radius = 0 };
uint64_t loval, hival;

static void
usage(void)
{
    fprintf(stderr, "Usage: bts-extract [-d] [-S val[:radius]] [-E val[:radius]] [-o outfile] xentt_event_log\n");
    fprintf(stderr, " Extracts BTS records from a XenTT replay log,\n");
    fprintf(stderr, " dumping them to stdout or a logfile (-o). Optionally\n");
    fprintf(stderr, " takes start and end branch counter values to limit\n");
    fprintf(stderr, " the range of the dumped records.\n");
    fprintf(stderr, "  -d               Turn on debugging.\n");
    fprintf(stderr, "  -x               Extended format, include brctr.\n");
    fprintf(stderr, "  -S val[:radius]  Starting brctr value and optional radius\n");
    fprintf(stderr, "  -E val[:radius]  Ending brctr value and optional radius\n");
    fprintf(stderr, "  -o outfile       Output file (stdout is default)\n");
    exit(1);
}

static int
get_brctr(char *arg, struct brctr_val *val)
{
    char *bp = index(arg, ':');
    if (bp) {
	bp[0] = '\0';
	if (bp[1] != '\0')
	    val->radius = strtoull(&bp[1], NULL, 0);
    }
    val->value = strtoull(arg, NULL, 0);
    if (bp)
	bp[0] = ':';

    return 0;
}

/*
 * XXX doesn't handle overlap of low and high values yet.
 */
static void
set_range(void)
{
    if (startat.value > startat.radius)
	loval = startat.value - startat.radius;
    else
	loval = 0;

    if (endat.value + endat.radius >= endat.value)
	hival = endat.value + endat.radius;
    else
	hival = UINT64_MAX;
}

int main(int argc, char **argv)
{
    char ch;
    char *outfile = 0;

    while ((ch = getopt(argc, argv, "dxS:E:o:")) != -1) {
	switch(ch) {
	case 'd':
	    debug++;
	    break;
	case 'x':
	    extended++;
	    break;
	case 'S':
	    if (get_brctr(optarg, &startat)) {
		fprintf(stderr, "invalid brctr value %s\n", optarg);
		usage();
	    }
	    break;
	case 'E':
	    if (get_brctr(optarg, &endat)) {
		fprintf(stderr, "invalid brctr value %s\n", optarg);
		usage();
	    }
	    break;
	case 'o':
	    outfile = optarg;
	    break;
	}
    }
    argc -= optind;
    argv += optind;

    if (argc != 1)
	usage();

    set_range();

    bts_dump(*argv, outfile);
    exit(0);
}

#define NCPU 8
static uint64_t curbrctr[NCPU];

static void bts_dump(const char *fname, char *outfile)
{
    struct ttd_rec *rec;
    unsigned long nrec, nbtsrec;
    uint64_t lofound = UINT64_MAX, hifound = 0;
    FILE *fd, *ofd;

    fd = fopen(fname, "r");
    if (fd == NULL) {
	fprintf(stderr, "Could not open XenTT log\n");
	return;
    }

    if (outfile) {
	ofd = fopen(outfile, "w");
	if (ofd == NULL) {
	    fprintf(stderr, "Could not open output file %s\n", outfile);
	    return;
	}
    } else
	ofd = stdout;

    if (debug) {
	fprintf(stderr, "Dumping BTS records from %s", fname);
	if (loval != 0 || hival != UINT64_MAX) {
	    fprintf(stderr, " in range [%llu-", loval);
	    if (hival == UINT64_MAX)
		fprintf(stderr, "end]");
	    else
		fprintf(stderr, "%llu]", hival);
	}
	if (extended)
	    fprintf(stderr, " in extended format");
	fprintf(stderr, " ...\n");
    }

    /*
     * Write a magic record indicating this is an extended dump.
     */
    if (extended) {
	struct bts_rec _rec;
	_rec.from = _rec.to = _rec.format = UINT64_MAX;
	fwrite(&_rec, sizeof(_rec), 1, ofd);
    }

    nrec = 0;
    while ((rec = xentt_readlog(fd)) != 0) {
	if (extended) {
	    assert(rec->vcpu_id < NCPU);
	    curbrctr[rec->vcpu_id] = rec->cpu_state.brctr_virt;
	}
	switch (rec->event.event) {
	case TTD_HW_BRANCHES:
	case TTD_HW_BRANCHES_64:
	    if (bts_dump_branch(rec, ofd))
		exit(1);
	    if (debug) {
		if (rec->cpu_state.brctr_virt < lofound)
		    lofound = rec->cpu_state.brctr_virt;
		if (rec->cpu_state.brctr_virt > hifound)
		    hifound = rec->cpu_state.brctr_virt;
	    }
	    nrec++;
	    nbtsrec += rec->data_len / sizeof(struct bts_rec);
	    break;
	default:
	    break;
	}
	free(rec);
    }

    fclose(fd);

    if (debug) {
	fprintf(stderr, "Found %lu log records ", nrec);
	if (nrec)
	    fprintf(stderr, "with range [%llu-%llu] ", lofound, hifound);
	if (nbtsrec)
	    fprintf(stderr, "containing %lu BTS records", nbtsrec);
	fprintf(stderr, "\n");
    }
}

static int bts_dump_branch(struct ttd_rec *rec, FILE *ofd)
{
    uint64_t brctr;

    assert(rec->event.event == TTD_HW_BRANCHES ||
	   rec->event.event == TTD_HW_BRANCHES_64);
    assert((rec->data_len % sizeof(struct bts_rec)) == 0);

    brctr = rec->cpu_state.brctr_virt;
    if (debug > 1) {
	int nrec = rec->data_len / sizeof(struct bts_rec);
	fprintf(stderr, "0x%08lx/%012llu: found %d records\n",
		rec->cpu_state.ip, brctr, nrec);
    }

    /*
     * Stash our value of the branch counter in the otherwise unused
     * format field.
     */
    if (extended) {
	struct bts_rec *brec = (struct bts_rec *)rec->data;
	struct bts_rec *erec = (struct bts_rec *)((void *)rec->data + rec->data_len);

	while (brec < erec) {
	    brec->format = curbrctr[rec->vcpu_id];
/* this does not yield a monotonically increasing log */
#if 0
	    curbrctr[rec->vcpu_id]++;
#endif
	    brec++;
	}
    }

    if (brctr >= loval && brctr <= hival) {
	if (fwrite(rec->data, rec->data_len, 1, ofd) == 1)
	    return 0;
	fprintf(stderr, "error writing record\n");
    }

    return 1;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
