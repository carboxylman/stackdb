/*
 * Use the awesome dwarf debug library.
 */
#include <assert.h>

#include <bts.h>
#include <dwdebug.h>

static struct debugfile_load_opts opts = {
    .flags = DEBUGFILE_LOAD_FLAG_REDUCETYPES|DEBUGFILE_LOAD_FLAG_PARTIALSYM
};

static struct symmap *mymap;
static int mymapsize;

int
symbol_init(struct symmap map[], int nmap)
{
	int i, j;
	struct debugfile *dbfile;

	dwdebug_init();

	for (i = 0; i < nmap; i++) {
		if (map[i].symfile) {
			dbfile = debugfile_filename_create(map[i].symfile,
							   DEBUGFILE_TYPE_MAIN);
			if (!dbfile) {
				fprintf(stderr, "ERROR: could not create debugfile from %s!\n",
						map[i].symfile);
				goto bad;
			}
			if (debugfile_load(dbfile, &opts)) {
				fprintf(stderr, "ERROR: could not read symbols from %s!\n",
						map[i].symfile);
				goto bad;
			}
			map[i].dbfile = dbfile;
		}
	}

	mymap = map;
	mymapsize = nmap;
	return 0;

 bad:
	if (dbfile)
		debugfile_free(dbfile, 0);
	for (j = 0; j < i; j++) {
		if (map[j].dbfile) {
			debugfile_free(map[j].dbfile, 0);
			map[j].dbfile = NULL;
		}
	}
	dwdebug_fini();
	return -1;
}

void
symbol_string(uint32_t addr, char *buf, int bufsize)
{
    struct lsymbol *lsymbol = NULL;
    char *prefix = "";
    int i;

    assert(buf != NULL);
    assert(bufsize > 0);

    for (i = 0; i < mymapsize; i++) {
	if (addr >= mymap[i].loaddr && addr <= mymap[i].hiaddr &&
	    mymap[i].dbfile) {
	    lsymbol = debugfile_lookup_addr(mymap[i].dbfile, addr);
	    if (mymap[i].prefix)
		prefix = mymap[i].prefix;
	    break;
	}
    }

    if (lsymbol) {
	struct symbol *s = lsymbol_get_noninline_parent_symbol(lsymbol);

	/* gdb style */
	if (s->base_addr == addr)
	    snprintf(buf, bufsize, "0x%08x <%s%s>",
		     addr, prefix, symbol_get_name(s));
	else
	    snprintf(buf, bufsize, "0x%08x <%s%s+%u>",
		     addr, prefix, symbol_get_name(s), addr - s->base_addr);
    } else {
	snprintf(buf, bufsize, "0x%08x", addr);
    }
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
