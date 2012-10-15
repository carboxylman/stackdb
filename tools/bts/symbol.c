/*
 * Use the awesome dwarf debug library.
 */
#include <assert.h>

#include <bts.h>
#include <dwdebug.h>

static struct debugfile_load_opts opts = {
    .flags = DEBUGFILE_LOAD_FLAG_REDUCETYPES
#if 0
             |DEBUGFILE_LOAD_FLAG_PARTIALSYM
#endif
};

static struct symmap *mymap;
static int mymapsize;

int
symlist_init(struct symmap map[], int nmap)
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

static inline struct lsymbol *
symlist_find(uint32_t addr, struct symmap **map)
{
    struct lsymbol *lsymbol = NULL;
    int i;

    for (i = 0; i < mymapsize; i++) {
	if (addr >= mymap[i].loaddr && addr <= mymap[i].hiaddr &&
	    mymap[i].dbfile) {
	    lsymbol = debugfile_lookup_addr(mymap[i].dbfile, addr);
	    break;
	}
    }
    if (lsymbol == NULL)
	return NULL;

    assert(lsymbol->symbol != NULL);
    if (map)
	*map = &mymap[i];

    return lsymbol;
}

int
symlist_isfunc_2(uint32_t addr, char **namep, int *isinlined,
		 uint32_t *loaddr, uint32_t *hiaddr)
{
    struct lsymbol *lsymbol;
    ADDR saddr, lo, hi;

    /*
     * XXX if symbol is found and our address matches, we consider it
     * a function! I'm sure there is better info in the lsymbol to base
     * our decision on...
     */
    lsymbol = symlist_find(addr, NULL);
    if (lsymbol && lsymbol->symbol->type == SYMBOL_TYPE_FUNCTION &&
	symbol_get_location_addr(lsymbol->symbol, &saddr) == 0 &&
	saddr == addr) {
	char *name = lsymbol_get_name(lsymbol);
#if 0
	printf("addr=%x, name='%s'/%x\n",
	       addr, name, lsymbol->symbol->base_addr);
#endif
	if (isinlined) {
	    struct symbol *s = lsymbol_get_noninline_parent_symbol(lsymbol);
	    if (s)
		name = symbol_get_name(s);
	    if (strncmp(name, "__INLINED", 9) == 0)
		*isinlined = 1;
	    else
		*isinlined = 0;
	}
	if (namep)
	    *namep = strdup(name);

	if (loaddr || hiaddr) {
#if 0
	    if (strcmp(name, "find_vma") == 0 ||
		strcmp(name, "follow_page") == 0) {
		struct dump_info udn = {
		    .stream = stderr,
		    .prefix = "",
		    .detail = 1,
		    .meta = 1,
		};
		lsymbol_dump(lsymbol, &udn);
		fprintf(stderr, "\n");
	    }
#endif
	    if (symbol_get_location_range(lsymbol->symbol, &lo, &hi, NULL)) {
		if (loaddr)
		    *loaddr = 0;
		if (hiaddr)
		    *hiaddr = 0;
	    } else {
		if (loaddr)
		    *loaddr = lo;
		if (hiaddr)
		    *hiaddr = hi;
#if 0
		fprintf(stderr, "%s range is pc %x/%x\n", name, lo, hi);
#endif
	    }
	}
	lsymbol_release(lsymbol);
	return 1;
    }

    if (lsymbol)
	lsymbol_release(lsymbol);
    return 0;
}

int
symlist_isfunc(uint32_t addr)
{
    return symlist_isfunc_2(addr, NULL, NULL, NULL, NULL);
}

static void
__symlist_string(uint32_t addr, char *buf, int bufsize, int gdbstyle)
{
    struct lsymbol *lsymbol;
    struct symbol *osymbol;
    char *name, *oname;
    unsigned long offset, ooffset;
    struct symmap *map;
    char *prefix;
    ADDR saddr;

    assert(buf != NULL);
    assert(bufsize > 0);

    lsymbol = symlist_find(addr, &map);
    if (lsymbol == NULL) {
	snprintf(buf, bufsize, "0x%08x", addr);
	return;
    }

    prefix = map->prefix ? map->prefix : "";

#if 1
    /*
     * XXX this is apparently some sort of inlined anonomous symbol
     */
    if (lsymbol->symbol->name == NULL) {
#if 0
        struct dump_info udn = {
            .stream = stderr,
            .prefix = "",
            .detail = 1,
            .meta = 1,
        };
	fprintf(stderr, "======== ADDR 0x%lx\n", addr);
	lsymbol_dump(lsymbol, &udn);
	fprintf(stderr, "\n========\n");
	osymbol = lsymbol_get_noninline_parent_symbol(lsymbol);
	fprintf(stderr, "non-inline returns %p (%s)\n",
		osymbol, osymbol ? osymbol->name : "<UNDEF>");
	assert(lsymbol->symbol->name != NULL);
#endif
	snprintf(buf, bufsize, "0x%08x", addr);
	goto done;
    }
#endif

    /*
     * Get name and location of the returned symbol.
     */
    name = lsymbol_get_name(lsymbol);
    if (symbol_get_location_addr(lsymbol->symbol, &saddr))
	saddr = addr;
    offset = addr - saddr;

    /*
     * If the symbol is an INLINE function, it will have a whacky name.
     * So we lookup the nearest containing function and get the name and
     * location of that. If the original name and the name returned here
     * (the "outer" name) are the same, then it wasn't an inline function
     * symbol.
     *
     * We use the outer name when presenting in "GDB style" since that is
     * what GDB does. We also use it to give a more exact specification
     * for an inlined function, see below.
     */
    osymbol = lsymbol_get_noninline_parent_symbol(lsymbol);
    if (osymbol) {
	oname = symbol_get_name(osymbol);
	if (symbol_get_location_addr(osymbol, &saddr))
	    saddr = addr;
	ooffset = addr - saddr;
    } else {
	oname = name;
	ooffset = offset;
    }

#if 0
    printf("addr=%x, name='%s'/%x, outername='%s'/%x, innername='%s'\n",
	   addr,
	   name, lsymbol->symbol->base_addr,
	   oname, osymbol ? osymbol->base_addr : ~0U,
	   symbol_get_name_inline(lsymbol->symbol));
#endif
#if 0
    if (lsymbol->symbol->name == NULL /* || addr == 0xc011e520 */) {
        struct dump_info udn = {
            .stream = stderr,
            .prefix = "",
            .detail = 1,
            .meta = 1,
        };
	fprintf(stderr, "======== ADDR 0x%x\n", addr);
	lsymbol_dump(lsymbol, &udn);
	fprintf(stderr, "\n========\n");
	assert(lsymbol->symbol->name != NULL);
    }
#endif

    /*
     * "Real" GDB does not reflect inlined function calls,
     * so don't even worry about them.
     */
    if (gdbstyle) {
	if (ooffset == 0)
	    snprintf(buf, bufsize, "0x%08x <%s%s>",
		     addr, prefix, oname);
	else
	    snprintf(buf, bufsize, "0x%08x <%s%s+%lu>",
		     addr, prefix, oname, ooffset);
	goto done;
    }

    /*
     * Handle inlined functions. We show them as:
     *   <foo+MM @ bar+NN>
     * which says that our location is at inlined function foo+MM
     * which was inlined at bar+NN.
     */
    if (strcmp(name, oname) != 0) {
	char *iname = symbol_get_name_inline(lsymbol->symbol);

	if (ooffset == 0) {
	    if (offset == 0)
		snprintf(buf, bufsize, "0x%08x <%s%s @ %s%s>",
			 addr, prefix, iname, prefix, oname);
	    else
		snprintf(buf, bufsize, "0x%08x <%s%s%+ld @ %s%s>",
			 addr, prefix, iname, offset, prefix, oname);
	} else {
	    if (offset == 0)
		snprintf(buf, bufsize, "0x%08x <%s%s @ %s%s+%lu>",
			 addr, prefix, iname, prefix, oname, ooffset);
	    else
		snprintf(buf, bufsize, "0x%08x <%s%s%+ld @ %s%s+%lu>",
			 addr, prefix, iname, offset, prefix, oname, ooffset);
	}
	goto done; 
    }

    /*
     * Regular functions.
     */
    if (offset == 0)
	snprintf(buf, bufsize, "0x%08x <%s%s>",
		 addr, prefix, name);
    else
	snprintf(buf, bufsize, "0x%08x <%s%s+%lu>",
		 addr, prefix, name, offset);

 done:
    lsymbol_release(lsymbol);
}

void
symlist_gdb_string(uint32_t addr, char *buf, int bufsize)
{
    __symlist_string(addr, buf, bufsize, 1);
}

void
symlist_string(uint32_t addr, char *buf, int bufsize)
{
    __symlist_string(addr, buf, bufsize, 0);
}

struct lsymbol *
symlist_lookup_name(char *name)
{
    struct lsymbol *lsymbol;
    int i;

    for (i = 0; i < mymapsize; i++) {
	if (mymap[i].dbfile) {
	    lsymbol = debugfile_lookup_sym(mymap[i].dbfile, name, ".",
					   NULL, SYMBOL_TYPE_FLAG_NONE);
	    if (lsymbol)
		return lsymbol;
	}
    }

    return 0;
}

void
symlist_deinit(void)
{
    int i;

    if (mymap == 0)
	return;

    for (i = 0; i < mymapsize; i++) {
	if (mymap[i].dbfile) {
	    debugfile_free(mymap[i].dbfile, 0);
	    mymap[i].dbfile = NULL;
	}
    }
    mymap = NULL;
    mymapsize = 0;

    dwdebug_fini();
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * End:
 */
