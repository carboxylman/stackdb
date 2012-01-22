#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>

#include "libdwdebug.h"

extern char *optarg;
extern int optind, opterr, optopt;

int main(int argc,char **argv) {
    char ch;
    int debug = 0;
    char *filename;
    struct debugfile *debugfile;
    int detail = 0;
    int meta = 0;
    int i;

    while ((ch = getopt(argc, argv, "dDM")) != -1) {
	switch(ch) {
	case 'd':
	    ++debug;
	    break;
	case 'D':
	    ++detail;
	    break;
	case 'M':
	    ++meta;
	    break;
	default:
	    fprintf(stderr,"ERROR: unknown option %c!\n",ch);
	    exit(-1);
	}
    }

    argc -= optind;
    argv += optind;

    if (argc >= 1)
	filename = argv[0];
    else {
	fprintf(stderr,"ERROR: you must supply an ELF filename!\n");
	exit(-1);
    }

    libdwdebug_init();
    libdwdebug_set_debug_level(debug);

    debugfile = debugfile_create(filename,DEBUGFILE_TYPE_MAIN);
    if (!debugfile) {
	fprintf(stderr,"ERROR: could not create debugfile from %s!\n",
		filename);
	exit(-1);
    }

    if (load_debug_info(debugfile)) {
	fprintf(stderr,"ERROR: could not create debugfile from %s!\n",
		filename);
	exit(-1);
    }

    struct dump_info ud = {
	.stream = stdout,
	.prefix = "",
	.meta = meta,
	.detail = detail,
    };

    if (argc < 2)
	debugfile_dump(debugfile,&ud);
    else {
	for (i = 1; i < argc; ++i) {
	    struct lsymbol *s = debugfile_lookup_sym(debugfile,argv[i],".",
						     NULL,SYMBOL_TYPE_NONE);
	    if (!s)
		fprintf(stderr,"Could not find symbol %s!\n",argv[i]);
	    else
		lsymbol_dump(s,&ud);
	}
    }

    debugfile_free(debugfile);

    return 0;
}
