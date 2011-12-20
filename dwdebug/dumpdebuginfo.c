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

    if (argc == (optind + 1))
	filename = argv[optind];
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

    debugfile_dump(debugfile,&ud);

    debugfile_free(debugfile);

    return 0;
}
