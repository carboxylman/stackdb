/*
 * Copyright (c) 2011, 2012 The University of Utah
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin St, Suite 500, Boston, MA 02110-1335, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>

#include "log.h"
#include "dwdebug.h"

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
    log_flags_t flags;

    dwdebug_init();

    while ((ch = getopt(argc, argv, "dDMl:")) != -1) {
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
	case 'l':
	    if (vmi_log_get_flag_mask(optarg,&flags)) {
		fprintf(stderr,"ERROR: bad debug flag in '%s'!\n",optarg);
		exit(-1);
	    }
	    vmi_set_log_flags(flags);
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

    vmi_set_log_level(debug);

    debugfile = debugfile_filename_create(filename,DEBUGFILE_TYPE_MAIN);
    if (!debugfile) {
	fprintf(stderr,"ERROR: could not create debugfile from %s!\n",
		filename);
	exit(-1);
    }

    if (debugfile_load(debugfile)) {
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

    dwdebug_fini();

    return 0;
}
