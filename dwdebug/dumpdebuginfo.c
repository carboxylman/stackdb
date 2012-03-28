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
#include <sys/types.h>
#include <regex.h>

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
    int i, j;
    log_flags_t flags;
    char *optargc;
    int dotypes = 1;
    int doglobals = 1;
    int dosymtabs = 1;
    char *endptr = NULL;

    int dlen = 0;
    struct debugfile_load_opts **dlo_list = \
	(struct debugfile_load_opts **)malloc(sizeof(*dlo_list));
    dlo_list[dlen] = NULL;

    dwdebug_init();

    while ((ch = getopt(argc, argv, "dDMl:R:TGS")) != -1) {
	switch(ch) {
	case 'd':
	    ++debug;
	    vmi_set_log_level(debug);
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
	case 'R':
	    optargc = strdup(optarg);

	    struct debugfile_load_opts *opts = \
		debugfile_load_opts_parse(optarg);

	    if (!opts)
		goto dlo_err;

	    dlo_list[dlen] = opts;
	    ++dlen;
	    dlo_list = realloc(dlo_list,sizeof(opts)*(dlen + 1));
	    dlo_list[dlen] = NULL;
	    free(optargc);
	    break;
    dlo_err:
	    fprintf(stderr,"ERROR: bad debugfile_load_opts '%s'!\n",optargc);
	    free(optargc);
	    exit(-1);
	case 'T':
	    dotypes = 0;
	    break;
	case 'G':
	    doglobals = 0;
	    break;
	case 'S':
	    dosymtabs = 0;
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

    debugfile = debugfile_filename_create(filename,DEBUGFILE_TYPE_MAIN);
    if (!debugfile) {
	fprintf(stderr,"ERROR: could not create debugfile from %s!\n",
		filename);
	exit(-1);
    }

    struct debugfile_load_opts *opts = NULL;
    for (i = 0; dlo_list[i]; ++i) {
	if (!dlo_list[i]->debugfile_regex_list
	    || dlo_list[i]->debugfile_regex_list[0] == NULL) {
	    opts = dlo_list[i];
	    break;
	}
	else {
	    for (j = 0; dlo_list[i]->debugfile_regex_list[j]; ++j) {
		if (!regexec(dlo_list[i]->debugfile_regex_list[j],
			     filename,0,NULL,0)) {
		    opts = dlo_list[i];
		    break;
		}
	    }
	    if (opts)
		break;
	}
    }

    if (debugfile_load(debugfile,opts)) {
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
	debugfile_dump(debugfile,&ud,dotypes,doglobals,dosymtabs);
    else {
	for (i = 1; i < argc; ++i) {
	    struct lsymbol *s;
	    struct lsymbol *s2;
	    struct symbol *is;
	    ADDR addr = (ADDR)strtoull(argv[i],&endptr,0);

	    if (endptr != argv[i])
		s = debugfile_lookup_addr(debugfile,addr);
	    else
		s = debugfile_lookup_sym(debugfile,argv[i],".",
					 NULL,SYMBOL_TYPE_NONE);
	    
	    if (!s)
		fprintf(stderr,"Could not find symbol %s!\n",argv[i]);
	    else {
		fprintf(stderr,"forward lookup %s: ",argv[i]);
		lsymbol_dump(s,&ud);
		is = s->symbol;
		/* We release this one because we got it through a
		 * lookup function, so a ref was taken to it on our
		 * behalf.
		 */
		lsymbol_release(s);

		s2 = lsymbol_create_from_symbol(is);
		fprintf(stderr,"reverse lookup %s: ",argv[i]);
		lsymbol_dump(s2,&ud);
		/* We free this one instead of releasing because we
		 * created it instead of looked it up, so a ref to it was
		 * not taken on our behalf.
		 */
		lsymbol_free(s2,0);
	    }
	}
    }

    debugfile_free(debugfile,0);

    dwdebug_fini();

    return 0;
}
