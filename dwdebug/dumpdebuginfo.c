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
 * Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "log.h"
#include "dwdebug.h"

extern char *optarg;
extern int optind, opterr, optopt;

int main(int argc,char **argv) {
    char ch;
    int debug = 0;
    int warn = 0;
    char *filename;
    struct debugfile *debugfile;
    int detail = 0;
    int meta = 0;
    int i;
    log_flags_t flags;
    char *optargc;
    int dotypes = 1;
    int doglobals = 1;
    int dosymtabs = 1;
    int doelfsymtab = 1;
    int doreverse = 0;
    char *endptr = NULL;
    int nofree = 0;

    int dlo_idx = 0;
    struct debugfile_load_opts **dlo_list = NULL;
    Elf *elf = NULL;
    int fd = -1;

    dwdebug_init();

    while ((ch = getopt(argc, argv, "dwgDMl:F:TGSNEr")) != -1) {
	switch(ch) {
	case 'd':
	    ++debug;
	    vmi_set_log_level(debug);
	    break;
	case 'w':
	    ++warn;
	    vmi_set_warn_level(warn);
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
	case 'F':
	    optargc = strdup(optarg);

	    struct debugfile_load_opts *opts = \
		debugfile_load_opts_parse(optarg);

	    if (!opts)
		goto dlo_err;

	    dlo_list = realloc(dlo_list,sizeof(opts)*(dlo_idx + 2));
	    dlo_list[dlo_idx] = opts;
	    ++dlo_idx;
	    dlo_list[dlo_idx] = NULL;
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
	case 'E':
	    doelfsymtab = 0;
	    break;
	case 'N':
	    nofree = 1;
	    break;
	case 'r':
	    doreverse = 1;
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

    /* Figure out which of them applies to our debugfile. */
    struct debugfile_load_opts *opts = NULL;
    if (dlo_list) {
	int accept;
	for (i = 0; dlo_list[i]; ++i) {
	    /* We only care if there was a match (or no match and the
	     * filter defaulted to accept) that accepted our filename
	     * for processing.
	     */
	    rfilter_check(dlo_list[i]->debugfile_filter,filename,&accept,NULL);
	    if (accept == RF_ACCEPT) {
		opts = dlo_list[i];
		break;
	    }
	}
    }

    /* Load the ELF symbols. */
    elf_version(EV_CURRENT);
    if ((fd = open(filename,0,O_RDONLY)) < 0) {
	vwarn("ELF fd open %s: %s\n",filename,strerror(errno));
    }
    else if (!(elf = elf_begin(fd,ELF_C_READ,NULL))) {
	vwarn("elf_begin %s: %s\n",filename,elf_errmsg(elf_errno()));
    }
    else if (elf_load_symtab(elf,filename,debugfile))
	vwarn("could not load ELF symtab into debugfile %s\n",
	      debugfile->idstr);
    if (elf)
	elf_end(elf);
    if (fd > -1)
	close(fd);

    /* Load the DWARF symbols. */
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
	debugfile_dump(debugfile,&ud,dotypes,doglobals,dosymtabs,doelfsymtab);
    else {
	for (i = 1; i < argc; ++i) {
	    struct lsymbol *s;
	    struct lsymbol *s2;
	    struct symbol *is;
	    ADDR addr = (ADDR)strtoull(argv[i],&endptr,0);
	    char *cptr = NULL;

	    if ((cptr = rindex(argv[i],':'))) {
		*cptr = '\0';
		++cptr;
		if (isdigit(*cptr))
		    s = debugfile_lookup_sym_line(debugfile,argv[i],
						  atoi(cptr),NULL,NULL);
		else if (*cptr == 'F' || *cptr == 'f') {
		    GList *list = NULL;
		    GList *list2;
		    struct rfilter *rfilter = rfilter_create_parse(argv[i]);
		    if (!rfilter) {
			fprintf(stderr,
				"Could not create symbol rfilter from '%s'!\n",
				argv[i]);
			continue;
		    }

		    list = debugfile_match_syms(debugfile,rfilter,
						SYMBOL_TYPE_FLAG_NONE,
						NULL,
						(*cptr == 'F') ? 1 : 0);
		    if (!list) {
			fprintf(stderr,
				"Did not find any symbols for rfilter '%s'!\n",
				argv[i]);
			continue;
		    }

		    list2 = g_list_first(list);
		    while (1) {
			symbol_dump((struct symbol *)list2->data,&ud);
			fprintf(ud.stream,"\n");
			if (!(list2 = g_list_next(list2)))
			    break;
		    }

		    rfilter_free(rfilter);
		    g_list_free(list);
		    continue;
		}
		else {
		    fprintf(stderr,
			    "Unknown suffix char '%c' in arg '%s', skipping!\n",
			    *cptr,argv[i]);
		    continue;
		}
	    }
	    else if (endptr != argv[i]) {
		s = debugfile_lookup_addr(debugfile,addr);
	    }
	    else {
		s = debugfile_lookup_sym(debugfile,argv[i],".",
					 NULL,SYMBOL_TYPE_NONE);
	    }

	    if (!s) {
		fprintf(stderr,"Could not lookup %s!\n",argv[i]);
	    }
	    else {
		fprintf(stdout,"forward lookup %s: ",argv[i]);
		lsymbol_dump(s,&ud);
		fprintf(stdout,"\n");
		is = s->symbol;
		if (s->symbol->isinlineinstance) {
		    fprintf(stdout,"first noninline parent %s: \n",argv[i]);
		    ud.prefix = "  ";
		    symbol_dump(lsymbol_get_noninline_parent_symbol(s),&ud);
		    fprintf(stdout,"\n");
		}
		/* We release this one because we got it through a
		 * lookup function, so a ref was taken to it on our
		 * behalf.
		 */
		lsymbol_release(s);

		if (doreverse) {
		    s2 = lsymbol_create_from_symbol(is);
		    fprintf(stdout,"reverse lookup %s: ",argv[i]);
		    ud.prefix = "";
		    lsymbol_dump(s2,&ud);
		    /* We free this one instead of releasing because we
		     * created it instead of looked it up, so a ref to it was
		     * not taken on our behalf.
		     */
		    lsymbol_free(s2,0);
		    fprintf(stdout,"\n");
		}
	    }
	}
    }

    if (!nofree)
	debugfile_free(debugfile,0);

    dwdebug_fini();

    return 0;
}
