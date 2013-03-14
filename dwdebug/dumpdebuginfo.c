/*
 * Copyright (c) 2011, 2012, 2013 The University of Utah
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

#include "common.h"
#include "log.h"
#include "dwdebug.h"

extern struct binfile_ops elf_binfile_ops;

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
    char *optargc;
    int dotypes = 1;
    int doglobals = 1;
    int dosymtabs = 1;
    int doelfsymtab = 1;
    int doreverse = 0;
    char *endptr = NULL;
    int nofree = 0;
    struct lsymbol *s;
    struct lsymbol *s2;
    struct symbol *is;
    struct symbol *ps;
    struct array_list *opts_list = NULL;
    struct debugfile_load_opts *opts;
    struct binfile_instance *bfi = NULL;
    struct binfile_instance_elf *bfelfi = NULL;
    char *saveptr = NULL;
    char *mapi;
    int sec;
    ADDR addr;
    ADDR base = 0;
    int infer = 0;

    dwdebug_init();

    while ((ch = getopt(argc, argv, "dwgDMl:F:TGSNErI:i:")) != -1) {
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
	    if (vmi_set_log_area_flaglist(optarg,NULL)) {
		fprintf(stderr,"ERROR: bad debug flag in '%s'!\n",optarg);
		exit(-1);
	    }
	    break;
	case 'F':
	    optargc = strdup(optarg);

	    opts = debugfile_load_opts_parse(optargc);

	    if (!opts) {
		verror("bad debugfile_load_opts '%s'!\n",optargc);
		free(optargc);
		array_list_foreach(opts_list,i,opts) {
		    debugfile_load_opts_free(opts);
		}
		array_list_free(opts_list);

		goto dlo_err;
	    }
	    else {
		if (!opts_list)
		    opts_list = array_list_create(4);

		array_list_append(opts_list,opts);
	    }
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
	case 'i':
	    infer = 1;
	    base = (ADDR)strtoul(optarg,NULL,0);
	    break;
	case 'I':
	    bfi = calloc(1,sizeof(*bfi));
	    bfi->ops = &elf_binfile_ops;
	    bfi->priv = bfelfi = calloc(1,sizeof(*bfelfi));

	    bfelfi->num_sections = 0;
	    bfelfi->section_tab = NULL;

	    while ((mapi = strtok_r(!saveptr ? optarg : NULL,",",&saveptr))) {
		if (sscanf(mapi,"%u:%lx",&sec,&addr) == 2) {
		    if ((sec + 1) > bfelfi->num_sections) {
			bfelfi->num_sections = sec + 1;
			bfelfi->section_tab = realloc(bfelfi->section_tab,
						      (sec + 1)*sizeof(ADDR));
		    }
		    bfelfi->section_tab[sec] = addr;
		}
	    }
	    
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

    if (infer) {
	bfi = binfile_infer_instance(filename,base,NULL);
	debugfile = debugfile_from_instance(bfi,opts_list);
    }
    else if (bfi) {
	bfi->filename = filename;
	debugfile = debugfile_from_instance(bfi,opts_list);
    }
    else
	debugfile = debugfile_from_file(filename,opts_list);
    if (!debugfile) {
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
		    ps = lsymbol_get_noninline_parent_symbol(s);
		    if (ps) {
			symbol_dump(ps,&ud);
			fprintf(stdout,"\n");
		    }
		    else
			fprintf(stdout,"NO PARENT! (fake inline of itself?)\n");
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
		    lsymbol_release(s2);
		    fprintf(stdout,"\n");
		}
	    }
	}
    }

    if (!nofree)
	debugfile_release(debugfile);

    dwdebug_fini();

#ifdef REF_DEBUG
    REF_DEBUG_REPORT_FINISH();
#endif

    return 0;
}
