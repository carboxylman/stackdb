/*
 * Copyright (c) 2012 The University of Utah
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
#include "common.h"
#include "clfit.h"
#include "alist.h"

#define LINE(s,a) "line " #s "->" #a
#define ADDLINE(cl,s,a) clmatch_add(&(cl),(s),LINE(s,a))
#define CHECKLINE(cl,s,retval,rs,ors,failures)	\
    retval = clmatch_find(&(cl),(s));		\
    if (!retval) {							\
	fprintf(stderr,"  ERROR: did not find line previous to %d!\n",(s)); \
	++failures;							\
    }									\
    else if (array_list_len(retval) == 1) {				\
	if (strcmp(rs,(char *)array_list_item(retval,0))) {		\
	    fprintf(stderr,"  ERROR: %d resulted in %s (should have been %s?!)\n", \
		    (s),(char *)array_list_item(retval,0),(rs));	\
	    ++failures;							\
	}								\
	else {								\
	    fprintf(stderr,"  SUCCESS: %d resulted in %s!\n",(s),rs);	\
	}								\
    }									\
    else if (array_list_len(retval) == 2) {				\
	if (strcmp(rs,(char *)array_list_item(retval,0))		\
	    && strcmp(ors,(char *)array_list_item(retval,1))) {		\
	    fprintf(stderr,						\
		    "  ERROR: %d resulted in %s %s (should have been %s %s?!)\n", \
		    (s),(char *)array_list_item(retval,0),		\
		    (char *)array_list_item(retval,1),rs,ors);		\
	    ++failures;							\
	}								\
	else {								\
	    fprintf(stderr,"  SUCCESS: %d resulted in %s %s!\n",(s),rs,ors); \
	}								\
    }									\
    else {								\
	fprintf(stderr,"  ERROR: %d resulted in list with %d elements!\n", \
		(s),array_list_len(retval));				\
    }
#define CHECKNOLINE(cl,s,retval,failures)	\
    retval = clmatch_find(&(cl),(s)); \
    if (retval) { \
	fprintf(stderr,"  ERROR: \"found\" unexpected line previous to %d!\n",(s)); \
	++failures; \
    } \
    else {								\
	fprintf(stderr,"  SUCCESS: %d did not have a previous line!\n",(s)); \
    }

int main(int argc,char **argv) {
    clmatch_t cl = clmatch_create();
    struct array_list *retval;
    int failures = 0;

    ADDLINE(cl,75,0x400510);
    ADDLINE(cl,76,0x400516);
    ADDLINE(cl,80,0x400520);
    ADDLINE(cl,100,0x400556);
    ADDLINE(cl,101,0x400560);
    ADDLINE(cl,120,0x400598);
    ADDLINE(cl,75,0x400600);
    ADDLINE(cl,76,0x400606);
    ADDLINE(cl,124,0x400610);
    ADDLINE(cl,125,0x400612);

    CHECKLINE(cl,80,retval,LINE(80,0x400520),"",failures);
    CHECKLINE(cl,85,retval,LINE(80,0x400520),"",failures);
    CHECKLINE(cl,130,retval,LINE(125,0x400612),"",failures);

    CHECKLINE(cl,77,retval,LINE(76,0x400516),LINE(76,0x400606),failures);

    CHECKNOLINE(cl,50,retval,failures);

    clmatch_free(cl);

    return failures;
}
