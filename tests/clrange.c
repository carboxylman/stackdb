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

#define RANGE(s,e) "range(" #s "," #e ")"
#define ADDRANGE(cl,s,e) clrange_add(&(cl),(s),(e),RANGE(s,e))
#define CHECKRANGE(cl,a,retval,rs,failures)	\
    retval = (char *)clrange_find(&(cl),(a)); \
    if (!retval) { \
	fprintf(stderr,"  ERROR: did not find 0x%x in any range!\n",(a));	\
	++failures; \
    } \
    else if (strcmp(retval,rs)) { \
        fprintf(stderr,"  ERROR: 0x%x was not in expected %s (in %s instead?!)\n", \
		(a),(rs),(retval)); \
	++failures; \
    } \
    else \
	fprintf(stderr,"  SUCCESS: found 0x%x in %s!\n",(a),retval);
#define CHECKNORANGE(cl,a,retval,failures)    \
    retval = (char *)clrange_find(&(cl),(a)); \
    if (retval) { \
	fprintf(stderr,"  ERROR: \"found\" 0x%x in %s!\n",(a),retval);	\
	++failures; \
    } \
    else \
	fprintf(stderr,"  SUCCESS: did not find 0x%x!\n",(a));

int main(int argc,char **argv) {
    clrange_t cl = clrange_create();
    char *retval;
    int failures = 0;

    ADDRANGE(cl,0x00,0xff);
    ADDRANGE(cl,0x0d,0x10);
    ADDRANGE(cl,0x10,0x20);
    ADDRANGE(cl,0x40,0x80);
    ADDRANGE(cl,0x44,0x60);
    ADDRANGE(cl,0x90,0xa0);

    CHECKRANGE(cl,0x00,retval,RANGE(0x00,0xff),failures);
    CHECKRANGE(cl,0x01,retval,RANGE(0x00,0xff),failures);
    CHECKRANGE(cl,0x0e,retval,RANGE(0x0d,0x10),failures);
    CHECKRANGE(cl,0x10,retval,RANGE(0x10,0x20),failures);
    CHECKRANGE(cl,0x50,retval,RANGE(0x44,0x60),failures);
    CHECKRANGE(cl,0x80,retval,RANGE(0x00,0xff),failures);

    CHECKNORANGE(cl,0xff,retval,failures);

    ADDRANGE(cl,0x00,0x02);
    CHECKRANGE(cl,0x01,retval,RANGE(0x00,0x02),failures);
    CHECKRANGE(cl,0x02,retval,RANGE(0x00,0xff),failures);

    clrange_free(cl);

    return failures;
}
