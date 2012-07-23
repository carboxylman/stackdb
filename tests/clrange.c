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
#include "log.h"

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

#define CHECKFINDLOOSEST(cl,idx,retval,rs,failures)	     \
    retval = clrange_find_loosest(&(cl),(idx),NULL); \
    if (!retval) { \
	fprintf(stderr,"  ERROR: did not find 0x%x in any range!\n",(idx)); \
	++failures; \
    } \
    else if (strcmp((char *)CLRANGE_DATA(retval),rs)) {			\
        fprintf(stderr,"  ERROR: 0x%x was not in expected %s (in %s instead?!)\n", \
		(idx),(rs),(char *)CLRANGE_DATA(retval));			\
	++failures; \
    } \
    else \
	fprintf(stderr,"  SUCCESS: found 0x%x in loosest range %s!\n",(idx), \
		(char *)CLRANGE_DATA(retval));

#define CHECKFINDNEXTLOOSEST(cl,idx,retval,rs,failures)	     \
    retval = clrange_find_next_loosest(&(cl),(idx),NULL);    \
    if (!retval) { \
	fprintf(stderr,"  ERROR: did not find next loosest range of 0x%x!\n",(idx)); \
	++failures; \
    } \
    else if (strcmp((char *)CLRANGE_DATA(retval),rs)) {			\
        fprintf(stderr,"  ERROR: 0x%x was not in expected next loosest %s (in %s instead?!)\n", \
		(idx),(rs),(char *)CLRANGE_DATA(retval));			\
	++failures; \
    } \
    else \
	fprintf(stderr,"  SUCCESS: found next loosest 0x%x in range %s!\n",(idx), \
		(char *)CLRANGE_DATA(retval));

int main(int argc,char **argv) {
    clrange_t cl = clrange_create();
    char *retval;
    int failures = 0;
    struct clf_range_data *crd;

    vmi_set_log_level(10);
    vmi_set_log_flags(LOG_OTHER);

    ADDRANGE(cl,0x00,0xff);
      ADDRANGE(cl,0x0d,0x10);
      ADDRANGE(cl,0x10,0x20);

      ADDRANGE(cl,0x40,0x80);
        ADDRANGE(cl,0x44,0x60);
      ADDRANGE(cl,0x90,0xa0);
    ADDRANGE(cl,0x200,0x300);
    ADDRANGE(cl,0x300,0x400);

    CHECKRANGE(cl,0x00,retval,RANGE(0x00,0xff),failures);
    CHECKRANGE(cl,0x01,retval,RANGE(0x00,0xff),failures);
    CHECKFINDLOOSEST(cl,0xd,crd,RANGE(0x00,0xff),failures);
    CHECKRANGE(cl,0x0e,retval,RANGE(0x0d,0x10),failures);
    CHECKFINDLOOSEST(cl,0xe,crd,RANGE(0x00,0xff),failures);
    CHECKRANGE(cl,0x10,retval,RANGE(0x10,0x20),failures);
    CHECKRANGE(cl,0x50,retval,RANGE(0x44,0x60),failures);
    CHECKFINDLOOSEST(cl,0x50,crd,RANGE(0x00,0xff),failures);
    CHECKRANGE(cl,0x80,retval,RANGE(0x00,0xff),failures);

    CHECKNORANGE(cl,0xff,retval,failures);

    ADDRANGE(cl,0x00,0x02);
    CHECKRANGE(cl,0x01,retval,RANGE(0x00,0x02),failures);
    CHECKRANGE(cl,0x02,retval,RANGE(0x00,0xff),failures);

    CHECKFINDNEXTLOOSEST(cl,0x50,crd,RANGE(0x200,0x300),failures);
    CHECKFINDLOOSEST(cl,0x202,crd,RANGE(0x200,0x300),failures);
    CHECKFINDNEXTLOOSEST(cl,0x202,crd,RANGE(0x300,0x400),failures);

    clrange_free(cl);

    return failures;
}
