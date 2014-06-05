/*
 * Copyright (c) 2014 The University of Utah
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
#define ADDRANGE(cl,s,e)						\
    rc = clrangesimple_add(&(cl),(s),(e),RANGE(s,e));			\
    if (rc == -1) {							\
	fprintf(stderr,"  ERROR: internal error; could not add 0x%x,0x%x!\n",	\
		s,e);							\
	++failures;							\
    }									\
    else if (rc == 1) {							\
	fprintf(stderr,"  ERROR: something already at/in range 0x%x,0x%x!\n",	\
		(s),(e));						\
	++failures;							\
    }									\
    else {								\
	fprintf(stderr,"  SUCCESS: added 0x%x,0x%x!\n",(s),(e));	\
    }
    
#define ADDRANGEFAIL(cl,s,e)						\
    rc = clrangesimple_add(&(cl),(s),(e),RANGE(s,e));			\
    if (rc == -1) {							\
	fprintf(stderr,"  ERROR: internal error; could not add 0x%x,0x%x!\n",	\
		s,e);							\
	++failures;							\
    }									\
    else if (rc == 1) {							\
	fprintf(stderr,"  SUCCESS: something already at/in range 0x%x,0x%x!\n", \
		(s),(e));						\
    }									\
    else {								\
	fprintf(stderr,"  ERROR: added 0x%x,0x%x!\n",(s),(e));	\
	++failures;							\
    }
#define REMOVERANGE(cl,s,end,retval)					\
    rc = clrangesimple_remove(&(cl),(s),&end,(void **)&retval);		\
    if (rc == -1) {							\
	fprintf(stderr,"  ERROR: internal error; could not remove 0x%x!\n",s); \
	++failures;							\
    }									\
    else if (rc == 1) {							\
	fprintf(stderr,"  ERROR: nothing at 0x%x; cannot remove!\n",s);	\
	++failures;							\
    }									\
    else {								\
	fprintf(stderr,"  SUCCESS: removed 0x%x,0x%x (%s)!\n",		\
		(s),(int)end,(char *)retval);				\
    }
#define CHECKRANGE(cl,a,rc,retval,rs,failures)				\
    rc = clrangesimple_find(&(cl),(a),NULL,NULL,(void **)&retval);	\
    if (rc == -1) {							\
	fprintf(stderr,"  ERROR: internal error; and did not find 0x%x in any range!\n",(a)); \
	++failures;							\
    }									\
    else if (rc == 1) {							\
	fprintf(stderr,"  ERROR: did not find 0x%x in any range!\n",(a)); \
	++failures;							\
    }									\
    else if (strcmp(retval,rs)) {					\
        fprintf(stderr,"  ERROR: 0x%x was not in expected %s (in %s instead?!)\n", \
		(a),(rs),(retval));					\
	++failures;							\
    }									\
    else								\
	fprintf(stderr,"  SUCCESS: found 0x%x in %s!\n",(a),retval);
#define CHECKNORANGE(cl,a,rc,retval,failures)				\
    rc = clrangesimple_find(&(cl),(a),NULL,NULL,(void **)&retval);	\
    if (rc == -1) {							\
	fprintf(stderr,"  ERROR: internal error; could not find 0x%x!\n",a); \
	++failures;							\
    }									\
    else if (rc == 1) {						\
	fprintf(stderr,"  SUCCESS: did not find 0x%x!\n",(a));		\
    }									\
    else {								\
	fprintf(stderr,"  ERROR: \"found\" 0x%x in %s!\n",(a),retval);	\
	++failures;							\
    }

int main(int argc,char **argv) {
    clrangesimple_t cl = clrangesimple_create();
    char *retval;
    int rc;
    int failures = 0;
    Word_t end;

    vmi_set_log_level(10);
    vmi_set_log_area_flags(LA_LIB,LF_CLRANGE);

    ADDRANGE(cl,0x00,0xff);
    ADDRANGEFAIL(cl,0x0d,0x10);
    ADDRANGEFAIL(cl,0x10,0x20);
    ADDRANGEFAIL(cl,0x40,0xff);
    ADDRANGEFAIL(cl,0x00,0xff);
    ADDRANGEFAIL(cl,0x00,0x02);

    ADDRANGE(cl,0x300,0x400);
    ADDRANGEFAIL(cl,0x250,0x350);

    ADDRANGE(cl,0xff,0x300);

    CHECKRANGE(cl,0x00,rc,retval,RANGE(0x00,0xff),failures);
    CHECKRANGE(cl,0x01,rc,retval,RANGE(0x00,0xff),failures);
    CHECKRANGE(cl,0x0e,rc,retval,RANGE(0x00,0xff),failures);
    CHECKRANGE(cl,0x10,rc,retval,RANGE(0x00,0xff),failures);
    CHECKRANGE(cl,0x50,rc,retval,RANGE(0x00,0xff),failures);
    CHECKRANGE(cl,0x80,rc,retval,RANGE(0x00,0xff),failures);

    CHECKRANGE(cl,0xff,rc,retval,RANGE(0xff,0x300),failures);
    CHECKRANGE(cl,0x301,rc,retval,RANGE(0x300,0x400),failures);

    REMOVERANGE(cl,0x300,end,retval);

    retval = NULL;
    CHECKNORANGE(cl,0x301,rc,retval,failures);

    clrangesimple_free(cl,NULL);

    return failures;
}
