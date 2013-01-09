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

#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdsoap2.h>
#include <stdlib.h>

#define SOAP_CALLOC(soap,nmemb,size)					\
    memset(soap_malloc((soap),(nmemb)*(size)),0,(nmemb)*(size));

#define SOAP_STRCPY(soap,d,s)					\
    do {							\
	char *_ss = (s);					\
	int _rc;						\
								\
	if (!_ss)						\
	    (d) = NULL;						\
	else {							\
	    _rc = strlen(_ss) + 1;				\
	    (d) = soap_malloc((soap),_rc);			\
	    strncpy((d),_ss,_rc);				\
	}							\
    } while (0);

#endif /* __UTIL_H__ */
