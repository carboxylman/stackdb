/*
 * Copyright (c) 2013 The University of Utah
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

#include "common.h"
#include "log.h"
#include "common_xml.h"

result_t
x_ResultT_to_t_result_t(struct soap *soap,
			enum vmi1__ResultT in) {
    switch (in) {
    case vmi1__ResultT__success:
	return RESULT_SUCCESS;
    case vmi1__ResultT__error:
	return RESULT_ERROR;
    case vmi1__ResultT__abort:
	return RESULT_ABORT;
    default:
	verror("unknown ResultT %d; returning RESULT_ABORT!\n",in);
	return RESULT_ABORT;
    }
}
enum vmi1__ResultT 
t_result_t_to_x_ResultT(struct soap *soap,
			result_t in) {
    switch (in) {
    case RESULT_SUCCESS:
	return vmi1__ResultT__success;
    case RESULT_ERROR:
	return vmi1__ResultT__error;
    case RESULT_ABORT:
	return vmi1__ResultT__abort;
    default:
	verror("unknown result_t %d; returning ResultT__abort!\n",in);
	return vmi1__ResultT__abort;
    }
}
