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

#ifndef __COMMON_XML_H__
#define __COMMON_XML_H__

#include "common.h"
#include "common_xml_moduleStub.h"

result_t
x_ResultT_to_t_result_t(struct soap *soap,
			enum vmi1__ResultT in);
enum vmi1__ResultT 
t_result_t_to_x_ResultT(struct soap *soap,
			result_t in);

#endif /* __COMMON_XML_H__ */
