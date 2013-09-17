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

#ifndef _UTIL_GLIB_H
#define _UTIL_GLIB_H

#define v_g_slist_foreach(gslhead,gslcur,elm)				\
    for ((gslcur) = (gslhead),						\
	     (elm) = (gslcur) ? (typeof(elm))(gslcur)->data : NULL;	\
	 (gslcur) != NULL;						\
	 (gslcur) = g_slist_next(gslcur),				\
	     (elm) = (gslcur) ? (typeof(elm))(gslcur)->data : NULL) 
#define v_g_slist_foreach_dual(gslhead1,gslhead2,gslcur1,gslcur2,elm1,elm2) \
    for ((gslcur1) = (gslhead1),(gslcur2) = (gslhead2),			\
	     (elm1) = (gslcur1) ? (typeof(elm1))(gslcur1)->data : NULL,	\
	     (elm2) = (gslcur2) ? (typeof(elm2))(gslcur2)->data : NULL;	\
	 (gslcur1) != NULL && (gslcur2) != NULL;			\
	 (gslcur1) = g_slist_next(gslcur1),(gslcur2) = g_slist_next(gslcur2), \
	     (elm1) = (gslcur1) ? (typeof(elm1))(gslcur1)->data : NULL,	\
	     (elm2) = (gslcur2) ? (typeof(elm2))(gslcur2)->data : NULL) 
#define v_g_slist_steal(gslcur)  (gslcur)->data = NULL

/*
#define vg_slist_foreach_safe(gslhead,gslcur,data,gslprev)		\
    for ((gslcur) = (gslhead),						\
	     (gslprev) = NULL,						\
	     (data) = (gslcur) ? (typeof(data))(gslcur)->data : NULL;	\
	 (gslcur) != NULL;						\
	 gslprev = gslcur, (gslcur) = g_slist_next(gslcur)) 

#define vg_slist_foreach_i(gslhead,gslcur,data,lpc)			\
    for ((lpc) = 0,							\
	     (gslcur) = (gslhead),					\
	     (data) = (gslcur) ? (typeof(data))(gslcur)->data : NULL; \
	 (gslcur) != NULL;						\
	 ++(lpc), (gslcur) = g_slist_next(gslcur)) 

#define vg_slist_foreach_delete(gslhead,gslcur,gslprev)			\
    do {								\
        GSList *next = (gslcur) ? g_slist_next(gslcur) : NULL;		\
	if (
    while (0);
    for ((lpc) = 0,							\
	     (gslcur) = (gslhead),					\
	     (data) = (gslcur) ? (typeof(data))gslhead->data : NULL;	\
	     gslhead->len - lpc > 0;					\
	 ++lpc, gslcur = g_slist_next(gslcur)) 
*/

#endif /* _UTIL_GLIB_H */
