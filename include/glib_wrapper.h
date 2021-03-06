/*
 * Copyright (c) 2013, 2014 The University of Utah
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

#include <glib.h>

/*
 * A little cast to quickly use any numeric type (for sizeof(type) <=
 * sizeof(uintptr_t), anyway) as a GHashTable gpointer key.
 */
#define VGINTKEY gpointer)(uintptr_t

/**
 * This function iterates through the current list.  It does not guard
 * against list modifications!
 */
#define v_g_list_foreach(glhead,glcur,elm)				\
    for ((glcur) = (glhead),						\
	     (elm) = (glcur) ? (typeof(elm))(glcur)->data : NULL;	\
	 (glcur) != NULL;						\
	 (glcur) = g_list_next(glcur),					\
	     (elm) = (glcur) ? (typeof(elm))(glcur)->data : NULL) 
/**
 * This function is safe and guards against list modifications, as long
 * as anything you call inside it only  deletes *the current* item.
 * Just make sure if you call any of those functions that might delete
 * the item, you don't use it again!
 */
#define v_g_list_foreach_safe(glhead,glcur,glnext,elm)			\
    for ((glcur) = (glhead),						\
	     (glnext) = (glcur) ? g_list_next(glcur) : NULL,		\
	     (elm) = (glcur) ? (typeof(elm))(glcur)->data : NULL;	\
	 (glcur) != NULL;						\
	 (glcur) = (glnext),						\
	     (glnext) = (glnext) ? g_list_next(glnext) : NULL,		\
	     (elm) = (glcur) ? (typeof(elm))(glcur)->data : NULL)

#define v_g_list_foreach_remove(glhead,glcur,glnext)			\
    do {								\
	(glhead) = g_list_remove_link(glhead,glcur); 			\
    } while (0)

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

static inline GSList *g_hash_table_get_keys_slist(GHashTable *t) {
    GSList *retval = NULL;
    GHashTableIter iter;
    gpointer k;

    if (!t)
	return NULL;

    g_hash_table_iter_init(&iter,t);
    while (g_hash_table_iter_next(&iter,&k,NULL)) {
	retval = g_slist_prepend(retval,k);
    }

    return retval;
}

static inline GSList *g_hash_table_get_values_slist(GHashTable *t) {
    GSList *retval = NULL;
    GHashTableIter iter;
    gpointer v;

    if (!t)
	return NULL;

    g_hash_table_iter_init(&iter,t);
    while (g_hash_table_iter_next(&iter,NULL,&v)) {
	retval = g_slist_prepend(retval,v);
    }

    return retval;
}

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
