/*
 * Copyright (c) 2012, 2013 The University of Utah
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

#ifndef __ANALYSIS_XML_H__
#define __ANALYSIS_XML_H__

#include "analysis_xml_moduleStub.h" 
#include "target_xml_moduleStub.h"
#include "analysis.h"
#include "target_api.h"

#include <glib.h>

struct vmi1__AnalysisT *a_analysis_to_x_AnalysisT(struct soap *soap,	
						  struct analysis *in,
						  GHashTable *reftab,
						  vmi1__AnalysisT *out);

struct analysis_desc *
x_AnalysisDescT_to_a_analysis_desc(struct soap *soap,
				   struct vmi1__AnalysisDescT *in,
				   GHashTable *reftab,
				   struct analysis_desc *out);
struct vmi1__AnalysisDescT *
a_analysis_desc_to_x_AnalysisDescT(struct soap *soap,
				   struct analysis_desc *in,
				   GHashTable *reftab,
				   struct vmi1__AnalysisDescT *out);

struct analysis_spec *
x_AnalysisSpecT_to_a_analysis_spec(struct soap *soap,
				   struct vmi1__AnalysisSpecT *in,
				   GHashTable *reftab,
				   struct analysis_spec *out);
struct vmi1__AnalysisSpecT *
a_analysis_spec_to_x_AnalysisSpecT(struct soap *soap,
				   struct analysis_spec *in,
				   GHashTable *reftab,
				   struct vmi1__AnalysisSpecT *out);

struct vmi1__AnalysisResultT *
a_analysis_datum_to_x_AnalysisResultT(struct soap *soap,
				      struct analysis_datum *in,
				      struct analysis *analysis,
				      GHashTable *reftab,
				      struct vmi1__AnalysisResultT *out);
struct vmi1__AnalysisResultsT *
a_analysis_datum_list_to_x_AnalysisResultsT(struct soap *soap,
					    struct array_list *in,
					    struct analysis *analysis,
					    GHashTable *reftab,
					    struct vmi1__AnalysisResultsT *out);

struct analysis_param *x_ParamT_to_a_param(struct soap *soap,
					   struct vmi1__ParamT *in,
					   struct analysis_param *out);
struct vmi1__ParamT *a_param_to_x_ParamT(struct soap *soap,	
					 struct analysis_param *in,
					 struct vmi1__ParamT *out);

struct analysis_name_value *
x_NameValueT_to_a_analysis_name_value(struct soap *soap,
				      struct vmi1__NameValueT *in,
				      struct analysis_name_value *out);
struct vmi1__NameValueT *
a_analysis_name_value_to_x_NameValueT(struct soap *soap,	
				      struct analysis_name_value *in,
				      struct vmi1__NameValueT *out);

analysis_status_t 
x_AnalysisStatusT_to_a_analysis_status_t(struct soap *soap,
					 enum vmi1__AnalysisStatusT status,
					 GHashTable *reftab,
					 analysis_status_t *out);
enum vmi1__AnalysisStatusT 
a_analysis_status_t_to_x_AnalysisStatusT(struct soap *soap,
					 analysis_status_t status,
					 GHashTable *reftab,
					 enum vmi1__AnalysisStatusT *out);


#endif /* __ANALYSIS_XML_H__ */
