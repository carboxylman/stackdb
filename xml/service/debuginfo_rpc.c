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

#include "debuginfo_xml.h"

int vmi1__lookupSymbol(struct soap *soap,
		       char *filename,char *name,char *filter,char *flags,
		       struct vmi1__lookupSymbolResponse *r) {
    struct debugfile *debugfile;
    struct lsymbol *lsymbol;

    if (filename == NULL || name == NULL
	|| strcmp(filename,"") == 0 || strcmp(name,"") == 0) {
	return soap_receiver_fault(soap,"Bad debugfile or name!",
				   "Bad debugfile or name!");
    }

    debugfile = debugfile_filename_create(filename,DEBUGFILE_TYPE_MAIN);
    if (!debugfile) 
	return soap_receiver_fault(soap,"Could not create debugfile!",
				   "Could not create debugfile!");

    /* Load the DWARF symbols. */
    if (debugfile_load(debugfile,NULL)) {
	return soap_receiver_fault(soap,"Could not load debugfile!",
				   "Could not load debugfile!");
    }

    lsymbol = debugfile_lookup_sym(debugfile,name,NULL,NULL,SYMBOL_TYPE_NONE);

    if (!lsymbol)
	return soap_receiver_fault(soap,"Could not find symbol!",
				   "Could not find symbol!");

    d_symbol_to_x_symbolchoice(lsymbol->symbol,&r->sc,&r->__sc);

    lsymbol_release(lsymbol);

    return SOAP_OK;
}
