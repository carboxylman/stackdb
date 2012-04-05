/*
 * Copyright (c) 2011, 2012 The University of Utah
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

%module vmtap

%{

#ifndef SWIGPYTHON
#error " High-level language other than Python not supported"
#else /* SWIGPYTHON */

#include "vmtap.h"

/* Internal function that does probe injection. 
   NOTE: Python user is supposed to call probe() instead of this function. */
bool
__probe(const char *probepoint, vmtap_callback_t callback, void *pyhandler);

%}

%include "vmtap.h"

/* Language independent exception handler */
%include exception.i

%{

/* Python callback wrapper */
static void 
vmtap_callback(int probe, void *pyhandler)
{
    PyObject *func, *arglist;
    
    /* get python function object */
    func = (PyObject *)pyhandler;
    if (func)
    {
        /* parse arguments */
        arglist = Py_BuildValue("(i)", probe);
    
        /* call the user handler in python */
        PyEval_CallObject(func, arglist);

        Py_DECREF(arglist);
    }
}

/*
 * Injects a probe at a given probe-point. A user handler (a Python function)
 * is called whenever the probe is triggered.
 * NOTE: Read the README file for details about probe-point specifications.
 */
bool
probe(const char *probepoint, PyObject *pyhandler)
{
    /* call the internal probe function */
    bool success = __probe(probepoint, vmtap_callback, pyhandler);
    Py_INCREF(pyhandler);
    return success;
}

#endif /* SWIGPYTHON */

%}
