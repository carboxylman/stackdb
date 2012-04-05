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

#include "vmtap.h"

%}

%include "vmtap.h"

%{

static int PythonCallBack(void *data)
{
    PyObject *func, *arglist;
    PyObject *result;
    int res = 0;

    func = (PyObject *)data;
    arglist = NULL;//Py_BuildValue("");
    result = PyEval_CallObject(func, arglist);
    //Py_DECREF(arglist);
    if (result)
        res = (int) PyInt_AsLong(result);
    Py_XDECREF(result);

    return res;
}

static int register_vmtap(const char *domain,
                          const char *symbol,
                          PyObject *PreFunc,
                          PyObject *PostFunc)
{
    int res = __register_vmtap(domain, 
                               symbol, 
                               PythonCallBack, 
                               PreFunc,
                               PostFunc);
    Py_INCREF(PreFunc);
    Py_INCREF(PostFunc);

    return res;
}

%}

%typemap(python, in) PyObject *PreFunc
{
    if (!PyCallable_Check($source))
    {
        PyErr_SetString(PyExc_TypeError,
            "Need a callback object!");
        return NULL;
    }
    $target = $source;
}

%typemap(python, in) PyObject *PostFunc
{
    if (!PyCallable_Check($source))
    {
        PyErr_SetString(PyExc_TypeError,
            "Need a callback object!");
        return NULL;
    }
    $target = $source;
}

int register_vmtap(const char *domain,
                   const char *symbol,
                   PyObject *PreFunc,
                   PyObject *PostFunc);
