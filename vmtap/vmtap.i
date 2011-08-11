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
