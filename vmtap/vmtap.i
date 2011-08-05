%module vmtap

%{

#include "vmtap.h"

/* Internal function that does probe injection. 
   NOTE: Python user is supposed to call probe() instread of this function. */
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

    /* parse arguments */
    arglist = Py_BuildValue("(i)", probe);
    
    /* call the user handler in python */
    PyEval_CallObject(func, arglist);

    Py_DECREF(arglist);
}

/*
 * Injects a probe at a given probe-point.
 * NOTE: Read the README file for details about probe-point specifications.
 */
static bool
probe(const char *probepoint, PyObject *pyhandler)
{
    /* call the internal probe function */
    bool success = __probe(probepoint, vmtap_callback, pyhandler);
    Py_INCREF(pyhandler);
    return success;
}

%}

static bool
probe(const char *probepoint, PyObject *pyhandler);
