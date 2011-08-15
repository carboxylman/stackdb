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
