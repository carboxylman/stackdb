## -*- mode: Text -*- 
##
## Copyright (c) 2013, 2014, 2015 The University of Utah
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License as
## published by the Free Software Foundation; either version 2 of
## the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.

###############################################################################

+----------+
| OVERVIEW |
+----------+

This is an example of using RPC support of the stackdb library.
It covers:
  - A brief description of RPC in the stackdb;
  - Where are the RPC related files located;
  - How to construct the Input parameters in the python client;
  - The specific output format;
  - What files need to be added to make a new RPC service and application.
  
+-------------------------+
| 1. about RPC in stackdb |
+-------------------------+

The stackdb is using SOAP to build the RPC web service and clients. As user, 
you may want to just use the functions exported by the services and write our 
own analysis program and a RPC client to call this program.

There are two client end in current stackdb RPC framework. The python client is
used to construct the parameters of the analysis program and receive return
value of the RPC call. The java client is used for receiving, parsing, and 
printing out the standard output of the RPC program.

           +--------------------------+
           |  Server to be analysed   |
           |                          |
           |   +------------------+   |
           |   | analysis program |   |
           |   +------------------+   |
           |            |             |
           |     +--------------+     |
           |     | RPC services |     |
           |     +--------------+     |
           |        /        \        |
           +-------/----------\-------+
                  /            \
                 /              \
    +-----------/----------------\-------------+
    |  +-------------+      +---------------+  |
    |  | java client |      | python client |  |
    |  +-------------+      +---------------+  |
    |           Client sending RPC             |
    +------------------------------------------+

So RPC programs in stackdb need three terminals:
  Terminal 1, run the RPC service: 
	<build_dir>/xml/service/analysis -d20 -w20 -l T_ALL,A_ALL,X_ALL -p 3903
  Terminal 2, run the java client:
	<build_dir>/xml/client/java/run.sh vmi1.SimpleServiceServer \
vmi1.SimpleAnalysisListener 
  Terminal 3, run the python client:
	cd <build_dir>/xml/client/python
	python -i analysis_ppm_xen.py

+--------------------+
|2. RPC related files|
+--------------------+

Files for the RPC framework are mainly located at:
  <source_dir>/xml/schema/
    *.rnc define the types of RPC call parameters.
    *_xml.c transfer the input value of parameters from the python client to 
arguments to trigger the analysis program, with which the RPC service trigger
the backend analysis program. 
  <source_dir>/xml/service/
    Exports the stackdb functions.
  <source_dir>/xml/client/java
    The java client code as a result receiver.
  <source_dir>/xml/client/python
    The python client code to call the RPC.

These files may be helpful for you to get to know how to write your RPC 
programs.
After you compile and install the stackdb, you may find these files may be 
useful:
  <build_dir>/xml/service/
    *.wsdl generated to describe services operations and messages.
  
  <build_dir>/xml/client/python
    *.py are python client examples you may want to learn.

  <build_dir>/xml/client/java
    *.py are python client examples you may want to learn.

  <build_dir>/tools/
    These are backend analysis programs can be called.

+--------------------+
|3. Input parameters |
+--------------------+

All the input parameters to the analysis program are provided by the python 
client. They can be categorized into three types:
  - Target specification parameters.
	Value of these parameters are assigned by creating a 'TargetSpecT' object
and giving value to the attributes of it (e.g tspec._type="xen").
  - Other stackdb standard parameters like the debugging levels '-d20'
  - Analysis program customized parameters
	These parameters are defined in the description.xml file describing the
analysis specification. You can define a parameter type which is command or
not and whether it is command line switched.

+----------------+
|4. Ouput format |
+----------------+

The output of the analysis program should follow a special format like:
	"RESULT:: (%c:%d) %s (%d) %s \"%s\" () ::RESULT\n"

The <source_dir>/tools/spf/README.spf.txt has more detail about this and the 
<source_dir>/tools/spf/spf.c can be used as a good example.

+------------------------+
|5. Files to add or edit |
+------------------------+

This section, we take the pingpongmonitor as an example. You may need to go to
the files mentioned here to know more detail.
First, you need to have a analysis program with a description.xml to export its
analysis descriptions, as well as a Makefile.in.
    <source_dir>/tools/pingpongmonitor/pingpongmonitor.c
    <source_dir>/tools/pingpongmonitor/description.xml
    <source_dir>/tools/pingpongmonitor/Makefile.in

Second, you need a python client like:
    <source_dir>/xml/client/python/analysis_ppm_xen.py.in

Third, you need to update the Makefiles.in correspondingly.
    <source_dir>/xml/client/python/Makefile.in
    <source_dir>/tools/Makefile.in 
    <source_dir>/configure.in

+---------------+
|6. Other notes |
+---------------+

- Specify the remote RPC service ip for the python client to connect to:
    In the python client code, the initialization of Client needs a "url" to 
specify the wsdl file. Specifically, the pingpongmonitor example, you need to
modify the location value in <build_dir>/xml/service/analysis.wsdl.test from 
localhost to the ip you want.

- Add a field to the TargetSpecT:
    An example to this can be see by running:
    `git show 6c9cf6a407e5576cac20a2c262ae3cd543b98acb`
