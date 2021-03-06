#!/usr/bin/env python
##
## Copyright (c) 2013 The University of Utah
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
##

import logging
logging.basicConfig(level=logging.INFO)
logging.getLogger('suds.client').setLevel(logging.DEBUG)
logging.getLogger('suds.transport').setLevel(logging.DEBUG)
logging.getLogger('suds.xsd.schema').setLevel(logging.DEBUG)
logging.getLogger('suds.wsdl').setLevel(logging.DEBUG)

from suds.client import Client
url = 'http://anathema.flux.utah.edu/wsdl/debuginfo.wsdl.local'
client = Client(url,cache=None)

opts = client.factory.create('DebugFileOptsT')
opts.symbolRefDepth = 8
opts.scopeRefDepth = 8
opts.doMultiRef = False
opts.doManualRef = False
opts.debugfileRefDepth = 8

result = client.service.LookupSymbol('/usr/lib/debug/bin/yes.debug','main.argc',opts)
