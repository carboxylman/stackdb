#!/usr/bin/env python
##
## Copyright (c) 2011, 2012 The University of Utah
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

import vmtap

count = 0

# User handler invoked by vmtap whenever the probe gets triggered
def on_sys_open(p):
    global count
    count += 1
    print "[%d] %s() called in %s" % (count, vmtap.symbol(p), vmtap.domain(p)) 
    print "  -- filename: %s" % (vmtap.arg_string(p,0))
    print "  -- flags: %08x" % (vmtap.arg(p,1))
    print "  -- mode: %08x" % (vmtap.arg(p,2))

# Inject a probe by passing a probepoint expression and a callback handler
success = vmtap.probe("a3guest.kernel.function(sys_open)", on_sys_open)

if success:
    print "probe injected"

    # Start trigerring all injected probes
    # This function returns when "vmtap.stop()" is called or "ctrl+c" is pressed
    vmtap.run()

    print "sys_open() called", count, "times"
